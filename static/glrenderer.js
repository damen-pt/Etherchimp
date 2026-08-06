// glrenderer.js — GLNetwork: a WebGL2 graph renderer that stands in for
// vis.Network (Phase 3 of docs/PERFORMANCE_PLAN.md).
//
// It implements exactly the vis.Network API subset app.js uses, so the rest of
// the app is renderer-agnostic:
//   on/off, redraw, setOptions, setSize, fit, focus, moveTo, selectNodes,
//   getScale, getPosition(s), getConnectedNodes/Edges, canvasToDOM/DOMtoCanvas,
//   body.nodes[id]{x,y,options.opacity}, body.edges[id]{options.{color,label},
//   fromId, edgeType.getPoint} — the last group being the hot-path surface the
//   Phase 1/2 work already writes to directly.
//
// Rendering model:
//   - Nodes and edges are drawn instanced in a single WebGL2 pass each (edge
//     quads, then node quads with an SDF circle/box fragment shader).
//   - Text (node/edge labels) and the subnet rings draw on a 2D overlay canvas
//     under the same camera transform, with viewport culling and zoom LOD —
//     text is the one thing Canvas2D was slow at when unbounded, so it's capped.
//   - A frame is drawn only when something asked for one (redraw()/interaction/
//     animation), same contract as vis. Instance buffers are rebuilt from the
//     body objects on each drawn frame: ~500 nodes + ~1000 edges is a few
//     thousand floats — negligible next to what it replaces.
//
// Enable with ?renderer=gl (or localStorage.renderer = 'gl'); vis-network stays
// the default until this has fully burned in.

(function () {
    'use strict';

    // ---------------------------------------------------------------- helpers

    // Shared with cosmosrenderer.js — see static/colorutil.js.
    const parseColor = window.parseRendererColor;
    const themeColor = window.themeProtocolColor || parseColor;
    const isLightTheme = () => (window.isLightTheme ? window.isLightTheme() : false);

    function easeInOutQuad(t) { return t < 0.5 ? 2 * t * t : 1 - Math.pow(-2 * t + 2, 2) / 2; }

    function compile(gl, type, src) {
        const sh = gl.createShader(type);
        gl.shaderSource(sh, src);
        gl.compileShader(sh);
        if (!gl.getShaderParameter(sh, gl.COMPILE_STATUS)) {
            throw new Error('shader: ' + gl.getShaderInfoLog(sh));
        }
        return sh;
    }
    function program(gl, vs, fs) {
        const p = gl.createProgram();
        gl.attachShader(p, compile(gl, gl.VERTEX_SHADER, vs));
        gl.attachShader(p, compile(gl, gl.FRAGMENT_SHADER, fs));
        gl.linkProgram(p);
        if (!gl.getProgramParameter(p, gl.LINK_STATUS)) {
            throw new Error('link: ' + gl.getProgramInfoLog(p));
        }
        return p;
    }

    // ---------------------------------------------------------------- shaders

    // Node: unit quad scaled per instance; fragment draws an SDF circle or box
    // with a border, anti-aliased in pixel space.
    const NODE_VS = `#version 300 es
    layout(location=0) in vec2 corner;      // unit quad -1..1
    layout(location=1) in vec2 iPos;        // graph coords
    layout(location=2) in vec2 iHalf;       // half size, graph units (w,h)
    layout(location=3) in vec4 iFill;
    layout(location=4) in vec4 iBorder;
    layout(location=5) in float iShape;     // 0 circle, 1 box
    uniform vec2 uCenter;                   // camera center, graph coords
    uniform float uScale;                   // px per graph unit
    uniform vec2 uViewPx;                   // viewport px
    out vec2 vLocalPx;                      // px from node center
    out vec2 vHalfPx;
    out vec4 vFill;
    out vec4 vBorder;
    out float vShape;
    void main() {
        vec2 pad = vec2(2.0) / uScale;                    // AA padding
        vec2 graph = iPos + corner * (iHalf + pad);
        vec2 px = (graph - uCenter) * uScale + uViewPx * 0.5;
        vec2 clip = px / uViewPx * 2.0 - 1.0;
        gl_Position = vec4(clip.x, -clip.y, 0.0, 1.0);
        vLocalPx = corner * (iHalf + pad) * uScale;
        vHalfPx = iHalf * uScale;
        vFill = iFill; vBorder = iBorder; vShape = iShape;
    }`;

    const NODE_FS = `#version 300 es
    precision mediump float;
    in vec2 vLocalPx; in vec2 vHalfPx; in vec4 vFill; in vec4 vBorder; in float vShape;
    out vec4 frag;
    void main() {
        float d;
        if (vShape < 0.5) {
            d = length(vLocalPx) - vHalfPx.x;              // circle
        } else {
            vec2 q = abs(vLocalPx) - vHalfPx + vec2(4.0);  // rounded box, r=4px
            d = length(max(q, vec2(0.0))) + min(max(q.x, q.y), 0.0) - 4.0;
        }
        float bw = 2.5;                                     // border px
        float aa = 1.0;
        // Subtle rim shading: blend fill toward the border color across the
        // outer band so nodes read as discs, not flat stickers.
        float rimStart = max(vHalfPx.x * 0.25, 6.0);
        float rim = smoothstep(-rimStart, -bw, d) * 0.30;
        vec4 body = mix(vFill, vec4(vBorder.rgb, vFill.a), rim);
        vec4 col = mix(body, vBorder, smoothstep(-bw - aa, -bw + aa, d));
        col.a *= 1.0 - smoothstep(-aa, aa, d);
        if (col.a <= 0.003) discard;
        frag = vec4(col.rgb * col.a, col.a);                // premultiplied
    }`;

    // Edge: instanced quadratic-bezier ribbon. The static vertex buffer holds
    // (t, side) pairs for a triangle strip along the curve; the vertex shader
    // evaluates the bezier per vertex. Control point = midpoint + perpendicular
    // offset (EDGE_CURVE fraction of length, side from iBend) — matches the JS
    // edgeCurvePoint helper used for particles, labels, and hit-testing.
    const EDGE_VS = `#version 300 es
    layout(location=0) in vec2 corner;      // x: t along curve 0..1, y: -1..1 across
    layout(location=1) in vec2 iFrom;
    layout(location=2) in vec2 iTo;
    layout(location=3) in float iWidth;     // px at current zoom
    layout(location=4) in vec4 iColor;
    layout(location=5) in float iBend;      // curve side: +1 / -1
    uniform vec2 uCenter; uniform float uScale; uniform vec2 uViewPx;
    uniform float uCurve;                   // perpendicular offset fraction
    out vec4 vColor;
    void main() {
        vec2 a = (iFrom - uCenter) * uScale + uViewPx * 0.5;
        vec2 b = (iTo   - uCenter) * uScale + uViewPx * 0.5;
        vec2 dir = b - a;
        float len = max(length(dir), 0.0001);
        vec2 n = vec2(-dir.y, dir.x) / len;
        vec2 ctrl = (a + b) * 0.5 + n * (len * uCurve * iBend);
        float t = corner.x;
        float mt = 1.0 - t;
        vec2 p = mt * mt * a + 2.0 * mt * t * ctrl + t * t * b;
        // Curve tangent -> normal for ribbon extrusion.
        vec2 tang = normalize(2.0 * mt * (ctrl - a) + 2.0 * t * (b - ctrl));
        vec2 pn = vec2(-tang.y, tang.x);
        vec2 px = p + pn * corner.y * (iWidth * 0.5 + 0.5);
        vec2 clip = px / uViewPx * 2.0 - 1.0;
        gl_Position = vec4(clip.x, -clip.y, 0.0, 1.0);
        vColor = iColor;
    }`;

    const EDGE_FS = `#version 300 es
    precision mediump float;
    in vec4 vColor; out vec4 frag;
    void main() {
        if (vColor.a <= 0.003) discard;
        frag = vec4(vColor.rgb * vColor.a, vColor.a);
    }`;

    // Label: instanced textured quads sampling the label sprite atlas. Glyphs
    // are rasterized WHITE into the atlas once per unique string and tinted
    // per instance here, so theme changes never invalidate the atlas — and no
    // Canvas2D fillText runs per frame (the Safari killer).
    const LABEL_VS = `#version 300 es
    layout(location=0) in vec2 corner;      // unit quad 0..1
    layout(location=1) in vec2 iAnchor;     // graph coords
    layout(location=2) in vec2 iOffset;     // graph units from anchor
    layout(location=3) in vec2 iSize;       // graph units (w,h)
    layout(location=4) in vec4 iUV;         // u0,v0,u1,v1
    layout(location=5) in vec4 iColor;
    uniform vec2 uCenter; uniform float uScale; uniform vec2 uViewPx;
    out vec2 vUV; out vec4 vColor;
    void main() {
        vec2 graph = iAnchor + iOffset + corner * iSize;
        vec2 px = (graph - uCenter) * uScale + uViewPx * 0.5;
        vec2 clip = px / uViewPx * 2.0 - 1.0;
        gl_Position = vec4(clip.x, -clip.y, 0.0, 1.0);
        vUV = mix(iUV.xy, iUV.zw, corner);
        vColor = iColor;
    }`;

    // Atlas sprites carry the halo in the red channel (stroke) and the glyph
    // fill in the green channel: fill = g, halo = r where not fill. The glyph
    // is tinted per instance; the halo color is a per-frame uniform (theme-
    // dependent) so text stays readable over busy line work in either theme.
    const LABEL_FS = `#version 300 es
    precision mediump float;
    uniform sampler2D uAtlas;
    uniform vec3 uHaloColor;
    in vec2 vUV; in vec4 vColor; out vec4 frag;
    void main() {
        vec4 tex = texture(uAtlas, vUV);
        float fill = tex.g;
        float halo = max(0.0, tex.r - tex.g) * 0.9;
        float a = (fill + halo * (1.0 - fill)) * vColor.a;
        if (a <= 0.003) discard;
        vec3 rgb = vColor.rgb * fill + uHaloColor * halo * (1.0 - fill);
        frag = vec4(rgb * vColor.a, a);
    }`;

    // -------------------------------------------------------------- GLNetwork

    const NODE_FLOATS = 13;  // pos2 half2 fill4 border4 shape1
    const EDGE_FLOATS = 10;  // from2 to2 width1 color4 bend1
    const LABEL_FLOATS = 14; // anchor2 offset2 size2 uv4 color4
    const MAX_PARTICLES = 220;
    const EDGE_SEGMENTS = 24;  // bezier ribbon tessellation (near zoom)
    const EDGE_SEGMENTS_FAR = 2; // straight ribbon when zoomed out (LOD)
    const EDGE_CURVE = 0.12;   // control-point offset as a fraction of length
    // Below this camera scale, draw straight thin edges (skip bezier cost).
    const EDGE_CURVE_MIN_SCALE = 0.55;
    // Don't spawn a new particle on an edge whose newest particle is still in
    // its first stretch — busy edges show a spaced stream, not a rope of dots.
    const PARTICLE_EDGE_GAP = 0.35;
    // Spatial hash cell size in graph units for hit-testing.
    const HIT_GRID_CELL = 80;

    // Quadratic-bezier point at t for the edge a->b, matching EDGE_VS. bend
    // (+1/-1) picks the curve side; it must be derived the same way everywhere:
    // from the canonical (lexicographic) endpoint ordering, so an edge bends
    // the same way no matter which endpoint is "from".
    function edgeBend(fromId, toId) {
        return fromId < toId ? 1 : -1;
    }
    function edgeCurvePoint(a, b, t, bend) {
        const dx = b.x - a.x, dy = b.y - a.y;
        const len = Math.hypot(dx, dy) || 0.0001;
        const cx = (a.x + b.x) / 2 - (dy / len) * len * EDGE_CURVE * bend;
        const cy = (a.y + b.y) / 2 + (dx / len) * len * EDGE_CURVE * bend;
        const mt = 1 - t;
        return {
            x: mt * mt * a.x + 2 * mt * t * cx + t * t * b.x,
            y: mt * mt * a.y + 2 * mt * t * cy + t * t * b.y
        };
    }

    class GLNetwork {
        static isSupported() {
            try {
                const c = document.createElement('canvas');
                return !!c.getContext('webgl2');
            } catch (e) { return false; }
        }

        constructor(container, data, options) {
            this.container = container;
            this.nodesData = data.nodes;
            this.edgesData = data.edges;
            this.options = options || {};
            this.listeners = {};
            this.body = { nodes: {}, edges: {} };
            this.selectedNode = null;
            this.hoveredNode = null;
            this.hoveredEdge = null;
            this.camera = { cx: 0, cy: 0, scale: 1 };
            this.anim = null;          // camera tween
            this.drawQueued = false;
            this.destroyed = false;
            this._didInitialFit = false;

            if (getComputedStyle(container).position === 'static') {
                container.style.position = 'relative';
            }
            container.tabIndex = container.tabIndex || 0;
            container.style.outline = 'none';

            this.glCanvas = document.createElement('canvas');
            this.glCanvas.style.cssText = 'position:absolute;top:0;left:0;z-index:1;';
            this.overlay = document.createElement('canvas');
            this.overlay.style.cssText = 'position:absolute;top:0;left:0;z-index:2;pointer-events:none;';
            container.appendChild(this.glCanvas);
            container.appendChild(this.overlay);
            this.ctx2d = this.overlay.getContext('2d');

            // antialias:false — the SDF fragment shaders already anti-alias in
            // pixel space, so MSAA is pure overhead (Safari pays most for it).
            const gl = this.glCanvas.getContext('webgl2', { antialias: false, alpha: true, premultipliedAlpha: true });
            if (!gl) throw new Error('WebGL2 unavailable');
            this.gl = gl;
            gl.enable(gl.BLEND);
            gl.blendFunc(gl.ONE, gl.ONE_MINUS_SRC_ALPHA);

            this.nodeProg = program(gl, NODE_VS, NODE_FS);
            this.edgeProg = program(gl, EDGE_VS, EDGE_FS);
            this.labelProg = program(gl, LABEL_VS, LABEL_FS);
            // Cache uniform locations once (getUniformLocation per draw is waste).
            const uniforms = p => ({
                center: gl.getUniformLocation(p, 'uCenter'),
                scale: gl.getUniformLocation(p, 'uScale'),
                view: gl.getUniformLocation(p, 'uViewPx'),
                atlas: gl.getUniformLocation(p, 'uAtlas'),
                curve: gl.getUniformLocation(p, 'uCurve'),
                haloColor: gl.getUniformLocation(p, 'uHaloColor')
            });
            this.nodeU = uniforms(this.nodeProg);
            this.edgeU = uniforms(this.edgeProg);
            this.labelU = uniforms(this.labelProg);
            this._initGeometry();
            this._initAtlas();

            this.nodeArr = new Float32Array(0);
            this.edgeArr = new Float32Array(0);
            this.labelArr = new Float32Array(0);

            // GL flow particles (replaces the app's 2D flow overlay when this
            // renderer is active): {fromId, toId, color:[4], progress, speed}.
            this.particles = [];

            // Ring/label overlay repaint gating.
            this._overlayDirty = true;
            this._overlayCamSig = '';

            // Phase 6 dirty flags: skip full instance rebuild on camera-only frames.
            this._nodesDirty = true;
            this._edgesDirty = true;
            this._hitDirty = true;
            this._cachedNodeCount = 0;
            this._hitGrid = null; // Map cellKey -> [id,...]
            this._lastFrameMs = 0;

            // Sync from the DataSets (initial load + live events).
            this._syncAll();
            this._nodeSub = (ev, props) => this._onNodesEvent(ev, props);
            this._edgeSub = (ev, props) => this._onEdgesEvent(ev, props);
            this.nodesData.on('*', this._nodeSub);
            this.edgesData.on('*', this._edgeSub);

            this._bindInput();
            this._resize();
            if (window.ResizeObserver) {
                this._ro = new ResizeObserver(() => { this._resize(); this.redraw(); });
                this._ro.observe(container);
            }
            this.redraw();
        }

        // Mark topology/style dirty so the next _draw rebuilds GPU instance buffers.
        // Position changes (easing) must dirty both nodes and edges — edge
        // instance data embeds endpoint coordinates.
        markSceneDirty(kind) {
            if (kind === 'nodes' || kind === 'all' || kind == null) {
                this._nodesDirty = true;
                this._edgesDirty = true; // endpoints move with nodes
                this._hitDirty = true;
            }
            if (kind === 'edges' || kind === 'all' || kind == null) {
                this._edgesDirty = true;
            }
            this.redraw();
        }

        // Adaptive particle cap: fewer dots when the graph is large or the last
        // frame was expensive, so pan/zoom stays fluid inside dense clusters.
        _particleCap() {
            const n = this._cachedNodeCount || Object.keys(this.body.nodes).length;
            let cap = MAX_PARTICLES;
            if (n > 400) cap = 80;
            else if (n > 200) cap = 140;
            if (this._lastFrameMs > 12) cap = Math.min(cap, 60);
            return cap;
        }

        // ----- geometry / GL state

        _initGeometry() {
            const gl = this.gl;
            // Shared unit quad for nodes (corner -1..1).
            this.nodeVAO = gl.createVertexArray();
            gl.bindVertexArray(this.nodeVAO);
            const quad = gl.createBuffer();
            gl.bindBuffer(gl.ARRAY_BUFFER, quad);
            gl.bufferData(gl.ARRAY_BUFFER, new Float32Array([-1, -1, 1, -1, -1, 1, 1, 1]), gl.STATIC_DRAW);
            gl.enableVertexAttribArray(0);
            gl.vertexAttribPointer(0, 2, gl.FLOAT, false, 0, 0);
            this.nodeInstBuf = gl.createBuffer();
            gl.bindBuffer(gl.ARRAY_BUFFER, this.nodeInstBuf);
            const nStride = NODE_FLOATS * 4;
            const nAttrs = [[1, 2, 0], [2, 2, 8], [3, 4, 16], [4, 4, 32], [5, 1, 48]];
            for (const [loc, size, off] of nAttrs) {
                gl.enableVertexAttribArray(loc);
                gl.vertexAttribPointer(loc, size, gl.FLOAT, false, nStride, off);
                gl.vertexAttribDivisor(loc, 1);
            }
            // Edge ribbon: triangle strip of (t, side) pairs along the bezier.
            this.edgeVAO = gl.createVertexArray();
            gl.bindVertexArray(this.edgeVAO);
            const estrip = gl.createBuffer();
            gl.bindBuffer(gl.ARRAY_BUFFER, estrip);
            const stripVerts = new Float32Array((EDGE_SEGMENTS + 1) * 4);
            for (let i = 0; i <= EDGE_SEGMENTS; i++) {
                const t = i / EDGE_SEGMENTS;
                stripVerts[i * 4] = t; stripVerts[i * 4 + 1] = -1;
                stripVerts[i * 4 + 2] = t; stripVerts[i * 4 + 3] = 1;
            }
            gl.bufferData(gl.ARRAY_BUFFER, stripVerts, gl.STATIC_DRAW);
            gl.enableVertexAttribArray(0);
            gl.vertexAttribPointer(0, 2, gl.FLOAT, false, 0, 0);
            this.edgeInstBuf = gl.createBuffer();
            gl.bindBuffer(gl.ARRAY_BUFFER, this.edgeInstBuf);
            const eStride = EDGE_FLOATS * 4;
            const eAttrs = [[1, 2, 0], [2, 2, 8], [3, 1, 16], [4, 4, 20], [5, 1, 36]];
            for (const [loc, size, off] of eAttrs) {
                gl.enableVertexAttribArray(loc);
                gl.vertexAttribPointer(loc, size, gl.FLOAT, false, eStride, off);
                gl.vertexAttribDivisor(loc, 1);
            }
            // Label quad: 0..1 both axes (top-left anchored).
            this.labelVAO = gl.createVertexArray();
            gl.bindVertexArray(this.labelVAO);
            const lquad = gl.createBuffer();
            gl.bindBuffer(gl.ARRAY_BUFFER, lquad);
            gl.bufferData(gl.ARRAY_BUFFER, new Float32Array([0, 0, 1, 0, 0, 1, 1, 1]), gl.STATIC_DRAW);
            gl.enableVertexAttribArray(0);
            gl.vertexAttribPointer(0, 2, gl.FLOAT, false, 0, 0);
            this.labelInstBuf = gl.createBuffer();
            gl.bindBuffer(gl.ARRAY_BUFFER, this.labelInstBuf);
            const lStride = LABEL_FLOATS * 4;
            const lAttrs = [[1, 2, 0], [2, 2, 8], [3, 2, 16], [4, 4, 24], [5, 4, 40]];
            for (const [loc, size, off] of lAttrs) {
                gl.enableVertexAttribArray(loc);
                gl.vertexAttribPointer(loc, size, gl.FLOAT, false, lStride, off);
                gl.vertexAttribDivisor(loc, 1);
            }
            gl.bindVertexArray(null);
        }

        // ----- label sprite atlas
        //
        // Each unique (font, text) is rasterized ONCE — white on transparent —
        // into a shelf-packed atlas canvas, uploaded to a texture when new
        // sprites were added. Rendering a label is then just an instanced quad.

        _initAtlas() {
            const gl = this.gl;
            this.atlasSize = Math.min(2048, gl.getParameter(gl.MAX_TEXTURE_SIZE));
            this.atlasScale = 2; // rasterize at 2x for crispness when zoomed in
            this.atlasCanvas = document.createElement('canvas');
            this.atlasCanvas.width = this.atlasCanvas.height = this.atlasSize;
            this.atlasCtx = this.atlasCanvas.getContext('2d', { willReadFrequently: false });
            this.atlasMap = new Map(); // "font|text" -> {u0,v0,u1,v1,w,h} (w/h at 1x)
            this.atlasX = 0;
            this.atlasY = 0;
            this.atlasRowH = 0;
            this.atlasDirty = false;
            this.atlasTex = gl.createTexture();
            gl.bindTexture(gl.TEXTURE_2D, this.atlasTex);
            gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_MIN_FILTER, gl.LINEAR);
            gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_MAG_FILTER, gl.LINEAR);
            gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_WRAP_S, gl.CLAMP_TO_EDGE);
            gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_WRAP_T, gl.CLAMP_TO_EDGE);
        }

        // Get (rasterizing on miss) the atlas sprite for a string. fontPx is the
        // 1x size; returns null when the atlas is full even after a reset.
        _atlasSprite(text, fontPx, fontFace) {
            const key = fontPx + fontFace + '|' + text;
            let s = this.atlasMap.get(key);
            if (s) return s;
            const ctx = this.atlasCtx;
            const scale = this.atlasScale;
            const pad = 2 * scale;
            ctx.font = (fontPx * scale) + 'px ' + fontFace;
            const w = Math.ceil(ctx.measureText(text).width) + pad * 2;
            const h = Math.ceil(fontPx * scale * 1.35) + pad;
            if (w > this.atlasSize) return null; // pathological string
            if (this.atlasX + w > this.atlasSize) {
                this.atlasX = 0;
                this.atlasY += this.atlasRowH;
                this.atlasRowH = 0;
            }
            if (this.atlasY + h > this.atlasSize) {
                // Full: reset and repopulate lazily from live demand. With the
                // per-frame label cap this only happens after heavy label churn.
                this.atlasMap.clear();
                this.atlasX = 0; this.atlasY = 0; this.atlasRowH = 0;
                ctx.clearRect(0, 0, this.atlasSize, this.atlasSize);
                ctx.font = (fontPx * scale) + 'px ' + fontFace;
            }
            // Halo in the RED channel (stroke), glyph in GREEN (white fill also
            // sets red, but the shader uses max(0, r - g) so overlap cancels).
            ctx.textBaseline = 'top';
            ctx.textAlign = 'left';
            ctx.lineJoin = 'round';
            ctx.lineWidth = 3 * scale;
            ctx.strokeStyle = '#ff0000';
            ctx.strokeText(text, this.atlasX + pad, this.atlasY + pad);
            ctx.fillStyle = '#ffffff';
            ctx.fillText(text, this.atlasX + pad, this.atlasY + pad);
            s = {
                u0: this.atlasX / this.atlasSize,
                v0: this.atlasY / this.atlasSize,
                u1: (this.atlasX + w) / this.atlasSize,
                v1: (this.atlasY + h) / this.atlasSize,
                w: w / scale,
                h: h / scale
            };
            this.atlasMap.set(key, s);
            this.atlasX += w;
            if (h > this.atlasRowH) this.atlasRowH = h;
            this.atlasDirty = true;
            return s;
        }

        _uploadAtlasIfDirty() {
            if (!this.atlasDirty) return;
            this.atlasDirty = false;
            const gl = this.gl;
            gl.bindTexture(gl.TEXTURE_2D, this.atlasTex);
            gl.pixelStorei(gl.UNPACK_PREMULTIPLY_ALPHA_WEBGL, false);
            gl.texImage2D(gl.TEXTURE_2D, 0, gl.RGBA, gl.RGBA, gl.UNSIGNED_BYTE, this.atlasCanvas);
        }

        // ----- DataSet sync

        _syncAll() {
            for (const item of this.nodesData.get()) this._syncNode(item);
            for (const item of this.edgesData.get()) this._syncEdge(item);
            this._recomputeSizes();
        }

        _onNodesEvent(ev, props) {
            if (this.destroyed) return;
            const ids = (props && props.items) || [];
            if (ev === 'remove') {
                for (const id of ids) delete this.body.nodes[id];
            } else {
                for (const id of ids) {
                    const item = this.nodesData.get(id);
                    if (item) this._syncNode(item);
                }
            }
            this._recomputeSizes();
            this._nodesDirty = true;
            this._hitDirty = true;
            // First data arrival: fit now for an immediate sensible view, then
            // keep watching until the server layout settles and fit once more —
            // the first positions are pre-convergence seeds, so a single early
            // fit would leave the settled graph off-center.
            if (!this._didInitialFit && Object.keys(this.body.nodes).length > 0) {
                this._didInitialFit = true;
                this.fit();
                this._autoFitUntilSettled();
            }
            this.redraw();
        }

        // Poll the node bounding box until it stops changing (layout converged),
        // then fit the camera to it. Gives up after 20s. Skipped as soon as the
        // user takes over the camera (pan/zoom/fit of their own).
        _autoFitUntilSettled() {
            let lastSig = null, stable = 0, checks = 0;
            this._userMovedCamera = false;
            const timer = setInterval(() => {
                if (this.destroyed || this._userMovedCamera || ++checks > 40) {
                    clearInterval(timer);
                    return;
                }
                let minX = Infinity, minY = Infinity, maxX = -Infinity, maxY = -Infinity, n = 0;
                for (const id in this.body.nodes) {
                    const p = this.body.nodes[id];
                    if (p.x < minX) minX = p.x;
                    if (p.x > maxX) maxX = p.x;
                    if (p.y < minY) minY = p.y;
                    if (p.y > maxY) maxY = p.y;
                    n++;
                }
                if (!n) return;
                const sig = Math.round(minX) + '|' + Math.round(minY) + '|' + Math.round(maxX) + '|' + Math.round(maxY);
                if (sig === lastSig) {
                    if (++stable >= 2) {
                        clearInterval(timer);
                        this.fit({ animation: { duration: 400 } });
                    }
                } else {
                    stable = 0;
                    lastSig = sig;
                }
            }, 500);
        }

        _onEdgesEvent(ev, props) {
            if (this.destroyed) return;
            const ids = (props && props.items) || [];
            if (ev === 'remove') {
                for (const id of ids) delete this.body.edges[id];
            } else {
                for (const id of ids) {
                    const item = this.edgesData.get(id);
                    if (item) this._syncEdge(item);
                }
            }
            this._edgesDirty = true;
            this.redraw();
        }

        _syncNode(item) {
            let bn = this.body.nodes[item.id];
            if (!bn) {
                bn = this.body.nodes[item.id] = {
                    id: item.id,
                    x: typeof item.x === 'number' ? item.x : 0,
                    y: typeof item.y === 'number' ? item.y : 0,
                    options: { opacity: 1 }
                };
            } else {
                if (typeof item.x === 'number') bn.x = item.x;
                if (typeof item.y === 'number') bn.y = item.y;
                bn.options.opacity = 1; // style update resets dim (vis parity)
            }
            const o = bn.options;
            o.label = item.label;
            o.color = item.color || {};
            o.font = item.font || null;
            o.isGroup = item.shape === 'box';
            o.value = typeof item.value === 'number' ? item.value : null;
            o.size = 20; // recomputed by _recomputeSizes
        }

        _syncEdge(item) {
            let be = this.body.edges[item.id];
            if (!be) {
                const self = this;
                be = this.body.edges[item.id] = {
                    id: item.id,
                    fromId: item.from,
                    toId: item.to,
                    options: {},
                    // Bezier param point matching the rendered curve, used by
                    // chimpy mode exactly like vis's edgeType.getPoint.
                    edgeType: {
                        getPoint(t) {
                            const a = self.body.nodes[be.fromId];
                            const b = self.body.nodes[be.toId];
                            if (!a || !b) return { x: 0, y: 0 };
                            return edgeCurvePoint(a, b, t, edgeBend(be.fromId, be.toId));
                        }
                    }
                };
            }
            be.fromId = item.from;
            be.toId = item.to;
            const o = be.options;
            const prevOpacity = o.color ? o.color.opacity : 1;
            const colStr = item.color && item.color.color ? item.color.color : '#848484';
            o.color = { color: colStr, opacity: prevOpacity == null ? 1 : prevOpacity };
            if (item.label !== undefined && item.label !== '' && item.label !== null) {
                o.label = item.label;
            } else if (item.label === '' && o.label === undefined) {
                o.label = undefined;
            }
            // vis parity quirk: an update carrying label '' must NOT clear an
            // existing label (app.js toggles labels via options.label directly).
            o.width = typeof item.width === 'number' ? item.width : 1;
        }

        // Node render size from 'value', matching vis scaling 20..30 px (and the
        // server's layout collision radii).
        _recomputeSizes() {
            let minV = Infinity, maxV = -Infinity, any = false;
            for (const id in this.body.nodes) {
                const v = this.body.nodes[id].options.value;
                if (v == null) continue;
                any = true;
                if (v < minV) minV = v;
                if (v > maxV) maxV = v;
            }
            for (const id in this.body.nodes) {
                const o = this.body.nodes[id].options;
                if (o.isGroup) { o.size = 12; continue; }
                if (!any || maxV <= minV || o.value == null) { o.size = 20; continue; }
                o.size = 20 + 10 * (o.value - minV) / (maxV - minV);
            }
        }

        // ----- events (vis-compatible emitter)

        on(ev, cb) { (this.listeners[ev] = this.listeners[ev] || []).push(cb); }
        off(ev, cb) {
            const l = this.listeners[ev];
            if (l) this.listeners[ev] = l.filter(f => f !== cb);
        }
        _emit(ev, arg) {
            const l = this.listeners[ev];
            if (!l) return;
            for (const cb of l) { try { cb(arg); } catch (e) { console.error(e); } }
        }

        // ----- public camera / coordinate API

        getScale() { return this.camera.scale; }
        canvasToDOM(p) {
            return {
                x: (p.x - this.camera.cx) * this.camera.scale + this.viewW / 2,
                y: (p.y - this.camera.cy) * this.camera.scale + this.viewH / 2
            };
        }
        DOMtoCanvas(p) {
            return {
                x: (p.x - this.viewW / 2) / this.camera.scale + this.camera.cx,
                y: (p.y - this.viewH / 2) / this.camera.scale + this.camera.cy
            };
        }
        getPosition(id) {
            const n = this.body.nodes[id];
            return n ? { x: n.x, y: n.y } : { x: 0, y: 0 };
        }
        getPositions(ids) {
            const out = {};
            const list = ids || Object.keys(this.body.nodes);
            for (const id of list) {
                const n = this.body.nodes[id];
                if (n) out[id] = { x: n.x, y: n.y };
            }
            return out;
        }
        getConnectedNodes(id) {
            const out = [];
            for (const eid in this.body.edges) {
                const e = this.body.edges[eid];
                if (e.fromId === id) out.push(e.toId);
                else if (e.toId === id) out.push(e.fromId);
            }
            return out;
        }
        getConnectedEdges(id) {
            const out = [];
            for (const eid in this.body.edges) {
                const e = this.body.edges[eid];
                if (e.fromId === id || e.toId === id) out.push(eid);
            }
            return out;
        }
        selectNodes(ids) {
            this.selectedNode = ids && ids.length ? ids[0] : null;
            this.redraw();
        }
        setOptions(options) {
            // Merge shallowly per top-level key: callers pass a full options object.
            this.options = Object.assign({}, this.options, options);
            this.redraw();
        }
        setSize(w, h) { this._resize(); this.redraw(); }

        fit(opts) {
            const ids = Object.keys(this.body.nodes);
            if (!ids.length) return;
            let minX = Infinity, minY = Infinity, maxX = -Infinity, maxY = -Infinity;
            for (const id of ids) {
                const n = this.body.nodes[id];
                if (n.x < minX) minX = n.x;
                if (n.x > maxX) maxX = n.x;
                if (n.y < minY) minY = n.y;
                if (n.y > maxY) maxY = n.y;
            }
            const pad = 80;
            const w = maxX - minX + pad * 2, h = maxY - minY + pad * 2;
            const scale = Math.min(2, Math.min(this.viewW / Math.max(w, 1), this.viewH / Math.max(h, 1)));
            this._moveCamera({ cx: (minX + maxX) / 2, cy: (minY + maxY) / 2, scale: scale }, opts && opts.animation);
        }
        focus(id, opts) {
            const n = this.body.nodes[id];
            if (!n) return;
            this._moveCamera({
                cx: n.x, cy: n.y,
                scale: (opts && opts.scale) || this.camera.scale
            }, opts && opts.animation);
        }
        moveTo(opts) {
            this._moveCamera({
                cx: opts.position ? opts.position.x : this.camera.cx,
                cy: opts.position ? opts.position.y : this.camera.cy,
                scale: opts.scale != null ? opts.scale : this.camera.scale
            }, opts.animation);
        }
        _moveCamera(target, animation) {
            if (!animation) {
                this.camera.cx = target.cx; this.camera.cy = target.cy; this.camera.scale = target.scale;
                this.anim = null;
                this.redraw();
                return;
            }
            this.anim = {
                from: { cx: this.camera.cx, cy: this.camera.cy, scale: this.camera.scale },
                to: target,
                start: performance.now(),
                duration: (animation && animation.duration) || 400
            };
            this.redraw();
        }

        redraw() {
            if (this.drawQueued || this.destroyed) return;
            this.drawQueued = true;
            requestAnimationFrame(() => { this.drawQueued = false; this._draw(); });
        }

        // Traffic-flow particles, rendered inside the GL scene (no 2D overlay).
        // flows: [{fromId, toId, color: cssString, speed}] — progress starts 0.
        // An edge whose newest particle hasn't cleared PARTICLE_EDGE_GAP yet is
        // skipped, so heavy flows show a spaced stream instead of a dot rope.
        spawnParticles(flows) {
            for (const f of flows) {
                if (!this.body.nodes[f.fromId] || !this.body.nodes[f.toId]) continue;
                let tooSoon = false;
                for (let i = this.particles.length - 1; i >= 0; i--) {
                    const p = this.particles[i];
                    if (p.fromId === f.fromId && p.toId === f.toId && p.progress < PARTICLE_EDGE_GAP) {
                        tooSoon = true;
                        break;
                    }
                }
                if (tooSoon) continue;
                this.particles.push({
                    fromId: f.fromId,
                    toId: f.toId,
                    color: parseColor(f.color, [0.5, 0.83, 1, 1]),
                    progress: 0,
                    speed: f.speed
                });
            }
            const cap = this._particleCap();
            if (this.particles.length > cap) {
                this.particles.splice(0, this.particles.length - cap);
            }
            this.redraw();
        }

        // Mark the 2D ring overlay stale (subnet islands changed). The overlay
        // otherwise repaints only when the camera moves.
        invalidateOverlay() {
            this._overlayDirty = true;
            this.redraw();
        }

        destroy() {
            this.destroyed = true;
            this.nodesData.off('*', this._nodeSub);
            this.edgesData.off('*', this._edgeSub);
            if (this._ro) this._ro.disconnect();
            this.glCanvas.remove();
            this.overlay.remove();
        }

        // ----- input

        _bindInput() {
            const c = this.container;
            let mouseDown = null;      // {x, y, nodeId|null, moved}
            const pos = ev => {
                const r = c.getBoundingClientRect();
                return { x: ev.clientX - r.left, y: ev.clientY - r.top };
            };

            c.addEventListener('wheel', ev => {
                ev.preventDefault();
                const p = pos(ev);
                const g = this.DOMtoCanvas(p);
                const zoomSpeed = 0.0015;
                const factor = Math.exp(-ev.deltaY * zoomSpeed);
                const ns = Math.min(10, Math.max(0.05, this.camera.scale * factor));
                // Keep the point under the cursor fixed.
                this.camera.cx = g.x - (p.x - this.viewW / 2) / ns;
                this.camera.cy = g.y - (p.y - this.viewH / 2) / ns;
                this.camera.scale = ns;
                this.anim = null;
                this._userMovedCamera = true;
                this._emit('zoom', { scale: ns });
                this.redraw();
            }, { passive: false });

            c.addEventListener('mousedown', ev => {
                if (ev.button !== 0) return;
                const p = pos(ev);
                mouseDown = { x: p.x, y: p.y, nodeId: this._hitNode(p), moved: false };
                c.focus();
            });
            window.addEventListener('mousemove', ev => {
                const p = pos(ev);
                if (mouseDown) {
                    const dx = p.x - mouseDown.x, dy = p.y - mouseDown.y;
                    if (!mouseDown.moved && (dx * dx + dy * dy) > 16) {
                        mouseDown.moved = true;
                        this._emit('dragStart', { nodes: mouseDown.nodeId ? [mouseDown.nodeId] : [] });
                    }
                    if (!mouseDown.moved) return;
                    if (mouseDown.nodeId) {
                        const g = this.DOMtoCanvas(p);
                        const n = this.body.nodes[mouseDown.nodeId];
                        if (n) { n.x = g.x; n.y = g.y; }
                    } else {
                        this.camera.cx -= (p.x - mouseDown.x) / this.camera.scale;
                        this.camera.cy -= (p.y - mouseDown.y) / this.camera.scale;
                        mouseDown.x = p.x; mouseDown.y = p.y;
                        this.anim = null;
                        this._userMovedCamera = true;
                    }
                    this.redraw();
                    return;
                }
                this._hover(p);
            });
            window.addEventListener('mouseup', ev => {
                if (ev.button !== 0 || !mouseDown) return;
                const wasClick = !mouseDown.moved;
                const nodeId = mouseDown.nodeId;
                mouseDown = null;
                if (!wasClick) { this._emit('dragEnd', { nodes: nodeId ? [nodeId] : [] }); return; }
                const p = pos(ev);
                // A click inside the container only (mouseup may land elsewhere).
                const r = c.getBoundingClientRect();
                if (ev.clientX < r.left || ev.clientX > r.right || ev.clientY < r.top || ev.clientY > r.bottom) return;
                const hitN = this._hitNode(p);
                const hitE = hitN ? null : this._hitEdge(p);
                this.selectedNode = hitN || null;
                this._emit('click', {
                    nodes: hitN ? [hitN] : [],
                    edges: hitN ? this.getConnectedEdges(hitN) : (hitE ? [hitE] : []),
                    pointer: { DOM: p, canvas: this.DOMtoCanvas(p) }
                });
                this.redraw();
            });
            c.addEventListener('mouseleave', () => {
                if (this.hoveredNode) { this._emit('blurNode', { node: this.hoveredNode }); this.hoveredNode = null; }
                if (this.hoveredEdge) { this._emit('blurEdge', { edge: this.hoveredEdge }); this.hoveredEdge = null; }
            });
            c.addEventListener('keydown', ev => {
                const panPx = 40;
                let handled = true;
                switch (ev.key) {
                    case 'ArrowUp': this.camera.cy -= panPx / this.camera.scale; break;
                    case 'ArrowDown': this.camera.cy += panPx / this.camera.scale; break;
                    case 'ArrowLeft': this.camera.cx -= panPx / this.camera.scale; break;
                    case 'ArrowRight': this.camera.cx += panPx / this.camera.scale; break;
                    case '+': case '=': this.camera.scale = Math.min(10, this.camera.scale * 1.2); break;
                    case '-': case '_': this.camera.scale = Math.max(0.05, this.camera.scale / 1.2); break;
                    default: handled = false;
                }
                if (handled) { ev.preventDefault(); this.anim = null; this._userMovedCamera = true; this.redraw(); }
            });
        }

        _hover(p) {
            const interaction = this.options.interaction || {};
            if (interaction.hover === false) return;
            const n = this._hitNode(p);
            if (n !== this.hoveredNode) {
                if (this.hoveredNode) this._emit('blurNode', { node: this.hoveredNode });
                this.hoveredNode = n;
                if (n) this._emit('hoverNode', { node: n });
            }
            if (!n) {
                const e = this._hitEdge(p);
                if (e !== this.hoveredEdge) {
                    if (this.hoveredEdge) this._emit('blurEdge', { edge: this.hoveredEdge });
                    this.hoveredEdge = e;
                    if (e) this._emit('hoverEdge', { edge: e });
                }
            } else if (this.hoveredEdge) {
                this._emit('blurEdge', { edge: this.hoveredEdge });
                this.hoveredEdge = null;
            }
        }

        _rebuildHitGrid() {
            const grid = new Map();
            const cell = HIT_GRID_CELL;
            let count = 0;
            for (const id in this.body.nodes) {
                const n = this.body.nodes[id];
                const cx = Math.floor(n.x / cell);
                const cy = Math.floor(n.y / cell);
                const key = cx + ',' + cy;
                let bucket = grid.get(key);
                if (!bucket) { bucket = []; grid.set(key, bucket); }
                bucket.push(id);
                count++;
            }
            this._hitGrid = grid;
            this._cachedNodeCount = count;
            this._hitDirty = false;
        }

        _hitNode(p) {
            const g = this.DOMtoCanvas(p);
            if (this._hitDirty || !this._hitGrid) this._rebuildHitGrid();
            const cell = HIT_GRID_CELL;
            const cx = Math.floor(g.x / cell);
            const cy = Math.floor(g.y / cell);
            let best = null, bestD = Infinity;
            // Search the home cell and its 8 neighbours (covers radius ~cell).
            for (let dx = -1; dx <= 1; dx++) {
                for (let dy = -1; dy <= 1; dy++) {
                    const bucket = this._hitGrid.get((cx + dx) + ',' + (cy + dy));
                    if (!bucket) continue;
                    for (const id of bucket) {
                        const n = this.body.nodes[id];
                        if (!n) continue;
                        const r = (n.options.size || 20) + 4 / this.camera.scale;
                        const ox = g.x - n.x, oy = g.y - n.y;
                        const d = ox * ox + oy * oy;
                        if (d < r * r && d < bestD) { bestD = d; best = id; }
                    }
                }
            }
            return best;
        }

        _hitEdge(p) {
            const g = this.DOMtoCanvas(p);
            const maxD = 6 / this.camera.scale;
            let best = null, bestD = maxD * maxD;
            for (const id in this.body.edges) {
                const e = this.body.edges[id];
                const a = this.body.nodes[e.fromId], b = this.body.nodes[e.toId];
                if (!a || !b) continue;
                // Coarse reject on the straight chord (with slack for the bow),
                // then distance to the sampled bezier polyline.
                const abx = b.x - a.x, aby = b.y - a.y;
                const len2 = abx * abx + aby * aby;
                let t = len2 > 0 ? ((g.x - a.x) * abx + (g.y - a.y) * aby) / len2 : 0;
                t = Math.max(0, Math.min(1, t));
                const cdx = g.x - (a.x + abx * t), cdy = g.y - (a.y + aby * t);
                const bow = Math.sqrt(len2) * EDGE_CURVE * 0.5 + maxD;
                if (cdx * cdx + cdy * cdy > bow * bow) continue;
                const bend = edgeBend(e.fromId, e.toId);
                let prev = a;
                for (let i = 1; i <= 8; i++) {
                    const cur = edgeCurvePoint(a, b, i / 8, bend);
                    const sx = cur.x - prev.x, sy = cur.y - prev.y;
                    const sl2 = sx * sx + sy * sy;
                    let st = sl2 > 0 ? ((g.x - prev.x) * sx + (g.y - prev.y) * sy) / sl2 : 0;
                    st = Math.max(0, Math.min(1, st));
                    const dx = g.x - (prev.x + sx * st), dy = g.y - (prev.y + sy * st);
                    const d = dx * dx + dy * dy;
                    if (d < bestD) { bestD = d; best = id; }
                    prev = cur;
                }
            }
            return best;
        }

        // ----- drawing

        _resize() {
            const dpr = window.devicePixelRatio || 1;
            this.viewW = this.container.clientWidth;
            this.viewH = this.container.clientHeight;
            for (const cv of [this.glCanvas, this.overlay]) {
                cv.width = Math.max(1, Math.round(this.viewW * dpr));
                cv.height = Math.max(1, Math.round(this.viewH * dpr));
                cv.style.width = this.viewW + 'px';
                cv.style.height = this.viewH + 'px';
            }
            this.dpr = dpr;
            this._overlayDirty = true; // canvas resize cleared the overlay
        }

        _stepAnim() {
            if (!this.anim) return false;
            const t = Math.min(1, (performance.now() - this.anim.start) / this.anim.duration);
            const k = easeInOutQuad(t);
            const f = this.anim.from, to = this.anim.to;
            this.camera.cx = f.cx + (to.cx - f.cx) * k;
            this.camera.cy = f.cy + (to.cy - f.cy) * k;
            this.camera.scale = f.scale + (to.scale - f.scale) * k;
            if (t >= 1) this.anim = null;
            return true;
        }

        // Advance flow particles one frame; returns true while any remain alive.
        _stepParticles() {
            if (!this.particles.length) return false;
            const alive = [];
            for (const p of this.particles) {
                p.progress += p.speed;
                if (p.progress < 1) alive.push(p);
            }
            this.particles = alive;
            return alive.length > 0;
        }

        _draw() {
            if (this.destroyed) return;
            const t0 = performance.now();
            const animating = this._stepAnim();
            const particlesAlive = this._stepParticles();
            const gl = this.gl;
            const cam = this.camera;
            // Far zoom: collapse bezier to straight ribbons (same geometry, curve=0).
            const useCurve = cam.scale >= EDGE_CURVE_MIN_SCALE;
            const curveAmt = useCurve ? EDGE_CURVE : 0;
            // Edge width embeds cam.scale, so zoom must rebuild edge instances.
            const scaleKey = Math.round(cam.scale * 100);
            if (scaleKey !== this._lastEdgeScaleKey) {
                this._lastEdgeScaleKey = scaleKey;
                this._edgesDirty = true;
            }

            gl.viewport(0, 0, this.glCanvas.width, this.glCanvas.height);
            gl.clearColor(0, 0, 0, 0);
            gl.clear(gl.COLOR_BUFFER_BIT);

            // --- edges (rebuild only when topology/style/zoom changes)
            const edgeIds = Object.keys(this.body.edges);
            if (edgeIds.length) {
                if (this._edgesDirty || this._edgeDrawCount == null) {
                    if (this.edgeArr.length < edgeIds.length * EDGE_FLOATS) {
                        this.edgeArr = new Float32Array(Math.ceil(edgeIds.length * 1.3) * EDGE_FLOATS);
                    }
                    const arr = this.edgeArr;
                    let n = 0;
                    for (const id of edgeIds) {
                        const e = this.body.edges[id];
                        const a = this.body.nodes[e.fromId], b = this.body.nodes[e.toId];
                        if (!a || !b) continue;
                        const col = themeColor(e.options.color.color, isLightTheme());
                        const alpha = (e.options.color.opacity == null ? 1 : e.options.color.opacity) * 0.78;
                        let o = n * EDGE_FLOATS;
                        arr[o++] = a.x; arr[o++] = a.y; arr[o++] = b.x; arr[o++] = b.y;
                        // Width in screen px: at far zoom keep a 1px floor.
                        arr[o++] = Math.max(1, (e.options.width || 1) * (useCurve ? cam.scale : Math.max(cam.scale, 0.4)));
                        arr[o++] = col[0]; arr[o++] = col[1]; arr[o++] = col[2]; arr[o++] = col[3] * alpha;
                        arr[o++] = edgeBend(e.fromId, e.toId);
                        n++;
                    }
                    this._edgeDrawCount = n;
                    gl.bindVertexArray(this.edgeVAO);
                    gl.bindBuffer(gl.ARRAY_BUFFER, this.edgeInstBuf);
                    gl.bufferData(gl.ARRAY_BUFFER, arr.subarray(0, n * EDGE_FLOATS), gl.DYNAMIC_DRAW);
                    this._edgesDirty = false;
                }
                if (this._edgeDrawCount > 0) {
                    gl.useProgram(this.edgeProg);
                    this._applyUniforms(this.edgeU);
                    gl.uniform1f(this.edgeU.curve, curveAmt);
                    gl.bindVertexArray(this.edgeVAO);
                    gl.drawArraysInstanced(gl.TRIANGLE_STRIP, 0, (EDGE_SEGMENTS + 1) * 2, this._edgeDrawCount);
                }
            }

            // --- nodes + flow particles (rebuild when dirty or particles move)
            const nodeIds = Object.keys(this.body.nodes);
            this._cachedNodeCount = nodeIds.length;
            const needNodeRebuild = this._nodesDirty || particlesAlive || this.particles.length > 0;
            const maxInst = nodeIds.length + this.particles.length;
            if (maxInst > 0) {
                if (needNodeRebuild || this._nodeDrawCount == null) {
                    if (this.nodeArr.length < maxInst * NODE_FLOATS) {
                        this.nodeArr = new Float32Array(Math.ceil(maxInst * 1.3) * NODE_FLOATS);
                    }
                    const arr = this.nodeArr;
                    let n = 0;
                    for (const id of nodeIds) {
                        const bn = this.body.nodes[id];
                        const o = bn.options;
                        const selected = id === this.selectedNode;
                        const colObj = o.color || {};
                        const fillStr = selected && colObj.highlight ? colObj.highlight.background : colObj.background;
                        const borderStr = selected && colObj.highlight ? colObj.highlight.border : colObj.border;
                        const fill = parseColor(fillStr, [0.6, 0.6, 0.6, 1]);
                        const border = parseColor(borderStr, [0.3, 0.3, 0.3, 1]);
                        const op = o.opacity == null ? 1 : o.opacity;
                        let halfW, halfH, shape;
                        if (o.isGroup) {
                            halfW = Math.max(24, ((o.label || '').length * 7 + 16) / 2);
                            halfH = 13;
                            shape = 1;
                        } else {
                            halfW = halfH = o.size || 20;
                            shape = 0;
                        }
                        let k = n * NODE_FLOATS;
                        arr[k++] = bn.x; arr[k++] = bn.y;
                        arr[k++] = halfW; arr[k++] = halfH;
                        arr[k++] = fill[0]; arr[k++] = fill[1]; arr[k++] = fill[2]; arr[k++] = fill[3] * op;
                        arr[k++] = border[0]; arr[k++] = border[1]; arr[k++] = border[2]; arr[k++] = border[3] * op;
                        arr[k++] = shape;
                        n++;
                    }
                    for (const p of this.particles) {
                        const a = this.body.nodes[p.fromId], b = this.body.nodes[p.toId];
                        if (!a || !b) continue;
                        const alpha = 0.9 * (1 - p.progress * 0.4);
                        const c = p.color;
                        // Ride the same curve the edge ribbon draws (straight when LOD far).
                        const bend = useCurve ? edgeBend(p.fromId, p.toId) : 0;
                        const pos = edgeCurvePoint(a, b, p.progress, bend);
                        let k = n * NODE_FLOATS;
                        arr[k++] = pos.x;
                        arr[k++] = pos.y;
                        arr[k++] = 3.5; arr[k++] = 3.5;
                        arr[k++] = c[0]; arr[k++] = c[1]; arr[k++] = c[2]; arr[k++] = c[3] * alpha;
                        arr[k++] = c[0]; arr[k++] = c[1]; arr[k++] = c[2]; arr[k++] = c[3] * alpha;
                        arr[k++] = 0;
                        n++;
                    }
                    this._nodeDrawCount = n;
                    gl.bindVertexArray(this.nodeVAO);
                    gl.bindBuffer(gl.ARRAY_BUFFER, this.nodeInstBuf);
                    gl.bufferData(gl.ARRAY_BUFFER, arr.subarray(0, n * NODE_FLOATS), gl.DYNAMIC_DRAW);
                    this._nodesDirty = false;
                }
                if (this._nodeDrawCount > 0) {
                    gl.useProgram(this.nodeProg);
                    this._applyUniforms(this.nodeU);
                    gl.bindVertexArray(this.nodeVAO);
                    gl.drawArraysInstanced(gl.TRIANGLE_STRIP, 0, 4, this._nodeDrawCount);
                }
            }

            this._drawLabels();
            this._drawOverlay();
            this._lastFrameMs = performance.now() - t0;
            if (animating || particlesAlive) this.redraw();
        }

        _applyUniforms(u) {
            const gl = this.gl;
            gl.uniform2f(u.center, this.camera.cx, this.camera.cy);
            gl.uniform1f(u.scale, this.camera.scale * this.dpr);
            gl.uniform2f(u.view, this.glCanvas.width, this.glCanvas.height);
        }

        // Labels as instanced atlas-sprite quads. Selection (viewport cull, zoom
        // LOD, count cap) runs per frame in cheap JS; text rasterization happens
        // at most once per unique string (see _atlasSprite).
        _drawLabels() {
            const gl = this.gl;
            const cam = this.camera;
            const margin = 100;
            const gx0 = cam.cx - (this.viewW / 2 + margin) / cam.scale;
            const gx1 = cam.cx + (this.viewW / 2 + margin) / cam.scale;
            const gy0 = cam.cy - (this.viewH / 2 + margin) / cam.scale;
            const gy1 = cam.cy + (this.viewH / 2 + margin) / cam.scale;

            const optNodes = this.options.nodes || {};
            const nodeFont = optNodes.font || {};
            const labelScaling = optNodes.scaling && optNodes.scaling.label;
            const nodeLabelsEnabled = !(labelScaling && labelScaling.enabled === false);
            const fontPx = nodeFont.size || 14;
            const nodeFontFace = nodeFont.face || 'monospace';
            const defaultCol = parseColor(nodeFont.color || '#ffffff');

            const inst = [];
            if (nodeLabelsEnabled && fontPx * cam.scale >= 5) {
                const visible = [];
                for (const id in this.body.nodes) {
                    const n = this.body.nodes[id];
                    if (n.x < gx0 || n.x > gx1 || n.y < gy0 || n.y > gy1) continue;
                    if (!n.options.label) continue;
                    visible.push(n);
                }
                const MAX_LABELS = 250;
                if (visible.length > MAX_LABELS) {
                    visible.sort((a, b) => (b.options.size || 20) - (a.options.size || 20));
                    visible.length = MAX_LABELS;
                }
                for (const n of visible) {
                    const o = n.options;
                    const s = this._atlasSprite(o.label, fontPx, nodeFontFace);
                    if (!s) continue;
                    const col = (o.font && o.font.color) ? parseColor(o.font.color) : defaultCol;
                    const op = o.opacity == null ? 1 : o.opacity;
                    if (o.isGroup) {
                        inst.push(n.x, n.y, -s.w / 2, -s.h / 2, s.w, s.h,
                            s.u0, s.v0, s.u1, s.v1, col[0], col[1], col[2], col[3] * op);
                    } else {
                        inst.push(n.x, n.y, -s.w / 2, (o.size || 20) + 4, s.w, s.h,
                            s.u0, s.v0, s.u1, s.v1, col[0], col[1], col[2], col[3] * op);
                    }
                }
            }

            // Edge labels (already tier-gated by app.js via options.label),
            // anchored to the CURVE midpoint, with a length LOD: an edge whose
            // on-screen span is shorter than ~60px gets no label (the text
            // would be longer than the line — pure clutter).
            const edgeFont = (this.options.edges && this.options.edges.font) || {};
            const eFontPx = edgeFont.size || 11;
            const eFontFace = edgeFont.face || 'arial';
            const eCol = parseColor(edgeFont.color || '#ecf0f1');
            if (eFontPx * cam.scale >= 7) {
                const minSpanGraph = 60 / cam.scale;
                let drawn = 0;
                for (const id in this.body.edges) {
                    if (drawn > 300) break;
                    const e = this.body.edges[id];
                    if (!e.options.label) continue;
                    const a = this.body.nodes[e.fromId], b = this.body.nodes[e.toId];
                    if (!a || !b) continue;
                    if (Math.hypot(b.x - a.x, b.y - a.y) < minSpanGraph) continue;
                    const mid = edgeCurvePoint(a, b, 0.5, edgeBend(e.fromId, e.toId));
                    if (mid.x < gx0 || mid.x > gx1 || mid.y < gy0 || mid.y > gy1) continue;
                    const s = this._atlasSprite(e.options.label, eFontPx, eFontFace);
                    if (!s) continue;
                    const alpha = e.options.color.opacity == null ? 1 : e.options.color.opacity;
                    inst.push(mid.x, mid.y, -s.w / 2, -s.h / 2, s.w, s.h,
                        s.u0, s.v0, s.u1, s.v1, eCol[0], eCol[1], eCol[2], eCol[3] * alpha);
                    drawn++;
                }
            }

            const count = inst.length / LABEL_FLOATS;
            if (count === 0) return;
            this._uploadAtlasIfDirty();
            if (this.labelArr.length < inst.length) {
                this.labelArr = new Float32Array(Math.ceil(inst.length * 1.3));
            }
            this.labelArr.set(inst);
            gl.useProgram(this.labelProg);
            this._applyUniforms(this.labelU);
            // Halo color tracks the theme so text is readable over line work.
            const light = document.body.classList.contains('light-theme');
            const halo = light ? [1, 1, 1] : [0.10, 0.15, 0.20];
            gl.uniform3f(this.labelU.haloColor, halo[0], halo[1], halo[2]);
            gl.activeTexture(gl.TEXTURE0);
            gl.bindTexture(gl.TEXTURE_2D, this.atlasTex);
            gl.uniform1i(this.labelU.atlas, 0);
            gl.bindVertexArray(this.labelVAO);
            gl.bindBuffer(gl.ARRAY_BUFFER, this.labelInstBuf);
            gl.bufferData(gl.ARRAY_BUFFER, this.labelArr.subarray(0, inst.length), gl.DYNAMIC_DRAW);
            gl.drawArraysInstanced(gl.TRIANGLE_STRIP, 0, 4, count);
        }

        // 2D overlay: subnet rings only (labels moved to the GL atlas pass).
        // Drawn in graph coordinates under the camera transform so the existing
        // drawSubnetIslands hook works unchanged — and repainted ONLY when the
        // camera moved or invalidateOverlay() was called. During live traffic
        // (particles/easing animating every frame with a still camera) this
        // costs nothing, which is what Safari needs.
        _drawOverlay() {
            const cam = this.camera;
            const camSig = cam.cx + '|' + cam.cy + '|' + cam.scale + '|' + this.viewW + '|' + this.viewH;
            if (!this._overlayDirty && camSig === this._overlayCamSig) return;
            this._overlayCamSig = camSig;
            this._overlayDirty = false;

            const ctx = this.ctx2d;
            const s = cam.scale * this.dpr;
            ctx.setTransform(1, 0, 0, 1, 0, 0);
            ctx.clearRect(0, 0, this.overlay.width, this.overlay.height);
            ctx.setTransform(s, 0, 0, s,
                this.overlay.width / 2 - cam.cx * s,
                this.overlay.height / 2 - cam.cy * s);
            this._emit('beforeDrawing', ctx);
        }
    }

    window.GLNetwork = GLNetwork;
})();
