// cosmosrenderer.js — CosmosNetwork: cosmos.gl as a stable GPU *renderer* for
// the server-side solar-system layout (graph/solar.go).
//
// Design (forensic solar-system explorer, not a particle sandbox):
//   • Server owns positions (layout mode "solar") — no browser force sim.
//   • ownsLayout = false so app.js applies binary position frames + easing.
//   • Nodes are "planets": size by traffic, soft glow, stable orbits.
//   • Labels (name + primary IP) via HTML overlay with zoom LOD.
//   • Click / hover → same details + packet path as WebGL (app.js).
//   • Light flow particles along edges using body positions.
//   • Optional legacy raw mode still works but simulation stays OFF.
//
// vis-compat surface (same contract as GLNetwork):
//   on/off, redraw, setOptions, setSize, fit, focus, moveTo, selectNodes,
//   getScale, getPosition(s), getConnectedNodes/Edges, canvasToDOM/DOMtoCanvas,
//   destroy, body.nodes/edges, spawnParticles, markSceneDirty.

(function () {
    'use strict';

    const parseColor = window.parseRendererColor;
    const themeColor = window.themeProtocolColor || parseColor;
    const isLight = () => (window.isLightTheme ? window.isLightTheme() : false);

    // Cosmos internal space (library expects a square world). Server layout
    // coords are centred on 0; we map them into this space.
    const SPACE = 8192;
    const CENTER = SPACE / 2;
    // Server layout units → cosmos space (solar systems span ~thousands of px).
    const LAYOUT_SCALE = 1.0;
    const TOPO_REBUILD_MS = 80;   // add/remove only
    const STYLE_MS = 750;         // traffic recolor — deliberately slow (no size thrash)
    const MAX_LABELS = 60;
    const MAX_EDGE_LABELS = 14;   // only selected/hover neighborhood
    const MAX_PARTICLES = 40;     // static solar map; particles are accents only
    const LABEL_MIN_SCALE = 0.06;
    const LABEL_MAX_WIDTH = 168;  // px; long hostnames get a trailing ellipsis
    // Freeze planet radii after first paint — size pulsing with pps is the
    // main "jank" when coordinates are already stable.
    const FREEZE_SIZES = true;

    function idJitter(id) {
        let h = 2166136261;
        for (let i = 0; i < (id || '').length; i++) {
            h ^= id.charCodeAt(i);
            h = Math.imul(h, 16777619);
        }
        return {
            x: (((h >>> 0) % 4096) / 4096) - 0.5,
            y: (((h >>> 12) % 4096) / 4096) - 0.5
        };
    }

    function toCosmos(x, y) {
        return [CENTER + x * LAYOUT_SCALE, CENTER + y * LAYOUT_SCALE];
    }
    function fromCosmos(cx, cy) {
        return { x: (cx - CENTER) / LAYOUT_SCALE, y: (cy - CENTER) / LAYOUT_SCALE };
    }

    class CosmosNetwork {
        static isSupported() {
            if (!window.Cosmos || !window.Cosmos.Graph) return false;
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
            // Server solar layout owns positions — do NOT skip pos frames.
            this.ownsLayout = false;
            this.rawMode = false;
            this.destroyed = false;
            this.selectedNode = null;
            this.hoveredNode = null;

            this.indexToId = [];
            this.idToIndex = new Map();
            this._positions = null;
            this._dirty = false;       // topology (ids / links) changed
            this._styleDirty = false;  // colors / sizes / opacity only
            this._posDirty = false;    // body x/y eased
            this._rebuildTimer = null;
            this._builtOnce = false;
            this._userMovedCamera = false;
            this._lastTopoKey = '';
            this._adjacency = new Map();
            this.particles = [];
            this._particleRaf = 0;

            if (getComputedStyle(container).position === 'static') {
                container.style.position = 'relative';
            }
            // Starfield / void backdrop — theme-aware (SpaceX mission-control feel).
            this.backdrop = document.createElement('div');
            this.backdrop.className = 'cosmos-starfield';
            this._applyThemeBackdrop();
            container.appendChild(this.backdrop);

            // Soft planet atmospheres drawn under cosmos points.
            this.glowCanvas = document.createElement('canvas');
            this.glowCanvas.style.cssText =
                'position:absolute;inset:0;z-index:1;pointer-events:none;';
            container.appendChild(this.glowCanvas);
            this.glowCtx = this.glowCanvas.getContext('2d');

            this.div = document.createElement('div');
            this.div.style.cssText = 'position:absolute;inset:0;z-index:2;';
            container.appendChild(this.div);

            this.labelLayer = document.createElement('div');
            this.labelLayer.className = 'cosmos-labels';
            this.labelLayer.style.cssText =
                'position:absolute;inset:0;z-index:4;pointer-events:none;overflow:hidden;';
            container.appendChild(this.labelLayer);
            this._labelEls = new Map();
            this._edgeLabelEls = new Map();

            this.particleCanvas = document.createElement('canvas');
            this.particleCanvas.style.cssText =
                'position:absolute;inset:0;z-index:3;pointer-events:none;';
            container.appendChild(this.particleCanvas);
            this.particleCtx = this.particleCanvas.getContext('2d');

            const self = this;
            const light = isLight();
            this.graph = new Cosmos.Graph(this.div, {
                // Simulation OFF — server solar layout is the source of truth.
                enableSimulation: false,
                spaceSize: SPACE,
                backgroundColor: [0, 0, 0, 0],
                fitViewOnInit: false,
                enableDrag: false,
                // Fixed point size vs zoom — scalePointsOnZoom made planets
                // "breathe" while panning and felt unstable.
                scalePointsOnZoom: false,
                renderLinks: true,
                curvedLinks: false,
                renderHoveredPointRing: true,
                hoveredPointRingColor: light ? '#0f766e' : '#5eead4',
                focusedPointRingColor: light ? '#0369a1' : '#7dd3fc',
                pointSizeScale: 1.0,
                linkWidthScale: 1.2,
                linkGreyoutOpacity: 0.08,
                onClick: (index, pos, event) => self._onCosmosClick(index, event),
                onPointMouseOver: (index) => self._onCosmosHover(index),
                onPointMouseOut: () => self._onCosmosBlur(),
                onZoomStart: (e, userDriven) => {
                    if (userDriven) self._userMovedCamera = true;
                    self._emit('dragStart', { nodes: [] });
                },
                onZoom: () => {
                    // Defer overlay work to one rAF — raw zoom events fire a lot.
                    self._camMoved = true;
                    self._overlayNeedsPaint = true;
                    self.redraw();
                    self._emit('zoom', { scale: self.getScale() });
                },
            });

            // React to theme toggles without reload.
            this._themeObs = new MutationObserver(() => {
                self._applyThemeBackdrop();
                self._styleDirty = true;
                self.redraw();
            });
            this._themeObs.observe(document.body, { attributes: true, attributeFilter: ['class'] });

            this._syncAll();
            this._nodeSub = (event, props) => this._markDirty('nodes', event, props);
            this._edgeSub = (event, props) => this._markDirty('edges', event, props);
            this.nodesData.on('*', this._nodeSub);
            this.edgesData.on('*', this._edgeSub);
            this._rebuild();

            this._bindRectSelect();
            this._resizeParticles();
            if (window.ResizeObserver) {
                this._ro = new ResizeObserver(() => {
                    this._resizeParticles();
                    this._paintPlanetFX();
                    this._updateLabels();
                });
                this._ro.observe(container);
            }
        }

        _applyThemeBackdrop() {
            const light = isLight();
            if (light) {
                this.backdrop.style.cssText =
                    'position:absolute;inset:0;pointer-events:none;z-index:0;' +
                    'background:radial-gradient(ellipse at 50% 40%,' +
                    'rgba(226,232,240,1) 0%,rgba(241,245,249,1) 55%,rgba(226,232,240,1) 100%),' +
                    'radial-gradient(1px 1px at 12% 22%,rgba(15,23,42,0.12),transparent),' +
                    'radial-gradient(1px 1px at 78% 38%,rgba(15,23,42,0.1),transparent),' +
                    'radial-gradient(1px 1px at 42% 72%,rgba(15,23,42,0.08),transparent);' +
                    'background-color:#e8eef5;';
            } else {
                // Void black + sparse stars + faint horizon glow (mission control).
                this.backdrop.style.cssText =
                    'position:absolute;inset:0;pointer-events:none;z-index:0;' +
                    'background:radial-gradient(ellipse 80% 50% at 50% 100%,' +
                    'rgba(14,40,70,0.55) 0%,transparent 55%),' +
                    'radial-gradient(ellipse at center,rgba(8,12,22,0.2) 0%,rgba(2,4,10,1) 75%),' +
                    'radial-gradient(1.2px 1.2px at 10% 20%,rgba(255,255,255,0.55),transparent),' +
                    'radial-gradient(1px 1px at 80% 40%,rgba(180,210,255,0.4),transparent),' +
                    'radial-gradient(1px 1px at 40% 70%,rgba(255,255,255,0.35),transparent),' +
                    'radial-gradient(1.5px 1.5px at 65% 15%,rgba(125,211,252,0.5),transparent),' +
                    'radial-gradient(1px 1px at 25% 85%,rgba(255,255,255,0.25),transparent),' +
                    'radial-gradient(1px 1px at 90% 80%,rgba(255,255,255,0.2),transparent);' +
                    'background-color:#02040a;';
            }
        }

        // ----- DataSet → body mirror -----------------------------------------

        _syncAll() {
            for (const item of this.nodesData.get()) this._syncNode(item);
            for (const item of this.edgesData.get()) this._syncEdge(item);
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
            } else if (typeof item.x === 'number' && typeof item.y === 'number') {
                // Initial seed only when no render position yet; easing writes body.
                if (!this._builtOnce) {
                    bn.x = item.x;
                    bn.y = item.y;
                }
            }
            const o = bn.options;
            o.label = item.label;
            o.color = item.color || {};
            o.isGroup = item.shape === 'box' || item.isGroup;
            o.isSubnet = !!item.isSubnet;
            o.isTail = !!item.isTail;
            o.value = typeof item.value === 'number' ? item.value : null;
            o.size = typeof item.size === 'number' ? item.size : (o.size || 14);
            o.hostname = item.hostname || item.label;
            o.ips = item.ips || [];
            o.macs = item.macs || [];
            o.primaryMac = item.primaryMac || '';
            o.hostCount = item.hostCount;
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
                    edgeType: {
                        getPoint(t) {
                            const a = self.body.nodes[be.fromId];
                            const b = self.body.nodes[be.toId];
                            if (!a || !b) return { x: 0, y: 0 };
                            return {
                                x: a.x + (b.x - a.x) * t,
                                y: a.y + (b.y - a.y) * t
                            };
                        }
                    }
                };
            }
            be.fromId = item.from;
            be.toId = item.to;
            const o = be.options;
            const prevOpacity = o.color ? o.color.opacity : 1;
            // Protocol color from server (Slurm, SSH, HTTPS…) — match WebGL.
            const proto = item.protocol || {};
            const colStr = (item.color && item.color.color) ||
                proto.Color || proto.color || '#5a6a80';
            o.color = { color: colStr, opacity: prevOpacity == null ? 1 : prevOpacity };
            o.protocolName = proto.Name || proto.name || item.label || '';
            if (item.label !== undefined && item.label !== '' && item.label !== null) {
                o.label = item.label;
            } else if (o.protocolName) {
                o.label = o.protocolName;
            }
            o.width = typeof item.width === 'number' ? item.width : 1;
            o.packetCount = item.packetCount || 0;
        }

        _markDirty(kind, event, props) {
            if (this.destroyed) return;
            this._applyDelta(kind, event, props);
            // Adds/removes need a full topology rebuild; pure updates only
            // recolor (sizes stay frozen — traffic must not animate radii).
            const isRemove = event === 'remove';
            const isAdd = event === 'add';
            if (isRemove || isAdd) {
                this._dirty = true;
                if (this._topoTimer) clearTimeout(this._topoTimer);
                this._topoTimer = setTimeout(() => {
                    this._topoTimer = null;
                    if (this._dirty) this._rebuild();
                }, TOPO_REBUILD_MS);
            } else {
                this._styleDirty = true;
                if (!this._styleTimer) {
                    this._styleTimer = setTimeout(() => {
                        this._styleTimer = null;
                        if (this._styleDirty && !this._dirty) this._pushColorsOnly();
                    }, STYLE_MS);
                }
            }
        }

        _applyDelta(kind, event, props) {
            const ids = props && props.items;
            if (!ids || !ids.length) {
                this._resyncFromData();
                return;
            }
            const nodes = kind === 'nodes';
            if (event === 'remove') {
                const pool = nodes ? this.body.nodes : this.body.edges;
                for (const id of ids) delete pool[id];
                return;
            }
            const items = (nodes ? this.nodesData : this.edgesData).get(ids);
            for (const item of items) {
                if (!item) continue;
                if (nodes) this._syncNode(item);
                else this._syncEdge(item);
            }
        }

        _resyncFromData() {
            const seenN = new Set(), seenE = new Set();
            for (const item of this.nodesData.get()) { this._syncNode(item); seenN.add(item.id); }
            for (const item of this.edgesData.get()) { this._syncEdge(item); seenE.add(item.id); }
            for (const id in this.body.nodes) if (!seenN.has(id)) delete this.body.nodes[id];
            for (const id in this.body.edges) if (!seenE.has(id)) delete this.body.edges[id];
        }

        // ----- GPU upload (positions from body / server, no force sim) -------

        _rebuild() {
            if (this.destroyed || this.rawMode) return;
            this._dirty = false;
            this._styleDirty = false;

            // Stable lexicographic order — Object.keys order churn re-indexed the
            // GPU buffers and looked like random hopping under traffic.
            const ids = Object.keys(this.body.nodes).sort();
            const n = ids.length;
            this.indexToId = ids;
            const idToIndex = this.idToIndex = new Map();
            for (let i = 0; i < n; i++) idToIndex.set(ids[i], i);

            const pos = new Float32Array(n * 2);
            const colors = new Float32Array(n * 4);
            const sizes = new Float32Array(n);
            const shapes = new Float32Array(n);
            const light = isLight();

            let minV = Infinity, maxV = -Infinity, anyV = false;
            for (const id of ids) {
                const v = this.body.nodes[id].options.value;
                if (v == null) continue;
                anyV = true;
                if (v < minV) minV = v;
                if (v > maxV) maxV = v;
            }

            for (let i = 0; i < n; i++) {
                const bn = this.body.nodes[ids[i]];
                const o = bn.options;
                const [cx, cy] = toCosmos(bn.x || 0, bn.y || 0);
                pos[i * 2] = cx;
                pos[i * 2 + 1] = cy;

                const fillHex = (o.color && (o.color.background || o.color.color)) || '#38bdf8';
                const fill = themeColor(fillHex, light);
                // SpaceX craft: bright core, slight cool bias for hosts.
                const dim = o.opacity != null ? o.opacity : 1;
                colors[i * 4] = fill[0];
                colors[i * 4 + 1] = fill[1];
                colors[i * 4 + 2] = fill[2];
                colors[i * 4 + 3] = Math.min(1, 0.92 * dim);

                shapes[i] = 0; // always disc
                // Prefer previously frozen size so traffic restyles don't resize.
                if (FREEZE_SIZES && o._frozenSize > 0) {
                    sizes[i] = o._frozenSize;
                } else if (o.isSubnet || o.isTail) {
                    sizes[i] = 18 + Math.min(30, (o.hostCount || 4) * 0.12);
                } else if (o.isGroup) {
                    sizes[i] = 10;
                } else if (!anyV || maxV <= minV || o.value == null) {
                    sizes[i] = 12;
                } else {
                    sizes[i] = 8 + 18 * (o.value - minV) / (maxV - minV);
                }
                o.size = sizes[i];
                o._frozenSize = sizes[i];
            }

            const edgeIds = Object.keys(this.body.edges).sort();
            const linkPairs = [];
            const linkColors = [];
            const linkWidths = [];
            this._adjacency = new Map();
            for (const eid of edgeIds) {
                const be = this.body.edges[eid];
                const a = idToIndex.get(be.fromId);
                const b = idToIndex.get(be.toId);
                if (a === undefined || b === undefined) continue;
                linkPairs.push(a, b);
                const hex = (be.options.color && be.options.color.color) || '#64748b';
                const col = themeColor(hex, light);
                const eDim = be.options.color && be.options.color.opacity != null
                    ? be.options.color.opacity : 1;
                // Full protocol color (Slurm coral, etc.) — not washed-out grey.
                const aLink = Math.min(0.92, 0.72 * eDim + 0.15);
                linkColors.push(col[0], col[1], col[2], aLink);
                linkWidths.push(Math.max(1.1, Math.min(6.5, (be.options.width || 1) * 1.15)));
                let adj = this._adjacency.get(be.fromId);
                if (!adj) this._adjacency.set(be.fromId, adj = []);
                adj.push({ id: eid, other: be.toId });
                adj = this._adjacency.get(be.toId);
                if (!adj) this._adjacency.set(be.toId, adj = []);
                adj.push({ id: eid, other: be.fromId });
            }

            this._positions = pos;
            this.graph.setPointPositions(pos, false);
            this.graph.setPointColors(colors);
            this.graph.setPointSizes(sizes);
            if (this.graph.setPointShapes) this.graph.setPointShapes(shapes);
            this.graph.setLinks(new Float32Array(linkPairs));
            this.graph.setLinkColors(new Float32Array(linkColors));
            if (this.graph.setLinkWidths) this.graph.setLinkWidths(new Float32Array(linkWidths));
            this.graph.render();

            if (!this._builtOnce && n > 0) {
                this._builtOnce = true;
                this.graph.fitView(500);
            }
            this._paintPlanetFX();
            this._updateLabels();
        }

        // Push body positions into GPU without topology rebuild (easing path).
        // Only call when coordinates actually moved — avoids flicker under traffic.
        _pushPositions() {
            if (this.destroyed || this.rawMode || !this._builtOnce) return;
            const n = this.indexToId.length;
            if (!n) return;
            const pos = this._positions && this._positions.length === n * 2
                ? this._positions : new Float32Array(n * 2);
            let moved = false;
            for (let i = 0; i < n; i++) {
                const bn = this.body.nodes[this.indexToId[i]];
                if (!bn) continue;
                const [cx, cy] = toCosmos(bn.x || 0, bn.y || 0);
                const oi = i * 2;
                if (!moved && (Math.abs(pos[oi] - cx) > 0.05 || Math.abs(pos[oi + 1] - cy) > 0.05)) {
                    moved = true;
                }
                pos[oi] = cx;
                pos[oi + 1] = cy;
            }
            this._positions = pos;
            if (!moved && this._positions) {
                // Still refresh labels on camera; skip GPU position write.
                return false;
            }
            this.graph.setPointPositions(pos, false);
            this.graph.render();
            // Positions rarely move on solar — FX/labels only if something actually moved.
            this._paintPlanetFX();
            this._updateLabels();
            return true;
        }

        // Traffic restyle: recolor points + links only. Never change sizes or
        // widths (those pulse with pps and read as jank). No label/FX work.
        _pushColorsOnly() {
            if (this.destroyed || this.rawMode || !this._builtOnce) return;
            this._styleDirty = false;
            const n = this.indexToId.length;
            if (!n) return;
            const light = isLight();
            const colors = new Float32Array(n * 4);
            for (let i = 0; i < n; i++) {
                const bn = this.body.nodes[this.indexToId[i]];
                if (!bn) continue;
                const o = bn.options;
                const fill = themeColor(
                    (o.color && (o.color.background || o.color.color)) || '#38bdf8',
                    light
                );
                const dim = o.opacity != null ? o.opacity : 1;
                colors[i * 4] = fill[0];
                colors[i * 4 + 1] = fill[1];
                colors[i * 4 + 2] = fill[2];
                colors[i * 4 + 3] = Math.min(1, 0.92 * dim);
            }
            this.graph.setPointColors(colors);
            const linkColors = [];
            for (const eid of Object.keys(this.body.edges).sort()) {
                const be = this.body.edges[eid];
                if (!this.idToIndex.has(be.fromId) || !this.idToIndex.has(be.toId)) continue;
                const hex = (be.options.color && be.options.color.color) || '#64748b';
                const col = themeColor(hex, light);
                const eDim = be.options.color && be.options.color.opacity != null
                    ? be.options.color.opacity : 1;
                const aLink = Math.min(0.92, 0.72 * eDim + 0.15);
                linkColors.push(col[0], col[1], col[2], aLink);
            }
            this.graph.setLinkColors(new Float32Array(linkColors));
            this.graph.render();
            // Intentionally skip _paintPlanetFX / _updateLabels — camera &
            // selection own those; traffic must not thrash the DOM/GPU.
        }

        _pushStyleAndSizes() { this._pushColorsOnly(); }
        _pushStyleArrays() { this._pushColorsOnly(); }

        // SpaceX-inspired planet atmospheres: soft glow disc + thin rim ring
        // under the cosmos point sprites (mission-control craft aesthetic).
        _paintPlanetFX() {
            if (this.destroyed || !this.glowCtx) return;
            const ctx = this.glowCtx;
            const w = this.container.clientWidth || 1;
            const h = this.container.clientHeight || 1;
            ctx.clearRect(0, 0, w, h);
            if (!this._builtOnce) return;
            const light = isLight();
            const scale = this.getScale();

            for (const id of this.indexToId) {
                const bn = this.body.nodes[id];
                if (!bn) continue;
                const o = bn.options || {};
                const dim = o.opacity != null ? o.opacity : 1;
                if (dim < 0.05) continue;
                const dom = this.canvasToDOM({ x: bn.x || 0, y: bn.y || 0 });
                if (dom.x < -80 || dom.y < -80 || dom.x > w + 80 || dom.y > h + 80) continue;

                const fillHex = (o.color && (o.color.background || o.color.color)) || '#38bdf8';
                const c = themeColor(fillHex, light);
                const r = Math.max(4, ((o.size || 12) * 0.55) * Math.min(2.2, Math.max(0.4, scale * 0.9)));
                const selected = id === this.selectedNode || id === this.hoveredNode;

                // Outer atmosphere
                const g = ctx.createRadialGradient(dom.x, dom.y, r * 0.15, dom.x, dom.y, r * 2.4);
                g.addColorStop(0, rgba(c, 0.55 * dim));
                g.addColorStop(0.35, rgba(c, 0.22 * dim));
                g.addColorStop(1, rgba(c, 0));
                ctx.beginPath();
                ctx.fillStyle = g;
                ctx.arc(dom.x, dom.y, r * 2.4, 0, Math.PI * 2);
                ctx.fill();

                // Specular highlight (sun glint)
                const hx = dom.x - r * 0.28, hy = dom.y - r * 0.32;
                const sg = ctx.createRadialGradient(hx, hy, 0, hx, hy, r * 0.7);
                sg.addColorStop(0, light ? 'rgba(255,255,255,0.55)' : 'rgba(255,255,255,0.45)');
                sg.addColorStop(1, 'rgba(255,255,255,0)');
                ctx.beginPath();
                ctx.fillStyle = sg;
                ctx.arc(dom.x, dom.y, r * 0.95, 0, Math.PI * 2);
                ctx.fill();

                // Thin orbital / hull ring for hubs + selection
                if (selected || (o.size || 0) > 18 || o.isSubnet) {
                    ctx.beginPath();
                    ctx.strokeStyle = selected
                        ? (light ? 'rgba(8,145,178,0.9)' : 'rgba(94,234,212,0.85)')
                        : rgba(c, 0.45 * dim);
                    ctx.lineWidth = selected ? 1.6 : 1.1;
                    ctx.arc(dom.x, dom.y, r * 1.35, 0, Math.PI * 2);
                    ctx.stroke();
                }
            }
        }

        // ----- Labels (name + IP) --------------------------------------------

        _planetLabel(bn) {
            const o = bn.options || {};
            let name = o.hostname || o.label || bn.id;
            // Avoid showing raw MAC as the only title when we have a hostname.
            if (o.primaryMac && name === o.primaryMac && o.ips && o.ips.length) {
                name = o.ips[0];
            }
            let ip = '';
            if (o.ips && o.ips.length) {
                ip = o.ips.find(x => /^\d+\.\d+\.\d+\.\d+$/.test(x)) || o.ips[0];
            } else if (/^\d+\.\d+\.\d+\.\d+$/.test(bn.id)) {
                ip = bn.id;
            }
            if (o.isSubnet) {
                return { title: name, sub: (o.hostCount || '?') + ' hosts' };
            }
            if (o.isTail) {
                return { title: name, sub: 'quieter hosts' };
            }
            if (o.isGroup) {
                return { title: name, sub: 'group' };
            }
            // Name + IP stay glued to the identifier (forensic map).
            const sub = ip && ip !== name ? ip : (o.primaryMac || '');
            return { title: name, sub };
        }

        _labelChrome() {
            const light = isLight();
            return light
                ? {
                    color: 'rgba(15,23,42,0.92)',
                    sub: 'rgba(51,65,85,0.85)',
                    shadow: '0 0 4px rgba(255,255,255,0.9),0 1px 2px rgba(255,255,255,0.7)',
                    edgeBg: 'rgba(255,255,255,0.82)',
                    edgeFg: 'rgba(15,23,42,0.9)'
                }
                : {
                    color: 'rgba(241,245,249,0.95)',
                    sub: 'rgba(148,163,184,0.92)',
                    shadow: '0 0 8px rgba(0,0,0,0.95),0 1px 2px rgba(0,0,0,0.9)',
                    edgeBg: 'rgba(2,6,14,0.78)',
                    edgeFg: 'rgba(226,232,240,0.95)'
                };
        }

        _updateLabels() {
            if (this.destroyed || !this.labelLayer) return;
            const scale = this.getScale();
            const keep = new Set();
            const chrome = this._labelChrome();
            if (scale < LABEL_MIN_SCALE) {
                for (const [, el] of this._labelEls) el.style.display = 'none';
                for (const [, el] of this._edgeLabelEls) el.style.display = 'none';
                return;
            }

            // Rank by size (traffic) for LOD cap.
            const ranked = [];
            for (const id of this.indexToId) {
                const bn = this.body.nodes[id];
                if (!bn) continue;
                ranked.push({ id, bn, size: (bn.options && bn.options.size) || 10 });
            }
            ranked.sort((a, b) => b.size - a.size);
            const budget = scale > 0.35 ? MAX_LABELS : Math.min(36, MAX_LABELS);
            const w = this.container.clientWidth, h = this.container.clientHeight;

            for (let i = 0; i < ranked.length && i < budget; i++) {
                const { id, bn } = ranked[i];
                const screen = this.graph.spaceToScreenPosition(
                    toCosmos(bn.x || 0, bn.y || 0)
                );
                if (!screen) continue;
                const sx = screen[0], sy = screen[1];
                if (sx < -40 || sy < -20 || sx > w + 40 || sy > h + 20) continue;
                keep.add(id);
                let el = this._labelEls.get(id);
                if (!el) {
                    el = document.createElement('div');
                    el.className = 'cosmos-planet-label';
                    this.labelLayer.appendChild(el);
                    this._labelEls.set(id, el);
                }
                el.style.cssText =
                    'position:absolute;transform:translate(-50%,8px);' +
                    'text-align:center;pointer-events:none;white-space:nowrap;' +
                    'max-width:' + LABEL_MAX_WIDTH + 'px;' +
                    'font:600 11px/1.25 "IBM Plex Mono",ui-monospace,Menlo,monospace;' +
                    'letter-spacing:0.02em;color:' + chrome.color + ';' +
                    'text-shadow:' + chrome.shadow + ';';
                const { title, sub } = this._planetLabel(bn);
                // Trailing-ellipsis truncation lives on the text lines themselves;
                // the wrapper is centered, so it can't clip. Full name stays on
                // the hover tooltip and details panel.
                const clip = 'overflow:hidden;text-overflow:ellipsis;';
                const html = sub
                    ? `<div style="${clip}">${escapeHtml(title)}</div>` +
                      `<div style="${clip}font-weight:500;font-size:10px;color:${chrome.sub}">${escapeHtml(sub)}</div>`
                    : `<div style="${clip}">${escapeHtml(title)}</div>`;
                if (el._html !== html) {
                    el.innerHTML = html;
                    el._html = html;
                }
                el.style.display = '';
                el.style.left = sx + 'px';
                el.style.top = sy + 'px';
            }
            for (const [id, el] of this._labelEls) {
                if (!keep.has(id)) el.style.display = 'none';
            }

            // Protocol labels on the busiest links (Slurm, SSH, …) like WebGL.
            this._updateEdgeLabels(chrome, scale, w, h);
        }

        _updateEdgeLabels(chrome, scale, w, h) {
            // Only label edges of the focused/hovered host — labeling every
            // DNS/TCP link was visual noise and DOM thrash under traffic.
            const focus = this.selectedNode || this.hoveredNode;
            if (!focus || scale < 0.1) {
                for (const [, el] of this._edgeLabelEls) el.style.display = 'none';
                return;
            }
            const adj = this._adjacency && this._adjacency.get(focus);
            if (!adj || !adj.length) {
                for (const [, el] of this._edgeLabelEls) el.style.display = 'none';
                return;
            }
            const ranked = [];
            for (const { id: eid } of adj) {
                const be = this.body.edges[eid];
                if (!be) continue;
                const a = this.body.nodes[be.fromId], b = this.body.nodes[be.toId];
                if (!a || !b) continue;
                const name = be.options.protocolName || be.options.label || '';
                if (!name) continue;
                ranked.push({ eid, be, a, b, name, pkts: be.options.packetCount || 0 });
            }
            ranked.sort((x, y) => y.pkts - x.pkts);
            const keepE = new Set();
            for (let i = 0; i < ranked.length && i < MAX_EDGE_LABELS; i++) {
                const { eid, be, a, b, name } = ranked[i];
                const mx = (a.x + b.x) / 2, my = (a.y + b.y) / 2;
                const dom = this.canvasToDOM({ x: mx, y: my });
                if (dom.x < 0 || dom.y < 0 || dom.x > w || dom.y > h) continue;
                keepE.add(eid);
                let el = this._edgeLabelEls.get(eid);
                if (!el) {
                    el = document.createElement('div');
                    el.className = 'cosmos-edge-label';
                    this.labelLayer.appendChild(el);
                    this._edgeLabelEls.set(eid, el);
                }
                const hex = (be.options.color && be.options.color.color) || '#94a3b8';
                el.style.cssText =
                    'position:absolute;transform:translate(-50%,-50%);pointer-events:none;' +
                    'font:600 9px/1 "IBM Plex Mono",ui-monospace,Menlo,monospace;' +
                    'letter-spacing:0.04em;text-transform:uppercase;' +
                    'padding:2px 6px;border-radius:999px;' +
                    'background:' + chrome.edgeBg + ';color:' + chrome.edgeFg + ';' +
                    'border:1px solid ' + hex + '99;' +
                    'box-shadow:0 0 12px ' + hex + '33;';
                if (el.textContent !== name) el.textContent = name;
                el.style.display = '';
                el.style.left = dom.x + 'px';
                el.style.top = dom.y + 'px';
            }
            for (const [eid, el] of this._edgeLabelEls) {
                if (!keepE.has(eid)) el.style.display = 'none';
            }
        }

        // ----- Raw topology (optional; still no bouncing sim) ----------------

        setRawTopology(frame, protos) {
            if (this.destroyed) return;
            this.rawMode = true;
            const n = frame.ids.length;
            const prevIndex = this.idToIndex;
            const prevPos = this._positions;

            this.indexToId = frame.ids.slice();
            const idToIndex = this.idToIndex = new Map();
            for (let i = 0; i < n; i++) idToIndex.set(frame.ids[i], i);

            // Deterministic solar-ish ring placement by subnet hash (no force).
            const systems = new Map();
            for (let i = 0; i < n; i++) {
                const key = subnetKey(frame.ids[i]);
                if (!systems.has(key)) systems.set(key, []);
                systems.get(key).push(i);
            }
            const sysKeys = [...systems.keys()].sort();
            const pos = new Float32Array(n * 2);
            const colors = new Float32Array(n * 4);
            const sizes = new Float32Array(n);
            const shapes = new Float32Array(n);
            const TIER = [
                [0.45, 0.58, 0.72, 0.85],
                [0.30, 0.65, 0.90, 1],
                [0.18, 0.75, 0.62, 1],
                [0.95, 0.72, 0.25, 1],
                [0.92, 0.33, 0.28, 1],
            ];

            sysKeys.forEach((key, si) => {
                const members = systems.get(key);
                const ring = Math.floor(si / 12);
                const slot = si % 12;
                const j = idJitter(key);
                const sysA = (slot / 12) * Math.PI * 2 + j.x;
                const sysR = SPACE * 0.12 + ring * SPACE * 0.08 + Math.abs(j.y) * 40;
                const starX = CENTER + Math.cos(sysA) * sysR;
                const starY = CENTER + Math.sin(sysA) * sysR;
                members.forEach((i, rank) => {
                    const id = frame.ids[i];
                    const pi = prevIndex.get(id);
                    if (pi !== undefined && prevPos && prevPos.length > pi * 2 + 1) {
                        pos[i * 2] = prevPos[pi * 2];
                        pos[i * 2 + 1] = prevPos[pi * 2 + 1];
                    } else if (rank === 0) {
                        pos[i * 2] = starX;
                        pos[i * 2 + 1] = starY;
                    } else {
                        const mj = idJitter(id);
                        const a = mj.x * Math.PI * 2;
                        const r = 25 + rank * 18;
                        pos[i * 2] = starX + Math.cos(a) * r;
                        pos[i * 2 + 1] = starY + Math.sin(a) * r;
                    }
                    // Mirror into body so details/hit helpers work.
                    let bn = this.body.nodes[id];
                    if (!bn) {
                        bn = this.body.nodes[id] = { id, x: 0, y: 0, options: { opacity: 1 } };
                    }
                    const gp = fromCosmos(pos[i * 2], pos[i * 2 + 1]);
                    bn.x = gp.x;
                    bn.y = gp.y;
                    const c = TIER[Math.min(frame.tiers[i], 4)];
                    colors[i * 4] = c[0];
                    colors[i * 4 + 1] = c[1];
                    colors[i * 4 + 2] = c[2];
                    colors[i * 4 + 3] = c[3];
                    const group = (frame.flags[i] & 1) !== 0;
                    shapes[i] = group ? 1 : 0;
                    sizes[i] = group ? 5 : 6 + frame.tiers[i] * 3;
                    bn.options.size = sizes[i];
                    bn.options.label = id;
                    bn.options.hostname = id;
                });
            });

            const m = frame.protoIdx.length;
            const linkColors = new Float32Array(m * 4);
            for (let i = 0; i < m; i++) {
                const p = protos && protos[frame.protoIdx[i]];
                const c = parseColor(p && p.color, [0.5, 0.5, 0.5, 1]);
                linkColors[i * 4] = c[0];
                linkColors[i * 4 + 1] = c[1];
                linkColors[i * 4 + 2] = c[2];
                linkColors[i * 4 + 3] = 0.28;
            }

            this._positions = pos;
            this.graph.setPointPositions(pos, false);
            this.graph.setPointColors(colors);
            this.graph.setPointSizes(sizes);
            if (this.graph.setPointShapes) this.graph.setPointShapes(shapes);
            this.graph.setLinks(frame.links);
            this.graph.setLinkColors(linkColors);
            this.graph.render();
            if (!this._builtOnce && n > 0) {
                this._builtOnce = true;
                this.graph.fitView(600);
            }
            this._updateLabels();
        }

        // ----- Events --------------------------------------------------------

        _onCosmosClick(index, event) {
            this._clearRectSelection();
            const id = index !== undefined ? this.indexToId[index] : undefined;
            const p = event ? { x: event.offsetX, y: event.offsetY } : { x: 0, y: 0 };
            this.selectedNode = id || null;
            if (this.graph.setConfigPartial) {
                this.graph.setConfigPartial({ focusedPointIndex: index });
            }
            this._overlayNeedsPaint = true;
            this._paintPlanetFX();
            this._updateLabels(); // edge pills for selection
            this._emit('click', {
                nodes: id !== undefined ? [id] : [],
                edges: id !== undefined ? this.getConnectedEdges(id) : [],
                pointer: { DOM: p, canvas: this.DOMtoCanvas(p) }
            });
        }

        _onCosmosHover(index) {
            const id = this.indexToId[index];
            if (id === undefined) return;
            if (this.hoveredNode && this.hoveredNode !== id) {
                this._emit('blurNode', { node: this.hoveredNode });
            }
            this.hoveredNode = id;
            this._updateLabels(); // protocol pills for hover neighborhood
            this._paintPlanetFX();
            this._emit('hoverNode', { node: id });
        }

        _onCosmosBlur() {
            if (this.hoveredNode) {
                this._emit('blurNode', { node: this.hoveredNode });
                this.hoveredNode = null;
                this._updateLabels();
                this._paintPlanetFX();
            }
        }

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

        // ----- Camera / coordinates (graph space, not cosmos space) ----------

        getScale() {
            // Map cosmos zoom to something app.js zoom-band logic understands.
            const z = this.graph.getZoomLevel ? this.graph.getZoomLevel() : 1;
            return typeof z === 'number' && z > 0 ? z : 1;
        }
        canvasToDOM(p) {
            const [cx, cy] = toCosmos(p.x, p.y);
            const s = this.graph.spaceToScreenPosition([cx, cy]);
            return { x: s[0], y: s[1] };
        }
        DOMtoCanvas(p) {
            const s = this.graph.screenToSpacePosition([p.x, p.y]);
            return fromCosmos(s[0], s[1]);
        }
        _posOf(id) {
            const n = this.body.nodes[id];
            if (n) return { x: n.x, y: n.y };
            return null;
        }
        getPosition(id) { return this._posOf(id) || { x: 0, y: 0 }; }
        getPositions(ids) {
            const out = {};
            const list = ids || Object.keys(this.body.nodes);
            for (const id of list) {
                const p = this._posOf(id);
                if (p) out[id] = p;
            }
            return out;
        }
        getConnectedNodes(id) {
            const adj = this._adjacency && this._adjacency.get(id);
            return adj ? adj.map(a => a.other) : [];
        }
        getConnectedEdges(id) {
            const adj = this._adjacency && this._adjacency.get(id);
            return adj ? adj.map(a => a.id) : [];
        }
        selectNodes(ids) {
            this.selectedNode = ids && ids.length ? ids[0] : null;
            const idx = this.selectedNode != null ? this.idToIndex.get(this.selectedNode) : undefined;
            if (this.graph.setConfigPartial) {
                this.graph.setConfigPartial({ focusedPointIndex: idx });
            }
        }
        setOptions(options) { this.options = Object.assign({}, this.options, options); }
        setSize() { this._resizeParticles(); this._updateLabels(); }

        fit(opts) {
            const dur = opts && opts.animation ? (opts.animation.duration || 400) : 0;
            this.graph.fitView(dur);
            setTimeout(() => this._updateLabels(), dur + 20);
        }
        focus(id, opts) {
            const idx = this.idToIndex.get(id);
            if (idx === undefined) return;
            const dur = opts && opts.animation ? (opts.animation.duration || 500) : 500;
            if (this.graph.zoomToPointByIndex) {
                this.graph.zoomToPointByIndex(idx, dur, opts && opts.scale);
            }
            this.selectNodes([id]);
            setTimeout(() => this._updateLabels(), dur + 20);
        }
        moveTo(opts) {
            if (opts.scale != null && this.graph.setZoomLevel) {
                this.graph.setZoomLevel(opts.scale, opts.animation ? 300 : 0);
            }
        }

        // Called by app when body positions change or focus dims.
        markSceneDirty(kind) {
            if (kind === 'nodes' || kind === 'all' || kind == null) {
                this._posDirty = true;
            }
            if (kind === 'edges' || kind === 'all') {
                // Focus dim = opacity only; treat as color restyle (throttled).
                this._styleDirty = true;
                if (!this._styleTimer) {
                    this._styleTimer = setTimeout(() => {
                        this._styleTimer = null;
                        if (this._styleDirty && !this._dirty) this._pushColorsOnly();
                    }, 50); // focus should feel snappy
                }
            }
            this.redraw();
        }

        redraw() {
            if (this.destroyed || !this._builtOnce) return;
            if (this._redrawQueued) return;
            this._redrawQueued = true;
            requestAnimationFrame(() => {
                this._redrawQueued = false;
                if (this.destroyed) return;
                let moved = false;
                if (this._posDirty) {
                    this._posDirty = false;
                    moved = !!this._pushPositions();
                }
                // Camera-only redraws (zoom/pan) refresh overlays without GPU style work.
                if (!moved && (this._overlayNeedsPaint || this._camMoved)) {
                    this._camMoved = false;
                    this._overlayNeedsPaint = false;
                    this._paintPlanetFX();
                    this._updateLabels();
                }
            });
        }

        // ----- Flow particles (light trails between planets) -----------------

        spawnParticles(flows) {
            if (this.destroyed || this.rawMode) return;
            // Hard cap: solar map is meant to feel still; a few streaks only.
            let added = 0;
            for (const f of flows) {
                if (added >= 8) break;
                if (!this.body.nodes[f.fromId] || !this.body.nodes[f.toId]) continue;
                this.particles.push({
                    fromId: f.fromId,
                    toId: f.toId,
                    color: f.color || '#7fd3ff',
                    progress: 0,
                    speed: f.speed || 0.025
                });
                added++;
            }
            if (this.particles.length > MAX_PARTICLES) {
                this.particles.splice(0, this.particles.length - MAX_PARTICLES);
            }
            this._startParticleLoop();
        }

        _resizeParticles() {
            const w = this.container.clientWidth || 1;
            const h = this.container.clientHeight || 1;
            const dpr = Math.min(window.devicePixelRatio || 1, 2);
            for (const [canvas, ctxName] of [
                [this.particleCanvas, 'particleCtx'],
                [this.glowCanvas, 'glowCtx']
            ]) {
                if (!canvas) continue;
                canvas.width = w * dpr;
                canvas.height = h * dpr;
                canvas.style.width = w + 'px';
                canvas.style.height = h + 'px';
                const ctx = this[ctxName];
                if (ctx) ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
            }
        }

        _startParticleLoop() {
            if (this._particleRaf) return;
            const step = () => {
                this._particleRaf = 0;
                if (this.destroyed) return;
                const ctx = this.particleCtx;
                const w = this.container.clientWidth;
                const h = this.container.clientHeight;
                ctx.clearRect(0, 0, w, h);
                const alive = [];
                for (const p of this.particles) {
                    p.progress += p.speed;
                    if (p.progress >= 1) continue;
                    const a = this.body.nodes[p.fromId];
                    const b = this.body.nodes[p.toId];
                    if (!a || !b) continue;
                    const gx = a.x + (b.x - a.x) * p.progress;
                    const gy = a.y + (b.y - a.y) * p.progress;
                    const dom = this.canvasToDOM({ x: gx, y: gy });
                    const alpha = 0.85 * (1 - p.progress * 0.5);
                    ctx.beginPath();
                    ctx.fillStyle = cssWithAlpha(p.color, alpha);
                    ctx.arc(dom.x, dom.y, 2.2, 0, Math.PI * 2);
                    ctx.fill();
                    alive.push(p);
                }
                this.particles = alive;
                if (alive.length) {
                    this._particleRaf = requestAnimationFrame(step);
                }
            };
            this._particleRaf = requestAnimationFrame(step);
        }

        // ----- Rect select ---------------------------------------------------

        _bindRectSelect() {
            const self = this;
            this._rectEl = null;
            this._rectStart = null;
            this._rsDown = (e) => {
                if (!e.shiftKey || e.button !== 0) return;
                e.preventDefault();
                e.stopPropagation();
                self._rectStart = { x: e.offsetX, y: e.offsetY };
                const r = document.createElement('div');
                r.style.cssText = 'position:absolute;border:1px dashed #f5d76e;' +
                    'background:rgba(245,215,110,0.12);pointer-events:none;z-index:10;';
                self.container.appendChild(r);
                self._rectEl = r;
            };
            this._rsMove = (e) => {
                if (!self._rectStart || !self._rectEl) return;
                const x0 = Math.min(self._rectStart.x, e.offsetX), x1 = Math.max(self._rectStart.x, e.offsetX);
                const y0 = Math.min(self._rectStart.y, e.offsetY), y1 = Math.max(self._rectStart.y, e.offsetY);
                Object.assign(self._rectEl.style, {
                    left: x0 + 'px', top: y0 + 'px', width: (x1 - x0) + 'px', height: (y1 - y0) + 'px'
                });
            };
            this._rsUp = (e) => {
                if (!self._rectStart) return;
                const start = self._rectStart;
                self._rectStart = null;
                if (self._rectEl) { self._rectEl.remove(); self._rectEl = null; }
                const x0 = Math.min(start.x, e.offsetX), x1 = Math.max(start.x, e.offsetX);
                const y0 = Math.min(start.y, e.offsetY), y1 = Math.max(start.y, e.offsetY);
                if (x1 - x0 < 4 && y1 - y0 < 4) return;
                const indices = (self.graph.findPointsInRect &&
                    self.graph.findPointsInRect([[x0, y0], [x1, y1]])) || [];
                self._applyRectSelection(indices.map(i => self.indexToId[i]).filter(Boolean));
            };
            this.container.addEventListener('mousedown', this._rsDown, true);
            this.container.addEventListener('mousemove', this._rsMove, true);
            this.container.addEventListener('mouseup', this._rsUp, true);
        }

        _applyRectSelection(ids) {
            this._rectSelection = new Set(ids);
            for (const id in this.body.nodes) {
                this.body.nodes[id].options.opacity =
                    (!ids.length || this._rectSelection.has(id)) ? 1 : 0.12;
            }
            for (const eid in this.body.edges) {
                const be = this.body.edges[eid];
                if (be.options.color) {
                    be.options.color.opacity =
                        (!ids.length || (this._rectSelection.has(be.fromId) &&
                            this._rectSelection.has(be.toId))) ? 1 : 0.06;
                }
            }
            this._styleDirty = true;
            this.redraw();
            let badge = document.getElementById('cosmosRectBadge');
            if (!ids.length) {
                if (badge) badge.remove();
                return;
            }
            if (!badge) {
                badge = document.createElement('div');
                badge.id = 'cosmosRectBadge';
                badge.style.cssText = 'position:absolute;top:12px;right:12px;z-index:20;' +
                    'padding:6px 10px;border-radius:6px;background:rgba(25,30,40,0.9);' +
                    'color:#f5d76e;font:12px sans-serif;pointer-events:none;';
                this.container.appendChild(badge);
            }
            badge.textContent = ids.length + ' host' + (ids.length === 1 ? '' : 's') + ' selected';
        }

        _clearRectSelection() {
            if (!this._rectSelection || !this._rectSelection.size) return;
            this._applyRectSelection([]);
            this._rectSelection = null;
        }

        destroy() {
            this.destroyed = true;
            this.nodesData.off('*', this._nodeSub);
            this.edgesData.off('*', this._edgeSub);
            if (this._rebuildTimer) clearTimeout(this._rebuildTimer);
            if (this._topoTimer) clearTimeout(this._topoTimer);
            if (this._styleTimer) clearTimeout(this._styleTimer);
            if (this._particleRaf) cancelAnimationFrame(this._particleRaf);
            if (this._ro) this._ro.disconnect();
            if (this._themeObs) this._themeObs.disconnect();
            this.container.removeEventListener('mousedown', this._rsDown, true);
            this.container.removeEventListener('mousemove', this._rsMove, true);
            this.container.removeEventListener('mouseup', this._rsUp, true);
            try { this.graph.destroy(); } catch (e) { /* already gone */ }
            for (const el of [this.div, this.labelLayer, this.particleCanvas, this.glowCanvas, this.backdrop]) {
                if (el && el.parentNode) el.parentNode.removeChild(el);
            }
        }
    }

    function subnetKey(id) {
        if (typeof id !== 'string') return 'other';
        let m = /^(\d+)\.(\d+)\.(\d+)\./.exec(id);
        if (m) return m[1] + '.' + m[2] + '.' + m[3];
        m = /^(\d+)\.(\d+)\./.exec(id);
        if (m) return m[1] + '.' + m[2];
        return 'other';
    }

    function escapeHtml(s) {
        return String(s == null ? '' : s)
            .replace(/&/g, '&amp;').replace(/</g, '&lt;')
            .replace(/>/g, '&gt;').replace(/"/g, '&quot;');
    }

    function rgba(c, a) {
        return 'rgba(' + Math.round(c[0] * 255) + ',' +
            Math.round(c[1] * 255) + ',' + Math.round(c[2] * 255) + ',' + a + ')';
    }

    function cssWithAlpha(css, a) {
        if (!css) return 'rgba(127,211,255,' + a + ')';
        if (css.startsWith('#')) {
            let h = css.slice(1);
            if (h.length === 3) h = h[0] + h[0] + h[1] + h[1] + h[2] + h[2];
            const r = parseInt(h.slice(0, 2), 16);
            const g = parseInt(h.slice(2, 4), 16);
            const b = parseInt(h.slice(4, 6), 16);
            return 'rgba(' + r + ',' + g + ',' + b + ',' + a + ')';
        }
        return css;
    }

    window.CosmosNetwork = CosmosNetwork;
})();
