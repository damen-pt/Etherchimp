// cosmosrenderer.js — CosmosNetwork: a cosmos.gl-backed renderer that stands in
// for vis.Network / GLNetwork, with the FORCE LAYOUT RUNNING ON THE GPU in the
// browser (cosmos.gl shaders) instead of on the server.
//
// Concepts from "How to visualize a graph with a million nodes" (Nightingale)
// via the cosmos.gl library (https://github.com/cosmosgl/graph, vendored at
// static/vendor/cosmos-graph.min.js): typed arrays + integer point indices in,
// GPU simulation + rendering out. The adapter's core job is mapping the app's
// string node IDs onto cosmos's integer indices (and back for events).
//
// Because the GPU owns positions, app.js must NOT apply server position frames
// in this mode: the adapter sets `ownsLayout = true` and app.js guards on it
// (position frames, flow particles, subnet islands are skipped).
//
// vis-compat surface implemented (same contract as GLNetwork, glrenderer.js):
//   on/off, redraw, setOptions, setSize, fit, focus, moveTo, selectNodes,
//   getScale, getPosition(s), getConnectedNodes/Edges, canvasToDOM/DOMtoCanvas,
//   destroy, body.nodes[id]{x,y,options.opacity}, body.edges[id]{fromId,toId,
//   options.{color,label}, edgeType.getPoint}.
//
// v1 feature matrix (?renderer=cosmos):
//   works    — render, GPU layout, pan/zoom/fit, hover tooltip + focus dim,
//              click -> details, search focus, protocol filters,
//              shift-drag rectangle selection (count + dim).
//   disabled — pinned positions/overrides, subnet expand/collapse rings,
//              flow particles, edge labels, game mode. Follow-ups.

(function () {
    'use strict';

    // Shared with glrenderer.js — see static/colorutil.js.
    const parseColor = window.parseRendererColor;

    const SPACE = 4096;          // cosmos simulation space (square)
    const CENTER = SPACE / 2;
    const REBUILD_MS = 250;      // topology re-upload throttle

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
            this.ownsLayout = true;       // app.js: skip server position frames
            this.destroyed = false;
            this.selectedNode = null;

            // id <-> integer index mapping (rebuilt on topology change).
            this.indexToId = [];
            this.idToIndex = new Map();
            this._positions = null;       // Float32Array cache from last upload/pull
            this._dirty = false;
            this._rebuildTimer = null;
            this._builtOnce = false;
            this._userMovedCamera = false;

            if (getComputedStyle(container).position === 'static') {
                container.style.position = 'relative';
            }
            this.div = document.createElement('div');
            this.div.style.cssText = 'position:absolute;inset:0;';
            container.appendChild(this.div);

            const self = this;
            this.graph = new Cosmos.Graph(this.div, {
                enableSimulation: true,
                spaceSize: SPACE,
                backgroundColor: [0, 0, 0, 0],
                fitViewOnInit: false,
                enableDrag: false,
                scalePointsOnZoom: false,
                renderHoveredPointRing: true,
                hoveredPointRingColor: '#f39c12',
                simulationDecay: 5000,
                simulationRepulsion: 1.0,
                simulationGravity: 0.25,
                simulationCenter: 0.6,
                simulationLinkSpring: 1.2,
                simulationLinkDistance: 12,
                simulationFriction: 0.85,
                onClick: (index, pos, event) => self._onCosmosClick(index, event),
                onPointMouseOver: (index) => self._onCosmosHover(index),
                onPointMouseOut: () => self._onCosmosBlur(),
                onZoomStart: (e, userDriven) => {
                    if (userDriven) self._userMovedCamera = true;
                    self._emit('dragStart', { nodes: [] });
                },
                onZoom: () => self._emit('zoom', { scale: self.getScale() }),
            });

            this._syncAll();
            this._nodeSub = (event, props) => this._markDirty('nodes', event, props);
            this._edgeSub = (event, props) => this._markDirty('edges', event, props);
            this.nodesData.on('*', this._nodeSub);
            this.edgesData.on('*', this._edgeSub);
            this._rebuild();

            this._bindRectSelect();
        }

        // ----- DataSet -> body mirror -------------------------------------

        _syncAll() {
            for (const item of this.nodesData.get()) this._syncNode(item);
            for (const item of this.edgesData.get()) this._syncEdge(item);
        }

        _syncNode(item) {
            let bn = this.body.nodes[item.id];
            if (!bn) {
                bn = this.body.nodes[item.id] = {
                    id: item.id,
                    // Server-styled adds carry a layout seed (x/y in layout px,
                    // roughly centered on 0); map it into cosmos space so the
                    // sim starts from something resembling the server's shape.
                    x: CENTER + (typeof item.x === 'number' ? item.x : 0),
                    y: CENTER + (typeof item.y === 'number' ? item.y : 0),
                    options: { opacity: 1 }
                };
            }
            const o = bn.options;
            o.label = item.label;
            o.color = item.color || {};
            o.isGroup = item.shape === 'box';
            o.value = typeof item.value === 'number' ? item.value : null;
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
                    // Straight-line param point (cosmos draws straight links);
                    // same contract as vis's edgeType.getPoint.
                    edgeType: {
                        getPoint(t) {
                            const a = self.body.nodes[be.fromId];
                            const b = self.body.nodes[be.toId];
                            if (!a || !b) return { x: 0, y: 0 };
                            return { x: a.x + (b.x - a.x) * t, y: a.y + (b.y - a.y) * t };
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
            }
            o.width = typeof item.width === 'number' ? item.width : 1;
        }

        _markDirty(kind, event, props) {
            if (this.destroyed) return;
            // Mirror the DataSet change into body immediately (app.js may touch
            // body right after a DataSet update); throttle the GPU re-upload.
            // Only the event's own items are synced — a full DataSet copy per
            // event was an O(nodes+edges) sweep on every 100ms delta.
            this._applyDelta(kind, event, props);
            this._dirty = true;
            if (!this._rebuildTimer) {
                this._rebuildTimer = setTimeout(() => {
                    this._rebuildTimer = null;
                    if (this._dirty) this._rebuild();
                }, REBUILD_MS);
            }
        }

        // Apply one DataSet event's items to the body mirror. Falls back to a
        // full resync when the event carries no item list (defensive; vis
        // add/update/remove events always do).
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

        // ----- typed-array upload (the cosmos.gl contract) ------------------

        _rebuild() {
            if (this.destroyed || this.rawMode) return;
            this._dirty = false;
            this._pullPositions(); // preserve motion across re-uploads

            const ids = Object.keys(this.body.nodes);
            const n = ids.length;
            const prevIndex = this.idToIndex;
            const prevPos = this._positions;

            this.indexToId = ids;
            const idToIndex = this.idToIndex = new Map();
            for (let i = 0; i < n; i++) idToIndex.set(ids[i], i);

            const pos = new Float32Array(n * 2);
            const colors = new Float32Array(n * 4);
            const sizes = new Float32Array(n);
            const shapes = new Float32Array(n);

            // Size scaling: match GL/vis (20..30px, groups small squares).
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
                const pi = prevIndex.get(ids[i]);
                if (pi !== undefined && prevPos) {
                    // Existing point: keep its simulated position.
                    bn.x = prevPos[pi * 2];
                    bn.y = prevPos[pi * 2 + 1];
                } else if (!this._builtOnce) {
                    // First build: seed from the server layout hint (set in
                    // _syncNode) — already in bn.x/bn.y.
                } else {
                    // New node mid-flight: spawn near a connected neighbor so
                    // it flies in from its cluster, not from (0,0).
                    const nb = this._anyNeighborPos(ids[i]);
                    bn.x = nb.x + (Math.random() - 0.5) * 30;
                    bn.y = nb.y + (Math.random() - 0.5) * 30;
                }
                pos[i * 2] = bn.x;
                pos[i * 2 + 1] = bn.y;

                const fill = parseColor(o.color && (o.color.background || o.color.color), [0.4, 0.65, 0.9, 1]);
                const dim = o.opacity != null ? o.opacity : 1;
                colors[i * 4] = fill[0];
                colors[i * 4 + 1] = fill[1];
                colors[i * 4 + 2] = fill[2];
                colors[i * 4 + 3] = fill[3] * dim;
                shapes[i] = o.isGroup ? 1 : 0; // 1 = square
                if (o.isGroup) {
                    sizes[i] = 8;
                } else if (!anyV || maxV <= minV || o.value == null) {
                    sizes[i] = 14;
                } else {
                    sizes[i] = 14 + 8 * (o.value - minV) / (maxV - minV);
                }
            }

            // Links + adjacency (adjacency also serves getConnectedNodes).
            const edgeIds = Object.keys(this.body.edges);
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
                const col = parseColor(be.options.color && be.options.color.color, [0.5, 0.5, 0.5, 1]);
                const eDim = be.options.color && be.options.color.opacity != null ? be.options.color.opacity : 1;
                linkColors.push(col[0], col[1], col[2], col[3] * eDim * 0.7);
                linkWidths.push(Math.max(1, be.options.width || 1));
                let adj = this._adjacency.get(be.fromId);
                if (!adj) this._adjacency.set(be.fromId, adj = []);
                adj.push({ id: eid, other: be.toId });
                adj = this._adjacency.get(be.toId);
                if (!adj) this._adjacency.set(be.toId, adj = []);
                adj.push({ id: eid, other: be.fromId });
            }

            this._positions = pos;
            this.graph.setPointPositions(pos, true);
            this.graph.setPointColors(colors);
            this.graph.setPointSizes(sizes);
            this.graph.setPointShapes(shapes);
            this.graph.setLinks(new Float32Array(linkPairs));
            this.graph.setLinkColors(new Float32Array(linkColors));
            this.graph.setLinkWidths(new Float32Array(linkWidths));
            this.graph.render();

            if (!this._builtOnce && n > 0) {
                this._builtOnce = true;
                this.graph.start(1);
                this.graph.fitView(400);
                // Re-fit once the sim has mostly settled, unless the user has
                // taken the camera (same idea as GLNetwork's settle-fit).
                setTimeout(() => {
                    if (!this.destroyed && !this._userMovedCamera) this.graph.fitView(600);
                }, 2500);
            } else if (n > 0) {
                this.graph.start(0.25); // gentle re-heat on topology change
            }
        }

        _anyNeighborPos(id) {
            const adj = this._adjacency && this._adjacency.get(id);
            if (adj) {
                for (const { other } of adj) {
                    const bn = this.body.nodes[other];
                    if (bn && this.idToIndex.has(other)) return { x: bn.x, y: bn.y };
                }
            }
            return { x: CENTER, y: CENTER };
        }

        // Pull simulated positions from the GPU into body + cache. Cheap (one
        // readback of a JS array cosmos already tracks); throttled per frame.
        _pullPositions() {
            if (!this._builtOnce) return;
            const now = performance.now();
            if (this._posPulledAt && now - this._posPulledAt < 16) return;
            this._posPulledAt = now;
            const flat = this.graph.getPointPositions();
            if (!flat || !flat.length) return;
            const pos = this._positions && this._positions.length === flat.length
                ? this._positions : new Float32Array(flat.length);
            for (let i = 0; i < flat.length; i++) pos[i] = flat[i];
            this._positions = pos;
            if (this.rawMode) return; // raw mode keeps no per-node body objects
            for (let i = 0; i < this.indexToId.length; i++) {
                const bn = this.body.nodes[this.indexToId[i]];
                if (bn) { bn.x = pos[i * 2]; bn.y = pos[i * 2 + 1]; }
            }
        }

        // ----- raw-scale topology (msgType=2 frames; M5) ----------------------
        //
        // Feeds server frames straight into cosmos typed arrays, bypassing the
        // vis DataSets and per-node body objects entirely — at 100k nodes the
        // object churn would be the bottleneck, exactly what the article's
        // typed-array design avoids. Positions survive across frames by id.

        setRawTopology(frame, protos) {
            if (this.destroyed) return;
            this.rawMode = true;
            const n = frame.ids.length;
            const prevIndex = this.idToIndex;
            const prevPos = this._builtOnce ? this.graph.getPointPositions() : null;

            this.indexToId = frame.ids;
            const idToIndex = this.idToIndex = new Map();
            for (let i = 0; i < n; i++) idToIndex.set(frame.ids[i], i);

            const pos = new Float32Array(n * 2);
            const colors = new Float32Array(n * 4);
            const sizes = new Float32Array(n);
            const shapes = new Float32Array(n);
            // Traffic-tier ramp: quiet gray-blue -> busy red (alpha included).
            const TIER = [
                [0.45, 0.58, 0.72, 0.85],
                [0.30, 0.65, 0.90, 1],
                [0.18, 0.75, 0.62, 1],
                [0.95, 0.72, 0.25, 1],
                [0.92, 0.33, 0.28, 1],
            ];
            for (let i = 0; i < n; i++) {
                const pi = prevIndex.get(frame.ids[i]);
                if (pi !== undefined && prevPos && prevPos.length > pi * 2 + 1) {
                    pos[i * 2] = prevPos[pi * 2];
                    pos[i * 2 + 1] = prevPos[pi * 2 + 1];
                } else {
                    // New node: random ring around center (a neighbor lookup at
                    // this scale isn't worth it; the sim sorts it out fast).
                    const a = Math.random() * Math.PI * 2;
                    const r = SPACE * 0.15 * (0.5 + Math.random());
                    pos[i * 2] = CENTER + Math.cos(a) * r;
                    pos[i * 2 + 1] = CENTER + Math.sin(a) * r;
                }
                const c = TIER[Math.min(frame.tiers[i], 4)];
                colors[i * 4] = c[0];
                colors[i * 4 + 1] = c[1];
                colors[i * 4 + 2] = c[2];
                colors[i * 4 + 3] = c[3];
                const group = (frame.flags[i] & 1) !== 0;
                shapes[i] = group ? 1 : 0;
                sizes[i] = group ? 4 : 5 + frame.tiers[i] * 2.5;
            }

            const m = frame.protoIdx.length;
            const linkColors = new Float32Array(m * 4);
            for (let i = 0; i < m; i++) {
                const p = protos && protos[frame.protoIdx[i]];
                const c = parseColor(p && p.color, [0.5, 0.5, 0.5, 1]);
                linkColors[i * 4] = c[0];
                linkColors[i * 4 + 1] = c[1];
                linkColors[i * 4 + 2] = c[2];
                linkColors[i * 4 + 3] = 0.35;
            }

            this._positions = pos;
            this.graph.setPointPositions(pos, true);
            this.graph.setPointColors(colors);
            this.graph.setPointSizes(sizes);
            this.graph.setPointShapes(shapes);
            this.graph.setLinks(frame.links);
            this.graph.setLinkColors(linkColors);
            this.graph.render();
            if (!this._builtOnce && n > 0) {
                this._builtOnce = true;
                this.graph.start(1);
                this.graph.fitView(400);
                setTimeout(() => {
                    if (!this.destroyed && !this._userMovedCamera) this.graph.fitView(600);
                }, 3000);
            } else if (n > 0) {
                this.graph.start(0.25);
            }
        }

        // ----- cosmos event bridge (integer index -> string id) -------------

        _onCosmosClick(index, event) {
            this._clearRectSelection();
            const id = index !== undefined ? this.indexToId[index] : undefined;
            const p = event ? { x: event.offsetX, y: event.offsetY } : { x: 0, y: 0 };
            this._emit('click', {
                nodes: id !== undefined ? [id] : [],
                edges: [],
                pointer: { DOM: p, canvas: this.DOMtoCanvas(p) }
            });
        }

        _onCosmosHover(index) {
            const id = this.indexToId[index];
            if (id === undefined) return;
            this._pullPositions();
            if (this.hoveredNode && this.hoveredNode !== id) {
                this._emit('blurNode', { node: this.hoveredNode });
            }
            this.hoveredNode = id;
            this._emit('hoverNode', { node: id });
        }

        _onCosmosBlur() {
            if (this.hoveredNode) {
                this._emit('blurNode', { node: this.hoveredNode });
                this.hoveredNode = null;
            }
        }

        // ----- vis-compatible emitter ---------------------------------------

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

        // ----- camera / coordinates ------------------------------------------
        // "Canvas" coordinates for app.js are cosmos space coordinates.

        getScale() { return this.graph.getZoomLevel(); }
        canvasToDOM(p) {
            const s = this.graph.spaceToScreenPosition([p.x, p.y]);
            return { x: s[0], y: s[1] };
        }
        DOMtoCanvas(p) {
            const s = this.graph.screenToSpacePosition([p.x, p.y]);
            return { x: s[0], y: s[1] };
        }
        _posOf(id) {
            const n = this.body.nodes[id];
            if (n) return { x: n.x, y: n.y };
            const idx = this.idToIndex.get(id);
            if (idx !== undefined && this._positions && this._positions.length > idx * 2 + 1) {
                return { x: this._positions[idx * 2], y: this._positions[idx * 2 + 1] };
            }
            return null;
        }
        getPosition(id) {
            this._pullPositions();
            return this._posOf(id) || { x: 0, y: 0 };
        }
        getPositions(ids) {
            this._pullPositions();
            const out = {};
            const list = ids || (this.rawMode ? this.indexToId : Object.keys(this.body.nodes));
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
            this.graph.setConfigPartial({ focusedPointIndex: idx });
        }
        setOptions(options) {
            this.options = Object.assign({}, this.options, options);
        }
        setSize() { /* cosmos observes its container itself */ }

        fit(opts) {
            const dur = opts && opts.animation ? (opts.animation.duration || 400) : 0;
            this.graph.fitView(dur);
        }
        focus(id, opts) {
            const idx = this.idToIndex.get(id);
            if (idx === undefined) return;
            const dur = opts && opts.animation ? (opts.animation.duration || 500) : 500;
            this.graph.zoomToPointByIndex(idx, dur, opts && opts.scale);
        }
        moveTo(opts) {
            if (opts.scale != null) this.graph.setZoomLevel(opts.scale, opts.animation ? 300 : 0);
        }

        // redraw: push style-only state (focus dim writes body opacities, then
        // calls this — same contract the GL renderer honors). No index rebuild.
        redraw() {
            if (this.destroyed || !this._builtOnce) return;
            if (this._redrawQueued) return;
            this._redrawQueued = true;
            requestAnimationFrame(() => {
                this._redrawQueued = false;
                if (this.destroyed) return;
                this._pushStyleArrays();
            });
        }

        _pushStyleArrays() {
            // Raw mode owns its colors (tier ramp set in setRawTopology) and
            // keeps no body objects to derive styles from.
            if (this.rawMode) return;
            const n = this.indexToId.length;
            if (!n) return;
            const colors = new Float32Array(n * 4);
            for (let i = 0; i < n; i++) {
                const bn = this.body.nodes[this.indexToId[i]];
                if (!bn) continue;
                const o = bn.options;
                const fill = parseColor(o.color && (o.color.background || o.color.color), [0.4, 0.65, 0.9, 1]);
                const dim = o.opacity != null ? o.opacity : 1;
                colors[i * 4] = fill[0];
                colors[i * 4 + 1] = fill[1];
                colors[i * 4 + 2] = fill[2];
                colors[i * 4 + 3] = fill[3] * dim;
            }
            this.graph.setPointColors(colors);
            const linkColors = [];
            for (const eid in this.body.edges) {
                const be = this.body.edges[eid];
                if (!this.idToIndex.has(be.fromId) || !this.idToIndex.has(be.toId)) continue;
                const col = parseColor(be.options.color && be.options.color.color, [0.5, 0.5, 0.5, 1]);
                const eDim = be.options.color && be.options.color.opacity != null ? be.options.color.opacity : 1;
                linkColors.push(col[0], col[1], col[2], col[3] * eDim * 0.7);
            }
            this.graph.setLinkColors(new Float32Array(linkColors));
            this.graph.render();
        }

        // ----- shift-drag rectangle selection (Cosmograph-style) -------------

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
                r.style.cssText = 'position:absolute;border:1px dashed #f39c12;' +
                    'background:rgba(243,156,18,0.12);pointer-events:none;z-index:10;';
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
                const indices = self.graph.findPointsInRect([[x0, y0], [x1, y1]]) || [];
                self._applyRectSelection(indices.map(i => self.indexToId[i]).filter(Boolean));
            };
            // Capture phase so shift-drag wins over cosmos's own pan handler.
            this.container.addEventListener('mousedown', this._rsDown, true);
            this.container.addEventListener('mousemove', this._rsMove, true);
            this.container.addEventListener('mouseup', this._rsUp, true);
        }

        _applyRectSelection(ids) {
            this._rectSelection = new Set(ids);
            // Dim everything outside the selection through the same body
            // opacity path focus mode uses.
            for (const id in this.body.nodes) {
                this.body.nodes[id].options.opacity =
                    (!ids.length || this._rectSelection.has(id)) ? 1 : 0.12;
            }
            for (const eid in this.body.edges) {
                const be = this.body.edges[eid];
                if (be.options.color) {
                    be.options.color.opacity =
                        (!ids.length || (this._rectSelection.has(be.fromId) && this._rectSelection.has(be.toId))) ? 1 : 0.06;
                }
            }
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
                    'color:#f39c12;font:12px sans-serif;pointer-events:none;';
                this.container.appendChild(badge);
            }
            badge.textContent = ids.length + ' host' + (ids.length === 1 ? '' : 's') + ' selected';
        }

        _clearRectSelection() {
            if (!this._rectSelection || !this._rectSelection.size) return;
            this._applyRectSelection([]);
            this._rectSelection = null;
        }

        // ----- teardown -------------------------------------------------------

        destroy() {
            this.destroyed = true;
            this.nodesData.off('*', this._nodeSub);
            this.edgesData.off('*', this._edgeSub);
            if (this._rebuildTimer) clearTimeout(this._rebuildTimer);
            this.container.removeEventListener('mousedown', this._rsDown, true);
            this.container.removeEventListener('mousemove', this._rsMove, true);
            this.container.removeEventListener('mouseup', this._rsUp, true);
            try { this.graph.destroy(); } catch (e) { /* already gone */ }
            if (this.div && this.div.parentNode) this.div.parentNode.removeChild(this.div);
        }
    }

    window.CosmosNetwork = CosmosNetwork;
})();
