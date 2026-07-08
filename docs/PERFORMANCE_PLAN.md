# Etherchimp Performance Plan — Fluid Graph at High Node/Traffic Counts

Goal: the graph stays fluid (steady 60fps pan/zoom/hover, no stutter) with hundreds
to thousands of nodes and heavy live traffic. Server does the heavy lifting; the
browser becomes a dumb, fast renderer. **All physics-based attributes (layout.go
constants, force model, easing behavior) stay exactly as they are.**

## Diagnosis

The server pipeline is already in good shape: per-client filtered views, server-side
layout (physics off in the browser), styled ViewNodes, per-client deltas, quantized
positions, 100ms tick. The stutter is almost entirely in the client render path,
which is built on vis-network (Canvas 2D):

1. **Per-frame `nodes.update()` in the easing loop** (`stepPositionAnimation`,
   app.js:2430). Every animation frame pushes a batch of moved nodes through
   `vis.DataSet.update()`: per-item deep-merge, change events, full node re-parse
   (label/shape/font resolution), then a full canvas redraw. At 200+ moving nodes ×
   60fps this is the #1 stutter source. DataSet is a database, not a render path.

2. **Edge labels embed live packet counts** (`formatEdgeLabel` → `"TCP (1234)"`,
   app.js:2706). Any packet on an edge changes `PacketCount`, so the server diff
   marks the edge changed, the client rebuilds its label/tooltip strings, and vis
   re-renders stroked text — the most expensive Canvas 2D operation — for that
   edge. Under load, essentially **every edge is "changed" every tick**, so every
   throttled update re-renders ~all edge labels. Node tooltips (`formatNodeTooltip`)
   are likewise built eagerly for every changed node on every delta, even though
   they only matter on hover.

3. **Hover/focus restyles the whole graph through the DataSet** (`focusNode`,
   app.js:2462). Each hover updates opacity on *every* node and recolors *every*
   edge via `nodes.update`/`edges.update` — O(N+E) deep merges + full redraw,
   repeatedly, as the mouse moves.

4. **vis-network redraws everything, always.** No viewport culling, no LOD, bezier
   ("smooth") edges, per-node labels, shadows. 500 nodes + 1000 smooth edges +
   labels is simply beyond Canvas 2D at 60fps regardless of how updates arrive.

5. **The adaptive performance tier never actually adapts.** `getNetworkOptions()`
   picks tier-based options (shadows, smooth edges, hover, label hiding) from the
   node count, but `network.setOptions(...)` is only called on theme change
   (app.js:2941). A session that grows 20 → 400 nodes keeps full-quality options.
   `getPhysicsSettings()` is dead code — physics is off (options at app.js:351).

6. **Main-thread churn per delta**: `JSON.parse` of large deltas on the UI thread;
   stats recomputed with `nodes.get()` (full array copy) + reduce and
   `edges.get().length` on every update (app.js:2375); `nodes.getIds()` array
   allocation per WS message in the throttle path (app.js:2094).

7. **Wire overhead**: a packet-count bump re-sends the *entire* ViewEdge (all 10
   fields); positions ride the same JSON message as styling; `protocolStats` (full
   map) is attached to every delta.

Minor: `updatePacketCache` sorts all cache keys to trim (Map preserves insertion
order — just delete the first k keys); flow overlay is already well-architected
(separate canvas, self-stopping rAF loop).

---

## Phase 1 — Stop fighting vis-network (client only, quick wins) ✅ DONE (2026-07-03)

Biggest stutter reduction per line of code changed. No protocol changes.

- **1.1 Move position easing off the DataSet.** In `stepPositionAnimation`, write
  eased positions directly into `network.body.nodes[id].x/.y` and call one
  `network.redraw()` per frame. Reserve `nodes.update()` for topology/style changes
  only. Pause the loop when `document.hidden`. (Easing constants — `POSITION_EASE`,
  thresholds — unchanged.)
- **1.2 Static edge labels.** Label = protocol name only; live counts move to the
  lazy tooltip/details panel. With counts out of the label, an edge whose only
  change is traffic volume no longer needs any vis re-render for its label. Also
  hide edge labels entirely above a node-count or below a zoom threshold.
- **1.3 Lazy tooltips.** Stop building `title` strings for every node/edge on every
  delta. Stash the raw data on the vis item and build the tooltip on
  `hoverNode`/`hoverEdge` (or a small custom tooltip div).
- **1.4 Field-level diffing in `updateGraph`.** Keep a client-side cache of the last
  applied ViewNode/ViewEdge; only push items (and only the fields) that changed
  something render-visible. A counter-only change updates the stash — no
  `DataSet.update` at all.
- **1.5 Focus/hover dimming without DataSet writes.** Keep the focused id-set; apply
  dimming by setting opacity directly on `network.body.nodes` /
  `network.body.edges` + one `redraw()`, or composite a dim overlay in the
  `afterDrawing` hook. Debounce hover.
- **1.6 Stats from the server.** Add `nodeCount`/`edgeCount`/`totalPackets` to the
  delta (server already has them); delete the per-update `nodes.get().reduce`.
- **1.7 Make the tier system live.** Re-apply `getNetworkOptions()` when the node
  count crosses a tier boundary (not just on theme change). Delete
  `getPhysicsSettings()` (dead — physics is off; server physics untouched).
- **1.8 Cheap cleanups.** Trim `packetCache` by insertion order (no sort); reuse
  `nodes.length` instead of `nodes.getIds().length` in the throttle path.

Expected result: smooth up to ~300–500 nodes under traffic; hover no longer stalls.

## Phase 2 — Wire protocol: split fast frames from slow state (server + client) ✅ DONE (2026-07-03; 2.3 worker parse deferred — after 2.1/2.2 the main-thread JSON left is rare deltas + a 1s counts frame, so a worker buys ~nothing)

Server renders/decides everything; the client parses less and draws less.

- **2.1 Message split** (per client, same tick loop):
  - `pos` frame — positions only, sent whenever the layout moved. Compact
    id-indexed layout; ideally a binary frame (id→index table established on each
    full sync, then `Float32Array` pairs). Applied straight to `body.nodes` +
    redraw. Tiny to marshal, tiny to parse.
  - `style` delta — adds/removes, labels, tier/role/shape changes. Rare.
  - `stats` frame — protocol totals + counters at a 1s cadence, not 100ms.
  - `flows` — stays on the fast path (drives the particle overlay).
- **2.2 Server-side change damping for counters.** In `buildDelta`, stop diffing raw
  packet/byte counts. Diff *render-relevant derived buckets* instead: edge width
  bucket (`log(count)` step), node `colorTier`, node value bucket. An edge that
  goes 1200 → 1300 packets renders identically — send nothing. This collapses
  delta volume under heavy traffic to near zero once the graph shape is stable.
  (Detailed counts stay available via lazy tooltip fetch or the 1s stats frame.)
- **2.3 Parse off the main thread.** Move the WS connection + JSON parse + diff
  into a Web Worker (the project already ships `search-worker.js`); post
  structured/transferable results to the UI thread.

Expected result: main thread near-idle under packet storms; bandwidth drops an
order of magnitude.

## Phase 3 — WebGL renderer (the real fix for 1000+ nodes) ✅ DONE (2026-07-03)

Shipped as `static/glrenderer.js` (`GLNetwork`), opt-in via `?renderer=gl` or
`localStorage.renderer='gl'`; `?renderer=vis` forces the vis fallback. Measured:
3,260 nodes / 5,273 edges panning at 8.3ms/frame avg (Apple M2 Max), ~2.3ms of
which is JS. CDN scripts are vendored into `static/vendor/`. Remaining polish,
deliberately deferred: flow particles stay on the existing 2D overlay (cheap,
already isolated), group-node borders are solid rather than dashed in GL, and
hit-testing is brute-force (fine ≤ ~5k nodes; add a grid if Phase 4 raises the
node budget).

Canvas 2D full-scene redraws are the hard ceiling. Replace vis-network's rendering
with a purpose-built WebGL renderer behind the **same protocol and same physics**:

- Nodes as instanced circles/boxes (per-instance position, radius, color, alpha);
  edges as instanced quads/lines; focus dimming is just per-instance alpha.
- Labels as a positioned HTML overlay for the top-K visible nodes at the current
  zoom (crisp, cheap, no GL text stack), with zoom LOD; SDF text later if needed.
- Flow particles join the same GL scene as a particle buffer — removes the second
  canvas and the per-particle `canvasToDOM`/`getPoint` calls.
- Camera (pan/zoom/fit/keyboard), hit-testing via a uniform grid over the known
  server positions, click/hover/drag-to-pin, subnet rings as line loops.
- Adapters for chimpy mode and game mode: both interpolate along straight edges
  between node positions, which our own position store serves directly (they
  currently poke vis internals: `edge.edgeType.getPoint`, `network.getPositions`).

Implementation options, in recommended order:
1. **Hand-rolled WebGL2** — ~1–2k lines, zero dependencies, total control, fits the
   single-file static app. Instanced dots/lines are simple shaders.
2. **PixiJS** — faster to build, well-maintained, still lets us keep our data model.
3. **Sigma.js** — graph-specific but imposes its own graph model (graphology).

Migrate behind a renderer flag (`?renderer=gl`), keeping vis-network as fallback
until parity; delete it after burn-in. Also vendor the current CDN scripts
(unpkg vis-network/three) locally so the tool works on airgapped/lab networks.

Expected result: 60fps pan/zoom with thousands of nodes and full particle traffic.

## Phase 4 — Server-side aggregation (unbounded network size) ✅ DONE (2026-07-03)

Shipped: above 300 visible hosts (per client; override via
`localStorage.aggThreshold` → `setAggregation` WS message), same-/24 hosts with
≥3 members collapse into blue subnet supernodes with merged edges and remapped
traffic flows. Click a supernode → details panel → "⊞ Expand subnet"; a member
host's details offers "⊟ Collapse". Expansion state is per client and re-synced
on reconnect. Verified: 260 hosts → 9 rendered nodes at threshold 50, full
expand/collapse round trip, both renderers, defaults unchanged below threshold.

Rendering budget stays fixed no matter how big the capture is — the server decides
what a "node" is:

- **Supernode clustering**: when a client's kept-node count exceeds its budget,
  collapse hosts into /24 subnet (or role) supernodes server-side, with aggregated
  counts/edges; click expands a supernode (per-client `ViewConfig` already exists
  to hold expansion state). Layout positions stay stable across collapse/expand.
- Zoom-level LOD driven by the same mechanism if needed (client reports zoom band;
  server picks aggregation level).

## Phase 5 — Safari smoothness + datacenter scale ✅ DONE (2026-07-03)

Prompted by Safari stutter on live SSH captures and a target of 100k+ endpoints.

- **WASM: considered and rejected.** The heavy compute (capture, graph, layout,
  diffing) is server-side Go; client per-frame JS is ~2-3ms; positions already
  arrive binary. The slow parts are GPU/Canvas rasterization and DOM, which
  WASM cannot touch. Revisit only if a CPU-heavy client feature appears.
- **Safari fix (the actual bottleneck was per-frame Canvas2D):** WebGL renderer
  is now the DEFAULT (vis fallback auto/`?renderer=vis`); labels render from a
  GL texture atlas (strings rasterized once, tinted per instance — zero
  per-frame fillText); flow particles moved into the GL scene; the 2D overlay
  (subnet rings) repaints only on camera change (measured: 0 repaints/s during
  particle animation, was ~60/s); uniforms cached; MSAA off (SDF shaders AA in
  pixel space). Verify on Safari: `sudo safaridriver --enable` once, then run
  scratchpad safari-drive.mjs, or just open the app and pan.
- **Scale:** `-synth N [-synth-rate pps]` dev load generator; hierarchical
  aggregation (/16 above /24, expansion peels one level); flows capped at 60/
  tick and merged post-remap; view rebuilds at 500ms cadence above 20k hosts
  (needsFull bypasses); hub tick telemetry in the log. Measured at 100k hosts,
  5k pkt/s: 2 rendered supernodes, tick EMA ~28ms, wire ~5 KB/s steady,
  client 8.3ms/frame.
- **Streaming (relevant-first):** ViewNodes stream slim (no ips/deviceInfo);
  `GET /api/node?id=` lazily fills tooltips/details; full snapshots are chunked
  busiest-first (150/message) for instant first paint; `GET /api/search?q=`
  searches the whole graph and `focusOnNode` auto-expands the subnet chain of
  hidden matches.

## Sequencing & verification

1 → 2 → 3 → 4; each phase ships independently. Benchmark before/after each phase
with a repeatable scenario: replay a large pcap (`-f pcaps/...`), measure with
Chrome tracing — main-thread time per WS message, per-frame time during easing,
dropped frames while panning at 100/300/500/1000 nodes. Add a debug HUD (fps +
delta size + apply time) behind a flag so regressions are visible during
development.

Explicit non-goals (per requirements): no changes to force-layout constants,
gravity, temperatures, collision, easing feel, or any physics behavior — server or
client. All changes are transport and presentation.
