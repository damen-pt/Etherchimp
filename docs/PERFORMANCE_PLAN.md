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

## Phase 6 — Fluid large clusters (2026-07-09)

Target: smoothness when **many individual hosts are visible inside large clusters**
(expand/drill-down), not just the aggregated overview path.

### Shipped

- **Budgeted expand** (`DefaultExpandBudget=120`): opening a dense CIDR reveals
  only the busiest members; quieter hosts stay as an orange residual `+N more`
  supernode (`id = cidr+"+"`, `isTail`). **Expand all** / residual click sets
  `FullExpand` to bypass the budget.
- **Isolate focus** (`FocusCIDR`): “Focus cluster” hides outsiders and raises
  per-view caps (800/1600) so drill-down stays useful; floating badge to exit.
- **Zoom LOD** (`ZoomBand` far/mid/near): client reports camera scale; server
  adjusts aggregation threshold and expand budget. User pin-open always wins.
- **Expand bloom** (`layout.go`): members of a departed supernode seed in a disk
  around its last position; cooler reheat so the rest of the map barely moves.
- **GL hot path**: dirty node/edge buffers (camera-only pans skip rebuild),
  spatial-hash hit-test, far-zoom straight edges (`curve=0`), adaptive particle
  cap under load; focus dim marks scene dirty.
- **Cosmos explore**: `/16` cluster forces via `setPointClusters`; Map vs Explore
  mode toggle in Clusters menu (`?renderer=cosmos&scale=raw`).

### Hybrid stance (unchanged)

GL + server aggregation remains the polished default. Cosmos raw remains the
high-N explorer. Do not collapse to a single renderer.

## Phase 7 — Cosmos solar-system explorer (2026-07-09)

Complete overhaul of the cosmos path for diagnostic/forensic use at hundreds–
~1000 nodes:

- **No GPU force bounce.** `enableSimulation: false`; server **solar layout**
  (`graph/solar.go`, mode `solar`) places /24 star-systems and host planets on
  deterministic orbits. Traffic never flings nodes across the screen.
- **ownsLayout = false** — binary position frames + client easing like WebGL.
- **Planet labels** — HTML overlay with name + primary IP (LOD by zoom).
- **Click parity** — details panel, MAC identity, multi-IP, recent packets,
  connection list from `/api/node`.
- **MAC ultimate identity** — exclusive host MACs re-key the node; multi-IP and
  hostname remain attributes; shared gateway MACs demote and never merge.
- **Explore (Solar)** menu mode loads `?renderer=cosmos` with layout `solar`
  (not raw). Optional `?scale=raw` still available for unaggregated browsing.
- Starfield backdrop + light edge particles for solar-system exploration feel.

## Phase 8 — Datacenter 500+ node review (2026-08-05)

Fresh end-to-end review targeting continuous monitoring of 500+ visible nodes
at ~5–10k pkt/s with 1–5 clients, plus a user-editable protocol catalog.
Visualizations, layout constants, and physics feel unchanged throughout.

### Findings (ranked) and resolutions

1. **Per-client O(n²) force layout every tick, even when converged** — the #1
   bottleneck: `stepForce` ran 6 all-pairs iterations (~750k pair-evals at 500
   nodes) per client per 100ms tick, serialized on the hub goroutine; 3+
   clients blew the tick budget. **Fixed:** `LayoutEngine.Step` now skips the
   relaxation entirely when the mode's existing `settled` flag is set, the
   node-set signature is unchanged, and pins are unchanged (new
   `forceCanSkip`/`pinsEqual` in `graph/layout.go`; per-mode state, so mode
   switches are unaffected). Any change — new node, expand/collapse, reheat,
   pin — un-settles via the pre-existing paths and animates exactly as before.
   Measured (500-node harness): settled step 5.6ms → ~31µs. Tests:
   `graph/layout_test.go`.
2. **Unbuffered per-packet pcap `write()` syscalls on the capture goroutine**
   (local + SSH paths) — a hard throughput ceiling with silent kernel-side
   drops on disk stall. **Fixed:** `capture/pcapwriter.go` — `bufio.Writer`
   (256KB) + `pcapgo` on a bounded 4096-packet queue drained by its own
   goroutine, 500ms flush ticker, clean drain/flush/close on shutdown, drop
   counter with rate-limited logging. Pause/shutdown semantics preserved;
   payload bytes are copied at enqueue (mandatory under NoCopy).
3. **Stream subsystem per-packet cost and memory** (`stream/stream.go`) —
   **Fixed:** packet payload base64 moved to serve-time (`StreamPacket.MarshalJSON`;
   JSON shape identical); `generateSummary` recomputed only on protocol change
   or first payload bytes (counts inside summary strings now freeze — live
   counts remain on `StreamInfo.PacketCount`/`ByteCount`); O(1000) eviction
   scan replaced with a `container/list` LRU preserving
   least-recently-seen-first semantics; per-direction payload cap 1MB → 64KB
   (UI truncates display at ≤4KB everywhere).
4. **Single ingest goroutine ceiling / silent drops** — **Fixed:**
   `startStreamFeeder` (main.go) moves `streamMgr.AddPacket` off the ingest
   goroutine onto its own 4096-buffered channel, started before all mode
   branches; `packetChan` and stream-queue overflows now counted and logged
   rate-limited (capture `dropCounter`, main `noteStreamDrop`).
5. **Eager gopacket decode + buffer copy per packet** — **Fixed:**
   `DecodeOptions{Lazy:true, NoCopy:true}` on the local PacketSource and the
   SSH `NewPacket`. Audit: `copyPayload` is the only retention of frame bytes;
   all layer access is `packet.Layer(...)` (forces lazy decode); VXLAN/Geneve
   inner re-parse unaffected. Replay path left at defaults deliberately.
6. **Per-client 1s counts-frame JSON (~60–150KB/client/s at full churn)** —
   already delta-encoded in the tree (`Client.lastNodeCounts`/`lastEdgeCounts`,
   client-side merge in `applyCountsFrame`, reset on full sync). Reviewed
   end-to-end; no change needed.
7. **`DrainFlows` full sort per tick to keep top 60** — **Fixed:**
   `topKFlows` (server/websocket.go) single-pass bounded selection, same
   comparator (Packets desc, ties in drain order). Tests:
   `server/websocket_test.go`.
8. **`mergeNodeInto` O(E+maps) sweeps under the write lock** — transient
   (startup/DNS-completion merge bursts), not steady-state. A correct fix
   needs incremental reverse indexes; risk outweighs reward at this scale.
   **Accepted, not changed.**

Architectural note (accepted): the styled view still recomputes per client per
tick on one hub goroutine — fixes 1/6/7 remove the dominant costs inside that
shape. If client count grows well beyond ~5, the next step is sharing
BuildView results between identically-configured clients (raw mode already
does this via `rawTopoCache`).

### Measured after (this change)

- `go build ./...`, `go vet`, `go test -count=1 ./...` — all green.
- `-synth 500 -synth-rate 5000`, 3 WS clients: hub tick EMA **~5.7ms** of the
  100ms budget.
- `-synth 5000 -synth-rate 5000`, 2 WS clients: tick EMA **~27ms**.
- Live capture smoke (`-i any`): 1370 packets written, pcap valid under
  `tcpdump -r`; replay smoke: 11038 packets loaded.

### Protocol catalog moved to `protocols.json`

All protocol/port conventions formerly hardcoded in `capture/protocols.go`
now live in a user-editable JSON file: protocol definitions
(name/color/layer/layerNum), TCP/UDP port→protocol maps, and the ~200-entry
well-known service port labels. Shipped defaults are embedded via `go:embed`
(`capture/protocols.json`) and materialized to `./protocols.json` on first
run; `-protocols <path>` overrides. Loaded at startup — restart to apply
edits (lenient validation: bad entries are skipped with warnings, malformed
JSON falls back to embedded defaults).

- New semantic flags replace name-string special cases so edits can't break
  behavior: `generic` (TCP/UDP sentinel rule, also used by store),
  `decap` (VXLAN/Geneve overlay decap), `l2Endpoints` (LLDP/CDP),
  `discovery` (multicast-drop exemption), `defaultVisible` (drives
  `DefaultVisible/HiddenProtocols`).
- `DetectProtocol` resolves everything (port lookups and L2/L3 structural
  detections) through the registry, so custom colors/names propagate to edges.
  Port detection checks dst port first, then src.
- `GET /api/protocols` serves the catalog; the frontend builds its legend,
  layer grouping, and default-visible set from it at startup (hardcoded
  tables remain as fetch-failure fallback). Note: legend grouping now follows
  the catalog's layer labels — WireGuard/OpenVPN appear under
  "L7 · Application" rather than the old bespoke "VPN · Tunnel" group, K8s
  under L7, and a new "OT · Industrial" section appears; edit the `layer`
  strings in `protocols.json` if different grouping is wanted. The
  server-driven default-visible set (10 protocols) now matches what the
  server already enforced.
- Tests: `capture/protocols_test.go` (port regressions, overrides, malformed
  JSON, registry-resolved detection).

## Phase 9 — Burst smoothness (2026-08-05)

Target: the graph stays smooth through traffic spikes (NMAP-scan-class mass
node/edge churn). Real-ish time, but favor smoothness over instant reaction.
All mechanisms are server-side; the client needed no changes (calmer
positions = calm rendering; client frame cost was already ~8ms at 3k nodes).

### Findings (ranked) and resolutions

1. **Continuous layout reheat while the node set changes every tick** — scan
   arrivals re-heated the whole force graph to temp 70 every 100ms tick;
   existing nodes swam for the scan's duration and the settle-gate could
   never engage. **Fixed:** burst mode in `graph/layout.go`. The engine keeps
   a per-mode ring of the last `burstWindowSteps=10` node-set sizes; growth
   of `>burstGrowthAbs=25` nodes, or `>burstGrowthPct=10%` with an absolute
   floor of `burstGrowthPctFloor=10`, enters burst mode. During a burst,
   already-placed nodes are frozen at integration (they still exert forces;
   user pins untouched; frozen–frozen pairs are skipped in the O(n²) loop),
   newcomers seed near their connected neighbor as before and settle at a
   capped temperature (`forceReheatTemp*burstTempFactor = 70*0.3`), and the
   global reheat is suppressed. After `burstStableSteps=10` stable steps the
   burst exits with ONE gentle reheat at the expand-bloom temperature
   (70*0.55), then the graph re-settles and the skip gate resumes.
   Newcomers are tracked per mode across the whole burst (`burstNew`) so
   late arrivals keep settling while elders stay frozen. No-burst behavior
   is byte-identical. Tests: `graph/layout_test.go` (freeze, single exit
   reheat, small-add non-burst).
2. **Aggregation cliff + top-N flap** — visible-host count oscillating around
   the 300 threshold flipped the display strategy tick to tick, and the
   top-500 sort had no tiebreak/stickiness. **Fixed:** hysteresis — collapse
   at >300, re-expand only below `threshold*5/6` (~250,
   `aggregateReexpandDivisor=6`); deterministic ID tiebreak in the kept-node
   sort; incumbent stickiness (`incumbentBonus=1.1` on the sort key only,
   never on displayed counts). Per-view state lives in a pointer-keyed side
   table (`viewStates`, bounded at `maxViewStates=64`) since `BuildView`
   gets `ViewConfig` by value. Tests: `graph/view_test.go`
   (hysteresis band, top-N stability, displacement by a clear leader).
3. **Role/icon reclassification churn** — scan fan-out flipped the scanner to
   "gateway" (≥16 peers) and hosts to "server" mid-burst, each flip a style
   delta. **Fixed:** `commitRole` damping (`graph/classify.go`) — role flips
   commit only after the candidate persists `roleFlipDamping=2s`; first
   classification commits immediately; flickers within the window never
   commit. Damping state lives on `Node`; `SnapshotRaw` moved to the write
   lock to mutate it (once per tick, cheap). `GetNodeDetail` still shows the
   instantaneous role (detail panel only — intentional). Tests:
   `graph/classify_test.go`.
4. **Post-scan decay cliff** — 60s after a scan, all one-packet nodes/edges
   died in ONE sweep → mass removal delta + reheat. **Fixed:** staggered
   decay — each 10s sweep removes at most `maxNodeRemovalsPerSweep=50` nodes
   / `maxEdgeRemovalsPerSweep=100` edges, stalest first; eligibility
   unchanged. A 500-node scan corpse fades over ~100s in gentle waves.
   Tests: `graph/decay_test.go`.
5. **Fixed 100ms tick with no burst pacing** — **Fixed:** adaptive pacing in
   `server/websocket.go`. The fixed ticker is now a `time.Timer` re-armed at
   tick completion (slow ticks stretch the cadence naturally; coalescing
   preserved). Interval from the tick EMA: `<50ms → 100ms`,
   `50–80ms → 200ms`, `>80ms → 500ms` ceiling; step-up immediate, step-down
   only after the EMA holds the lower band for `pacingHysteresis=2s`;
   transitions logged once. The idle and layout-busy paths inherit the
   cadence automatically. Message formats and slow-consumer disconnect
   unchanged. Tests: `server/websocket_test.go` (`TestPacingBand`,
   `TestTickPacer`).

### Dev harness

`-synth-burst N` (with `-synth` only): 15s in, scanner `10.254.0.1` sweeps N
fresh hosts (10.254.b.c space) evenly over 5s — one-packet edges, then quiet.
Repeatable NMAP-shaped spike for before/after measurement.

### Measured (before → after; 2 WS clients)

Scenario `-synth 150 -synth-rate 2000 -synth-burst 100` (stays under the
aggregation threshold, so the raw churn hits the view directly):

- **Position-frame bytes during the 5s sweep: 373.6KB → 99.3KB (~73% cut).**
  Before: every node re-heated, positions for all ~250 nodes shipped every
  tick. After: only the ~100 newcomers move; 150 elders frozen byte-exact.
- **Post-sweep:** before ships another 113.7KB of cooling tail; after ships
  one 105.5KB reheat (the designed single re-balance) — then both go silent
  (0KB pos) in steady state via the settle-gate.
- Steady-state wire is dominated by the flow-particle feed (~60 flows/tick
  cap, ~110KB/s/client at 2000 pkt/s at 10Hz) — intentional, keeps the
  display alive; adaptive pacing (fix 5) is the knob that stretches it under
  real overload.

Scenario `-synth 500 -synth-rate 5000 -synth-burst 1000`, 3 clients: tick EMA
~11.6ms pre-burst, ~16ms during (before) vs ~16.2ms during settling back to
~11.9ms (after) — aggregation already masks node churn at that scale; the
hysteresis (fix 2) is what prevents threshold flap there. Pacing never
engaged in any test (EMA < 50ms): headroom insurance for larger views/more
clients, covered by unit tests.
