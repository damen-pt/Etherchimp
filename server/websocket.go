package server

import (
	"encoding/binary"
	"encoding/json"
	"log"
	"math"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"etherchimp/graph"
	"etherchimp/store"

	"github.com/gorilla/websocket"
)

const (
	// Time allowed to write a message to the peer
	writeWait = 10 * time.Second

	// Time allowed to read the next pong message from the peer
	pongWait = 60 * time.Second

	// Send pings to peer with this period (must be less than pongWait)
	pingPeriod = (pongWait * 9) / 10

	// Maximum message size allowed from peer. Large enough to hold a full
	// hidden-protocol set in a SetFiltersMsg.
	maxMessageSize = 8192
)

var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
	// Same-origin check to prevent cross-site WebSocket hijacking: a browser must
	// only connect from a page served by this host. Non-browser clients (no Origin
	// header) are allowed, matching the previous open behavior for tooling.
	CheckOrigin: func(r *http.Request) bool {
		origin := r.Header.Get("Origin")
		if origin == "" {
			return true
		}
		u, err := url.Parse(origin)
		if err != nil {
			return false
		}
		return strings.EqualFold(u.Host, r.Host)
	},
}

// outMsg is one outbound WebSocket message: JSON text (style deltas, counts
// frames) or a binary position frame.
type outMsg struct {
	data   []byte
	binary bool
}

// Client represents a WebSocket client. Each client has its own server-computed
// view: a filter set + layout mode (cfg) and the last view it was sent
// (lastNodes/lastEdges) for per-client delta detection.
type Client struct {
	hub  *Hub
	conn *websocket.Conn
	send chan outMsg

	mu        sync.Mutex // guards cfg, needsFull, lastNodes, lastEdges
	cfg       graph.ViewConfig
	needsFull bool // force a full styled view next tick (new client / filter / layout change)
	lastNodes map[string]graph.ViewNode
	lastEdges map[string]graph.ViewEdge
	// Positions last shipped to this client (via a full snapshot or a binary pos
	// frame), so each tick only encodes the nodes that actually moved.
	lastPos map[string]graph.Vec
	// Counter values last shipped in a counts frame, and when; counts travel at
	// countsInterval, not per tick, and only for entries whose numbers changed.
	lastNodeCounts map[string][2]int64
	lastEdgeCounts map[string][6]int64
	lastCountsAt   time.Time
	// Per-client layout engine: stepped over only this client's filtered view, so
	// hidden nodes don't spread the visible ones and filter changes re-converge.
	layout *graph.LayoutEngine
	// Timeline mode: non-nil when this client scrubs a stored capture instead
	// of watching the live graph (guarded by mu; see timeline.go).
	timeline *timelineState
	// Raw-scale streaming cadence marker (hub goroutine only; see rawstream.go).
	lastRawAt time.Time
}

// countsInterval is how often per-node/per-edge counters (tooltips, stats bar,
// protocol legend) are refreshed. Counters don't drive rendering, so they don't
// belong on the per-tick fast path.
const countsInterval = time.Second

// maxFlowsPerTick caps the traffic flows shipped per tick (they only feed the
// particle animation, which itself caps at ~220 live particles).
const maxFlowsPerTick = 60

// viewRebuildEveryLarge: above largeGraphNodes hosts, full view rebuilds run on
// every Nth tick (500ms cadence) instead of every 100ms tick — snapshotting and
// re-aggregating a 100k-node graph 10x/s costs more than the tick budget, and
// at that scale the rendered view is supernodes whose positions barely move
// (client easing hides the coarser cadence). needsFull requests (expand clicks,
// new clients, filter changes) bypass the skip so interaction stays snappy.
const (
	largeGraphNodes       = 20000
	viewRebuildEveryLarge = 5
)

// Adaptive tick pacing: the hub's tick cadence follows the smoothed tick cost
// (Hub.tickEMA) so a traffic burst stretches the update rate (2–5Hz) instead of
// letting a monolithic tick run permanently late at a pinned 10Hz.
const (
	// tickIntervalFast is the full real-time cadence while ticks are cheap.
	tickIntervalFast = 100 * time.Millisecond
	// tickIntervalBusy is used once the tick EMA crosses tickEMAMedium.
	tickIntervalBusy = 200 * time.Millisecond
	// tickIntervalMax is the ceiling past tickEMAHigh — the hub keeps updating
	// through a burst at 2Hz instead of degrading into late 10Hz ticks.
	tickIntervalMax = 500 * time.Millisecond

	// tickEMAMedium and tickEMAHigh are the tick-cost EMA thresholds selecting
	// the busy and max cadences respectively (see pacingBand).
	tickEMAMedium = 50 * time.Millisecond
	tickEMAHigh   = 80 * time.Millisecond

	// pacingHysteresis: the EMA must hold in a LOWER band for this long before
	// the cadence steps back down, so the rate doesn't oscillate around a
	// threshold. Step-ups are immediate (latency protection), step-downs patient.
	pacingHysteresis = 2 * time.Second
)

// pacingBand maps a tick-cost EMA to the cadence it calls for, before any
// hysteresis: <50ms → fast, 50–80ms → busy, >80ms → max.
func pacingBand(ema time.Duration) time.Duration {
	switch {
	case ema > tickEMAHigh:
		return tickIntervalMax
	case ema >= tickEMAMedium:
		return tickIntervalBusy
	default:
		return tickIntervalFast
	}
}

// tickPacer adapts the hub tick interval to the tick-cost EMA: it steps up the
// moment the EMA crosses into a higher band, but only steps down after the EMA
// has held in the lower band for pacingHysteresis. Transitions are logged once
// per change. All state is hub-goroutine only.
type tickPacer struct {
	interval time.Duration // current cadence
	lowSince time.Time     // when the EMA first sat below the current band (zero = not below)
}

// next returns the cadence for the following tick given the latest EMA.
// now is passed in so tests can drive the hysteresis clock deterministically.
func (p *tickPacer) next(ema time.Duration, now time.Time) time.Duration {
	target := pacingBand(ema)
	switch {
	case target > p.interval:
		p.set(target, ema) // burst: slow down immediately
	case target < p.interval:
		if p.lowSince.IsZero() {
			p.lowSince = now
		}
		if now.Sub(p.lowSince) >= pacingHysteresis {
			p.set(target, ema)
		}
	default:
		p.lowSince = time.Time{}
	}
	return p.interval
}

func (p *tickPacer) set(interval time.Duration, ema time.Duration) {
	if interval != p.interval {
		log.Printf("hub pacing: %v → %v (tick EMA %v)", p.interval, interval, ema.Round(time.Microsecond))
		p.interval = interval
	}
	p.lowSince = time.Time{}
}

// Hub maintains active WebSocket clients and computes per-client views.
type Hub struct {
	clients    map[*Client]bool
	register   chan *Client
	unregister chan *Client
	graphMgr   *graph.Manager
	overrides  *graph.OverrideStore
	resyncAll  chan struct{}

	tickEMA     time.Duration // smoothed tick cost (telemetry)
	lastTickLog time.Time
	tickSeq     uint64 // for the large-graph rebuild cadence

	// Timeline mode (requires -db): db is nil-safe, tlCache holds recent
	// window reconstructions (hub goroutine only — see timeline.go).
	db      *store.Store
	tlCache []tlCacheEntry
}

// MarkResyncAll asks the hub to send every client a fresh full view on the next
// tick. Used after an override change so customizations show immediately even
// when the graph and layout are otherwise idle. Non-blocking.
func (h *Hub) MarkResyncAll() {
	select {
	case h.resyncAll <- struct{}{}:
	default:
	}
}

// NewHub creates a new WebSocket hub. db may be nil (timeline mode disabled).
func NewHub(graphMgr *graph.Manager, overrides *graph.OverrideStore, db *store.Store) *Hub {
	return &Hub{
		clients:    make(map[*Client]bool),
		register:   make(chan *Client),
		unregister: make(chan *Client),
		graphMgr:   graphMgr,
		overrides:  overrides,
		resyncAll:  make(chan struct{}, 1),
		db:         db,
	}
}

// viewDelta is the per-client wire message: changed/new styled nodes & edges,
// removed IDs, traffic flows for animation, and a full-snapshot flag.
type viewDelta struct {
	Nodes         []graph.ViewNode     `json:"nodes"`
	Edges         []graph.ViewEdge     `json:"edges"`
	RemovedNodes  []string             `json:"removedNodes,omitempty"`
	RemovedEdges  []string             `json:"removedEdges,omitempty"`
	TrafficFlows  []graph.TrafficFlow  `json:"trafficFlows,omitempty"`
	SubnetIslands []graph.SubnetIsland `json:"subnetIslands,omitempty"`
	ProtocolStats map[string]int       `json:"protocolStats,omitempty"` // per-protocol packet totals (all, unfiltered)
	Stats         *viewStats           `json:"stats,omitempty"`         // view-wide totals for the client's stats bar
	IsFull        bool                 `json:"isFull,omitempty"`
	// Partial marks a CHUNKED full snapshot (Phase 5): the busiest nodes arrive
	// in the first message (IsFull+Partial) for instant first paint, the rest
	// stream in follow-up messages.
	Partial bool `json:"partial,omitempty"`
	// FullDone marks the message that COMPLETES a full snapshot — the only
	// message of an unchunked full, or the last chunk of a chunked one. Only
	// then does the client hold the complete view, so this is where it
	// reconciles stale local nodes/edges (server RemovedNodes are relative to
	// per-client state, which is empty on a fresh reconnect) and runs any
	// deferred camera fit.
	FullDone bool `json:"fullDone,omitempty"`
}

// fullChunkSize is how many nodes ride each message of a chunked full snapshot.
// The first chunk (the busiest nodes — BuildView keeps them traffic-sorted) is
// what the user sees instantly.
const fullChunkSize = 150

// viewStats carries the header-bar totals for the client's current view, so the
// client never recomputes them by walking its datasets.
type viewStats struct {
	NodeCount    int `json:"nodeCount"`
	EdgeCount    int `json:"edgeCount"`
	TotalPackets int `json:"totalPackets"`
}

// Run starts the hub's main loop
func (h *Hub) Run() {
	// The tick runs on a timer re-armed at the END of each iteration (delay
	// measured from tick completion) rather than a fixed ticker: slow ticks
	// naturally stretch the cadence, and like a ticker's 1-slot buffer, ticks
	// coalesce instead of queueing. The pacer adapts the interval to the
	// smoothed tick cost (h.tickEMA), so bursts run at 2–5Hz — this covers the
	// idle short-circuit and the anyLayoutBusy fast path in tick() too, since
	// both are entered at this same cadence.
	pacer := tickPacer{interval: tickIntervalFast}
	timer := time.NewTimer(pacer.interval)
	defer timer.Stop()

	for {
		select {
		case client := <-h.register:
			h.clients[client] = true
			log.Printf("Client connected (total: %d)", len(h.clients))
			// First view is sent on the next tick (needsFull was set at creation).

		case client := <-h.unregister:
			if _, ok := h.clients[client]; ok {
				delete(h.clients, client)
				close(client.send)
				log.Printf("Client disconnected (total: %d)", len(h.clients))
			}

		case <-h.resyncAll:
			// Force every client to receive a full styled view next tick.
			for client := range h.clients {
				client.mu.Lock()
				client.needsFull = true
				client.mu.Unlock()
			}

		case <-timer.C:
			h.tick()
			timer.Reset(pacer.next(h.tickEMA, time.Now()))
		}
	}
}

// tick computes and sends each client's view delta. Shared work (raw snapshot,
// flow drain) happens at most once per tick; per-client work is filter+style+diff.
func (h *Hub) tick() {
	if len(h.clients) == 0 {
		return
	}
	// Tick-duration telemetry: EMA logged every 30s so scale problems are
	// visible in the server log instead of only as client-side lag.
	tickStart := time.Now()
	defer func() {
		d := time.Since(tickStart)
		if h.tickEMA == 0 {
			h.tickEMA = d
		} else {
			h.tickEMA = (h.tickEMA*9 + d) / 10
		}
		if time.Since(h.lastTickLog) > 30*time.Second {
			h.lastTickLog = time.Now()
			log.Printf("hub tick: %v (EMA %v, %d clients)", d.Round(time.Microsecond), h.tickEMA.Round(time.Microsecond), len(h.clients))
		}
	}()
	dirty := h.graphMgr.IsDirty()

	// Per-client gating: whether anyone awaits a full, whether any client's own
	// layout is still converging (so we keep ticking), and whether subnet mode is
	// in use anywhere (to compute VLANs once).
	anyNeedsFull := false
	anyLayoutBusy := false
	subnetActive := false
	anyTimelineDirty := false
	for client := range h.clients {
		client.mu.Lock()
		mode := client.cfg.LayoutMode
		needsFull := client.needsFull
		tlDirty := client.timelineDirtyLocked()
		client.mu.Unlock()
		if needsFull {
			anyNeedsFull = true
		}
		if tlDirty {
			anyTimelineDirty = true
		}
		if mode == "subnet" {
			subnetActive = true
		}
		if client.layout.Unsettled(map[string]bool{mode: true}) {
			anyLayoutBusy = true
		}
	}

	if !dirty && !anyNeedsFull && !anyLayoutBusy && !anyTimelineDirty {
		return
	}

	// Adaptive cadence: at datacenter scale, dirty-driven rebuilds run at 500ms
	// instead of 100ms (see viewRebuildEveryLarge). Full-view requests, a
	// still-converging layout, and a moved timeline scrubber are never skipped.
	h.tickSeq++
	if dirty && !anyNeedsFull && !anyLayoutBusy && !anyTimelineDirty &&
		h.graphMgr.GetNodeCount() > largeGraphNodes &&
		h.tickSeq%viewRebuildEveryLarge != 0 {
		return
	}

	// Shared per-tick work, computed at most once and only when some client
	// actually consumes it this tick: the raw snapshot is a full O(nodes+edges)
	// copy that pure-timeline clients never read and raw clients read only on
	// their frame cadence; protocol totals are only shipped on fulls and 1s
	// counts frames. Flows are drained eagerly so they keep accumulating
	// per-interval semantics.
	h.graphMgr.ClearDirty()
	var raw graph.RawSnapshot
	rawTaken := false
	snapshotRaw := func() graph.RawSnapshot {
		if !rawTaken {
			raw = h.graphMgr.SnapshotRaw()
			rawTaken = true
		}
		return raw
	}
	var protoStats map[string]int
	getProtoStats := func() map[string]int {
		if protoStats == nil {
			protoStats = h.graphMgr.ProtocolCounts()
		}
		return protoStats
	}
	// Raw topologies flattened this tick, shared across raw clients with the
	// same hidden-protocol set (keyed by hiddenKey).
	rawTopoCache := make(map[string]graph.RawTopology)
	flows := h.graphMgr.DrainFlows()
	// Flows exist to animate particles (client caps at ~220 live particles), so
	// there is no point shipping more than the busiest handful per tick. At
	// datacenter scale DrainFlows can return one entry per active edge —
	// thousands — which without this cap dominated the wire.
	flows = topKFlows(flows, maxFlowsPerTick)
	var vlanByIP map[string]uint16
	if subnetActive {
		vlanByIP = h.graphMgr.VLANByIP()
	}
	var pins map[string]graph.Vec
	if h.overrides != nil {
		pins = h.overrides.Pins()
	}

	now := time.Now()
	for client := range h.clients {
		// Build/marshal each client's view under its own recover so a panic on one
		// client's data can't kill the hub goroutine and freeze updates for everyone.
		func() {
			defer func() {
				if r := recover(); r != nil {
					log.Printf("recovered panic while building client view: %v", r)
				}
			}()
			full := client.consumeNeedsFull()
			// Raw-scale clients (cosmos.gl): stream the full filtered topology
			// as binary snapshots; no layout, styling, positions, or counts.
			// Raw mode ignores the timeline, so mark any timeline position as
			// built — otherwise it stays dirty forever and defeats the hub's
			// idle short-circuit (continuous 100ms rebuilds).
			if client.snapshotCfg().Raw {
				if tl, active := client.timelineParams(); active {
					client.markTimelineBuilt(tl.t, tl.window)
				}
				h.sendRawTopology(client, snapshotRaw, full, rawTopoCache)
				return
			}
			// Timeline clients see a reconstructed window of a stored capture
			// instead of the live graph; flows (particles) don't exist there.
			var clientRaw graph.RawSnapshot
			clientFlows := flows
			if tl, active := client.timelineParams(); active {
				clientRaw = h.timelineRaw(tl.captureID, tl.t, tl.window)
				clientFlows = nil
				client.markTimelineBuilt(tl.t, tl.window)
			} else {
				clientRaw = snapshotRaw()
			}
			view := graph.BuildView(clientRaw, client.snapshotCfg(), client.layout, h.overrides, pins, vlanByIP)

			// 1) Style/topology delta (JSON): rare once the graph shape is stable —
			//    render-bucket damping means counter churn produces nothing here.
			//    Large fulls are chunked busiest-first for instant first paint.
			if delta := client.buildDelta(view, clientFlows, full); delta != nil {
				if full {
					// Legend breakdown rides fulls; afterwards it refreshes with
					// the 1s counts frame instead of every delta.
					delta.ProtocolStats = getProtoStats()
				}
				for _, chunk := range splitDelta(delta) {
					data, err := json.Marshal(chunk)
					if err == nil && !h.trySend(client, outMsg{data: data}) {
						return
					}
				}
			}
			// 2) Positions (binary, fast path): only nodes that moved this tick.
			if pos := client.buildPosFrame(view, full); pos != nil {
				if !h.trySend(client, outMsg{data: pos, binary: true}) {
					return
				}
			}
			// 3) Counters (JSON, 1s cadence): changed counts + stats + legend.
			if cf := client.buildCountsFrame(view, getProtoStats, full, now); cf != nil {
				if data, err := json.Marshal(cf); err == nil {
					h.trySend(client, outMsg{data: data})
				}
			}
		}()
	}
}

// splitDelta chunks a large full snapshot into progressive messages: the first
// carries the busiest fullChunkSize nodes (plus removals/stats/islands, and
// IsFull+Partial), the rest follow as plain add-deltas. Each edge rides the
// first chunk in which both its endpoints have been sent, so the client never
// receives an edge before its nodes. Small deltas pass through untouched.
func splitDelta(d *viewDelta) []*viewDelta {
	if !d.IsFull || len(d.Nodes) <= fullChunkSize {
		d.FullDone = d.IsFull
		return []*viewDelta{d}
	}
	nChunks := (len(d.Nodes) + fullChunkSize - 1) / fullChunkSize
	chunkOf := make(map[string]int, len(d.Nodes))
	for i, n := range d.Nodes {
		chunkOf[n.ID] = i / fullChunkSize
	}
	chunks := make([]*viewDelta, nChunks)
	for i := 0; i < nChunks; i++ {
		lo := i * fullChunkSize
		hi := lo + fullChunkSize
		if hi > len(d.Nodes) {
			hi = len(d.Nodes)
		}
		// Partial on every chunk: the client applies these immediately instead
		// of coalescing them in its throttle (which keeps only the newest
		// pending delta and would drop earlier chunks' nodes).
		chunks[i] = &viewDelta{Nodes: d.Nodes[lo:hi], Partial: true}
	}
	for _, e := range d.Edges {
		ci, ok1 := chunkOf[e.From]
		cj, ok2 := chunkOf[e.To]
		if !ok1 || !ok2 {
			continue // endpoint fell outside the full view; drop
		}
		if cj > ci {
			ci = cj
		}
		chunks[ci].Edges = append(chunks[ci].Edges, e)
	}
	first := chunks[0]
	first.IsFull = true
	first.Partial = true
	first.RemovedNodes = d.RemovedNodes
	first.RemovedEdges = d.RemovedEdges
	first.TrafficFlows = d.TrafficFlows
	first.SubnetIslands = d.SubnetIslands
	first.ProtocolStats = d.ProtocolStats
	first.Stats = d.Stats
	chunks[nChunks-1].FullDone = true
	return chunks
}

// topKFlows bounds the drained flows to the k busiest by packet count without
// a full O(n log n) sort: a single pass keeps a descending-Packets slice of at
// most k entries (insertion into the small slice is fine at k=60). The
// selection criterion is the old full sort's comparator — Packets descending —
// and ties keep drain order (a flow inserts after entries with equal Packets),
// so the result equals the first k of a stable descending sort. Slices already
// within the cap pass through unsorted, preserving the previous behavior.
func topKFlows(flows []graph.TrafficFlow, k int) []graph.TrafficFlow {
	if len(flows) <= k {
		return flows
	}
	top := make([]graph.TrafficFlow, 0, k)
	for _, f := range flows {
		i := 0
		for i < len(top) && top[i].Packets >= f.Packets {
			i++
		}
		if i == k {
			continue // smaller than (or tied below) everything currently kept
		}
		top = append(top, graph.TrafficFlow{})
		copy(top[i+1:], top[i:])
		top[i] = f
		if len(top) > k {
			top = top[:k]
		}
	}
	return top
}

// trySend queues a message for a client, dropping the client (slow consumer)
// when its buffer is full. Returns false if the client was dropped.
func (h *Hub) trySend(c *Client, m outMsg) bool {
	select {
	case c.send <- m:
		return true
	default:
		close(c.send)
		delete(h.clients, c)
		return false
	}
}

// consumeNeedsFull atomically reads and clears the client's needsFull flag.
func (c *Client) consumeNeedsFull() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	full := c.needsFull
	c.needsFull = false
	return full
}

// snapshotCfg returns a copy of the client's view config for use off-lock.
func (c *Client) snapshotCfg() graph.ViewConfig {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.cfg
}

// valueBucket quantizes a node's size driver into ~5% steps. Node size only
// spans 20..30px on screen, so growth inside a bucket renders identically and
// must not trigger a delta. MUST mirror valueQ in static/app.js updateGraph.
func valueBucket(v float64) int {
	return int(math.Round(math.Log(v+1) * 20))
}

// widthBucket quantizes an edge's rendered width (log scale) to 0.25px steps.
// MUST mirror the width quantization in static/app.js updateGraph.
func widthBucket(packetCount int) int {
	return int(math.Round((math.Log(float64(packetCount)+1)*0.5 + 1) * 4))
}

// nodeRenderEqual reports whether two ViewNodes RENDER identically. Raw counters
// and position are deliberately excluded: counters travel in the 1s counts frame
// and positions in binary pos frames, so a node that merely accumulated packets
// (or drifted in the layout) produces no style delta at all. Value is compared
// by bucket for the same reason.
func nodeRenderEqual(a, b graph.ViewNode) bool {
	if a.ID != b.ID || a.Label != b.Label || a.IsGroup != b.IsGroup ||
		a.ColorTier != b.ColorTier || a.Shape != b.Shape || a.Color != b.Color ||
		a.Role != b.Role || a.Icon != b.Icon || a.DeviceInfo != b.DeviceInfo ||
		a.Pinned != b.Pinned || a.IsSubnet != b.IsSubnet || a.HostCount != b.HostCount ||
		valueBucket(a.Value) != valueBucket(b.Value) {
		return false
	}
	if len(a.IPs) != len(b.IPs) {
		return false
	}
	for i := range a.IPs {
		if a.IPs[i] != b.IPs[i] {
			return false
		}
	}
	return true
}

// edgeRenderEqual is the edge counterpart: protocol/topology plus the width
// bucket; raw packet/byte counters ride the counts frame instead.
func edgeRenderEqual(a, b graph.ViewEdge) bool {
	return a.ID == b.ID && a.From == b.From && a.To == b.To &&
		a.Protocol == b.Protocol &&
		widthBucket(a.PacketCount) == widthBucket(b.PacketCount)
}

// buildDelta diffs a freshly-built view against the last one sent to this client
// and returns the wire message (or nil when there is nothing to send). On a full
// build it emits every node/edge and sets IsFull. Comparison is by RENDER
// equality: counter-only and position-only changes never produce a style delta
// (they travel in counts and pos frames respectively).
func (c *Client) buildDelta(view graph.ViewSnapshot, flows []graph.TrafficFlow, full bool) *viewDelta {
	// Under subnet aggregation, remap each flow's endpoints to their supernode
	// so the particle animation keeps working on the aggregated view; flows
	// that collapse into a single supernode (intra-subnet) are dropped, and
	// flows landing on the same super-pair merge into one.
	if len(view.HostToSuper) > 0 && len(flows) > 0 {
		merged := make(map[string]*graph.TrafficFlow)
		order := make([]string, 0, len(flows))
		for _, f := range flows {
			if s, ok := view.HostToSuper[f.From]; ok {
				f.From = s
			}
			if s, ok := view.HostToSuper[f.To]; ok {
				f.To = s
			}
			if f.From == f.To {
				continue
			}
			f.EdgeID = graph.CanonicalEdgeID(f.From, f.To)
			if m, ok := merged[f.EdgeID]; ok {
				m.Packets += f.Packets
				m.Bytes += f.Bytes
			} else {
				cp := f
				merged[f.EdgeID] = &cp
				order = append(order, f.EdgeID)
			}
		}
		remapped := make([]graph.TrafficFlow, 0, len(order))
		for _, id := range order {
			remapped = append(remapped, *merged[id])
		}
		flows = remapped
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	var changedNodes []graph.ViewNode
	var changedEdges []graph.ViewEdge
	var removedNodes, removedEdges []string

	curNodes := make(map[string]bool, len(view.Nodes))
	for _, n := range view.Nodes {
		curNodes[n.ID] = true
		prev, ok := c.lastNodes[n.ID]
		if full || !ok || !nodeRenderEqual(prev, n) {
			changedNodes = append(changedNodes, n)
		}
		c.lastNodes[n.ID] = n
	}
	for id := range c.lastNodes {
		if !curNodes[id] {
			removedNodes = append(removedNodes, id)
			delete(c.lastNodes, id)
		}
	}

	curEdges := make(map[string]bool, len(view.Edges))
	for _, e := range view.Edges {
		curEdges[e.ID] = true
		prev, ok := c.lastEdges[e.ID]
		if full || !ok || !edgeRenderEqual(prev, e) {
			changedEdges = append(changedEdges, e)
		}
		c.lastEdges[e.ID] = e
	}
	for id := range c.lastEdges {
		if !curEdges[id] {
			removedEdges = append(removedEdges, id)
			delete(c.lastEdges, id)
		}
	}

	if !full && len(changedNodes) == 0 && len(changedEdges) == 0 &&
		len(removedNodes) == 0 && len(removedEdges) == 0 && len(flows) == 0 {
		return nil
	}

	delta := &viewDelta{
		Nodes:         changedNodes,
		Edges:         changedEdges,
		RemovedNodes:  removedNodes,
		RemovedEdges:  removedEdges,
		TrafficFlows:  flows,
		SubnetIslands: view.SubnetIslands,
		IsFull:        full,
	}
	// Stats ride full snapshots (so the header fills immediately on connect);
	// afterwards they refresh with the 1s counts frame, not per delta.
	if full {
		delta.Stats = viewStatsFor(view)
	}
	return delta
}

func viewStatsFor(view graph.ViewSnapshot) *viewStats {
	stats := &viewStats{NodeCount: len(view.Nodes), EdgeCount: len(view.Edges)}
	// Sum edges, not nodes: every packet increments BOTH endpoint nodes, so a
	// node sum double-counts. Edge totals also match raw mode's stats bar.
	for i := range view.Edges {
		stats.TotalPackets += view.Edges[i].PacketCount
	}
	return stats
}

// buildPosFrame encodes the positions that changed since the last frame as a
// compact binary message the client applies without JSON parsing:
//
//	[u8 msgType=1][u16 count] then per node:
//	[u16 idLen][idLen bytes utf8 id][f32 x][f32 y]   (little-endian)
//
// On a full snapshot the positions ride the JSON (ViewNode.X/Y), so this only
// resets the cache and returns nil. Returns nil when nothing moved.
func (c *Client) buildPosFrame(view graph.ViewSnapshot, full bool) []byte {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.lastPos == nil || full {
		c.lastPos = make(map[string]graph.Vec, len(view.Nodes))
		for i := range view.Nodes {
			n := &view.Nodes[i]
			c.lastPos[n.ID] = graph.Vec{X: n.X, Y: n.Y}
		}
		return nil
	}

	var moved []*graph.ViewNode
	cur := make(map[string]bool, len(view.Nodes))
	for i := range view.Nodes {
		n := &view.Nodes[i]
		cur[n.ID] = true
		if p, ok := c.lastPos[n.ID]; !ok || p.X != n.X || p.Y != n.Y {
			moved = append(moved, n)
			c.lastPos[n.ID] = graph.Vec{X: n.X, Y: n.Y}
		}
	}
	for id := range c.lastPos {
		if !cur[id] {
			delete(c.lastPos, id)
		}
	}
	if len(moved) == 0 {
		return nil
	}

	size := 3
	for _, n := range moved {
		size += 2 + len(n.ID) + 8
	}
	buf := make([]byte, size)
	buf[0] = 1 // msgType: positions
	binary.LittleEndian.PutUint16(buf[1:], uint16(len(moved)))
	off := 3
	for _, n := range moved {
		binary.LittleEndian.PutUint16(buf[off:], uint16(len(n.ID)))
		off += 2
		off += copy(buf[off:], n.ID)
		binary.LittleEndian.PutUint32(buf[off:], math.Float32bits(float32(n.X)))
		off += 4
		binary.LittleEndian.PutUint32(buf[off:], math.Float32bits(float32(n.Y)))
		off += 4
	}
	return buf
}

// countsFrame is the 1s counter refresh: per-node and per-edge counters that
// changed since the last frame, plus the stats-bar totals and the (unfiltered)
// per-protocol breakdown for the legend. Node values are [packets, bytes];
// edge values are [packets, bytes, fwdPkts, revPkts, fwdBytes, revBytes].
type countsFrame struct {
	Type          string              `json:"type"` // "counts"
	Nodes         map[string][2]int64 `json:"nodes,omitempty"`
	Edges         map[string][6]int64 `json:"edges,omitempty"`
	Stats         *viewStats          `json:"stats"`
	ProtocolStats map[string]int      `json:"protocolStats,omitempty"`
}

// buildCountsFrame returns the counts frame for this tick, or nil when the
// interval hasn't elapsed. full resets the baseline (the full snapshot already
// carried fresh counters on every node/edge). protoStats is a lazy getter so
// the per-protocol map is only materialized on ticks that actually emit a frame.
func (c *Client) buildCountsFrame(view graph.ViewSnapshot, protoStats func() map[string]int, full bool, now time.Time) *countsFrame {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.lastNodeCounts == nil || full {
		c.lastNodeCounts = make(map[string][2]int64, len(view.Nodes))
		c.lastEdgeCounts = make(map[string][6]int64, len(view.Edges))
		for i := range view.Nodes {
			n := &view.Nodes[i]
			c.lastNodeCounts[n.ID] = [2]int64{int64(n.PacketCount), n.ByteCount}
		}
		for i := range view.Edges {
			e := &view.Edges[i]
			c.lastEdgeCounts[e.ID] = [6]int64{int64(e.PacketCount), e.ByteCount,
				int64(e.ForwardPackets), int64(e.ReversePackets), e.ForwardBytes, e.ReverseBytes}
		}
		c.lastCountsAt = now
		return nil
	}
	if now.Sub(c.lastCountsAt) < countsInterval {
		return nil
	}
	c.lastCountsAt = now

	frame := &countsFrame{Type: "counts", ProtocolStats: protoStats()}
	nodeCounts := make(map[string][2]int64)
	curN := make(map[string]bool, len(view.Nodes))
	for i := range view.Nodes {
		n := &view.Nodes[i]
		curN[n.ID] = true
		v := [2]int64{int64(n.PacketCount), n.ByteCount}
		if c.lastNodeCounts[n.ID] != v {
			nodeCounts[n.ID] = v
			c.lastNodeCounts[n.ID] = v
		}
	}
	for id := range c.lastNodeCounts {
		if !curN[id] {
			delete(c.lastNodeCounts, id)
		}
	}
	edgeCounts := make(map[string][6]int64)
	curE := make(map[string]bool, len(view.Edges))
	for i := range view.Edges {
		e := &view.Edges[i]
		curE[e.ID] = true
		v := [6]int64{int64(e.PacketCount), e.ByteCount,
			int64(e.ForwardPackets), int64(e.ReversePackets), e.ForwardBytes, e.ReverseBytes}
		if c.lastEdgeCounts[e.ID] != v {
			edgeCounts[e.ID] = v
			c.lastEdgeCounts[e.ID] = v
		}
	}
	for id := range c.lastEdgeCounts {
		if !curE[id] {
			delete(c.lastEdgeCounts, id)
		}
	}
	frame.Nodes = nodeCounts
	frame.Edges = edgeCounts
	frame.Stats = viewStatsFor(view)
	return frame
}

// applyControl handles an inbound control message, updating the client's view
// config and forcing a full resync next tick.
func (c *Client) applyControl(msg ClientMessage) {
	c.mu.Lock()
	defer c.mu.Unlock()

	switch msg.Type {
	case msgSetFilters:
		var m SetFiltersMsg
		if json.Unmarshal(msg.Data, &m) != nil {
			return
		}
		hidden := make(map[string]bool, len(m.Hidden))
		for _, name := range m.Hidden {
			hidden[name] = true
		}
		c.cfg.Hidden = hidden
		c.needsFull = true
	case msgSetLayout:
		var m SetLayoutMsg
		if json.Unmarshal(msg.Data, &m) != nil || m.Mode == "" {
			return
		}
		c.cfg.LayoutMode = m.Mode
		c.needsFull = true
	case msgSetAggregation:
		var m SetAggregationMsg
		if json.Unmarshal(msg.Data, &m) != nil {
			return
		}
		exp := make(map[string]bool, len(m.Expanded))
		for _, cidr := range m.Expanded {
			exp[cidr] = true
		}
		full := make(map[string]bool, len(m.FullExpand))
		for _, cidr := range m.FullExpand {
			full[cidr] = true
		}
		c.cfg.ExpandedSubnets = exp
		c.cfg.FullExpand = full
		c.cfg.FocusCIDR = m.Focus
		switch m.ZoomBand {
		case "far", "mid", "near", "":
			c.cfg.ZoomBand = m.ZoomBand
		}
		c.cfg.AggregateThreshold = m.Threshold
		c.needsFull = true
	case msgResync:
		c.needsFull = true
	case msgSetTimeline:
		var m SetTimelineMsg
		if json.Unmarshal(msg.Data, &m) != nil {
			return
		}
		if m.CaptureID == 0 {
			// Exit timeline mode back to the live view.
			if c.timeline != nil {
				c.timeline = nil
				c.needsFull = true
			}
			return
		}
		win := int64(m.Window)
		if win <= 0 {
			win = 60 // mirror the live decay window
		}
		if c.timeline == nil || c.timeline.captureID != m.CaptureID {
			c.timeline = &timelineState{captureID: m.CaptureID}
			c.needsFull = true
		}
		c.timeline.t = int64(m.T)
		c.timeline.window = win
	case msgSetViewMode:
		var m SetViewModeMsg
		if json.Unmarshal(msg.Data, &m) != nil {
			return
		}
		raw := m.Mode == "raw"
		if raw != c.cfg.Raw {
			c.cfg.Raw = raw
			c.needsFull = true
		}
	}
}

// readPump pumps messages from the WebSocket connection to the hub
func (c *Client) readPump() {
	defer func() {
		c.hub.unregister <- c
		c.conn.Close()
	}()

	c.conn.SetReadLimit(maxMessageSize)
	c.conn.SetReadDeadline(time.Now().Add(pongWait))
	c.conn.SetPongHandler(func(string) error {
		c.conn.SetReadDeadline(time.Now().Add(pongWait))
		return nil
	})

	for {
		_, data, err := c.conn.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				log.Printf("WebSocket error: %v", err)
			}
			break
		}
		var msg ClientMessage
		if json.Unmarshal(data, &msg) == nil {
			c.applyControl(msg)
		}
	}
}

// writePump pumps messages from the hub to the WebSocket connection
func (c *Client) writePump() {
	ticker := time.NewTicker(pingPeriod)
	defer func() {
		ticker.Stop()
		c.conn.Close()
	}()

	for {
		select {
		case message, ok := <-c.send:
			c.conn.SetWriteDeadline(time.Now().Add(writeWait))
			if !ok {
				c.conn.WriteMessage(websocket.CloseMessage, []byte{})
				return
			}

			msgType := websocket.TextMessage
			if message.binary {
				msgType = websocket.BinaryMessage
			}
			w, err := c.conn.NextWriter(msgType)
			if err != nil {
				return
			}
			w.Write(message.data)

			if err := w.Close(); err != nil {
				return
			}

		case <-ticker.C:
			c.conn.SetWriteDeadline(time.Now().Add(writeWait))
			if err := c.conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				return
			}
		}
	}
}

// handleWebSocket handles WebSocket connections
func handleWebSocket(hub *Hub, w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("WebSocket upgrade failed: %v", err)
		return
	}

	client := &Client{
		hub:  hub,
		conn: conn,
		send: make(chan outMsg, 256),
		cfg: graph.ViewConfig{
			Hidden:     graph.DefaultHiddenProtocols(),
			LayoutMode: "force",
		},
		needsFull: true, // first tick sends a full styled snapshot
		lastNodes: make(map[string]graph.ViewNode),
		lastEdges: make(map[string]graph.ViewEdge),
		layout:    graph.NewLayoutEngine(),
	}

	client.hub.register <- client

	go client.writePump()
	go client.readPump()
}
