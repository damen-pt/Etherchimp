package graph

import (
	"math"
	"sort"
	"strings"
	"sync"

	"etherchimp/capture"
)

// view.go computes a render-ready, per-client view of the graph on the server.
// It ports the heavy work that used to run in the browser (static/app.js
// updateGraph / computeVisibleCounts / remapNodePopularity / styleNodeVisual):
// protocol filtering, top-N selection, traffic thresholds, and per-node
// size/color-tier styling. The client becomes a thin renderer.

// Default selection caps. The graph can hold far more than is useful to render;
// the server keeps only the busiest nodes/edges. Tuned for the 100-500 node
// target scale (well above the old client-side MAX_NODES=100/MAX_EDGES=200).
const (
	DefaultMaxNodes = 500
	DefaultMaxEdges = 1000

	// Phase 4: when a client's filtered view holds more hosts than this,
	// same-/24 hosts collapse into subnet supernodes (click to expand). Keeps
	// the rendered element count bounded no matter how big the capture is.
	DefaultAggregateThreshold = 300
	// A /24 only collapses when it has at least this many visible hosts;
	// smaller subnets stay as individual nodes.
	minHostsToCollapse = 3

	// Aggregation hysteresis: once the kept-host count crosses the aggregate
	// threshold upward the view collapses into subnet supernodes, and it then
	// STAYS collapsed until the count falls below threshold*(divisor-1)/divisor
	// (5/6, i.e. ~250 at the 300 default). Without this band a traffic burst
	// hovering around the threshold flips the display strategy (individual
	// hosts <-> supernodes) every tick.
	aggregateReexpandDivisor = 6

	// incumbentBonus multiplies the effective traffic of nodes that were in the
	// previous tick's kept set, but ONLY inside the top-N selection sort key —
	// displayed counts never change. A node hovering at the boundary then no
	// longer flaps in/out of the view on every tick; a challenger still needs
	// >~10% more traffic to displace an incumbent (a bias, not a lock).
	incumbentBonus = 1.1

	// maxViewStates bounds the per-client view-state side table (see
	// viewStateFor). Entries can't be removed on client disconnect (view.go
	// has no disconnect hook), so on overflow the table is reset — hysteresis
	// simply restarts for a tick.
	maxViewStates = 64

	// Phase 6: budgeted expand — when a user opens a dense CIDR, only the
	// busiest ExpandBudget members become individual nodes; the quiet remainder
	// stays as a residual "+N more" supernode (id = cidr+"+"). Prevents a single
	// expand from dumping hundreds of hosts into the force layout.
	DefaultExpandBudget = 120

	// Isolate-mode caps: when FocusCIDR is set the view only shows that cluster
	// and may raise the element budget so drill-down stays useful.
	DefaultIsolateMaxNodes = 800
	DefaultIsolateMaxEdges = 1600
)

// DefaultVisibleProtocols returns the set of "general" protocol names shown to
// a freshly connected client. Everything else starts hidden until the user
// opts in. Derived from the catalog's DefaultVisible flag (protocols.json).
// Note: the K8s · Cluster protocols (VXLAN/Geneve/K8s-API/etcd/Kubelet) are
// intentionally hidden by default — enable them in the filters when needed.
func DefaultVisibleProtocols() map[string]bool {
	visible := make(map[string]bool)
	for _, p := range capture.GetAllProtocols() {
		if p.DefaultVisible {
			visible[p.Name] = true
		}
	}
	return visible
}

// DefaultHiddenProtocols returns the set of protocol names a new client should
// hide by default: every known protocol not in DefaultVisibleProtocols.
func DefaultHiddenProtocols() map[string]bool {
	hidden := make(map[string]bool)
	for _, p := range capture.GetAllProtocols() {
		if !p.DefaultVisible {
			hidden[p.Name] = true
		}
	}
	return hidden
}

// ID returns the node's identity key. The Manager stores nodes keyed by a
// hostname-or-IP ID and mirrors that key into the IP field (graph.go), so edges'
// From/To and this value are the same namespace.
func (n Node) ID() string { return n.IP }

// CanonicalEdgeID returns the canonical (order-independent) edge ID for a node
// pair, matching getCanonicalEdgeID in graph.go. Exported for the hub, which
// re-keys traffic flows after subnet aggregation remaps their endpoints.
func CanonicalEdgeID(a, b string) string {
	id, _, _ := getCanonicalEdgeID(a, b)
	return id
}

// RawSnapshot is an unfiltered copy of the graph taken once per tick and shared
// across all per-client BuildView calls (so the snapshot work happens once).
type RawSnapshot struct {
	Nodes []Node
	Edges []Edge
}

// ViewConfig is a single client's view parameters.
type ViewConfig struct {
	Hidden     map[string]bool // protocol names to hide
	LayoutMode string          // "force" | "circular" | "subnet" | "gravity" | "hierarchical"
	MaxNodes   int             // 0 -> DefaultMaxNodes
	MaxEdges   int             // 0 -> DefaultMaxEdges

	// Phase 4 subnet aggregation: kicks in above AggregateThreshold hosts
	// (0 -> DefaultAggregateThreshold); ExpandedSubnets lists the /24 or /16
	// CIDRs the user has opened (budgeted expand — see ExpandBudget).
	AggregateThreshold int
	ExpandedSubnets    map[string]bool

	// Phase 6: FullExpand lists CIDRs that bypass the expand budget (show every
	// member). FocusCIDR isolates the view to one cluster. ZoomBand is
	// "far"|"mid"|"near"|"" and drives automatic aggregation depth.
	// ExpandBudget 0 -> DefaultExpandBudget.
	FullExpand   map[string]bool
	FocusCIDR    string
	ZoomBand     string
	ExpandBudget int

	// Raw switches the client to raw-scale streaming (cosmos.gl renderer): the
	// hub sends the full filtered topology as binary frames (BuildRawTopology)
	// and skips aggregation, top-N, layout, styling, and position/counts frames
	// entirely — the browser GPU lays the graph out itself.
	Raw bool
}

// ViewNode is a fully styled node ready to render. Label/ID/IPs/counts are
// passed through so the client can still build labels/tooltips; Value, ColorTier
// and Shape are computed server-side. Color/Role/Icon/X/Y are populated by later
// phases (overrides, classification, layout) and omitted when empty.
type ViewNode struct {
	ID          string   `json:"id"`
	Label       string   `json:"label"`
	IPs         []string `json:"ips,omitempty"`
	PacketCount int      `json:"packetCount"`
	ByteCount   int64    `json:"byteCount"`
	IsGroup     bool     `json:"isGroup,omitempty"`
	Value       float64  `json:"value"`
	ColorTier   int      `json:"colorTier"`
	Shape       string   `json:"shape"`
	Color       string   `json:"color,omitempty"`      // override; empty -> client derives from tier
	Role        string   `json:"role,omitempty"`       // Phase C
	Icon        string   `json:"icon,omitempty"`       // Phase C
	DeviceInfo  string   `json:"deviceInfo,omitempty"` // LLDP/CDP port/mgmt (switches/routers)
	X           float64  `json:"x"`                    // server-computed layout position
	Y           float64  `json:"y"`
	Pinned      bool     `json:"pinned,omitempty"`    // user-pinned position (Phase D)
	IsSubnet    bool     `json:"isSubnet,omitempty"`  // Phase 4: collapsed /24 supernode
	HostCount   int      `json:"hostCount,omitempty"` // member hosts in a collapsed subnet
	IsTail      bool     `json:"isTail,omitempty"`    // Phase 6: residual "+N more" after budgeted expand
}

// ViewEdge is a render-ready edge. Hidden edges are never emitted.
// Protocol carries Name + Color (canonical palette from capture/protocols.go)
// so every renderer paints the same link color (Slurm coral, SSH red, …).
// Width is precomputed server-side so clients don't redo log math.
type ViewEdge struct {
	ID             string           `json:"id"`
	From           string           `json:"from"`
	To             string           `json:"to"`
	Protocol       capture.Protocol `json:"protocol"`
	PacketCount    int              `json:"packetCount"`
	ByteCount      int64            `json:"byteCount"`
	ForwardPackets int              `json:"forwardPackets"`
	ReversePackets int              `json:"reversePackets"`
	ForwardBytes   int64            `json:"forwardBytes"`
	ReverseBytes   int64            `json:"reverseBytes"`
	Width          float64          `json:"width"` // render stroke width (px at 1×)
}

// ViewSnapshot is the full styled view for a client. The hub turns this into a
// per-client delta (changed nodes/edges, removed IDs) and attaches flows/IsFull.
type ViewSnapshot struct {
	Nodes         []ViewNode     `json:"nodes"`
	Edges         []ViewEdge     `json:"edges"`
	SubnetIslands []SubnetIsland `json:"subnetIslands,omitempty"` // subnet layout only
	// HostToSuper maps a collapsed host ID to its subnet supernode ID (empty
	// when aggregation is inactive). Server-side only: the hub uses it to remap
	// traffic flows into the aggregated view.
	HostToSuper map[string]string `json:"-"`
}

// viewState carries per-client BuildView state across ticks: whether the view
// is currently aggregated (hysteresis) and the previous tick's kept-node IDs
// (top-N incumbent stickiness).
type viewState struct {
	aggregated bool
	prevKept   map[string]bool
}

// viewStates is a side table keyed by the client's *LayoutEngine. BuildView
// takes ViewConfig BY VALUE (the server hands it a copy per tick), so the
// config itself can't carry state; the layout engine is the one per-client
// graph object that arrives by pointer. The hub calls BuildView from a single
// goroutine, so a viewState is only ever mutated by one goroutine at a time;
// the mutex guards the table itself.
var (
	viewStatesMu sync.Mutex
	viewStates   = make(map[*LayoutEngine]*viewState)
)

// viewStateFor returns the persistent view state for this client's layout
// engine, or nil when le is nil (tests, one-shot replay builds — stateless).
func viewStateFor(le *LayoutEngine) *viewState {
	if le == nil {
		return nil
	}
	viewStatesMu.Lock()
	defer viewStatesMu.Unlock()
	if len(viewStates) >= maxViewStates {
		viewStates = make(map[*LayoutEngine]*viewState)
	}
	vs := viewStates[le]
	if vs == nil {
		vs = &viewState{}
		viewStates[le] = vs
	}
	return vs
}

// BuildView runs the full server-side pipeline for one client view:
// filter -> visible counts -> drop dead nodes -> top-N nodes -> top-M edges ->
// thresholds -> LAYOUT (over just this view's nodes/edges) -> per-node styling.
// The layout engine is PER CLIENT and is stepped over only the displayed subset,
// so hidden/filtered nodes never spread the visible ones apart, and a filter
// change reheats the layout so new nodes animate in. A nil engine leaves
// positions at the origin (used only in tests).
func BuildView(raw RawSnapshot, cfg ViewConfig, le *LayoutEngine, ov *OverrideStore, pins map[string]Vec, vlanByIP map[string]uint16) ViewSnapshot {
	// A node counts as a "group" (compact box, excluded from traffic thresholds)
	// when the server flagged it OR the user designated it via an override.
	isGroup := func(n *Node) bool {
		if n.IsGroup {
			return true
		}
		if ov != nil {
			if o, ok := ov.Get(n.ID()); ok && o.IsGroup {
				return true
			}
		}
		return false
	}
	maxNodes := cfg.MaxNodes
	if maxNodes <= 0 {
		maxNodes = DefaultMaxNodes
	}
	maxEdges := cfg.MaxEdges
	if maxEdges <= 0 {
		maxEdges = DefaultMaxEdges
	}
	// Solar (cosmos explorer) targets hundreds–~1000 individual hosts — a graph
	// of planets, not two giant /24 boxes. Raise caps and defer aggregation so
	// the map actually shows hosts (see Image: collapsed supernodes felt empty).
	if cfg.LayoutMode == "solar" {
		if maxNodes < 1000 {
			maxNodes = 1000
		}
		if maxEdges < 2500 {
			maxEdges = 2500
		}
	}
	// Isolate mode: raise caps so a focused cluster can show more members.
	if cfg.FocusCIDR != "" {
		if maxNodes < DefaultIsolateMaxNodes {
			maxNodes = DefaultIsolateMaxNodes
		}
		if maxEdges < DefaultIsolateMaxEdges {
			maxEdges = DefaultIsolateMaxEdges
		}
	}
	expandBudget := cfg.ExpandBudget
	if expandBudget <= 0 {
		expandBudget = DefaultExpandBudget
	}
	// Zoom band adjusts how aggressively we collapse (semantic zoom).
	// User pin-open (ExpandedSubnets / FullExpand) always wins over auto-collapse.
	switch cfg.ZoomBand {
	case "far":
		if expandBudget > 40 {
			expandBudget = 40
		}
	case "near":
		// Allow denser individual hosts when zoomed in.
		if expandBudget < 200 {
			expandBudget = 200
		}
	}
	hidden := cfg.Hidden
	filtering := len(hidden) > 0

	// Per-node visible packet counts over UNfiltered edges, and the set of nodes
	// touched by at least one visible edge (its "survivors").
	visible := make(map[string]int)
	survivors := make(map[string]bool)
	for i := range raw.Edges {
		e := &raw.Edges[i]
		if filtering && hidden[e.Protocol.Name] {
			continue
		}
		visible[e.From] += e.PacketCount
		visible[e.To] += e.PacketCount
		survivors[e.From] = true
		survivors[e.To] = true
	}

	// Effective count drives sizing/coloring and selection: visible-only when a
	// filter is active, else the server total.
	effective := func(n *Node) int {
		if filtering {
			return visible[n.ID()]
		}
		return n.PacketCount
	}

	// Select nodes. When filtering, drop nodes whose only traffic was filtered
	// out (no visible edge) — this is what makes the mDNS group node and
	// mDNS-only hosts vanish, computed server-side now.
	kept := make([]Node, 0, len(raw.Nodes))
	for i := range raw.Nodes {
		n := raw.Nodes[i]
		if filtering && !survivors[n.ID()] {
			continue
		}
		kept = append(kept, n)
	}

	// Per-client state for aggregation hysteresis + top-N stickiness (nil when
	// no layout engine — one-shot builds stay stateless).
	vs := viewStateFor(le)

	// Phase 4/5/6: hierarchical subnet aggregation with budgeted expand.
	// Above the threshold, hosts sharing a /24 collapse into supernodes; if
	// still over budget, fold into /16s. Expansion peels one level. Phase 6
	// budgeted expand: opening a dense CIDR reveals only the top ExpandBudget
	// members; the rest become a residual "+N more" supernode (id = cidr+"+").
	aggThreshold := cfg.AggregateThreshold
	if aggThreshold <= 0 {
		aggThreshold = DefaultAggregateThreshold
	}
	// Solar explorer: show individual hosts up to the node cap. Collapsing to a
	// handful of /24 squares is the opposite of a fluid network graph.
	if cfg.LayoutMode == "solar" && (cfg.AggregateThreshold <= 0 || cfg.AggregateThreshold == DefaultAggregateThreshold) {
		aggThreshold = maxNodes + 1 // no collapse until past the top-N cap
	}
	switch cfg.ZoomBand {
	case "far":
		// Prefer heavy aggregation when zoomed out — but not in solar mode,
		// where orbits need real hosts to feel like a system map.
		if cfg.LayoutMode != "solar" && aggThreshold > 80 {
			aggThreshold = 80
		}
	case "near":
		// Stay expanded longer when zoomed in.
		if aggThreshold < 600 {
			aggThreshold = 600
		}
	}
	var hostToSuper map[string]string // collapsed host/super ID -> visible supernode ID
	superHosts := map[string]int{}    // supernode ID -> member host count
	tailSupers := map[string]bool{}   // residual "+N more" supernode IDs

	// isExpanded reports whether the user has pin-opened a CIDR (budgeted or full).
	isExpanded := func(cidr string) bool {
		return cfg.ExpandedSubnets[cidr] || (cfg.FullExpand != nil && cfg.FullExpand[cidr])
	}
	isFullExpand := func(cidr string) bool {
		return cfg.FullExpand != nil && cfg.FullExpand[cidr]
	}

	// memberHostCount returns how many leaf hosts a kept entry represents.
	memberHostCount := func(n *Node) int {
		if mh := superHosts[n.ID()]; mh > 0 {
			return mh
		}
		return 1
	}

	// collapseLevel folds kept-nodes into supernodes keyed by cidrOf.
	// Expanded CIDRs get a budgeted partial expand instead of full reveal.
	// Mutates kept/hostToSuper/superHosts/visible/tailSupers.
	collapseLevel := func(cidrOf func(*Node) string) {
		groups := make(map[string][]int)
		for i := range kept {
			if isGroup(&kept[i]) {
				continue // multicast/broadcast groups stay as-is
			}
			// Residual tails and other supers already in superHosts are only
			// re-grouped when cidrOf returns a parent key (e.g. /24 -> /16).
			cidr := cidrOf(&kept[i])
			if cidr == "" {
				continue
			}
			groups[cidr] = append(groups[cidr], i)
		}
		if hostToSuper == nil {
			hostToSuper = make(map[string]string)
		}
		collapsed := make(map[int]bool)
		var supers []Node

		for cidr, idxs := range groups {
			// Fully open: leave every member as its own node.
			if isFullExpand(cidr) {
				continue
			}
			// Budgeted expand: keep the busiest ExpandBudget members free;
			// fold the quiet remainder into a residual tail supernode.
			if isExpanded(cidr) {
				if len(idxs) <= expandBudget {
					continue
				}
				sort.Slice(idxs, func(a, b int) bool {
					return effective(&kept[idxs[a]]) > effective(&kept[idxs[b]])
				})
				tailID := residualSuperID(cidr)
				tail := Node{
					IP:       tailID,
					Hostname: cidr, // base CIDR for labels / expand-more
					IPs:      []string{networkAddrOfCIDR(cidr)},
				}
				hc := 0
				for _, i := range idxs[expandBudget:] {
					collapsed[i] = true
					memberID := kept[i].ID()
					hostToSuper[memberID] = tailID
					tail.PacketCount += kept[i].PacketCount
					tail.ByteCount += kept[i].ByteCount
					visible[tailID] += visible[memberID]
					hc += memberHostCount(&kept[i])
				}
				superHosts[tailID] = hc
				tailSupers[tailID] = true
				supers = append(supers, tail)
				continue
			}
			// Fully collapsed supernode.
			if len(idxs) < minHostsToCollapse {
				continue
			}
			super := Node{
				IP:       cidr, // ID; can't collide with host IDs
				Hostname: cidr,
				// Network address as the node's IP so the subnet layout mode
				// groups each supernode into its own island.
				IPs: []string{networkAddrOfCIDR(cidr)},
			}
			hc := 0
			for _, i := range idxs {
				collapsed[i] = true
				memberID := kept[i].ID()
				hostToSuper[memberID] = cidr
				super.PacketCount += kept[i].PacketCount
				super.ByteCount += kept[i].ByteCount
				// Keep effective() correct when a protocol filter is active.
				visible[cidr] += visible[memberID]
				hc += memberHostCount(&kept[i])
			}
			superHosts[cidr] = hc
			supers = append(supers, super)
		}
		if len(supers) > 0 || len(collapsed) > 0 {
			newKept := supers
			for i := range kept {
				if !collapsed[i] {
					newKept = append(newKept, kept[i])
				}
			}
			kept = newKept
		}
	}

	// Always aggregate when over threshold; at "far" zoom force aggregation even
	// for modest graphs so the overview stays legible.
	forceAgg := cfg.ZoomBand == "far" && len(kept) > minHostsToCollapse
	// Hysteresis: once aggregated, stay aggregated until the kept-host count
	// drops well below the threshold, so a burst hovering near it doesn't flip
	// the display strategy (hosts <-> supernodes) tick to tick.
	reexpandFloor := aggThreshold * (aggregateReexpandDivisor - 1) / aggregateReexpandDivisor
	aggActive := len(kept) > aggThreshold || forceAgg
	if !aggActive && vs != nil && vs.aggregated && len(kept) > reexpandFloor {
		aggActive = true
	}
	if aggActive {
		// Level 1: hosts -> /24 supernodes.
		collapseLevel(func(n *Node) string {
			id := n.ID()
			if superHosts[id] > 0 {
				return "" // already a supernode (including residual tails)
			}
			s := primarySubnet24(*n)
			if s == "" {
				return "" // non-IPv4 hosts stay individual
			}
			return s + ".0/24"
		})
		// Level 2: still over budget (or far zoom) -> fold /24 supers + loose
		// hosts into /16s. Hosts/tails whose /24 is pin-expanded stay out so
		// the peel-one-level UX is preserved.
		needL2 := len(kept) > aggThreshold || cfg.ZoomBand == "far"
		if needL2 {
			collapseLevel(func(n *Node) string {
				id := n.ID()
				var s string
				if superHosts[id] > 0 {
					base := baseCIDR(id)
					// Expanded /24 (or its residual tail) must stay visible —
					// do not fold it back into a /16 while the user has it open.
					if isExpanded(base) {
						return ""
					}
					s = strings.TrimSuffix(base, ".0/24") // "a.b.c" from "a.b.c.0/24"
					if s == base {
						return "" // already a /16 (or other) supernode
					}
				} else {
					s = primarySubnet24(*n)
					if s == "" {
						return ""
					}
					// A host whose /24 the user explicitly expanded stays out.
					if isExpanded(s + ".0/24") {
						return ""
					}
				}
				dot := strings.LastIndexByte(s, '.')
				if dot < 0 {
					return ""
				}
				return s[:dot] + ".0.0/16"
			})
		}
		// Flatten host -> /24 -> /16 chains so flow/edge remapping is one hop.
		for id, s := range hostToSuper {
			if s2, ok := hostToSuper[s]; ok {
				hostToSuper[id] = s2
			}
		}
		if len(superHosts) == 0 {
			hostToSuper = nil
		}
	}
	isSuper := func(id string) bool { return superHosts[id] > 0 }
	remapID := func(id string) string {
		if hostToSuper != nil {
			if s, ok := hostToSuper[id]; ok {
				return s
			}
		}
		return id
	}

	// Isolate mode: keep only nodes that belong to the focused cluster.
	if focus := cfg.FocusCIDR; focus != "" {
		focus = baseCIDR(focus)
		filtered := kept[:0]
		for i := range kept {
			if nodeBelongsToCIDR(&kept[i], focus, isSuper) {
				filtered = append(filtered, kept[i])
			}
		}
		kept = filtered
	}

	// Top-N by effective traffic. Protect focused/expanded-cluster members so
	// a busy unrelated hub can't push the drill-down set off the screen.
	var prevKept map[string]bool
	if vs != nil {
		prevKept = vs.prevKept
	}
	sort.Slice(kept, func(a, b int) bool {
		ka, kb := effective(&kept[a]), effective(&kept[b])
		// Incumbent stickiness: nodes kept last tick get a small bonus on the
		// sort key only, so boundary nodes don't flap in/out every tick.
		if prevKept != nil {
			if prevKept[kept[a].ID()] {
				ka = int(float64(ka) * incumbentBonus)
			}
			if prevKept[kept[b].ID()] {
				kb = int(float64(kb) * incumbentBonus)
			}
		}
		if ka != kb {
			return ka > kb
		}
		// ID tiebreak (mirrors the edge sort below): equal-traffic nodes never
		// reshuffle between ticks.
		return kept[a].ID() < kept[b].ID()
	})
	if len(kept) > maxNodes {
		// Prefer keeping: focus members, residual tails, expanded-CIDR members.
		protected := make(map[string]bool)
		if cfg.FocusCIDR != "" {
			f := baseCIDR(cfg.FocusCIDR)
			for i := range kept {
				if nodeBelongsToCIDR(&kept[i], f, isSuper) {
					protected[kept[i].ID()] = true
				}
			}
		}
		for cidr := range cfg.ExpandedSubnets {
			for i := range kept {
				if nodeBelongsToCIDR(&kept[i], baseCIDR(cidr), isSuper) {
					protected[kept[i].ID()] = true
				}
			}
		}
		if len(protected) == 0 || len(protected) >= maxNodes {
			kept = kept[:maxNodes]
		} else {
			// Take all protected first, then fill with busiest unprotected.
			out := make([]Node, 0, maxNodes)
			seen := make(map[string]bool, maxNodes)
			for i := range kept {
				id := kept[i].ID()
				if protected[id] && len(out) < maxNodes {
					out = append(out, kept[i])
					seen[id] = true
				}
			}
			for i := range kept {
				if len(out) >= maxNodes {
					break
				}
				id := kept[i].ID()
				if !seen[id] {
					out = append(out, kept[i])
					seen[id] = true
				}
			}
			kept = out
		}
	}
	keptIDs := make(map[string]bool, len(kept))
	for i := range kept {
		keptIDs[kept[i].ID()] = true
	}
	// Persist per-view state for the next tick: the final kept set drives
	// incumbent stickiness, the aggregation flag drives the hysteresis band.
	if vs != nil {
		vs.prevKept = keptIDs
		vs.aggregated = aggActive
	}

	// Thresholds from real (non-group, non-subnet) kept nodes' effective counts.
	// Group nodes and subnet supernodes are excluded so they don't skew the
	// scale (both aggregate lots of traffic by construction).
	maxCount := 1
	for i := range kept {
		if isGroup(&kept[i]) || isSuper(kept[i].ID()) {
			continue
		}
		if c := effective(&kept[i]); c > maxCount {
			maxCount = c
		}
	}
	lowThreshold := float64(maxCount) * 0.2
	mediumThreshold := float64(maxCount) * 0.5

	// Select edges: both endpoints kept and protocol not hidden, top-M by
	// packets. Under aggregation, endpoints remap to their supernode first;
	// edges landing on the same pair merge (summing counters, keeping the
	// dominant contributor's protocol) and intra-subnet edges disappear.
	var candEdges []Edge
	if hostToSuper == nil {
		candEdges = make([]Edge, 0, len(raw.Edges))
		for i := range raw.Edges {
			e := raw.Edges[i]
			if filtering && hidden[e.Protocol.Name] {
				continue
			}
			if !keptIDs[e.From] || !keptIDs[e.To] {
				continue
			}
			candEdges = append(candEdges, e)
		}
	} else {
		merged := make(map[string]*Edge)
		domPk := make(map[string]int) // merged ID -> packets behind its Protocol pick
		for i := range raw.Edges {
			e := &raw.Edges[i]
			if filtering && hidden[e.Protocol.Name] {
				continue
			}
			f, t := remapID(e.From), remapID(e.To)
			if f == t {
				continue // intra-subnet traffic lives inside the supernode
			}
			if !keptIDs[f] || !keptIDs[t] {
				continue
			}
			id, cf, ct := getCanonicalEdgeID(f, t)
			m, ok := merged[id]
			if !ok {
				m = &Edge{ID: id, From: cf, To: ct, Protocol: e.Protocol}
				merged[id] = m
			}
			m.PacketCount += e.PacketCount
			m.ByteCount += e.ByteCount
			// Directional counters relative to the canonical From.
			if remapID(e.From) == m.From {
				m.ForwardPackets += e.ForwardPackets
				m.ReversePackets += e.ReversePackets
				m.ForwardBytes += e.ForwardBytes
				m.ReverseBytes += e.ReverseBytes
			} else {
				m.ForwardPackets += e.ReversePackets
				m.ReversePackets += e.ForwardPackets
				m.ForwardBytes += e.ReverseBytes
				m.ReverseBytes += e.ForwardBytes
			}
			if e.PacketCount > domPk[id] {
				domPk[id] = e.PacketCount
				m.Protocol = e.Protocol
			}
		}
		candEdges = make([]Edge, 0, len(merged))
		for _, m := range merged {
			candEdges = append(candEdges, *m)
		}
	}
	sort.Slice(candEdges, func(a, b int) bool {
		if candEdges[a].PacketCount != candEdges[b].PacketCount {
			return candEdges[a].PacketCount > candEdges[b].PacketCount
		}
		return candEdges[a].ID < candEdges[b].ID
	})
	if len(candEdges) > maxEdges {
		candEdges = candEdges[:maxEdges]
	}

	// Per-node collision radius matching the client's render size (nodes scale to
	// ~15..50px by value). Feeding these to the layout keeps room around big
	// circles so they don't overlap neighbouring nodes' labels.
	radii := make(map[string]float64, len(kept))
	minV, maxV := math.MaxFloat64, 0.0
	vals := make([]float64, len(kept))
	for i := range kept {
		v := nodeValue(effective(&kept[i]), isGroup(&kept[i]))
		vals[i] = v
		if v < minV {
			minV = v
		}
		if v > maxV {
			maxV = v
		}
	}
	for i := range kept {
		r := layoutNodeRadiusMin
		if maxV > minV {
			r = layoutNodeRadiusMin + (layoutNodeRadiusMax-layoutNodeRadiusMin)*(vals[i]-minV)/(maxV-minV)
		}
		if isSuper(kept[i].ID()) {
			r = layoutNodeRadiusMax // supernodes render big; keep label room
		}
		radii[kept[i].ID()] = r
	}

	// Advance the PER-CLIENT layout over exactly the nodes/edges being shown, so
	// the view stays compact and filtered-out nodes don't push the visible ones
	// apart. Changing the filter changes this set, which reheats the force layout
	// (new positions) and makes the added nodes animate in on the client.
	if le != nil {
		le.Step(RawSnapshot{Nodes: kept, Edges: candEdges},
			map[string]bool{cfg.LayoutMode: true}, pins, vlanByIP, radii)
	}

	// Style nodes (positions come from the layout just stepped above).
	viewNodes := make([]ViewNode, 0, len(kept))
	for i := range kept {
		n := &kept[i]
		count := effective(n)
		// Phase 5 slim wire: IPs and DeviceInfo are NOT streamed — they only
		// matter on hover/details, where the client lazily fetches /api/node.
		// Role stays (it drives the color-by-role render mode and is tiny).
		// An unresolved hostname (nil DNS resolver in replay ingest, or DNS
		// still pending) falls back to the node ID so labels are never blank.
		label := n.Hostname
		if label == "" {
			label = n.ID()
		}
		vn := ViewNode{
			ID:          n.ID(),
			Label:       label,
			PacketCount: n.PacketCount,
			ByteCount:   n.ByteCount,
			IsGroup:     n.IsGroup,
			Role:        n.Role,
			Icon:        n.Icon,
		}
		grp := isGroup(n)
		vn.IsGroup = grp
		styleNode(&vn, count, grp, lowThreshold, mediumThreshold)
		// Subnet supernodes: large circles (not boxes — boxes looked like a UI
		// glitch on the map). Size from host count; residual tails run warmer.
		if hc := superHosts[vn.ID]; hc > 0 {
			vn.IsSubnet = true
			vn.HostCount = hc
			vn.Shape = "dot"
			vn.Value = math.Sqrt(float64(hc)) * 6
			if tailSupers[vn.ID] {
				vn.IsTail = true
				vn.Label = residualLabel(vn.ID, hc)
				vn.ColorTier = 2 // warmer than collapsed supernodes
			} else {
				vn.ColorTier = 0
			}
		}
		if le != nil {
			p := le.Position(cfg.LayoutMode, vn.ID)
			// Quantize to whole pixels so a converged layout produces identical
			// values tick-to-tick and the per-client diff stops re-sending it.
			vn.X = math.Round(p.X)
			vn.Y = math.Round(p.Y)
		}
		// Apply user overrides last so they win over computed styling.
		if ov != nil {
			if o, ok := ov.Get(vn.ID); ok {
				if o.Label != "" {
					vn.Label = o.Label
				}
				if o.Color != "" {
					vn.Color = o.Color
				}
				if o.Icon != "" {
					vn.Icon = o.Icon
				}
				if o.PinnedX != nil && o.PinnedY != nil {
					vn.X = math.Round(*o.PinnedX)
					vn.Y = math.Round(*o.PinnedY)
					vn.Pinned = true
				}
			}
		}
		viewNodes = append(viewNodes, vn)
	}

	viewEdges := make([]ViewEdge, 0, len(candEdges))
	for i := range candEdges {
		e := &candEdges[i]
		// log-scaled width matches the WebGL/vis path so cosmos and map agree.
		w := math.Log1p(float64(e.PacketCount))*0.5 + 1
		if w < 1 {
			w = 1
		}
		if w > 8 {
			w = 8
		}
		// Ensure protocol color is always populated (defensive).
		proto := e.Protocol
		if proto.Color == "" {
			proto.Color = "#95a5a6"
		}
		if proto.Name == "" {
			proto.Name = "Other"
		}
		viewEdges = append(viewEdges, ViewEdge{
			ID:             e.ID,
			From:           e.From,
			To:             e.To,
			Protocol:       proto,
			PacketCount:    e.PacketCount,
			ByteCount:      e.ByteCount,
			ForwardPackets: e.ForwardPackets,
			ReversePackets: e.ReversePackets,
			ForwardBytes:   e.ForwardBytes,
			ReverseBytes:   e.ReverseBytes,
			Width:          w,
		})
	}

	snap := ViewSnapshot{Nodes: viewNodes, Edges: viewEdges, HostToSuper: hostToSuper}

	// In subnet mode, attach the dotted-ring islands — but only those that still
	// contain a kept node, so filtered-away subnets don't draw empty rings.
	if le != nil && cfg.LayoutMode == "subnet" {
		keptSubnets := make(map[string]bool)
		for i := range kept {
			s := primarySubnet24(kept[i])
			if s == "" {
				s = "unknown"
			}
			keptSubnets[s] = true
		}
		for _, isl := range le.Islands("subnet") {
			key := "unknown"
			if isl.CIDR != "unknown" {
				key = strings.TrimSuffix(isl.CIDR, ".0/24")
			}
			if keptSubnets[key] {
				snap.SubnetIslands = append(snap.SubnetIslands, isl)
			}
		}
	}

	return snap
}

// styleNode ports styleNodeVisual + getColorTier from app.js. Group nodes render
// as a fixed-size muted box (tier 0); real hosts are dots sized by sqrt(traffic)
// and tiered by the thresholds.
func styleNode(vn *ViewNode, count int, isGroup bool, low, medium float64) {
	vn.Value = nodeValue(count, isGroup)
	if isGroup {
		vn.Shape = "box"
		vn.ColorTier = 0
		return
	}
	vn.Shape = "dot"
	vn.ColorTier = colorTier(count, low, medium)
}

// residualSuperID is the synthetic id for a budgeted-expand tail supernode.
// The trailing '+' never appears in real IPv4 host or CIDR ids.
func residualSuperID(cidr string) string {
	return cidr + "+"
}

// baseCIDR strips a residual '+' suffix so focus/expand keys compare cleanly.
func baseCIDR(id string) string {
	return strings.TrimSuffix(id, "+")
}

// networkAddrOfCIDR returns the network address portion before the slash
// (e.g. "10.0.0.0/24" -> "10.0.0.0"). Falls back to the whole string.
func networkAddrOfCIDR(cidr string) string {
	if i := strings.IndexByte(cidr, '/'); i >= 0 {
		return cidr[:i]
	}
	return cidr
}

// residualLabel is the human-readable name for a "+N more" tail supernode.
func residualLabel(tailID string, hostCount int) string {
	return "+" + itoa(hostCount) + " more in " + baseCIDR(tailID)
}

// itoa avoids strconv for a tiny helper used only in residual labels.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

// nodeBelongsToCIDR reports whether n is the given CIDR supernode, its residual
// tail, a nested /24 under a focused /16, or a host inside that CIDR.
func nodeBelongsToCIDR(n *Node, cidr string, isSuper func(string) bool) bool {
	if cidr == "" {
		return true
	}
	cidr = baseCIDR(cidr)
	id := n.ID()
	if id == cidr || id == residualSuperID(cidr) {
		return true
	}
	// Nested supernode under a /16 focus: "a.b.c.0/24" belongs to "a.b.0.0/16".
	if isSuper != nil && isSuper(id) {
		base := baseCIDR(id)
		if strings.HasSuffix(cidr, "/16") && strings.HasSuffix(base, "/24") {
			return subnet16From24(base) == cidr
		}
		return false
	}
	if strings.HasSuffix(cidr, "/24") {
		s := primarySubnet24(*n)
		return s != "" && s+".0/24" == cidr
	}
	if strings.HasSuffix(cidr, "/16") {
		s := primarySubnet24(*n)
		if s == "" {
			return false
		}
		return subnet16From24(s+".0/24") == cidr
	}
	return false
}

// subnet16From24 maps "a.b.c.0/24" -> "a.b.0.0/16".
func subnet16From24(c24 string) string {
	base := strings.TrimSuffix(c24, ".0/24")
	if base == c24 {
		return ""
	}
	dot := strings.LastIndexByte(base, '.')
	if dot < 0 {
		return ""
	}
	return base[:dot] + ".0.0/16"
}

// nodeValue is the traffic-based size driver, kept in one place so the layout's
// collision radius matches the rendered node size.
func nodeValue(count int, isGroup bool) float64 {
	if isGroup {
		return 1
	}
	return math.Sqrt(float64(count)+1) * 3
}

// colorTier mirrors getColorTier in app.js.
func colorTier(count int, low, medium float64) int {
	switch {
	case count == 0:
		return 0
	case float64(count) < low:
		return 1
	case float64(count) < medium:
		return 2
	default:
		return 3
	}
}
