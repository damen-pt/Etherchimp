package graph

import (
	"math"
	"sort"
	"strings"

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
)

// DefaultVisibleProtocols are the "general" protocols shown to a freshly
// connected client. Everything else starts hidden until the user opts in.
// Mirrors the client-side default that used to live in app.js.
var DefaultVisibleProtocols = map[string]bool{
	"ARP": true, "ICMP": true, "TCP": true, "UDP": true,
	"HTTP": true, "HTTPS": true, "DNS": true, "SSH": true,
	"WireGuard": true, "OpenVPN": true,
	// Note: the K8s · Cluster protocols (VXLAN/Geneve/K8s-API/etcd/Kubelet) are
	// intentionally hidden by default — enable them in the filters when needed.
}

// DefaultHiddenProtocols returns the set of protocol names a new client should
// hide by default: every known protocol not in DefaultVisibleProtocols.
func DefaultHiddenProtocols() map[string]bool {
	hidden := make(map[string]bool)
	for _, p := range capture.GetAllProtocols() {
		if !DefaultVisibleProtocols[p.Name] {
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
	// (0 -> DefaultAggregateThreshold); ExpandedSubnets lists the /24 CIDRs the
	// user has opened back up into individual hosts.
	AggregateThreshold int
	ExpandedSubnets    map[string]bool

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
}

// ViewEdge is a render-ready edge. Hidden edges are never emitted.
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

	// Phase 4/5: hierarchical subnet aggregation. Above the threshold, hosts
	// sharing a /24 collapse into one supernode per subnet; if the view is
	// STILL over budget, /24 supernodes (and loose hosts) collapse further into
	// /16 supernodes. Expansion peels one level: expanding a /16 reveals its
	// /24 supernodes, expanding a /24 reveals hosts. Supernodes carry their
	// members' summed counters and compete in top-N selection like any node.
	aggThreshold := cfg.AggregateThreshold
	if aggThreshold <= 0 {
		aggThreshold = DefaultAggregateThreshold
	}
	var hostToSuper map[string]string // collapsed host/super ID -> visible supernode ID
	superHosts := map[string]int{}    // supernode ID -> member host count

	// collapseLevel folds kept-nodes into supernodes keyed by cidrOf (empty key
	// = never collapse). Members already counted in superHosts contribute their
	// own host counts. Mutates kept/hostToSuper/superHosts/visible.
	collapseLevel := func(cidrOf func(*Node) string) {
		groups := make(map[string][]int)
		for i := range kept {
			if isGroup(&kept[i]) {
				continue // multicast/broadcast groups stay as-is
			}
			cidr := cidrOf(&kept[i])
			if cidr == "" || cfg.ExpandedSubnets[cidr] {
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
			if len(idxs) < minHostsToCollapse {
				continue
			}
			super := Node{
				IP:       cidr, // ID; can't collide with host IDs
				Hostname: cidr,
				// Network address as the node's IP so the subnet layout mode
				// groups each supernode into its own island.
				IPs: []string{cidr[:strings.IndexByte(cidr, '/')]},
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
				if mh := superHosts[memberID]; mh > 0 {
					hc += mh // member is itself a supernode (e.g. /24 in /16)
				} else {
					hc++
				}
			}
			superHosts[cidr] = hc
			supers = append(supers, super)
		}
		if len(supers) > 0 {
			newKept := supers
			for i := range kept {
				if !collapsed[i] {
					newKept = append(newKept, kept[i])
				}
			}
			kept = newKept
		}
	}

	if len(kept) > aggThreshold {
		// Level 1: hosts -> /24 supernodes.
		collapseLevel(func(n *Node) string {
			if superHosts[n.ID()] > 0 {
				return "" // already a supernode
			}
			s := primarySubnet24(*n)
			if s == "" {
				return "" // non-IPv4 hosts stay individual
			}
			return s + ".0/24"
		})
		// Level 2: still over budget -> fold /24 supers + loose hosts into /16s.
		if len(kept) > aggThreshold {
			collapseLevel(func(n *Node) string {
				id := n.ID()
				var s string
				if superHosts[id] > 0 {
					s = strings.TrimSuffix(id, ".0/24") // "a.b.c"
					if s == id {
						return "" // already a /16 (or other) supernode
					}
				} else {
					s = primarySubnet24(*n)
					if s == "" {
						return ""
					}
					// A host whose /24 the user explicitly expanded stays out.
					if cfg.ExpandedSubnets[s+".0/24"] {
						return ""
					}
				}
				dot := strings.LastIndexByte(s, '.')
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

	// Top-N by effective traffic.
	sort.Slice(kept, func(a, b int) bool {
		return effective(&kept[a]) > effective(&kept[b])
	})
	if len(kept) > maxNodes {
		kept = kept[:maxNodes]
	}
	keptIDs := make(map[string]bool, len(kept))
	for i := range kept {
		keptIDs[kept[i].ID()] = true
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
		// Subnet supernodes get their own look: box shape, size driven by how
		// many hosts they hold (not raw traffic, which would dwarf everything),
		// neutral tier — the client colors them distinctly via isSubnet.
		if hc := superHosts[vn.ID]; hc > 0 {
			vn.IsSubnet = true
			vn.HostCount = hc
			vn.Shape = "box"
			vn.Value = math.Sqrt(float64(hc)) * 6
			vn.ColorTier = 0
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
		viewEdges = append(viewEdges, ViewEdge{
			ID:             e.ID,
			From:           e.From,
			To:             e.To,
			Protocol:       e.Protocol,
			PacketCount:    e.PacketCount,
			ByteCount:      e.ByteCount,
			ForwardPackets: e.ForwardPackets,
			ReversePackets: e.ReversePackets,
			ForwardBytes:   e.ForwardBytes,
			ReverseBytes:   e.ReverseBytes,
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
