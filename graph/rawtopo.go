package graph

import (
	"math"
	"sort"

	"etherchimp/capture"
)

// RawTopology is the full, unaggregated graph shape for raw-scale clients
// (cosmos.gl renderer): no server layout, no top-N, no subnet supernodes, no
// per-node styling beyond a tier byte — the browser's GPU does the rest.
// Edges reference nodes by index into IDs, which is exactly the format the
// client's setLinks wants; protocols are indexed into a small table so each
// edge costs one byte on the wire.
type RawTopology struct {
	IDs   []string
	Tiers []uint8 // 0..4 traffic tier (log scale vs the busiest node)
	Flags []uint8 // bit0: group (multicast/broadcast rendezvous)

	EdgeA, EdgeB []uint32
	EdgeProto    []uint8 // index into Protos
	Protos       []capture.Protocol

	TotalPackets int // view-wide, for the client stats bar
}

// DefaultRawMaxNodes caps a raw topology frame; beyond it the quietest nodes
// are dropped (a 150k-point frame is already ~5MB and browser-bound).
const DefaultRawMaxNodes = 150000

// BuildRawTopology filters the snapshot by hidden protocols and flattens it to
// indexed arrays. When no protocol filter is active every live node is emitted
// so a host persists on its own lifetime (node decay) instead of vanishing the
// moment its last edge decays — the "grow and decay" behavior. With a filter
// active it matches the styled view and drops nodes left isolated by the filter.
func BuildRawTopology(raw RawSnapshot, hidden map[string]bool, maxNodes int) RawTopology {
	if maxNodes <= 0 {
		maxNodes = DefaultRawMaxNodes
	}

	nodeByID := make(map[string]*Node, len(raw.Nodes))
	for i := range raw.Nodes {
		nodeByID[raw.Nodes[i].IP] = &raw.Nodes[i]
	}

	visible := make([]*Edge, 0, len(raw.Edges))
	packetsByNode := make(map[string]int, len(raw.Nodes))
	total := 0
	for i := range raw.Edges {
		e := &raw.Edges[i]
		if hidden[e.Protocol.Name] {
			continue
		}
		if nodeByID[e.From] == nil || nodeByID[e.To] == nil {
			continue
		}
		visible = append(visible, e)
		total += e.PacketCount
		packetsByNode[e.From] += e.PacketCount
		if e.To != e.From {
			packetsByNode[e.To] += e.PacketCount
		}
	}

	// Without a protocol filter, seed every live node as a candidate so it is
	// emitted even with no visible edge — persistence is tied to node lifetime,
	// not edge lifetime. Uses the node's own packet count for tier/cap ranking.
	if len(hidden) == 0 {
		for i := range raw.Nodes {
			id := raw.Nodes[i].IP
			if _, ok := packetsByNode[id]; !ok {
				packetsByNode[id] = raw.Nodes[i].PacketCount
			}
		}
	}

	// Cap: keep the busiest nodes, drop edges touching dropped ones.
	if len(packetsByNode) > maxNodes {
		ids := make([]string, 0, len(packetsByNode))
		for id := range packetsByNode {
			ids = append(ids, id)
		}
		sort.Slice(ids, func(a, b int) bool { return packetsByNode[ids[a]] > packetsByNode[ids[b]] })
		for _, id := range ids[maxNodes:] {
			delete(packetsByNode, id)
		}
	}

	t := RawTopology{TotalPackets: total}
	index := make(map[string]uint32, len(packetsByNode))
	maxPackets := 0
	for _, p := range packetsByNode {
		if p > maxPackets {
			maxPackets = p
		}
	}
	logMax := math.Log1p(float64(maxPackets))

	addNode := func(id string) uint32 {
		if idx, ok := index[id]; ok {
			return idx
		}
		n := nodeByID[id]
		idx := uint32(len(t.IDs))
		index[id] = idx
		t.IDs = append(t.IDs, id)
		tier := uint8(0)
		if logMax > 0 {
			tier = uint8(math.Min(4, math.Floor(math.Log1p(float64(packetsByNode[id]))/logMax*4.999)))
		}
		t.Tiers = append(t.Tiers, tier)
		var flags uint8
		if n.IsGroup {
			flags |= 1
		}
		t.Flags = append(t.Flags, flags)
		return idx
	}

	protoIdx := make(map[string]uint8)
	for _, e := range visible {
		if _, keepA := packetsByNode[e.From]; !keepA {
			continue
		}
		if _, keepB := packetsByNode[e.To]; !keepB {
			continue
		}
		pi, ok := protoIdx[e.Protocol.Name]
		if !ok {
			if len(t.Protos) >= 255 {
				pi = 0 // proto table overflow: fold into the first entry
			} else {
				pi = uint8(len(t.Protos))
				t.Protos = append(t.Protos, e.Protocol)
				protoIdx[e.Protocol.Name] = pi
			}
		}
		t.EdgeA = append(t.EdgeA, addNode(e.From))
		t.EdgeB = append(t.EdgeB, addNode(e.To))
		t.EdgeProto = append(t.EdgeProto, pi)
	}

	// Emit any node that survived the cap but wasn't referenced by a visible
	// edge (standalone nodes). addNode is idempotent, so edge endpoints already
	// emitted are skipped. Iterating raw.Nodes keeps the order deterministic.
	for i := range raw.Nodes {
		id := raw.Nodes[i].IP
		if _, keep := packetsByNode[id]; keep {
			addNode(id)
		}
	}
	return t
}
