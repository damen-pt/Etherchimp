package graph

import (
	"math"
	"sort"
	"testing"

	"etherchimp/capture"
)

func findNode(nodes []ViewNode, id string) (ViewNode, bool) {
	for _, n := range nodes {
		if n.ID == id {
			return n, true
		}
	}
	return ViewNode{}, false
}

func hasEdge(edges []ViewEdge, id string) bool {
	for _, e := range edges {
		if e.ID == id {
			return true
		}
	}
	return false
}

// TestBuildViewStyling checks that node sizing and color tiers are computed
// server-side to match the old client (value=sqrt(count+1)*3, tier by threshold).
func TestBuildViewStyling(t *testing.T) {
	raw := RawSnapshot{
		Nodes: []Node{
			{IP: "10.0.0.1", Hostname: "10.0.0.1", PacketCount: 100},
			{IP: "10.0.0.2", Hostname: "10.0.0.2", PacketCount: 5},
			{IP: "224.0.0.251", Hostname: "mDNS (group)", IsGroup: true, PacketCount: 9999},
		},
		Edges: []Edge{
			{ID: "10.0.0.1<->10.0.0.2", From: "10.0.0.1", To: "10.0.0.2", Protocol: capture.ProtocolTCP, PacketCount: 100},
			{ID: "10.0.0.1<->224.0.0.251", From: "10.0.0.1", To: "224.0.0.251", Protocol: capture.ProtocolMDNS, PacketCount: 5},
		},
	}

	view := BuildView(raw, ViewConfig{}, nil, nil, nil, nil) // no filter

	n1, ok := findNode(view.Nodes, "10.0.0.1")
	if !ok {
		t.Fatal("expected node 10.0.0.1 in view")
	}
	wantValue := math.Sqrt(100+1) * 3
	if math.Abs(n1.Value-wantValue) > 1e-9 {
		t.Errorf("node value = %v, want %v", n1.Value, wantValue)
	}
	if n1.Shape != "dot" {
		t.Errorf("real node shape = %q, want dot", n1.Shape)
	}
	// max real count is 100 (group excluded); 100 >= 0.5*100 -> tier 3.
	if n1.ColorTier != 3 {
		t.Errorf("busiest node tier = %d, want 3", n1.ColorTier)
	}

	g, ok := findNode(view.Nodes, "224.0.0.251")
	if !ok {
		t.Fatal("expected group node in view")
	}
	if g.Shape != "box" || g.Value != 1 || g.ColorTier != 0 {
		t.Errorf("group node styled as real: shape=%q value=%v tier=%d", g.Shape, g.Value, g.ColorTier)
	}
}

// TestBuildViewFiltering checks that hiding a protocol drops edges of that
// protocol and any node whose only traffic was that protocol — including the
// group node — exactly like the old client-side behavior, now server-side.
func TestBuildViewFiltering(t *testing.T) {
	raw := RawSnapshot{
		Nodes: []Node{
			{IP: "10.0.0.1", Hostname: "10.0.0.1", PacketCount: 100},
			{IP: "10.0.0.2", Hostname: "10.0.0.2", PacketCount: 80},
			{IP: "224.0.0.251", Hostname: "mDNS (group)", IsGroup: true, PacketCount: 50},
		},
		Edges: []Edge{
			{ID: "10.0.0.1<->10.0.0.2", From: "10.0.0.1", To: "10.0.0.2", Protocol: capture.ProtocolTCP, PacketCount: 60},
			{ID: "10.0.0.1<->224.0.0.251", From: "10.0.0.1", To: "224.0.0.251", Protocol: capture.ProtocolMDNS, PacketCount: 40},
			{ID: "10.0.0.2<->224.0.0.251", From: "10.0.0.2", To: "224.0.0.251", Protocol: capture.ProtocolMDNS, PacketCount: 40},
		},
	}

	view := BuildView(raw, ViewConfig{Hidden: map[string]bool{"mDNS": true}}, nil, nil, nil, nil)

	if _, ok := findNode(view.Nodes, "224.0.0.251"); ok {
		t.Error("mDNS group node should be dropped when mDNS is hidden")
	}
	if _, ok := findNode(view.Nodes, "10.0.0.1"); !ok {
		t.Error("host 10.0.0.1 has TCP traffic and should survive")
	}
	if hasEdge(view.Edges, "10.0.0.1<->224.0.0.251") || hasEdge(view.Edges, "10.0.0.2<->224.0.0.251") {
		t.Error("mDNS edges should be omitted when mDNS is hidden")
	}
	if !hasEdge(view.Edges, "10.0.0.1<->10.0.0.2") {
		t.Error("TCP edge should remain")
	}
}

// TestBuildViewTopN checks the node cap selects the busiest nodes.
func TestBuildViewTopN(t *testing.T) {
	raw := RawSnapshot{}
	for i := 0; i < 10; i++ {
		raw.Nodes = append(raw.Nodes, Node{
			IP:          string(rune('a' + i)),
			Hostname:    string(rune('a' + i)),
			PacketCount: i, // a=0 .. j=9
		})
	}
	view := BuildView(raw, ViewConfig{MaxNodes: 3}, nil, nil, nil, nil)
	if len(view.Nodes) != 3 {
		t.Fatalf("got %d nodes, want 3", len(view.Nodes))
	}
	for _, want := range []string{"j", "i", "h"} {
		if _, ok := findNode(view.Nodes, want); !ok {
			t.Errorf("expected busiest node %q in top-3", want)
		}
	}
}

// synthSubnet builds n hosts in 10.0.0.0/24 with decreasing traffic.
func synthSubnet(n int) RawSnapshot {
	raw := RawSnapshot{}
	for i := 1; i <= n; i++ {
		ip := "10.0.0." + itoa(i)
		raw.Nodes = append(raw.Nodes, Node{
			IP: ip, Hostname: ip, IPs: []string{ip},
			PacketCount: n - i + 1,
		})
	}
	// Star edges to the busiest host so everyone is connected.
	hub := "10.0.0.1"
	for i := 2; i <= n; i++ {
		ip := "10.0.0." + itoa(i)
		raw.Edges = append(raw.Edges, Edge{
			ID: hub + "<->" + ip, From: hub, To: ip,
			Protocol: capture.ProtocolTCP, PacketCount: n - i + 1,
		})
	}
	return raw
}

// TestBuildViewBudgetedExpand reveals only ExpandBudget hosts + a residual tail.
func TestBuildViewBudgetedExpand(t *testing.T) {
	raw := synthSubnet(50)
	view := BuildView(raw, ViewConfig{
		AggregateThreshold: 10, // force aggregation
		MaxNodes:           500,
		ExpandBudget:       10,
		ExpandedSubnets:    map[string]bool{"10.0.0.0/24": true},
	}, nil, nil, nil, nil)

	var hosts, tails, supers int
	for _, n := range view.Nodes {
		switch {
		case n.IsTail:
			tails++
			if n.HostCount <= 0 {
				t.Errorf("tail %q has no hostCount", n.ID)
			}
		case n.IsSubnet:
			supers++
		default:
			hosts++
		}
	}
	if hosts > 10 {
		t.Errorf("budgeted expand showed %d hosts, want ≤ 10", hosts)
	}
	if tails != 1 {
		t.Errorf("want exactly 1 residual tail, got %d (supers=%d hosts=%d total=%d)",
			tails, supers, hosts, len(view.Nodes))
	}
}

// TestBuildViewFullExpand reveals every host when FullExpand is set.
func TestBuildViewFullExpand(t *testing.T) {
	raw := synthSubnet(30)
	view := BuildView(raw, ViewConfig{
		AggregateThreshold: 10,
		MaxNodes:           500,
		ExpandBudget:       5,
		ExpandedSubnets:    map[string]bool{"10.0.0.0/24": true},
		FullExpand:         map[string]bool{"10.0.0.0/24": true},
	}, nil, nil, nil, nil)

	hosts := 0
	for _, n := range view.Nodes {
		if !n.IsSubnet && !n.IsTail {
			hosts++
		}
		if n.IsTail {
			t.Errorf("full expand should not produce residual tail %q", n.ID)
		}
	}
	if hosts != 30 {
		t.Errorf("full expand hosts = %d, want 30", hosts)
	}
}

// TestBuildViewIsolateFocus keeps only the focused /24.
func TestBuildViewIsolateFocus(t *testing.T) {
	raw := synthSubnet(20)
	// Add a second subnet so focus can filter it out.
	for i := 1; i <= 15; i++ {
		ip := "10.1.0." + itoa(i)
		raw.Nodes = append(raw.Nodes, Node{
			IP: ip, Hostname: ip, IPs: []string{ip}, PacketCount: 50,
		})
		raw.Edges = append(raw.Edges, Edge{
			ID: "10.0.0.1<->" + ip, From: "10.0.0.1", To: ip,
			Protocol: capture.ProtocolTCP, PacketCount: 10,
		})
	}
	view := BuildView(raw, ViewConfig{
		AggregateThreshold: 5,
		MaxNodes:           500,
		ExpandedSubnets:    map[string]bool{"10.0.0.0/24": true},
		FullExpand:         map[string]bool{"10.0.0.0/24": true},
		FocusCIDR:          "10.0.0.0/24",
	}, nil, nil, nil, nil)

	for _, n := range view.Nodes {
		if n.IsSubnet || n.IsTail {
			continue
		}
		if !nodeBelongsToCIDR(&Node{IP: n.ID, IPs: n.IPs}, "10.0.0.0/24", nil) {
			// Re-check with primary: host IDs are IPs.
			if !nodeBelongsToCIDR(&Node{IP: n.ID, IPs: []string{n.ID}}, "10.0.0.0/24", func(string) bool { return false }) {
				t.Errorf("isolate leaked node %q outside focus", n.ID)
			}
		}
	}
}

// keptIDSet returns the sorted IDs of a view's nodes for set comparison.
func keptIDSet(view ViewSnapshot) []string {
	ids := make([]string, 0, len(view.Nodes))
	for _, n := range view.Nodes {
		ids = append(ids, n.ID)
	}
	sort.Strings(ids)
	return ids
}

func equalIDs(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// synthHosts builds n hosts spread across 10.0.x.0/24 subnets (max 250 per
// subnet) so subnet aggregation has real /24 groups to collapse.
func synthHosts(n int) RawSnapshot {
	raw := RawSnapshot{}
	for i := 0; i < n; i++ {
		ip := "10.0." + itoa(i/250) + "." + itoa(i%250+1)
		raw.Nodes = append(raw.Nodes, Node{
			IP: ip, Hostname: ip, IPs: []string{ip},
			PacketCount: 100 - i%50,
		})
	}
	// Star edges to the first host so the layout has connectivity.
	hub := "10.0.0.1"
	for i := 1; i < n; i++ {
		ip := raw.Nodes[i].IP
		raw.Edges = append(raw.Edges, Edge{
			ID: hub + "<->" + ip, From: hub, To: ip,
			Protocol: capture.ProtocolTCP, PacketCount: 10,
		})
	}
	return raw
}

func countSupernodes(view ViewSnapshot) int {
	n := 0
	for _, vn := range view.Nodes {
		if vn.IsSubnet {
			n++
		}
	}
	return n
}

// TestBuildViewAggregationHysteresis: crossing the threshold upward collapses
// hosts into supernodes; dropping part-way (260 > 250 floor) stays collapsed;
// dropping below the re-expand floor (240 < 250) expands again.
func TestBuildViewAggregationHysteresis(t *testing.T) {
	le := NewLayoutEngine()
	cfg := ViewConfig{AggregateThreshold: 300, MaxNodes: 1000}

	// Below threshold: individual hosts, no supernodes.
	view := BuildView(synthHosts(290), cfg, le, nil, nil, nil)
	if s := countSupernodes(view); s != 0 {
		t.Fatalf("290 hosts: got %d supernodes, want 0 (below threshold)", s)
	}

	// Cross upward: collapse.
	view = BuildView(synthHosts(310), cfg, le, nil, nil, nil)
	if s := countSupernodes(view); s == 0 {
		t.Fatal("310 hosts: expected subnet supernodes after crossing 300")
	}

	// Drop to 260 — inside the hysteresis band (floor = 300*5/6 = 250):
	// must stay collapsed instead of flapping back to individual hosts.
	view = BuildView(synthHosts(260), cfg, le, nil, nil, nil)
	if s := countSupernodes(view); s == 0 {
		t.Fatal("260 hosts: view should stay collapsed (hysteresis), got individual hosts")
	}

	// Drop below the floor: re-expand.
	view = BuildView(synthHosts(240), cfg, le, nil, nil, nil)
	if s := countSupernodes(view); s != 0 {
		t.Fatalf("240 hosts: got %d supernodes, want 0 (below re-expand floor)", s)
	}
}

// TestBuildViewTopNStability: with more nodes than maxNodes and near-equal
// traffic, repeated ticks keep the same kept set (no boundary flap), and a
// clear traffic leader still displaces an incumbent (bias, not a lock).
func TestBuildViewTopNStability(t *testing.T) {
	le := NewLayoutEngine()
	cfg := ViewConfig{MaxNodes: 30}

	mkRaw := func(outsiderCount, leaderCount int) RawSnapshot {
		raw := RawSnapshot{}
		for i := 0; i < 40; i++ {
			id := "n" + itoa(i)
			if i < 10 {
				id = "n0" + itoa(i)
			}
			pc := 100
			switch {
			case id == "n30" && leaderCount > 0:
				pc = leaderCount
			case i >= 30:
				pc = outsiderCount
			}
			raw.Nodes = append(raw.Nodes, Node{IP: id, Hostname: id, PacketCount: pc})
		}
		return raw
	}

	// Tick 1 (all equal traffic): deterministic set thanks to the ID tiebreak.
	first := keptIDSet(BuildView(mkRaw(100, 0), cfg, le, nil, nil, nil))
	if len(first) != 30 {
		t.Fatalf("kept %d nodes, want 30", len(first))
	}
	// Same raw again: identical kept set, no reshuffle.
	again := keptIDSet(BuildView(mkRaw(100, 0), cfg, le, nil, nil, nil))
	if !equalIDs(first, again) {
		t.Fatalf("identical input produced different kept sets:\n%v\n%v", first, again)
	}

	// Tick 2: outsiders creep slightly above incumbents (101 vs 100). The
	// incumbent bonus (x1.1) must hold the boundary — no flap.
	stable := keptIDSet(BuildView(mkRaw(101, 0), cfg, le, nil, nil, nil))
	if !equalIDs(first, stable) {
		t.Fatalf("kept set flapped on marginal traffic change:\n%v\n%v", first, stable)
	}

	// Tick 3: outsider n30 becomes a clear leader (200 > 100*1.1) and must
	// displace an incumbent — stickiness is a bias, not a lock.
	view := BuildView(mkRaw(101, 200), cfg, le, nil, nil, nil)
	leader, ok := findNode(view.Nodes, "n30")
	if !ok {
		t.Fatal("clear traffic leader n30 should displace an incumbent")
	}
	if leader.PacketCount != 200 {
		t.Errorf("leader PacketCount = %d, want 200 (bonus must never touch displayed counts)", leader.PacketCount)
	}
	if len(view.Nodes) != 30 {
		t.Fatalf("kept %d nodes after displacement, want 30", len(view.Nodes))
	}
}
