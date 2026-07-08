package graph

import (
	"math"
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
