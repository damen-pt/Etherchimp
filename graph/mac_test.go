package graph

import (
	"testing"
	"time"

	"etherchimp/capture"
)

func macPkt(srcIP, srcMAC, dstIP string) *capture.PacketInfo {
	return &capture.PacketInfo{
		SrcIP:    srcIP,
		DstIP:    dstIP,
		SrcMAC:   srcMAC,
		Protocol: capture.ProtocolTCP,
		Length:   100,
	}
}

// A host that is re-addressed (DHCP) keeps one node keyed by its exclusive MAC
// (ultimate identity). Both IPs remain attributes on that node.
func TestMACDHCPReaddressMerges(t *testing.T) {
	m := NewManager()
	const mac = "aa:bb:cc:00:11:22"
	m.Ingest(macPkt("10.0.0.5", mac, "10.0.0.1"), "", "")

	// Age the old node past the active window so the next sighting reads as a
	// re-address rather than a concurrent second host.
	oldID := m.ipToNodeID["10.0.0.5"]
	if oldID == "" {
		t.Fatal("expected node for 10.0.0.5")
	}
	if oldID != mac {
		t.Fatalf("exclusive host MAC should become node id, got %q", oldID)
	}
	m.nodes[oldID].LastSeen = time.Now().Add(-5 * time.Minute)

	m.Ingest(macPkt("10.0.0.9", mac, "10.0.0.1"), "", "")

	if _, ok := m.nodes["10.0.0.5"]; ok {
		t.Error("old IP key 10.0.0.5 should have been re-keyed / merged away")
	}
	n, ok := m.nodes[mac]
	if !ok {
		t.Fatal("expected surviving node keyed by MAC")
	}
	if !containsString(n.IPs, "10.0.0.5") || !containsString(n.IPs, "10.0.0.9") {
		t.Errorf("surviving node should hold both IPs, got %v", n.IPs)
	}
	if !containsString(n.MACs, mac) {
		t.Errorf("surviving node should carry MAC %s, got %v", mac, n.MACs)
	}
	if m.macToNodeID[mac] != mac {
		t.Errorf("MAC anchor should point at MAC id, got %q", m.macToNodeID[mac])
	}
	if m.ipToNodeID["10.0.0.9"] != mac || m.ipToNodeID["10.0.0.5"] != mac {
		t.Errorf("both IPs should resolve to MAC node, map=%v", m.ipToNodeID)
	}
}

// A gateway/NAT MAC forwards many IPs concurrently. Distinct IPs that appear on
// the same MAC while both are active must NOT be merged, and the MAC must be
// flagged shared so it never anchors (or stay as a node id).
func TestMACSharedGatewayNotMerged(t *testing.T) {
	m := NewManager()
	const gw = "de:ad:be:ef:00:01"
	m.Ingest(macPkt("8.8.8.8", gw, "10.0.0.5"), "", "")
	m.Ingest(macPkt("1.1.1.1", gw, "10.0.0.5"), "", "") // both recent

	// After shared detection, each IP remains its own node (MAC demoted).
	id88 := m.ipToNodeID["8.8.8.8"]
	id11 := m.ipToNodeID["1.1.1.1"]
	if id88 == "" || m.nodes[id88] == nil {
		t.Error("8.8.8.8 should remain its own node")
	}
	if id11 == "" || m.nodes[id11] == nil {
		t.Error("1.1.1.1 should remain its own node")
	}
	if id88 == id11 {
		t.Error("gateway IPs must not merge into one node")
	}
	if !m.macShared[gw] {
		t.Error("gateway MAC should be flagged shared")
	}
	if _, ok := m.macToNodeID[gw]; ok {
		t.Error("shared MAC must not remain an anchor")
	}
	if _, ok := m.nodes[gw]; ok {
		t.Error("shared gateway MAC must not remain a node id")
	}
	// A third IP on the same MAC stays separate too.
	m.Ingest(macPkt("9.9.9.9", gw, "10.0.0.5"), "", "")
	if id := m.ipToNodeID["9.9.9.9"]; id == "" || m.nodes[id] == nil {
		t.Error("9.9.9.9 should remain its own node under a shared MAC")
	}
	// The MAC is still recorded on each node for display/search.
	if n := m.nodes[m.ipToNodeID["8.8.8.8"]]; n == nil || !containsString(n.MACs, gw) {
		t.Error("shared MAC should still be recorded on the node for display")
	}
}

// Broadcast/multicast MACs are not host identities and are neither recorded nor
// anchored.
func TestMACBroadcastIgnored(t *testing.T) {
	m := NewManager()
	p := macPkt("10.0.0.5", "aa:bb:cc:00:11:33", "10.0.0.200")
	p.DstMAC = "ff:ff:ff:ff:ff:ff"
	m.Ingest(p, "", "")

	dstID := m.ipToNodeID["10.0.0.200"]
	if n := m.nodes[dstID]; n != nil && containsString(n.MACs, "ff:ff:ff:ff:ff:ff") {
		t.Error("broadcast MAC must not be recorded on a node")
	}
	if _, ok := m.macToNodeID["ff:ff:ff:ff:ff:ff"]; ok {
		t.Error("broadcast MAC must not anchor")
	}
}

// The eth.addr display filter finds a node by its recorded MAC (node id is the
// MAC when exclusive).
func TestMACSearchFilter(t *testing.T) {
	m := NewManager()
	const mac = "aa:bb:cc:dd:ee:ff"
	m.Ingest(macPkt("10.0.0.5", mac, "10.0.0.1"), "", "")

	res, ok := m.SearchFilter("eth.addr == "+mac, 10)
	if !ok {
		t.Fatal("eth.addr query should parse as a structured filter")
	}
	found := false
	for _, r := range res {
		if r.ID == mac || r.ID == "10.0.0.5" || containsString(r.IPs, "10.0.0.5") {
			found = true
		}
	}
	if !found {
		t.Errorf("eth.addr == %s should find the host (MAC-keyed), got %v", mac, res)
	}
}

// Solar layout is deterministic and settled (no force thrash). Traffic volume
// changes must NOT move hosts — that was the hop-around-with-packets bug.
func TestSolarLayoutStable(t *testing.T) {
	le := NewLayoutEngine()
	raw := RawSnapshot{}
	for i := 1; i <= 20; i++ {
		ip := "10.0.0." + itoa(i)
		raw.Nodes = append(raw.Nodes, Node{
			IP: ip, Hostname: ip, IPs: []string{ip}, PacketCount: 21 - i,
		})
	}
	for i := 1; i <= 10; i++ {
		ip := "10.1.0." + itoa(i)
		raw.Nodes = append(raw.Nodes, Node{
			IP: ip, Hostname: ip, IPs: []string{ip}, PacketCount: 10,
		})
	}
	le.Step(raw, map[string]bool{"solar": true}, nil, nil, nil)
	p1 := le.Position("solar", "10.0.0.1")
	le.Step(raw, map[string]bool{"solar": true}, nil, nil, nil)
	p2 := le.Position("solar", "10.0.0.1")
	if p1 != p2 {
		t.Errorf("solar positions moved without membership change: %v -> %v", p1, p2)
	}
	// Spike traffic on a different host — coordinates must stay put.
	for i := range raw.Nodes {
		if raw.Nodes[i].IP == "10.0.0.15" {
			raw.Nodes[i].PacketCount = 999999
		}
	}
	le.Step(raw, map[string]bool{"solar": true}, nil, nil, nil)
	p3 := le.Position("solar", "10.0.0.1")
	p15a := le.Position("solar", "10.0.0.15")
	if p1 != p3 {
		t.Errorf("traffic change moved 10.0.0.1: %v -> %v", p1, p3)
	}
	// Re-step again; 10.0.0.15 must also be frozen.
	le.Step(raw, map[string]bool{"solar": true}, nil, nil, nil)
	if le.Position("solar", "10.0.0.15") != p15a {
		t.Error("traffic change moved the spiked host")
	}
	if !le.settled["solar"] {
		t.Error("solar layout should be settled")
	}
	// Different systems should not share the same coordinates.
	q := le.Position("solar", "10.1.0.1")
	if p1 == q {
		t.Error("hosts in different /24s should not share the same position")
	}
}
