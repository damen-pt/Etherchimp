package store

import (
	"path/filepath"
	"testing"
	"time"
)

// TestRoundTrip drives the full write path (RecordPacketSync -> writer flush)
// and checks the three read paths: LoadAggregates (pcap cache),
// TimelineOverview, and WindowAggregates (timeline scrubbing).
func TestRoundTrip(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "test.db"), Options{PacketEvery: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	capID, err := s.BeginCapture("pcap", "test.pcap", FileMeta{Size: 42, MTime: time.Now(), Hash: "abc"})
	if err != nil {
		t.Fatal(err)
	}

	base := time.Unix(1000000, 0)
	// Three packets A->B at t+0s, one B->A at t+1s, one A->C at t+61s.
	for i := 0; i < 3; i++ {
		s.RecordPacketSync(PacketEvent{CaptureID: capID, TS: base, Src: "10.0.0.1", Dst: "10.0.0.2",
			SrcHost: "alpha", Proto: "TCP", Length: 100, PcapOffset: -1})
	}
	s.RecordPacketSync(PacketEvent{CaptureID: capID, TS: base.Add(time.Second), Src: "10.0.0.2", Dst: "10.0.0.1",
		Proto: "HTTPS", Length: 200, PcapOffset: -1})
	s.RecordPacketSync(PacketEvent{CaptureID: capID, TS: base.Add(61 * time.Second), Src: "10.0.0.1", Dst: "10.0.0.3",
		Proto: "DNS", Length: 50, PcapOffset: -1})

	if err := s.EndCapture(capID, true); err != nil {
		t.Fatal(err)
	}

	// Cache lookup by identity.
	if id, ok := s.FindCompletePcap("test.pcap", FileMeta{Size: 42, Hash: "abc"}); !ok || id != capID {
		t.Fatalf("FindCompletePcap = (%d, %v), want (%d, true)", id, ok, capID)
	}
	if _, ok := s.FindCompletePcap("test.pcap", FileMeta{Size: 43, Hash: "abc"}); ok {
		t.Fatal("FindCompletePcap matched a different file size")
	}

	// Aggregates.
	nodes, edges, err := s.LoadAggregates(capID)
	if err != nil {
		t.Fatal(err)
	}
	if len(nodes) != 3 || len(edges) != 2 {
		t.Fatalf("got %d nodes / %d edges, want 3 / 2", len(nodes), len(edges))
	}
	byID := map[string]StoredNode{}
	for _, n := range nodes {
		byID[n.ID] = n
	}
	// 10.0.0.1 touched all 5 packets: 3*100 + 200 + 50 bytes.
	if n := byID["10.0.0.1"]; n.PacketCount != 5 || n.ByteCount != 550 || n.Hostname != "alpha" {
		t.Fatalf("10.0.0.1 = %+v, want packets 5, bytes 550, hostname alpha", n)
	}
	for _, e := range edges {
		if e.ID == "10.0.0.1<->10.0.0.2" {
			// 4 packets, protocol upgraded to HTTPS (more specific than TCP),
			// forward = from 10.0.0.1 (canonical from): 3 packets / 300 bytes.
			if e.PacketCount != 4 || e.ByteCount != 500 || e.Protocol != "HTTPS" ||
				e.ForwardPackets != 3 || e.ReversePackets != 1 ||
				e.ForwardBytes != 300 || e.ReverseBytes != 200 {
				t.Fatalf("edge A<->B = %+v", e)
			}
		}
	}

	// Timeline overview covers both buckets.
	points, first, last, err := s.TimelineOverview(capID, 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(points) != 3 || first != 1000000 || last != 1000061 {
		t.Fatalf("overview = %d points, bounds [%d, %d]", len(points), first, last)
	}

	// A 60s window ending before the DNS packet sees only A<->B.
	wn, we, err := s.WindowAggregates(capID, first, first+60)
	if err != nil {
		t.Fatal(err)
	}
	if len(wn) != 2 || len(we) != 1 {
		t.Fatalf("window[0,60) = %d nodes / %d edges, want 2 / 1", len(wn), len(we))
	}
	if we[0].From != "10.0.0.1" || we[0].To != "10.0.0.2" || we[0].PacketCount != 4 {
		t.Fatalf("window edge = %+v", we[0])
	}
	// A window over everything sees all three nodes.
	wn, we, err = s.WindowAggregates(capID, first, last+1)
	if err != nil {
		t.Fatal(err)
	}
	if len(wn) != 3 || len(we) != 2 {
		t.Fatalf("window[all] = %d nodes / %d edges, want 3 / 2", len(wn), len(we))
	}

	// Packet index: all 5 rows, node-scoped query.
	rows, err := s.QueryPackets(capID, 0, 0, "", 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 5 {
		t.Fatalf("packet index has %d rows, want 5", len(rows))
	}
	rows, err = s.QueryPackets(capID, 0, 0, "10.0.0.3", 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].Proto != "DNS" {
		t.Fatalf("node-scoped query = %+v", rows)
	}
}

// TestWindowAggregatesDominantProtocol checks that a reconstructed edge is
// labeled by the specific protocol that carried the MOST traffic, not by
// whichever name sorts last — the flow buckets are written per bucket-second,
// so one edge can span rows with different protocols.
func TestWindowAggregatesDominantProtocol(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "test.db"), Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	capID, err := s.BeginCapture("live", "eth0", FileMeta{})
	if err != nil {
		t.Fatal(err)
	}
	base := time.Unix(2000000, 0)
	// Distinct bucket seconds so each protocol lands in its own flow_buckets
	// row: 5x HTTPS at t+0, 1x SSH at t+1 ("SSH" > "HTTPS" lexicographically),
	// 10x TCP at t+2 (generic must never beat a specific protocol).
	for i := 0; i < 5; i++ {
		s.RecordPacket(PacketEvent{CaptureID: capID, TS: base, Src: "a", Dst: "b", Proto: "HTTPS", Length: 100, PcapOffset: -1})
	}
	s.RecordPacket(PacketEvent{CaptureID: capID, TS: base.Add(time.Second), Src: "a", Dst: "b", Proto: "SSH", Length: 100, PcapOffset: -1})
	for i := 0; i < 10; i++ {
		s.RecordPacket(PacketEvent{CaptureID: capID, TS: base.Add(2 * time.Second), Src: "a", Dst: "b", Proto: "TCP", Length: 100, PcapOffset: -1})
	}
	s.Flush()

	_, edges, err := s.WindowAggregates(capID, base.Unix(), base.Unix()+60)
	if err != nil {
		t.Fatal(err)
	}
	if len(edges) != 1 {
		t.Fatalf("got %d edges, want 1", len(edges))
	}
	if edges[0].Protocol != "HTTPS" {
		t.Fatalf("edge protocol = %q, want HTTPS (busiest specific protocol)", edges[0].Protocol)
	}
	if edges[0].PacketCount != 16 {
		t.Fatalf("edge packets = %d, want 16", edges[0].PacketCount)
	}
}
