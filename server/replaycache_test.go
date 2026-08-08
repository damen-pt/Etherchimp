package server

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"etherchimp/graph"
	"etherchimp/replay"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

// writeScrubTestPcap writes a pcap where 10.0.0.1↔10.0.0.2 talk at t=0 and
// 10.0.0.3 joins at t=10s, so small and large offsets have different node sets
// with a common subset.
func writeScrubTestPcap(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "scrub_test.pcap")
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	defer f.Close()

	w := pcapgo.NewWriter(f)
	if err := w.WriteFileHeader(1600, layers.LinkTypeEthernet); err != nil {
		t.Fatalf("header: %v", err)
	}

	base := time.Unix(1700000000, 0)
	write := func(at time.Time, srcOctet byte) {
		eth := &layers.Ethernet{
			SrcMAC:       []byte{0x02, 0, 0, 0, 0, srcOctet},
			DstMAC:       []byte{0x02, 0, 0, 0, 0, 2},
			EthernetType: layers.EthernetTypeIPv4,
		}
		ip := &layers.IPv4{
			Version:  4,
			IHL:      5,
			TTL:      64,
			Protocol: layers.IPProtocolTCP,
			SrcIP:    []byte{10, 0, 0, srcOctet},
			DstIP:    []byte{10, 0, 0, 2},
		}
		tcp := &layers.TCP{
			SrcPort: layers.TCPPort(12345),
			DstPort: layers.TCPPort(80),
			SYN:     true,
		}
		tcp.SetNetworkLayerForChecksum(ip)
		buf := gopacket.NewSerializeBuffer()
		opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
		if err := gopacket.SerializeLayers(buf, opts, eth, ip, tcp, gopacket.Payload("x")); err != nil {
			t.Fatalf("serialize: %v", err)
		}
		ci := gopacket.CaptureInfo{
			Timestamp:     at,
			CaptureLength: len(buf.Bytes()),
			Length:        len(buf.Bytes()),
		}
		if err := w.WritePacket(ci, buf.Bytes()); err != nil {
			t.Fatalf("write: %v", err)
		}
	}
	write(base, 1)
	write(base.Add(10*time.Second), 3)
	return path
}

// viewAtOffset mirrors the handler's parse path: snapshot up to offset,
// rendered with the cached full-capture layout.
func viewAtOffset(s *replaySession, offset float64) graph.ViewSnapshot {
	s.mu.Lock()
	defer s.mu.Unlock()
	pkts := s.reader.GetPacketsUpToTime(offset)
	snap := replay.BuildSnapshotFromPackets(pkts, s.dnsCache)
	le := graph.NewLayoutEngine()
	le.SeedPositions("force", s.positions)
	return graph.BuildView(graph.RawSnapshot{Nodes: snap.Nodes, Edges: snap.Edges},
		graph.ViewConfig{LayoutMode: "force"}, le, nil, nil, nil)
}

func TestReplaySessionStablePositions(t *testing.T) {
	path := writeScrubTestPcap(t)
	m := &Manager{replaySessions: make(map[string]*replaySession)}

	s1, err := m.replaySessionFor(path)
	if err != nil {
		t.Fatalf("session build: %v", err)
	}
	s2, err := m.replaySessionFor(path)
	if err != nil {
		t.Fatalf("session rebuild: %v", err)
	}
	if s1 != s2 {
		t.Fatalf("expected the same cached session instance")
	}
	if len(s1.positions) != 3 {
		t.Fatalf("full layout has %d positions, want 3", len(s1.positions))
	}

	early := viewAtOffset(s1, 5)  // 2 nodes
	full := viewAtOffset(s1, 15)  // 3 nodes
	if len(early.Nodes) != 2 || len(full.Nodes) != 3 {
		t.Fatalf("node counts: early=%d full=%d, want 2/3", len(early.Nodes), len(full.Nodes))
	}

	fullPos := make(map[string][2]float64, len(full.Nodes))
	for _, n := range full.Nodes {
		fullPos[n.ID] = [2]float64{n.X, n.Y}
	}
	for _, n := range early.Nodes {
		fp, ok := fullPos[n.ID]
		if !ok {
			t.Fatalf("early node %s missing from full view", n.ID)
		}
		if fp[0] != n.X || fp[1] != n.Y {
			t.Errorf("node %s moved between offsets: early (%v,%v) full (%v,%v)",
				n.ID, n.X, n.Y, fp[0], fp[1])
		}
	}
}
