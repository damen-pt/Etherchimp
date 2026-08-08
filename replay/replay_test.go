package replay

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

// writeTestPcap builds a pcap with one TCP packet per payload, spaced 10s
// apart starting at a fixed base time.
func writeTestPcap(t *testing.T, payloads []string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "search_test.pcap")
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
	for i, payload := range payloads {
		eth := &layers.Ethernet{
			SrcMAC:       []byte{0x02, 0, 0, 0, 0, 1},
			DstMAC:       []byte{0x02, 0, 0, 0, 0, 2},
			EthernetType: layers.EthernetTypeIPv4,
		}
		ip := &layers.IPv4{
			Version:  4,
			IHL:      5,
			TTL:      64,
			Protocol: layers.IPProtocolTCP,
			SrcIP:    []byte{10, 0, 0, 1},
			DstIP:    []byte{10, 0, 0, 2},
		}
		tcp := &layers.TCP{
			SrcPort: layers.TCPPort(12345),
			DstPort: layers.TCPPort(80),
			SYN:     true,
			Seq:     uint32(i),
		}
		tcp.SetNetworkLayerForChecksum(ip)

		buf := gopacket.NewSerializeBuffer()
		opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
		if err := gopacket.SerializeLayers(buf, opts, eth, ip, tcp, gopacket.Payload(payload)); err != nil {
			t.Fatalf("serialize: %v", err)
		}
		ci := gopacket.CaptureInfo{
			Timestamp:     base.Add(time.Duration(i*10) * time.Second),
			CaptureLength: len(buf.Bytes()),
			Length:        len(buf.Bytes()),
		}
		if err := w.WritePacket(ci, buf.Bytes()); err != nil {
			t.Fatalf("write packet %d: %v", i, err)
		}
	}
	return path
}

func TestSearchPackets(t *testing.T) {
	path := writeTestPcap(t, []string{"hello world", "the SECRET-token is here", "bye"})

	reader, err := NewReader(path)
	if err != nil {
		t.Fatalf("NewReader: %v", err)
	}
	defer reader.Close()

	if len(reader.packets) != 3 {
		t.Fatalf("loaded %d packets, want 3", len(reader.packets))
	}

	// Payload search is case-insensitive and reports the capture offset.
	matches := reader.SearchPackets("secret", 50)
	if len(matches) != 1 {
		t.Fatalf("payload search: %d matches, want 1", len(matches))
	}
	m := matches[0]
	if m.Field != "payload" {
		t.Errorf("field = %q, want payload", m.Field)
	}
	if m.OffsetSec != 10 {
		t.Errorf("offset = %v, want 10", m.OffsetSec)
	}
	if m.Index != 1 {
		t.Errorf("index = %d, want 1", m.Index)
	}
	if m.Preview == "" {
		t.Errorf("expected non-empty payload preview")
	}
	if m.Src != "10.0.0.1" || m.Dst != "10.0.0.2" || m.DstPort != 80 {
		t.Errorf("unexpected tuple %s:%d -> %s:%d", m.Src, m.SrcPort, m.Dst, m.DstPort)
	}

	// Host search matches every packet (all share the endpoints).
	matches = reader.SearchPackets("10.0.0.2", 50)
	if len(matches) != 3 {
		t.Fatalf("host search: %d matches, want 3", len(matches))
	}
	for _, m := range matches {
		if m.Field != "host" {
			t.Errorf("field = %q, want host", m.Field)
		}
	}

	// Protocol name search (port 80 classifies as HTTP).
	matches = reader.SearchPackets("http", 50)
	if len(matches) != 3 || matches[0].Field != "protocol" {
		t.Fatalf("protocol search: %+v", matches)
	}

	// Result limit is honored.
	matches = reader.SearchPackets("10.0.0.1", 2)
	if len(matches) != 2 {
		t.Fatalf("limited search: %d matches, want 2", len(matches))
	}

	// No match / empty query.
	if got := reader.SearchPackets("zzzz-nothing", 50); len(got) != 0 {
		t.Fatalf("no-match search: %d results, want 0", len(got))
	}
	if got := reader.SearchPackets("", 50); len(got) != 0 {
		t.Fatalf("empty query: %d results, want 0", len(got))
	}
}
