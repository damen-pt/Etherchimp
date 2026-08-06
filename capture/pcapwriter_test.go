package capture

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

// TestPcapWriterRoundTrip writes packets through the async writer, closes it,
// and reads the file back: every queued packet must survive the flush+close.
func TestPcapWriterRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.pcap")
	file, err := os.Create(path)
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	pw, err := newPcapWriter(file, 1600, layers.LinkTypeEthernet)
	if err != nil {
		t.Fatalf("newPcapWriter: %v", err)
	}

	const n = 100
	payloads := make([][]byte, n)
	for i := 0; i < n; i++ {
		// Distinct, self-identifying payloads
		payloads[i] = []byte{byte(i), byte(i >> 8), 0xde, 0xad, 0xbe, 0xef}
		ci := gopacket.CaptureInfo{
			Timestamp:     time.Unix(int64(1000+i), 0),
			CaptureLength: len(payloads[i]),
			Length:        len(payloads[i]),
		}
		pw.WritePacket(ci, payloads[i])
	}
	pw.Close()

	if drops := pw.drops.total(); drops != 0 {
		t.Fatalf("unexpected drops: %d", drops)
	}

	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer f.Close()

	r, err := pcapgo.NewReader(f)
	if err != nil {
		t.Fatalf("NewReader (header unreadable): %v", err)
	}
	if lt := r.LinkType(); lt != layers.LinkTypeEthernet {
		t.Fatalf("link type = %v, want %v", lt, layers.LinkTypeEthernet)
	}

	got := 0
	for {
		data, _, err := r.ReadPacketData()
		if err != nil {
			break
		}
		if got >= n {
			t.Fatalf("more packets than written")
		}
		if len(data) != len(payloads[got]) {
			t.Fatalf("packet %d: len %d, want %d", got, len(data), len(payloads[got]))
		}
		for j, b := range payloads[got] {
			if data[j] != b {
				t.Fatalf("packet %d byte %d = %x, want %x", got, j, data[j], b)
			}
		}
		got++
	}
	if got != n {
		t.Fatalf("read %d packets, want %d", got, n)
	}
}

// TestPcapWriterDoubleClose ensures Close is idempotent.
func TestPcapWriterDoubleClose(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.pcap")
	file, err := os.Create(path)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	pw, err := newPcapWriter(file, 1600, layers.LinkTypeEthernet)
	if err != nil {
		t.Fatalf("newPcapWriter: %v", err)
	}
	pw.Close()
	pw.Close() // must not panic or hang
}

// TestDropCounterRateLimit ensures the counter accumulates and reports totals.
func TestDropCounterRateLimit(t *testing.T) {
	d := newDropCounter("test")
	for i := 0; i < 5; i++ {
		d.add()
	}
	if got := d.total(); got != 5 {
		t.Fatalf("total = %d, want 5", got)
	}
}
