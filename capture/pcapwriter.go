package capture

import (
	"bufio"
	"log"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

// dropLogInterval is the minimum time between "dropped packets" warnings from
// a single source, so a saturated consumer doesn't flood the log.
const dropLogInterval = 10 * time.Second

// dropCounter counts dropped packets (async pcap writes or graph-channel
// sends) and emits a rate-limited warning carrying the number of drops since
// the previous report.
type dropCounter struct {
	name     string
	count    atomic.Uint64 // drops since the last log report
	lifetime atomic.Uint64

	mu      sync.Mutex
	lastLog time.Time
}

func newDropCounter(name string) *dropCounter {
	return &dropCounter{name: name, lastLog: time.Now()}
}

// add records one dropped packet, logging at most once per dropLogInterval.
func (d *dropCounter) add() {
	d.count.Add(1)
	d.lifetime.Add(1)
	d.mu.Lock()
	defer d.mu.Unlock()
	if time.Since(d.lastLog) >= dropLogInterval {
		d.lastLog = time.Now()
		if n := d.count.Swap(0); n > 0 {
			log.Printf("Warning: %s: dropped %d packets in the last %s (consumer too slow)", d.name, n, dropLogInterval)
		}
	}
}

// total returns the lifetime drop count (used for a final report on Close).
func (d *dropCounter) total() uint64 {
	return d.lifetime.Load()
}

// pcapQueueSize bounds the async pcap write queue. At 10k pkt/s this absorbs
// ~400ms of disk stall before writes start being dropped.
const pcapQueueSize = 4096

// pcapFlushInterval is how often the drain goroutine flushes buffered packets
// to disk, bounding data loss on crash and keeping the file readable live.
const pcapFlushInterval = 500 * time.Millisecond

// queuedPacket is one packet awaiting an async pcap write. data is owned by
// the queue: it is copied at enqueue time because the capture buffer (and the
// pcapgo reader buffer on the SSH path) is reused between packets.
type queuedPacket struct {
	ci   gopacket.CaptureInfo
	data []byte
}

// pcapWriter writes packets to a pcap file off the capture hot path: callers
// hand packets to a bounded queue and a dedicated goroutine does the actual
// writing through a bufio.Writer, so disk latency never stalls packet decode
// (which would back up the kernel ring and drop packets at the NIC). When the
// queue is full the write is dropped and counted — the graph path is
// unaffected.
type pcapWriter struct {
	file *os.File
	buf  *bufio.Writer
	w    *pcapgo.Writer

	ch        chan queuedPacket
	quit      chan struct{}
	done      chan struct{}
	closeOnce sync.Once
	drops     *dropCounter
}

// newPcapWriter wraps file in a buffered, asynchronously-drained pcap writer.
// The file header is written and flushed synchronously so a failure here still
// means "no usable file", matching the old direct-write behavior.
func newPcapWriter(file *os.File, snaplen uint32, linkType layers.LinkType) (*pcapWriter, error) {
	buf := bufio.NewWriterSize(file, 256*1024)
	w := pcapgo.NewWriter(buf)
	if err := w.WriteFileHeader(snaplen, linkType); err != nil {
		return nil, err
	}
	if err := buf.Flush(); err != nil {
		return nil, err
	}
	pw := &pcapWriter{
		file:  file,
		buf:   buf,
		w:     w,
		ch:    make(chan queuedPacket, pcapQueueSize),
		quit:  make(chan struct{}),
		done:  make(chan struct{}),
		drops: newDropCounter("pcap writer"),
	}
	go pw.run()
	return pw, nil
}

// WritePacket queues a packet for async writing. The send is non-blocking:
// when the queue is full the pcap write is dropped and counted. Never blocks
// the caller, and safe to call until Close returns.
func (pw *pcapWriter) WritePacket(ci gopacket.CaptureInfo, data []byte) {
	// Copy: data aliases a reused capture/read buffer and must survive until
	// the drain goroutine writes it.
	pkt := queuedPacket{ci: ci, data: make([]byte, len(data))}
	copy(pkt.data, data)
	select {
	case pw.ch <- pkt:
	default:
		pw.drops.add()
	}
}

// run is the drain goroutine: it writes queued packets, flushes on a ticker,
// and on quit drains whatever remains, flushes, and closes the file.
func (pw *pcapWriter) run() {
	defer close(pw.done)
	ticker := time.NewTicker(pcapFlushInterval)
	defer ticker.Stop()
	flush := func() {
		if err := pw.buf.Flush(); err != nil {
			log.Printf("Warning: failed to flush pcap file: %v", err)
		}
	}
	for {
		select {
		case pkt := <-pw.ch:
			if err := pw.w.WritePacket(pkt.ci, pkt.data); err != nil {
				log.Printf("Warning: Failed to write packet to pcap: %v", err)
			}
		case <-ticker.C:
			flush()
		case <-pw.quit:
			for {
				select {
				case pkt := <-pw.ch:
					if err := pw.w.WritePacket(pkt.ci, pkt.data); err != nil {
						log.Printf("Warning: Failed to write packet to pcap: %v", err)
					}
				default:
					flush()
					pw.file.Close()
					return
				}
			}
		}
	}
}

// Close flushes and closes the underlying file, waiting for the drain
// goroutine to finish. Safe to call multiple times; producers must have
// stopped calling WritePacket before Close returns (both capture paths stop
// their reader goroutines first).
func (pw *pcapWriter) Close() {
	pw.closeOnce.Do(func() { close(pw.quit) })
	<-pw.done
	if n := pw.drops.total(); n > 0 {
		log.Printf("pcap writer: %d packets dropped in total (write queue full)", n)
	}
}
