package store

import (
	"log"
	"sync"
	"sync/atomic"
	"time"

	"etherchimp/graph"
)

const (
	flushInterval = 500 * time.Millisecond
	batchSize     = 5000  // packet rows that trigger an early flush
	drainMax      = 20000 // max packet rows consumed per flush
)

// nodeKey / edgeKey scope aggregates to a capture.
type nodeKey struct {
	captureID int64
	id        string
}
type edgeKey struct {
	captureID int64
	id        string
}
type bucketKey struct {
	captureID int64
	ts        int64 // floored to bucket width
	edgeID    string
	proto     string
}

type nodeAgg struct {
	hostname    string
	packets     int64
	bytes       int64
	first, last int64 // unix millis
}

type edgeAgg struct {
	from, to    string
	proto       string
	packets     int64
	bytes       int64
	fwdP, revP  int64
	fwdB, revB  int64
	first, last int64
}

// bucketAgg rows are deltas since the last flush (flushed additively then
// cleared), unlike node/edge aggs which are cumulative (flushed absolutely).
type bucketAgg struct {
	proto      string
	packets    int64
	bytes      int64
	fwdP, revP int64
	fwdB, revB int64
}

// aggregator is the hot-path side of the writer: cheap map updates under its
// own mutex. The writer goroutine snapshots dirty entries at each flush.
type aggregator struct {
	mu         sync.Mutex
	bucketSecs int64

	nodes      map[nodeKey]*nodeAgg
	edges      map[edgeKey]*edgeAgg
	buckets    map[bucketKey]*bucketAgg
	dirtyNodes map[nodeKey]struct{}
	dirtyEdges map[edgeKey]struct{}

	sampleN atomic.Uint64 // lock-free: bumped once per packet on the hot path
	dropped int64         // packet rows dropped under backpressure

	flushReq chan chan struct{} // Flush() rendezvous
}

func newAggregator(bucketSecs int64) *aggregator {
	return &aggregator{
		bucketSecs: bucketSecs,
		nodes:      make(map[nodeKey]*nodeAgg),
		edges:      make(map[edgeKey]*edgeAgg),
		buckets:    make(map[bucketKey]*bucketAgg),
		dirtyNodes: make(map[nodeKey]struct{}),
		dirtyEdges: make(map[edgeKey]struct{}),
		flushReq:   make(chan chan struct{}),
	}
}

func (a *aggregator) sampleTick() uint64 {
	return a.sampleN.Add(1)
}

func (a *aggregator) droppedPacketRow() {
	a.mu.Lock()
	a.dropped++
	a.mu.Unlock()
}

// apply folds one packet into the cumulative node/edge aggregates and the
// current flow bucket. Mirrors graph.Manager semantics: canonical edge id via
// lexicographic endpoint order, protocol upgraded when more specific than
// TCP/UDP.
func (a *aggregator) apply(ev PacketEvent) {
	ts := ev.TS.UnixMilli()
	edgeID, from, to := ev.Src, ev.Src, ev.Dst
	if ev.Src < ev.Dst {
		edgeID = ev.Src + graph.EdgeIDSep + ev.Dst
	} else {
		edgeID, from, to = ev.Dst+graph.EdgeIDSep+ev.Src, ev.Dst, ev.Src
	}
	isForward := ev.Src == from
	length := int64(ev.Length)

	a.mu.Lock()
	defer a.mu.Unlock()

	for _, e := range [2]struct {
		id, host string
	}{{ev.Src, ev.SrcHost}, {ev.Dst, ev.DstHost}} {
		nk := nodeKey{ev.CaptureID, e.id}
		n := a.nodes[nk]
		if n == nil {
			n = &nodeAgg{first: ts}
			a.nodes[nk] = n
		}
		if e.host != "" && e.host != e.id {
			n.hostname = e.host
		}
		n.packets++
		n.bytes += length
		n.last = ts
		a.dirtyNodes[nk] = struct{}{}
	}

	ek := edgeKey{ev.CaptureID, edgeID}
	eg := a.edges[ek]
	if eg == nil {
		eg = &edgeAgg{from: from, to: to, proto: ev.Proto, first: ts}
		a.edges[ek] = eg
	}
	eg.packets++
	eg.bytes += length
	eg.last = ts
	if isForward {
		eg.fwdP++
		eg.fwdB += length
	} else {
		eg.revP++
		eg.revB += length
	}
	if ev.Proto != "TCP" && ev.Proto != "UDP" {
		eg.proto = ev.Proto
	}
	a.dirtyEdges[ek] = struct{}{}

	// Buckets are per-protocol (schema v2): the row carries the PACKET's
	// protocol so mixed-protocol edges attribute volume correctly and the
	// timeline can reconstruct a dominant protocol from real traffic.
	bk := bucketKey{ev.CaptureID, (ev.TS.Unix() / a.bucketSecs) * a.bucketSecs, edgeID, ev.Proto}
	b := a.buckets[bk]
	if b == nil {
		b = &bucketAgg{proto: ev.Proto}
		a.buckets[bk] = b
	}
	b.packets++
	b.bytes += length
	if isForward {
		b.fwdP++
		b.fwdB += length
	} else {
		b.revP++
		b.revB += length
	}
}

// snapshot moves the dirty state out under the lock: dirty node/edge entries
// are copied (cumulative values, maps retained), buckets are taken wholesale
// and reset (delta semantics).
type flushBatch struct {
	nodes   map[nodeKey]nodeAgg
	edges   map[edgeKey]edgeAgg
	buckets map[bucketKey]bucketAgg
	dropped int64
}

func (a *aggregator) snapshot() flushBatch {
	a.mu.Lock()
	defer a.mu.Unlock()
	fb := flushBatch{
		nodes:   make(map[nodeKey]nodeAgg, len(a.dirtyNodes)),
		edges:   make(map[edgeKey]edgeAgg, len(a.dirtyEdges)),
		buckets: a.snapshotBucketsLocked(),
		dropped: a.dropped,
	}
	a.dropped = 0
	for nk := range a.dirtyNodes {
		fb.nodes[nk] = *a.nodes[nk]
	}
	for ek := range a.dirtyEdges {
		fb.edges[ek] = *a.edges[ek]
	}
	a.dirtyNodes = make(map[nodeKey]struct{})
	a.dirtyEdges = make(map[edgeKey]struct{})
	return fb
}

func (a *aggregator) snapshotBucketsLocked() map[bucketKey]bucketAgg {
	out := make(map[bucketKey]bucketAgg, len(a.buckets))
	for k, v := range a.buckets {
		out[k] = *v
	}
	a.buckets = make(map[bucketKey]*bucketAgg)
	return out
}

// dropCapture forgets in-memory aggregates for a finished capture so the maps
// don't grow across many sessions. Called after EndCapture's flush.
func (a *aggregator) dropCapture(id int64) {
	a.mu.Lock()
	defer a.mu.Unlock()
	for k := range a.nodes {
		if k.captureID == id {
			delete(a.nodes, k)
			delete(a.dirtyNodes, k)
		}
	}
	for k := range a.edges {
		if k.captureID == id {
			delete(a.edges, k)
			delete(a.dirtyEdges, k)
		}
	}
}

// writerLoop is the single owner of SQL writes.
func (s *Store) writerLoop() {
	defer close(s.flushd)
	ticker := time.NewTicker(flushInterval)
	defer ticker.Stop()

	pending := make([]PacketEvent, 0, batchSize)
	var totalDropped int64
	lastDropLog := time.Now()

	flush := func() {
		fb := s.agg.snapshot()
		if len(pending) == 0 && len(fb.nodes) == 0 && len(fb.edges) == 0 && len(fb.buckets) == 0 {
			return
		}
		if err := s.flushTx(pending, fb); err != nil {
			log.Printf("store: flush failed (%d pkt rows, %d nodes, %d edges): %v",
				len(pending), len(fb.nodes), len(fb.edges), err)
		}
		pending = pending[:0]
		if fb.dropped > 0 {
			totalDropped += fb.dropped
			if time.Since(lastDropLog) > 30*time.Second {
				log.Printf("store: packet index under backpressure: %d rows sampled out (aggregates unaffected)", totalDropped)
				lastDropLog = time.Now()
			}
		}
	}

	for {
		select {
		case ev := <-s.events:
			pending = append(pending, ev)
			if len(pending) >= batchSize {
				flush()
			}
		case <-ticker.C:
			flush()
		case reply := <-s.agg.flushReq:
			// Drain whatever is queued right now, then flush synchronously.
			for len(pending) < drainMax {
				select {
				case ev := <-s.events:
					pending = append(pending, ev)
					continue
				default:
				}
				break
			}
			flush()
			close(reply)
		case <-s.done:
			for len(pending) < drainMax {
				select {
				case ev := <-s.events:
					pending = append(pending, ev)
					continue
				default:
				}
				break
			}
			flush()
			return
		}
	}
}

func (s *Store) flushTx(pkts []PacketEvent, fb flushBatch) error {
	tx, err := s.writeDB.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	if len(pkts) > 0 {
		stmt, err := tx.Prepare(`INSERT INTO packets
			(capture_id, ts, src, dst, src_port, dst_port, protocol, length, vlan, pcap_offset)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
		if err != nil {
			return err
		}
		for i := range pkts {
			p := &pkts[i]
			var off interface{}
			if p.PcapOffset >= 0 {
				off = p.PcapOffset
			}
			if _, err := stmt.Exec(p.CaptureID, p.TS.UnixMicro(), p.Src, p.Dst,
				p.SrcPort, p.DstPort, p.Proto, p.Length, p.VLAN, off); err != nil {
				stmt.Close()
				return err
			}
		}
		stmt.Close()
	}

	if len(fb.nodes) > 0 {
		stmt, err := tx.Prepare(`INSERT INTO nodes
			(capture_id, id, hostname, packet_count, byte_count, first_seen, last_seen)
			VALUES (?, ?, ?, ?, ?, ?, ?)
			ON CONFLICT (capture_id, id) DO UPDATE SET
			  hostname = COALESCE(NULLIF(excluded.hostname, ''), hostname),
			  packet_count = excluded.packet_count,
			  byte_count = excluded.byte_count,
			  last_seen = excluded.last_seen`)
		if err != nil {
			return err
		}
		for nk, n := range fb.nodes {
			if _, err := stmt.Exec(nk.captureID, nk.id, n.hostname,
				n.packets, n.bytes, n.first, n.last); err != nil {
				stmt.Close()
				return err
			}
		}
		stmt.Close()
	}

	if len(fb.edges) > 0 {
		stmt, err := tx.Prepare(`INSERT INTO edges
			(capture_id, id, from_id, to_id, protocol, packet_count, byte_count,
			 fwd_packets, rev_packets, fwd_bytes, rev_bytes, first_seen, last_seen)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
			ON CONFLICT (capture_id, id) DO UPDATE SET
			  protocol = excluded.protocol,
			  packet_count = excluded.packet_count,
			  byte_count = excluded.byte_count,
			  fwd_packets = excluded.fwd_packets,
			  rev_packets = excluded.rev_packets,
			  fwd_bytes = excluded.fwd_bytes,
			  rev_bytes = excluded.rev_bytes,
			  last_seen = excluded.last_seen`)
		if err != nil {
			return err
		}
		for ek, e := range fb.edges {
			if _, err := stmt.Exec(ek.captureID, ek.id, e.from, e.to, e.proto,
				e.packets, e.bytes, e.fwdP, e.revP, e.fwdB, e.revB, e.first, e.last); err != nil {
				stmt.Close()
				return err
			}
		}
		stmt.Close()
	}

	if len(fb.buckets) > 0 {
		stmt, err := tx.Prepare(`INSERT INTO flow_buckets
			(capture_id, bucket_ts, edge_id, protocol, packets, bytes,
			 fwd_packets, rev_packets, fwd_bytes, rev_bytes)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
			ON CONFLICT (capture_id, bucket_ts, edge_id, protocol) DO UPDATE SET
			  packets = packets + excluded.packets,
			  bytes = bytes + excluded.bytes,
			  fwd_packets = fwd_packets + excluded.fwd_packets,
			  rev_packets = rev_packets + excluded.rev_packets,
			  fwd_bytes = fwd_bytes + excluded.fwd_bytes,
			  rev_bytes = rev_bytes + excluded.rev_bytes`)
		if err != nil {
			return err
		}
		for bk, b := range fb.buckets {
			if _, err := stmt.Exec(bk.captureID, bk.ts, bk.edgeID, b.proto,
				b.packets, b.bytes, b.fwdP, b.revP, b.fwdB, b.revB); err != nil {
				stmt.Close()
				return err
			}
		}
		stmt.Close()
	}

	return tx.Commit()
}
