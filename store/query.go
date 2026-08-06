package store

import (
	"time"

	"etherchimp/capture"
	"etherchimp/graph"
)

// StoredNode / StoredEdge are the persisted aggregate shapes handed back to
// the graph layer on a cache hit. IDs are raw endpoint ids as captured;
// graph.Manager.BulkLoad re-runs hostname merging and group classification.
type StoredNode struct {
	ID          string
	Hostname    string
	PacketCount int64
	ByteCount   int64
	FirstSeen   time.Time
	LastSeen    time.Time
}

type StoredEdge struct {
	ID             string
	From, To       string
	Protocol       string
	PacketCount    int64
	ByteCount      int64
	ForwardPackets int64
	ReversePackets int64
	ForwardBytes   int64
	ReverseBytes   int64
	FirstSeen      time.Time
	LastSeen       time.Time
}

// BulkNodes / BulkEdges convert stored aggregate rows into the graph package's
// bulk-load shapes. Shared by every reconstruction path (pcap cache in main,
// timeline windows, replay-from-cache) so the field mapping exists once.
func BulkNodes(in []StoredNode) []graph.BulkNode {
	out := make([]graph.BulkNode, len(in))
	for i, n := range in {
		out[i] = graph.BulkNode{
			ID:          n.ID,
			Hostname:    n.Hostname,
			PacketCount: n.PacketCount,
			ByteCount:   n.ByteCount,
		}
	}
	return out
}

func BulkEdges(in []StoredEdge) []graph.BulkEdge {
	out := make([]graph.BulkEdge, len(in))
	for i, e := range in {
		out[i] = graph.BulkEdge{
			From: e.From, To: e.To, Protocol: e.Protocol,
			PacketCount: e.PacketCount, ByteCount: e.ByteCount,
			ForwardPackets: e.ForwardPackets, ReversePackets: e.ReversePackets,
			ForwardBytes: e.ForwardBytes, ReverseBytes: e.ReverseBytes,
		}
	}
	return out
}

// LoadAggregates returns the stored node/edge aggregates for a capture.
func (s *Store) LoadAggregates(captureID int64) ([]StoredNode, []StoredEdge, error) {
	if s == nil {
		return nil, nil, nil
	}
	rows, err := s.readDB.Query(
		`SELECT id, COALESCE(hostname, ''), packet_count, byte_count,
		        COALESCE(first_seen, 0), COALESCE(last_seen, 0)
		 FROM nodes WHERE capture_id = ?`, captureID)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()

	var nodes []StoredNode
	for rows.Next() {
		var n StoredNode
		var first, last int64
		if err := rows.Scan(&n.ID, &n.Hostname, &n.PacketCount, &n.ByteCount, &first, &last); err != nil {
			return nil, nil, err
		}
		n.FirstSeen = time.UnixMilli(first)
		n.LastSeen = time.UnixMilli(last)
		nodes = append(nodes, n)
	}
	if err := rows.Err(); err != nil {
		return nil, nil, err
	}

	erows, err := s.readDB.Query(
		`SELECT id, from_id, to_id, protocol, packet_count, byte_count,
		        fwd_packets, rev_packets, fwd_bytes, rev_bytes,
		        COALESCE(first_seen, 0), COALESCE(last_seen, 0)
		 FROM edges WHERE capture_id = ?`, captureID)
	if err != nil {
		return nil, nil, err
	}
	defer erows.Close()

	var edges []StoredEdge
	for erows.Next() {
		var e StoredEdge
		var first, last int64
		if err := erows.Scan(&e.ID, &e.From, &e.To, &e.Protocol, &e.PacketCount, &e.ByteCount,
			&e.ForwardPackets, &e.ReversePackets, &e.ForwardBytes, &e.ReverseBytes, &first, &last); err != nil {
			return nil, nil, err
		}
		e.FirstSeen = time.UnixMilli(first)
		e.LastSeen = time.UnixMilli(last)
		edges = append(edges, e)
	}
	return nodes, edges, erows.Err()
}

// CaptureInfo describes one stored capture session for the history UI.
type CaptureInfo struct {
	ID        int64  `json:"id"`
	Kind      string `json:"kind"`
	Source    string `json:"source"`
	StartedAt int64  `json:"startedAt"`         // unix millis
	EndedAt   int64  `json:"endedAt,omitempty"` // 0 while still running
	Complete  bool   `json:"complete"`
	Nodes     int64  `json:"nodes"`
	Edges     int64  `json:"edges"`
	Packets   int64  `json:"packets"` // indexed packet rows (0 if index disabled)
	// FirstBucket/LastBucket are the capture's data time bounds in unix
	// seconds, from the flow buckets — the timeline's scrub range.
	FirstBucket int64 `json:"firstBucket"`
	LastBucket  int64 `json:"lastBucket"`
}

// ListCaptures returns stored sessions, newest first.
func (s *Store) ListCaptures(limit int) ([]CaptureInfo, error) {
	if s == nil {
		return nil, nil
	}
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	rows, err := s.readDB.Query(`
		SELECT c.id, c.kind, c.source, c.started_at, COALESCE(c.ended_at, 0), c.complete,
		       (SELECT COUNT(*) FROM nodes n WHERE n.capture_id = c.id),
		       (SELECT COUNT(*) FROM edges e WHERE e.capture_id = c.id),
		       (SELECT COUNT(*) FROM packets p WHERE p.capture_id = c.id),
		       COALESCE((SELECT MIN(bucket_ts) FROM flow_buckets f WHERE f.capture_id = c.id), 0),
		       COALESCE((SELECT MAX(bucket_ts) FROM flow_buckets f WHERE f.capture_id = c.id), 0)
		FROM captures c ORDER BY c.id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []CaptureInfo
	for rows.Next() {
		var c CaptureInfo
		var complete int
		if err := rows.Scan(&c.ID, &c.Kind, &c.Source, &c.StartedAt, &c.EndedAt, &complete,
			&c.Nodes, &c.Edges, &c.Packets, &c.FirstBucket, &c.LastBucket); err != nil {
			return nil, err
		}
		c.Complete = complete == 1
		out = append(out, c)
	}
	return out, rows.Err()
}

// PacketRow is one indexed packet returned by QueryPackets.
type PacketRow struct {
	ID       int64
	TS       int64 // unix micros
	Src, Dst string
	SrcPort  uint16
	DstPort  uint16
	Proto    string
	Length   int
	VLAN     uint16
}

// QueryPackets returns indexed packets for a capture, optionally bounded by
// time (unix micros; 0 = unbounded), scoped to a node id, and paged by sinceID.
func (s *Store) QueryPackets(captureID, fromMicros, toMicros int64, node string, sinceID int64, limit int) ([]PacketRow, error) {
	if s == nil {
		return nil, nil
	}
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	q := `SELECT id, ts, COALESCE(src,''), COALESCE(dst,''), src_port, dst_port,
	             COALESCE(protocol,''), length, vlan
	      FROM packets WHERE capture_id = ?`
	args := []interface{}{captureID}
	if fromMicros > 0 {
		q += ` AND ts >= ?`
		args = append(args, fromMicros)
	}
	if toMicros > 0 {
		q += ` AND ts < ?`
		args = append(args, toMicros)
	}
	if node != "" {
		q += ` AND (src = ? OR dst = ?)`
		args = append(args, node, node)
	}
	if sinceID > 0 {
		q += ` AND id > ?`
		args = append(args, sinceID)
	}
	q += ` ORDER BY id LIMIT ?`
	args = append(args, limit)

	rows, err := s.readDB.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []PacketRow
	for rows.Next() {
		var p PacketRow
		if err := rows.Scan(&p.ID, &p.TS, &p.Src, &p.Dst, &p.SrcPort, &p.DstPort,
			&p.Proto, &p.Length, &p.VLAN); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// OverviewPoint is one point of the timeline sparkline: total traffic in
// [T, T+step).
type OverviewPoint struct {
	T       int64 `json:"t"` // unix seconds, floored to step
	Packets int64 `json:"packets"`
	Bytes   int64 `json:"bytes"`
}

// TimelineOverview returns the capture's traffic-over-time series at the given
// step plus its [first,last] bucket bounds (unix seconds).
func (s *Store) TimelineOverview(captureID, stepSec int64) ([]OverviewPoint, int64, int64, error) {
	if s == nil {
		return nil, 0, 0, nil
	}
	if stepSec <= 0 {
		stepSec = 1
	}
	rows, err := s.readDB.Query(`
		SELECT (bucket_ts / ?) * ?, SUM(packets), SUM(bytes)
		FROM flow_buckets WHERE capture_id = ?
		GROUP BY 1 ORDER BY 1`, stepSec, stepSec, captureID)
	if err != nil {
		return nil, 0, 0, err
	}
	defer rows.Close()
	var pts []OverviewPoint
	for rows.Next() {
		var p OverviewPoint
		if err := rows.Scan(&p.T, &p.Packets, &p.Bytes); err != nil {
			return nil, 0, 0, err
		}
		pts = append(pts, p)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, 0, err
	}
	var first, last int64
	if err := s.readDB.QueryRow(
		`SELECT COALESCE(MIN(bucket_ts),0), COALESCE(MAX(bucket_ts),0)
		 FROM flow_buckets WHERE capture_id = ?`, captureID).Scan(&first, &last); err != nil {
		return nil, 0, 0, err
	}
	return pts, first, last, nil
}

// WindowAggregates reconstructs node/edge aggregates for the time window
// [from, to) (unix seconds) from the flow buckets — the timeline's sliding
// window. Node counters are derived from their incident edges (each packet
// counts on both endpoints, matching the live packet path); hostnames come
// from the capture's node rows.
func (s *Store) WindowAggregates(captureID, from, to int64) ([]StoredNode, []StoredEdge, error) {
	if s == nil {
		return nil, nil, nil
	}
	// One row per (edge, protocol) so the dominant protocol can be picked by
	// traffic volume in Go — a lexicographic MAX over protocol names would let
	// a minority protocol label the edge.
	rows, err := s.readDB.Query(`
		SELECT edge_id, protocol,
		       SUM(packets), SUM(bytes),
		       SUM(fwd_packets), SUM(rev_packets), SUM(fwd_bytes), SUM(rev_bytes)
		FROM flow_buckets
		WHERE capture_id = ? AND bucket_ts >= ? AND bucket_ts < ?
		GROUP BY edge_id, protocol`, captureID, from, to)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()

	type nodeTotals struct{ packets, bytes int64 }
	nodeAggs := make(map[string]*nodeTotals)
	edgeByID := make(map[string]*StoredEdge)
	protoPackets := make(map[string]int64) // per edge: packets carried by its current Protocol
	var order []string
	for rows.Next() {
		var id, proto string
		var packets, bytes, fwdP, revP, fwdB, revB int64
		if err := rows.Scan(&id, &proto, &packets, &bytes,
			&fwdP, &revP, &fwdB, &revB); err != nil {
			return nil, nil, err
		}
		e := edgeByID[id]
		if e == nil {
			// edge_id is canonical "a<->b" (graph.getCanonicalEdgeID via
			// writer.go apply); anything unsplittable is malformed — skip.
			from, to, ok := graph.SplitEdgeID(id)
			if !ok {
				continue
			}
			e = &StoredEdge{ID: id, From: from, To: to, Protocol: proto}
			protoPackets[id] = packets
			edgeByID[id] = e
			order = append(order, id)
		}
		e.PacketCount += packets
		e.ByteCount += bytes
		e.ForwardPackets += fwdP
		e.ReversePackets += revP
		e.ForwardBytes += fwdB
		e.ReverseBytes += revB
		// Dominant protocol, mirroring the live edge rule: a specific protocol
		// beats generic TCP/UDP; within the same class the busiest wins.
		curGeneric := capture.IsGenericName(e.Protocol)
		newGeneric := capture.IsGenericName(proto)
		if (curGeneric && !newGeneric) ||
			(curGeneric == newGeneric && packets > protoPackets[id]) {
			e.Protocol = proto
			protoPackets[id] = packets
		}
		for _, nid := range [2]string{e.From, e.To} {
			nt := nodeAggs[nid]
			if nt == nil {
				nt = &nodeTotals{}
				nodeAggs[nid] = nt
			}
			nt.packets += packets
			nt.bytes += bytes
		}
	}
	if err := rows.Err(); err != nil {
		return nil, nil, err
	}
	edges := make([]StoredEdge, 0, len(order))
	for _, id := range order {
		edges = append(edges, *edgeByID[id])
	}
	if len(nodeAggs) == 0 {
		return nil, nil, nil
	}

	hostnames := make(map[string]string, len(nodeAggs))
	hrows, err := s.readDB.Query(
		`SELECT id, COALESCE(hostname,'') FROM nodes WHERE capture_id = ?`, captureID)
	if err != nil {
		return nil, nil, err
	}
	defer hrows.Close()
	for hrows.Next() {
		var id, host string
		if err := hrows.Scan(&id, &host); err != nil {
			return nil, nil, err
		}
		if host != "" {
			hostnames[id] = host
		}
	}
	if err := hrows.Err(); err != nil {
		return nil, nil, err
	}

	nodes := make([]StoredNode, 0, len(nodeAggs))
	for id, nt := range nodeAggs {
		nodes = append(nodes, StoredNode{
			ID:          id,
			Hostname:    hostnames[id],
			PacketCount: nt.packets,
			ByteCount:   nt.bytes,
		})
	}
	return nodes, edges, nil
}
