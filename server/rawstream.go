package server

import (
	"encoding/binary"
	"encoding/json"
	"sort"
	"strings"
	"time"

	"etherchimp/graph"
)

// rawstream.go — raw-scale topology streaming for cosmos.gl clients (M5).
//
// A raw client gets the FULL filtered graph as periodic binary snapshots
// instead of the styled/aggregated/laid-out view. Full-frame-only is
// deliberate: the client re-uploads whole typed arrays to the GPU on any
// topology change anyway, and it preserves positions across frames by node id,
// so server-side diffing would buy nothing.
//
// Wire format, little-endian (msgType=2; follows the msgType=1 position-frame
// precedent in buildPosFrame):
//
//	[u8 type=2][u32 nodeCount]
//	  nodeCount x { [u16 idLen][id utf8][u8 tier][u8 flags] }
//	[u32 edgeCount]
//	  edgeCount x { [u32 a][u32 b][u8 protoIdx] }
//
// Each frame is preceded by a small JSON "rawMeta" message carrying the
// protocol table (protoIdx -> name/color) and view stats for the stats bar.

type rawMetaMsg struct {
	Type   string        `json:"type"` // "rawMeta"
	Protos []rawProtoRef `json:"protos"`
	Stats  viewStats     `json:"stats"`
}

type rawProtoRef struct {
	Name  string `json:"name"`
	Color string `json:"color"`
}

// rawFrameInterval picks the snapshot cadence: 1s normally, 5s at datacenter
// scale where a frame is megabytes.
func rawFrameInterval(nodeCount int) time.Duration {
	if nodeCount > largeGraphNodes {
		return 5 * time.Second
	}
	return time.Second
}

// hiddenKey canonicalizes a hidden-protocol set for use as a cache key.
func hiddenKey(hidden map[string]bool) string {
	if len(hidden) == 0 {
		return ""
	}
	names := make([]string, 0, len(hidden))
	for name, on := range hidden {
		if on {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	return strings.Join(names, ",")
}

// sendRawTopology builds and ships one raw snapshot to the client if its
// cadence (or a forced full) says so. Called from the hub tick goroutine.
// snapshotRaw is the tick's lazy snapshot getter (only taken when a frame is
// actually due), and cache shares the flattened topology across raw clients
// with the same hidden-protocol set within one tick.
func (h *Hub) sendRawTopology(c *Client, snapshotRaw func() graph.RawSnapshot, force bool, cache map[string]graph.RawTopology) {
	// Cadence check uses the manager's node count (cheap) so the O(nodes+edges)
	// snapshot isn't taken on ticks where no frame is due.
	if !force && time.Since(c.lastRawAt) < rawFrameInterval(h.graphMgr.GetNodeCount()) {
		return
	}
	c.lastRawAt = time.Now()

	hidden := c.snapshotCfg().Hidden
	key := hiddenKey(hidden)
	topo, ok := cache[key]
	if !ok {
		topo = graph.BuildRawTopology(snapshotRaw(), hidden, 0)
		cache[key] = topo
	}

	protos := make([]rawProtoRef, len(topo.Protos))
	for i, p := range topo.Protos {
		protos[i] = rawProtoRef{Name: p.Name, Color: p.Color}
	}
	meta, err := json.Marshal(rawMetaMsg{
		Type:   "rawMeta",
		Protos: protos,
		Stats: viewStats{
			NodeCount:    len(topo.IDs),
			EdgeCount:    len(topo.EdgeA),
			TotalPackets: topo.TotalPackets,
		},
	})
	if err == nil && !h.trySend(c, outMsg{data: meta}) {
		return
	}
	h.trySend(c, outMsg{data: encodeRawFrame(topo), binary: true})
}

func encodeRawFrame(t graph.RawTopology) []byte {
	size := 1 + 4 + 4 + len(t.EdgeA)*9
	for _, id := range t.IDs {
		size += 2 + len(id) + 2
	}
	buf := make([]byte, size)
	buf[0] = 2
	off := 1
	binary.LittleEndian.PutUint32(buf[off:], uint32(len(t.IDs)))
	off += 4
	for i, id := range t.IDs {
		binary.LittleEndian.PutUint16(buf[off:], uint16(len(id)))
		off += 2
		off += copy(buf[off:], id)
		buf[off] = t.Tiers[i]
		buf[off+1] = t.Flags[i]
		off += 2
	}
	binary.LittleEndian.PutUint32(buf[off:], uint32(len(t.EdgeA)))
	off += 4
	for i := range t.EdgeA {
		binary.LittleEndian.PutUint32(buf[off:], t.EdgeA[i])
		binary.LittleEndian.PutUint32(buf[off+4:], t.EdgeB[i])
		buf[off+8] = t.EdgeProto[i]
		off += 9
	}
	return buf[:off]
}
