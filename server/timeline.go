package server

import (
	"encoding/json"
	"log"
	"net/http"

	"etherchimp/graph"
	"etherchimp/store"
)

// timelineState is a client's timeline-mode position: its view is rebuilt from
// stored flow buckets over the sliding window [t-window, t) instead of the
// live graph. built/builtWin track the last position actually rendered so the
// hub only reconstructs when the scrubber moved.
type timelineState struct {
	captureID int64
	t         int64 // unix seconds, quantized
	window    int64 // seconds
	built     int64
	builtWin  int64
}

// timelineParams snapshots the client's timeline position (nil-safe copy).
func (c *Client) timelineParams() (timelineState, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.timeline == nil {
		return timelineState{}, false
	}
	return *c.timeline, true
}

// timelineDirtyLocked reports whether the client's timeline position moved
// since the last built view. Caller holds c.mu.
func (c *Client) timelineDirtyLocked() bool {
	return c.timeline != nil &&
		(c.timeline.built != c.timeline.t || c.timeline.builtWin != c.timeline.window)
}

// timelineDirty is the self-locking variant of timelineDirtyLocked.
func (c *Client) timelineDirty() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.timelineDirtyLocked()
}

// hasTimeline reports whether the client is scrubbing a stored capture.
func (c *Client) hasTimeline() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.timeline != nil
}

// markTimelineBuilt records that the current position has been rendered.
func (c *Client) markTimelineBuilt(t, window int64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.timeline != nil {
		c.timeline.built = t
		c.timeline.builtWin = window
	}
}

// tlCacheEntry caches one reconstructed window snapshot so scrub ticks and
// multiple clients at the same position don't re-query SQLite.
type tlCacheEntry struct {
	captureID, t, window int64
	raw                  graph.RawSnapshot
}

const tlCacheSize = 4

// timelineRaw returns the graph state at time t (window ending at t) for a
// capture, reconstructing it from flow buckets through the same BulkLoad path
// the pcap cache uses — so hostname merging, group folding, and classification
// match the live view. Only called from the hub goroutine (no locking).
func (h *Hub) timelineRaw(captureID, t, window int64) graph.RawSnapshot {
	for i, e := range h.tlCache {
		if e.captureID == captureID && e.t == t && e.window == window {
			if i != 0 {
				copy(h.tlCache[1:i+1], h.tlCache[:i])
				h.tlCache[0] = e
			}
			return e.raw
		}
	}
	nodes, edges, err := h.db.WindowAggregates(captureID, t-window, t)
	if err != nil {
		log.Printf("timeline: window query failed (capture %d @ %d): %v", captureID, t, err)
		return graph.RawSnapshot{}
	}
	tmp := graph.NewManager()
	tmp.BulkLoad(store.BulkNodes(nodes), store.BulkEdges(edges))
	raw := tmp.SnapshotRaw()

	if len(h.tlCache) < tlCacheSize {
		h.tlCache = append(h.tlCache, tlCacheEntry{})
	}
	copy(h.tlCache[1:], h.tlCache[:len(h.tlCache)-1])
	h.tlCache[0] = tlCacheEntry{captureID: captureID, t: t, window: window, raw: raw}
	return raw
}

// handleTimeline serves the capture's traffic-over-time overview for the
// timeline bar. GET /api/timeline?capture=<id>&step=<sec>
func (m *Manager) handleTimeline(w http.ResponseWriter, r *http.Request) {
	captureID, ok := m.resolveCapture(w, r)
	if !ok {
		return
	}
	step := int64(parseIntParam(r, "step", 0))
	points, first, last, err := m.db.TimelineOverview(captureID, step)
	if err != nil {
		http.Error(w, "query failed", http.StatusInternalServerError)
		return
	}
	if step <= 0 {
		step = 1
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(struct {
		CaptureID int64                 `json:"captureId"`
		First     int64                 `json:"first"`
		Last      int64                 `json:"last"`
		Step      int64                 `json:"step"`
		Points    []store.OverviewPoint `json:"points"`
	}{captureID, first, last, step, points})
}
