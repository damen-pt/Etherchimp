package graph

import (
	"context"
	"log"
	"time"
)

// Sweep removal caps. Eligibility (age > threshold) is unchanged, but each
// 10s sweep removes at most this many of the stalest nodes/edges. Without the
// cap, everything from one burst (e.g. a 500-node port scan) hits the TTL at
// the same moment and dies in a single tick — a mass-removal delta plus a
// layout reheat, a delayed second freak-out long after the scan itself.
// Staggered, a large corpse fades over a couple of minutes in gentle waves.
const (
	maxNodeRemovalsPerSweep = 50
	maxEdgeRemovalsPerSweep = 100
)

// DecayManager handles time-based removal of stale nodes and edges
type DecayManager struct {
	graphMgr  *Manager
	threshold time.Duration
	interval  time.Duration
}

// NewDecayManager creates a new decay manager
func NewDecayManager(graphMgr *Manager, thresholdSeconds int) *DecayManager {
	return &DecayManager{
		graphMgr:  graphMgr,
		threshold: time.Duration(thresholdSeconds) * time.Second,
		interval:  10 * time.Second, // Run cleanup every 10 seconds
	}
}

// Start begins the decay cleanup process
func (d *DecayManager) Start(ctx context.Context) {
	go d.run(ctx)
}

// run executes the cleanup loop
func (d *DecayManager) run(ctx context.Context) {
	ticker := time.NewTicker(d.interval)
	defer ticker.Stop()

	log.Printf("Decay manager started (threshold: %v, interval: %v)", d.threshold, d.interval)

	for {
		select {
		case <-ctx.Done():
			log.Println("Decay manager stopped")
			return
		case <-ticker.C:
			d.cleanup()
		}
	}
}

// cleanup removes stale nodes and edges
func (d *DecayManager) cleanup() {
	removedNodes := d.graphMgr.RemoveStaleNodes(d.threshold)
	removedEdges := d.graphMgr.RemoveStaleEdges(d.threshold)

	if removedNodes > 0 || removedEdges > 0 {
		log.Printf("Cleanup: removed %d nodes and %d edges (nodes: %d, edges: %d)",
			removedNodes, removedEdges, d.graphMgr.GetNodeCount(), d.graphMgr.GetEdgeCount())
	}
}
