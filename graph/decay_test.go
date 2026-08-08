package graph

import (
	"fmt"
	"testing"
	"time"
)

// seedStaleNodes inserts n stale nodes with strictly increasing LastSeen
// (index 0 is the stalest) plus freshCount fresh nodes, returning the stale
// IDs in stalest-first order.
func seedStaleNodes(m *Manager, base time.Time, staleCount, freshCount int) []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	staleIDs := make([]string, 0, staleCount)
	for i := 0; i < staleCount; i++ {
		id := fmt.Sprintf("10.1.%d.%d", i/256, i%256)
		m.nodes[id] = &Node{
			IP:       id,
			IPs:      []string{id},
			LastSeen: base.Add(-2*time.Hour + time.Duration(i)*time.Second),
		}
		staleIDs = append(staleIDs, id)
	}
	for i := 0; i < freshCount; i++ {
		id := fmt.Sprintf("192.168.0.%d", i+1)
		m.nodes[id] = &Node{
			IP:       id,
			IPs:      []string{id},
			LastSeen: base,
		}
	}
	return staleIDs
}

func nodeExists(m *Manager, id string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	_, ok := m.nodes[id]
	return ok
}

func TestRemoveStaleNodesStaggered(t *testing.T) {
	const (
		staleCount = 200
		freshCount = 5
		threshold  = time.Hour
	)
	base := time.Now()
	m := NewManager()
	staleIDs := seedStaleNodes(m, base, staleCount, freshCount)

	// First sweep: exactly the cap, and exactly the stalest nodes.
	removed := m.RemoveStaleNodes(threshold)
	if removed != maxNodeRemovalsPerSweep {
		t.Fatalf("first sweep removed %d nodes, want cap %d", removed, maxNodeRemovalsPerSweep)
	}
	for i, id := range staleIDs {
		exists := nodeExists(m, id)
		if i < maxNodeRemovalsPerSweep && exists {
			t.Errorf("stale node %d (%s) should have been removed in first sweep (stalest first)", i, id)
		}
		if i >= maxNodeRemovalsPerSweep && !exists {
			t.Errorf("stale node %d (%s) removed too early — sweep must take stalest first", i, id)
		}
	}
	if got := m.GetNodeCount(); got != staleCount+freshCount-maxNodeRemovalsPerSweep {
		t.Errorf("after first sweep: %d nodes, want %d", got, staleCount+freshCount-maxNodeRemovalsPerSweep)
	}

	// Subsequent sweeps drain the rest, cap at a time.
	total := removed
	sweeps := 1
	for m.GetNodeCount() > freshCount && sweeps < 100 {
		r := m.RemoveStaleNodes(threshold)
		if r <= 0 || r > maxNodeRemovalsPerSweep {
			t.Fatalf("sweep %d removed %d, want 1..%d", sweeps+1, r, maxNodeRemovalsPerSweep)
		}
		total += r
		sweeps++
	}
	if total != staleCount {
		t.Errorf("drained %d stale nodes total, want %d", total, staleCount)
	}
	if sweeps != staleCount/maxNodeRemovalsPerSweep {
		t.Errorf("took %d sweeps to drain, want %d", sweeps, staleCount/maxNodeRemovalsPerSweep)
	}

	// Fresh nodes untouched throughout.
	if got := m.GetNodeCount(); got != freshCount {
		t.Errorf("fresh nodes: %d remain, want %d", got, freshCount)
	}
	for i := 0; i < freshCount; i++ {
		id := fmt.Sprintf("192.168.0.%d", i+1)
		if !nodeExists(m, id) {
			t.Errorf("fresh node %s was removed", id)
		}
	}
}

func TestRemoveStaleEdgesStaggered(t *testing.T) {
	const (
		staleCount = 250
		freshCount = 3
		threshold  = time.Hour
	)
	base := time.Now()
	m := NewManager()

	m.mu.Lock()
	staleIDs := make([]string, 0, staleCount)
	for i := 0; i < staleCount; i++ {
		a := fmt.Sprintf("10.2.%d.%d", i/256, i%256)
		b := fmt.Sprintf("10.3.%d.%d", i/256, i%256)
		id, from, to := getCanonicalEdgeID(a, b)
		m.edges[id] = &Edge{
			ID:       id,
			From:     from,
			To:       to,
			LastSeen: base.Add(-2*time.Hour + time.Duration(i)*time.Second),
		}
		staleIDs = append(staleIDs, id)
	}
	for i := 0; i < freshCount; i++ {
		a := fmt.Sprintf("192.168.1.%d", i+1)
		b := fmt.Sprintf("192.168.2.%d", i+1)
		id, from, to := getCanonicalEdgeID(a, b)
		m.edges[id] = &Edge{ID: id, From: from, To: to, LastSeen: base}
	}
	m.mu.Unlock()

	edgeExists := func(id string) bool {
		m.mu.RLock()
		defer m.mu.RUnlock()
		_, ok := m.edges[id]
		return ok
	}

	// First sweep: exactly the cap, stalest first.
	removed := m.RemoveStaleEdges(threshold)
	if removed != maxEdgeRemovalsPerSweep {
		t.Fatalf("first sweep removed %d edges, want cap %d", removed, maxEdgeRemovalsPerSweep)
	}
	for i, id := range staleIDs {
		exists := edgeExists(id)
		if i < maxEdgeRemovalsPerSweep && exists {
			t.Errorf("stale edge %d should have been removed in first sweep (stalest first)", i)
		}
		if i >= maxEdgeRemovalsPerSweep && !exists {
			t.Errorf("stale edge %d removed too early — sweep must take stalest first", i)
		}
	}

	// Drain the rest.
	total := removed
	for m.GetEdgeCount() > freshCount {
		r := m.RemoveStaleEdges(threshold)
		if r <= 0 || r > maxEdgeRemovalsPerSweep {
			t.Fatalf("drain sweep removed %d, want 1..%d", r, maxEdgeRemovalsPerSweep)
		}
		total += r
	}
	if total != staleCount {
		t.Errorf("drained %d stale edges total, want %d", total, staleCount)
	}
	if got := m.GetEdgeCount(); got != freshCount {
		t.Errorf("fresh edges: %d remain, want %d", got, freshCount)
	}
}
