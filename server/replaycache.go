package server

import (
	"math"
	"sync"
	"time"

	"etherchimp/graph"
	"etherchimp/replay"
)

// maxReplaySessions bounds the per-file replay cache (LRU by lastUsed).
const maxReplaySessions = 2

// replaySession holds everything scrubbing one pcap needs, built once: the
// parsed packets, a shared reverse-DNS cache, and the converged layout of the
// FULL capture. Offset views reuse the full-capture positions, so nodes never
// move while scrubbing the timeline — new ones simply appear. mu serializes
// requests using the session (the dnsCache map is mutated during snapshot
// builds).
type replaySession struct {
	mu        sync.Mutex
	reader    *replay.Reader
	dnsCache  map[string]string
	positions map[string]graph.Vec
	// valueMin/valueMax are the node-value extremes over the FULL capture. The
	// client scales node sizes against this fixed domain so scrubbing backward
	// visibly shrinks nodes (per-snapshot normalization would keep the biggest
	// node the same size at every offset).
	valueMin float64
	valueMax float64
	lastUsed time.Time
}

// replaySessionFor returns the cached session for path, building it on first
// use. Pcap capture files are immutable (rotation creates new names), so there
// is no invalidation beyond LRU eviction.
func (m *Manager) replaySessionFor(path string) (*replaySession, error) {
	m.replayMu.Lock()
	if s, ok := m.replaySessions[path]; ok {
		s.lastUsed = time.Now()
		m.replayMu.Unlock()
		return s, nil
	}
	m.replayMu.Unlock()

	// Build outside the lock: parsing + DNS + layout convergence is slow.
	reader, err := replay.NewReader(path)
	if err != nil {
		return nil, err
	}
	s := &replaySession{
		reader:   reader,
		dnsCache: make(map[string]string),
		lastUsed: time.Now(),
	}
	full := replay.BuildSnapshotFromPackets(
		reader.GetPacketsUpToTime(reader.GetDuration().Seconds()+1), s.dnsCache)
	view := convergeReplayView(graph.RawSnapshot{Nodes: full.Nodes, Edges: full.Edges})
	s.positions = make(map[string]graph.Vec, len(view.Nodes))
	s.valueMin = math.Inf(1)
	s.valueMax = math.Inf(-1)
	for _, n := range view.Nodes {
		s.positions[n.ID] = graph.Vec{X: n.X, Y: n.Y}
		if n.Value < s.valueMin {
			s.valueMin = n.Value
		}
		if n.Value > s.valueMax {
			s.valueMax = n.Value
		}
	}
	if len(view.Nodes) == 0 {
		s.valueMin, s.valueMax = 0, 0
	}

	m.replayMu.Lock()
	defer m.replayMu.Unlock()
	// A concurrent request may have built the same session; keep the existing
	// one and close the duplicate reader.
	if existing, ok := m.replaySessions[path]; ok {
		reader.Close()
		existing.lastUsed = time.Now()
		return existing, nil
	}
	m.replaySessions[path] = s

	// Evict least-recently-used sessions beyond the cap.
	for len(m.replaySessions) > maxReplaySessions {
		var oldestPath string
		var oldest time.Time
		for p, sess := range m.replaySessions {
			if oldestPath == "" || sess.lastUsed.Before(oldest) {
				oldestPath, oldest = p, sess.lastUsed
			}
		}
		m.replaySessions[oldestPath].reader.Close()
		delete(m.replaySessions, oldestPath)
	}
	return s, nil
}
