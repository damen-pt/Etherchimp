package graph

import (
	"encoding/json"
	"os"
	"sync"
)

// overrides.go is the server-side store of per-node user customizations (rename,
// recolor, custom icon, group designation, pinned position). It persists to a
// JSON file so customizations survive restarts and are shared across clients,
// replacing the old client-side localStorage userGroups. Keyed by node ID
// (hostname-or-IP); an override keyed by a bare IP is lost if that IP later
// resolves to a hostname (acceptable v1 limitation).

// NodeOverride is a single node's user customization. Empty fields mean "no
// override" and fall back to the server-computed value.
type NodeOverride struct {
	Label   string   `json:"label,omitempty"`
	Color   string   `json:"color,omitempty"`
	Icon    string   `json:"icon,omitempty"`
	Group   string   `json:"group,omitempty"`   // free-text user group name
	IsGroup bool     `json:"isGroup,omitempty"` // force compact "group" styling
	PinnedX *float64 `json:"pinnedX,omitempty"`
	PinnedY *float64 `json:"pinnedY,omitempty"`
}

// empty reports whether the override carries no customization (so it can be
// dropped from the store instead of persisting a no-op entry).
func (o NodeOverride) empty() bool {
	return o.Label == "" && o.Color == "" && o.Icon == "" && o.Group == "" &&
		!o.IsGroup && o.PinnedX == nil && o.PinnedY == nil
}

// OverrideStore is a concurrency-safe, file-backed map of node overrides.
type OverrideStore struct {
	mu   sync.RWMutex
	byID map[string]NodeOverride
	path string
}

// NewOverrideStore loads overrides from path (if it exists) and returns the store.
func NewOverrideStore(path string) *OverrideStore {
	s := &OverrideStore{byID: make(map[string]NodeOverride), path: path}
	if data, err := os.ReadFile(path); err == nil {
		_ = json.Unmarshal(data, &s.byID)
	}
	return s
}

// Get returns the override for a node ID, if any.
func (s *OverrideStore) Get(id string) (NodeOverride, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	o, ok := s.byID[id]
	return o, ok
}

// Set upserts (or, if empty, deletes) an override and persists the store.
func (s *OverrideStore) Set(id string, o NodeOverride) {
	s.mu.Lock()
	if o.empty() {
		delete(s.byID, id)
	} else {
		s.byID[id] = o
	}
	s.flushLocked()
	s.mu.Unlock()
}

// Delete removes an override and persists the store.
func (s *OverrideStore) Delete(id string) {
	s.mu.Lock()
	delete(s.byID, id)
	s.flushLocked()
	s.mu.Unlock()
}

// All returns a copy of every override (for the GET endpoint).
func (s *OverrideStore) All() map[string]NodeOverride {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make(map[string]NodeOverride, len(s.byID))
	for k, v := range s.byID {
		out[k] = v
	}
	return out
}

// Pins returns the pinned positions, for the layout engine to hold fixed.
func (s *OverrideStore) Pins() map[string]Vec {
	s.mu.RLock()
	defer s.mu.RUnlock()
	pins := make(map[string]Vec)
	for id, o := range s.byID {
		if o.PinnedX != nil && o.PinnedY != nil {
			pins[id] = Vec{X: *o.PinnedX, Y: *o.PinnedY}
		}
	}
	return pins
}

// flushLocked writes the store to disk atomically (tmp + rename). Caller holds
// the write lock. Errors are ignored: a failed persist must not break serving.
func (s *OverrideStore) flushLocked() {
	if s.path == "" {
		return
	}
	data, err := json.MarshalIndent(s.byID, "", "  ")
	if err != nil {
		return
	}
	tmp := s.path + ".tmp"
	if os.WriteFile(tmp, data, 0o644) != nil {
		return
	}
	_ = os.Rename(tmp, s.path)
}
