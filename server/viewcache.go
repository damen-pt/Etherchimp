package server

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"etherchimp/graph"
)

// viewcache.go shares view computation across clients with identical view
// configs. The layout is per-CONFIG by design (hidden nodes must not spread
// visible ones — a config property, not a client property), so N browsers with
// the same filters can share one layout engine and one BuildView per tick
// instead of N. Deltas stay per-client (each diffs against its own last view).

// sharedLayoutEngine is the persistent physics state for one config bucket.
type sharedLayoutEngine struct {
	eng      *graph.LayoutEngine
	lastUsed time.Time
}

// sharedEngineMaxIdle prunes config buckets no client has used in this long
// (e.g. after a filter/zoom change moves everyone to a new key).
const sharedEngineMaxIdle = 2 * time.Minute

// viewConfigKey serializes the view-affecting ViewConfig fields into a
// deterministic map key.
func viewConfigKey(cfg graph.ViewConfig) string {
	var b strings.Builder
	b.WriteString(cfg.LayoutMode)
	fmt.Fprintf(&b, "|%d|%d|%d|%d|%s|%s",
		cfg.MaxNodes, cfg.MaxEdges, cfg.AggregateThreshold, cfg.ExpandBudget,
		cfg.FocusCIDR, cfg.ZoomBand)
	writeSortedKeys(&b, cfg.Hidden)
	writeSortedKeys(&b, cfg.ExpandedSubnets)
	writeSortedKeys(&b, cfg.FullExpand)
	return b.String()
}

func writeSortedKeys(b *strings.Builder, m map[string]bool) {
	keys := make([]string, 0, len(m))
	for k, v := range m {
		if v {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	for _, k := range keys {
		b.WriteByte('|')
		b.WriteString(k)
	}
}

// sharedEngineFor returns the layout engine for a config bucket, creating it
// on first use. Hub goroutine only.
func (h *Hub) sharedEngineFor(key string) *graph.LayoutEngine {
	se := h.sharedEngines[key]
	if se == nil {
		se = &sharedLayoutEngine{eng: graph.NewLayoutEngine()}
		h.sharedEngines[key] = se
	}
	se.lastUsed = time.Now()
	return se.eng
}

// sharedEngineUnsettled reports whether a config bucket's layout is still
// converging; a missing engine counts as unsettled (a fresh one will need
// convergence once created).
func (h *Hub) sharedEngineUnsettled(key, mode string) bool {
	se := h.sharedEngines[key]
	if se == nil {
		return true
	}
	return se.eng.Unsettled(map[string]bool{mode: true})
}

// pruneSharedEngines drops idle config buckets. Hub goroutine only.
func (h *Hub) pruneSharedEngines(now time.Time) {
	for key, se := range h.sharedEngines {
		if now.Sub(se.lastUsed) > sharedEngineMaxIdle {
			delete(h.sharedEngines, key)
		}
	}
}
