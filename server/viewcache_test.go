package server

import (
	"encoding/json"
	"testing"

	"etherchimp/capture"
	"etherchimp/graph"
)

// newTestClient builds a hub client without a websocket connection, draining
// nothing: the send buffer (256) is enough for a couple of ticks.
func newTestClient(h *Hub) *Client {
	return &Client{
		hub:       h,
		send:      make(chan outMsg, 256),
		cfg:       graph.ViewConfig{Hidden: graph.DefaultHiddenProtocols(), LayoutMode: "force"},
		needsFull: true,
		lastNodes: make(map[string]graph.ViewNode),
		lastEdges: make(map[string]graph.ViewEdge),
		layout:    graph.NewLayoutEngine(),
	}
}

// drainJSON collects the client's queued JSON view messages (skipping binary
// position frames).
func drainJSON(c *Client) []viewDelta {
	var out []viewDelta
	for {
		select {
		case m := <-c.send:
			if m.binary {
				continue
			}
			var d viewDelta
			if err := json.Unmarshal(m.data, &d); err == nil {
				out = append(out, d)
			}
		default:
			return out
		}
	}
}

// Identically configured clients share one layout engine and see identical
// positions; a diverging config gets its own bucket.
func TestSharedViewBuckets(t *testing.T) {
	gm := graph.NewManager()
	tcp := capture.Protocol{Name: "TCP", Layer: "transport", LayerNum: 4}
	gm.AddOrUpdateNode("10.0.0.1", "", 100)
	gm.AddOrUpdateNode("10.0.0.2", "", 100)
	gm.AddOrUpdateEdge("10.0.0.1", "10.0.0.2", tcp, 100)

	h := NewHub(gm, nil, nil)
	c1, c2 := newTestClient(h), newTestClient(h)
	h.clients[c1] = true
	h.clients[c2] = true

	h.tick()

	if len(h.sharedEngines) != 1 {
		t.Fatalf("shared engines = %d, want 1 (identical configs share a bucket)", len(h.sharedEngines))
	}

	d1, d2 := drainJSON(c1), drainJSON(c2)
	if len(d1) == 0 || len(d2) == 0 {
		t.Fatalf("clients received no view messages (%d, %d)", len(d1), len(d2))
	}
	posOf := func(ds []viewDelta) map[string][2]float64 {
		out := map[string][2]float64{}
		for _, d := range ds {
			for _, n := range d.Nodes {
				out[n.ID] = [2]float64{n.X, n.Y}
			}
		}
		return out
	}
	p1, p2 := posOf(d1), posOf(d2)
	if len(p1) != 2 || len(p2) != 2 {
		t.Fatalf("node counts: c1=%d c2=%d, want 2 each", len(p1), len(p2))
	}
	for id, p := range p1 {
		if p2[id] != p {
			t.Errorf("node %s position differs across shared clients: %v vs %v", id, p, p2[id])
		}
	}

	// A diverging config (hidden protocol) opens a second bucket.
	c2.mu.Lock()
	c2.cfg.Hidden = map[string]bool{"TCP": true}
	c2.needsFull = true
	c2.mu.Unlock()
	h.tick()
	if len(h.sharedEngines) != 2 {
		t.Fatalf("shared engines after divergence = %d, want 2", len(h.sharedEngines))
	}
}
