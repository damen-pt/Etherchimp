package server

import (
	"encoding/json"
	"log"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"go-etherape/graph"

	"github.com/gorilla/websocket"
)

const (
	// Time allowed to write a message to the peer
	writeWait = 10 * time.Second

	// Time allowed to read the next pong message from the peer
	pongWait = 60 * time.Second

	// Send pings to peer with this period (must be less than pongWait)
	pingPeriod = (pongWait * 9) / 10

	// Maximum message size allowed from peer. Large enough to hold a full
	// hidden-protocol set in a SetFiltersMsg.
	maxMessageSize = 8192
)

var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
	// Same-origin check to prevent cross-site WebSocket hijacking: a browser must
	// only connect from a page served by this host. Non-browser clients (no Origin
	// header) are allowed, matching the previous open behavior for tooling.
	CheckOrigin: func(r *http.Request) bool {
		origin := r.Header.Get("Origin")
		if origin == "" {
			return true
		}
		u, err := url.Parse(origin)
		if err != nil {
			return false
		}
		return strings.EqualFold(u.Host, r.Host)
	},
}

// Client represents a WebSocket client. Each client has its own server-computed
// view: a filter set + layout mode (cfg) and the last view it was sent
// (lastNodes/lastEdges) for per-client delta detection.
type Client struct {
	hub  *Hub
	conn *websocket.Conn
	send chan []byte

	mu        sync.Mutex // guards cfg, needsFull, lastNodes, lastEdges
	cfg       graph.ViewConfig
	needsFull bool // force a full styled view next tick (new client / filter / layout change)
	lastNodes map[string]graph.ViewNode
	lastEdges map[string]graph.ViewEdge
	// Per-client layout engine: stepped over only this client's filtered view, so
	// hidden nodes don't spread the visible ones and filter changes re-converge.
	layout *graph.LayoutEngine
}

// Hub maintains active WebSocket clients and computes per-client views.
type Hub struct {
	clients    map[*Client]bool
	register   chan *Client
	unregister chan *Client
	graphMgr   *graph.Manager
	overrides  *graph.OverrideStore
	resyncAll  chan struct{}
}

// MarkResyncAll asks the hub to send every client a fresh full view on the next
// tick. Used after an override change so customizations show immediately even
// when the graph and layout are otherwise idle. Non-blocking.
func (h *Hub) MarkResyncAll() {
	select {
	case h.resyncAll <- struct{}{}:
	default:
	}
}

// NewHub creates a new WebSocket hub
func NewHub(graphMgr *graph.Manager, overrides *graph.OverrideStore) *Hub {
	return &Hub{
		clients:    make(map[*Client]bool),
		register:   make(chan *Client),
		unregister: make(chan *Client),
		graphMgr:   graphMgr,
		overrides:  overrides,
		resyncAll:  make(chan struct{}, 1),
	}
}

// viewDelta is the per-client wire message: changed/new styled nodes & edges,
// removed IDs, traffic flows for animation, and a full-snapshot flag.
type viewDelta struct {
	Nodes         []graph.ViewNode     `json:"nodes"`
	Edges         []graph.ViewEdge     `json:"edges"`
	RemovedNodes  []string             `json:"removedNodes,omitempty"`
	RemovedEdges  []string             `json:"removedEdges,omitempty"`
	TrafficFlows  []graph.TrafficFlow  `json:"trafficFlows,omitempty"`
	SubnetIslands []graph.SubnetIsland `json:"subnetIslands,omitempty"`
	ProtocolStats map[string]int       `json:"protocolStats,omitempty"` // per-protocol packet totals (all, unfiltered)
	IsFull        bool                 `json:"isFull,omitempty"`
}

// Run starts the hub's main loop
func (h *Hub) Run() {
	ticker := time.NewTicker(100 * time.Millisecond) // Broadcast updates every 100ms
	defer ticker.Stop()

	for {
		select {
		case client := <-h.register:
			h.clients[client] = true
			log.Printf("Client connected (total: %d)", len(h.clients))
			// First view is sent on the next tick (needsFull was set at creation).

		case client := <-h.unregister:
			if _, ok := h.clients[client]; ok {
				delete(h.clients, client)
				close(client.send)
				log.Printf("Client disconnected (total: %d)", len(h.clients))
			}

		case <-h.resyncAll:
			// Force every client to receive a full styled view next tick.
			for client := range h.clients {
				client.mu.Lock()
				client.needsFull = true
				client.mu.Unlock()
			}

		case <-ticker.C:
			h.tick()
		}
	}
}

// tick computes and sends each client's view delta. Shared work (raw snapshot,
// flow drain) happens at most once per tick; per-client work is filter+style+diff.
func (h *Hub) tick() {
	if len(h.clients) == 0 {
		return
	}
	dirty := h.graphMgr.IsDirty()

	// Per-client gating: whether anyone awaits a full, whether any client's own
	// layout is still converging (so we keep ticking), and whether subnet mode is
	// in use anywhere (to compute VLANs once).
	anyNeedsFull := false
	anyLayoutBusy := false
	subnetActive := false
	for client := range h.clients {
		client.mu.Lock()
		mode := client.cfg.LayoutMode
		needsFull := client.needsFull
		client.mu.Unlock()
		if needsFull {
			anyNeedsFull = true
		}
		if mode == "subnet" {
			subnetActive = true
		}
		if client.layout.Unsettled(map[string]bool{mode: true}) {
			anyLayoutBusy = true
		}
	}

	if !dirty && !anyNeedsFull && !anyLayoutBusy {
		return
	}

	// Shared per-tick work: snapshot + drain flows once. Each client's layout is
	// stepped inside its own BuildView (over just that client's filtered view).
	h.graphMgr.ClearDirty()
	raw := h.graphMgr.SnapshotRaw()
	flows := h.graphMgr.DrainFlows()
	var vlanByIP map[string]uint16
	if subnetActive {
		vlanByIP = h.graphMgr.VLANByIP()
	}
	var pins map[string]graph.Vec
	if h.overrides != nil {
		pins = h.overrides.Pins()
	}

	// Filter-independent per-protocol totals, attached to every sent delta so the
	// legend can show a breakdown including hidden protocols.
	protoStats := h.graphMgr.ProtocolCounts()

	for client := range h.clients {
		// Build/marshal each client's view under its own recover so a panic on one
		// client's data can't kill the hub goroutine and freeze updates for everyone.
		func() {
			defer func() {
				if r := recover(); r != nil {
					log.Printf("recovered panic while building client view: %v", r)
				}
			}()
			full := client.consumeNeedsFull()
			view := graph.BuildView(raw, client.snapshotCfg(), client.layout, h.overrides, pins, vlanByIP)
			delta := client.buildDelta(view, flows, full)
			if delta == nil {
				return
			}
			delta.ProtocolStats = protoStats
			data, err := json.Marshal(delta)
			if err != nil {
				return
			}
			select {
			case client.send <- data:
			default:
				close(client.send)
				delete(h.clients, client)
			}
		}()
	}
}

// consumeNeedsFull atomically reads and clears the client's needsFull flag.
func (c *Client) consumeNeedsFull() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	full := c.needsFull
	c.needsFull = false
	return full
}

// snapshotCfg returns a copy of the client's view config for use off-lock.
func (c *Client) snapshotCfg() graph.ViewConfig {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.cfg
}

// nodeEqual reports whether two ViewNodes are identical. ViewNode is comparable
// except for its IPs slice, so we compare every scalar field with == and IPs
// element-wise. This replaces reflect.DeepEqual on the per-client, per-tick diff
// hot path (10x/sec * clients * nodes), avoiding reflection. ViewEdge is fully
// comparable and uses == directly.
func nodeEqual(a, b graph.ViewNode) bool {
	if a.ID != b.ID || a.Label != b.Label || a.PacketCount != b.PacketCount ||
		a.ByteCount != b.ByteCount || a.IsGroup != b.IsGroup || a.Value != b.Value ||
		a.ColorTier != b.ColorTier || a.Shape != b.Shape || a.Color != b.Color ||
		a.Role != b.Role || a.Icon != b.Icon || a.DeviceInfo != b.DeviceInfo ||
		a.X != b.X || a.Y != b.Y || a.Pinned != b.Pinned {
		return false
	}
	if len(a.IPs) != len(b.IPs) {
		return false
	}
	for i := range a.IPs {
		if a.IPs[i] != b.IPs[i] {
			return false
		}
	}
	return true
}

// buildDelta diffs a freshly-built view against the last one sent to this client
// and returns the wire message (or nil when there is nothing to send). On a full
// build it emits every node/edge and sets IsFull.
func (c *Client) buildDelta(view graph.ViewSnapshot, flows []graph.TrafficFlow, full bool) *viewDelta {
	c.mu.Lock()
	defer c.mu.Unlock()

	var changedNodes []graph.ViewNode
	var changedEdges []graph.ViewEdge
	var removedNodes, removedEdges []string

	curNodes := make(map[string]bool, len(view.Nodes))
	for _, n := range view.Nodes {
		curNodes[n.ID] = true
		prev, ok := c.lastNodes[n.ID]
		if full || !ok || !nodeEqual(prev, n) {
			changedNodes = append(changedNodes, n)
		}
		c.lastNodes[n.ID] = n
	}
	for id := range c.lastNodes {
		if !curNodes[id] {
			removedNodes = append(removedNodes, id)
			delete(c.lastNodes, id)
		}
	}

	curEdges := make(map[string]bool, len(view.Edges))
	for _, e := range view.Edges {
		curEdges[e.ID] = true
		prev, ok := c.lastEdges[e.ID]
		if full || !ok || prev != e {
			changedEdges = append(changedEdges, e)
		}
		c.lastEdges[e.ID] = e
	}
	for id := range c.lastEdges {
		if !curEdges[id] {
			removedEdges = append(removedEdges, id)
			delete(c.lastEdges, id)
		}
	}

	if !full && len(changedNodes) == 0 && len(changedEdges) == 0 &&
		len(removedNodes) == 0 && len(removedEdges) == 0 && len(flows) == 0 {
		return nil
	}

	return &viewDelta{
		Nodes:         changedNodes,
		Edges:         changedEdges,
		RemovedNodes:  removedNodes,
		RemovedEdges:  removedEdges,
		TrafficFlows:  flows,
		SubnetIslands: view.SubnetIslands,
		IsFull:        full,
	}
}

// applyControl handles an inbound control message, updating the client's view
// config and forcing a full resync next tick.
func (c *Client) applyControl(msg ClientMessage) {
	c.mu.Lock()
	defer c.mu.Unlock()

	switch msg.Type {
	case msgSetFilters:
		var m SetFiltersMsg
		if json.Unmarshal(msg.Data, &m) != nil {
			return
		}
		hidden := make(map[string]bool, len(m.Hidden))
		for _, name := range m.Hidden {
			hidden[name] = true
		}
		c.cfg.Hidden = hidden
		c.needsFull = true
	case msgSetLayout:
		var m SetLayoutMsg
		if json.Unmarshal(msg.Data, &m) != nil || m.Mode == "" {
			return
		}
		c.cfg.LayoutMode = m.Mode
		c.needsFull = true
	case msgResync:
		c.needsFull = true
	}
}

// readPump pumps messages from the WebSocket connection to the hub
func (c *Client) readPump() {
	defer func() {
		c.hub.unregister <- c
		c.conn.Close()
	}()

	c.conn.SetReadLimit(maxMessageSize)
	c.conn.SetReadDeadline(time.Now().Add(pongWait))
	c.conn.SetPongHandler(func(string) error {
		c.conn.SetReadDeadline(time.Now().Add(pongWait))
		return nil
	})

	for {
		_, data, err := c.conn.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				log.Printf("WebSocket error: %v", err)
			}
			break
		}
		var msg ClientMessage
		if json.Unmarshal(data, &msg) == nil {
			c.applyControl(msg)
		}
	}
}

// writePump pumps messages from the hub to the WebSocket connection
func (c *Client) writePump() {
	ticker := time.NewTicker(pingPeriod)
	defer func() {
		ticker.Stop()
		c.conn.Close()
	}()

	for {
		select {
		case message, ok := <-c.send:
			c.conn.SetWriteDeadline(time.Now().Add(writeWait))
			if !ok {
				c.conn.WriteMessage(websocket.CloseMessage, []byte{})
				return
			}

			w, err := c.conn.NextWriter(websocket.TextMessage)
			if err != nil {
				return
			}
			w.Write(message)

			if err := w.Close(); err != nil {
				return
			}

		case <-ticker.C:
			c.conn.SetWriteDeadline(time.Now().Add(writeWait))
			if err := c.conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				return
			}
		}
	}
}

// handleWebSocket handles WebSocket connections
func handleWebSocket(hub *Hub, w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("WebSocket upgrade failed: %v", err)
		return
	}

	client := &Client{
		hub:  hub,
		conn: conn,
		send: make(chan []byte, 256),
		cfg: graph.ViewConfig{
			Hidden:     graph.DefaultHiddenProtocols(),
			LayoutMode: "force",
		},
		needsFull: true, // first tick sends a full styled snapshot
		lastNodes: make(map[string]graph.ViewNode),
		lastEdges: make(map[string]graph.ViewEdge),
		layout:    graph.NewLayoutEngine(),
	}

	client.hub.register <- client

	go client.writePump()
	go client.readPump()
}
