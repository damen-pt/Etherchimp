package server

import "encoding/json"

// wsmsg.go defines the inbound WebSocket control protocol. The client sends
// these to drive its server-computed view (which protocols to hide, which
// layout mode to use). readPump decodes the envelope and dispatches by Type.

// ClientMessage is the envelope for all inbound control messages.
type ClientMessage struct {
	Type string          `json:"type"`
	Data json.RawMessage `json:"data"`
}

// SetFiltersMsg replaces the client's hidden-protocol set. Hidden lists the
// protocol names the client wants excluded from its view.
type SetFiltersMsg struct {
	Hidden []string `json:"hidden"`
}

// SetLayoutMsg selects the layout mode whose positions the server should send.
type SetLayoutMsg struct {
	Mode string `json:"mode"`
}

// Inbound message type tags.
const (
	msgSetFilters = "setFilters"
	msgSetLayout  = "setLayout"
	msgResync     = "resync"
)
