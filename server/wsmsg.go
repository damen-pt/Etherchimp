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

// SetAggregationMsg syncs the client's Phase 4/6 subnet-aggregation state: the
// activation threshold (0 = server default), pin-opened CIDRs (budgeted expand),
// fully-expanded CIDRs (no residual tail), optional isolate FocusCIDR, and the
// camera ZoomBand for semantic zoom LOD. Sent on connect and on every change.
type SetAggregationMsg struct {
	Threshold  int      `json:"threshold"`
	Expanded   []string `json:"expanded"`
	FullExpand []string `json:"fullExpand,omitempty"`
	Focus      string   `json:"focus,omitempty"`
	ZoomBand   string   `json:"zoomBand,omitempty"`
}

// SetTimelineMsg enters/moves/exits timeline mode: the client's view is built
// from stored flow buckets in a sliding window ending at T instead of the live
// graph. CaptureID 0 exits back to the live view. T is unix seconds; Window is
// the sliding-window length in seconds (0 = default 60, mirroring live decay).
type SetTimelineMsg struct {
	CaptureID int64   `json:"captureId"`
	T         float64 `json:"t"`
	Window    float64 `json:"window"`
}

// SetViewModeMsg switches between the styled/aggregated view ("normal") and
// raw-scale topology streaming ("raw", cosmos.gl clients — see rawstream.go).
type SetViewModeMsg struct {
	Mode string `json:"mode"`
}

// Inbound message type tags.
const (
	msgSetFilters     = "setFilters"
	msgSetLayout      = "setLayout"
	msgSetAggregation = "setAggregation"
	msgResync         = "resync"
	msgSetTimeline    = "setTimeline"
	msgSetViewMode    = "setViewMode"
)
