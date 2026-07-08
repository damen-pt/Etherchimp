package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"etherchimp/capture"
	"etherchimp/graph"
	"etherchimp/store"
)

// resolveCapture implements the shared contract of every history/timeline
// endpoint: persistence must be enabled, and the capture id comes from the
// ?capture= query param falling back to this process's active session. On
// failure it writes the HTTP error and returns ok=false.
func (m *Manager) resolveCapture(w http.ResponseWriter, r *http.Request) (int64, bool) {
	if !m.db.Enabled() {
		http.Error(w, "persistence disabled (run with -db)", http.StatusNotImplemented)
		return 0, false
	}
	captureID, _ := strconv.ParseInt(r.URL.Query().Get("capture"), 10, 64)
	if captureID == 0 {
		captureID = m.captureID
	}
	if captureID == 0 {
		http.Error(w, "missing capture id", http.StatusBadRequest)
		return 0, false
	}
	return captureID, true
}

// handleHistoryCaptures lists stored capture sessions (requires -db).
// GET /api/history/captures
func (m *Manager) handleHistoryCaptures(w http.ResponseWriter, r *http.Request) {
	if !m.db.Enabled() {
		http.Error(w, "persistence disabled (run with -db)", http.StatusNotImplemented)
		return
	}
	captures, err := m.db.ListCaptures(parseIntParam(r, "limit", 100))
	if err != nil {
		http.Error(w, "query failed", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(struct {
		Captures interface{} `json:"captures"`
		Current  int64       `json:"current"` // this process's active session (0 = none)
	}{captures, m.captureID})
}

// handleHistoryPackets serves the persistent packet index — the drill-down
// beyond the in-memory 1000-packet ring buffer. Response shape matches
// /api/packets so the existing packet-table UI can consume it.
// GET /api/history/packets?capture=&from=&to=&node=&since=&limit=
// (from/to are unix seconds, fractional ok)
func (m *Manager) handleHistoryPackets(w http.ResponseWriter, r *http.Request) {
	captureID, ok := m.resolveCapture(w, r)
	if !ok {
		return
	}
	fromMicros := int64(parseFloatParam(r, "from", 0) * 1e6)
	toMicros := int64(parseFloatParam(r, "to", 0) * 1e6)
	sinceID := int64(parseIntParam(r, "since", 0))
	limit := parseIntParam(r, "limit", 200)

	rows, err := m.db.QueryPackets(captureID, fromMicros, toMicros,
		r.URL.Query().Get("node"), sinceID, limit)
	if err != nil {
		http.Error(w, "query failed", http.StatusInternalServerError)
		return
	}

	pkts := make([]graph.PacketData, len(rows))
	cursor := 0
	for i, p := range rows {
		pkts[i] = storePacketToData(p)
		cursor = int(p.ID)
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(packetsResponse{Packets: pkts, Cursor: cursor})
}

// storePacketToData converts an indexed packet row into the wire shape the
// packet-table UI consumes. The summary follows the live path's rule
// (graph.packetSummary): well-known service label when a port is recognized,
// protocol name otherwise — so the same packet reads identically in the
// history drill-down and the live table.
func storePacketToData(p store.PacketRow) graph.PacketData {
	summary := capture.ServiceLabel(p.SrcPort, p.DstPort)
	if summary == "" {
		summary = fmt.Sprintf("%s packet", p.Proto)
	}
	return graph.PacketData{
		ID:        int(p.ID),
		Timestamp: time.UnixMicro(p.TS),
		SrcIP:     p.Src,
		DstIP:     p.Dst,
		SrcPort:   p.SrcPort,
		DstPort:   p.DstPort,
		Protocol:  p.Proto,
		Length:    p.Length,
		VLANID:    p.VLAN,
		Summary:   summary,
	}
}

// parseFloatParam mirrors parseIntParam for fractional query values.
func parseFloatParam(r *http.Request, name string, def float64) float64 {
	if v := r.URL.Query().Get(name); v != "" {
		if f, err := strconv.ParseFloat(v, 64); err == nil {
			return f
		}
	}
	return def
}
