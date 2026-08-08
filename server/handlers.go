package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"etherchimp/capture"
	"etherchimp/graph"
	"etherchimp/replay"
	"etherchimp/store"
	"etherchimp/stream"
)

// Input validation constants
const (
	maxFilenameLength = 255
	maxOffsetSeconds  = 86400 * 365 // 1 year max offset
	minOffsetSeconds  = 0
)

// validFilenameRegex allows only safe characters in filenames
// Note: hyphen must be at end of character class to be treated as literal
var validFilenameRegex = regexp.MustCompile(`^[a-zA-Z0-9_.-]+\.pcap$`)

// handleIndex serves the main HTML page
func (m *Manager) handleIndex(w http.ResponseWriter, r *http.Request) {
	// Only serve index.html for root path
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}

	// Read and serve the index.html file
	indexFile := "static/index.html"
	data, err := os.ReadFile(indexFile)
	if err != nil {
		http.Error(w, "Failed to load page", http.StatusInternalServerError)
		return
	}

	// Tell the client whether the -chimpy sidebar items are enabled, inline so
	// the UI can gate them before first paint.
	flagScript := fmt.Sprintf(`<script>window.ETHERCHIMP_CHIMPY = %t;</script></head>`, m.chimpyEnabled)
	data = []byte(strings.Replace(string(data), "</head>", flagScript, 1))

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(data)
}

// handleNodeDetail serves the lazily-fetched full record for one node
// (Phase 5): the fields stripped from the streamed ViewNode plus a connection
// summary. GET /api/node?id=<nodeID>.
func (m *Manager) handleNodeDetail(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	if id == "" {
		http.Error(w, "missing id", http.StatusBadRequest)
		return
	}
	detail, ok := m.graphMgr.GetNodeDetail(id)
	if !ok {
		http.Error(w, "node not found", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(detail)
}

// handleSearch serves server-side node search over the WHOLE graph (Phase 5),
// so hosts hidden inside collapsed subnets or beyond the top-N view are still
// findable. GET /api/search?q=<query>&limit=<n>.
func (m *Manager) handleSearch(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query().Get("q")
	limit := parseIntParam(r, "limit", 20)
	if limit > 100 {
		limit = 100
	}
	// Try the Wireshark-subset display filter first; if the query isn't a
	// structured filter (e.g. a bare "192"), fall back to substring search so
	// existing behavior is preserved.
	results, ok := m.graphMgr.SearchFilter(q, limit)
	if !ok {
		results = m.graphMgr.SearchNodes(q, limit)
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"results": results})
}

// handlePayloadSearch searches the live packet ring for a case-insensitive
// payload substring, returning the newest matches with previews. Replaces the
// old client-side base64 scan of the browser's packet cache.
// GET /api/search/payload?q=<query>&limit=<n>.
func (m *Manager) handlePayloadSearch(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query().Get("q")
	if q == "" {
		http.Error(w, "missing query", http.StatusBadRequest)
		return
	}
	limit := parseIntParam(r, "limit", 50)
	if limit > 100 {
		limit = 100
	}
	results := m.graphMgr.SearchPayload(q, limit)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"results": results})
}

// handlePacketDetail returns preformatted payload views (hex dump, ASCII) for
// one buffered packet, so the browser inspector renders them verbatim instead
// of decoding/formatting base64 itself. GET /api/packet/detail?id=<n>.
func (m *Manager) handlePacketDetail(w http.ResponseWriter, r *http.Request) {
	id := parseIntParam(r, "id", 0)
	if id <= 0 {
		http.Error(w, "missing or invalid id", http.StatusBadRequest)
		return
	}
	pkt, ok := m.graphMgr.PacketByID(id)
	if !ok {
		http.Error(w, "packet no longer in buffer", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"id":        pkt.ID,
		"hexDump":   capture.HexDumpText(pkt.Payload, 512),
		"asciiView": capture.ASCIIText(pkt.Payload, 2048),
	})
}

// handleRecentPacket returns the single most-recent buffered packet (with
// payload) for a node or for a payload-text match, so clicking a search result
// opens the packet inspector on the latest relevant packet rather than only the
// details sidebar. GET /api/packet/recent?node=<id> or ?contains=<text>.
//
// Note: only the in-memory ring is searched. Matches older than the buffer
// window (e.g. text early in a large replay) are not found — full historic
// payload search needs persisted payloads or pcap offsets, which aren't
// currently recorded.
func (m *Manager) handleRecentPacket(w http.ResponseWriter, r *http.Request) {
	node := r.URL.Query().Get("node")
	contains := r.URL.Query().Get("contains")
	var (
		pkt graph.PacketData
		ok  bool
	)
	switch {
	case contains != "":
		pkt, ok = m.graphMgr.MostRecentPacketContaining(contains)
	case node != "":
		pkt, ok = m.graphMgr.MostRecentPacketForNode(node)
	default:
		http.Error(w, "missing node or contains", http.StatusBadRequest)
		return
	}
	if !ok {
		http.Error(w, "no matching packet in buffer", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(pkt)
}

// handleGraphAPI returns the current graph snapshot as JSON
func (m *Manager) handleGraphAPI(w http.ResponseWriter, r *http.Request) {
	snapshot := m.graphMgr.GetSnapshot()

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(snapshot); err != nil {
		http.Error(w, "Failed to encode graph data", http.StatusInternalServerError)
		return
	}
}

// handleOverrides serves the per-node customization store: GET returns the whole
// map, POST upserts one node's override, DELETE removes one. Changes persist to
// overrides.json and trigger a resync so all clients see them immediately.
func (m *Manager) handleOverrides(w http.ResponseWriter, r *http.Request) {
	if m.overrides == nil {
		http.Error(w, "Overrides not available", http.StatusServiceUnavailable)
		return
	}
	switch r.Method {
	case http.MethodGet:
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(m.overrides.All())

	case http.MethodPost:
		// Cap the body: overrides are tiny, so reject oversized payloads before
		// allocating to parse them.
		r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
		var body struct {
			NodeID   string             `json:"nodeId"`
			Override graph.NodeOverride `json:"override"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.NodeID == "" {
			http.Error(w, "Invalid override payload", http.StatusBadRequest)
			return
		}
		if len(body.NodeID) > 256 {
			http.Error(w, "Node ID too long", http.StatusBadRequest)
			return
		}
		m.overrides.Set(body.NodeID, body.Override)
		if m.hub != nil {
			m.hub.MarkResyncAll()
		}
		w.WriteHeader(http.StatusNoContent)

	case http.MethodDelete:
		id := r.URL.Query().Get("id")
		if id == "" {
			http.Error(w, "id is required", http.StatusBadRequest)
			return
		}
		m.overrides.Delete(id)
		if m.hub != nil {
			m.hub.MarkResyncAll()
		}
		w.WriteHeader(http.StatusNoContent)

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// packetsResponse wraps a page of packets with the next polling cursor.
type packetsResponse struct {
	Packets []graph.PacketData `json:"packets"`
	Cursor  int                `json:"cursor"`
}

// parseIntParam reads a non-negative int query param, defaulting to def.
func parseIntParam(r *http.Request, name string, def int) int {
	if v := r.URL.Query().Get(name); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			return n
		}
	}
	return def
}

// handlePackets serves recent packets for the live table. ?since=<id> returns
// only packets newer than the cursor (incremental polling); ?node=<id> or
// ?edge=<id> scopes to a selected node/edge. Replaces the old WS packet push.
func (m *Manager) handlePackets(w http.ResponseWriter, r *http.Request) {
	since := parseIntParam(r, "since", 0)
	limit := parseIntParam(r, "limit", 200)
	if limit > 1000 {
		limit = 1000
	}

	var pkts []graph.PacketData
	var cursor int
	switch {
	case r.URL.Query().Get("node") != "":
		pkts, cursor = m.graphMgr.GetPacketsForNode(r.URL.Query().Get("node"), since, limit)
	case r.URL.Query().Get("edge") != "":
		pkts, cursor = m.graphMgr.GetPacketsForEdge(r.URL.Query().Get("edge"), since, limit)
	default:
		pkts, cursor = m.graphMgr.GetPacketsSince(since, limit)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(packetsResponse{Packets: pkts, Cursor: cursor})
}

// handleListPcaps returns list of available pcap files
func (m *Manager) handleListPcaps(w http.ResponseWriter, r *http.Request) {
	pcapFiles, err := replay.GetPcapFiles("pcaps")
	if err != nil {
		http.Error(w, "Failed to list pcap files", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(pcapFiles); err != nil {
		http.Error(w, "Failed to encode response", http.StatusInternalServerError)
		return
	}
}

// validateFilename validates and sanitizes the filename parameter
func validateFilename(filename string) (string, error) {
	// Check for empty filename
	if filename == "" {
		return "", fmt.Errorf("filename is required")
	}

	// Check length
	if len(filename) > maxFilenameLength {
		return "", fmt.Errorf("filename too long (max %d characters)", maxFilenameLength)
	}

	// Get base filename to prevent path traversal
	filename = filepath.Base(filename)

	// Check for path traversal attempts
	if strings.Contains(filename, "..") || strings.HasPrefix(filename, "/") || strings.HasPrefix(filename, "\\") {
		return "", fmt.Errorf("invalid filename: path traversal not allowed")
	}

	// Validate filename format (alphanumeric, underscore, hyphen, dot, must end in .pcap)
	if !validFilenameRegex.MatchString(filename) {
		return "", fmt.Errorf("invalid filename format: must contain only alphanumeric characters, underscores, hyphens, dots, and end with .pcap")
	}

	return filename, nil
}

// validateOffset validates and parses the offset parameter
func validateOffset(offsetStr string) (float64, error) {
	if offsetStr == "" {
		return 0.0, nil
	}

	// Parse as float
	offset, err := strconv.ParseFloat(offsetStr, 64)
	if err != nil {
		return 0.0, fmt.Errorf("invalid offset format: must be a number")
	}

	// Validate range
	if offset < minOffsetSeconds {
		return 0.0, fmt.Errorf("offset must be non-negative")
	}

	if offset > maxOffsetSeconds {
		return 0.0, fmt.Errorf("offset too large (max %d seconds)", maxOffsetSeconds)
	}

	return offset, nil
}

// handleReplayPcap loads and processes a pcap file for replay
func (m *Manager) handleReplayPcap(w http.ResponseWriter, r *http.Request) {
	// Validate and sanitize filename
	filename, err := validateFilename(r.URL.Query().Get("filename"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Validate and parse offset
	offsetSeconds, err := validateOffset(r.URL.Query().Get("offset"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Resolve the file inside pcaps/ (or the startup -f file)
	safePath, err := m.resolvePcapPath(filename)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	// Pcap cache: when this exact file was fully ingested before (-db), rebuild
	// the offset snapshot from stored flow buckets instead of re-parsing the
	// file packet by packet.
	if m.db.Enabled() {
		if fm, err := store.ComputeFileMeta(safePath); err == nil {
			if capID, ok := m.db.FindCompletePcap(filename, fm); ok {
				if resp, ok := m.replayFromCache(capID, offsetSeconds); ok {
					w.Header().Set("Content-Type", "application/json")
					json.NewEncoder(w).Encode(resp)
					return
				}
			}
		}
	}

	// Replay session: the file is parsed and laid out once, then cached. Every
	// offset view reuses the FULL capture's converged positions, so scrubbing is
	// a binary search plus a snapshot build — and nodes never move between
	// offsets (new ones simply appear), which keeps the view stable.
	session, err := m.replaySessionFor(safePath)
	if err != nil {
		http.Error(w, "Failed to open pcap file", http.StatusNotFound)
		return
	}

	session.mu.Lock()
	defer session.mu.Unlock()

	// Get packets up to the specified time
	packetsWithTime := session.reader.GetPacketsUpToTime(offsetSeconds)

	// Build graph snapshot from packets (shared DNS cache across offsets)
	snapshot := replay.BuildSnapshotFromPackets(packetsWithTime, session.dnsCache)

	// Style the snapshot with the cached full-capture layout: every node in any
	// offset view exists in the full capture, so all positions are known.
	le := graph.NewLayoutEngine()
	le.SeedPositions("force", session.positions)
	view := graph.BuildView(graph.RawSnapshot{Nodes: snapshot.Nodes, Edges: snapshot.Edges},
		graph.ViewConfig{LayoutMode: "force"}, le, nil, nil, nil)
	resp := replayResponse{
		Nodes:    view.Nodes,
		Edges:    view.Edges,
		Packets:  snapshot.Packets,
		IsFull:   true,
		ValueMin: &session.valueMin,
		ValueMax: &session.valueMax,
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		http.Error(w, "Failed to encode response", http.StatusInternalServerError)
		return
	}
}

// replayResponse is the styled, render-ready payload for a replay offset.
type replayResponse struct {
	Nodes   []graph.ViewNode   `json:"nodes"`
	Edges   []graph.ViewEdge   `json:"edges"`
	Packets []graph.PacketData `json:"packets"`
	IsFull  bool               `json:"isFull"`
	// ValueMin/ValueMax are the FULL capture's node-value range, so the client
	// can scale node sizes absolutely across the timeline (nil when unknown,
	// e.g. the -db cache path — the client then uses per-view scaling).
	ValueMin *float64 `json:"valueMin,omitempty"`
	ValueMax *float64 `json:"valueMax,omitempty"`
}

// handleReplaySearch scans an entire pcap file for a query (endpoint IPs/names,
// protocol, or payload bytes) and returns each match with its offset in
// seconds, so the client can jump the replay timeline to it.
// GET /api/replay/search?filename=<file>&q=<query>&limit=<n>.
func (m *Manager) handleReplaySearch(w http.ResponseWriter, r *http.Request) {
	filename, err := validateFilename(r.URL.Query().Get("filename"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	query := r.URL.Query().Get("q")
	if query == "" {
		http.Error(w, "missing query", http.StatusBadRequest)
		return
	}
	limit := parseIntParam(r, "limit", 50)
	if limit > 100 {
		limit = 100
	}

	// Resolve the file inside pcaps/ (or the startup -f file)
	safePath, err := m.resolvePcapPath(filename)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	reader, err := replay.NewReader(safePath)
	if err != nil {
		http.Error(w, "Failed to open pcap file", http.StatusNotFound)
		return
	}
	defer reader.Close()

	results := reader.SearchPackets(query, limit)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"results": results})
}

// resolvePcapPath maps a validated base filename to a servable pcap: a file in
// the pcaps directory, or the startup -f replay file wherever it lives (a -f
// path outside pcaps/ must still be scrubbable through the replay endpoints).
func (m *Manager) resolvePcapPath(filename string) (string, error) {
	safePath := filepath.Join("pcaps", filename)

	// Verify the path stays within the pcaps directory
	absPath, err := filepath.Abs(safePath)
	if err != nil {
		return "", fmt.Errorf("invalid file path")
	}
	pcapsDir, err := filepath.Abs("pcaps")
	if err != nil {
		return "", fmt.Errorf("server configuration error")
	}
	if !strings.HasPrefix(absPath, pcapsDir+string(filepath.Separator)) {
		return "", fmt.Errorf("access denied")
	}
	if _, err := os.Stat(absPath); err == nil {
		return safePath, nil
	}

	// Fall back to the startup -f file (matched by base name only, so the
	// client never supplies — or learns — an arbitrary server path).
	if m.replayFile != "" && filepath.Base(m.replayFile) == filename {
		if _, err := os.Stat(m.replayFile); err == nil {
			return m.replayFile, nil
		}
	}
	return "", fmt.Errorf("pcap file not found")
}

// handleReplayInfo tells the client whether the server was started with -f
// (replay-only), and if so which file — so the UI can auto-enter replay mode
// with the timeline slider instead of rendering the static full-file graph as
// if it were live. GET /api/replay/info.
func (m *Manager) handleReplayInfo(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if m.replayFile == "" {
		json.NewEncoder(w).Encode(map[string]interface{}{"active": false})
		return
	}
	// When the -f file also lives in pcaps/, serve it under the pcaps/ path the
	// replay file list uses, so client behavior is identical either way.
	servedPath := m.replayFile
	if _, err := os.Stat(filepath.Join("pcaps", filepath.Base(m.replayFile))); err == nil {
		servedPath = filepath.Join("pcaps", filepath.Base(m.replayFile))
	}
	info, err := replay.GetFileInfo(servedPath)
	if err != nil {
		http.Error(w, "Failed to read replay file", http.StatusNotFound)
		return
	}
	json.NewEncoder(w).Encode(map[string]interface{}{
		"active":      true,
		"filename":    info.Filename,
		"path":        info.Path,
		"startTime":   info.StartTime,
		"endTime":     info.EndTime,
		"packetCount": info.PacketCount,
		"durationSec": info.DurationSec,
	})
}

// convergeReplayView styles and lays out a static (frozen) snapshot: replay has
// no live ticking, so a throwaway force layout is run to convergence before
// BuildView. Shared by the parse path and the pcap-cache path so both render
// identically.
func convergeReplayView(raw graph.RawSnapshot) graph.ViewSnapshot {
	le := graph.NewLayoutEngine()
	forceMode := map[string]bool{"force": true}
	for i := 0; i < 80; i++ {
		le.Step(raw, forceMode, nil, nil, nil)
	}
	return graph.BuildView(raw, graph.ViewConfig{LayoutMode: "force"}, le, nil, nil, nil)
}

// replayFromCache reconstructs the replay snapshot at offsetSeconds from the
// stored flow buckets (cumulative from capture start — matching what parsing
// the file up to that offset produces) and the persistent packet index. The
// aggregates route through the same BulkLoad path the startup cache uses, so
// hostname merging and styling match the cold path.
func (m *Manager) replayFromCache(capID int64, offsetSeconds float64) (replayResponse, bool) {
	_, first, _, err := m.db.TimelineOverview(capID, 1)
	if err != nil || first == 0 {
		return replayResponse{}, false
	}
	to := first + int64(offsetSeconds) + 1
	storedNodes, storedEdges, err := m.db.WindowAggregates(capID, first, to)
	if err != nil || len(storedNodes) == 0 {
		return replayResponse{}, false
	}
	tmp := graph.NewManager()
	tmp.BulkLoad(store.BulkNodes(storedNodes), store.BulkEdges(storedEdges))
	tmp.CommitRoles()
	view := convergeReplayView(tmp.SnapshotRaw())

	var pkts []graph.PacketData
	if rows, err := m.db.QueryPackets(capID, 0, to*1_000_000, "", 0, 1000); err == nil {
		for _, p := range rows {
			pkts = append(pkts, storePacketToData(p))
		}
	}
	return replayResponse{Nodes: view.Nodes, Edges: view.Edges, Packets: pkts, IsFull: true}, true
}

// handleDownloadCurrentPcap returns the current live capture pcap file
func (m *Manager) handleDownloadCurrentPcap(w http.ResponseWriter, r *http.Request) {
	// Get the most recent pcap file
	pcapFiles, err := replay.GetPcapFiles("pcaps")
	if err != nil || len(pcapFiles) == 0 {
		http.Error(w, "No pcap files available", http.StatusNotFound)
		return
	}

	// Get most recent file
	currentFile := pcapFiles[0]

	// Serve file for download
	w.Header().Set("Content-Type", "application/vnd.tcpdump.pcap")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s\"", currentFile.Filename))

	http.ServeFile(w, r, currentFile.Path)
}

// protocolInfo is the per-protocol shape served to the frontend legend/filter
// UI (lowercase keys, matching the protocols.json schema).
type protocolInfo struct {
	Name           string `json:"name"`
	Color          string `json:"color"`
	Layer          string `json:"layer"`
	LayerNum       int    `json:"layerNum"`
	Discovery      bool   `json:"discovery"`
	DefaultVisible bool   `json:"defaultVisible"`
}

// handleProtocols returns the active protocol catalog (ordered legend list)
// so the frontend builds its legend, layer grouping, and default filters from
// the server instead of hardcoded tables.
func (m *Manager) handleProtocols(w http.ResponseWriter, r *http.Request) {
	all := capture.GetAllProtocols()
	out := make([]protocolInfo, len(all))
	for i, p := range all {
		out[i] = protocolInfo{
			Name:           p.Name,
			Color:          p.Color,
			Layer:          p.Layer,
			LayerNum:       p.LayerNum,
			Discovery:      p.Discovery,
			DefaultVisible: p.DefaultVisible,
		}
	}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(out); err != nil {
		http.Error(w, "Failed to encode response", http.StatusInternalServerError)
		return
	}
}

// handleListStreams returns a list of all tracked streams
func (m *Manager) handleListStreams(w http.ResponseWriter, r *http.Request) {
	if m.streamMgr == nil {
		http.Error(w, "Stream tracking not available", http.StatusServiceUnavailable)
		return
	}

	// Check for protocol filter
	protocol := r.URL.Query().Get("protocol")
	var streams []stream.StreamInfo

	if protocol != "" {
		streams = m.streamMgr.GetStreamsByProtocol(stream.StreamProtocol(protocol))
	} else {
		streams = m.streamMgr.GetStreams()
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(streams); err != nil {
		http.Error(w, "Failed to encode response", http.StatusInternalServerError)
		return
	}
}

// handleGetStream returns detailed information for a specific stream
func (m *Manager) handleGetStream(w http.ResponseWriter, r *http.Request) {
	if m.streamMgr == nil {
		http.Error(w, "Stream tracking not available", http.StatusServiceUnavailable)
		return
	}

	// Get stream ID from query parameter
	streamID := r.URL.Query().Get("id")
	if streamID == "" {
		http.Error(w, "Stream ID is required", http.StatusBadRequest)
		return
	}

	// Validate stream ID format (basic sanity check)
	if len(streamID) > 200 || strings.ContainsAny(streamID, "<>\"'&") {
		http.Error(w, "Invalid stream ID format", http.StatusBadRequest)
		return
	}

	streamDetail, err := m.streamMgr.GetStream(streamID)
	if err != nil {
		http.Error(w, "Stream not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(streamDetail); err != nil {
		http.Error(w, "Failed to encode response", http.StatusInternalServerError)
		return
	}
}

// handleGetStreamStats returns stream tracking statistics
func (m *Manager) handleGetStreamStats(w http.ResponseWriter, r *http.Request) {
	if m.streamMgr == nil {
		http.Error(w, "Stream tracking not available", http.StatusServiceUnavailable)
		return
	}

	stats := m.streamMgr.GetStats()

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(stats); err != nil {
		http.Error(w, "Failed to encode response", http.StatusInternalServerError)
		return
	}
}
