package graph

import (
	"strconv"
	"strings"
	"sync"
	"time"

	"etherchimp/capture"
)

// PacketData represents a captured packet with payload. Payload holds raw
// bytes in memory; encoding/json marshals []byte as base64, so the wire
// format is unchanged while ingest avoids a per-packet encode.
type PacketData struct {
	ID        int       `json:"id"`
	Timestamp time.Time `json:"timestamp"`
	SrcIP     string    `json:"src"`
	DstIP     string    `json:"dst"`
	SrcPort   uint16    `json:"srcPort"`
	DstPort   uint16    `json:"dstPort"`
	Protocol  string    `json:"protocol"`
	Length    int       `json:"length"`
	Payload   []byte    `json:"payload"`
	Summary   string    `json:"summary"`
	VLANID    uint16    `json:"vlanId,omitempty"` // 802.1Q VLAN ID when tagged
	// StreamID links the packet to its bidirectional stream (same key the
	// stream package builds); empty when the packet has no ports.
	StreamID string `json:"streamId,omitempty"`
}

// StreamKey builds the direction-normalized stream identifier for a packet,
// e.g. "TCP-10.0.0.1:80-10.0.0.2:5555". Returns "" without both ports.
func StreamKey(srcIP string, srcPort uint16, dstIP string, dstPort uint16, protocol string) string {
	if srcPort == 0 || dstPort == 0 {
		return ""
	}
	streamType := "TCP"
	if protocol == "UDP" || protocol == "DNS" {
		streamType = "UDP"
	}
	src := srcIP + ":" + strconv.Itoa(int(srcPort))
	dst := dstIP + ":" + strconv.Itoa(int(dstPort))
	if src > dst {
		src, dst = dst, src
	}
	return streamType + "-" + src + "-" + dst
}

// PacketStore manages a sliding window of recent packets using a ring buffer
// for efficient O(1) insertions without memory reallocation
type PacketStore struct {
	packets    []PacketData
	maxPackets int
	head       int // Index of oldest packet
	size       int // Current number of packets in buffer
	nextID     int
	mu         sync.RWMutex
}

// NewPacketStore creates a new packet store with ring buffer
func NewPacketStore(maxPackets int) *PacketStore {
	return &PacketStore{
		packets:    make([]PacketData, maxPackets),
		maxPackets: maxPackets,
		head:       0,
		size:       0,
		nextID:     1,
	}
}

// AddPacket adds a packet to the store using ring buffer logic
func (ps *PacketStore) AddPacket(pkt *capture.PacketInfo) {
	ps.mu.Lock()
	defer ps.mu.Unlock()

	// Create packet data; payload stays raw bytes (base64 happens at JSON
	// encode time, and only for packets actually served).
	packetData := PacketData{
		ID:        ps.nextID,
		Timestamp: time.Now(),
		SrcIP:     pkt.SrcIP,
		DstIP:     pkt.DstIP,
		SrcPort:   pkt.SrcPort,
		DstPort:   pkt.DstPort,
		Protocol:  pkt.Protocol.Name,
		Length:    pkt.Length,
		Payload:   pkt.Payload,
		Summary:   packetSummary(pkt),
		VLANID:    pkt.VLANID,
		StreamID:  StreamKey(pkt.SrcIP, pkt.SrcPort, pkt.DstIP, pkt.DstPort, pkt.Protocol.Name),
	}

	ps.nextID++

	// Calculate insert position (tail of ring buffer)
	insertPos := (ps.head + ps.size) % ps.maxPackets

	if ps.size < ps.maxPackets {
		// Buffer not full yet, just add
		ps.packets[insertPos] = packetData
		ps.size++
	} else {
		// Buffer full, overwrite oldest (at head) and advance head
		ps.packets[ps.head] = packetData
		ps.head = (ps.head + 1) % ps.maxPackets
	}
}

// packetSummary labels a packet by its well-known service (e.g. "Redis (6379)")
// when the port is recognized, otherwise falls back to the protocol name. This
// surfaces the top known ports in the packet list without making each one its
// own colored protocol.
func packetSummary(pkt *capture.PacketInfo) string {
	if label := capture.ServiceLabel(pkt.SrcPort, pkt.DstPort); label != "" {
		return label
	}
	return pkt.Protocol.Name + " packet"
}

// GetPackets returns all stored packets in chronological order
func (ps *PacketStore) GetPackets() []PacketData {
	ps.mu.RLock()
	defer ps.mu.RUnlock()

	result := make([]PacketData, ps.size)
	for i := 0; i < ps.size; i++ {
		idx := (ps.head + i) % ps.maxPackets
		result[i] = ps.packets[idx]
	}
	return result
}

// GetPacketsSince returns packets with ID > sinceID, up to limit, in
// chronological order, plus the highest ID returned (the next cursor). Drives
// the live packet table's incremental polling.
func (ps *PacketStore) GetPacketsSince(sinceID, limit int) ([]PacketData, int) {
	ps.mu.RLock()
	defer ps.mu.RUnlock()
	if limit <= 0 {
		limit = 200
	}
	result := make([]PacketData, 0, limit)
	cursor := sinceID
	for i := 0; i < ps.size; i++ {
		idx := (ps.head + i) % ps.maxPackets
		p := ps.packets[idx]
		if p.ID <= sinceID {
			continue
		}
		result = append(result, p)
		if p.ID > cursor {
			cursor = p.ID
		}
		if len(result) >= limit {
			break
		}
	}
	return result, cursor
}

// GetPacketsForIPs returns packets whose src or dst IP is in ipSet, with ID >
// sinceID, up to limit, chronological, plus the next cursor.
func (ps *PacketStore) GetPacketsForIPs(ipSet map[string]bool, sinceID, limit int) ([]PacketData, int) {
	ps.mu.RLock()
	defer ps.mu.RUnlock()
	if limit <= 0 {
		limit = 200
	}
	result := make([]PacketData, 0, limit)
	cursor := sinceID
	for i := 0; i < ps.size; i++ {
		idx := (ps.head + i) % ps.maxPackets
		p := ps.packets[idx]
		if p.ID <= sinceID || (!ipSet[p.SrcIP] && !ipSet[p.DstIP]) {
			continue
		}
		result = append(result, p)
		if p.ID > cursor {
			cursor = p.ID
		}
		if len(result) >= limit {
			break
		}
	}
	return result, cursor
}

// GetPacketsBetween returns packets exchanged strictly between the two IP sets
// (src in A & dst in B, or src in B & dst in A), with ID > sinceID.
func (ps *PacketStore) GetPacketsBetween(setA, setB map[string]bool, sinceID, limit int) ([]PacketData, int) {
	ps.mu.RLock()
	defer ps.mu.RUnlock()
	if limit <= 0 {
		limit = 200
	}
	result := make([]PacketData, 0, limit)
	cursor := sinceID
	for i := 0; i < ps.size; i++ {
		idx := (ps.head + i) % ps.maxPackets
		p := ps.packets[idx]
		if p.ID <= sinceID {
			continue
		}
		between := (setA[p.SrcIP] && setB[p.DstIP]) || (setB[p.SrcIP] && setA[p.DstIP])
		if !between {
			continue
		}
		result = append(result, p)
		if p.ID > cursor {
			cursor = p.ID
		}
		if len(result) >= limit {
			break
		}
	}
	return result, cursor
}

// MostRecentForIPs returns the newest buffered packet whose src or dst IP is in
// ipSet. The ring is stored oldest->newest, so we walk it from the tail.
func (ps *PacketStore) MostRecentForIPs(ipSet map[string]bool) (PacketData, bool) {
	ps.mu.RLock()
	defer ps.mu.RUnlock()
	for i := ps.size - 1; i >= 0; i-- {
		idx := (ps.head + i) % ps.maxPackets
		p := ps.packets[idx]
		if ipSet[p.SrcIP] || ipSet[p.DstIP] {
			return p, true
		}
	}
	return PacketData{}, false
}

// GetByID returns the buffered packet with the given ID, if still in the ring.
func (ps *PacketStore) GetByID(id int) (PacketData, bool) {
	ps.mu.RLock()
	defer ps.mu.RUnlock()
	for i := ps.size - 1; i >= 0; i-- {
		idx := (ps.head + i) % ps.maxPackets
		if ps.packets[idx].ID == id {
			return ps.packets[idx], true
		}
	}
	return PacketData{}, false
}

// MostRecentContaining returns the newest buffered packet whose decoded payload
// contains text (case-insensitive). Only the in-memory ring is searched, so
// matches older than the buffer window are not found — full historic payload
// search would require persisting payloads or pcap byte offsets (offsets are
// currently never recorded).
func (ps *PacketStore) MostRecentContaining(text string) (PacketData, bool) {
	if text == "" {
		return PacketData{}, false
	}
	lower := strings.ToLower(text)
	ps.mu.RLock()
	defer ps.mu.RUnlock()
	for i := ps.size - 1; i >= 0; i-- {
		idx := (ps.head + i) % ps.maxPackets
		p := ps.packets[idx]
		if payloadContains(p.Payload, lower) {
			return p, true
		}
	}
	return PacketData{}, false
}

// PayloadMatch is one packet matching a payload substring search.
type PayloadMatch struct {
	Packet PacketData `json:"packet"`
	// Preview is printable context (±20 bytes) around the first match.
	Preview string `json:"preview"`
}

// SearchPayload scans the ring (newest first) for a case-insensitive payload
// substring, returning at most limit matches.
func (ps *PacketStore) SearchPayload(text string, limit int) []PayloadMatch {
	matches := make([]PayloadMatch, 0)
	if text == "" || limit <= 0 {
		return matches
	}
	lower := strings.ToLower(text)
	ps.mu.RLock()
	defer ps.mu.RUnlock()
	for i := ps.size - 1; i >= 0 && len(matches) < limit; i-- {
		idx := (ps.head + i) % ps.maxPackets
		p := ps.packets[idx]
		pos := payloadContainsAt(p.Payload, lower)
		if pos < 0 {
			continue
		}
		matches = append(matches, PayloadMatch{Packet: p, Preview: payloadPreview(p.Payload, pos, len(lower))})
	}
	return matches
}

// payloadContains reports whether payload contains lower (already-lowercased)
// under ASCII case-insensitive comparison.
func payloadContains(payload []byte, lower string) bool {
	return payloadContainsAt(payload, lower) >= 0
}

// payloadContainsAt finds the first ASCII case-insensitive occurrence of lower
// in payload, or -1.
func payloadContainsAt(payload []byte, lower string) int {
	if len(lower) == 0 || len(lower) > len(payload) {
		return -1
	}
	for i := 0; i+len(lower) <= len(payload); i++ {
		found := true
		for j := 0; j < len(lower); j++ {
			b := payload[i+j]
			if b >= 'A' && b <= 'Z' {
				b += 32
			}
			if b != lower[j] {
				found = false
				break
			}
		}
		if found {
			return i
		}
	}
	return -1
}

// payloadPreview renders printable context around a match.
func payloadPreview(payload []byte, matchPos, matchLen int) string {
	start := matchPos - 20
	if start < 0 {
		start = 0
	}
	end := matchPos + matchLen + 20
	if end > len(payload) {
		end = len(payload)
	}
	var b strings.Builder
	for i := start; i < end; i++ {
		c := payload[i]
		if c >= 32 && c <= 126 {
			b.WriteByte(c)
		} else {
			b.WriteByte('.')
		}
	}
	preview := b.String()
	if len(preview) > 50 {
		preview = preview[:47] + "..."
	}
	return preview
}

// GetRecentPackets returns the most recent N packets in chronological order
func (ps *PacketStore) GetRecentPackets(n int) []PacketData {
	ps.mu.RLock()
	defer ps.mu.RUnlock()

	if n <= 0 || n > ps.size {
		n = ps.size
	}

	result := make([]PacketData, n)
	// Start from (size - n) packets from the head
	startOffset := ps.size - n
	for i := 0; i < n; i++ {
		idx := (ps.head + startOffset + i) % ps.maxPackets
		result[i] = ps.packets[idx]
	}
	return result
}
