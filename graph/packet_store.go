package graph

import (
	"encoding/base64"
	"strings"
	"sync"
	"time"

	"etherchimp/capture"
)

// PacketData represents a captured packet with payload
type PacketData struct {
	ID        int       `json:"id"`
	Timestamp time.Time `json:"timestamp"`
	SrcIP     string    `json:"src"`
	DstIP     string    `json:"dst"`
	SrcPort   uint16    `json:"srcPort"`
	DstPort   uint16    `json:"dstPort"`
	Protocol  string    `json:"protocol"`
	Length    int       `json:"length"`
	Payload   string    `json:"payload"` // Base64 encoded payload
	Summary   string    `json:"summary"`
	VLANID    uint16    `json:"vlanId,omitempty"` // 802.1Q VLAN ID when tagged
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

	// Create packet data with base64 encoded payload
	packetData := PacketData{
		ID:        ps.nextID,
		Timestamp: time.Now(),
		SrcIP:     pkt.SrcIP,
		DstIP:     pkt.DstIP,
		SrcPort:   pkt.SrcPort,
		DstPort:   pkt.DstPort,
		Protocol:  pkt.Protocol.Name,
		Length:    pkt.Length,
		Payload:   base64.StdEncoding.EncodeToString(pkt.Payload),
		Summary:   packetSummary(pkt),
		VLANID:    pkt.VLANID,
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
		raw, err := base64.StdEncoding.DecodeString(p.Payload)
		if err != nil {
			continue
		}
		if strings.Contains(strings.ToLower(string(raw)), lower) {
			return p, true
		}
	}
	return PacketData{}, false
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
