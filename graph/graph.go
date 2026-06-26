package graph

import (
	"net"
	"strings"
	"sync"
	"time"

	"go-etherape/capture"
)

// Node represents a network node (IP address)
type Node struct {
	IP          string    `json:"id"`
	Hostname    string    `json:"label"`
	IPs         []string  `json:"ips"` // All IPs that map to this hostname
	PacketCount int       `json:"packetCount"`
	ByteCount   int64     `json:"byteCount"`
	LastSeen    time.Time `json:"lastSeen"`
	// IsGroup marks multicast/broadcast rendezvous addresses (mDNS, SSDP,
	// broadcast, …). These are protocol meeting points, not real hosts, so the
	// UI renders them small and excludes them from traffic-based sizing to keep
	// the focus on the actual network.
	IsGroup bool `json:"isGroup,omitempty"`

	// Device-role classification stats, populated by AddPortObservation. They are
	// internal (json:"-") and read only under the manager lock (in SnapshotRaw)
	// where the derived Role/Icon are computed — never copied out and read
	// concurrently. See classify.go.
	InPackets   int                 `json:"-"` // times this node was a packet destination
	OutPackets  int                 `json:"-"` // times this node was a packet source
	ListenPorts map[uint16]int      `json:"-"` // well-known dst ports it received on (serving)
	Peers       map[string]struct{} `json:"-"` // distinct peer node IDs (fan-out)

	// Role/Icon are the classification result, filled in by SnapshotRaw under the
	// read lock and carried out on the copy (safe scalars).
	Role string `json:"-"`
	Icon string `json:"-"`

	// DeviceKind/DeviceInfo come from LLDP/CDP discovery: "switch" or "router",
	// and the advertised port / management address. They make the node a
	// recognized piece of network hardware regardless of its traffic profile.
	DeviceKind string `json:"-"`
	DeviceInfo string `json:"-"`
}

// wellKnownGroups maps specific multicast/broadcast addresses to a stable label.
var wellKnownGroups = map[string]string{
	"224.0.0.251":     "mDNS (group)",
	"ff02::fb":        "mDNS (group)",
	"239.255.255.250": "SSDP (group)",
	"ff02::c":         "SSDP (group)",
	"224.0.0.252":     "LLMNR (group)",
	"ff02::1:3":       "LLMNR (group)",
	"224.0.0.5":       "OSPF (group)",
	"224.0.0.6":       "OSPF (group)",
	"224.0.0.1":       "All Hosts (group)",
	"224.0.0.2":       "All Routers (group)",
	"224.0.0.22":      "IGMP (group)",
	"255.255.255.255": "Broadcast",
}

// groupAddressLabel returns a stable, friendly label for multicast/broadcast
// "group" addresses and reports whether the IP is such a group. These represent
// a protocol rendezvous point rather than a real host. ok is false for ordinary
// unicast addresses (and for non-IP node IDs such as MAC-based L2 nodes).
func groupAddressLabel(ipStr string) (string, bool) {
	lower := strings.ToLower(ipStr)
	if label, ok := wellKnownGroups[lower]; ok {
		return label, true
	}
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return "", false
	}
	if ip4 := ip.To4(); ip4 != nil {
		if ip4[0] >= 224 && ip4[0] <= 239 { // 224.0.0.0/4 multicast
			return "Multicast (group)", true
		}
		if ip4[0] == 255 && ip4[1] == 255 && ip4[2] == 255 && ip4[3] == 255 {
			return "Broadcast", true
		}
		// Directed broadcast for a typical /24 (x.x.x.255). A heuristic, but on
		// the common LAN it is broadcast rather than a real host.
		if ip4[3] == 255 {
			return "Broadcast", true
		}
		return "", false
	}
	if strings.HasPrefix(lower, "ff") { // IPv6 multicast ff00::/8
		return "Multicast (group)", true
	}
	return "", false
}

// Edge represents a bidirectional connection between two nodes
type Edge struct {
	ID          string           `json:"id"`
	From        string           `json:"from"`
	To          string           `json:"to"`
	Protocol    capture.Protocol `json:"protocol"`
	PacketCount int              `json:"packetCount"`
	ByteCount   int64            `json:"byteCount"`
	LastSeen    time.Time        `json:"lastSeen"`
	// Bidirectional tracking
	ForwardPackets int   `json:"forwardPackets"` // From -> To
	ReversePackets int   `json:"reversePackets"` // To -> From
	ForwardBytes   int64 `json:"forwardBytes"`
	ReverseBytes   int64 `json:"reverseBytes"`
}

// getCanonicalEdgeID returns a consistent edge ID regardless of direction
func getCanonicalEdgeID(nodeA, nodeB string) (edgeID, from, to string) {
	if nodeA < nodeB {
		return nodeA + "<->" + nodeB, nodeA, nodeB
	}
	return nodeB + "<->" + nodeA, nodeB, nodeA
}

// TrafficFlow represents recent per-edge traffic for real-time visualization
type TrafficFlow struct {
	EdgeID   string `json:"edgeId"`
	From     string `json:"from"`
	To       string `json:"to"`
	Packets  int    `json:"packets"`
	Bytes    int64  `json:"bytes"`
	Protocol string `json:"protocol"`
	Color    string `json:"color"`
}

// GraphSnapshot represents the current state of the graph
type GraphSnapshot struct {
	Nodes   []Node       `json:"nodes"`
	Edges   []Edge       `json:"edges"`
	Packets []PacketData `json:"packets"`
}

// flowKey is a directional edge key for tracking per-interval traffic
type flowKey struct {
	edgeID   string
	from     string
	to       string
	protocol string
	color    string
}

// Manager manages the network graph data
type Manager struct {
	nodes            map[string]*Node // Key: node ID (hostname or IP)
	edges            map[string]*Edge
	ipToNodeID       map[string]string // Maps IP -> node ID (for lookup)
	hostnameToNodeID map[string]string // Maps hostname -> node ID (for merging)
	packetStore      *PacketStore
	dirty            bool                     // true when graph has been modified since last snapshot
	recentFlows      map[flowKey]*TrafficFlow // per-edge traffic since last drain
	protoCounts      map[string]int           // cumulative packets seen per protocol (all of them)
	mu               sync.RWMutex
}

// NewManager creates a new graph manager
func NewManager() *Manager {
	return &Manager{
		nodes:            make(map[string]*Node),
		edges:            make(map[string]*Edge),
		ipToNodeID:       make(map[string]string),
		hostnameToNodeID: make(map[string]string),
		packetStore:      NewPacketStore(1000),
		recentFlows:      make(map[flowKey]*TrafficFlow),
		protoCounts:      make(map[string]int),
	}
}

// ProtocolCounts returns a copy of the cumulative packet count per protocol,
// across ALL traffic regardless of the client's filter — so the legend can show
// a breakdown including currently-hidden protocols.
func (m *Manager) ProtocolCounts() map[string]int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make(map[string]int, len(m.protoCounts))
	for k, v := range m.protoCounts {
		out[k] = v
	}
	return out
}

// IsDirty returns true if the graph has been modified since last ClearDirty call
func (m *Manager) IsDirty() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.dirty
}

// ClearDirty resets the dirty flag
func (m *Manager) ClearDirty() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.dirty = false
}

// AddOrUpdateNode adds a new node or updates an existing one
func (m *Manager) AddOrUpdateNode(ip, hostname string, bytes int) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.dirty = true

	// Group (multicast/broadcast) addresses get a stable, friendly label instead
	// of a DNS name so they don't masquerade as a real host (e.g. mcast.mdns.net)
	// and become a generalized communication hub. Same label across IPv4/IPv6
	// collapses, e.g., 224.0.0.251 and ff02::fb into one "mDNS (group)" node.
	groupLabel, isGroup := groupAddressLabel(ip)
	if isGroup {
		hostname = groupLabel
	}

	// Determine if we should merge based on hostname
	useHostname := hostname != "" && hostname != ip
	var nodeID string
	var existingNodeID string

	// Check if this IP already belongs to a node
	if existing, ok := m.ipToNodeID[ip]; ok {
		existingNodeID = existing
	}

	// If hostname is valid and different from IP, check if it's already mapped
	if useHostname {
		if existing, ok := m.hostnameToNodeID[hostname]; ok {
			// This hostname already exists, use its node
			nodeID = existing
		} else {
			// New hostname, use it as node ID
			nodeID = hostname
			m.hostnameToNodeID[hostname] = nodeID
		}
	} else {
		// No hostname resolution, use IP as node ID
		nodeID = ip
	}

	// If IP was previously part of a different node, merge the nodes
	if existingNodeID != "" && existingNodeID != nodeID {
		// Merge old node into new node
		if oldNode, exists := m.nodes[existingNodeID]; exists {
			// Transfer data if new node doesn't exist yet
			if _, newExists := m.nodes[nodeID]; !newExists {
				m.nodes[nodeID] = oldNode
				m.nodes[nodeID].IP = nodeID // Update ID
				m.nodes[nodeID].Hostname = hostname
			} else {
				// Merge stats into existing node
				m.nodes[nodeID].PacketCount += oldNode.PacketCount
				m.nodes[nodeID].ByteCount += oldNode.ByteCount
				// Merge IPs using map for O(1) lookup instead of O(n²) nested loops
				existingIPs := make(map[string]bool, len(m.nodes[nodeID].IPs))
				for _, ip := range m.nodes[nodeID].IPs {
					existingIPs[ip] = true
				}
				for _, oldIP := range oldNode.IPs {
					if !existingIPs[oldIP] {
						m.nodes[nodeID].IPs = append(m.nodes[nodeID].IPs, oldIP)
					}
				}
			}
			// Delete old node
			delete(m.nodes, existingNodeID)
		}

		// Update all edges that used the old node ID
		// Collect edges to update/merge to avoid modifying map during iteration
		edgesToDelete := make([]string, 0)
		edgesToAdd := make(map[string]*Edge)

		for edgeID, edge := range m.edges {
			updated := false
			newFrom := edge.From
			newTo := edge.To
			if edge.From == existingNodeID {
				newFrom = nodeID
				updated = true
			}
			if edge.To == existingNodeID {
				newTo = nodeID
				updated = true
			}
			if updated {
				// Skip self-loops that might be created by merging
				if newFrom == newTo {
					edgesToDelete = append(edgesToDelete, edgeID)
					continue
				}

				// Calculate new canonical edge ID
				newEdgeID, canonicalFrom, canonicalTo := getCanonicalEdgeID(newFrom, newTo)

				if newEdgeID != edgeID {
					edgesToDelete = append(edgesToDelete, edgeID)

					// Check if an edge with the new ID already exists
					if existingEdge, exists := m.edges[newEdgeID]; exists {
						// Merge edge stats
						existingEdge.PacketCount += edge.PacketCount
						existingEdge.ByteCount += edge.ByteCount
						existingEdge.ForwardPackets += edge.ForwardPackets
						existingEdge.ReversePackets += edge.ReversePackets
						existingEdge.ForwardBytes += edge.ForwardBytes
						existingEdge.ReverseBytes += edge.ReverseBytes
						if edge.LastSeen.After(existingEdge.LastSeen) {
							existingEdge.LastSeen = edge.LastSeen
						}
					} else if pendingEdge, exists := edgesToAdd[newEdgeID]; exists {
						// Merge with pending edge
						pendingEdge.PacketCount += edge.PacketCount
						pendingEdge.ByteCount += edge.ByteCount
						pendingEdge.ForwardPackets += edge.ForwardPackets
						pendingEdge.ReversePackets += edge.ReversePackets
						pendingEdge.ForwardBytes += edge.ForwardBytes
						pendingEdge.ReverseBytes += edge.ReverseBytes
						if edge.LastSeen.After(pendingEdge.LastSeen) {
							pendingEdge.LastSeen = edge.LastSeen
						}
					} else {
						// Add as new edge with canonical ordering
						edge.ID = newEdgeID
						edge.From = canonicalFrom
						edge.To = canonicalTo
						edgesToAdd[newEdgeID] = edge
					}
				}
			}
		}

		// Apply edge changes
		for _, edgeID := range edgesToDelete {
			delete(m.edges, edgeID)
		}
		for edgeID, edge := range edgesToAdd {
			m.edges[edgeID] = edge
		}
	}

	// Update IP mapping
	m.ipToNodeID[ip] = nodeID

	// Add or update the node
	node, exists := m.nodes[nodeID]
	if !exists {
		ips := []string{ip}
		m.nodes[nodeID] = &Node{
			IP:          nodeID,
			Hostname:    hostname,
			IPs:         ips,
			PacketCount: 1,
			ByteCount:   int64(bytes),
			LastSeen:    time.Now(),
			IsGroup:     isGroup,
		}
	} else {
		node.PacketCount++
		node.ByteCount += int64(bytes)
		node.LastSeen = time.Now()

		// Add IP to list if not already present
		// Use ipToNodeID for O(1) existence check - if IP maps to this node, it's in the list
		if prevNodeID, exists := m.ipToNodeID[ip]; !exists || prevNodeID != nodeID {
			node.IPs = append(node.IPs, ip)
		}

		// Update hostname if resolved and not set
		if useHostname && node.Hostname == node.IP {
			node.Hostname = hostname
		}

		// Preserve group classification across updates
		if isGroup {
			node.IsGroup = true
		}
	}
}

// AddPortObservation records directional + port stats used for device-role
// classification. Called once per packet alongside AddOrUpdateNode/Edge (after
// them, so both nodes exist). A node serving a well-known (<1024) destination
// port looks like a server; high distinct-peer fan-out looks like a gateway.
func (m *Manager) AddPortObservation(srcIP, dstIP string, srcPort, dstPort uint16) {
	m.mu.Lock()
	defer m.mu.Unlock()

	srcID := m.ipToNodeID[srcIP]
	dstID := m.ipToNodeID[dstIP]
	src := m.nodes[srcID]
	dst := m.nodes[dstID]

	if src != nil {
		src.OutPackets++
		if dst != nil && srcID != dstID {
			if src.Peers == nil {
				src.Peers = make(map[string]struct{})
			}
			src.Peers[dstID] = struct{}{}
		}
	}
	if dst != nil {
		dst.InPackets++
		// A low destination port means this node is offering a service there.
		if dstPort > 0 && dstPort < 1024 {
			if dst.ListenPorts == nil {
				dst.ListenPorts = make(map[uint16]int)
			}
			dst.ListenPorts[dstPort]++
		}
		if src != nil && srcID != dstID {
			if dst.Peers == nil {
				dst.Peers = make(map[string]struct{})
			}
			dst.Peers[srcID] = struct{}{}
		}
	}
}

// AddOrUpdateEdge adds a new edge or updates an existing one (bidirectional)
func (m *Manager) AddOrUpdateEdge(srcIP, dstIP string, protocol capture.Protocol, bytes int) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.dirty = true
	// Called once per (graphed) packet, so this is an accurate per-protocol total
	// even for multi-protocol node pairs that collapse to one edge.
	m.protoCounts[protocol.Name]++

	// Map IPs to node IDs (might be hostnames)
	srcNodeID := srcIP
	if nodeID, ok := m.ipToNodeID[srcIP]; ok {
		srcNodeID = nodeID
	}

	dstNodeID := dstIP
	if nodeID, ok := m.ipToNodeID[dstIP]; ok {
		dstNodeID = nodeID
	}

	// Use canonical edge ID for bidirectional edges
	edgeID, canonicalFrom, canonicalTo := getCanonicalEdgeID(srcNodeID, dstNodeID)
	isForward := srcNodeID == canonicalFrom // true if packet flows From -> To

	edge, exists := m.edges[edgeID]

	if !exists {
		newEdge := &Edge{
			ID:          edgeID,
			From:        canonicalFrom,
			To:          canonicalTo,
			Protocol:    protocol,
			PacketCount: 1,
			ByteCount:   int64(bytes),
			LastSeen:    time.Now(),
		}
		if isForward {
			newEdge.ForwardPackets = 1
			newEdge.ForwardBytes = int64(bytes)
		} else {
			newEdge.ReversePackets = 1
			newEdge.ReverseBytes = int64(bytes)
		}
		m.edges[edgeID] = newEdge
	} else {
		edge.PacketCount++
		edge.ByteCount += int64(bytes)
		edge.LastSeen = time.Now()
		if isForward {
			edge.ForwardPackets++
			edge.ForwardBytes += int64(bytes)
		} else {
			edge.ReversePackets++
			edge.ReverseBytes += int64(bytes)
		}
		// Update protocol if it's more specific
		if protocol.Name != "TCP" && protocol.Name != "UDP" {
			edge.Protocol = protocol
		}
	}

	// Record directional flow for real-time traffic visualization
	fk := flowKey{
		edgeID:   edgeID,
		from:     srcNodeID,
		to:       dstNodeID,
		protocol: protocol.Name,
		color:    protocol.Color,
	}
	if flow, ok := m.recentFlows[fk]; ok {
		flow.Packets++
		flow.Bytes += int64(bytes)
	} else {
		m.recentFlows[fk] = &TrafficFlow{
			EdgeID:   edgeID,
			From:     srcNodeID,
			To:       dstNodeID,
			Packets:  1,
			Bytes:    int64(bytes),
			Protocol: protocol.Name,
			Color:    protocol.Color,
		}
	}
}

// GetSnapshot returns a snapshot of the current graph state
func (m *Manager) GetSnapshot() GraphSnapshot {
	m.mu.RLock()
	defer m.mu.RUnlock()

	nodes := make([]Node, 0, len(m.nodes))
	for _, node := range m.nodes {
		nodes = append(nodes, *node)
	}

	edges := make([]Edge, 0, len(m.edges))
	for _, edge := range m.edges {
		edges = append(edges, *edge)
	}

	// Get recent packets (limit to 100 for performance)
	packets := m.packetStore.GetRecentPackets(100)

	return GraphSnapshot{
		Nodes:   nodes,
		Edges:   edges,
		Packets: packets,
	}
}

// SnapshotRaw returns an unfiltered copy of the graph's nodes and edges without
// packets. Taken once per hub tick and fed to per-client BuildView so the copy
// work happens once rather than per client.
func (m *Manager) SnapshotRaw() RawSnapshot {
	m.mu.RLock()
	defer m.mu.RUnlock()

	nodes := make([]Node, 0, len(m.nodes))
	for _, node := range m.nodes {
		cp := *node
		// Classify under the read lock, where the stat maps are safe to read, and
		// carry only the scalar Role/Icon out on the copy.
		cp.Role, cp.Icon = classifyNode(node)
		nodes = append(nodes, cp)
	}
	edges := make([]Edge, 0, len(m.edges))
	for _, edge := range m.edges {
		edges = append(edges, *edge)
	}
	return RawSnapshot{Nodes: nodes, Edges: edges}
}

// GetPacketsSince returns recent packets with ID > sinceID (and the next cursor).
func (m *Manager) GetPacketsSince(sinceID, limit int) ([]PacketData, int) {
	return m.packetStore.GetPacketsSince(sinceID, limit)
}

// GetPacketsForNode returns packets involving any IP of the given node (by node
// ID), with ID > sinceID. Resolves the node's IP set under the manager lock.
func (m *Manager) GetPacketsForNode(nodeID string, sinceID, limit int) ([]PacketData, int) {
	m.mu.RLock()
	ipSet := make(map[string]bool)
	if node, ok := m.nodes[nodeID]; ok {
		for _, ip := range node.IPs {
			ipSet[ip] = true
		}
	}
	// nodeID may itself be an IP (unresolved node).
	ipSet[nodeID] = true
	m.mu.RUnlock()
	return m.packetStore.GetPacketsForIPs(ipSet, sinceID, limit)
}

// GetPacketsForEdge returns packets exchanged between the two endpoints of an
// edge ("nodeA<->nodeB"), with ID > sinceID.
func (m *Manager) GetPacketsForEdge(edgeID string, sinceID, limit int) ([]PacketData, int) {
	ipsOf := func(end string) map[string]bool {
		s := map[string]bool{end: true}
		if node, ok := m.nodes[end]; ok {
			for _, ip := range node.IPs {
				s[ip] = true
			}
		}
		return s
	}
	m.mu.RLock()
	edge, ok := m.edges[edgeID]
	if !ok {
		m.mu.RUnlock()
		return nil, sinceID
	}
	setA := ipsOf(edge.From)
	setB := ipsOf(edge.To)
	m.mu.RUnlock()
	return m.packetStore.GetPacketsBetween(setA, setB, sinceID, limit)
}

// VLANByIP maps each source/destination IP seen in the recent packet buffer to
// the first non-zero 802.1Q VLAN ID observed for it. Used by the subnet layout
// to label each island's dominant VLAN. Empty when no tagged traffic was seen.
func (m *Manager) VLANByIP() map[string]uint16 {
	pkts := m.packetStore.GetPackets()
	out := make(map[string]uint16)
	for i := range pkts {
		p := &pkts[i]
		if p.VLANID == 0 {
			continue
		}
		if p.SrcIP != "" {
			if _, ok := out[p.SrcIP]; !ok {
				out[p.SrcIP] = p.VLANID
			}
		}
		if p.DstIP != "" {
			if _, ok := out[p.DstIP]; !ok {
				out[p.DstIP] = p.VLANID
			}
		}
	}
	return out
}

// DrainFlows returns accumulated per-edge traffic flows and resets the counters.
// Called by the WebSocket hub on each broadcast tick.
func (m *Manager) DrainFlows() []TrafficFlow {
	m.mu.Lock()
	defer m.mu.Unlock()

	if len(m.recentFlows) == 0 {
		return nil
	}

	flows := make([]TrafficFlow, 0, len(m.recentFlows))
	for _, flow := range m.recentFlows {
		flows = append(flows, *flow)
	}
	m.recentFlows = make(map[flowKey]*TrafficFlow)
	return flows
}

// AddPacket adds a packet to the packet store
func (m *Manager) AddPacket(pkt *capture.PacketInfo) {
	m.packetStore.AddPacket(pkt)
	m.mu.Lock()
	m.dirty = true
	// LLDP/CDP frames carry network-device identity; stamp it on the source node
	// (already created earlier in the packet-processing order) for the hardware map.
	if pkt.DeviceKind != "" {
		if id, ok := m.ipToNodeID[pkt.SrcIP]; ok {
			if n := m.nodes[id]; n != nil {
				n.DeviceKind = pkt.DeviceKind
				if pkt.DeviceInfo != "" {
					n.DeviceInfo = pkt.DeviceInfo
				}
			}
		}
	}
	m.mu.Unlock()
}

// RemoveStaleNodes removes nodes that haven't been seen recently
func (m *Manager) RemoveStaleNodes(threshold time.Duration) int {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now()
	removed := 0

	// Collect stale node IDs first to avoid modifying map during iteration
	staleNodeIDs := make([]string, 0)
	for nodeID, node := range m.nodes {
		if now.Sub(node.LastSeen) > threshold {
			staleNodeIDs = append(staleNodeIDs, nodeID)
		}
	}

	if len(staleNodeIDs) > 0 {
		m.dirty = true
	}

	// Remove stale nodes and clean up mappings
	for _, nodeID := range staleNodeIDs {
		node := m.nodes[nodeID]
		if node != nil {
			// Remove all IP mappings for this node
			for _, ip := range node.IPs {
				delete(m.ipToNodeID, ip)
			}
			// Remove hostname mapping if it exists
			if node.Hostname != "" && node.Hostname != nodeID {
				delete(m.hostnameToNodeID, node.Hostname)
			}
			// Also check if nodeID itself is a hostname
			delete(m.hostnameToNodeID, nodeID)
		}
		delete(m.nodes, nodeID)
		removed++
	}

	return removed
}

// RemoveStaleEdges removes edges that haven't been seen recently
func (m *Manager) RemoveStaleEdges(threshold time.Duration) int {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now()

	// Collect stale edge IDs first to avoid modifying map during iteration
	staleEdgeIDs := make([]string, 0)
	for id, edge := range m.edges {
		if now.Sub(edge.LastSeen) > threshold {
			staleEdgeIDs = append(staleEdgeIDs, id)
		}
	}

	if len(staleEdgeIDs) > 0 {
		m.dirty = true
	}

	// Remove stale edges
	for _, id := range staleEdgeIDs {
		delete(m.edges, id)
	}

	return len(staleEdgeIDs)
}

// GetNodeCount returns the current number of nodes
func (m *Manager) GetNodeCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.nodes)
}

// GetEdgeCount returns the current number of edges
func (m *Manager) GetEdgeCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.edges)
}

// Clear removes all nodes, edges, and packets from the graph
func (m *Manager) Clear() {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.nodes = make(map[string]*Node)
	m.edges = make(map[string]*Edge)
	m.ipToNodeID = make(map[string]string)
	m.hostnameToNodeID = make(map[string]string)
	m.packetStore = NewPacketStore(1000)
	m.recentFlows = make(map[flowKey]*TrafficFlow)
	m.dirty = true
}
