package graph

import (
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"etherchimp/capture"
)

// Node represents a network node (IP address)
type Node struct {
	IP          string    `json:"id"`
	Hostname    string    `json:"label"`
	IPs         []string  `json:"ips"`            // All IPs that map to this hostname
	MACs        []string  `json:"macs,omitempty"` // Ethernet MACs seen for this node (populated by the capture/merge path)
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

	// Role/Icon are the classification result, committed by SnapshotRaw under the
	// write lock (with flip damping, see classify.go) and carried out on the copy
	// (safe scalars).
	Role string `json:"-"`
	Icon string `json:"-"`

	// Role-flip damping state, mutated only by SnapshotRaw under the write lock.
	// A candidate role different from Role must persist for roleFlipDamping
	// before it is committed, so bursts (port scans) flip icons once, late,
	// instead of flickering.
	pendingRole  string    `json:"-"`
	pendingSince time.Time `json:"-"`

	// DeviceKind/DeviceInfo come from LLDP/CDP discovery: "switch" or "router",
	// and the advertised port / management address. They make the node a
	// recognized piece of network hardware regardless of its traffic profile.
	DeviceKind string `json:"-"`
	DeviceInfo string `json:"-"`

	// searchCorpus is the precomputed lowercase haystack (id + hostname + IPs +
	// MACs) used by SearchNodes, rebuilt only at identity-changing events
	// (creation, hostname/IP/MAC updates, merges) — never per packet.
	searchCorpus string
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

// EdgeIDSep joins the two endpoint IDs of a canonical edge ID. The store
// persists edge IDs verbatim, so anything that builds or parses one must go
// through getCanonicalEdgeID / SplitEdgeID rather than hand-rolling the format.
const EdgeIDSep = "<->"

// getCanonicalEdgeID returns a consistent edge ID regardless of direction
func getCanonicalEdgeID(nodeA, nodeB string) (edgeID, from, to string) {
	if nodeA < nodeB {
		return nodeA + EdgeIDSep + nodeB, nodeA, nodeB
	}
	return nodeB + EdgeIDSep + nodeA, nodeB, nodeA
}

// SplitEdgeID parses a canonical edge ID back into its endpoints. Node IDs can
// themselves contain the separator's characters, so it splits on the FIRST
// occurrence, matching how getCanonicalEdgeID joined them.
func SplitEdgeID(id string) (from, to string, ok bool) {
	if i := strings.Index(id, EdgeIDSep); i > 0 && i+len(EdgeIDSep) < len(id) {
		return id[:i], id[i+len(EdgeIDSep):], true
	}
	return "", "", false
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
	// edgesByNode is the per-node adjacency index (nodeID -> set of edge IDs),
	// maintained at every edge insert/delete/re-key so GetNodeDetail is
	// O(degree) instead of scanning all edges per request.
	edgesByNode      map[string]map[string]bool
	ipToNodeID       map[string]string // Maps IP -> node ID (for lookup)
	hostnameToNodeID map[string]string // Maps hostname -> node ID (for merging)
	macToNodeID      map[string]string // Maps host MAC -> node ID (identity anchor)
	macShared        map[string]bool   // MACs seen concurrently on distinct hosts (router/NAT) — never anchor
	packetStore      *PacketStore
	dirty            bool                     // true when graph has been modified since last snapshot
	recentFlows      map[flowKey]*TrafficFlow // per-edge traffic since last drain
	protoCounts      map[string]int           // cumulative packets seen per protocol (all of them)
	// macActiveWindow: if a MAC's current anchor node was seen more recently than
	// this, a second distinct IP appearing on that MAC means two hosts share it
	// concurrently (a gateway) rather than one host being re-addressed (DHCP), so
	// we refuse to merge. Kept a bit above the DNS/decay cadence.
	macActiveWindow time.Duration
	mu              sync.RWMutex
}

// NewManager creates a new graph manager
func NewManager() *Manager {
	return &Manager{
		nodes:            make(map[string]*Node),
		edges:            make(map[string]*Edge),
		edgesByNode:      make(map[string]map[string]bool),
		ipToNodeID:       make(map[string]string),
		hostnameToNodeID: make(map[string]string),
		macToNodeID:      make(map[string]string),
		macShared:        make(map[string]bool),
		packetStore:      NewPacketStore(1000),
		recentFlows:      make(map[flowKey]*TrafficFlow),
		protoCounts:      make(map[string]int),
		macActiveWindow:  90 * time.Second,
	}
}

// indexEdgeLocked records an edge under both endpoints in the adjacency index.
func (m *Manager) indexEdgeLocked(e *Edge) {
	for _, nodeID := range [2]string{e.From, e.To} {
		set := m.edgesByNode[nodeID]
		if set == nil {
			set = make(map[string]bool)
			m.edgesByNode[nodeID] = set
		}
		set[e.ID] = true
	}
}

// unindexEdgeLocked drops an edge from both endpoints' adjacency sets.
func (m *Manager) unindexEdgeLocked(e *Edge) {
	for _, nodeID := range [2]string{e.From, e.To} {
		if set := m.edgesByNode[nodeID]; set != nil {
			delete(set, e.ID)
			if len(set) == 0 {
				delete(m.edgesByNode, nodeID)
			}
		}
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
	m.addOrUpdateNodeLocked(ip, hostname, bytes)
}

// addOrUpdateNodeLocked is AddOrUpdateNode's body; caller holds m.mu.
func (m *Manager) addOrUpdateNodeLocked(ip, hostname string, bytes int) {
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
		m.mergeNodeInto(nodeID, existingNodeID, hostname)
	}

	// Update IP mapping
	m.ipToNodeID[ip] = nodeID

	// Add or update the node
	node, exists := m.nodes[nodeID]
	if !exists {
		ips := []string{ip}
		newNode := &Node{
			IP:          nodeID,
			Hostname:    hostname,
			IPs:         ips,
			PacketCount: 1,
			ByteCount:   int64(bytes),
			LastSeen:    time.Now(),
			IsGroup:     isGroup,
		}
		m.nodes[nodeID] = newNode
		rebuildSearchCorpusLocked(newNode)
	} else {
		node.PacketCount++
		node.ByteCount += int64(bytes)
		node.LastSeen = time.Now()

		corpusDirty := false

		// Add IP to list if not already present
		// Use ipToNodeID for O(1) existence check - if IP maps to this node, it's in the list
		if prevNodeID, exists := m.ipToNodeID[ip]; !exists || prevNodeID != nodeID {
			node.IPs = append(node.IPs, ip)
			corpusDirty = true
		}

		// Update hostname if resolved and not set
		if useHostname && node.Hostname == node.IP {
			node.Hostname = hostname
			corpusDirty = true
		}

		if corpusDirty {
			rebuildSearchCorpusLocked(node)
		}

		// Preserve group classification across updates
		if isGroup {
			node.IsGroup = true
		}
	}
}

// rebuildSearchCorpusLocked recomputes a node's lowercase search haystack
// (id + hostname + IPs + MACs). Caller holds m.mu.
func rebuildSearchCorpusLocked(n *Node) {
	var b strings.Builder
	b.WriteString(strings.ToLower(n.IP))
	if n.Hostname != "" && n.Hostname != n.IP {
		b.WriteByte('\n')
		b.WriteString(strings.ToLower(n.Hostname))
	}
	for _, ip := range n.IPs {
		b.WriteByte('\n')
		b.WriteString(strings.ToLower(ip))
	}
	for _, mc := range n.MACs {
		b.WriteByte('\n')
		b.WriteString(strings.ToLower(mc))
	}
	n.searchCorpus = b.String()
}

// mergeNodeInto folds oldID's node and all its edges into newID, re-keying edges
// to canonical form and merging duplicate stats. Shared by the IP->hostname
// merge and the MAC-identity merge. Caller holds m.mu and guarantees
// oldID != newID and oldID != "".
func (m *Manager) mergeNodeInto(newID, oldID, hostname string) {
	if oldNode, exists := m.nodes[oldID]; exists {
		// Transfer data if new node doesn't exist yet
		if _, newExists := m.nodes[newID]; !newExists {
			m.nodes[newID] = oldNode
			m.nodes[newID].IP = newID // Update ID
			m.nodes[newID].Hostname = hostname
		} else {
			// Merge stats into existing node
			m.nodes[newID].PacketCount += oldNode.PacketCount
			m.nodes[newID].ByteCount += oldNode.ByteCount
			// Merge IPs using map for O(1) lookup instead of O(n²) nested loops
			existingIPs := make(map[string]bool, len(m.nodes[newID].IPs))
			for _, ip := range m.nodes[newID].IPs {
				existingIPs[ip] = true
			}
			for _, oldIP := range oldNode.IPs {
				if !existingIPs[oldIP] {
					m.nodes[newID].IPs = append(m.nodes[newID].IPs, oldIP)
				}
			}
			// Merge MACs the same way.
			existingMACs := make(map[string]bool, len(m.nodes[newID].MACs))
			for _, mc := range m.nodes[newID].MACs {
				existingMACs[mc] = true
			}
			for _, mc := range oldNode.MACs {
				if !existingMACs[mc] {
					m.nodes[newID].MACs = append(m.nodes[newID].MACs, mc)
				}
			}
		}
		// Delete old node
		delete(m.nodes, oldID)
	}

	// Update all edges that used the old node ID
	// Collect edges to update/merge to avoid modifying map during iteration
	edgesToDelete := make([]string, 0)
	edgesToAdd := make(map[string]*Edge)

	for edgeID, edge := range m.edges {
		updated := false
		newFrom := edge.From
		newTo := edge.To
		if edge.From == oldID {
			newFrom = newID
			updated = true
		}
		if edge.To == oldID {
			newTo = newID
			updated = true
		}
		if updated {
			// Skip self-loops that might be created by merging
			if newFrom == newTo {
				m.unindexEdgeLocked(edge)
				edgesToDelete = append(edgesToDelete, edgeID)
				continue
			}

			// Calculate new canonical edge ID
			newEdgeID, canonicalFrom, canonicalTo := getCanonicalEdgeID(newFrom, newTo)

			if newEdgeID != edgeID {
				// Unindex while the edge still carries its ORIGINAL id/endpoints
				// (the else branch below re-keys the struct in place).
				m.unindexEdgeLocked(edge)
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

	// Apply edge changes (already unindexed at decision time above)
	for _, edgeID := range edgesToDelete {
		delete(m.edges, edgeID)
	}
	for edgeID, edge := range edgesToAdd {
		m.edges[edgeID] = edge
		m.indexEdgeLocked(edge)
	}

	// Repoint any IP/MAC lookups from the deleted node to the surviving one so
	// later packets for those addresses resolve correctly (and don't try to
	// re-merge a node that no longer exists).
	for ip, id := range m.ipToNodeID {
		if id == oldID {
			m.ipToNodeID[ip] = newID
		}
	}
	for mc, id := range m.macToNodeID {
		if id == oldID {
			m.macToNodeID[mc] = newID
		}
	}
	if n := m.nodes[newID]; n != nil {
		rebuildSearchCorpusLocked(n)
	}
}

// isHostMAC reports whether mac is a stable per-host identity: a well-formed,
// unicast address that isn't broadcast or all-zero. Multicast/broadcast MACs
// (low bit of the first octet set) are destinations, not host identities, so
// they never anchor. Locally-administered MACs (VMs, containers) are allowed —
// they are legitimate host identities.
func isHostMAC(mac string) bool {
	if len(mac) < 17 { // "xx:xx:xx:xx:xx:xx"
		return false
	}
	hi, ok1 := hexNibble(mac[0])
	lo, ok2 := hexNibble(mac[1])
	if !ok1 || !ok2 {
		return false
	}
	first := hi<<4 | lo
	if first&0x01 != 0 { // multicast/broadcast (includes ff:ff:...)
		return false
	}
	if mac == "00:00:00:00:00:00" {
		return false
	}
	return true
}

func hexNibble(c byte) (int, bool) {
	switch {
	case c >= '0' && c <= '9':
		return int(c - '0'), true
	case c >= 'a' && c <= 'f':
		return int(c-'a') + 10, true
	case c >= 'A' && c <= 'F':
		return int(c-'A') + 10, true
	}
	return 0, false
}

func containsString(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

// recordMACLocked attaches mac to the node and, when safe, uses it as a stable
// identity anchor so a host keeps one node across IP changes (DHCP). It refuses
// to anchor a MAC that is seen on two distinct hosts concurrently (a gateway/NAT
// MAC forwarding many IPs), which would otherwise collapse unrelated hosts into
// one node. Caller holds m.mu.
func (m *Manager) recordMACLocked(nodeID, mac string) {
	if nodeID == "" || !isHostMAC(mac) {
		return
	}
	node, ok := m.nodes[nodeID]
	if !ok {
		return
	}
	// Always record the MAC on the node (display + eth.addr search), even for
	// shared MACs — only identity anchoring is withheld.
	if !containsString(node.MACs, mac) {
		node.MACs = append(node.MACs, mac)
		rebuildSearchCorpusLocked(node)
	}
	if m.macShared[mac] {
		return
	}

	anchorID, anchored := m.macToNodeID[mac]
	if !anchored {
		m.macToNodeID[mac] = nodeID
		// First exclusive host MAC: re-key the node so MAC is the stable id
		// (ultimate identity). Hostname/IPs remain attributes on the node.
		m.promoteNodeIDToMAC(nodeID, mac)
		return
	}
	if anchorID == nodeID {
		// Already anchored here — still promote if id is still an IP/hostname.
		m.promoteNodeIDToMAC(nodeID, mac)
		return
	}
	anchor, exists := m.nodes[anchorID]
	if !exists {
		// Previous anchor decayed away: treat this as the current holder.
		m.macToNodeID[mac] = nodeID
		m.promoteNodeIDToMAC(nodeID, mac)
		return
	}
	// Same MAC now appears on a different live node. If the previous anchor is
	// still recently active, two hosts use this MAC at once -> gateway/NAT, so
	// mark it shared and never anchor it again. If the previous anchor has gone
	// quiet, this is a re-addressing (DHCP) of the same host -> merge.
	if time.Since(anchor.LastSeen) < m.macActiveWindow {
		m.macShared[mac] = true
		delete(m.macToNodeID, mac)
		// If we already re-keyed the anchor to the MAC id, demote it back to an
		// IP key — a shared gateway MAC must not be any node's identity.
		m.demoteMACIdentity(mac, anchorID)
		return
	}
	m.mergeNodeInto(nodeID, anchorID, node.Hostname)
	m.macToNodeID[mac] = nodeID
	m.promoteNodeIDToMAC(nodeID, mac)
}

// promoteNodeIDToMAC re-keys a node so its map key / edge endpoints use the
// exclusive host MAC. Human-readable Hostname and multi-IP lists are preserved.
// No-op for groups, shared MACs, or nodes already keyed by this MAC.
func (m *Manager) promoteNodeIDToMAC(nodeID, mac string) {
	if nodeID == "" || mac == "" || nodeID == mac || m.macShared[mac] {
		return
	}
	if !isHostMAC(mac) {
		return
	}
	node, ok := m.nodes[nodeID]
	if !ok || node.IsGroup {
		return
	}
	// Already MAC-shaped id for a different MAC — leave alone.
	if isHostMAC(nodeID) {
		return
	}
	hostname := node.Hostname
	if hostname == "" || hostname == nodeID {
		for _, ip := range node.IPs {
			if _, g := groupAddressLabel(ip); !g {
				hostname = ip
				break
			}
		}
		if hostname == "" {
			hostname = nodeID
		}
	}
	// mergeNodeInto folds oldID into newID; creates newID from old when needed.
	m.mergeNodeInto(mac, nodeID, hostname)
	if n := m.nodes[mac]; n != nil {
		n.IP = mac
		if n.Hostname == "" || n.Hostname == mac {
			n.Hostname = hostname
		}
		rebuildSearchCorpusLocked(n)
	}
	m.macToNodeID[mac] = mac
	// Drop stale hostname map entry for the old id.
	if m.hostnameToNodeID[nodeID] == nodeID {
		delete(m.hostnameToNodeID, nodeID)
	}
	if hostname != "" && hostname != mac {
		m.hostnameToNodeID[hostname] = mac
	}
}

// demoteMACIdentity re-keys a node that was promoted to a MAC id back to a
// unicast IP id. Used when that MAC is later discovered to be a shared
// gateway/NAT address rather than a host identity.
func (m *Manager) demoteMACIdentity(mac, nodeID string) {
	if nodeID != mac {
		// Anchor may have been promoted after we captured nodeID; resolve live.
		if m.nodes[mac] != nil {
			nodeID = mac
		} else {
			return
		}
	}
	node := m.nodes[nodeID]
	if node == nil {
		return
	}
	newID := ""
	for _, ip := range node.IPs {
		if _, g := groupAddressLabel(ip); !g {
			newID = ip
			break
		}
	}
	if newID == "" || newID == nodeID {
		return
	}
	hostname := node.Hostname
	if hostname == "" || hostname == mac {
		hostname = newID
	}
	m.mergeNodeInto(newID, nodeID, hostname)
	if n := m.nodes[newID]; n != nil {
		n.IP = newID
		if n.Hostname == "" || n.Hostname == mac {
			n.Hostname = hostname
		}
		rebuildSearchCorpusLocked(n)
	}
}

// AddPortObservation records directional + port stats used for device-role
// classification. Called once per packet alongside AddOrUpdateNode/Edge (after
// them, so both nodes exist). A node serving a well-known (<1024) destination
// port looks like a server; high distinct-peer fan-out looks like a gateway.
func (m *Manager) AddPortObservation(srcIP, dstIP string, srcPort, dstPort uint16) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.addPortObservationLocked(srcIP, dstIP, srcPort, dstPort)
}

func (m *Manager) addPortObservationLocked(srcIP, dstIP string, srcPort, dstPort uint16) {
	srcID := m.ipToNodeID[srcIP]
	dstID := m.ipToNodeID[dstIP]
	src := m.nodes[srcID]
	dst := m.nodes[dstID]

	if src != nil {
		src.OutPackets++
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
	}
}

// addPeersLocked records the two endpoints of an edge as each other's peers.
// Lives on the edge path (not the port-observation path) so every ingest route
// — live packets, synthetic traffic, bulk loads — maintains the peer sets.
func (m *Manager) addPeersLocked(aID, bID string) {
	if aID == bID {
		return
	}
	a, b := m.nodes[aID], m.nodes[bID]
	if a == nil || b == nil {
		return
	}
	if a.Peers == nil {
		a.Peers = make(map[string]struct{})
	}
	a.Peers[bID] = struct{}{}
	if b.Peers == nil {
		b.Peers = make(map[string]struct{})
	}
	b.Peers[aID] = struct{}{}
}

// AddOrUpdateEdge adds a new edge or updates an existing one (bidirectional)
func (m *Manager) AddOrUpdateEdge(srcIP, dstIP string, protocol capture.Protocol, bytes int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.addOrUpdateEdgeLocked(srcIP, dstIP, protocol, bytes)
}

func (m *Manager) addOrUpdateEdgeLocked(srcIP, dstIP string, protocol capture.Protocol, bytes int) {
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

	m.addPeersLocked(canonicalFrom, canonicalTo)

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
		m.indexEdgeLocked(newEdge)
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
		if !protocol.Generic {
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
// work happens once rather than per client. Read-locked only: the damped role
// classification commits separately on a ~1s cadence (CommitRoles), so packet
// ingest never stalls behind the broadcast snapshot copy.
func (m *Manager) SnapshotRaw() RawSnapshot {
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
	return RawSnapshot{Nodes: nodes, Edges: edges}
}

// CommitRoles commits the damped role classification onto every node. The
// damping window is 2s, so a ~1s call cadence (hub tick) loses nothing; doing
// this inside SnapshotRaw forced a write lock on the broadcast hot path.
func (m *Manager) CommitRoles() {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now()
	for _, node := range m.nodes {
		commitRole(node, now)
	}
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

// MostRecentPacketForNode returns the newest buffered packet involving any IP of
// the given node, with its payload — used by the search click-through to open
// the packet inspector on a node's latest traffic instead of only the sidebar.
func (m *Manager) MostRecentPacketForNode(nodeID string) (PacketData, bool) {
	m.mu.RLock()
	ipSet := map[string]bool{nodeID: true}
	if node, ok := m.nodes[nodeID]; ok {
		for _, ip := range node.IPs {
			ipSet[ip] = true
		}
	}
	m.mu.RUnlock()
	return m.packetStore.MostRecentForIPs(ipSet)
}

// MostRecentPacketContaining returns the newest buffered packet whose payload
// contains text (case-insensitive). Ring-only; see PacketStore.MostRecentContaining.
func (m *Manager) MostRecentPacketContaining(text string) (PacketData, bool) {
	return m.packetStore.MostRecentContaining(text)
}

// SearchPayload scans the packet ring (newest first) for a case-insensitive
// payload substring. Ring-only: matches older than the buffer window are not
// found. This backs the live-mode "/" payload search, replacing the old
// client-side base64 scan of the browser's packet cache.
func (m *Manager) SearchPayload(text string, limit int) []PayloadMatch {
	return m.packetStore.SearchPayload(text, limit)
}

// PacketByID returns the buffered packet with the given ID, if still in the ring.
func (m *Manager) PacketByID(id int) (PacketData, bool) {
	return m.packetStore.GetByID(id)
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
	m.stampDeviceInfoLocked(pkt)
	m.mu.Unlock()
}

// stampDeviceInfoLocked applies LLDP/CDP device identity carried on a packet to
// its source node (already created earlier in the packet-processing order) for
// the hardware map. Caller holds m.mu.
func (m *Manager) stampDeviceInfoLocked(pkt *capture.PacketInfo) {
	if pkt.DeviceKind == "" {
		return
	}
	if id, ok := m.ipToNodeID[pkt.SrcIP]; ok {
		if n := m.nodes[id]; n != nil {
			n.DeviceKind = pkt.DeviceKind
			if pkt.DeviceInfo != "" {
				n.DeviceInfo = pkt.DeviceInfo
			}
		}
	}
}

// Ingest applies one packet's complete graph update — both endpoint nodes, the
// edge, port/peer observations, device identity, and the packet-store append —
// under a single acquisition of the manager lock. This is the hot ingest path:
// the discrete AddOrUpdateNode/AddOrUpdateEdge/AddPortObservation/AddPacket
// calls it replaces took the same write lock five times per packet.
func (m *Manager) Ingest(pkt *capture.PacketInfo, srcHostname, dstHostname string) {
	m.packetStore.AddPacket(pkt) // has its own lock

	m.mu.Lock()
	defer m.mu.Unlock()
	m.dirty = true
	m.addOrUpdateNodeLocked(pkt.SrcIP, srcHostname, pkt.Length)
	m.addOrUpdateNodeLocked(pkt.DstIP, dstHostname, pkt.Length)
	// Anchor host identity by MAC (DHCP re-addressing), after both nodes exist.
	// Any merge here re-keys edges, so it must run before the edge is added.
	if pkt.SrcMAC != "" {
		if id, ok := m.ipToNodeID[pkt.SrcIP]; ok {
			m.recordMACLocked(id, pkt.SrcMAC)
		}
	}
	if pkt.DstMAC != "" {
		if id, ok := m.ipToNodeID[pkt.DstIP]; ok {
			m.recordMACLocked(id, pkt.DstMAC)
		}
	}
	m.addOrUpdateEdgeLocked(pkt.SrcIP, pkt.DstIP, pkt.Protocol, pkt.Length)
	m.addPortObservationLocked(pkt.SrcIP, pkt.DstIP, pkt.SrcPort, pkt.DstPort)
	m.stampDeviceInfoLocked(pkt)
}

// RemoveStaleNodes removes nodes that haven't been seen recently, at most
// maxNodeRemovalsPerSweep per call, stalest first — see decay.go for why
// removal is staggered.
func (m *Manager) RemoveStaleNodes(threshold time.Duration) int {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now()

	// Collect stale candidates first to avoid modifying the map during
	// iteration, then take only the stalest few so one sweep can't mass-remove
	// a whole burst's worth of corpses at once.
	stale := make([]*Node, 0)
	for _, node := range m.nodes {
		if now.Sub(node.LastSeen) > threshold {
			stale = append(stale, node)
		}
	}
	sort.Slice(stale, func(i, j int) bool {
		if stale[i].LastSeen.Equal(stale[j].LastSeen) {
			return stale[i].IP < stale[j].IP // deterministic tie-break
		}
		return stale[i].LastSeen.Before(stale[j].LastSeen)
	})
	if len(stale) > maxNodeRemovalsPerSweep {
		stale = stale[:maxNodeRemovalsPerSweep]
	}

	if len(stale) > 0 {
		m.dirty = true
	}

	// Remove the selected stale nodes and clean up mappings
	for _, node := range stale {
		nodeID := node.IP
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
		// Drop any MAC anchors pointing at this node.
		for _, mac := range node.MACs {
			if m.macToNodeID[mac] == nodeID {
				delete(m.macToNodeID, mac)
			}
		}
		delete(m.nodes, nodeID)
	}

	return len(stale)
}

// RemoveStaleEdges removes edges that haven't been seen recently, at most
// maxEdgeRemovalsPerSweep per call, stalest first — see decay.go for why
// removal is staggered.
func (m *Manager) RemoveStaleEdges(threshold time.Duration) int {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now()

	// Collect stale candidates first, then cap the sweep stalest-first (same
	// staggering as RemoveStaleNodes).
	stale := make([]*Edge, 0)
	for _, edge := range m.edges {
		if now.Sub(edge.LastSeen) > threshold {
			stale = append(stale, edge)
		}
	}
	sort.Slice(stale, func(i, j int) bool {
		if stale[i].LastSeen.Equal(stale[j].LastSeen) {
			return stale[i].ID < stale[j].ID // deterministic tie-break
		}
		return stale[i].LastSeen.Before(stale[j].LastSeen)
	})
	if len(stale) > maxEdgeRemovalsPerSweep {
		stale = stale[:maxEdgeRemovalsPerSweep]
	}

	if len(stale) > 0 {
		m.dirty = true
	}

	// Remove the selected stale edges
	for _, edge := range stale {
		m.unindexEdgeLocked(edge)
		delete(m.edges, edge.ID)
	}

	return len(stale)
}

// NodeDetail is the full lazily-fetched record for one node (Phase 5): the
// fields stripped from the streamed ViewNode plus a connection summary. Served
// by GET /api/node?id=. MAC is the hardware identity when known; a node may
// hold many IPs/names (multi-homed hosts, k8s nodes, DHCP renames).
type NodeDetail struct {
	ID          string           `json:"id"`
	Label       string           `json:"label"`
	IPs         []string         `json:"ips,omitempty"`
	MACs        []string         `json:"macs,omitempty"`
	PrimaryMAC  string           `json:"primaryMac,omitempty"` // exclusive host MAC when known
	Role        string           `json:"role,omitempty"`
	Icon        string           `json:"icon,omitempty"`
	DeviceInfo  string           `json:"deviceInfo,omitempty"`
	Vendor      string           `json:"vendor,omitempty"`      // IEEE OUI org for the primary MAC
	DeviceClass string           `json:"deviceClass,omitempty"` // coarse device category from the vendor
	PacketCount int              `json:"packetCount"`
	ByteCount   int64            `json:"byteCount"`
	IsGroup     bool             `json:"isGroup,omitempty"`
	LastSeen    time.Time        `json:"lastSeen"`
	Peers       int              `json:"peers"` // distinct peer count (full graph)
	Edges       []NodeDetailEdge `json:"edges,omitempty"`
	// Tooltip is the preformatted hover tooltip; the client renders it
	// verbatim instead of re-deriving it from the individual fields.
	Tooltip string `json:"tooltip,omitempty"`
}

// NodeDetailEdge summarizes one connection of a node for the detail panel.
type NodeDetailEdge struct {
	Peer        string `json:"peer"`
	Protocol    string `json:"protocol"`
	Color       string `json:"color"`
	PacketCount int    `json:"packetCount"`
	ByteCount   int64  `json:"byteCount"`
	Outbound    bool   `json:"outbound"` // this node is the edge's From
}

// GetNodeDetail returns the full record for one node, or false when unknown.
// Edge summaries are capped so a datacenter hub doesn't return megabytes.
// Also resolves lookup by any known IP or MAC alias of the node.
func (m *Manager) GetNodeDetail(id string) (NodeDetail, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	n, ok := m.nodes[id]
	if !ok {
		// Resolve IP or MAC aliases to the canonical node id.
		if nid, ok2 := m.ipToNodeID[id]; ok2 {
			n, ok = m.nodes[nid]
			id = nid
		} else if nid, ok2 := m.macToNodeID[id]; ok2 {
			n, ok = m.nodes[nid]
			id = nid
		}
	}
	if !ok || n == nil {
		return NodeDetail{}, false
	}
	role, icon := classifyNode(n)
	label := n.Hostname
	if label == "" {
		label = id
	}
	primaryMAC := ""
	if len(n.MACs) > 0 {
		primaryMAC = n.MACs[0]
	}
	// Prefer exclusive MAC identity when this node is the live anchor.
	for _, mc := range n.MACs {
		if m.macToNodeID[mc] == id && !m.macShared[mc] {
			primaryMAC = mc
			break
		}
	}
	// Identify the maker (and a coarse device category) from the primary MAC's
	// IEEE OUI. Only meaningful for real Ethernet hosts, not group/MAC-less nodes.
	vendor, deviceClass := capture.IdentifyMAC(primaryMAC)
	d := NodeDetail{
		ID:          id,
		Label:       label,
		IPs:         append([]string(nil), n.IPs...),
		MACs:        append([]string(nil), n.MACs...),
		PrimaryMAC:  primaryMAC,
		Role:        role,
		Icon:        icon,
		DeviceInfo:  n.DeviceInfo,
		Vendor:      vendor,
		DeviceClass: deviceClass,
		PacketCount: n.PacketCount,
		ByteCount:   n.ByteCount,
		IsGroup:     n.IsGroup,
		LastSeen:    n.LastSeen,
		Peers:       len(n.Peers),
	}
	const maxDetailEdges = 100
	// Adjacency index lookup: O(degree), not a full edge scan.
	for edgeID := range m.edgesByNode[id] {
		e := m.edges[edgeID]
		if e == nil {
			continue
		}
		peer := e.To
		out := true
		if e.To == id {
			peer = e.From
			out = false
		}
		d.Edges = append(d.Edges, NodeDetailEdge{
			Peer:        peer,
			Protocol:    e.Protocol.Name,
			Color:       e.Protocol.Color,
			PacketCount: e.PacketCount,
			ByteCount:   e.ByteCount,
			Outbound:    out,
		})
	}
	// Sort BEFORE capping so a >100-edge hub returns its busiest connections,
	// not an arbitrary map-order subset.
	sort.Slice(d.Edges, func(a, b int) bool { return d.Edges[a].PacketCount > d.Edges[b].PacketCount })
	if len(d.Edges) > maxDetailEdges {
		d.Edges = d.Edges[:maxDetailEdges]
	}
	d.Tooltip = nodeTooltip(d)
	return d, true
}

// SearchResult is one match from SearchNodes (Phase 5 server-side search over
// the WHOLE graph, not just a client's rendered view).
type SearchResult struct {
	ID          string   `json:"id"`
	Label       string   `json:"label"`
	IPs         []string `json:"ips,omitempty"`
	PacketCount int      `json:"packetCount"`
	ByteCount   int64    `json:"byteCount"`
	Subnet24    string   `json:"subnet24,omitempty"` // CIDR chain for un-collapsing
	Subnet16    string   `json:"subnet16,omitempty"`
}

// SearchNodes returns up to limit nodes whose ID, hostname or any IP contains
// the query (case-insensitive), busiest first.
func (m *Manager) SearchNodes(query string, limit int) []SearchResult {
	q := strings.ToLower(strings.TrimSpace(query))
	if q == "" {
		return nil
	}
	if limit <= 0 {
		limit = 20
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	var out []SearchResult
	for id, n := range m.nodes {
		// searchCorpus is the precomputed lowercase haystack (id + hostname +
		// IPs + MACs), maintained at identity changes — no per-request ToLower.
		// Fall back to the id for nodes that predate the corpus (defensive).
		corpus := n.searchCorpus
		if corpus == "" {
			corpus = strings.ToLower(id)
		}
		if !strings.Contains(corpus, q) {
			continue
		}
		r := SearchResult{
			ID:          id,
			Label:       n.Hostname,
			IPs:         append([]string(nil), n.IPs...),
			PacketCount: n.PacketCount,
			ByteCount:   n.ByteCount,
		}
		if s := primarySubnet24(*n); s != "" {
			r.Subnet24 = s + ".0/24"
			if dot := strings.LastIndexByte(s, '.'); dot > 0 {
				r.Subnet16 = s[:dot] + ".0.0/16"
			}
		}
		out = append(out, r)
	}
	sort.Slice(out, func(a, b int) bool {
		if out[a].PacketCount != out[b].PacketCount {
			return out[a].PacketCount > out[b].PacketCount
		}
		return out[a].ID < out[b].ID
	})
	if len(out) > limit {
		out = out[:limit]
	}
	return out
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
	m.edgesByNode = make(map[string]map[string]bool)
	m.ipToNodeID = make(map[string]string)
	m.hostnameToNodeID = make(map[string]string)
	m.packetStore = NewPacketStore(1000)
	m.recentFlows = make(map[flowKey]*TrafficFlow)
	m.dirty = true
}

// BulkNode / BulkEdge are pre-aggregated rows from the persistence layer
// (store package), replayed into the graph in one shot on a pcap cache hit.
// IDs are raw endpoint ids as captured; BulkLoad re-runs the same hostname
// merging and group classification the packet path would have.
type BulkNode struct {
	ID          string
	Hostname    string
	PacketCount int64
	ByteCount   int64
}

type BulkEdge struct {
	From, To       string
	Protocol       string // protocol name; resolved against capture.GetAllProtocols
	PacketCount    int64
	ByteCount      int64
	ForwardPackets int64
	ReversePackets int64
	ForwardBytes   int64
	ReverseBytes   int64
}

// BulkLoad populates the graph from stored aggregates. Nodes route through
// AddOrUpdateNode so IP->hostname merging and group labels behave exactly as
// on the packet path; counters are then overwritten with the stored totals
// (AddOrUpdateNode counted a fake packet per row). LastSeen is "now", matching
// what a cold replay run would produce when it loads a file at startup.
func (m *Manager) BulkLoad(nodes []BulkNode, edges []BulkEdge) {
	for _, n := range nodes {
		m.AddOrUpdateNode(n.ID, n.Hostname, 0)
	}

	protoByName := make(map[string]capture.Protocol)
	for _, p := range capture.GetAllProtocols() {
		protoByName[p.Name] = p
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	m.dirty = true

	// Overwrite counters. Several raw IPs may have merged into one node, so
	// zero each target once, then accumulate.
	zeroed := make(map[string]bool, len(nodes))
	for _, n := range nodes {
		id, ok := m.ipToNodeID[n.ID]
		if !ok {
			id = n.ID
		}
		node := m.nodes[id]
		if node == nil {
			continue
		}
		if !zeroed[id] {
			node.PacketCount = 0
			node.ByteCount = 0
			zeroed[id] = true
		}
		node.PacketCount += int(n.PacketCount)
		node.ByteCount += n.ByteCount
	}

	for _, e := range edges {
		// A genuine self-loop (src==dst in the capture) is kept — the packet
		// path creates those too. One that only appears after IP->hostname
		// mapping is a merge artifact, which the packet path deletes.
		genuineSelfLoop := e.From == e.To
		from, to := e.From, e.To
		if id, ok := m.ipToNodeID[from]; ok {
			from = id
		}
		if id, ok := m.ipToNodeID[to]; ok {
			to = id
		}
		if from == to && !genuineSelfLoop {
			continue
		}
		proto, ok := protoByName[e.Protocol]
		if !ok {
			proto = capture.Protocol{Name: e.Protocol, Color: "#95a5a6", Layer: capture.LayerTransport, LayerNum: 4}
		}
		edgeID, canonicalFrom, canonicalTo := getCanonicalEdgeID(from, to)
		// Derive peer sets from the edges (stored aggregates have no per-packet
		// data) or GetNodeDetail would report 0 peers for loaded graphs.
		m.addPeersLocked(canonicalFrom, canonicalTo)
		// Stored fwd/rev are relative to the stored canonical order; if merging
		// flipped the endpoints, swap the directional splits to match.
		fwdP, revP, fwdB, revB := e.ForwardPackets, e.ReversePackets, e.ForwardBytes, e.ReverseBytes
		if canonicalFrom != from {
			fwdP, revP, fwdB, revB = revP, fwdP, revB, fwdB
		}
		if edge, exists := m.edges[edgeID]; exists {
			edge.PacketCount += int(e.PacketCount)
			edge.ByteCount += e.ByteCount
			edge.ForwardPackets += int(fwdP)
			edge.ReversePackets += int(revP)
			edge.ForwardBytes += fwdB
			edge.ReverseBytes += revB
			edge.LastSeen = time.Now()
			if !proto.Generic {
				edge.Protocol = proto
			}
		} else {
			newEdge := &Edge{
				ID:             edgeID,
				From:           canonicalFrom,
				To:             canonicalTo,
				Protocol:       proto,
				PacketCount:    int(e.PacketCount),
				ByteCount:      e.ByteCount,
				LastSeen:       time.Now(),
				ForwardPackets: int(fwdP),
				ReversePackets: int(revP),
				ForwardBytes:   fwdB,
				ReverseBytes:   revB,
			}
			m.edges[edgeID] = newEdge
			m.indexEdgeLocked(newEdge)
		}
		m.protoCounts[e.Protocol] += int(e.PacketCount)
	}
}
