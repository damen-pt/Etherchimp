package graph

import "time"

// classify.go assigns each node a coarse device role from the traffic stats
// collected in AddPortObservation. The heuristics are deliberately conservative
// (default to "client"/"unknown"); users can override a wrong guess via the
// Phase D customization. classifyNode is pure; the damped commit of its result
// (commitRole) runs in SnapshotRaw under the manager write lock.

// roleIcons maps a role to the icon name the client renders. Keep in sync with
// the ROLE_GLYPH table in static/app.js.
var roleIcons = map[string]string{
	"server":    "server",
	"client":    "client",
	"router":    "router",
	"switch":    "switch",
	"gateway":   "gateway",
	"iot":       "iot",
	"multicast": "multicast",
	"unknown":   "unknown",
}

// Fan-out threshold above which a node looks like a gateway/router rather than a
// busy server (it talks to many distinct peers).
const gatewayFanout = 16

// classifyNode returns (role, icon) for a node based on its observed stats.
func classifyNode(n *Node) (string, string) {
	// LLDP/CDP discovery is authoritative: if the device advertised itself as a
	// switch or router, use that over any traffic-based guess.
	if n.DeviceKind == "switch" || n.DeviceKind == "router" {
		return n.DeviceKind, roleIcons[n.DeviceKind]
	}

	role := "unknown"
	total := n.InPackets + n.OutPackets

	switch {
	case n.IsGroup:
		// Multicast/broadcast rendezvous points are not real hosts.
		role = "multicast"
	case len(n.Peers) >= gatewayFanout:
		// Talks to many distinct peers — a routing/gateway hub.
		role = "gateway"
	case len(n.ListenPorts) > 0 && n.InPackets >= n.OutPackets:
		// Receives connections on well-known ports: it offers services.
		role = "server"
	case len(n.Peers) == 1 && len(n.ListenPorts) == 0 && total > 0:
		// Talks to exactly one endpoint and serves nothing — sensor/IoT-like.
		role = "iot"
	case total > 0:
		role = "client"
	}
	return role, roleIcons[role]
}

// roleFlipDamping is how long a candidate role must persist before it replaces
// a node's committed role. During a port scan, fan-out flips the scanner to
// "gateway" and scanned hosts flip "client"->"server" within seconds; without
// damping every flip ships a style delta exactly when the system is busiest.
// Roles still flip — just once, ~2s late, instead of flickering.
const roleFlipDamping = 2 * time.Second

// commitRole applies flip damping and commits the node's Role/Icon in place.
// Caller holds the manager write lock (SnapshotRaw). A first-time
// classification commits immediately — damping applies to flips only, not to a
// node's birth. A candidate role different from the committed one is held in
// n.pendingRole until it has persisted for roleFlipDamping; if the
// classification flickers back to the committed role within the window, the
// pending flip is dropped and never becomes visible.
func commitRole(n *Node, now time.Time) {
	role, icon := classifyNode(n)

	if n.Role == "" || role == n.Role {
		// Birth (no committed role yet) or steady state: commit now and drop
		// any pending flip.
		n.Role, n.Icon = role, icon
		n.pendingRole = ""
		n.pendingSince = time.Time{}
		return
	}

	if n.pendingRole != role {
		// New candidate: (re)start the persistence window.
		n.pendingRole = role
		n.pendingSince = now
		return
	}

	if now.Sub(n.pendingSince) >= roleFlipDamping {
		n.Role, n.Icon = role, icon
		n.pendingRole = ""
		n.pendingSince = time.Time{}
	}
}
