package graph

// classify.go assigns each node a coarse device role from the traffic stats
// collected in AddPortObservation. The heuristics are deliberately conservative
// (default to "client"/"unknown"); users can override a wrong guess via the
// Phase D customization. classifyNode runs under the manager read lock.

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
