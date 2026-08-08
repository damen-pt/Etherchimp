package graph

import (
	"fmt"
	"net"
)

// roleNames maps a classified role to its display name. Keep in sync with
// ROLE_NAME in static/app.js.
var roleNames = map[string]string{
	"server":    "Server",
	"client":    "Client",
	"router":    "Router",
	"switch":    "Switch",
	"gateway":   "Gateway",
	"iot":       "IoT",
	"multicast": "Multicast/Broadcast",
	"unknown":   "Unknown",
}

// formatByteCount renders bytes as B/KB/MB/GB (mirrors formatBytes in app.js).
func formatByteCount(b int64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	v := float64(b)
	for _, suffix := range []string{"KB", "MB", "GB", "TB"} {
		v /= unit
		if v < unit {
			return fmt.Sprintf("%.1f %s", v, suffix)
		}
	}
	return fmt.Sprintf("%.1f PB", v)
}

// nodeTooltip builds the preformatted hover tooltip for a node detail,
// mirroring formatNodeTooltip in static/app.js (host-node branch; subnet/tail
// variants are view constructs the detail endpoint never describes).
func nodeTooltip(d NodeDetail) string {
	t := ""
	if d.IsGroup {
		t += "⚲ Multicast/broadcast group (not a host)\n"
	}
	if d.Role != "" && d.Role != "unknown" && !d.IsGroup {
		name := roleNames[d.Role]
		if name == "" {
			name = d.Role
		}
		t += "Role: " + name + "\n"
	}
	if d.DeviceInfo != "" {
		t += "Link: " + d.DeviceInfo + "\n"
	}
	if d.Vendor != "" {
		t += "Device: " + d.Vendor
		if d.DeviceClass != "" {
			t += " · " + d.DeviceClass
		}
		t += "\n"
	} else if d.DeviceClass != "" {
		t += "Device: " + d.DeviceClass + "\n"
	}
	if d.Label != "" && d.Label != d.ID {
		t += "Hostname: " + d.Label + "\n"
	}
	if len(d.IPs) == 1 {
		t += "IP: " + d.IPs[0] + "\n"
	} else if len(d.IPs) > 1 {
		t += "IPs:\n"
		for _, ip := range d.IPs {
			t += "  " + ip + "\n"
		}
	} else if net.ParseIP(d.ID) != nil {
		t += "IP: " + d.ID + "\n"
	}
	t += fmt.Sprintf("Packets: %d\nBytes: %s", d.PacketCount, formatByteCount(d.ByteCount))
	return t
}
