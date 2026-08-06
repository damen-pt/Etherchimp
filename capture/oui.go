package capture

import (
	_ "embed"
	"strings"
	"sync"
)

// oui_data.tsv is the IEEE MA-L (OUI) registry, slimmed to "PREFIX<TAB>Vendor"
// lines (one per 24-bit assignment) from the public ieee.org oui.txt. It lets us
// name the maker of any device from its MAC's first three bytes, and from there
// guess a coarse device category — the "what is this box" identification the
// graph shows next to a host.
//
//go:embed oui_data.tsv
var ouiData string

var (
	ouiOnce sync.Once
	ouiMap  map[string]string
)

func loadOUI() {
	ouiMap = make(map[string]string, 40000)
	for len(ouiData) > 0 {
		nl := strings.IndexByte(ouiData, '\n')
		var line string
		if nl < 0 {
			line, ouiData = ouiData, ""
		} else {
			line, ouiData = ouiData[:nl], ouiData[nl+1:]
		}
		tab := strings.IndexByte(line, '\t')
		if tab != 6 { // every prefix is exactly 6 hex chars
			continue
		}
		ouiMap[line[:tab]] = line[tab+1:]
	}
	ouiData = "" // release the embedded blob once parsed
}

// ouiPrefix normalizes a MAC to its 6-hex-char OUI (uppercase), accepting
// colon/dash/dot-separated or bare forms. Returns "" if it can't read 3 octets.
func ouiPrefix(mac string) string {
	var sb strings.Builder
	sb.Grow(6)
	for i := 0; i < len(mac) && sb.Len() < 6; i++ {
		c := mac[i]
		switch {
		case c >= '0' && c <= '9', c >= 'A' && c <= 'F':
			sb.WriteByte(c)
		case c >= 'a' && c <= 'f':
			sb.WriteByte(c - ('a' - 'A'))
		}
	}
	if sb.Len() < 6 {
		return ""
	}
	return sb.String()
}

// isLocallyAdministered reports whether a MAC's first octet has the
// locally-administered bit (0x02) set — the marker for randomized/private MACs
// used by phones and VMs, which are never in the IEEE registry.
func isLocallyAdministered(mac string) bool {
	p := ouiPrefix(mac)
	if len(p) < 2 {
		return false
	}
	var b byte
	for i := 0; i < 2; i++ {
		b <<= 4
		c := p[i]
		switch {
		case c >= '0' && c <= '9':
			b |= c - '0'
		case c >= 'A' && c <= 'F':
			b |= c - 'A' + 10
		}
	}
	return b&0x02 != 0
}

// VendorForMAC returns the IEEE-registered organization for a MAC's OUI, or ""
// when the MAC is malformed, randomized/locally-administered, or unregistered.
func VendorForMAC(mac string) string {
	prefix := ouiPrefix(mac)
	if prefix == "" {
		return ""
	}
	ouiOnce.Do(loadOUI)
	return ouiMap[prefix]
}

// IdentifyMAC returns the vendor and a coarse device category for a MAC. The
// category is a best-effort hint derived from the vendor name (a maker sells
// many product lines), strongest for industrial and networking vendors. Either
// field may be "" — a randomized MAC yields ("", "Private/randomized MAC").
func IdentifyMAC(mac string) (vendor, class string) {
	vendor = VendorForMAC(mac)
	if vendor == "" {
		if isLocallyAdministered(mac) {
			return "", "Private/randomized MAC"
		}
		return "", ""
	}
	return vendor, DeviceClassForVendor(vendor)
}

// vendorClass pairs a lowercase substring of a registered org name with the
// device category it implies. Order matters: the first match wins, so put the
// most specific / strongest signals first (industrial before generic computer).
type vendorClass struct {
	needle string
	class  string
}

// deviceClassRules classifies a vendor by substring. Not exhaustive and
// deliberately conservative — an unmatched vendor still shows its name, just
// without a category. Categories mirror the kinds of gear these makers ship.
var deviceClassRules = []vendorClass{
	// OT / ICS / SCADA — PLCs, RTUs, drives, industrial switches
	{"rockwell", "PLC / ICS"}, {"allen-bradley", "PLC / ICS"}, {"allen bradley", "PLC / ICS"},
	{"schneider", "PLC / ICS"}, {"siemens", "PLC / ICS"}, {"phoenix contact", "PLC / ICS"},
	{"beckhoff", "PLC / ICS"}, {"omron", "PLC / ICS"}, {"mitsubishi electric", "PLC / ICS"},
	{"yokogawa", "PLC / ICS"}, {"yaskawa", "PLC / ICS"}, {"wago", "PLC / ICS"},
	{"b&r industrial", "PLC / ICS"}, {"bachmann", "PLC / ICS"}, {"pilz", "PLC / ICS"},
	{"opto 22", "PLC / ICS"}, {"red lion", "PLC / ICS"}, {"turck", "PLC / ICS"},
	{"pepperl", "PLC / ICS"}, {"endress", "PLC / ICS"}, {"sick ag", "PLC / ICS"},
	{"fanuc", "PLC / ICS"}, {"kuka", "PLC / ICS"}, {"emerson", "PLC / ICS"},
	{"rockwell automation", "PLC / ICS"}, {"hms industrial", "PLC / ICS"},
	{"honeywell", "PLC / ICS"}, {"abb", "PLC / ICS"}, {"delta electronics", "PLC / ICS"},
	// Industrial networking gear (ruggedized switches/gateways)
	{"moxa", "Industrial network"}, {"hirschmann", "Industrial network"},
	{"advantech", "Industrial network"}, {"westermo", "Industrial network"},
	// IP cameras / NVR
	{"hikvision", "IP camera"}, {"dahua", "IP camera"}, {"axis communications", "IP camera"},
	{"hanwha", "IP camera"}, {"amcrest", "IP camera"}, {"reolink", "IP camera"},
	{"wyze", "IP camera"},
	// VoIP phones
	{"polycom", "VoIP phone"}, {"yealink", "VoIP phone"}, {"grandstream", "VoIP phone"},
	{"avaya", "VoIP phone"}, {"snom", "VoIP phone"},
	// Printers / MFPs
	{"brother", "Printer"}, {"canon", "Printer"}, {"seiko epson", "Printer"},
	{"lexmark", "Printer"}, {"xerox", "Printer"}, {"kyocera", "Printer"},
	{"ricoh", "Printer"}, {"zebra tech", "Printer"},
	// Networking (routers / switches / APs / gateways)
	{"cisco-linksys", "Network gear"}, {"linksys", "Network gear"}, {"netgear", "Network gear"},
	{"tp-link", "Network gear"}, {"d-link", "Network gear"}, {"ubiquiti", "Network gear"},
	{"mikrotik", "Network gear"}, {"aruba", "Network gear"}, {"juniper", "Network gear"},
	{"ruckus", "Network gear"}, {"zyxel", "Network gear"}, {"arris", "Network gear"},
	{"technicolor", "Network gear"}, {"sagemcom", "Network gear"}, {"actiontec", "Network gear"},
	{"fortinet", "Network gear"}, {"palo alto", "Network gear"}, {"extreme networks", "Network gear"},
	{"meraki", "Network gear"}, {"cisco", "Network gear"},
	// Virtualization / hypervisor NICs
	{"vmware", "Virtual machine"}, {"xensource", "Virtual machine"}, {"parallels", "Virtual machine"},
	{"proxmox", "Virtual machine"}, {"nutanix", "Virtual machine"}, {"openstack", "Virtual machine"},
	// TVs / streaming / media
	{"lg electronics", "TV / media"}, {"vizio", "TV / media"}, {"roku", "TV / media"},
	{"tcl", "TV / media"}, {"hisense", "TV / media"}, {"sonos", "TV / media"},
	{"sony", "TV / media"}, {"sharp", "TV / media"},
	// IoT / embedded modules
	{"espressif", "IoT / embedded"}, {"raspberry pi", "IoT / embedded"},
	{"nordic semiconductor", "IoT / embedded"}, {"texas instruments", "IoT / embedded"},
	{"tuya", "IoT / embedded"}, {"nest labs", "IoT / embedded"}, {"ring", "IoT / embedded"},
	{"ecobee", "IoT / embedded"}, {"particle", "IoT / embedded"},
	// General computers / phones (broadest — keep last)
	{"apple", "Computer / mobile"}, {"dell", "Computer / mobile"}, {"lenovo", "Computer / mobile"},
	{"hewlett packard", "Computer / mobile"}, {"hp inc", "Computer / mobile"},
	{"intel corporate", "Computer / mobile"}, {"micro-star", "Computer / mobile"},
	{"asustek", "Computer / mobile"}, {"acer", "Computer / mobile"}, {"microsoft", "Computer / mobile"},
	{"samsung", "Computer / mobile"}, {"google", "Computer / mobile"}, {"amazon", "Computer / mobile"},
	{"xiaomi", "Computer / mobile"}, {"huawei", "Computer / mobile"},
}

// DeviceClassForVendor maps a registered vendor name to a coarse device category
// via substring rules, or "" when nothing matches confidently.
func DeviceClassForVendor(vendor string) string {
	v := strings.ToLower(vendor)
	for _, r := range deviceClassRules {
		if strings.Contains(v, r.needle) {
			return r.class
		}
	}
	return ""
}
