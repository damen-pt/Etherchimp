package capture

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strconv"
	"sync"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// OSI layer labels used for grouping protocols in the UI.
const (
	LayerDataLink    = "L2 · Data Link"
	LayerNetwork     = "L3 · Network"
	LayerTransport   = "L4 · Transport"
	LayerApplication = "L7 · Application"
	LayerOT          = "OT · Industrial"
	LayerUnknown     = "— · Unknown"
)

// defaultColor is assigned to catalog protocols with an empty color.
const defaultColor = "#95a5a6"

//go:embed protocols.json
var defaultProtocolsJSON []byte

// DefaultProtocolsJSON returns the embedded default protocol catalog, so the
// caller can materialize an editable copy on disk.
func DefaultProtocolsJSON() []byte { return defaultProtocolsJSON }

// Protocol represents a detected network protocol with its display properties.
// Layer/LayerNum carry the correlative OSI layer so the UI can group protocols.
// Discovery marks broadcast/multicast topology & service-discovery protocols
// (mDNS, SSDP, LLDP, …) so the capture pipeline keeps them instead of
// filtering them out as ordinary multicast noise.
//
// The remaining flags replace name-string special cases in the pipeline:
// Generic marks the bare transports (TCP/UDP) that always lose to a more
// specific protocol; Decap marks overlay encapsulations (VXLAN/Geneve) whose
// inner packet is processed instead; L2Endpoints marks link-layer protocols
// (LLDP/CDP) that advertise neighbour identity TLVs; DefaultVisible marks the
// "general" protocols shown to a freshly connected client.
type Protocol struct {
	Name           string `json:"Name"`
	Color          string `json:"Color"`
	Layer          string `json:"Layer"`
	LayerNum       int    `json:"LayerNum"`
	Discovery      bool   `json:"Discovery,omitempty"`
	Generic        bool   `json:"generic,omitempty"`
	Decap          bool   `json:"decap,omitempty"`
	L2Endpoints    bool   `json:"l2Endpoints,omitempty"`
	DefaultVisible bool   `json:"defaultVisible,omitempty"`
}

// Registry is the active protocol catalog: the ordered protocol list, the
// name index, and the port tables used for detection and service labels.
type Registry struct {
	All       []Protocol
	ByName    map[string]Protocol
	TCPPorts  map[uint16]string
	UDPPorts  map[uint16]string
	WellKnown map[uint16]string
}

// protocolsFile mirrors the protocols.json schema. Port keys are strings
// (JSON object keys) mapping to protocol names; wellKnownPorts maps to a
// free-form service label.
type protocolsFile struct {
	Protocols      []Protocol        `json:"protocols"`
	TCPPorts       map[string]string `json:"tcpPorts"`
	UDPPorts       map[string]string `json:"udpPorts"`
	WellKnownPorts map[string]string `json:"wellKnownPorts"`
}

var (
	registryMu sync.RWMutex
	registry   *Registry
)

func init() {
	reg, err := parseProtocols(defaultProtocolsJSON)
	if err != nil {
		// The embedded catalog is compiled in, so this can only fail if it was
		// corrupted at build time; fall back to an empty registry rather than
		// panicking.
		log.Printf("capture: embedded protocols.json failed to parse: %v", err)
		reg = &Registry{
			ByName:    make(map[string]Protocol),
			TCPPorts:  make(map[uint16]string),
			UDPPorts:  make(map[uint16]string),
			WellKnown: make(map[uint16]string),
		}
	}
	registry = reg
	populateProtocolVars(reg)
}

// parseProtocols decodes a catalog and builds a Registry. Validation is
// lenient: protocols with an empty color get a default, and port entries that
// are not numbers or that reference unknown protocol names are skipped with a
// log warning. Malformed JSON returns an error.
func parseProtocols(data []byte) (*Registry, error) {
	var f protocolsFile
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, fmt.Errorf("invalid protocols JSON: %v", err)
	}

	reg := &Registry{
		ByName:    make(map[string]Protocol, len(f.Protocols)),
		TCPPorts:  make(map[uint16]string, len(f.TCPPorts)),
		UDPPorts:  make(map[uint16]string, len(f.UDPPorts)),
		WellKnown: make(map[uint16]string, len(f.WellKnownPorts)),
	}
	for _, p := range f.Protocols {
		if p.Name == "" {
			log.Printf("capture: protocols catalog: skipping entry with empty name")
			continue
		}
		if p.Color == "" {
			p.Color = defaultColor
		}
		reg.All = append(reg.All, p)
		reg.ByName[p.Name] = p
	}

	parsePortMap := func(src map[string]string, validateName bool, dst map[uint16]string, what string) {
		for k, v := range src {
			port, err := strconv.Atoi(k)
			if err != nil || port < 0 || port > 65535 {
				log.Printf("capture: protocols catalog: skipping %s entry with invalid port %q", what, k)
				continue
			}
			if validateName {
				if _, ok := reg.ByName[v]; !ok {
					log.Printf("capture: protocols catalog: skipping %s %d -> %q: unknown protocol", what, port, v)
					continue
				}
			}
			dst[uint16(port)] = v
		}
	}
	parsePortMap(f.TCPPorts, true, reg.TCPPorts, "tcpPorts")
	parsePortMap(f.UDPPorts, true, reg.UDPPorts, "udpPorts")
	parsePortMap(f.WellKnownPorts, false, reg.WellKnown, "wellKnownPorts")

	return reg, nil
}

// loadProtocols parses catalog bytes and atomically replaces the global
// registry. On a parse error the current registry is left untouched.
func loadProtocols(data []byte) error {
	reg, err := parseProtocols(data)
	if err != nil {
		return err
	}
	registryMu.Lock()
	registry = reg
	registryMu.Unlock()
	return nil
}

// LoadProtocols reads a protocol catalog JSON file and replaces the global
// registry. On error (unreadable file or malformed JSON) the current registry
// is left untouched and the caller should fall back to the embedded defaults.
func LoadProtocols(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return loadProtocols(data)
}

// currentRegistry returns the active catalog (never nil).
func currentRegistry() *Registry {
	registryMu.RLock()
	defer registryMu.RUnlock()
	return registry
}

// ByName returns the catalog protocol with the given name.
func ByName(name string) (Protocol, bool) {
	p, ok := currentRegistry().ByName[name]
	return p, ok
}

// IsGenericName reports whether name is one of the generic transport protocols
// (TCP/UDP) in the active catalog. Unknown names are not generic — matching
// the old `name != "TCP" && name != "UDP"` sentinel rule.
func IsGenericName(name string) bool {
	p, ok := currentRegistry().ByName[name]
	return ok && p.Generic
}

// Protocol color scheme. These exported variables are populated from the
// embedded protocols.json at init (they are used by main.go's synth harness
// and by tests); the literals are the fallback should the embedded catalog
// ever drop an entry.
var (
	// Transport (L4)
	ProtocolTCP = Protocol{Name: "TCP", Color: "#3498db", Layer: LayerTransport, LayerNum: 4, Generic: true, DefaultVisible: true}
	ProtocolUDP = Protocol{Name: "UDP", Color: "#2ecc71", Layer: LayerTransport, LayerNum: 4, Generic: true, DefaultVisible: true}

	// Network (L3)
	ProtocolICMP = Protocol{Name: "ICMP", Color: "#f39c12", Layer: LayerNetwork, LayerNum: 3, DefaultVisible: true}
	ProtocolIPv6 = Protocol{Name: "IPv6", Color: "#7f8c8d", Layer: LayerNetwork, LayerNum: 3}
	ProtocolIGMP = Protocol{Name: "IGMP", Color: "#c0392b", Layer: LayerNetwork, LayerNum: 3, Discovery: true}
	ProtocolOSPF = Protocol{Name: "OSPF", Color: "#f1c40f", Layer: LayerNetwork, LayerNum: 3, Discovery: true}
	ProtocolNDP  = Protocol{Name: "NDP", Color: "#1f8a70", Layer: LayerNetwork, LayerNum: 3, Discovery: true}

	// Data Link (L2)
	ProtocolARP  = Protocol{Name: "ARP", Color: "#95a5a6", Layer: LayerDataLink, LayerNum: 2, Discovery: true, DefaultVisible: true}
	ProtocolVLAN = Protocol{Name: "VLAN", Color: "#d35400", Layer: LayerDataLink, LayerNum: 2}
	ProtocolLLDP = Protocol{Name: "LLDP", Color: "#27ae60", Layer: LayerDataLink, LayerNum: 2, Discovery: true, L2Endpoints: true}
	ProtocolCDP  = Protocol{Name: "CDP", Color: "#2980b9", Layer: LayerDataLink, LayerNum: 2, Discovery: true, L2Endpoints: true}
	ProtocolSTP  = Protocol{Name: "STP", Color: "#8e44ad", Layer: LayerDataLink, LayerNum: 2, Discovery: true}

	// Application (L7)
	ProtocolHTTP       = Protocol{Name: "HTTP", Color: "#e67e22", Layer: LayerApplication, LayerNum: 7, DefaultVisible: true}
	ProtocolHTTPS      = Protocol{Name: "HTTPS", Color: "#9b59b6", Layer: LayerApplication, LayerNum: 7, DefaultVisible: true}
	ProtocolDNS        = Protocol{Name: "DNS", Color: "#1abc9c", Layer: LayerApplication, LayerNum: 7, DefaultVisible: true}
	ProtocolSSH        = Protocol{Name: "SSH", Color: "#e74c3c", Layer: LayerApplication, LayerNum: 7, DefaultVisible: true}
	ProtocolFTP        = Protocol{Name: "FTP", Color: "#ff6b9d", Layer: LayerApplication, LayerNum: 7}
	ProtocolSMTP       = Protocol{Name: "SMTP", Color: "#8b4513", Layer: LayerApplication, LayerNum: 7}
	ProtocolMySQL      = Protocol{Name: "MySQL", Color: "#34495e", Layer: LayerApplication, LayerNum: 7}
	ProtocolPostgreSQL = Protocol{Name: "PostgreSQL", Color: "#16a085", Layer: LayerApplication, LayerNum: 7}
	ProtocolInfluxDB   = Protocol{Name: "InfluxDB", Color: "#22ADF6", Layer: LayerApplication, LayerNum: 7}
	ProtocolSlurm      = Protocol{Name: "Slurm", Color: "#ff7f50", Layer: LayerApplication, LayerNum: 7}
	ProtocolMDNS       = Protocol{Name: "mDNS", Color: "#e84393", Layer: LayerApplication, LayerNum: 7, Discovery: true}
	ProtocolSSDP       = Protocol{Name: "SSDP", Color: "#00cec9", Layer: LayerApplication, LayerNum: 7, Discovery: true}
	ProtocolLLMNR      = Protocol{Name: "LLMNR", Color: "#6c5ce7", Layer: LayerApplication, LayerNum: 7, Discovery: true}
	ProtocolNetBIOS    = Protocol{Name: "NetBIOS", Color: "#fdcb6e", Layer: LayerApplication, LayerNum: 7, Discovery: true}
	ProtocolDHCP       = Protocol{Name: "DHCP", Color: "#0984e3", Layer: LayerApplication, LayerNum: 7, Discovery: true}
	ProtocolWSD        = Protocol{Name: "WS-Discovery", Color: "#a29bfe", Layer: LayerApplication, LayerNum: 7, Discovery: true}

	// VPN / tunnel transports (identified by their well-known ports).
	ProtocolWireGuard = Protocol{Name: "WireGuard", Color: "#b5179e", Layer: LayerApplication, LayerNum: 7, DefaultVisible: true}
	ProtocolOpenVPN   = Protocol{Name: "OpenVPN", Color: "#f48c06", Layer: LayerApplication, LayerNum: 7, DefaultVisible: true}

	// Kubernetes cluster traffic: overlay encapsulations (VXLAN/Geneve) and the
	// control-plane services. LayerNum 7 keeps the normal IP handling for the
	// outer packet; VXLAN/Geneve are decapsulated in ProcessPacket.
	ProtocolVXLAN   = Protocol{Name: "VXLAN", Color: "#326ce5", Layer: LayerApplication, LayerNum: 7, Decap: true}
	ProtocolGeneve  = Protocol{Name: "Geneve", Color: "#5b8def", Layer: LayerApplication, LayerNum: 7, Decap: true}
	ProtocolK8sAPI  = Protocol{Name: "K8s-API", Color: "#1f6feb", Layer: LayerApplication, LayerNum: 7}
	ProtocolEtcd    = Protocol{Name: "etcd", Color: "#419eda", Layer: LayerApplication, LayerNum: 7}
	ProtocolKubelet = Protocol{Name: "Kubelet", Color: "#6cb6ff", Layer: LayerApplication, LayerNum: 7}

	// OT / ICS / SCADA industrial protocols. The ten most commonly seen on
	// plant/utility networks, identified by their registered ports. Vendors map
	// onto these: Allen-Bradley/Rockwell & Omron speak EtherNet/IP (CIP);
	// Schneider speaks Modbus (and EtherNet/IP); Siemens speaks S7comm & PROFINET.
	// Grouped under LayerOT so they stand out from IT traffic in the legend.
	ProtocolModbus     = Protocol{Name: "Modbus", Color: "#b7472a", Layer: LayerOT, LayerNum: 7}
	ProtocolEtherNetIP = Protocol{Name: "EtherNet/IP", Color: "#e07a1f", Layer: LayerOT, LayerNum: 7}
	ProtocolDNP3       = Protocol{Name: "DNP3", Color: "#8a6d3b", Layer: LayerOT, LayerNum: 7}
	ProtocolS7comm     = Protocol{Name: "S7comm", Color: "#009999", Layer: LayerOT, LayerNum: 7}
	ProtocolBACnet     = Protocol{Name: "BACnet", Color: "#7a5195", Layer: LayerOT, LayerNum: 7}
	ProtocolOPCUA      = Protocol{Name: "OPC-UA", Color: "#2a6f97", Layer: LayerOT, LayerNum: 7}
	ProtocolIEC104     = Protocol{Name: "IEC-104", Color: "#bc5090", Layer: LayerOT, LayerNum: 7}
	ProtocolPROFINET   = Protocol{Name: "PROFINET", Color: "#ff764a", Layer: LayerOT, LayerNum: 7}
	ProtocolHARTIP     = Protocol{Name: "HART-IP", Color: "#58508d", Layer: LayerOT, LayerNum: 7}
	ProtocolFINS       = Protocol{Name: "FINS", Color: "#1f6f78", Layer: LayerOT, LayerNum: 7}

	ProtocolOther = Protocol{Name: "Other", Color: "#ecf0f1", Layer: LayerUnknown, LayerNum: 0}
)

// populateProtocolVars refreshes the exported Protocol variables from a
// registry, keeping the literal fallback when the catalog lacks the entry.
func populateProtocolVars(reg *Registry) {
	set := func(dst *Protocol, name string) {
		if p, ok := reg.ByName[name]; ok {
			*dst = p
		}
	}
	set(&ProtocolTCP, "TCP")
	set(&ProtocolUDP, "UDP")
	set(&ProtocolICMP, "ICMP")
	set(&ProtocolIPv6, "IPv6")
	set(&ProtocolIGMP, "IGMP")
	set(&ProtocolOSPF, "OSPF")
	set(&ProtocolNDP, "NDP")
	set(&ProtocolARP, "ARP")
	set(&ProtocolVLAN, "VLAN")
	set(&ProtocolLLDP, "LLDP")
	set(&ProtocolCDP, "CDP")
	set(&ProtocolSTP, "STP")
	set(&ProtocolHTTP, "HTTP")
	set(&ProtocolHTTPS, "HTTPS")
	set(&ProtocolDNS, "DNS")
	set(&ProtocolSSH, "SSH")
	set(&ProtocolFTP, "FTP")
	set(&ProtocolSMTP, "SMTP")
	set(&ProtocolMySQL, "MySQL")
	set(&ProtocolPostgreSQL, "PostgreSQL")
	set(&ProtocolInfluxDB, "InfluxDB")
	set(&ProtocolSlurm, "Slurm")
	set(&ProtocolMDNS, "mDNS")
	set(&ProtocolSSDP, "SSDP")
	set(&ProtocolLLMNR, "LLMNR")
	set(&ProtocolNetBIOS, "NetBIOS")
	set(&ProtocolDHCP, "DHCP")
	set(&ProtocolWSD, "WS-Discovery")
	set(&ProtocolWireGuard, "WireGuard")
	set(&ProtocolOpenVPN, "OpenVPN")
	set(&ProtocolVXLAN, "VXLAN")
	set(&ProtocolGeneve, "Geneve")
	set(&ProtocolK8sAPI, "K8s-API")
	set(&ProtocolEtcd, "etcd")
	set(&ProtocolKubelet, "Kubelet")
	set(&ProtocolModbus, "Modbus")
	set(&ProtocolEtherNetIP, "EtherNet/IP")
	set(&ProtocolDNP3, "DNP3")
	set(&ProtocolS7comm, "S7comm")
	set(&ProtocolBACnet, "BACnet")
	set(&ProtocolOPCUA, "OPC-UA")
	set(&ProtocolIEC104, "IEC-104")
	set(&ProtocolPROFINET, "PROFINET")
	set(&ProtocolHARTIP, "HART-IP")
	set(&ProtocolFINS, "FINS")
	set(&ProtocolOther, "Other")
}

// resolveProtocol returns the catalog entry for a structurally detected
// protocol, falling back to the exported default var when the active catalog
// lacks the name. This lets a custom protocols.json's color/layer edits reach
// packet detection for the layer-type-detected protocols too, not just the
// port-based ones.
func resolveProtocol(name string, fallback Protocol) Protocol {
	if p, ok := currentRegistry().ByName[name]; ok {
		return p
	}
	return fallback
}

// DetectProtocol analyzes a packet and returns the detected protocol.
// Works with both IPv4 and IPv6 packets - gopacket extracts transport layers from either.
// Detection runs most-specific-first: L2 topology/discovery, then L3 routing/control,
// then transport-based application protocols, falling back to VLAN/IPv6/Other.
// The gopacket layer-type checks identify the protocol structurally; the
// returned Protocol is then resolved through the registry (see resolveProtocol).
func DetectProtocol(packet gopacket.Packet) Protocol {
	// L2 topology & discovery protocols (no IP layer)
	if packet.Layer(layers.LayerTypeLinkLayerDiscovery) != nil {
		return resolveProtocol("LLDP", ProtocolLLDP)
	}
	if packet.Layer(layers.LayerTypeCiscoDiscovery) != nil {
		return resolveProtocol("CDP", ProtocolCDP)
	}
	if packet.Layer(layers.LayerTypeSTP) != nil {
		return resolveProtocol("STP", ProtocolSTP)
	}

	// ARP (IPv4 address resolution)
	if packet.Layer(layers.LayerTypeARP) != nil {
		return resolveProtocol("ARP", ProtocolARP)
	}

	// L3 routing / multicast control planes
	if packet.Layer(layers.LayerTypeOSPF) != nil {
		return resolveProtocol("OSPF", ProtocolOSPF)
	}
	if packet.Layer(layers.LayerTypeIGMP) != nil {
		return resolveProtocol("IGMP", ProtocolIGMP)
	}

	// IPv6 Neighbor Discovery / Router Advertisement (a subset of ICMPv6)
	if packet.Layer(layers.LayerTypeICMPv6RouterSolicitation) != nil ||
		packet.Layer(layers.LayerTypeICMPv6RouterAdvertisement) != nil ||
		packet.Layer(layers.LayerTypeICMPv6NeighborSolicitation) != nil ||
		packet.Layer(layers.LayerTypeICMPv6NeighborAdvertisement) != nil {
		return resolveProtocol("NDP", ProtocolNDP)
	}

	// Generic ICMP (both IPv4 and IPv6)
	if packet.Layer(layers.LayerTypeICMPv4) != nil || packet.Layer(layers.LayerTypeICMPv6) != nil {
		return resolveProtocol("ICMP", ProtocolICMP)
	}

	// Transport-based application protocols (IPv4 and IPv6)
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp, _ := tcpLayer.(*layers.TCP)
		return detectTCPProtocol(tcp)
	}
	if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		udp, _ := udpLayer.(*layers.UDP)
		return detectUDPProtocol(udp)
	}

	// 802.1Q VLAN tag with no recognized upper-layer protocol
	if packet.Layer(layers.LayerTypeDot1Q) != nil {
		return resolveProtocol("VLAN", ProtocolVLAN)
	}

	// IPv6 packets without a recognized upper layer
	if packet.Layer(layers.LayerTypeIPv6) != nil {
		return resolveProtocol("IPv6", ProtocolIPv6)
	}

	return resolveProtocol("Other", ProtocolOther)
}

// lookupPortProtocol resolves a transport port pair against a port table:
// destination first (the server side is typically the destination), then
// source. The old hardcoded switch matched srcPort==X || dstPort==X per case
// in a fixed order; the map lookup checks dst first, which only differs when
// BOTH ports are mapped — vanishingly rare for real traffic, and dst-first is
// the better guess when it happens. Unknown ports fall back to the generic
// transport protocol (TCP/UDP) from the catalog.
func lookupPortProtocol(ports map[uint16]string, srcPort, dstPort uint16, generic Protocol) Protocol {
	reg := currentRegistry()
	if name, ok := ports[dstPort]; ok {
		if p, ok := reg.ByName[name]; ok {
			return p
		}
	}
	if name, ok := ports[srcPort]; ok {
		if p, ok := reg.ByName[name]; ok {
			return p
		}
	}
	if p, ok := reg.ByName[generic.Name]; ok {
		return p
	}
	return generic
}

// detectTCPProtocol detects application-layer protocols over TCP
func detectTCPProtocol(tcp *layers.TCP) Protocol {
	return lookupPortProtocol(currentRegistry().TCPPorts,
		uint16(tcp.SrcPort), uint16(tcp.DstPort), ProtocolTCP)
}

// detectUDPProtocol detects application-layer protocols over UDP.
// Includes the broadcast/multicast discovery protocols (mDNS, SSDP, LLMNR,
// NetBIOS, DHCP, WS-Discovery) that advertise hosts and services on a segment.
func detectUDPProtocol(udp *layers.UDP) Protocol {
	return lookupPortProtocol(currentRegistry().UDPPorts,
		uint16(udp.SrcPort), uint16(udp.DstPort), ProtocolUDP)
}

// GetAllProtocols returns a list of all supported protocols with their colors,
// in the catalog's display order.
func GetAllProtocols() []Protocol {
	all := currentRegistry().All
	out := make([]Protocol, len(all))
	copy(out, all)
	return out
}

// ServiceLabel returns a "Name (port)" label for a packet's ports (preferring the
// destination, the typical server side), or "" when neither port is well-known.
// The well-known port table comes from the catalog; it labels a packet's
// summary (e.g. "Redis", "RDP", "WireGuard") even when the traffic is
// otherwise just generic TCP/UDP, so the packet list identifies the service
// without turning every port into its own colored protocol/filter.
func ServiceLabel(srcPort, dstPort uint16) string {
	wellKnown := currentRegistry().WellKnown
	if s, ok := wellKnown[dstPort]; ok {
		return fmt.Sprintf("%s (%d)", s, dstPort)
	}
	if s, ok := wellKnown[srcPort]; ok {
		return fmt.Sprintf("%s (%d)", s, srcPort)
	}
	return ""
}
