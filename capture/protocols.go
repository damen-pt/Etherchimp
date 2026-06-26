package capture

import (
	"fmt"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// OSI layer labels used for grouping protocols in the UI.
const (
	LayerDataLink    = "L2 · Data Link"
	LayerNetwork     = "L3 · Network"
	LayerTransport   = "L4 · Transport"
	LayerApplication = "L7 · Application"
	LayerUnknown     = "— · Unknown"
)

// Protocol represents a detected network protocol with its display properties.
// Layer/LayerNum carry the correlative OSI layer so the UI can group protocols.
// Discovery marks broadcast/multicast topology & service-discovery protocols
// (mDNS, SSDP, LLDP, …) so the capture pipeline keeps them instead of
// filtering them out as ordinary multicast noise.
type Protocol struct {
	Name      string `json:"Name"`
	Color     string `json:"Color"`
	Layer     string `json:"Layer"`
	LayerNum  int    `json:"LayerNum"`
	Discovery bool   `json:"Discovery,omitempty"`
}

// Protocol color scheme
var (
	// Transport (L4)
	ProtocolTCP = Protocol{Name: "TCP", Color: "#3498db", Layer: LayerTransport, LayerNum: 4}
	ProtocolUDP = Protocol{Name: "UDP", Color: "#2ecc71", Layer: LayerTransport, LayerNum: 4}

	// Network (L3)
	ProtocolICMP = Protocol{Name: "ICMP", Color: "#f39c12", Layer: LayerNetwork, LayerNum: 3}
	ProtocolIPv6 = Protocol{Name: "IPv6", Color: "#7f8c8d", Layer: LayerNetwork, LayerNum: 3}
	ProtocolIGMP = Protocol{Name: "IGMP", Color: "#c0392b", Layer: LayerNetwork, LayerNum: 3, Discovery: true}
	ProtocolOSPF = Protocol{Name: "OSPF", Color: "#f1c40f", Layer: LayerNetwork, LayerNum: 3, Discovery: true}
	ProtocolNDP  = Protocol{Name: "NDP", Color: "#1f8a70", Layer: LayerNetwork, LayerNum: 3, Discovery: true}

	// Data Link (L2)
	ProtocolARP  = Protocol{Name: "ARP", Color: "#95a5a6", Layer: LayerDataLink, LayerNum: 2, Discovery: true}
	ProtocolVLAN = Protocol{Name: "VLAN", Color: "#d35400", Layer: LayerDataLink, LayerNum: 2}
	ProtocolLLDP = Protocol{Name: "LLDP", Color: "#27ae60", Layer: LayerDataLink, LayerNum: 2, Discovery: true}
	ProtocolCDP  = Protocol{Name: "CDP", Color: "#2980b9", Layer: LayerDataLink, LayerNum: 2, Discovery: true}
	ProtocolSTP  = Protocol{Name: "STP", Color: "#8e44ad", Layer: LayerDataLink, LayerNum: 2, Discovery: true}

	// Application (L7)
	ProtocolHTTP       = Protocol{Name: "HTTP", Color: "#e67e22", Layer: LayerApplication, LayerNum: 7}
	ProtocolHTTPS      = Protocol{Name: "HTTPS", Color: "#9b59b6", Layer: LayerApplication, LayerNum: 7}
	ProtocolDNS        = Protocol{Name: "DNS", Color: "#1abc9c", Layer: LayerApplication, LayerNum: 7}
	ProtocolSSH        = Protocol{Name: "SSH", Color: "#e74c3c", Layer: LayerApplication, LayerNum: 7}
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
	ProtocolWireGuard = Protocol{Name: "WireGuard", Color: "#b5179e", Layer: LayerApplication, LayerNum: 7}
	ProtocolOpenVPN   = Protocol{Name: "OpenVPN", Color: "#f48c06", Layer: LayerApplication, LayerNum: 7}

	// Kubernetes cluster traffic: overlay encapsulations (VXLAN/Geneve) and the
	// control-plane services. LayerNum 7 keeps the normal IP handling for the
	// outer packet; VXLAN/Geneve are decapsulated in ProcessPacket.
	ProtocolVXLAN   = Protocol{Name: "VXLAN", Color: "#326ce5", Layer: LayerApplication, LayerNum: 7}
	ProtocolGeneve  = Protocol{Name: "Geneve", Color: "#5b8def", Layer: LayerApplication, LayerNum: 7}
	ProtocolK8sAPI  = Protocol{Name: "K8s-API", Color: "#1f6feb", Layer: LayerApplication, LayerNum: 7}
	ProtocolEtcd    = Protocol{Name: "etcd", Color: "#419eda", Layer: LayerApplication, LayerNum: 7}
	ProtocolKubelet = Protocol{Name: "Kubelet", Color: "#6cb6ff", Layer: LayerApplication, LayerNum: 7}

	ProtocolOther = Protocol{Name: "Other", Color: "#ecf0f1", Layer: LayerUnknown, LayerNum: 0}
)

// DetectProtocol analyzes a packet and returns the detected protocol.
// Works with both IPv4 and IPv6 packets - gopacket extracts transport layers from either.
// Detection runs most-specific-first: L2 topology/discovery, then L3 routing/control,
// then transport-based application protocols, falling back to VLAN/IPv6/Other.
func DetectProtocol(packet gopacket.Packet) Protocol {
	// L2 topology & discovery protocols (no IP layer)
	if packet.Layer(layers.LayerTypeLinkLayerDiscovery) != nil {
		return ProtocolLLDP
	}
	if packet.Layer(layers.LayerTypeCiscoDiscovery) != nil {
		return ProtocolCDP
	}
	if packet.Layer(layers.LayerTypeSTP) != nil {
		return ProtocolSTP
	}

	// ARP (IPv4 address resolution)
	if packet.Layer(layers.LayerTypeARP) != nil {
		return ProtocolARP
	}

	// L3 routing / multicast control planes
	if packet.Layer(layers.LayerTypeOSPF) != nil {
		return ProtocolOSPF
	}
	if packet.Layer(layers.LayerTypeIGMP) != nil {
		return ProtocolIGMP
	}

	// IPv6 Neighbor Discovery / Router Advertisement (a subset of ICMPv6)
	if packet.Layer(layers.LayerTypeICMPv6RouterSolicitation) != nil ||
		packet.Layer(layers.LayerTypeICMPv6RouterAdvertisement) != nil ||
		packet.Layer(layers.LayerTypeICMPv6NeighborSolicitation) != nil ||
		packet.Layer(layers.LayerTypeICMPv6NeighborAdvertisement) != nil {
		return ProtocolNDP
	}

	// Generic ICMP (both IPv4 and IPv6)
	if packet.Layer(layers.LayerTypeICMPv4) != nil || packet.Layer(layers.LayerTypeICMPv6) != nil {
		return ProtocolICMP
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
		return ProtocolVLAN
	}

	// IPv6 packets without a recognized upper layer
	if packet.Layer(layers.LayerTypeIPv6) != nil {
		return ProtocolIPv6
	}

	return ProtocolOther
}

// detectTCPProtocol detects application-layer protocols over TCP
func detectTCPProtocol(tcp *layers.TCP) Protocol {
	srcPort := uint16(tcp.SrcPort)
	dstPort := uint16(tcp.DstPort)

	// Check common TCP ports
	switch {
	case srcPort == 80 || dstPort == 80:
		return ProtocolHTTP
	case srcPort == 443 || dstPort == 443:
		return ProtocolHTTPS
	case srcPort == 22 || dstPort == 22:
		return ProtocolSSH
	case srcPort == 21 || dstPort == 21:
		return ProtocolFTP
	case srcPort == 20 || dstPort == 20:
		return ProtocolFTP // FTP data
	case srcPort == 25 || dstPort == 25:
		return ProtocolSMTP
	case srcPort == 587 || dstPort == 587:
		return ProtocolSMTP // Submission
	case srcPort == 3306 || dstPort == 3306:
		return ProtocolMySQL
	case srcPort == 5432 || dstPort == 5432:
		return ProtocolPostgreSQL
	case srcPort == 8086 || dstPort == 8086:
		return ProtocolInfluxDB
	case srcPort == 6817 || dstPort == 6817:
		return ProtocolSlurm // slurmctld
	case srcPort == 6818 || dstPort == 6818:
		return ProtocolSlurm // slurmd
	case srcPort == 8080 || dstPort == 8080:
		return ProtocolHTTP // Alternative HTTP
	case srcPort == 8443 || dstPort == 8443:
		return ProtocolHTTPS // Alternative HTTPS
	case srcPort == 1194 || dstPort == 1194:
		return ProtocolOpenVPN // OpenVPN also runs over TCP
	case srcPort == 6443 || dstPort == 6443:
		return ProtocolK8sAPI // kube-apiserver
	case srcPort == 2379 || dstPort == 2379 || srcPort == 2380 || dstPort == 2380:
		return ProtocolEtcd // etcd client/peer
	case srcPort == 10250 || dstPort == 10250:
		return ProtocolKubelet // kubelet API
	default:
		return ProtocolTCP
	}
}

// detectUDPProtocol detects application-layer protocols over UDP.
// Includes the broadcast/multicast discovery protocols (mDNS, SSDP, LLMNR,
// NetBIOS, DHCP, WS-Discovery) that advertise hosts and services on a segment.
func detectUDPProtocol(udp *layers.UDP) Protocol {
	srcPort := uint16(udp.SrcPort)
	dstPort := uint16(udp.DstPort)

	// Check common UDP ports
	switch {
	case srcPort == 53 || dstPort == 53:
		return ProtocolDNS
	case srcPort == 5353 || dstPort == 5353:
		return ProtocolMDNS // multicast DNS / Bonjour / DNS-SD
	case srcPort == 1900 || dstPort == 1900:
		return ProtocolSSDP // SSDP / UPnP discovery
	case srcPort == 5355 || dstPort == 5355:
		return ProtocolLLMNR // Link-Local Multicast Name Resolution
	case srcPort == 137 || dstPort == 137 || srcPort == 138 || dstPort == 138:
		return ProtocolNetBIOS // NetBIOS name / datagram service
	case srcPort == 67 || dstPort == 67 || srcPort == 68 || dstPort == 68:
		return ProtocolDHCP
	case srcPort == 3702 || dstPort == 3702:
		return ProtocolWSD // WS-Discovery
	case srcPort == 51820 || dstPort == 51820:
		return ProtocolWireGuard
	case srcPort == 1194 || dstPort == 1194:
		return ProtocolOpenVPN
	case srcPort == 4789 || dstPort == 4789 || srcPort == 8472 || dstPort == 8472:
		return ProtocolVXLAN // VXLAN overlay (standard 4789, Flannel 8472)
	case srcPort == 6081 || dstPort == 6081:
		return ProtocolGeneve // Geneve overlay (Cilium/OVN/Antrea)
	default:
		return ProtocolUDP
	}
}

// GetAllProtocols returns a list of all supported protocols with their colors
func GetAllProtocols() []Protocol {
	return []Protocol{
		// L2 - Data Link
		ProtocolARP,
		ProtocolVLAN,
		ProtocolLLDP,
		ProtocolCDP,
		ProtocolSTP,
		// L3 - Network
		ProtocolICMP,
		ProtocolNDP,
		ProtocolIGMP,
		ProtocolOSPF,
		ProtocolIPv6,
		// L4 - Transport
		ProtocolTCP,
		ProtocolUDP,
		// L7 - Application
		ProtocolHTTP,
		ProtocolHTTPS,
		ProtocolDNS,
		ProtocolMDNS,
		ProtocolSSDP,
		ProtocolLLMNR,
		ProtocolNetBIOS,
		ProtocolDHCP,
		ProtocolWSD,
		ProtocolSSH,
		ProtocolFTP,
		ProtocolSMTP,
		ProtocolMySQL,
		ProtocolPostgreSQL,
		ProtocolInfluxDB,
		ProtocolSlurm,
		ProtocolWireGuard,
		ProtocolOpenVPN,
		// Kubernetes
		ProtocolVXLAN,
		ProtocolGeneve,
		ProtocolK8sAPI,
		ProtocolEtcd,
		ProtocolKubelet,
		// Unknown
		ProtocolOther,
	}
}

// wellKnownPorts maps common service ports to a short service name. It is used to
// label a packet's summary (e.g. "Redis", "RDP", "WireGuard") even when the
// traffic is otherwise just generic TCP/UDP, so the packet list identifies the
// service without turning every port into its own colored protocol/filter. This
// covers the commonly-seen well-known services; extend freely.
var wellKnownPorts = map[uint16]string{
	7: "Echo", 9: "Discard", 13: "Daytime", 19: "Chargen", 20: "FTP-Data", 21: "FTP",
	22: "SSH", 23: "Telnet", 25: "SMTP", 37: "Time", 43: "WHOIS", 49: "TACACS",
	53: "DNS", 67: "DHCP", 68: "DHCP", 69: "TFTP", 70: "Gopher", 79: "Finger",
	80: "HTTP", 88: "Kerberos", 102: "S7/ISO-TSAP", 110: "POP3", 111: "RPC/portmap",
	113: "Ident", 119: "NNTP", 123: "NTP", 135: "MS-RPC", 137: "NetBIOS-NS",
	138: "NetBIOS-DGM", 139: "NetBIOS-SSN", 143: "IMAP", 161: "SNMP", 162: "SNMP-Trap",
	179: "BGP", 194: "IRC", 201: "AppleTalk", 264: "BGMP", 389: "LDAP", 443: "HTTPS",
	445: "SMB", 465: "SMTPS", 500: "IKE/IPsec", 502: "Modbus", 514: "Syslog",
	515: "LPD/Printer", 520: "RIP", 521: "RIPng", 540: "UUCP", 546: "DHCPv6",
	547: "DHCPv6", 554: "RTSP", 587: "SMTP-Sub", 593: "MS-RPC-HTTP", 623: "IPMI",
	631: "IPP/CUPS", 636: "LDAPS", 646: "LDP", 660: "MacOS-Server", 873: "rsync",
	902: "VMware", 989: "FTPS-Data", 990: "FTPS", 993: "IMAPS", 995: "POP3S",
	1080: "SOCKS", 1099: "Java-RMI", 1194: "OpenVPN", 1352: "Lotus-Notes",
	1433: "MSSQL", 1434: "MSSQL-Mon", 1521: "Oracle", 1701: "L2TP", 1723: "PPTP",
	1812: "RADIUS", 1813: "RADIUS-Acct", 1883: "MQTT", 1900: "SSDP", 2049: "NFS",
	2082: "cPanel", 2083: "cPanel-SSL", 2181: "ZooKeeper", 2222: "SSH-Alt",
	2375: "Docker", 2376: "Docker-TLS", 2379: "etcd", 2380: "etcd-peer",
	2483: "Oracle", 2484: "Oracle-SSL", 3000: "Dev/Grafana", 3128: "Squid-Proxy",
	3268: "GlobalCatalog", 3269: "GlobalCatalog-SSL", 3306: "MySQL", 3389: "RDP",
	3478: "STUN/TURN", 3690: "SVN", 4369: "Erlang-EPMD", 4500: "IPsec-NAT-T",
	4567: "MySQL-Galera", 4789: "VXLAN", 5000: "UPnP/Dev", 5044: "Logstash-Beats",
	5060: "SIP", 5061: "SIP-TLS", 5222: "XMPP", 5269: "XMPP-Server", 5353: "mDNS",
	5355: "LLMNR", 5432: "PostgreSQL", 5601: "Kibana", 5672: "AMQP/RabbitMQ",
	5683: "CoAP", 5684: "CoAP-DTLS", 5900: "VNC", 5938: "TeamViewer",
	5985: "WinRM", 5986: "WinRM-SSL", 6000: "X11", 6379: "Redis", 6443: "Kubernetes-API",
	6514: "Syslog-TLS", 6566: "SANE", 6817: "Slurm", 6881: "BitTorrent",
	7000: "Cassandra", 7077: "Spark", 7777: "Game/Alt", 8000: "HTTP-Alt",
	8006: "Proxmox", 8025: "Mailhog", 8080: "HTTP-Proxy", 8086: "InfluxDB",
	8123: "Home-Assistant", 8200: "Vault", 8443: "HTTPS-Alt", 8500: "Consul",
	8883: "MQTT-TLS", 8888: "HTTP-Alt", 9000: "SonarQube/PHP-FPM", 9042: "Cassandra",
	9090: "Prometheus", 9092: "Kafka", 9100: "JetDirect/Printer", 9200: "Elasticsearch",
	9300: "Elasticsearch", 9418: "Git", 9999: "Admin/Alt", 10000: "Webmin",
	11211: "Memcached", 15672: "RabbitMQ-Mgmt", 25565: "Minecraft", 27017: "MongoDB",
	27018: "MongoDB", 32400: "Plex", 51820: "WireGuard",
}

// ServiceLabel returns a "Name (port)" label for a packet's ports (preferring the
// destination, the typical server side), or "" when neither port is well-known.
func ServiceLabel(srcPort, dstPort uint16) string {
	if s, ok := wellKnownPorts[dstPort]; ok {
		return fmt.Sprintf("%s (%d)", s, dstPort)
	}
	if s, ok := wellKnownPorts[srcPort]; ok {
		return fmt.Sprintf("%s (%d)", s, srcPort)
	}
	return ""
}
