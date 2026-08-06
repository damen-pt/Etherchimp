package capture

import (
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// expectedProtocolOrder is the catalog order as shipped in protocols.json
// (the old GetAllProtocols order), pinned so the JSON stays in sync.
var expectedProtocolOrder = []string{
	"ARP", "VLAN", "LLDP", "CDP", "STP",
	"ICMP", "NDP", "IGMP", "OSPF", "IPv6",
	"TCP", "UDP",
	"HTTP", "HTTPS", "DNS", "mDNS", "SSDP", "LLMNR", "NetBIOS", "DHCP",
	"WS-Discovery", "SSH", "FTP", "SMTP", "MySQL", "PostgreSQL", "InfluxDB",
	"Slurm", "PBS", "Warewulf", "xCAT", "LSF", "GridEngine", "BrightCMD",
	"WireGuard", "OpenVPN",
	"VXLAN", "Geneve", "K8s-API", "etcd", "Kubelet",
	"Modbus", "EtherNet/IP", "DNP3", "S7comm", "BACnet", "OPC-UA", "IEC-104",
	"PROFINET", "HART-IP", "FINS",
	"Other",
}

// restoreDefaults returns a cleanup that puts the embedded default registry
// back (the registry is package-global).
func restoreDefaults(t *testing.T) {
	t.Cleanup(func() {
		if err := loadProtocols(defaultProtocolsJSON); err != nil {
			t.Fatalf("failed to restore default protocol registry: %v", err)
		}
	})
}

func TestEmbeddedDefaultsLoad(t *testing.T) {
	all := GetAllProtocols()
	if len(all) != len(expectedProtocolOrder) {
		t.Fatalf("GetAllProtocols returned %d protocols, want %d", len(all), len(expectedProtocolOrder))
	}
	for i, name := range expectedProtocolOrder {
		if all[i].Name != name {
			t.Errorf("protocol %d = %q, want %q", i, all[i].Name, name)
		}
	}

	// Spot-check flags carried by the shipped defaults.
	tcp, ok := ByName("TCP")
	if !ok || !tcp.Generic || !tcp.DefaultVisible {
		t.Errorf("TCP: Generic=%v DefaultVisible=%v, want both true", tcp.Generic, tcp.DefaultVisible)
	}
	vxlan, ok := ByName("VXLAN")
	if !ok || !vxlan.Decap {
		t.Errorf("VXLAN: Decap=%v, want true", vxlan.Decap)
	}
	lldp, ok := ByName("LLDP")
	if !ok || !lldp.L2Endpoints {
		t.Errorf("LLDP: L2Endpoints=%v, want true", lldp.L2Endpoints)
	}
	mdns, ok := ByName("mDNS")
	if !ok || !mdns.Discovery {
		t.Errorf("mDNS: Discovery=%v, want true", mdns.Discovery)
	}

	// The exported vars are populated from the embedded defaults at init.
	if ProtocolTCP.Color != "#3498db" || !ProtocolTCP.Generic {
		t.Errorf("ProtocolTCP = %+v, want embedded default", ProtocolTCP)
	}
	if ProtocolBACnet.Layer != LayerOT {
		t.Errorf("ProtocolBACnet.Layer = %q, want %q", ProtocolBACnet.Layer, LayerOT)
	}

	if !IsGenericName("TCP") || !IsGenericName("UDP") {
		t.Error("IsGenericName: TCP/UDP should be generic")
	}
	if IsGenericName("HTTP") || IsGenericName("NoSuchProtocol") {
		t.Error("IsGenericName: HTTP/unknown should not be generic")
	}
}

func TestDetectTCPProtocolPorts(t *testing.T) {
	cases := []struct {
		src, dst uint16
		want     string
	}{
		{12345, 22, "SSH"},
		{12345, 443, "HTTPS"},
		{502, 12345, "Modbus"}, // source-side match (server replied)
		{12345, 6443, "K8s-API"},
		{12345, 8080, "HTTP"}, // alternative HTTP
		{12345, 44818, "EtherNet/IP"},
		// HPC cluster orchestration / job schedulers
		{12345, 6819, "Slurm"},      // slurmdbd
		{12345, 6820, "Slurm"},      // slurmrestd
		{12345, 15001, "PBS"},       // pbs_server
		{15004, 12345, "PBS"},       // pbs_sched (source-side)
		{12345, 17001, "PBS"},       // pbs_comm (PBS Pro TPP)
		{12345, 9873, "Warewulf"},   // warewulfd
		{12345, 3001, "xCAT"},       // xcatd
		{12345, 7869, "LSF"},        // lim
		{12345, 6881, "LSF"},        // mbatchd
		{12345, 6444, "GridEngine"}, // sge_qmaster
		{12345, 8081, "BrightCMD"},  // cmdaemon
		{12345, 9999, "TCP"},        // unmapped port falls back to generic
	}
	for _, c := range cases {
		tcp := &layers.TCP{SrcPort: layers.TCPPort(c.src), DstPort: layers.TCPPort(c.dst)}
		if got := detectTCPProtocol(tcp); got.Name != c.want {
			t.Errorf("detectTCPProtocol(%d->%d) = %q, want %q", c.src, c.dst, got.Name, c.want)
		}
	}
}

func TestDetectUDPProtocolPorts(t *testing.T) {
	cases := []struct {
		src, dst uint16
		want     string
	}{
		{12345, 53, "DNS"},
		{12345, 5353, "mDNS"},
		{4789, 12345, "VXLAN"}, // source-side match
		{12345, 47808, "BACnet"},
		{12345, 6081, "Geneve"},
		{12345, 51820, "WireGuard"},
		// HPC (UDP side): Torque/PBS mom traffic, xCAT, LSF lim
		{12345, 15002, "PBS"},
		{3001, 12345, "xCAT"},
		{12345, 7869, "LSF"},
		{12345, 9999, "UDP"}, // unmapped port falls back to generic
	}
	for _, c := range cases {
		udp := &layers.UDP{SrcPort: layers.UDPPort(c.src), DstPort: layers.UDPPort(c.dst)}
		if got := detectUDPProtocol(udp); got.Name != c.want {
			t.Errorf("detectUDPProtocol(%d->%d) = %q, want %q", c.src, c.dst, got.Name, c.want)
		}
	}
}

func TestServiceLabel(t *testing.T) {
	if got := ServiceLabel(12345, 3389); got != "RDP (3389)" {
		t.Errorf("ServiceLabel(12345, 3389) = %q, want %q", got, "RDP (3389)")
	}
	// Falls back to the source port when the destination is not well-known.
	if got := ServiceLabel(6379, 45678); got != "Redis (6379)" {
		t.Errorf("ServiceLabel(6379, 45678) = %q, want %q", got, "Redis (6379)")
	}
	if got := ServiceLabel(12345, 45678); got != "" {
		t.Errorf("ServiceLabel(12345, 45678) = %q, want empty", got)
	}
}

func TestLoadProtocolsCustom(t *testing.T) {
	restoreDefaults(t)

	custom := `{
	  "protocols": [
	    {"name": "TCP", "color": "#3498db", "layer": "L4 · Transport", "layerNum": 4, "generic": true, "defaultVisible": true},
	    {"name": "UDP", "color": "#2ecc71", "layer": "L4 · Transport", "layerNum": 4, "generic": true, "defaultVisible": true},
	    {"name": "SSH", "color": "#123456", "layer": "L7 · Application", "layerNum": 7},
	    {"name": "MyProto", "color": "", "layer": "L7 · Application", "layerNum": 7}
	  ],
	  "tcpPorts": {"22": "SSH", "9999": "MyProto", "5555": "NoSuchProtocol"},
	  "udpPorts": {},
	  "wellKnownPorts": {"9999": "MySvc"}
	}`
	path := filepath.Join(t.TempDir(), "protocols.json")
	if err := os.WriteFile(path, []byte(custom), 0644); err != nil {
		t.Fatal(err)
	}
	if err := LoadProtocols(path); err != nil {
		t.Fatalf("LoadProtocols: %v", err)
	}

	// Color override is honored.
	ssh, ok := ByName("SSH")
	if !ok || ssh.Color != "#123456" {
		t.Errorf("SSH color = %q, want overridden #123456", ssh.Color)
	}
	// Custom port mapping resolves; empty color got the default.
	my, ok := ByName("MyProto")
	if !ok {
		t.Fatal("MyProto missing from registry")
	}
	if my.Color != defaultColor {
		t.Errorf("MyProto color = %q, want default %q", my.Color, defaultColor)
	}
	tcp := &layers.TCP{SrcPort: 12345, DstPort: 9999}
	if got := detectTCPProtocol(tcp); got.Name != "MyProto" {
		t.Errorf("detectTCPProtocol(->9999) = %q, want MyProto", got.Name)
	}
	// Unknown protocol name in tcpPorts was skipped -> generic fallback.
	tcp = &layers.TCP{SrcPort: 12345, DstPort: 5555}
	if got := detectTCPProtocol(tcp); got.Name != "TCP" {
		t.Errorf("detectTCPProtocol(->5555) = %q, want TCP (unknown name skipped)", got.Name)
	}
	// Custom well-known port label.
	if got := ServiceLabel(12345, 9999); got != "MySvc (9999)" {
		t.Errorf("ServiceLabel(->9999) = %q, want %q", got, "MySvc (9999)")
	}
	// Generic flag from the custom catalog drives IsGenericName.
	if !IsGenericName("TCP") || IsGenericName("MyProto") {
		t.Error("IsGenericName wrong under custom registry")
	}
}

func TestLoadProtocolsMalformed(t *testing.T) {
	restoreDefaults(t)

	path := filepath.Join(t.TempDir(), "protocols.json")
	if err := os.WriteFile(path, []byte("{not json"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := LoadProtocols(path); err == nil {
		t.Fatal("LoadProtocols with malformed JSON: want error, got nil")
	}
	// Registry is unchanged.
	all := GetAllProtocols()
	if len(all) != len(expectedProtocolOrder) {
		t.Fatalf("registry changed after failed load: %d protocols, want %d", len(all), len(expectedProtocolOrder))
	}
}

func TestLoadProtocolsMissingFile(t *testing.T) {
	if err := LoadProtocols(filepath.Join(t.TempDir(), "nope.json")); err == nil {
		t.Fatal("LoadProtocols with missing file: want error, got nil")
	}
}

// buildPacket serializes the given layers into a decoded Ethernet packet.
func buildPacket(t *testing.T, ls ...gopacket.SerializableLayer) gopacket.Packet {
	t.Helper()
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if err := gopacket.SerializeLayers(buf, opts, ls...); err != nil {
		t.Fatalf("SerializeLayers: %v", err)
	}
	return gopacket.NewPacket(buf.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
}

func testARPPacket(t *testing.T) gopacket.Packet {
	return buildPacket(t,
		&layers.Ethernet{
			SrcMAC:       net.HardwareAddr{0, 1, 2, 3, 4, 5},
			DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
			EthernetType: layers.EthernetTypeARP,
		},
		&layers.ARP{
			AddrType:          layers.LinkTypeEthernet,
			Protocol:          layers.EthernetTypeIPv4,
			HwAddressSize:     6,
			ProtAddressSize:   4,
			Operation:         layers.ARPRequest,
			SourceHwAddress:   []byte{0, 1, 2, 3, 4, 5},
			SourceProtAddress: []byte{192, 168, 1, 10},
			DstHwAddress:      []byte{0, 0, 0, 0, 0, 0},
			DstProtAddress:    []byte{192, 168, 1, 1},
		},
	)
}

func testICMPPacket(t *testing.T) gopacket.Packet {
	return buildPacket(t,
		&layers.Ethernet{
			SrcMAC:       net.HardwareAddr{0, 1, 2, 3, 4, 5},
			DstMAC:       net.HardwareAddr{6, 7, 8, 9, 10, 11},
			EthernetType: layers.EthernetTypeIPv4,
		},
		&layers.IPv4{
			Version:  4,
			IHL:      5,
			TTL:      64,
			Protocol: layers.IPProtocolICMPv4,
			SrcIP:    net.IP{192, 168, 1, 10},
			DstIP:    net.IP{192, 168, 1, 1},
		},
		&layers.ICMPv4{TypeCode: layers.CreateICMPv4TypeCode(layers.ICMPv4TypeEchoRequest, 0)},
	)
}

// TestDetectProtocolResolvesRegistry verifies that the structurally detected
// protocols (ARP, ICMP, …) are resolved through the active catalog, so a
// custom protocols.json's color/layer edits reach packet detection.
func TestDetectProtocolResolvesRegistry(t *testing.T) {
	restoreDefaults(t)

	arp := testARPPacket(t)
	icmp := testICMPPacket(t)

	// Defaults: exported-var values.
	if got := DetectProtocol(arp); got.Name != "ARP" || got.Color != "#95a5a6" {
		t.Fatalf("default DetectProtocol(ARP) = %+v", got)
	}
	if got := DetectProtocol(icmp); got.Name != "ICMP" || got.Color != "#f39c12" {
		t.Fatalf("default DetectProtocol(ICMP) = %+v", got)
	}

	custom := `{
	  "protocols": [
	    {"name": "TCP", "color": "#3498db", "layer": "L4 · Transport", "layerNum": 4, "generic": true},
	    {"name": "UDP", "color": "#2ecc71", "layer": "L4 · Transport", "layerNum": 4, "generic": true},
	    {"name": "ARP", "color": "#aa0000", "layer": "L2 · Data Link", "layerNum": 2, "discovery": true},
	    {"name": "ICMP", "color": "#00aa00", "layer": "L3 · Network", "layerNum": 3}
	  ],
	  "tcpPorts": {},
	  "udpPorts": {},
	  "wellKnownPorts": {}
	}`
	path := filepath.Join(t.TempDir(), "protocols.json")
	if err := os.WriteFile(path, []byte(custom), 0644); err != nil {
		t.Fatal(err)
	}
	if err := LoadProtocols(path); err != nil {
		t.Fatalf("LoadProtocols: %v", err)
	}

	if got := DetectProtocol(arp); got.Name != "ARP" || got.Color != "#aa0000" {
		t.Errorf("custom DetectProtocol(ARP) = %+v, want color #aa0000", got)
	}
	if got := DetectProtocol(icmp); got.Name != "ICMP" || got.Color != "#00aa00" {
		t.Errorf("custom DetectProtocol(ICMP) = %+v, want color #00aa00", got)
	}
}
