package capture

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// maxPayloadCopy bounds the per-packet frame copy kept in PacketInfo.Payload
// (see copyPayload in ProcessPacket).
const maxPayloadCopy = 16 * 1024

// PacketInfo contains parsed packet information
type PacketInfo struct {
	SrcIP    string
	DstIP    string
	SrcMAC   string // Ethernet source MAC ("" if no Ethernet layer)
	DstMAC   string // Ethernet destination MAC ("" if no Ethernet layer)
	SrcPort  uint16
	DstPort  uint16
	Protocol Protocol
	Length   int
	Payload  []byte // Raw frame bytes, capped at maxPayloadCopy (16KB)
	// VLANID is the 802.1Q VLAN identifier when the frame carries a VLAN tag,
	// or 0 when untagged / not identifiable.
	VLANID uint16
	// SrcName/DstName are optional friendly labels for endpoints that have no
	// resolvable IP (e.g. L2 topology nodes identified by MAC). When set, the
	// graph uses them as the node hostname instead of a DNS lookup.
	SrcName string
	DstName string
	// DeviceKind/DeviceInfo come from LLDP/CDP discovery frames: the source is a
	// network device of kind "switch" or "router", and DeviceInfo carries the
	// advertised port / management address for the details panel. Empty otherwise.
	DeviceKind string
	DeviceInfo string
}

// isLocalOrMulticastAddress checks if an IP address is local/link-local/multicast
// These are filtered out as they clutter the graph with non-routable addresses
func isLocalOrMulticastAddress(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}

	// Check IPv4
	if ip4 := ip.To4(); ip4 != nil {
		// Link-local: 169.254.x.x
		if ip4[0] == 169 && ip4[1] == 254 {
			return true
		}
		// Multicast: 224.0.0.0 - 239.255.255.255
		if ip4[0] >= 224 && ip4[0] <= 239 {
			return true
		}
		// Loopback: 127.x.x.x
		if ip4[0] == 127 {
			return true
		}
		return false
	}

	// Check IPv6
	lowerIP := strings.ToLower(ipStr)

	// Link-local: fe80::/10
	if strings.HasPrefix(lowerIP, "fe80:") {
		return true
	}

	// Multicast: ff00::/8 (includes ff02::, ff01::, etc.)
	if strings.HasPrefix(lowerIP, "ff") {
		return true
	}

	// Loopback: ::1
	if ip.Equal(net.IPv6loopback) {
		return true
	}

	// Unique local addresses: fc00::/7 (fd00::/8 is commonly used)
	if strings.HasPrefix(lowerIP, "fc") || strings.HasPrefix(lowerIP, "fd") {
		return true
	}

	return false
}

// isLocalOrMulticastIP is the net.IP form of isLocalOrMulticastAddress, used on
// the per-packet hot path to avoid re-parsing an address we already hold as a
// net.IP (the IPv4 case, which is the common one). IPv6 defers to the string
// implementation so the (prefix-based) filtering result stays identical.
func isLocalOrMulticastIP(ip net.IP) bool {
	if ip4 := ip.To4(); ip4 != nil {
		return (ip4[0] == 169 && ip4[1] == 254) ||
			(ip4[0] >= 224 && ip4[0] <= 239) ||
			ip4[0] == 127
	}
	return isLocalOrMulticastAddress(ip.String())
}

// Capture manages packet capture from one or more network interfaces.
type Capture struct {
	handles    []*pcap.Handle
	packetChan chan *PacketInfo
	pcap       *pcapWriter
	pcapDir    string
	enablePcap bool
	mu         sync.Mutex
	paused     bool
	chanDrops  *dropCounter
}

// NewCapture creates a new packet capture instance. iface may be a single
// interface name, or "any" to listen on all interfaces. On platforms whose
// libpcap supports the "any" pseudo-device (Linux) we use it directly; otherwise
// (macOS/BSD) we open a handle on every interface and merge them.
func NewCapture(iface string, packetChan chan *PacketInfo) (*Capture, error) {
	var handles []*pcap.Handle

	if iface == "any" {
		// Try the native "any" device first (Linux); fall back to opening every
		// interface (macOS/BSD have no "any").
		if h, err := pcap.OpenLive("any", 1600, true, pcap.BlockForever); err == nil {
			// Force the v1 cooked link type (LINUX_SLL): modern Linux defaults
			// "any" to LINUX_SLL2, which our gopacket version can't decode (and
			// its DLT 276 overflows gopacket's uint8 LinkType). v1 decodes fine;
			// the error is ignored when only v1 is available.
			_ = h.SetLinkType(layers.LinkTypeLinuxSLL)
			handles = append(handles, h)
			log.Printf("  Listening on: all interfaces (native 'any')")
		} else {
			handles = openAllInterfaces()
			if len(handles) == 0 {
				return nil, fmt.Errorf("could not open any interface for '-i any'")
			}
		}
	} else {
		h, err := pcap.OpenLive(iface, 1600, true, pcap.BlockForever)
		if err != nil {
			return nil, fmt.Errorf("failed to open interface %s: %v", iface, err)
		}
		handles = append(handles, h)
	}

	return newCaptureFromHandles(handles, packetChan)
}

// NewCaptureOnDevices creates a capture that listens on exactly the named
// interfaces (used by -interface-filter, which resolves a CIDR to a device
// list). Devices that can't be opened are skipped; an error is returned only if
// none could be opened.
func NewCaptureOnDevices(names []string, packetChan chan *PacketInfo) (*Capture, error) {
	handles := openInterfaces(names)
	if len(handles) == 0 {
		return nil, fmt.Errorf("could not open any of the filtered interfaces: %v", names)
	}
	return newCaptureFromHandles(handles, packetChan)
}

// newCaptureFromHandles builds a Capture from already-opened handles and applies
// the shared pcap-saving policy (disabled when merging multiple handles, since
// one pcap file can hold only one link-layer type).
func newCaptureFromHandles(handles []*pcap.Handle, packetChan chan *PacketInfo) (*Capture, error) {
	c := &Capture{
		handles:    handles,
		packetChan: packetChan,
		pcapDir:    "pcaps",
		enablePcap: true, // Enable pcap saving by default
		chanDrops:  newDropCounter("packet channel"),
	}

	// One shared pcap file can only hold one link-layer type, so saving is only
	// enabled when capturing from a single handle.
	if len(handles) > 1 {
		c.enablePcap = false
		log.Printf("  pcap saving disabled in multi-interface mode (mixed link types)")
	}

	if c.enablePcap {
		if err := os.MkdirAll(c.pcapDir, 0755); err != nil {
			log.Printf("Warning: Failed to create pcaps directory: %v", err)
			c.enablePcap = false
		} else if err := c.createPcapFile(); err != nil {
			log.Printf("Warning: Failed to create pcap file: %v", err)
			c.enablePcap = false
		}
	}

	return c, nil
}

// openAllInterfaces opens a live capture handle on every interface libpcap can
// open (used for "-i any" on platforms without a native "any" device). Devices
// that can't be opened (no permission, virtual, down) are skipped.
func openAllInterfaces() []*pcap.Handle {
	devs, err := pcap.FindAllDevs()
	if err != nil {
		log.Printf("  Failed to enumerate interfaces: %v", err)
		return nil
	}
	var handles []*pcap.Handle
	for _, d := range devs {
		if d.Name == "any" {
			continue
		}
		h, err := pcap.OpenLive(d.Name, 1600, true, pcap.BlockForever)
		if err != nil {
			continue // skip interfaces we can't open
		}
		handles = append(handles, h)
		log.Printf("  Listening on: %s", d.Name)
	}
	return handles
}

// openInterfaces opens a live capture handle on each named interface. Devices
// that can't be opened (no permission, virtual, down) are skipped with a
// warning rather than aborting the whole capture.
func openInterfaces(names []string) []*pcap.Handle {
	var handles []*pcap.Handle
	for _, name := range names {
		h, err := pcap.OpenLive(name, 1600, true, pcap.BlockForever)
		if err != nil {
			log.Printf("  Skipping interface %s: %v", name, err)
			continue
		}
		handles = append(handles, h)
		log.Printf("  Listening on: %s", name)
	}
	return handles
}

// createPcapFile creates a new pcap file with timestamp
func (c *Capture) createPcapFile() error {
	// Close existing writer if open (flushes and closes the old file)
	if c.pcap != nil {
		c.pcap.Close()
	}

	// Generate filename with timestamp
	timestamp := time.Now().Format("2006-01-02_15-04-05")
	filename := filepath.Join(c.pcapDir, fmt.Sprintf("capture_%s.pcap", timestamp))

	// Create file
	file, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("failed to create pcap file: %v", err)
	}

	// Create the buffered async pcap writer (single-handle mode only, so
	// handles[0] is the source). The header is written synchronously inside.
	pw, err := newPcapWriter(file, 1600, c.handles[0].LinkType())
	if err != nil {
		file.Close()
		return fmt.Errorf("failed to write pcap header: %v", err)
	}

	c.pcap = pw

	log.Printf("Created pcap file: %s", filename)
	return nil
}

// Start begins packet capture on every handle and runs until the context is
// cancelled. Each handle gets its own reader goroutine, all feeding the shared
// packet channel.
func (c *Capture) Start(ctx context.Context) {
	log.Println("Packet capture started")
	if c.enablePcap {
		log.Printf("Saving packets to: %s/", c.pcapDir)
	}

	var wg sync.WaitGroup
	for _, h := range c.handles {
		wg.Add(1)
		go func(h *pcap.Handle) {
			defer wg.Done()
			// Lazy + NoCopy: layers are decoded on demand (packet.Layer(...)
			// forces the decode) and the packet buffer is not copied. Anything
			// retained past processing must be copied — see copyPayload in
			// ProcessPacket and the enqueue copy in pcapWriter.WritePacket.
			src := gopacket.NewPacketSource(h, h.LinkType())
			src.DecodeOptions = gopacket.DecodeOptions{Lazy: true, NoCopy: true}
			packets := src.Packets()
			for {
				select {
				case <-ctx.Done():
					return
				case packet, ok := <-packets:
					if !ok {
						return
					}
					if !c.isPaused() {
						c.processPacket(packet)
					}
				}
			}
		}(h)
	}

	<-ctx.Done()
	log.Println("Packet capture stopped")
	// Closing the handles unblocks the gopacket reader goroutines.
	for _, h := range c.handles {
		h.Close()
	}
	wg.Wait()
	if c.pcap != nil {
		c.pcap.Close()
		log.Println("Closed pcap file")
	}
}

// decapOverlay returns the inner packet carried by a VXLAN/Geneve overlay frame
// (the pod-to-pod packet for Kubernetes CNIs), or nil if it can't be decoded.
// The name switch picks the overlay type; only protocols flagged Decap in the
// catalog (VXLAN, Geneve) ever reach this function.
func decapOverlay(packet gopacket.Packet, name string) gopacket.Packet {
	udpLayer := packet.Layer(layers.LayerTypeUDP)
	if udpLayer == nil {
		return nil
	}
	udp, _ := udpLayer.(*layers.UDP)
	if udp == nil || len(udp.Payload) == 0 {
		return nil
	}
	switch name {
	case "VXLAN":
		vx := gopacket.NewPacket(udp.Payload, layers.LayerTypeVXLAN, gopacket.Default)
		if v := vx.Layer(layers.LayerTypeVXLAN); v != nil {
			// The VXLAN payload is a full inner Ethernet frame.
			return gopacket.NewPacket(v.LayerPayload(), layers.LayerTypeEthernet, gopacket.Default)
		}
	case "Geneve":
		gv := gopacket.NewPacket(udp.Payload, layers.LayerTypeGeneve, gopacket.Default)
		if g := gv.Layer(layers.LayerTypeGeneve); g != nil {
			// The Geneve protocol type says whether the inner is Ethernet or IP.
			start := layers.LayerTypeEthernet
			if gen, ok := g.(*layers.Geneve); ok {
				switch gen.Protocol {
				case layers.EthernetTypeIPv4:
					start = layers.LayerTypeIPv4
				case layers.EthernetTypeIPv6:
					start = layers.LayerTypeIPv6
				}
			}
			return gopacket.NewPacket(g.LayerPayload(), start, gopacket.Default)
		}
	}
	return nil
}

// ProcessPacket extracts information from a packet (exported for replay usage)
func ProcessPacket(packet gopacket.Packet) *PacketInfo {
	// Detect protocol first so the multicast filter can be bypassed for
	// broadcast/discovery/topology protocols (mDNS, SSDP, LLDP, …) that would
	// otherwise be dropped as ordinary multicast noise.
	protocol := DetectProtocol(packet)

	// Kubernetes overlay decapsulation: if this is a VXLAN/Geneve tunnel, process
	// the inner (pod-to-pod) packet instead, so the graph shows the real cluster
	// traffic and its endpoints rather than just node-to-node "VXLAN". The
	// decision is driven by the catalog's Decap flag (only VXLAN and Geneve set
	// it); decapOverlay then switches on the name to pick the overlay type.
	if protocol.Decap {
		if inner := decapOverlay(packet, protocol.Name); inner != nil {
			if info := ProcessPacket(inner); info != nil {
				return info
			}
		}
		// Decap failed or the inner packet was filtered: fall through and record
		// the outer tunnel as a node-to-node VXLAN/Geneve flow.
	}

	// The pcap buffer is reused between packets, so any frame bytes we keep must be
	// copied. The copy is deferred to just before each return path that actually
	// keeps the packet, so filtered/dropped packets don't allocate. The copy is
	// capped at maxPayloadCopy: display consumers read at most 2KB (inspector
	// hex/ASCII) and stream reassembly retains 64KB/direction, so a 16KB bound
	// keeps search/stream content nearly whole while bounding per-packet
	// allocation on jumbo frames at high packet rates.
	payload := packet.Data()
	length := len(payload)
	copyPayload := func() []byte {
		n := length
		if n > maxPayloadCopy {
			n = maxPayloadCopy
		}
		c := make([]byte, n)
		copy(c, payload[:n])
		return c
	}

	// Extract the 802.1Q VLAN ID if the frame is tagged (identifiable only when
	// a Dot1Q layer is present; left as 0 otherwise).
	var vlanID uint16
	if d := packet.Layer(layers.LayerTypeDot1Q); d != nil {
		if dot1q, ok := d.(*layers.Dot1Q); ok {
			vlanID = dot1q.VLANIdentifier
		}
	}

	// L2 topology protocols (LLDP/CDP/STP) carry no IP. Synthesize endpoints
	// from the Ethernet MAC addresses so they appear as real graph nodes,
	// enriched with a device name when the protocol advertises one.
	if protocol.LayerNum == 2 && protocol.Name != "ARP" && protocol.Name != "VLAN" {
		srcID, dstID, srcName, dstName, deviceKind, deviceInfo := extractL2Endpoints(packet, protocol)
		if srcID == "" {
			return nil
		}
		return &PacketInfo{
			SrcIP:      srcID,
			DstIP:      dstID,
			Protocol:   protocol,
			Length:     length,
			Payload:    copyPayload(),
			VLANID:     vlanID,
			SrcName:    srcName,
			DstName:    dstName,
			DeviceKind: deviceKind,
			DeviceInfo: deviceInfo,
		}
	}

	// Extract IP addresses. Keep the net.IP forms (when available) so the
	// local/multicast filter can run without re-parsing the string.
	var srcIP, dstIP string
	var srcNetIP, dstNetIP net.IP

	// Try IPv4 first
	if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
		ip, _ := ipLayer.(*layers.IPv4)
		srcIP = ip.SrcIP.String()
		dstIP = ip.DstIP.String()
		srcNetIP, dstNetIP = ip.SrcIP, ip.DstIP
	} else if ipLayer := packet.Layer(layers.LayerTypeIPv6); ipLayer != nil {
		// Try IPv6
		ip, _ := ipLayer.(*layers.IPv6)
		srcIP = ip.SrcIP.String()
		dstIP = ip.DstIP.String()
		srcNetIP, dstNetIP = ip.SrcIP, ip.DstIP
	} else if arpLayer := packet.Layer(layers.LayerTypeARP); arpLayer != nil {
		// Handle ARP packets
		arp, _ := arpLayer.(*layers.ARP)
		srcIP = fmt.Sprintf("%d.%d.%d.%d", arp.SourceProtAddress[0], arp.SourceProtAddress[1],
			arp.SourceProtAddress[2], arp.SourceProtAddress[3])
		dstIP = fmt.Sprintf("%d.%d.%d.%d", arp.DstProtAddress[0], arp.DstProtAddress[1],
			arp.DstProtAddress[2], arp.DstProtAddress[3])
	} else {
		// Skip packets without IP information
		return nil
	}

	// Skip local/multicast addresses (clutters the graph) - except for discovery
	// protocols, whose whole purpose is to advertise to a multicast group. Use the
	// net.IP form when we have it (IPv4/IPv6) to avoid re-parsing; ARP only has the
	// string form.
	srcLocal := isLocalOrMulticastAddress(srcIP)
	if srcNetIP != nil {
		srcLocal = isLocalOrMulticastIP(srcNetIP)
	}
	dstLocal := isLocalOrMulticastAddress(dstIP)
	if dstNetIP != nil {
		dstLocal = isLocalOrMulticastIP(dstNetIP)
	}
	if !protocol.Discovery && (srcLocal || dstLocal) {
		return nil
	}

	// Extract port information from transport layer
	var srcPort, dstPort uint16
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp, _ := tcpLayer.(*layers.TCP)
		srcPort = uint16(tcp.SrcPort)
		dstPort = uint16(tcp.DstPort)
	} else if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		udp, _ := udpLayer.(*layers.UDP)
		srcPort = uint16(udp.SrcPort)
		dstPort = uint16(udp.DstPort)
	}
	// Note: ICMP and ARP don't have ports, so srcPort and dstPort will be 0

	// Ethernet MACs, when present, let the graph anchor a host's identity across
	// IP changes (see graph.recordMACLocked). Absent for link types without an
	// Ethernet header.
	var srcMAC, dstMAC string
	if ethLayer := packet.Layer(layers.LayerTypeEthernet); ethLayer != nil {
		if eth, ok := ethLayer.(*layers.Ethernet); ok {
			srcMAC = eth.SrcMAC.String()
			dstMAC = eth.DstMAC.String()
		}
	}

	return &PacketInfo{
		SrcIP:    srcIP,
		DstIP:    dstIP,
		SrcMAC:   srcMAC,
		DstMAC:   dstMAC,
		SrcPort:  srcPort,
		DstPort:  dstPort,
		Protocol: protocol,
		Length:   length,
		Payload:  copyPayload(),
		VLANID:   vlanID,
	}
}

// extractL2Endpoints derives source/destination node identities for link-layer
// topology protocols (LLDP/CDP/STP) that have no IP. Nodes are keyed by MAC
// address; when the protocol advertises a system/device name it is returned as
// a friendly label for the source node.
func extractL2Endpoints(packet gopacket.Packet, protocol Protocol) (srcID, dstID, srcName, dstName, deviceKind, deviceInfo string) {
	ethLayer := packet.Layer(layers.LayerTypeEthernet)
	if ethLayer == nil {
		return "", "", "", "", "", ""
	}
	eth, _ := ethLayer.(*layers.Ethernet)
	srcID = eth.SrcMAC.String()
	dstID = eth.DstMAC.String()

	// Label the well-known L2 multicast destinations by protocol for readability.
	dstName = protocol.Name + " group"

	// LLDP/CDP advertise the neighbour's identity, role (switch/router), the port
	// you're connected to, and a management address — the basis of a hardware map.
	// Gated on the catalog's L2Endpoints flag (only LLDP and CDP set it); the
	// per-protocol TLV parsing below stays name-switched.
	if protocol.L2Endpoints {
		switch protocol.Name {
		case "LLDP":
			if info, ok := packet.Layer(layers.LayerTypeLinkLayerDiscoveryInfo).(*layers.LinkLayerDiscoveryInfo); ok {
				if info.SysName != "" {
					srcName = info.SysName
				}
				caps := info.SysCapabilities
				if caps.SystemCap.Router || caps.EnabledCap.Router {
					deviceKind = "router"
				} else if caps.SystemCap.Bridge || caps.EnabledCap.Bridge {
					deviceKind = "switch"
				}
				var parts []string
				if disc, ok := packet.Layer(layers.LayerTypeLinkLayerDiscovery).(*layers.LinkLayerDiscovery); ok {
					if p := strings.TrimSpace(string(disc.PortID.ID)); p != "" {
						parts = append(parts, "port "+p)
					}
				}
				if a := mgmtIPString(info.MgmtAddress.Address); a != "" {
					parts = append(parts, "mgmt "+a)
				}
				deviceInfo = strings.Join(parts, " · ")
			}
		case "CDP":
			if cdp, ok := packet.Layer(layers.LayerTypeCiscoDiscoveryInfo).(*layers.CiscoDiscoveryInfo); ok {
				if cdp.DeviceID != "" {
					srcName = cdp.DeviceID
				}
				if cdp.Capabilities.L3Router {
					deviceKind = "router"
				} else if cdp.Capabilities.L2Switch {
					deviceKind = "switch"
				}
				var parts []string
				if p := strings.TrimSpace(cdp.PortID); p != "" {
					parts = append(parts, "port "+p)
				}
				ips := cdp.MgmtAddresses
				if len(ips) == 0 {
					ips = cdp.Addresses
				}
				if len(ips) > 0 {
					parts = append(parts, "mgmt "+ips[0].String())
				}
				deviceInfo = strings.Join(parts, " · ")
			}
		}
	}

	return srcID, dstID, srcName, dstName, deviceKind, deviceInfo
}

// mgmtIPString formats an LLDP management-address byte slice as an IP, or "".
func mgmtIPString(addr []byte) string {
	if len(addr) == 4 || len(addr) == 16 {
		return net.IP(addr).String()
	}
	return ""
}

// Pause pauses packet capture
// SetBPFFilter compiles and installs a libpcap BPF filter on every open handle,
// so filtering happens in the kernel — packets that don't match never reach the
// pcap writer or the graph channel (used by -net to slim a capture to one or
// more subnets). Handles that reject the filter (rare, exotic link types) are
// skipped with a warning; an error is returned only if no handle accepted it.
func (c *Capture) SetBPFFilter(expr string) error {
	if expr == "" {
		return nil
	}
	applied := 0
	var lastErr error
	for _, h := range c.handles {
		if err := h.SetBPFFilter(expr); err != nil {
			lastErr = err
			log.Printf("  Warning: BPF filter %q rejected on a handle: %v", expr, err)
			continue
		}
		applied++
	}
	if applied == 0 {
		return fmt.Errorf("BPF filter %q could not be applied to any interface: %v", expr, lastErr)
	}
	return nil
}

func (c *Capture) Pause() {
	c.mu.Lock()
	c.paused = true
	c.mu.Unlock()
	log.Println("Packet capture paused")
}

// Resume resumes packet capture
func (c *Capture) Resume() {
	c.mu.Lock()
	c.paused = false
	c.mu.Unlock()
	log.Println("Packet capture resumed")
}

// isPaused reports whether capture is currently paused (safe across goroutines).
func (c *Capture) isPaused() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.paused
}

// processPacket extracts information from a packet and sends it to the channel
func (c *Capture) processPacket(packet gopacket.Packet) {
	// Queue the packet for async pcap writing if enabled (non-blocking; drops
	// are counted and rate-limited-logged inside the writer)
	if c.enablePcap && c.pcap != nil {
		metadata := packet.Metadata()
		c.pcap.WritePacket(metadata.CaptureInfo, packet.Data())
	}

	// Process packet using shared function
	packetInfo := ProcessPacket(packet)
	if packetInfo == nil {
		return
	}

	// Send packet info to channel (non-blocking)
	select {
	case c.packetChan <- packetInfo:
	default:
		// Channel is full, drop packet to avoid blocking
		c.chanDrops.add()
	}
}
