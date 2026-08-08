package replay

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"etherchimp/capture"
	"etherchimp/graph"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

// PcapInfo contains metadata about a pcap file
type PcapInfo struct {
	Filename    string    `json:"filename"`
	Path        string    `json:"path"`
	StartTime   time.Time `json:"startTime"`
	EndTime     time.Time `json:"endTime"`
	PacketCount int       `json:"packetCount"`
	FileSize    int64     `json:"fileSize"`
	ModTime     time.Time `json:"modTime"`
	DurationSec float64   `json:"durationSec"`
}

// PacketWithTime represents a packet with its timestamp
type PacketWithTime struct {
	Info      *capture.PacketInfo
	Timestamp time.Time
}

// Reader manages pcap file reading for replay
type Reader struct {
	handle    *pcap.Handle
	packets   []PacketWithTime
	startTime time.Time
	endTime   time.Time
}

// GetPcapFiles scans the pcaps directory and returns info about available files
func GetPcapFiles(pcapDir string) ([]PcapInfo, error) {
	files, err := os.ReadDir(pcapDir)
	if err != nil {
		return nil, fmt.Errorf("failed to read pcaps directory: %v", err)
	}

	var pcapInfos []PcapInfo

	for _, file := range files {
		if file.IsDir() || filepath.Ext(file.Name()) != ".pcap" {
			continue
		}

		fullPath := filepath.Join(pcapDir, file.Name())
		info, err := file.Info()
		if err != nil {
			continue
		}

		// Quick scan to get packet metadata
		metadata, err := scanPcapMetadata(fullPath)
		if err != nil {
			// File might be corrupted, skip
			continue
		}

		pcapInfos = append(pcapInfos, PcapInfo{
			Filename:    file.Name(),
			Path:        fullPath,
			StartTime:   metadata.StartTime,
			EndTime:     metadata.EndTime,
			PacketCount: metadata.PacketCount,
			FileSize:    info.Size(),
			ModTime:     info.ModTime(),
			DurationSec: metadata.EndTime.Sub(metadata.StartTime).Seconds(),
		})
	}

	// Sort by modification time, newest first
	sort.Slice(pcapInfos, func(i, j int) bool {
		return pcapInfos[i].ModTime.After(pcapInfos[j].ModTime)
	})

	return pcapInfos, nil
}

// GetFileInfo returns metadata for a single pcap file (the same scan used for
// directory listings).
func GetFileInfo(path string) (PcapInfo, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return PcapInfo{}, err
	}
	metadata, err := scanPcapMetadata(path)
	if err != nil {
		return PcapInfo{}, err
	}
	return PcapInfo{
		Filename:    filepath.Base(path),
		Path:        path,
		StartTime:   metadata.StartTime,
		EndTime:     metadata.EndTime,
		PacketCount: metadata.PacketCount,
		FileSize:    fi.Size(),
		ModTime:     fi.ModTime(),
		DurationSec: metadata.EndTime.Sub(metadata.StartTime).Seconds(),
	}, nil
}

// scanPcapMetadata does a quick scan to get timestamps and packet count
func scanPcapMetadata(filename string) (PcapInfo, error) {
	handle, err := pcap.OpenOffline(filename)
	if err != nil {
		return PcapInfo{}, err
	}
	defer handle.Close()

	var startTime, endTime time.Time
	packetCount := 0

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	for packet := range packetSource.Packets() {
		timestamp := packet.Metadata().Timestamp

		if packetCount == 0 {
			startTime = timestamp
		}
		endTime = timestamp
		packetCount++
	}

	return PcapInfo{
		StartTime:   startTime,
		EndTime:     endTime,
		PacketCount: packetCount,
	}, nil
}

// NewReader creates a new pcap replay reader
func NewReader(filename string) (*Reader, error) {
	return NewReaderFiltered(filename, "")
}

// NewReaderFiltered is NewReader with an optional libpcap BPF filter (e.g. the
// -net subnet filter) applied before packets are loaded, so non-matching packets
// never enter the graph.
func NewReaderFiltered(filename, bpf string) (*Reader, error) {
	handle, err := pcap.OpenOffline(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to open pcap file: %v", err)
	}
	if bpf != "" {
		if err := handle.SetBPFFilter(bpf); err != nil {
			handle.Close()
			return nil, fmt.Errorf("failed to apply filter %q: %v", bpf, err)
		}
	}

	reader := &Reader{
		handle:  handle,
		packets: make([]PacketWithTime, 0),
	}

	// Pre-load all packets for fast seeking
	if err := reader.loadPackets(); err != nil {
		handle.Close()
		return nil, err
	}

	return reader, nil
}

// loadPackets reads all packets from the pcap file
func (r *Reader) loadPackets() error {
	packetSource := gopacket.NewPacketSource(r.handle, r.handle.LinkType())

	for packet := range packetSource.Packets() {
		packetInfo := capture.ProcessPacket(packet)
		if packetInfo == nil {
			continue
		}

		timestamp := packet.Metadata().Timestamp

		if len(r.packets) == 0 {
			r.startTime = timestamp
		}
		r.endTime = timestamp

		r.packets = append(r.packets, PacketWithTime{
			Info:      packetInfo,
			Timestamp: timestamp,
		})
	}

	return nil
}

// GetPacketsUpToTime returns all packets up to a given timestamp offset
func (r *Reader) GetPacketsUpToTime(offsetSeconds float64) []PacketWithTime {
	if len(r.packets) == 0 {
		return []PacketWithTime{}
	}

	targetTime := r.startTime.Add(time.Duration(offsetSeconds * float64(time.Second)))

	// Binary search for efficiency
	idx := sort.Search(len(r.packets), func(i int) bool {
		return r.packets[i].Timestamp.After(targetTime)
	})

	return r.packets[:idx]
}

// GetDuration returns the total duration of the capture
func (r *Reader) GetDuration() time.Duration {
	return r.endTime.Sub(r.startTime)
}

// SearchMatch describes one packet matching a replay search query, with its
// position in the capture so the client can jump the timeline to it.
type SearchMatch struct {
	Index     int     `json:"index"` // packet index in file order (0-based)
	OffsetSec float64 `json:"offsetSec"`
	Src       string  `json:"src"`
	Dst       string  `json:"dst"`
	SrcPort   uint16  `json:"srcPort"`
	DstPort   uint16  `json:"dstPort"`
	Protocol  string  `json:"protocol"`
	Length    int     `json:"length"`
	Field     string  `json:"field"`  // what matched: "host", "protocol", or "payload"
	Preview   string  `json:"preview"` // context around a payload match, empty otherwise
}

// SearchPackets scans the whole capture for a case-insensitive substring match
// on endpoint IPs/names, protocol name, or raw payload bytes, returning at most
// maxResults matches in file order.
func (r *Reader) SearchPackets(query string, maxResults int) []SearchMatch {
	matches := make([]SearchMatch, 0)
	if query == "" || maxResults <= 0 {
		return matches
	}
	queryLower := strings.ToLower(query)
	queryBytes := []byte(queryLower)
	dnsCache := make(map[string]string) // lazily resolved, shared with resolveIPSync

	for i, pwt := range r.packets {
		if len(matches) >= maxResults {
			break
		}
		pkt := pwt.Info
		m := SearchMatch{
			Index:     i,
			OffsetSec: pwt.Timestamp.Sub(r.startTime).Seconds(),
			Src:       pkt.SrcIP,
			Dst:       pkt.DstIP,
			SrcPort:   pkt.SrcPort,
			DstPort:   pkt.DstPort,
			Protocol:  pkt.Protocol.Name,
			Length:    pkt.Length,
		}
		switch {
		case strings.Contains(strings.ToLower(pkt.SrcIP), queryLower),
			strings.Contains(strings.ToLower(pkt.DstIP), queryLower),
			pkt.SrcName != "" && strings.Contains(strings.ToLower(pkt.SrcName), queryLower),
			pkt.DstName != "" && strings.Contains(strings.ToLower(pkt.DstName), queryLower):
			m.Field = "host"
		case strings.Contains(strings.ToLower(pkt.Protocol.Name), queryLower):
			m.Field = "protocol"
		default:
			// Hostnames shown in the graph come from reverse DNS, so match
			// against the resolved names too (cached per unique IP).
			if strings.Contains(strings.ToLower(resolveIPSync(pkt.SrcIP, dnsCache)), queryLower) ||
				strings.Contains(strings.ToLower(resolveIPSync(pkt.DstIP, dnsCache)), queryLower) {
				m.Field = "host"
				break
			}
			pos := payloadMatchPos(pkt.Payload, queryBytes)
			if pos < 0 {
				continue
			}
			m.Field = "payload"
			m.Preview = payloadPreview(pkt.Payload, pos, len(queryBytes))
		}
		matches = append(matches, m)
	}
	return matches
}

// payloadMatchPos finds the first case-insensitive (ASCII) occurrence of
// query in payload, or -1.
func payloadMatchPos(payload, query []byte) int {
	if len(query) == 0 || len(query) > len(payload) {
		return -1
	}
	for i := 0; i+len(query) <= len(payload); i++ {
		found := true
		for j := 0; j < len(query); j++ {
			b := payload[i+j]
			if b >= 'A' && b <= 'Z' {
				b += 32
			}
			if b != query[j] {
				found = false
				break
			}
		}
		if found {
			return i
		}
	}
	return -1
}

// payloadPreview renders printable context around a payload match.
func payloadPreview(payload []byte, matchPos, matchLen int) string {
	start := matchPos - 20
	if start < 0 {
		start = 0
	}
	end := matchPos + matchLen + 20
	if end > len(payload) {
		end = len(payload)
	}
	var b strings.Builder
	for i := start; i < end; i++ {
		c := payload[i]
		if c >= 32 && c <= 126 {
			b.WriteByte(c)
		} else {
			b.WriteByte('.')
		}
	}
	preview := b.String()
	if len(preview) > 50 {
		preview = preview[:47] + "..."
	}
	return preview
}

// Close closes the pcap handle
func (r *Reader) Close() error {
	if r.handle != nil {
		r.handle.Close()
	}
	return nil
}

// BuildSnapshotFromPackets creates a graph snapshot from a list of packets.
// dnsCache memoizes reverse-DNS lookups; pass a shared cache (e.g. the replay
// session's) so scrubbing many offsets doesn't re-resolve the same IPs.
func BuildSnapshotFromPackets(packetsWithTime []PacketWithTime, dnsCache map[string]string) graph.GraphSnapshot {
	// Create temporary graph manager for replay
	tempGraph := graph.NewManager()

	if dnsCache == nil {
		dnsCache = make(map[string]string)
	}

	// Process each packet
	for _, pwt := range packetsWithTime {
		pkt := pwt.Info

		// Resolve hostnames with simple caching. Endpoints without a
		// resolvable IP (e.g. L2 topology nodes) carry a friendly name on
		// the packet, which takes precedence over DNS.
		srcHostname := pkt.SrcName
		if srcHostname == "" {
			srcHostname = resolveIPSync(pkt.SrcIP, dnsCache)
		}
		dstHostname := pkt.DstName
		if dstHostname == "" {
			dstHostname = resolveIPSync(pkt.DstIP, dnsCache)
		}

		// Update graph
		tempGraph.AddOrUpdateNode(pkt.SrcIP, srcHostname, pkt.Length)
		tempGraph.AddOrUpdateNode(pkt.DstIP, dstHostname, pkt.Length)
		tempGraph.AddOrUpdateEdge(pkt.SrcIP, pkt.DstIP, pkt.Protocol, pkt.Length)
		tempGraph.AddPacket(pkt)
	}

	// Commit role classifications so replay views style roles the same way the
	// live view does (SnapshotRaw no longer commits them as a side effect).
	tempGraph.CommitRoles()
	return tempGraph.GetSnapshot()
}

// resolveIPSync performs synchronous DNS resolution with caching
func resolveIPSync(ip string, cache map[string]string) string {
	// Check cache first
	if hostname, ok := cache[ip]; ok {
		return hostname
	}

	// Perform reverse lookup
	names, err := net.LookupAddr(ip)
	if err != nil || len(names) == 0 {
		cache[ip] = ip
		return ip
	}

	hostname := names[0]
	// Remove trailing dot if present
	hostname = strings.TrimSuffix(hostname, ".")

	// Cache the result
	cache[ip] = hostname

	return hostname
}
