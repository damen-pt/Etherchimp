package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	mrand "math/rand"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"etherchimp/capture"
	"etherchimp/daemon"
	"etherchimp/graph"
	"etherchimp/replay"
	"etherchimp/server"
	"etherchimp/store"
	"etherchimp/stream"

	"github.com/google/gopacket/pcap"
)

func main() {
	// Parse command-line flags
	iface := flag.String("i", "", "Network interface to capture from, or 'any' for all interfaces (required for capture mode)")
	replayFile := flag.String("f", "", "Pcap file path for replay-only mode (disables live capture)")
	synthCount := flag.Int("synth", 0, "DEV: serve a synthetic graph of N hosts with continuous random traffic (no capture; for scale testing)")
	synthRate := flag.Int("synth-rate", 2000, "DEV: synthetic packets per second (with -synth)")
	port := flag.Int("p", 8443, "HTTPS server port")
	bindIP := flag.String("ip", "0.0.0.0", "IP address to bind server to")
	daemonCmd := flag.String("daemon", "", "Daemon command: start, stop, pause, resume, status, rotate-logs, log-status, cleanup-logs")
	background := flag.Bool("background", false, "Run in background (internal use)")

	// SSH capture flags
	sshHost := flag.String("ssh", "", "SSH host for remote capture (host:port format, e.g., 192.168.1.1:22)")
	sshPrivateKey := flag.String("pkey", "", "Path to SSH private key file (for key-based authentication)")
	sshUser := flag.String("user", "", "SSH username")
	sshPass := flag.String("pass", "", "SSH password (for password-based authentication)")

	// TLS certificate flags
	var hostnames flagSlice
	flag.Var(&hostnames, "hostname", "Hostname or IP for TLS certificate (can be specified multiple times)")

	// Rate limiting flags
	rateLimit := flag.Float64("rate-limit", 10.0, "API requests per second per client")
	rateBurst := flag.Int("rate-burst", 50, "Maximum burst size for rate limiting")

	// Persistence flags (SQLite; opt-in — unset means no disk writes beyond overrides.json)
	dbPath := flag.String("db", "", "SQLite database path for capture persistence (pcap cache, timeline, packet index). Empty = disabled")
	dbRetention := flag.Duration("db-retention", 168*time.Hour, "Prune stored captures older than this (with -db)")
	dbPackets := flag.String("db-packets", "true", "Per-packet index: true, false, or 1/N sampling (with -db)")
	dbBucket := flag.Int("db-bucket", 1, "Flow-bucket width in seconds for the timeline (with -db)")

	// Log rotation flags
	logMaxSize := flag.String("log-max-size", "10MB", "Maximum log file size before rotation (e.g., 10MB, 1GB)")
	logMaxBackups := flag.Int("log-max-backups", 5, "Maximum number of backup log files to keep")
	logMaxAge := flag.Int("log-max-age", 30, "Maximum age of backup log files in days (0 = no limit)")
	logCompress := flag.Bool("log-compress", true, "Compress rotated log files")
	logCheckInterval := flag.Int("log-check-interval", 60, "Log rotation check interval in seconds")
	enableLogRotation := flag.Bool("enable-log-rotation", true, "Enable automatic log rotation")

	flag.Parse()

	// Build log rotation config from flags
	logRotateConfig := buildLogRotateConfig(*logMaxSize, *logMaxBackups, *logMaxAge, *logCompress, *logCheckInterval)

	// Handle daemon commands
	if *daemonCmd != "" {
		handleDaemonCommand(*daemonCmd, logRotateConfig)
		return
	}

	// Setup logging for background mode
	if *background {
		if err := daemon.SetupLogging(true); err != nil {
			log.Fatalf("Failed to setup logging: %v", err)
		}
		// Ensure PID file is removed on exit
		defer daemon.RemovePIDFileOnExit()

		// Start log rotation if enabled
		if *enableLogRotation {
			if err := daemon.StartLogRotation(logRotateConfig); err != nil {
				log.Printf("Warning: Failed to start log rotation: %v", err)
			} else {
				defer daemon.StopLogRotation()
			}
		}
	}

	// Determine mode based on flags
	replayOnlyMode := *replayFile != ""
	sshCaptureMode := *sshHost != ""
	synthMode := *synthCount > 0

	// Validate flags based on mode
	if synthMode {
		if *iface != "" || replayOnlyMode || sshCaptureMode {
			fmt.Println("Error: -synth cannot be combined with -i, -f or -ssh")
			os.Exit(1)
		}
	} else if replayOnlyMode {
		// Replay-only mode: -f is specified, -i and -ssh are not allowed
		if *iface != "" {
			fmt.Println("Error: Cannot use -i (interface) with -f (replay file)")
			fmt.Println("  -f enables replay-only mode which does not capture from interfaces")
			os.Exit(1)
		}
		if sshCaptureMode {
			fmt.Println("Error: Cannot use -ssh with -f (replay file)")
			fmt.Println("  -f enables replay-only mode which does not capture from remote hosts")
			os.Exit(1)
		}

		// Validate replay file exists
		if _, err := os.Stat(*replayFile); os.IsNotExist(err) {
			log.Fatalf("Replay file not found: %s", *replayFile)
		}
	} else if sshCaptureMode {
		// SSH capture mode: validate SSH flags
		if *iface == "" {
			fmt.Println("Error: -i (interface) is required for SSH capture mode")
			fmt.Println("  Specify the remote interface to capture from")
			os.Exit(1)
		}
		if *sshUser == "" {
			fmt.Println("Error: -user is required for SSH capture mode")
			os.Exit(1)
		}
		if *sshPrivateKey == "" && *sshPass == "" {
			fmt.Println("Error: Either -pkey (private key) or -pass (password) is required for SSH capture")
			os.Exit(1)
		}
		if *sshPrivateKey != "" && *sshPass != "" {
			fmt.Println("Error: Cannot use both -pkey and -pass. Choose one authentication method")
			os.Exit(1)
		}
		// Validate private key file exists if specified
		if *sshPrivateKey != "" {
			if _, err := os.Stat(*sshPrivateKey); os.IsNotExist(err) {
				log.Fatalf("SSH private key file not found: %s", *sshPrivateKey)
			}
		}
	} else {
		// Local capture mode: -i is required
		if *iface == "" {
			fmt.Println("Error: One of the following is required:")
			fmt.Println("  -i: Network interface for live capture mode")
			fmt.Println("  -f: Pcap file for replay-only mode")
			fmt.Println("  -ssh: SSH host for remote capture mode (requires -i, -user, and -pkey or -pass)")
			flag.Usage()
			os.Exit(1)
		}

		// Validate the interface exists. "any" is a special value (listen on all
		// interfaces) and is not a real device, so it skips this check.
		if *iface != "any" {
			devices, err := pcap.FindAllDevs()
			if err != nil {
				log.Fatalf("Failed to enumerate network interfaces: %v", err)
			}

			interfaceExists := false
			for _, device := range devices {
				if device.Name == *iface {
					interfaceExists = true
					break
				}
			}

			if !interfaceExists {
				log.Fatalf("Network interface '%s' not found. Available interfaces:", *iface)
			}
		}
	}

	// Create context for graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Initialize graph manager
	graphMgr := graph.NewManager()

	// Initialize stream manager (track last 1000 streams)
	streamMgr := stream.NewManager(1000)

	// Optional persistence backend. A nil *store.Store is valid everywhere
	// downstream (all methods no-op), so no call site needs to guard on -db.
	var db *store.Store
	if *dbPath != "" {
		packetEvery, err := parsePacketSampling(*dbPackets)
		if err != nil {
			log.Fatalf("Invalid -db-packets value %q: %v", *dbPackets, err)
		}
		db, err = store.Open(*dbPath, store.Options{
			BucketSeconds: *dbBucket,
			PacketEvery:   packetEvery,
			Retention:     *dbRetention,
		})
		if err != nil {
			log.Fatalf("Failed to open database %s: %v", *dbPath, err)
		}
		defer db.Close()
		log.Printf("  Persistence: %s (packet index: %s, bucket: %ds, retention: %s)",
			*dbPath, *dbPackets, *dbBucket, *dbRetention)
	}

	// captureID is the DB session for whatever ingest mode runs below (0 = none).
	var captureID int64

	if synthMode {
		// SYNTHETIC MODE (dev): no capture, generated topology + traffic.
		log.Printf("Starting etherchimp in SYNTHETIC mode...")
		log.Printf("  Hosts: %d, rate: %d pkt/s", *synthCount, *synthRate)
		log.Printf("  Server: https://%s:%d", *bindIP, *port)
		captureID = beginCaptureSession(db, "synth", fmt.Sprintf("synth-%d", *synthCount), store.FileMeta{})
		go runSynthetic(ctx, graphMgr, *synthCount, *synthRate, db, captureID)
	} else if replayOnlyMode {
		// REPLAY-ONLY MODE
		log.Printf("Starting etherchimp in REPLAY-ONLY mode...")
		log.Printf("  Replay file: %s", *replayFile)
		log.Printf("  Server: https://%s:%d", *bindIP, *port)

		// Pcap cache: if this exact file was fully ingested before, load the
		// stored aggregates instead of re-parsing packet by packet.
		cacheHit := false
		var meta store.FileMeta
		if db.Enabled() {
			var err error
			meta, err = store.ComputeFileMeta(*replayFile)
			if err != nil {
				log.Printf("  Warning: cannot fingerprint replay file, cache disabled: %v", err)
			} else if capID, ok := db.FindCompletePcap(filepath.Base(*replayFile), meta); ok {
				start := time.Now()
				storedNodes, storedEdges, err := db.LoadAggregates(capID)
				if err != nil {
					log.Printf("  Warning: cache load failed, falling back to parse: %v", err)
				} else {
					graphMgr.BulkLoad(store.BulkNodes(storedNodes), store.BulkEdges(storedEdges))
					log.Printf("  Cache hit: %d nodes / %d edges from capture #%d in %s",
						len(storedNodes), len(storedEdges), capID, time.Since(start).Round(time.Millisecond))
					captureID = capID
					cacheHit = true
				}
			}
		}

		if !cacheHit {
			// Load the initial pcap file and populate the graph
			reader, err := replay.NewReader(*replayFile)
			if err != nil {
				log.Fatalf("Failed to load replay file: %v", err)
			}

			// Get all packets from the file (full replay)
			allPackets := reader.GetPacketsUpToTime(reader.GetDuration().Seconds() + 1)
			reader.Close()

			log.Printf("  Loaded %d packets from replay file", len(allPackets))
			log.Printf("  Duration: %.2f seconds", reader.GetDuration().Seconds())

			var ingestID int64
			if meta.Hash != "" {
				ingestID = beginCaptureSession(db, "pcap", filepath.Base(*replayFile), meta)
			}

			// Populate graph with all packets
			for _, pwt := range allPackets {
				processPacket(pwt.Info, pwt.Timestamp, graphMgr, streamMgr, nil, db, ingestID, true)
			}

			if ingestID != 0 {
				if err := db.EndCapture(ingestID, true); err != nil {
					log.Printf("  Warning: failed to finalize capture session: %v", err)
				} else {
					log.Printf("  Capture stored as #%d (next replay of this file is instant)", ingestID)
				}
				captureID = ingestID
			}
		}

		log.Printf("  Stream tracking: enabled")
	} else if sshCaptureMode {
		// SSH CAPTURE MODE
		log.Printf("Starting etherchimp in SSH CAPTURE mode...")
		log.Printf("  SSH Host: %s", *sshHost)
		log.Printf("  Remote Interface: %s", *iface)
		log.Printf("  SSH User: %s", *sshUser)
		if *sshPrivateKey != "" {
			log.Printf("  Auth: Public Key (%s)", *sshPrivateKey)
		} else {
			log.Printf("  Auth: Password")
		}
		log.Printf("  Server: https://%s:%d", *bindIP, *port)
		log.Printf("  Stream tracking: enabled")

		// Start DNS resolver
		dnsResolver := graph.NewDNSResolver()
		dnsResolver.Start(ctx)

		// Start decay manager
		decayMgr := graph.NewDecayManager(graphMgr, 60) // 60 second timeout
		decayMgr.Start(ctx)

		// Initialize SSH packet capture
		packetChan := make(chan *capture.PacketInfo, 1000)
		sshConfig := capture.SSHCaptureConfig{
			Host:       *sshHost,
			Interface:  *iface,
			PrivateKey: *sshPrivateKey,
			Username:   *sshUser,
			Password:   *sshPass,
		}
		sshCaptureEngine, err := capture.NewSSHCapture(sshConfig, packetChan)
		if err != nil {
			log.Fatalf("Failed to initialize SSH capture: %v", err)
		}

		// Setup signal handlers for pause/resume
		pauseSigChan := make(chan os.Signal, 1)
		resumeSigChan := make(chan os.Signal, 1)
		signal.Notify(pauseSigChan, syscall.SIGUSR1)
		signal.Notify(resumeSigChan, syscall.SIGUSR2)

		// Handle pause/resume signals
		go func() {
			for {
				select {
				case <-pauseSigChan:
					log.Println("Received pause signal")
					sshCaptureEngine.Pause()
				case <-resumeSigChan:
					log.Println("Received resume signal")
					sshCaptureEngine.Resume()
				case <-ctx.Done():
					return
				}
			}
		}()

		// Start SSH packet capture
		go sshCaptureEngine.Start(ctx)

		captureID = beginCaptureSession(db, "ssh", *sshHost+"/"+*iface, store.FileMeta{})

		// Process packets and update graph
		go func() {
			for {
				select {
				case <-ctx.Done():
					return
				case pkt := <-packetChan:
					processPacket(pkt, time.Now(), graphMgr, streamMgr, dnsResolver, db, captureID, false)
				}
			}
		}()
	} else {
		// LOCAL CAPTURE MODE (original behavior)
		log.Printf("Starting etherchimp...")
		log.Printf("  Interface: %s", *iface)
		log.Printf("  Server: https://%s:%d", *bindIP, *port)
		log.Printf("  Stream tracking: enabled")

		// Start DNS resolver
		dnsResolver := graph.NewDNSResolver()
		dnsResolver.Start(ctx)

		// Start decay manager
		decayMgr := graph.NewDecayManager(graphMgr, 60) // 60 second timeout
		decayMgr.Start(ctx)

		// Initialize packet capture
		packetChan := make(chan *capture.PacketInfo, 1000)
		captureEngine, err := capture.NewCapture(*iface, packetChan)
		if err != nil {
			log.Fatalf("Failed to initialize packet capture: %v", err)
		}

		// Setup signal handlers for pause/resume
		pauseSigChan := make(chan os.Signal, 1)
		resumeSigChan := make(chan os.Signal, 1)
		signal.Notify(pauseSigChan, syscall.SIGUSR1)
		signal.Notify(resumeSigChan, syscall.SIGUSR2)

		// Handle pause/resume signals
		go func() {
			for {
				select {
				case <-pauseSigChan:
					log.Println("Received pause signal")
					captureEngine.Pause()
				case <-resumeSigChan:
					log.Println("Received resume signal")
					captureEngine.Resume()
				case <-ctx.Done():
					return
				}
			}
		}()

		// Start packet capture
		go captureEngine.Start(ctx)

		captureID = beginCaptureSession(db, "live", *iface, store.FileMeta{})

		// Process packets and update graph
		go func() {
			for {
				select {
				case <-ctx.Done():
					return
				case pkt := <-packetChan:
					processPacket(pkt, time.Now(), graphMgr, streamMgr, dnsResolver, db, captureID, false)
				}
			}
		}()
	}

	// Build server config with rate limiting
	serverConfig := server.ServerConfig{
		BindIP: *bindIP,
		Port:   *port,
		RateLimitConfig: server.RateLimitConfig{
			RequestsPerSecond: *rateLimit,
			BurstSize:         *rateBurst,
			CleanupInterval:   5 * time.Minute,
			ClientMaxAge:      10 * time.Minute,
		},
		StreamMgr:      streamMgr,
		ReplayOnlyMode: replayOnlyMode || synthMode,
		Hostnames:      hostnames,
		DB:             db,
		CaptureID:      captureID,
	}

	// Initialize and start HTTPS server
	srv := server.NewServerWithConfig(serverConfig, graphMgr)
	go func() {
		if err := srv.Start(); err != nil && err != http.ErrServerClosed {
			// Fatalf would os.Exit and skip the deferred db.Close() flush; a
			// real startup failure warrants it, a graceful Shutdown does not.
			log.Fatalf("Server failed: %v", err)
		}
	}()

	if synthMode {
		log.Printf("Synthetic server started. Visit https://%s:%d (accept the self-signed certificate warning)", *bindIP, *port)
	} else if replayOnlyMode {
		log.Printf("Replay-only server started. Visit https://%s:%d (accept the self-signed certificate warning)", *bindIP, *port)
		log.Printf("Live capture is disabled. Use the web UI to analyze the loaded pcap file.")
	} else {
		log.Printf("Server started successfully. Visit https://%s:%d (accept the self-signed certificate warning)", *bindIP, *port)
	}
	log.Printf("Press Ctrl+C to stop...")

	// Wait for interrupt signal
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	<-sigChan

	log.Println("Shutting down gracefully...")
	cancel()
	// Close out the persistence session before the process exits: flush pending
	// writes and mark the session cleanly ended (replay sessions were already
	// finalized at ingest time).
	if db.Enabled() && captureID != 0 && !replayOnlyMode {
		if err := db.EndCapture(captureID, true); err != nil {
			log.Printf("Failed to finalize capture session: %v", err)
		}
	}
	// Bound the wait so a slow/streaming in-flight request can't hang shutdown.
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		log.Printf("Graceful shutdown timed out: %v", err)
	}
	log.Println("Shutdown complete")
}

// handleDaemonCommand handles daemon control commands
func handleDaemonCommand(cmd string, logConfig daemon.LogRotateConfig) {
	switch cmd {
	case "start":
		if err := daemon.Daemonize(); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to start daemon: %v\n", err)
			os.Exit(1)
		}
	case "stop":
		if err := daemon.Stop(); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to stop daemon: %v\n", err)
			os.Exit(1)
		}
	case "pause":
		if err := daemon.Pause(); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to pause daemon: %v\n", err)
			os.Exit(1)
		}
	case "resume":
		if err := daemon.Resume(); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to resume daemon: %v\n", err)
			os.Exit(1)
		}
	case "status":
		daemon.Status()
	case "rotate-logs":
		fmt.Println("Rotating logs...")
		if err := daemon.RotateLogs(logConfig); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to rotate logs: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("Log rotation complete")
	case "log-status":
		daemon.GetLogRotateStatus()
	case "cleanup-logs":
		fmt.Println("Cleaning up all log files...")
		if err := daemon.CleanupAllLogs(); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to cleanup logs: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("Log cleanup complete")
	default:
		fmt.Fprintf(os.Stderr, "Unknown daemon command: %s\n", cmd)
		fmt.Println("Valid commands: start, stop, pause, resume, status, rotate-logs, log-status, cleanup-logs")
		os.Exit(1)
	}
}

// buildLogRotateConfig parses CLI flags into a LogRotateConfig
func buildLogRotateConfig(maxSize string, maxBackups, maxAge int, compress bool, checkInterval int) daemon.LogRotateConfig {
	config := daemon.DefaultLogRotateConfig()

	// Parse size string
	if size, err := daemon.ParseSizeString(maxSize); err == nil && size > 0 {
		config.MaxSizeBytes = size
	}

	if maxBackups >= 0 {
		config.MaxBackups = maxBackups
	}
	if maxAge >= 0 {
		config.MaxAgeDays = maxAge
	}
	config.Compress = compress
	if checkInterval > 0 {
		config.CheckInterval = time.Duration(checkInterval) * time.Second
	}

	return config
}

// processPacket is the single packet ingest path shared by local capture, SSH
// capture, and pcap replay: hostname resolution, graph/stream updates, and the
// optional persistence hook. It runs outside the graph Manager's lock and sees
// raw endpoint IDs before DNS merging mutates them, which is exactly what the
// store's aggregates need. dnsResolver is nil in replay mode. syncIndex makes
// the packet-index write blocking (complete index) instead of best-effort —
// only offline ingest (replay) should set it.
func processPacket(pkt *capture.PacketInfo, ts time.Time, graphMgr *graph.Manager,
	streamMgr *stream.Manager, dnsResolver *graph.DNSResolver, db *store.Store, captureID int64, syncIndex bool) {
	// Resolve hostnames asynchronously. Endpoints without a resolvable IP
	// (e.g. L2 topology nodes) carry a friendly name on the packet, which
	// takes precedence over DNS.
	srcHostname := pkt.SrcName
	if srcHostname == "" && dnsResolver != nil {
		srcHostname = dnsResolver.Resolve(pkt.SrcIP)
	}
	dstHostname := pkt.DstName
	if dstHostname == "" && dnsResolver != nil {
		dstHostname = dnsResolver.Resolve(pkt.DstIP)
	}

	// Update graph: nodes, edge, port observations, device identity, and the
	// packet store in one combined call — a single manager lock acquisition on
	// the hot path instead of five.
	graphMgr.Ingest(pkt, srcHostname, dstHostname)

	// Add packet to stream tracking
	streamMgr.AddPacket(pkt)

	if captureID != 0 {
		ev := store.PacketEvent{
			CaptureID:  captureID,
			TS:         ts,
			Src:        pkt.SrcIP,
			Dst:        pkt.DstIP,
			SrcHost:    srcHostname,
			DstHost:    dstHostname,
			SrcPort:    pkt.SrcPort,
			DstPort:    pkt.DstPort,
			Proto:      pkt.Protocol.Name,
			Length:     pkt.Length,
			VLAN:       pkt.VLANID,
			PcapOffset: -1,
		}
		if syncIndex {
			db.RecordPacketSync(ev)
		} else {
			db.RecordPacket(ev)
		}
	}
}

// parsePacketSampling parses -db-packets: "true" (every packet), "false"/"0"
// (aggregates only), or "1/N" (one packet row in N).
func parsePacketSampling(v string) (int, error) {
	switch strings.ToLower(v) {
	case "true", "1", "all":
		return 1, nil
	case "false", "0", "off", "none":
		return 0, nil
	}
	if rest, ok := strings.CutPrefix(v, "1/"); ok {
		n, err := strconv.Atoi(rest)
		if err != nil || n < 1 {
			return 0, fmt.Errorf("expected true, false, or 1/N")
		}
		return n, nil
	}
	return 0, fmt.Errorf("expected true, false, or 1/N")
}

// beginCaptureSession opens a persistence session for one ingest mode,
// logging (not failing) when the session can't be recorded. Returns 0 when
// persistence is disabled — the shared "no session" value every RecordPacket
// call site already understands.
func beginCaptureSession(db *store.Store, kind, source string, meta store.FileMeta) int64 {
	if !db.Enabled() {
		return 0
	}
	id, err := db.BeginCapture(kind, source, meta)
	if err != nil {
		log.Printf("  Warning: cannot record capture session: %v", err)
		return 0
	}
	return id
}

// flagSlice implements flag.Value for collecting multiple flag values
type flagSlice []string

func (f *flagSlice) String() string {
	return strings.Join(*f, ", ")
}

func (f *flagSlice) Set(value string) error {
	*f = append(*f, value)
	return nil
}

// runSynthetic feeds the graph a synthetic network of n hosts with continuous
// random traffic — a dev harness for exercising supercomputer-scale views
// without a capture (-synth N). Hosts are laid out 10.a.b.c across /16s and
// /24s so the hierarchical subnet aggregation sees realistic structure: each
// /24 has a "rack hub" (.0) its hosts talk to, hubs talk across subnets.
func runSynthetic(ctx context.Context, graphMgr *graph.Manager, n, pktRate int, db *store.Store, captureID int64) {
	recordSynth := func(src, dst string, proto capture.Protocol, size int) {
		if captureID == 0 {
			return
		}
		db.RecordPacket(store.PacketEvent{
			CaptureID: captureID, TS: time.Now(),
			Src: src, Dst: dst,
			Proto: proto.Name, Length: size, PcapOffset: -1,
		})
	}
	protos := []capture.Protocol{
		capture.ProtocolTCP, capture.ProtocolUDP, capture.ProtocolHTTPS,
		capture.ProtocolSSH, capture.ProtocolDNS,
	}
	// Skip .255 (directed broadcast — the graph folds those into a single
	// "Broadcast" group node, which is correct but not what a load test wants).
	hosts := make([]string, 0, n)
	for i := 0; len(hosts) < n; i++ {
		if i%256 == 255 {
			continue
		}
		hosts = append(hosts, fmt.Sprintf("10.%d.%d.%d", (i/65536)%256, (i/256)%256, i%256))
	}
	n = len(hosts)
	rng := mrand.New(mrand.NewSource(42))

	// Seed the full population with hub-and-spoke structure per /24 (each /24
	// contributes 255 hosts, .0-.254, so array chunks of 255 align with /24s).
	const perSubnet = 255
	for i, h := range hosts {
		graphMgr.AddOrUpdateNode(h, h, 100)
		if hub := hosts[(i/perSubnet)*perSubnet]; h != hub {
			graphMgr.AddOrUpdateEdge(hub, h, protos[i%len(protos)], 100)
			recordSynth(hub, h, protos[i%len(protos)], 100)
		}
	}
	log.Printf("  Synthetic graph seeded: %d hosts across %d /24s", n, (n+perSubnet-1)/perSubnet)

	// Continuous traffic: mostly intra-rack (host <-> its hub), some hub-to-hub
	// chatter across subnets so inter-subnet edges exist at every level. Edge
	// count stays bounded (spokes + hub pairs), memory does not run away.
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	perTick := pktRate / 10
	if perTick < 1 {
		perTick = 1
	}
	numHubs := (n + perSubnet - 1) / perSubnet
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			for i := 0; i < perTick; i++ {
				size := 64 + rng.Intn(1400)
				proto := protos[rng.Intn(len(protos))]
				if rng.Intn(10) < 7 {
					// Intra-rack: random host to its /24 hub.
					hi := rng.Intn(n)
					h := hosts[hi]
					hub := hosts[(hi/perSubnet)*perSubnet]
					if h == hub {
						continue
					}
					graphMgr.AddOrUpdateNode(h, h, size)
					graphMgr.AddOrUpdateNode(hub, hub, size)
					graphMgr.AddOrUpdateEdge(h, hub, proto, size)
					recordSynth(h, hub, proto, size)
				} else {
					// Hub-to-hub across subnets.
					a := hosts[rng.Intn(numHubs)*perSubnet]
					b := hosts[rng.Intn(numHubs)*perSubnet]
					if a == b {
						continue
					}
					graphMgr.AddOrUpdateNode(a, a, size)
					graphMgr.AddOrUpdateNode(b, b, size)
					graphMgr.AddOrUpdateEdge(a, b, proto, size)
					recordSynth(a, b, proto, size)
				}
			}
		}
	}
}
