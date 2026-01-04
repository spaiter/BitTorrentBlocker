package blocker

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/example/BitTorrentBlocker/internal/xdp"
	nfqueue "github.com/florianl/go-nfqueue/v2"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// Blocker is the main BitTorrent blocker service (inline blocking via NFQUEUE)
type Blocker struct {
	config          Config
	analyzer        *Analyzer
	nfq             *nfqueue.Nfqueue
	logger          *Logger
	detectionLogger *DetectionLogger
	xdpFilter       *xdp.Filter // XDP filter for fast-path blocking of known IPs
}

// New creates a new BitTorrent blocker instance with inline blocking (NFQUEUE)
func New(config Config) (*Blocker, error) {
	if config.QueueNum < 0 || config.QueueNum > 65535 {
		return nil, fmt.Errorf("invalid queue number: %d (must be 0-65535)", config.QueueNum)
	}

	logger := NewLogger(config.LogLevel)

	// Initialize detection logger if enabled
	detectionLogger, err := NewDetectionLogger(config.DetectionLogPath)
	if err != nil {
		return nil, fmt.Errorf("failed to create detection logger: %w", err)
	}
	if config.DetectionLogPath != "" {
		logger.Info("Detection logging enabled: %s", config.DetectionLogPath)
	}

	// Initialize XDP filter for fast-path blocking (optional but recommended)
	var xdpFilter *xdp.Filter
	if len(config.Interfaces) > 0 && config.Interfaces[0] != "" {
		logger.Info("Initializing XDP filter on %s (mode: %s)", config.Interfaces[0], config.XDPMode)
		xdpFilter, err = xdp.NewXDPFilter(config.Interfaces[0])
		if err != nil {
			logger.Warn("Failed to initialize XDP filter: %v (continuing without XDP fast-path)", err)
			xdpFilter = nil
		} else {
			// Start periodic cleanup of expired IPs
			cleanupInterval := time.Duration(config.CleanupInterval) * time.Second
			xdpFilter.GetMapManager().StartPeriodicCleanup(cleanupInterval)
			logger.Info("XDP filter initialized successfully (cleanup interval: %v)", cleanupInterval)
		}
	}

	blocker := &Blocker{
		config:          config,
		analyzer:        NewAnalyzer(config),
		logger:          logger,
		detectionLogger: detectionLogger,
		xdpFilter:       xdpFilter,
	}

	return blocker, nil
}

// Start begins the inline packet filtering loop (NFQUEUE)
func (b *Blocker) Start(ctx context.Context) error {
	mode := "blocking enabled"
	if b.config.MonitorOnly {
		mode = "MONITOR ONLY - accepting all packets"
	}

	xdpStatus := "disabled"
	if b.xdpFilter != nil {
		xdpStatus = "enabled (fast-path)"
	}

	b.logger.Info("BitTorrent blocker started on NFQUEUE %d (inline DPI, XDP: %s, log level: %s, mode: %s)",
		b.config.QueueNum, xdpStatus, b.config.LogLevel, mode)

	// Configure NFQUEUE
	nfqConfig := nfqueue.Config{
		NfQueue:      uint16(b.config.QueueNum),
		MaxPacketLen: 0xFFFF, // 64KB max packet size
		MaxQueueLen:  1024,   // Queue up to 1024 packets
		Copymode:     nfqueue.NfQnlCopyPacket,
		Flags:        nfqueue.NfQaCfgFlagGSO, // Enable GSO (Generic Segmentation Offload)
	}

	// Create NFQUEUE instance
	var err error
	b.nfq, err = nfqueue.Open(&nfqConfig)
	if err != nil {
		return fmt.Errorf("failed to open NFQUEUE %d: %w (ensure iptables rules are configured)", b.config.QueueNum, err)
	}
	defer b.Close()

	// Register packet callback
	hookFunc := func(attr nfqueue.Attribute) int {
		verdict := b.processNFQPacket(attr)
		return verdict
	}

	if err := b.nfq.RegisterWithErrorFunc(ctx, hookFunc, func(err error) int {
		b.logger.Error("NFQUEUE error: %v", err)
		return 0
	}); err != nil {
		return fmt.Errorf("failed to register NFQUEUE callback: %w", err)
	}

	b.logger.Info("NFQUEUE registered, processing packets inline...")

	// Block until context is cancelled
	<-ctx.Done()
	b.logger.Info("Shutting down...")
	return ctx.Err()
}

// processNFQPacket processes a single packet from NFQUEUE and returns verdict
// This function is called synchronously for each packet - must be FAST!
func (b *Blocker) processNFQPacket(attr nfqueue.Attribute) int {
	// Default verdict: accept packet
	verdict := nfqueue.NfAccept

	// Get packet ID (required for verdict)
	packetID := *attr.PacketID

	// Get packet payload
	if attr.Payload == nil || len(*attr.Payload) == 0 {
		// No payload, accept by default
		_ = b.nfq.SetVerdict(packetID, verdict)
		return 0
	}

	payload := *attr.Payload

	// Parse packet using gopacket
	packet := gopacket.NewPacket(payload, layers.LayerTypeIPv4, gopacket.DecodeOptions{
		Lazy:   true,
		NoCopy: true, // Zero-copy for performance
	})

	// Check if already blocked by XDP fast-path
	// (This should rarely happen since XDP blocks at kernel level,
	//  but checking here prevents wasted DPI analysis)
	if b.xdpFilter != nil {
		if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
			ip, _ := ipLayer.(*layers.IPv4)
			srcIP := ip.SrcIP
			if blocked, _ := b.xdpFilter.GetMapManager().IsBlocked(srcIP); blocked {
				// Already blocked by XDP, drop immediately
				_ = b.nfq.SetVerdict(packetID, nfqueue.NfDrop)
				return 0
			}
		}
	}

	// Extract packet information
	var srcIP, dstIP string
	var srcPort, dstPort uint16
	var appLayer []byte
	isUDP := false

	// Parse IP layer
	if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
		ip, _ := ipLayer.(*layers.IPv4)
		srcIP = ip.SrcIP.String()
		dstIP = ip.DstIP.String()
	} else {
		// Not IPv4, accept by default
		_ = b.nfq.SetVerdict(packetID, verdict)
		return 0
	}

	// Parse TCP/UDP layers
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp, _ := tcpLayer.(*layers.TCP)
		srcPort, dstPort = uint16(tcp.SrcPort), uint16(tcp.DstPort)
		appLayer = tcp.Payload
	} else if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		udp, _ := udpLayer.(*layers.UDP)
		srcPort, dstPort = uint16(udp.SrcPort), uint16(udp.DstPort)
		appLayer = udp.Payload
		isUDP = true
	} else {
		// Not TCP/UDP, accept by default
		_ = b.nfq.SetVerdict(packetID, verdict)
		return 0
	}

	// Whitelist check (fast rejection)
	if WhitelistPorts[srcPort] || WhitelistPorts[dstPort] {
		b.logger.Debug("Whitelisted port: %s:%d -> %d", srcIP, srcPort, dstPort)
		_ = b.nfq.SetVerdict(packetID, verdict)
		return 0
	}

	// No payload to analyze, accept
	if len(appLayer) == 0 {
		_ = b.nfq.SetVerdict(packetID, verdict)
		return 0
	}

	// Analyze packet for BitTorrent traffic
	result := b.analyzer.AnalyzePacketEx(appLayer, isUDP, dstIP, dstPort)

	// Handle detection
	if result.ShouldBlock {
		proto := "TCP"
		if isUDP {
			proto = "UDP"
		}

		// Log detection
		if b.config.MonitorOnly {
			b.logger.Info("[DETECT] %s %s:%d (%s) - Monitor only (accepting)", proto, srcIP, srcPort, result.Reason)
			verdict = nfqueue.NfAccept // Accept in monitor mode
		} else {
			duration := formatDuration(b.config.BanDuration)
			b.logger.Info("[DETECT] %s %s:%d (%s) - Dropping packet, banning IP for %s", proto, srcIP, srcPort, result.Reason, duration)
			verdict = nfqueue.NfDrop // DROP the packet inline

			// Add to XDP blocklist for fast-path blocking of future packets
			if b.xdpFilter != nil {
				ip := net.ParseIP(srcIP)
				if ip != nil {
					banDuration := time.Duration(b.config.BanDuration) * time.Second
					if err := b.xdpFilter.GetMapManager().AddIP(ip, banDuration); err != nil {
						b.logger.Error("Failed to add IP %s to XDP blocklist: %v", srcIP, err)
					} else {
						b.logger.Debug("Added IP %s to XDP fast-path (expires in %v)", srcIP, banDuration)
					}
				}
			}
		}

		// Log detailed packet information for false positive analysis
		b.detectionLogger.LogDetection(
			time.Now(),
			fmt.Sprintf("nfq%d", b.config.QueueNum),
			proto,
			srcIP,
			srcPort,
			dstIP,
			dstPort,
			result.Reason,
			appLayer,
		)
	}

	// Set verdict and return
	_ = b.nfq.SetVerdict(packetID, verdict)
	return 0
}

// formatDuration converts seconds to a human-readable duration string
func formatDuration(seconds int) string {
	d := time.Duration(seconds) * time.Second
	hours := int(d.Hours())
	minutes := int(d.Minutes()) % 60

	if minutes == 0 {
		return fmt.Sprintf("%dh", hours)
	}
	return fmt.Sprintf("%dh%dm", hours, minutes)
}

// Close cleans up resources
func (b *Blocker) Close() error {
	// Close NFQUEUE
	if b.nfq != nil {
		b.logger.Info("Closing NFQUEUE")
		if err := b.nfq.Close(); err != nil {
			b.logger.Error("Failed to close NFQUEUE: %v", err)
		}
	}

	// Close XDP filter (if enabled)
	if b.xdpFilter != nil {
		b.logger.Info("Closing XDP filter")
		if err := b.xdpFilter.Close(); err != nil {
			b.logger.Error("Failed to close XDP filter: %v", err)
		}
	}

	// Close detection logger
	if b.detectionLogger != nil {
		b.detectionLogger.Close()
	}

	return nil
}
