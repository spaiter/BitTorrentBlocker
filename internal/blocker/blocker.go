package blocker

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/example/BitTorrentBlocker/internal/xdp"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// Blocker is the main BitTorrent blocker service (passive monitoring)
type Blocker struct {
	config          Config
	analyzer        *Analyzer
	banManager      *IPBanManager
	handles         []*pcap.Handle
	logger          *Logger
	detectionLogger *DetectionLogger
	xdpFilter       *xdp.Filter // Optional XDP filter for two-tier architecture
}

// New creates a new BitTorrent blocker instance with passive monitoring (like ndpiReader)
func New(config Config) (*Blocker, error) {
	if len(config.Interfaces) == 0 {
		return nil, fmt.Errorf("no interfaces specified")
	}

	logger := NewLogger(config.LogLevel)
	handles := make([]*pcap.Handle, 0, len(config.Interfaces))

	// Initialize detection logger if enabled
	detectionLogger, err := NewDetectionLogger(config.DetectionLogPath)
	if err != nil {
		return nil, fmt.Errorf("failed to create detection logger: %w", err)
	}
	if config.DetectionLogPath != "" {
		logger.Info("Detection logging enabled: %s", config.DetectionLogPath)
	}

	// Open pcap handles for all interfaces
	for _, iface := range config.Interfaces {
		handle, err := pcap.OpenLive(
			iface,             // Network interface to monitor
			65536,             // Snapshot length (max bytes per packet)
			true,              // Promiscuous mode
			pcap.BlockForever, // Read timeout
		)
		if err != nil {
			// Close any already opened handles
			for _, h := range handles {
				h.Close()
			}
			return nil, fmt.Errorf("could not open interface %s: %w", iface, err)
		}

		// Set BPF filter to capture only TCP and UDP (optimization)
		if err := handle.SetBPFFilter("tcp or udp"); err != nil {
			handle.Close()
			for _, h := range handles {
				h.Close()
			}
			return nil, fmt.Errorf("could not set BPF filter on %s: %w", iface, err)
		}

		handles = append(handles, handle)
		logger.Info("Opened interface %s for monitoring", iface)
	}

	blocker := &Blocker{
		config:          config,
		analyzer:        NewAnalyzer(config),
		banManager:      NewIPBanManager(config.IPSetName, config.BanDuration),
		handles:         handles,
		logger:          logger,
		detectionLogger: detectionLogger,
	}

	// Initialize XDP filter if enabled (two-tier architecture)
	if config.EnableXDP {
		logger.Info("Initializing XDP filter on %s (mode: %s)", config.Interfaces[0], config.XDPMode)
		xdpFilter, err := xdp.NewXDPFilter(config.Interfaces[0])
		if err != nil {
			// Close pcap handles before returning error
			for _, h := range handles {
				h.Close()
			}
			if detectionLogger != nil {
				detectionLogger.Close()
			}
			return nil, fmt.Errorf("failed to initialize XDP filter: %w (XDP requires Linux 4.18+)", err)
		}

		// Start periodic cleanup of expired IPs
		cleanupInterval := time.Duration(config.CleanupInterval) * time.Second
		xdpFilter.GetMapManager().StartPeriodicCleanup(cleanupInterval)
		logger.Info("XDP filter initialized successfully (cleanup interval: %v)", cleanupInterval)

		blocker.xdpFilter = xdpFilter
	}

	return blocker, nil
}

// Start begins the passive packet monitoring loop (like ndpiReader)
func (b *Blocker) Start(ctx context.Context) error {
	mode := "blocking enabled"
	if b.config.MonitorOnly {
		mode = "MONITOR ONLY - no blocking"
	}

	architecture := "single-tier (DPI only)"
	if b.xdpFilter != nil {
		architecture = "two-tier (XDP + DPI)"
	}

	b.logger.Info("BitTorrent blocker started on %d interface(s) (passive monitoring, log level: %s, mode: %s, architecture: %s)", len(b.config.Interfaces), b.config.LogLevel, mode, architecture)

	// Use WaitGroup to wait for all interface monitors to finish
	var wg sync.WaitGroup
	errChan := make(chan error, len(b.handles))

	// Start monitoring each interface in a separate goroutine
	for i, handle := range b.handles {
		wg.Add(1)
		go func(iface string, h *pcap.Handle) {
			defer wg.Done()
			if err := b.monitorInterface(ctx, iface, h); err != nil && !errors.Is(err, context.Canceled) {
				errChan <- err
			}
		}(b.config.Interfaces[i], handle)
	}

	// Wait for all goroutines to finish
	go func() {
		wg.Wait()
		close(errChan)
	}()

	// Return first error if any
	for err := range errChan {
		if err != nil {
			return err
		}
	}

	return ctx.Err()
}

// monitorInterface monitors a single interface for packets
func (b *Blocker) monitorInterface(ctx context.Context, iface string, handle *pcap.Handle) error {
	b.logger.Info("Started monitoring interface %s", iface)

	// Create packet source from pcap handle
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	// Process packets asynchronously
	for {
		select {
		case <-ctx.Done():
			b.logger.Info("Stopped monitoring interface %s", iface)
			return ctx.Err()
		case packet := <-packetSource.Packets():
			if packet == nil {
				continue
			}

			// Process packet in background (non-blocking, like ndpiReader)
			go b.processPacket(packet, iface)
		}
	}
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

// processPacket analyzes a single packet and bans IP if BitTorrent is detected
func (b *Blocker) processPacket(packet gopacket.Packet, iface string) {
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
		return
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
		return // Not TCP/UDP
	}

	// Whitelist check
	if WhitelistPorts[srcPort] || WhitelistPorts[dstPort] {
		b.logger.Debug("[%s] Whitelisted port: %s:%d -> %d", iface, srcIP, srcPort, dstPort)
		return
	}

	if len(appLayer) == 0 {
		return
	}

	// Analyze packet
	result := b.analyzer.AnalyzePacketEx(appLayer, isUDP, dstIP, dstPort)

	// Ban IP if BitTorrent detected
	if result.ShouldBlock {
		proto := "TCP"
		if isUDP {
			proto = "UDP"
		}

		// Log detection
		if b.config.MonitorOnly {
			b.logger.Info("[%s] [DETECT] %s %s:%d (%s) - Monitor only (no ban)", iface, proto, srcIP, srcPort, result.Reason)
		} else {
			duration := formatDuration(b.config.BanDuration)
			b.logger.Info("[%s] [DETECT] %s %s:%d (%s) - Banning for %s", iface, proto, srcIP, srcPort, result.Reason, duration)
		}

		// Log detailed packet information for false positive analysis
		b.detectionLogger.LogDetection(
			time.Now(),
			iface,
			proto,
			srcIP,
			srcPort,
			dstIP,
			dstPort,
			result.Reason,
			appLayer,
		)

		// Ban IP only if not in monitor-only mode
		if !b.config.MonitorOnly {
			// Add to XDP blocklist if two-tier architecture is enabled
			if b.xdpFilter != nil {
				ip := net.ParseIP(srcIP)
				if ip != nil {
					duration := time.Duration(b.config.BanDuration) * time.Second
					if err := b.xdpFilter.GetMapManager().AddIP(ip, duration); err != nil {
						b.logger.Error("[%s] Failed to add IP %s to XDP map: %v", iface, srcIP, err)
					} else {
						b.logger.Debug("[%s] Added IP %s to XDP blocklist (expires in %v)", iface, srcIP, duration)
					}
				}
			}

			// Also maintain ipset for backward compatibility (single-tier mode)
			if err := b.banManager.BanIP(srcIP); err != nil {
				b.logger.Error("[%s] Failed to ban IP %s: %v", iface, srcIP, err)
			}
		}
	}
}

// Close cleans up resources
func (b *Blocker) Close() error {
	// Close XDP filter first (detach from interface)
	if b.xdpFilter != nil {
		b.logger.Info("Closing XDP filter")
		if err := b.xdpFilter.Close(); err != nil {
			b.logger.Error("Failed to close XDP filter: %v", err)
		}
	}

	// Close pcap handles
	for _, handle := range b.handles {
		if handle != nil {
			handle.Close()
		}
	}

	// Close detection logger
	if b.detectionLogger != nil {
		b.detectionLogger.Close()
	}

	return nil
}
