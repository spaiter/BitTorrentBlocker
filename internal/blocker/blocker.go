package blocker

import (
	"context"
	"fmt"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// Blocker is the main BitTorrent blocker service (passive monitoring)
type Blocker struct {
	config     Config
	analyzer   *Analyzer
	banManager *IPBanManager
	handle     *pcap.Handle
	logger     *Logger
}

// New creates a new BitTorrent blocker instance with passive monitoring (like ndpiReader)
func New(config Config) (*Blocker, error) {
	// Open device for passive packet capture
	handle, err := pcap.OpenLive(
		config.Interface,  // Network interface to monitor
		65536,             // Snapshot length (max bytes per packet)
		true,              // Promiscuous mode
		pcap.BlockForever, // Read timeout
	)
	if err != nil {
		return nil, fmt.Errorf("could not open interface %s: %w", config.Interface, err)
	}

	// Set BPF filter to capture only TCP and UDP (optimization)
	if err := handle.SetBPFFilter("tcp or udp"); err != nil {
		handle.Close()
		return nil, fmt.Errorf("could not set BPF filter: %w", err)
	}

	logger := NewLogger(config.LogLevel)

	return &Blocker{
		config:     config,
		analyzer:   NewAnalyzer(config),
		banManager: NewIPBanManager(config.IPSetName, config.BanDuration),
		handle:     handle,
		logger:     logger,
	}, nil
}

// Start begins the passive packet monitoring loop (like ndpiReader)
func (b *Blocker) Start(ctx context.Context) error {
	b.logger.Info("BitTorrent blocker started on interface %s (passive monitoring, log level: %s)", b.config.Interface, b.config.LogLevel)

	// Create packet source from pcap handle
	packetSource := gopacket.NewPacketSource(b.handle, b.handle.LinkType())

	// Process packets asynchronously
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case packet := <-packetSource.Packets():
			if packet == nil {
				continue
			}

			// Process packet in background (non-blocking, like ndpiReader)
			go b.processPacket(packet)
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
func (b *Blocker) processPacket(packet gopacket.Packet) {
	var remoteIP string
	var srcPort, dstPort uint16
	var appLayer []byte
	isUDP := false

	// Parse IP layer
	if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
		ip, _ := ipLayer.(*layers.IPv4)
		remoteIP = ip.SrcIP.String() // Source IP is the client
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
		b.logger.Debug("Whitelisted port: %s:%d -> %d", remoteIP, srcPort, dstPort)
		return
	}

	if len(appLayer) == 0 {
		return
	}

	// Analyze packet
	result := b.analyzer.AnalyzePacketEx(appLayer, isUDP, remoteIP, dstPort)

	// Ban IP if BitTorrent detected
	if result.ShouldBlock {
		proto := "TCP"
		if isUDP {
			proto = "UDP"
		}
		duration := formatDuration(b.config.BanDuration)
		b.logger.Info("[DETECT] %s %s:%d (%s) - Banning for %s", proto, remoteIP, srcPort, result.Reason, duration)

		if err := b.banManager.BanIP(remoteIP); err != nil {
			b.logger.Error("Failed to ban IP %s: %v", remoteIP, err)
		}
	}
}

// Close cleans up resources
func (b *Blocker) Close() error {
	if b.handle != nil {
		b.handle.Close()
	}
	return nil
}
