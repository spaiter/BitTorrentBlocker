package blocker

import (
	"context"
	"fmt"
	"sync"
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
	handles    []*pcap.Handle
	logger     *Logger
}

// New creates a new BitTorrent blocker instance with passive monitoring (like ndpiReader)
func New(config Config) (*Blocker, error) {
	if len(config.Interfaces) == 0 {
		return nil, fmt.Errorf("no interfaces specified")
	}

	logger := NewLogger(config.LogLevel)
	handles := make([]*pcap.Handle, 0, len(config.Interfaces))

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

	return &Blocker{
		config:     config,
		analyzer:   NewAnalyzer(config),
		banManager: NewIPBanManager(config.IPSetName, config.BanDuration),
		handles:    handles,
		logger:     logger,
	}, nil
}

// Start begins the passive packet monitoring loop (like ndpiReader)
func (b *Blocker) Start(ctx context.Context) error {
	b.logger.Info("BitTorrent blocker started on %d interface(s) (passive monitoring, log level: %s)", len(b.config.Interfaces), b.config.LogLevel)

	// Use WaitGroup to wait for all interface monitors to finish
	var wg sync.WaitGroup
	errChan := make(chan error, len(b.handles))

	// Start monitoring each interface in a separate goroutine
	for i, handle := range b.handles {
		wg.Add(1)
		go func(iface string, h *pcap.Handle) {
			defer wg.Done()
			if err := b.monitorInterface(ctx, iface, h); err != nil && err != context.Canceled {
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
		b.logger.Debug("[%s] Whitelisted port: %s:%d -> %d", iface, remoteIP, srcPort, dstPort)
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
		b.logger.Info("[%s] [DETECT] %s %s:%d (%s) - Banning for %s", iface, proto, remoteIP, srcPort, result.Reason, duration)

		if err := b.banManager.BanIP(remoteIP); err != nil {
			b.logger.Error("[%s] Failed to ban IP %s: %v", iface, remoteIP, err)
		}
	}
}

// Close cleans up resources
func (b *Blocker) Close() error {
	for _, handle := range b.handles {
		if handle != nil {
			handle.Close()
		}
	}
	return nil
}
