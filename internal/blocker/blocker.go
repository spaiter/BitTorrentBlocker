package blocker

import (
	"context"
	"fmt"

	"github.com/florianl/go-nfqueue"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// Blocker is the main BitTorrent blocker service
type Blocker struct {
	config     Config
	analyzer   *Analyzer
	banManager *IPBanManager
	nfq        *nfqueue.Nfqueue
	logger     *Logger
}

// New creates a new BitTorrent blocker instance
func New(config Config) (*Blocker, error) {
	nfqConfig := nfqueue.Config{
		NfQueue:      config.QueueNum,
		MaxPacketLen: 0xFFFF,
		MaxQueueLen:  1024,
		Copymode:     nfqueue.NfQnlCopyPacket,
		WriteTimeout: 15000000,
	}

	nfq, err := nfqueue.Open(&nfqConfig)
	if err != nil {
		return nil, fmt.Errorf("could not open nfqueue: %w", err)
	}

	logger := NewLogger(config.LogLevel)

	return &Blocker{
		config:     config,
		analyzer:   NewAnalyzer(config),
		banManager: NewIPBanManager(config.IPSetName, config.BanDuration),
		nfq:        nfq,
		logger:     logger,
	}, nil
}

// Start begins the packet processing loop
func (b *Blocker) Start(ctx context.Context) error {
	fn := func(a nfqueue.Attribute) int {
		id := *a.PacketID
		payload := *a.Payload
		verdict := nfqueue.NfAccept

		if len(payload) == 0 {
			_ = b.nfq.SetVerdict(id, verdict)
			return 0
		}

		// Parse packet
		packet := gopacket.NewPacket(payload, layers.LayerTypeIPv4, gopacket.DecodeOptions{Lazy: true, NoCopy: true})

		var remoteIP string
		var srcPort, dstPort uint16
		var appLayer []byte
		isUDP := false

		// Parse IP layer (for banning)
		if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
			ip, _ := ipLayer.(*layers.IPv4)
			remoteIP = ip.DstIP.String()
		} else {
			_ = b.nfq.SetVerdict(id, verdict)
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
			_ = b.nfq.SetVerdict(id, verdict) // Not TCP/UDP -> pass
			return 0
		}

		// Whitelist check
		if WhitelistPorts[srcPort] || WhitelistPorts[dstPort] {
			b.logger.Debug("Whitelisted port: %s:%d -> %s:%d", "src", srcPort, remoteIP, dstPort)
			_ = b.nfq.SetVerdict(id, verdict)
			return 0
		}

		if len(appLayer) == 0 {
			b.logger.Debug("Empty payload: %s:%d", remoteIP, dstPort)
			_ = b.nfq.SetVerdict(id, verdict)
			return 0
		}

		// Analyze packet with destination info for LSD detection
		result := b.analyzer.AnalyzePacketEx(appLayer, isUDP, remoteIP, dstPort)

		// Apply verdict
		if result.ShouldBlock {
			proto := "TCP"
			if isUDP {
				proto = "UDP"
			}
			b.logger.Info("[BLOCK] %s %s:%d (%s) - Banning for 5h", proto, remoteIP, dstPort, result.Reason)
			_ = b.nfq.SetVerdict(id, nfqueue.NfDrop)
			go func() {
				if err := b.banManager.BanIP(remoteIP); err != nil {
					b.logger.Error("Failed to ban IP %s: %v", remoteIP, err)
				}
			}()
			return 0
		}

		b.logger.Debug("[ALLOW] %s:%d (payload: %d bytes)", remoteIP, dstPort, len(appLayer))
		_ = b.nfq.SetVerdict(id, verdict)
		return 0
	}

	if err := b.nfq.RegisterWithErrorFunc(ctx, fn, func(e error) int {
		b.logger.Error("Error: %v", e)
		return -1
	}); err != nil {
		return fmt.Errorf("could not register callback: %w", err)
	}

	b.logger.Info("BitTorrent blocker started on queue %d (log level: %s)", b.config.QueueNum, b.config.LogLevel)

	return nil
}

// Close cleans up resources
func (b *Blocker) Close() error {
	if b.nfq != nil {
		return b.nfq.Close()
	}
	return nil
}
