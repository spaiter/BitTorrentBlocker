package blocker

import (
	"context"
	"fmt"
	"log"

	"github.com/florianl/go-nfqueue"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// Blocker is the main BitTorrent blocker service
type Blocker struct {
	config      Config
	analyzer    *Analyzer
	banManager  *IPBanManager
	nfq         *nfqueue.Nfqueue
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

	return &Blocker{
		config:     config,
		analyzer:   NewAnalyzer(config),
		banManager: NewIPBanManager(config.IPSetName, config.BanDuration),
		nfq:        nfq,
	}, nil
}

// Start begins the packet processing loop
func (b *Blocker) Start(ctx context.Context) error {
	fn := func(a nfqueue.Attribute) int {
		id := *a.PacketID
		payload := *a.Payload
		verdict := nfqueue.NfAccept

		if len(payload) == 0 {
			b.nfq.SetVerdict(id, verdict)
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
			b.nfq.SetVerdict(id, verdict)
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
			b.nfq.SetVerdict(id, verdict) // Not TCP/UDP -> pass
			return 0
		}

		// Whitelist check
		if WhitelistPorts[srcPort] || WhitelistPorts[dstPort] {
			b.nfq.SetVerdict(id, verdict)
			return 0
		}

		if len(appLayer) == 0 {
			b.nfq.SetVerdict(id, verdict)
			return 0
		}

		// Analyze packet
		result := b.analyzer.AnalyzePacket(appLayer, isUDP)

		// Apply verdict
		if result.ShouldBlock {
			log.Printf("[BLOCK] %s -> %s:%d (Banning for 5h)", result.Reason, remoteIP, dstPort)
			b.nfq.SetVerdict(id, nfqueue.NfDrop)
			go b.banManager.BanIP(remoteIP) // Async ban
			return 0
		}

		b.nfq.SetVerdict(id, verdict)
		return 0
	}

	if err := b.nfq.RegisterWithErrorFunc(ctx, fn, func(e error) int {
		log.Printf("Error: %v", e)
		return -1
	}); err != nil {
		return fmt.Errorf("could not register callback: %w", err)
	}

	return nil
}

// Close cleans up resources
func (b *Blocker) Close() error {
	if b.nfq != nil {
		return b.nfq.Close()
	}
	return nil
}
