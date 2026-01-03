package blocker

import (
	"encoding/binary"
	"os"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

// TestAnalyzeRXProtocol analyzes what's triggering false positives in RX protocol
func TestAnalyzeRXProtocol(t *testing.T) {
	pcapPath := "../../test/testdata/pcap/false-positive/rx.pcap"

	f, err := os.Open(pcapPath)
	if err != nil {
		t.Skipf("Failed to open pcap: %v", err)
	}
	defer f.Close()

	ngReader, err := pcapgo.NewNgReader(f, pcapgo.NgReaderOptions{})
	if err != nil {
		t.Fatalf("Failed to create pcap reader: %v", err)
	}

	analyzer := NewAnalyzer(DefaultConfig())
	detectionCount := 0
	maxToAnalyze := 5 // Analyze first 5 detections in detail

	for {
		data, _, err := ngReader.ReadPacketData()
		if err != nil {
			break
		}

		packet := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.Default)

		var payload []byte
		var isUDP bool

		if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
			udp, _ := udpLayer.(*layers.UDP)
			payload = udp.Payload
			isUDP = true
		}

		if len(payload) == 0 {
			continue
		}

		result := analyzer.AnalyzePacket(payload, isUDP)

		if result.ShouldBlock && detectionCount < maxToAnalyze {
			detectionCount++
			t.Logf("\n=== FALSE POSITIVE #%d ===", detectionCount)
			t.Logf("Reason: %s", result.Reason)
			t.Logf("Payload length: %d bytes", len(payload))

			// Print first 64 bytes in hex
			printLen := 64
			if len(payload) < printLen {
				printLen = len(payload)
			}
			t.Logf("First %d bytes (hex): % X", printLen, payload[:printLen])
			t.Logf("First %d bytes (ascii): %q", printLen, payload[:printLen])

			// Analyze UDP tracker structure
			if len(payload) >= 16 {
				connectionID := binary.BigEndian.Uint64(payload[:8])
				action := binary.BigEndian.Uint32(payload[8:12])
				transactionID := binary.BigEndian.Uint32(payload[12:16])

				t.Logf("Parsed as UDP Tracker:")
				t.Logf("  Connection ID: 0x%016X", connectionID)
				t.Logf("  Action: 0x%08X (%d)", action, action)
				t.Logf("  Transaction ID: 0x%08X", transactionID)

				// Check if this matches the tracker magic number
				if connectionID == 0x41727101980 {
					t.Logf("  -> Matches BitTorrent tracker magic number!")
				}

				// Check action values
				actionNames := map[uint32]string{
					0: "Connect",
					1: "Announce",
					2: "Scrape",
					3: "Error",
				}
				if name, ok := actionNames[action]; ok {
					t.Logf("  -> Action is valid BitTorrent action: %s", name)
				}
			}

			// Check for RX protocol markers
			// AFS RX protocol typically has specific epoch/call markers
			if len(payload) >= 28 {
				epoch := binary.BigEndian.Uint32(payload[0:4])
				connID := binary.BigEndian.Uint32(payload[4:8])
				callNum := binary.BigEndian.Uint32(payload[8:12])
				seq := binary.BigEndian.Uint32(payload[12:16])
				serial := binary.BigEndian.Uint32(payload[16:20])

				t.Logf("Parsed as RX Protocol:")
				t.Logf("  Epoch: 0x%08X", epoch)
				t.Logf("  Connection ID: 0x%08X", connID)
				t.Logf("  Call Number: 0x%08X", callNum)
				t.Logf("  Sequence: 0x%08X", seq)
				t.Logf("  Serial: 0x%08X", serial)
			}
		}

		if detectionCount >= maxToAnalyze {
			break
		}
	}

	t.Logf("\nTotal false positives found: %d", detectionCount)
}
