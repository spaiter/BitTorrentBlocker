package blocker

import (
	"bytes"
	"encoding/binary"
	"os"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

// TestAnalyzeSSHFalsePositive analyzes the SSH false positive in detail
func TestAnalyzeSSHFalsePositive(t *testing.T) {
	pcapPath := "../../test/testdata/pcap/false-positive/ssh.pcap"

	f, err := os.Open(pcapPath)
	if err != nil {
		t.Skipf("Failed to open pcap: %v", err)
	}
	defer f.Close()

	ngReader, err := pcapgo.NewNgReader(f, pcapgo.NgReaderOptions{})
	var packetSource interface {
		ReadPacketData() ([]byte, gopacket.CaptureInfo, error)
	}

	if err == nil {
		packetSource = ngReader
	} else {
		f.Seek(0, 0)
		reader, err := pcapgo.NewReader(f)
		if err != nil {
			t.Skipf("Failed to create pcap reader: %v", err)
		}
		packetSource = reader
	}

	analyzer := NewAnalyzer(DefaultConfig())
	allPackets := 0
	falsePositives := 0

	for {
		data, _, err := packetSource.ReadPacketData()
		if err != nil {
			break
		}

		packet := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.Default)

		var payload []byte
		if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
			tcp, _ := tcpLayer.(*layers.TCP)
			payload = tcp.Payload
		}

		if len(payload) == 0 {
			continue
		}

		allPackets++

		// Analyze the packet
		result := analyzer.AnalyzePacket(payload, false)

		if result.ShouldBlock {
			falsePositives++

			t.Logf("\n=== FALSE POSITIVE Packet #%d ===", allPackets)
			t.Logf("Reason: %s", result.Reason)

			// Show payload context
			printLen := 100
			if len(payload) < printLen {
				printLen = len(payload)
			}
			t.Logf("Payload (%d bytes): %q", len(payload), payload[:printLen])
			t.Logf("Payload hex: %x", payload[:printLen])

			// Check for SSH markers
			hasSSH := bytes.Contains(payload, []byte("SSH"))
			t.Logf("Contains SSH: %v", hasSSH)

			// If detected by BitTorrent Message Structure, analyze the structure
			if result.Reason == "BitTorrent Message Structure" {
				t.Logf("\nBitTorrent Message Structure Analysis:")
				if len(payload) >= 5 {
					msgLen := binary.BigEndian.Uint32(payload[0:4])
					msgID := payload[4]
					t.Logf("  Message length: %d (0x%08x)", msgLen, msgLen)
					t.Logf("  Message ID: %d (0x%02x)", msgID, msgID)
					t.Logf("  Expected total: %d bytes", msgLen+4)
					t.Logf("  Actual payload: %d bytes", len(payload))

					// Check if this looks like SSH binary packet
					if hasSSH || bytes.HasPrefix(payload, []byte{0x00}) {
						t.Logf("  Note: SSH uses length-prefixed binary packets too")
					}

					// BitTorrent message IDs range from 0-21 typically
					if msgID > 21 {
						t.Logf("  ⚠️  Message ID %d is outside typical BitTorrent range (0-21)", msgID)
					}
				}
			}

			// Check individual detectors
			t.Logf("\nIndividual Detector Results:")
			t.Logf("  CheckSignatures: %v", CheckSignatures(payload))
			t.Logf("  CheckBitTorrentMessage: %v", CheckBitTorrentMessage(payload))
			t.Logf("  CheckHTTPBitTorrent: %v", CheckHTTPBitTorrent(payload))
			t.Logf("  CheckFASTExtension: %v", CheckFASTExtension(payload))
		}
	}

	t.Logf("\n=== Summary ===")
	t.Logf("Total packets: %d", allPackets)
	t.Logf("False positives: %d (%.2f%%)", falsePositives, float64(falsePositives)/float64(allPackets)*100)

	if falsePositives > 0 {
		t.Errorf("Found %d false positive(s) in SSH traffic", falsePositives)
	}
}
