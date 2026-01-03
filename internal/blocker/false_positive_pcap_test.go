package blocker

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

// TestFalsePositivePcaps validates that we don't falsely flag legitimate protocols
// Dynamically discovers and tests all pcap files in the false-positive directory
func TestFalsePositivePcaps(t *testing.T) {
	pcapDir := "../../test/testdata/pcap/false-positive"

	// Find all pcap files in the directory
	pcapFiles, err := filepath.Glob(filepath.Join(pcapDir, "*.pcap"))
	if err != nil {
		t.Fatalf("Failed to list pcap files: %v", err)
	}

	if len(pcapFiles) == 0 {
		t.Skip("No false-positive pcap files found")
	}

	analyzer := NewAnalyzer(DefaultConfig())

	// Track overall statistics
	totalFiles := 0
	filesWithDetections := 0
	protocolsWithFalsePositives := make(map[string]int)

	t.Logf("Testing %d false-positive pcap files...\n", len(pcapFiles))

	for _, pcapPath := range pcapFiles {
		totalFiles++
		fileName := filepath.Base(pcapPath)
		protocolName := strings.TrimSuffix(fileName, ".pcap")

		t.Run(protocolName, func(t *testing.T) {
			f, err := os.Open(pcapPath)
			if err != nil {
				t.Skipf("Failed to open pcap: %v", err)
			}
			defer f.Close()

			// Try pcapng format first
			ngReader, err := pcapgo.NewNgReader(f, pcapgo.NgReaderOptions{})
			var packetSource interface {
				ReadPacketData() ([]byte, gopacket.CaptureInfo, error)
			}

			if err == nil {
				packetSource = ngReader
			} else {
				// Fall back to classic pcap format
				f.Seek(0, 0)
				reader, err := pcapgo.NewReader(f)
				if err != nil {
					t.Skipf("Failed to create pcap reader: %v", err)
				}
				packetSource = reader
			}

			totalPackets := 0
			detectedPackets := 0
			detectionReasons := make(map[string]int)
			maxPackets := 200 // Limit packets per file for performance

			for {
				data, _, err := packetSource.ReadPacketData()
				if err != nil {
					break // End of file
				}

				if totalPackets >= maxPackets {
					break
				}

				// Decode packet
				packet := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.Default)

				// Check if we have TCP or UDP payload
				var payload []byte
				var isUDP bool

				if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
					tcp, _ := tcpLayer.(*layers.TCP)
					payload = tcp.Payload
					isUDP = false
				} else if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
					udp, _ := udpLayer.(*layers.UDP)
					payload = udp.Payload
					isUDP = true
				}

				if len(payload) == 0 {
					continue
				}

				totalPackets++

				// Analyze the packet
				result := analyzer.AnalyzePacket(payload, isUDP)

				if result.ShouldBlock {
					detectedPackets++
					detectionReasons[result.Reason]++
				}
			}

			// Calculate false positive rate
			falsePositiveRate := 0.0
			if totalPackets > 0 {
				falsePositiveRate = float64(detectedPackets) / float64(totalPackets) * 100
			}

			if detectedPackets > 0 {
				filesWithDetections++
				protocolsWithFalsePositives[protocolName] = detectedPackets

				// Log detailed information for false positives
				t.Logf("❌ FALSE POSITIVE: %s", protocolName)
				t.Logf("   Packets analyzed: %d", totalPackets)
				t.Logf("   False detections: %d (%.2f%%)", detectedPackets, falsePositiveRate)
				t.Logf("   Detection reasons:")
				for reason, count := range detectionReasons {
					t.Logf("     - %s: %d packets", reason, count)
				}

				// Fail the test if we detect any false positives
				t.Errorf("FALSE POSITIVE: Detected %d/%d packets as BitTorrent in %s (%.2f%%)",
					detectedPackets, totalPackets, protocolName, falsePositiveRate)
			} else {
				t.Logf("✅ PASS: %s (%d packets tested)", protocolName, totalPackets)
			}
		})
	}

	// Summary report
	t.Logf("\n=== FALSE POSITIVE TEST SUMMARY ===")
	t.Logf("Total protocols tested: %d", totalFiles)
	t.Logf("Protocols with false positives: %d", filesWithDetections)
	t.Logf("Clean protocols (no false positives): %d", totalFiles-filesWithDetections)

	if filesWithDetections > 0 {
		t.Logf("\n=== PROTOCOLS WITH FALSE POSITIVES (sorted by detection count) ===")
		// Simple bubble sort to show worst offenders first
		protocols := make([]string, 0, len(protocolsWithFalsePositives))
		for proto := range protocolsWithFalsePositives {
			protocols = append(protocols, proto)
		}
		for i := 0; i < len(protocols); i++ {
			for j := i + 1; j < len(protocols); j++ {
				if protocolsWithFalsePositives[protocols[j]] > protocolsWithFalsePositives[protocols[i]] {
					protocols[i], protocols[j] = protocols[j], protocols[i]
				}
			}
		}
		for _, proto := range protocols {
			t.Logf("  - %s: %d detections", proto, protocolsWithFalsePositives[proto])
		}
	}

	t.Logf("\n=== OVERALL RESULT ===")
	if filesWithDetections == 0 {
		t.Logf("✅ SUCCESS: No false positives detected across all %d protocols", totalFiles)
	} else {
		accuracyRate := float64(totalFiles-filesWithDetections) / float64(totalFiles) * 100
		t.Logf("⚠️  FALSE POSITIVES DETECTED")
		t.Logf("   Accuracy: %.2f%% (%d/%d protocols clean)", accuracyRate, totalFiles-filesWithDetections, totalFiles)
	}
}
