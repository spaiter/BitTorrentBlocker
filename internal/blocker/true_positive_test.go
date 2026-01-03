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

// TestTruePositiveDetection validates that we correctly detect real BitTorrent traffic
// Uses diverse pcap files from multiple sources to ensure comprehensive coverage
func TestTruePositiveDetection(t *testing.T) {
	testCases := []struct {
		name             string
		pcapFile         string
		description      string
		minDetectionRate float64 // Minimum percentage of packets we should detect
		maxPackets       int     // Limit packets to test (0 = all)
	}{
		{
			name:             "Standard TCP Handshake (knqyf263)",
			pcapFile:         "bittorrent_knqyf263.pcap",
			description:      "Clean BitTorrent protocol handshake and transfer",
			minDetectionRate: 50.0, // Should detect at least 50% of BitTorrent packets
			maxPackets:       200,
		},
		// NOTE: nDPI and encrypted pcaps are too large for GitHub raw download
		// They would need Git LFS or direct clone of the repository
		{
			name:             "DHT UDP Traffic",
			pcapFile:         "torrent-dht.pcap",
			description:      "Distributed Hash Table discovery traffic on UDP",
			minDetectionRate: 80.0, // DHT has clear bencode structure
			maxPackets:       100,
		},
		{
			name:             "File Reconstruction",
			pcapFile:         "mippo.pcap",
			description:      "Capture designed to test reassembling a downloaded file",
			minDetectionRate: 30.0,
			maxPackets:       200,
		},
		{
			name:             "USTC Dataset (TLS Encrypted)",
			pcapFile:         "ustc_bittorrent.pcap",
			description:      "BitTorrent over TLS/SSL - very difficult to detect without decryption",
			minDetectionRate: 0.0, // TLS-wrapped traffic is not detectable without SSL interception
			maxPackets:       500, // Limit to first 500 packets for performance
		},
		{
			name:             "Existing: Standard TCP",
			pcapFile:         "bittorrent.pcap",
			description:      "Original test file",
			minDetectionRate: 50.0,
			maxPackets:       200,
		},
		{
			name:             "Existing: uTP",
			pcapFile:         "bittorrent_utp.pcap",
			description:      "Micro Transport Protocol (uTP) over UDP",
			minDetectionRate: 60.0,
			maxPackets:       100,
		},
		{
			name:             "Existing: Suricata DHT",
			pcapFile:         "suricata-dht.pcap",
			description:      "DHT packets from Suricata test suite",
			minDetectionRate: 80.0,
			maxPackets:       50,
		},
	}

	analyzer := NewAnalyzer(DefaultConfig())

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			pcapPath := filepath.Join("../../test/testdata/pcap/true-positive", tc.pcapFile)
			f, err := os.Open(pcapPath)
			if err != nil {
				t.Skipf("Skipping test - pcap not found: %v", err)
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
					t.Fatalf("Failed to create pcap reader: %v", err)
				}
				packetSource = reader
			}

			packetNum := 0
			totalPackets := 0
			detectedPackets := 0
			tcpPackets := 0
			udpPackets := 0
			tcpDetections := 0
			udpDetections := 0

			for {
				data, _, err := packetSource.ReadPacketData()
				if err != nil {
					break // End of file
				}

				packetNum++
				if tc.maxPackets > 0 && packetNum > tc.maxPackets {
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
					if len(payload) > 0 {
						tcpPackets++
					}
				} else if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
					udp, _ := udpLayer.(*layers.UDP)
					payload = udp.Payload
					isUDP = true
					if len(payload) > 0 {
						udpPackets++
					}
				}

				if len(payload) == 0 {
					continue
				}

				totalPackets++

				// Analyze the packet
				result := analyzer.AnalyzePacket(payload, isUDP)

				if result.ShouldBlock {
					detectedPackets++
					if isUDP {
						udpDetections++
					} else {
						tcpDetections++
					}
				}
			}

			// Calculate detection rate
			detectionRate := 0.0
			if totalPackets > 0 {
				detectionRate = float64(detectedPackets) / float64(totalPackets) * 100
			}

			// Summary
			t.Logf("=== %s Summary ===", tc.name)
			t.Logf("Description: %s", tc.description)
			t.Logf("Total packets read: %d", packetNum)
			t.Logf("Packets with payload: %d (TCP: %d, UDP: %d)", totalPackets, tcpPackets, udpPackets)
			t.Logf("Detections: %d (TCP: %d, UDP: %d)", detectedPackets, tcpDetections, udpDetections)
			t.Logf("Detection rate: %.2f%%", detectionRate)
			t.Logf("Required minimum: %.2f%%", tc.minDetectionRate)

			if detectionRate < tc.minDetectionRate {
				t.Errorf("FAILED: Detection rate %.2f%% is below required minimum %.2f%%",
					detectionRate, tc.minDetectionRate)
				t.Errorf("Detected %d out of %d packets", detectedPackets, totalPackets)
			} else {
				t.Logf("✅ PASSED - Detection rate meets requirements")
			}

			// Additional check: we should detect at least SOME packets (unless min is 0)
			if totalPackets > 10 && detectedPackets == 0 && tc.minDetectionRate > 0 {
				t.Errorf("CRITICAL: No BitTorrent packets detected in a BitTorrent pcap file!")
			}
		})
	}
}

// TestTruePositiveBreakdown provides detailed breakdown of detection methods
func TestTruePositiveBreakdown(t *testing.T) {
	// Test with a known good BitTorrent pcap to understand what we're detecting
	pcapPath := "../../test/testdata/pcap/true-positive/bittorrent.pcap"
	f, err := os.Open(pcapPath)
	if err != nil {
		t.Skipf("Skipping test - pcap not found: %v", err)
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
			t.Fatalf("Failed to create pcap reader: %v", err)
		}
		packetSource = reader
	}

	analyzer := NewAnalyzer(DefaultConfig())
	reasonCounts := make(map[string]int)
	totalPackets := 0
	maxPackets := 200

	for {
		data, _, err := packetSource.ReadPacketData()
		if err != nil {
			break
		}

		if totalPackets >= maxPackets {
			break
		}

		packet := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.Default)

		var payload []byte
		var isUDP bool

		if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
			tcp, _ := tcpLayer.(*layers.TCP)
			payload = tcp.Payload
		} else if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
			udp, _ := udpLayer.(*layers.UDP)
			payload = udp.Payload
			isUDP = true
		}

		if len(payload) == 0 {
			continue
		}

		totalPackets++
		result := analyzer.AnalyzePacket(payload, isUDP)

		if result.ShouldBlock {
			reason := result.Reason
			// Normalize reason for counting
			if strings.Contains(reason, "Signature") {
				reason = "Signature Match"
			} else if strings.Contains(reason, "uTP") {
				reason = "uTP Protocol"
			} else if strings.Contains(reason, "DHT") {
				reason = "DHT Bencode"
			} else if strings.Contains(reason, "UDP Tracker") {
				reason = "UDP Tracker"
			} else if strings.Contains(reason, "Encrypted") {
				reason = "High Entropy"
			}
			reasonCounts[reason]++
		}
	}

	t.Logf("\n=== Detection Method Breakdown ===")
	t.Logf("Total packets analyzed: %d", totalPackets)
	t.Logf("\nDetections by method:")

	totalDetections := 0
	for _, count := range reasonCounts {
		totalDetections += count
	}

	for reason, count := range reasonCounts {
		percentage := float64(count) / float64(totalDetections) * 100
		t.Logf("  %s: %d (%.1f%%)", reason, count, percentage)
	}

	t.Logf("\nTotal detections: %d", totalDetections)
	t.Logf("Overall detection rate: %.2f%%", float64(totalDetections)/float64(totalPackets)*100)
}
