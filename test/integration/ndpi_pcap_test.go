//go:build integration
// +build integration

package integration

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/example/BitTorrentBlocker/internal/blocker"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

// TestNDPI_BitTorrentPcap tests BitTorrent detection using real-world pcap files
// These are real-world BitTorrent traffic captures originally from the nDPI project
func TestNDPI_BitTorrentPcap(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping nDPI pcap test in short mode")
	}

	testCases := []struct {
		name            string
		pcapFile        string
		expectedFlows   int  // Number of BitTorrent flows nDPI expects
		shouldDetectAny bool // Should detect at least one BitTorrent packet
		description     string
	}{
		{
			name:            "Standard BitTorrent TCP",
			pcapFile:        "testdata/pcap/bittorrent.pcap",
			expectedFlows:   24,
			shouldDetectAny: true,
			description:     "Standard BitTorrent TCP protocol with handshakes and data transfer",
		},
		{
			name:            "BitTorrent TCP Missing Initial Packets",
			pcapFile:        "testdata/pcap/bittorrent_tcp_miss.pcapng",
			expectedFlows:   1,
			shouldDetectAny: true,
			description:     "BitTorrent detection when initial TCP handshake packets are missing",
		},
		{
			name:            "BitTorrent uTP (UDP)",
			pcapFile:        "testdata/pcap/bittorrent_utp.pcap",
			expectedFlows:   2,
			shouldDetectAny: true,
			description:     "BitTorrent over UDP using Micro Transport Protocol (uTP)",
		},
		{
			name:            "BitTorrent DHT DNS Queries",
			pcapFile:        "testdata/pcap/bt-dns.pcap",
			expectedFlows:   0, // DNS queries, not direct BT traffic
			shouldDetectAny: false,
			description:     "BitTorrent DHT DNS queries (not direct BT protocol)",
		},
		{
			name:            "BitTorrent DHT Peer Search",
			pcapFile:        "testdata/pcap/bt_search.pcap",
			expectedFlows:   0, // DHT search packets
			shouldDetectAny: true,
			description:     "BitTorrent DHT peer search queries",
		},
		{
			name:            "BitTorrent over TLS",
			pcapFile:        "testdata/pcap/tls_torrent.pcapng",
			expectedFlows:   1,
			shouldDetectAny: false, // Our detector doesn't decrypt TLS
			description:     "BitTorrent encrypted with TLS (requires TLS decryption)",
		},
	}

	config := blocker.DefaultConfig()
	analyzer := blocker.NewAnalyzer(config)

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Tests run from test/integration, so go up to project root
			pcapPath := filepath.Join("..", tc.pcapFile)

			// Check if pcap file exists
			if _, err := os.Stat(pcapPath); os.IsNotExist(err) {
				t.Skipf("Pcap file not found: %s", pcapPath)
				return
			}

			t.Logf("Testing: %s", tc.description)
			t.Logf("Reading pcap: %s", pcapPath)

			// Open pcap file
			f, err := os.Open(pcapPath)
			if err != nil {
				t.Fatalf("Failed to open pcap file %s: %v", pcapPath, err)
			}
			defer f.Close()

			// Try pcap reader first, fallback to pcapng if that fails
			var packetSource *gopacket.PacketSource
			reader, err := pcapgo.NewReader(f)
			if err != nil {
				// Might be pcapng format, try that
				f.Seek(0, 0) // Reset file pointer
				ngReader, ngErr := pcapgo.NewNgReader(f, pcapgo.NgReaderOptions{})
				if ngErr != nil {
					t.Fatalf("Failed to read pcap file (tried both pcap and pcapng): pcap error: %v, pcapng error: %v", err, ngErr)
				}
				packetSource = gopacket.NewPacketSource(ngReader, ngReader.LinkType())
			} else {
				packetSource = gopacket.NewPacketSource(reader, layers.LinkTypeEthernet)
			}

			detectedPackets := 0
			totalPackets := 0
			detectionReasons := make(map[string]int)

			// Read packets
			for packet := range packetSource.Packets() {
				totalPackets++

				// Extract TCP or UDP payload
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
				} else {
					continue
				}

				if len(payload) == 0 {
					continue
				}

				// Analyze packet
				result := analyzer.AnalyzePacket(payload, isUDP)
				if result.ShouldBlock {
					detectedPackets++
					detectionReasons[result.Reason]++
				}
			}

			t.Logf("Results:")
			t.Logf("  Total packets: %d", totalPackets)
			t.Logf("  Detected as BitTorrent: %d", detectedPackets)
			t.Logf("  Expected flows (nDPI): %d", tc.expectedFlows)

			if len(detectionReasons) > 0 {
				t.Logf("  Detection reasons:")
				for reason, count := range detectionReasons {
					t.Logf("    - %s: %d packets", reason, count)
				}
			}

			// Validate expectations
			if tc.shouldDetectAny {
				if detectedPackets == 0 {
					t.Errorf("Expected to detect BitTorrent traffic, but detected 0 packets")
				} else {
					t.Logf("✓ Successfully detected BitTorrent traffic")
				}
			} else {
				if detectedPackets > 0 {
					t.Logf("Note: Detected %d packets as BitTorrent (nDPI expects %d flows)", detectedPackets, tc.expectedFlows)
				} else {
					t.Logf("✓ Correctly did not detect BitTorrent (as expected)")
				}
			}
		})
	}
}

// TestNDPI_CompareDetectionMethods compares our detection against nDPI's expected results
func TestNDPI_CompareDetectionMethods(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping nDPI comparison test in short mode")
	}

	pcapPath := filepath.Join("..", "testdata", "pcap", "bittorrent.pcap")

	// Check if pcap file exists
	if _, err := os.Stat(pcapPath); os.IsNotExist(err) {
		t.Skip("Pcap file not found: make sure testdata/pcap folder is present")
		return
	}

	config := blocker.DefaultConfig()
	analyzer := blocker.NewAnalyzer(config)

	// Open pcap file
	f, err := os.Open(pcapPath)
	if err != nil {
		t.Fatalf("Failed to open pcap file: %v", err)
	}
	defer f.Close()

	// Create pcap reader
	reader, err := pcapgo.NewReader(f)
	if err != nil {
		t.Fatalf("Failed to create pcap reader: %v", err)
	}

	// Track which detection methods work
	detectionMethods := map[string]int{
		"Signature Match":   0,
		"UDP Tracker":       0,
		"uTP Protocol":      0,
		"DHT Bencoded":      0,
		"MSE/PE Encryption": 0,
		"Unknown":           0,
	}

	totalDetected := 0
	packetSource := gopacket.NewPacketSource(reader, layers.LinkTypeEthernet)

	for packet := range packetSource.Packets() {
		// Extract TCP payload
		if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
			tcp, _ := tcpLayer.(*layers.TCP)
			if len(tcp.Payload) == 0 {
				continue
			}

			result := analyzer.AnalyzePacket(tcp.Payload, false)
			if result.ShouldBlock {
				totalDetected++

				// Categorize detection method
				switch {
				case contains(result.Reason, "Signature"):
					detectionMethods["Signature Match"]++
				case contains(result.Reason, "UDP Tracker"):
					detectionMethods["UDP Tracker"]++
				case contains(result.Reason, "uTP"):
					detectionMethods["uTP Protocol"]++
				case contains(result.Reason, "DHT"):
					detectionMethods["DHT Bencoded"]++
				case contains(result.Reason, "MSE") || contains(result.Reason, "PE"):
					detectionMethods["MSE/PE Encryption"]++
				default:
					detectionMethods["Unknown"]++
				}
			}
		}
	}

	t.Logf("Detection Method Statistics:")
	t.Logf("  Total packets detected: %d", totalDetected)
	t.Logf("  nDPI expected flows: 24")
	t.Logf("\nBreakdown by detection method:")

	for method, count := range detectionMethods {
		if count > 0 {
			percentage := float64(count) / float64(totalDetected) * 100
			t.Logf("  - %-20s: %d packets (%.1f%%)", method, count, percentage)
		}
	}

	// Validate we detected something
	if totalDetected == 0 {
		t.Error("Failed to detect any BitTorrent traffic in nDPI test pcap")
	} else {
		t.Logf("\n✓ Successfully detected BitTorrent traffic using nDPI test data")
	}
}

// Helper function
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || findInString(s, substr))
}
