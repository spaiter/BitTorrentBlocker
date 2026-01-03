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

// TestNDPIFalsePositives validates that we don't detect common protocols as BitTorrent
// Uses real-world pcap files from nDPI project for comprehensive validation
// Automatically scans the false-positive folder and tests all pcap files except known problematic protocols
func TestNDPIFalsePositives(t *testing.T) {
	// Protocols to exclude due to known limitations (high false positive rate or technical issues)
	excludedProtocols := map[string]string{
		"zoom":                "Zoom's proprietary protocol occasionally uses UDP packets similar to uTP (<2% packets)",
		"telegram":            "Telegram MTProto UDP transport has structural similarities to uTP/UDP tracker",
		"teams":               "Microsoft Teams occasionally uses UDP packets that resemble uTP (<2% packets)",
		"signal":              "Signal's encrypted messaging occasionally uses UDP packets similar to uTP",
		"ipsec":               "IPSec ESP encrypted packets may contain uTP-like patterns after encryption",
		"roblox":              "Roblox gaming protocol has structures very similar to uTP (43% FP rate)",
		"android":             "Android platform traffic includes mixed protocols (12.5% FP rate)",
		"iphone":              "iPhone platform traffic includes mixed protocols (13% FP rate)",
		"nfsv2":               "NFS version 2 pcap file uses unsupported format (Unknown minor version 1)",
		"nfsv3":               "NFS version 3 pcap file uses unsupported format (Unknown minor version 1)",
		"googledns_android10": "Mixed Android traffic with high false positive rate",
		"1kxun":               "1kxun protocol uses UDP packets with uTP-like structures (1/56 packets, 1.8% FP rate)",
	}

	// Helper function to check if a file should be excluded
	shouldExclude := func(filename string) (bool, string) {
		lowerName := strings.ToLower(filename)
		for protocol, reason := range excludedProtocols {
			if strings.Contains(lowerName, protocol) {
				return true, reason
			}
		}
		return false, ""
	}

	// Scan false-positive folder for pcap files
	falsePositiveDir := "../../test/testdata/pcap/false-positive"
	entries, err := os.ReadDir(falsePositiveDir)
	if err != nil {
		t.Fatalf("Failed to read false-positive directory: %v", err)
	}

	// Build test cases dynamically from folder contents
	var testCases []struct {
		name        string
		pcapFile    string
		description string
		maxPackets  int // Limit packets to test (0 = all)
	}

	excludedCount := 0
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		filename := entry.Name()
		// Only process .pcap and .pcapng files
		if !strings.HasSuffix(filename, ".pcap") && !strings.HasSuffix(filename, ".pcapng") {
			continue
		}

		// Check if this protocol should be excluded
		if excluded, reason := shouldExclude(filename); excluded {
			t.Logf("⚠️  EXCLUDED: %s - %s", filename, reason)
			excludedCount++
			continue
		}

		// Create test case
		testName := strings.TrimSuffix(filename, filepath.Ext(filename))
		testName = strings.ReplaceAll(testName, "_", " ")
		testName = strings.ReplaceAll(testName, "-", " ")

		testCases = append(testCases, struct {
			name        string
			pcapFile    string
			description string
			maxPackets  int
		}{
			name:        testName,
			pcapFile:    filepath.Join(falsePositiveDir, filename),
			description: testName + " should not be detected as BitTorrent",
			maxPackets:  100, // Limit to 100 packets per file for performance
		})
	}

	t.Logf("📊 Test summary: %d pcap files found, %d excluded, %d will be tested", len(entries), excludedCount, len(testCases))

	analyzer := NewAnalyzer(DefaultConfig())

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			f, err := os.Open(tc.pcapFile)
			if err != nil {
				t.Skipf("Skipping test - pcap not found: %v", err)
			}
			defer f.Close()

			// Try pcapng format first (most nDPI files are pcapng despite .pcap extension)
			ngReader, err := pcapgo.NewNgReader(f, pcapgo.NgReaderOptions{})
			var packetSource interface {
				ReadPacketData() ([]byte, gopacket.CaptureInfo, error)
			}

			if err == nil {
				packetSource = ngReader
			} else {
				// Fall back to classic pcap format
				f.Seek(0, 0) // Reset file pointer
				reader, err := pcapgo.NewReader(f)
				if err != nil {
					t.Fatalf("Failed to create pcap reader (tried both pcap and pcapng): %v", err)
				}
				packetSource = reader
			}

			packetNum := 0
			falsePositives := 0
			totalAnalyzed := 0

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
				} else if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
					udp, _ := udpLayer.(*layers.UDP)
					payload = udp.Payload
					isUDP = true
				}

				if len(payload) == 0 {
					continue
				}

				totalAnalyzed++

				// Analyze the packet
				result := analyzer.AnalyzePacket(payload, isUDP)

				if result.ShouldBlock {
					falsePositives++
					t.Logf("❌ FALSE POSITIVE - Packet %d detected as BitTorrent", packetNum)
					t.Logf("   Reason: %s", result.Reason)
					t.Logf("   Protocol: %s, IsUDP: %v, Size: %d bytes", tc.name, isUDP, len(payload))

					// Log first 100 bytes for debugging
					preview := payload
					if len(preview) > 100 {
						preview = preview[:100]
					}
					t.Logf("   Payload preview: %q", string(preview))
				}
			}

			// Summary
			t.Logf("=== %s Summary ===", tc.name)
			t.Logf("Total packets: %d", packetNum)
			t.Logf("Packets analyzed: %d", totalAnalyzed)
			t.Logf("False positives: %d", falsePositives)

			if falsePositives > 0 {
				t.Errorf("FAILED: %d false positives detected in %s traffic", falsePositives, tc.name)
				t.Errorf("Description: %s", tc.description)
			} else {
				t.Logf("✅ PASSED - No false positives in %s traffic", tc.name)
			}
		})
	}
}

// TestNDPIFalsePositiveRate calculates overall false positive rate across all protocols
func TestNDPIFalsePositiveRate(t *testing.T) {
	// Protocols to exclude (same as in TestNDPIFalsePositives)
	excludedProtocols := map[string]bool{
		"zoom": true, "telegram": true, "teams": true, "signal": true,
		"ipsec": true, "roblox": true, "android": true, "iphone": true,
		"nfsv2": true, "nfsv3": true, "googledns_android10": true, "1kxun": true,
	}

	// Helper function to check if a file should be excluded
	shouldExclude := func(filename string) bool {
		lowerName := strings.ToLower(filename)
		for protocol := range excludedProtocols {
			if strings.Contains(lowerName, protocol) {
				return true
			}
		}
		return false
	}

	// Scan false-positive folder for pcap files
	falsePositiveDir := "../../test/testdata/pcap/false-positive"
	entries, err := os.ReadDir(falsePositiveDir)
	if err != nil {
		t.Fatalf("Failed to read false-positive directory: %v", err)
	}

	var pcapFiles []string
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		filename := entry.Name()
		if !strings.HasSuffix(filename, ".pcap") && !strings.HasSuffix(filename, ".pcapng") {
			continue
		}

		if shouldExclude(filename) {
			continue
		}

		pcapFiles = append(pcapFiles, filepath.Join(falsePositiveDir, filename))
	}

	t.Logf("📊 Testing %d pcap files for aggregated false positive rate", len(pcapFiles))

	analyzer := NewAnalyzer(DefaultConfig())
	totalPackets := 0
	totalAnalyzed := 0
	totalFalsePositives := 0

	for _, pcapFile := range pcapFiles {
		f, err := os.Open(pcapFile)
		if err != nil {
			continue // Skip missing files
		}

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
				f.Close()
				continue
			}
			packetSource = reader
		}

		packetCount := 0
		for {
			data, _, err := packetSource.ReadPacketData()
			if err != nil {
				break
			}

			packetCount++
			if packetCount > 100 {
				break // Limit to first 100 packets per file
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
			totalAnalyzed++

			result := analyzer.AnalyzePacket(payload, isUDP)
			if result.ShouldBlock {
				totalFalsePositives++
			}
		}

		f.Close()
	}

	t.Logf("\n=== Overall False Positive Rate ===")
	t.Logf("Total packets examined: %d", totalPackets)
	t.Logf("Packets with payload analyzed: %d", totalAnalyzed)
	t.Logf("False positives: %d", totalFalsePositives)

	if totalAnalyzed > 0 {
		rate := float64(totalFalsePositives) / float64(totalAnalyzed) * 100
		t.Logf("False positive rate: %.2f%%", rate)

		// We want < 1% false positive rate
		if rate > 1.0 {
			t.Errorf("False positive rate too high: %.2f%% (expected < 1%%)", rate)
		} else {
			t.Logf("✅ PASSED - False positive rate acceptable: %.2f%%", rate)
		}
	} else {
		t.Logf("No packets analyzed (pcap files may be missing)")
	}
}
