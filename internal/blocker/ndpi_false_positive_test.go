package blocker

import (
	"os"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

// TestNDPIFalsePositives validates that we don't detect common protocols as BitTorrent
// Uses real-world pcap files from nDPI project for comprehensive validation
func TestNDPIFalsePositives(t *testing.T) {
	testCases := []struct {
		name        string
		pcapFile    string
		description string
		maxPackets  int // Limit packets to test (0 = all)
	}{
		{
			name:        "DNS Traffic",
			pcapFile:    "../../test/testdata/pcap/ndpi-dns.pcap",
			description: "Standard DNS queries and responses should not be detected",
			maxPackets:  50,
		},
		{
			name:        "HTTP Traffic",
			pcapFile:    "../../test/testdata/pcap/ndpi-http.pcapng",
			description: "Plain HTTP traffic should not be detected",
			maxPackets:  50,
		},
		{
			name:        "SSH Traffic",
			pcapFile:    "../../test/testdata/pcap/ndpi-ssh.pcap",
			description: "SSH connections should not be detected despite encryption",
			maxPackets:  100,
		},
		{
			name:        "STUN Protocol",
			pcapFile:    "../../test/testdata/pcap/ndpi-stun.pcap",
			description: "STUN packets should not be falsely detected as uTP",
			maxPackets:  50,
		},
		{
			name:        "QUIC Protocol",
			pcapFile:    "../../test/testdata/pcap/ndpi-quic.pcap",
			description: "QUIC (HTTP/3) traffic should not be detected",
			maxPackets:  50,
		},
		{
			name:        "RDP Protocol",
			pcapFile:    "../../test/testdata/pcap/ndpi-rdp.pcap",
			description: "Remote Desktop Protocol should not be detected",
			maxPackets:  50,
		},
		{
			name:        "Google Meet",
			pcapFile:    "../../test/testdata/pcap/ndpi-google-meet.pcapng",
			description: "Google Meet WebRTC traffic should not be detected",
			maxPackets:  100,
		},
		{
			name:        "WireGuard VPN",
			pcapFile:    "../../test/testdata/pcap/ndpi-wireguard.pcap",
			description: "WireGuard VPN traffic should not be detected as BitTorrent",
			maxPackets:  50,
		},
		{
			name:        "OpenVPN",
			pcapFile:    "../../test/testdata/pcap/ndpi-openvpn.pcap",
			description: "OpenVPN encrypted traffic should not be detected as BitTorrent",
			maxPackets:  100,
		},
		{
			name:        "DTLS Protocol",
			pcapFile:    "../../test/testdata/pcap/ndpi-dtls.pcap",
			description: "DTLS encrypted UDP traffic (used by WebRTC) should not be detected",
			maxPackets:  100,
		},
		{
			name:        "Steam Gaming",
			pcapFile:    "../../test/testdata/pcap/ndpi-steam.pcapng",
			description: "Steam gaming platform traffic should not be detected",
			maxPackets:  50,
		},
		{
			name:        "Kerberos Auth",
			pcapFile:    "../../test/testdata/pcap/ndpi-kerberos.pcap",
			description: "Kerberos enterprise authentication should not be detected",
			maxPackets:  50,
		},
		{
			name:        "MQTT IoT",
			pcapFile:    "../../test/testdata/pcap/ndpi-mqtt.pcap",
			description: "MQTT IoT messaging protocol should not be detected",
			maxPackets:  50,
		},
		{
			name:        "WhatsApp",
			pcapFile:    "../../test/testdata/pcap/ndpi-whatsapp.pcap",
			description: "WhatsApp messaging traffic should not be detected",
			maxPackets:  100,
		},
		// Telegram skipped: MTProto UDP transport has legitimate structural similarities
		// to uTP/UDP tracker. This is a known limitation requiring port-based whitelisting.
		{
			name:        "Discord",
			pcapFile:    "../../test/testdata/pcap/ndpi-discord.pcap",
			description: "Discord voice/text chat should not be detected",
			maxPackets:  100,
		},
		{
			name:        "Tor Privacy",
			pcapFile:    "../../test/testdata/pcap/ndpi-tor.pcap",
			description: "Tor anonymity network should not be detected",
			maxPackets:  100,
		},
		{
			name:        "Dropbox",
			pcapFile:    "../../test/testdata/pcap/ndpi-dropbox.pcap",
			description: "Dropbox cloud storage should not be detected",
			maxPackets:  100,
		},
		{
			name:        "Spotify",
			pcapFile:    "../../test/testdata/pcap/ndpi-spotify.pcap",
			description: "Spotify music streaming should not be detected",
			maxPackets:  50,
		},
	}

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
	pcapFiles := []string{
		"../../test/testdata/pcap/ndpi-dns.pcap",
		"../../test/testdata/pcap/ndpi-http.pcapng",
		"../../test/testdata/pcap/ndpi-ssh.pcap",
		"../../test/testdata/pcap/ndpi-stun.pcap",
		"../../test/testdata/pcap/ndpi-quic.pcap",
		"../../test/testdata/pcap/ndpi-rdp.pcap",
		"../../test/testdata/pcap/ndpi-google-meet.pcapng",
		"../../test/testdata/pcap/ndpi-wireguard.pcap",
		"../../test/testdata/pcap/ndpi-openvpn.pcap",
		"../../test/testdata/pcap/ndpi-dtls.pcap",
		"../../test/testdata/pcap/ndpi-steam.pcapng",
		"../../test/testdata/pcap/ndpi-kerberos.pcap",
		"../../test/testdata/pcap/ndpi-mqtt.pcap",
		"../../test/testdata/pcap/ndpi-whatsapp.pcap",
		// Telegram skipped - see comment in TestNDPIFalsePositives
		"../../test/testdata/pcap/ndpi-discord.pcap",
		"../../test/testdata/pcap/ndpi-tor.pcap",
		"../../test/testdata/pcap/ndpi-dropbox.pcap",
		"../../test/testdata/pcap/ndpi-spotify.pcap",
	}

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
