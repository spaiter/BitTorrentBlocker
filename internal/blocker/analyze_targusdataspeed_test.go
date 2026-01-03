package blocker

import (
	"os"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

// TestAnalyzeTargusdataspeed analyzes the targusdataspeed "false positive"
func TestAnalyzeTargusdataspeed(t *testing.T) {
	pcapPath := "../../test/testdata/pcap/false-positive/targusdataspeed_false_positives.pcap"

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
	packetNum := 0

	for {
		data, _, err := packetSource.ReadPacketData()
		if err != nil {
			break
		}

		packet := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.Default)

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

		packetNum++

		t.Logf("\n=== Packet #%d ===", packetNum)
		t.Logf("Protocol: %s", map[bool]string{true: "UDP", false: "TCP"}[isUDP])
		t.Logf("Payload length: %d bytes", len(payload))

		// Show payload
		printLen := 200
		if len(payload) < printLen {
			printLen = len(payload)
		}
		t.Logf("Payload: %q", payload[:printLen])
		t.Logf("Hex: %x", payload[:printLen])

		// Analyze
		result := analyzer.AnalyzePacket(payload, isUDP)
		t.Logf("Detection: ShouldBlock=%v, Reason=%s", result.ShouldBlock, result.Reason)

		// Check individual detectors
		t.Logf("CheckBencodeDHT: %v", CheckBencodeDHT(payload))

		// If it's bencode DHT, show the structure
		if CheckBencodeDHT(payload) {
			t.Logf("\n🔍 DHT Bencode Analysis:")

			// Check if this is a bencode dictionary
			if len(payload) > 0 && payload[0] == 'd' {
				t.Logf("  ✓ Bencode dictionary detected (starts with 'd')")
				t.Logf("  Note: This appears to be legitimate BitTorrent DHT traffic")
				t.Logf("  Recommendation: Move this pcap to true-positive folder")
			}
		}
	}

	t.Logf("\n=== Summary ===")
	t.Logf("Total packets analyzed: %d", packetNum)
	t.Logf("\nConclusion: If all packets are DHT bencode dictionaries,")
	t.Logf("this file likely contains actual BitTorrent DHT traffic and is correctly detected.")
}
