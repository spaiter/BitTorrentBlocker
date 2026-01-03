package blocker

import (
	"bytes"
	"os"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

// TestAnalyzeGnutellaVsShareaza compares Gnutella and potential Shareaza BitTorrent packets
func TestAnalyzeGnutellaVsShareaza(t *testing.T) {
	pcapPath := "../../test/testdata/pcap/false-positive/gnutella.pcap"

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
	shareazaPackets := 0
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

		// Check if this packet contains Shareaza
		if bytes.Contains(payload, []byte("Shareaza")) {
			shareazaPackets++

			t.Logf("\n=== Packet #%d with Shareaza ===", shareazaPackets)

			// Show full packet context
			printLen := 200
			if len(payload) < printLen {
				printLen = len(payload)
			}
			t.Logf("Payload (%d bytes): %q", len(payload), payload[:printLen])

			// Check for Gnutella markers
			hasGnutella := bytes.Contains(payload, []byte("GNUTELLA"))
			t.Logf("Contains GNUTELLA: %v", hasGnutella)

			// Check for BitTorrent markers
			hasBTProtocol := bytes.Contains(payload, []byte("BitTorrent protocol"))
			hasInfoHash := bytes.Contains(payload, []byte("info_hash"))
			hasPeerID := bytes.Contains(payload, []byte("peer_id"))
			hasAnnounce := bytes.Contains(payload, []byte("announce"))

			t.Logf("BitTorrent markers:")
			t.Logf("  - BitTorrent protocol: %v", hasBTProtocol)
			t.Logf("  - info_hash: %v", hasInfoHash)
			t.Logf("  - peer_id: %v", hasPeerID)
			t.Logf("  - announce: %v", hasAnnounce)

			// Check what signature is triggering
			if CheckSignatures(payload) {
				t.Logf("CheckSignatures returned TRUE")
				// Check each signature individually
				sigs := [][]byte{
					[]byte("BitTorrent protocol"),
					[]byte("d1:ad2:id20:"),
					[]byte("d1:rd2:id20:"),
					[]byte("announce"),
					[]byte("info_hash"),
					[]byte("/data?fid="),
					[]byte("User-Agent: Azureus"),
					[]byte("User-Agent: BitTorrent"),
					[]byte("User-Agent: BTWebClient"),
					[]byte("User-Agent: Shareaza"),
					[]byte("User-Agent: FlashGet"),
				}
				for _, sig := range sigs {
					if bytes.Contains(payload, sig) {
						t.Logf("  Signature match: %q", sig)
					}
				}
			} else {
				t.Logf("CheckSignatures returned FALSE")
			}

			// Check what the analyzer detects
			result := analyzer.AnalyzePacket(payload, false)
			t.Logf("Analyzer result: ShouldBlock=%v, Reason=%s", result.ShouldBlock, result.Reason)

			if result.ShouldBlock && hasGnutella {
				falsePositives++
				t.Logf("❌ FALSE POSITIVE: Gnutella packet detected as BitTorrent")
			}
		}
	}

	t.Logf("\n=== Summary ===")
	t.Logf("Total packets: %d", allPackets)
	t.Logf("Packets with Shareaza: %d", shareazaPackets)
	t.Logf("False positives: %d", falsePositives)
}
