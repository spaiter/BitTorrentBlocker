package blocker

import (
	"os"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

// TestSuricataDHTDetection validates our detection against Suricata's reference test pcap
// The pcap contains 16 packets testing various DHT message types:
// - Ping queries/responses (packets 1-3)
// - Error responses (packets 4, 16)
// - find_node queries/responses (packets 5-6)
// - get_peers queries/responses (packets 7-10)
// - announce_peer queries/responses (packets 11-14)
// - Malformed packets (packet 15)
func TestSuricataDHTDetection(t *testing.T) {
	// Open the Suricata test pcap
	f, err := os.Open("../../test/testdata/pcap/true-positive/suricata-dht.pcap")
	if err != nil {
		t.Fatalf("Failed to open suricata-dht.pcap: %v", err)
	}
	defer f.Close()

	reader, err := pcapgo.NewReader(f)
	if err != nil {
		t.Fatalf("Failed to create pcap reader: %v", err)
	}

	analyzer := NewAnalyzer(DefaultConfig())

	// Expected detections based on test.yaml
	// Packets 1-14, 16 should be detected (15 is malformed but still has DHT structure)
	expectedDetections := map[int]struct {
		shouldDetect bool
		description  string
	}{
		1:  {true, "DHT ping query (190.0.0.1:40000 -> 190.0.0.2:50000)"},
		2:  {true, "DHT ping response (190.0.0.2:50000 -> 190.0.0.1:40000)"},
		3:  {true, "DHT ping query (190.0.0.1:20000 -> 190.0.0.3:30000)"},
		4:  {true, "DHT error response (190.0.0.3:30000 -> 190.0.0.1:20000)"},
		5:  {true, "DHT find_node query with client version UT01"},
		6:  {true, "DHT find_node response with nodes"},
		7:  {true, "DHT get_peers query with info_hash"},
		8:  {true, "DHT get_peers response with token and peer values"},
		9:  {true, "DHT get_peers query (no client version)"},
		10: {true, "DHT get_peers response with token only"},
		11: {true, "DHT announce_peer with explicit port 6881"},
		12: {true, "DHT announce_peer response"},
		13: {true, "DHT announce_peer with implied_port=1"},
		14: {true, "DHT announce_peer response"},
		15: {true, "Malformed DHT packet (should still detect DHT structure)"},
		16: {true, "DHT error response: Malformed Packet (error code 203)"},
	}

	packetNum := 0
	detectedCount := 0

	for {
		data, _, err := reader.ReadPacketData()
		if err != nil {
			break // End of file
		}

		packetNum++

		// Decode packet
		packet := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.Default)

		// Parse UDP layer
		udpLayer := packet.Layer(layers.LayerTypeUDP)
		if udpLayer == nil {
			continue
		}

		udp, ok := udpLayer.(*layers.UDP)
		if !ok {
			continue
		}

		payload := udp.Payload
		if len(payload) == 0 {
			continue
		}

		// Analyze the packet
		result := analyzer.AnalyzePacket(payload, true)

		expected, exists := expectedDetections[packetNum]
		if !exists {
			continue // Skip packets we don't have expectations for
		}

		if result.ShouldBlock {
			detectedCount++
			t.Logf("Packet %2d: ✅ DETECTED - %s (Reason: %s)",
				packetNum, expected.description, result.Reason)

			if !expected.shouldDetect {
				t.Errorf("Packet %d: False positive - should NOT be detected: %s",
					packetNum, expected.description)
			}
		} else {
			t.Logf("Packet %2d: ❌ MISSED - %s",
				packetNum, expected.description)

			if expected.shouldDetect {
				t.Errorf("Packet %d: False negative - should be detected: %s",
					packetNum, expected.description)
			}
		}
	}

	// Summary
	expectedTotal := 0
	for _, exp := range expectedDetections {
		if exp.shouldDetect {
			expectedTotal++
		}
	}

	t.Logf("\n=== SUMMARY ===")
	t.Logf("Total packets analyzed: %d", packetNum)
	t.Logf("Expected detections: %d", expectedTotal)
	t.Logf("Actual detections: %d", detectedCount)
	t.Logf("Detection rate: %.1f%%", float64(detectedCount)/float64(expectedTotal)*100)

	// We should detect all DHT packets (including malformed ones that have DHT structure)
	if detectedCount < expectedTotal {
		t.Errorf("Detection rate too low: %d/%d (%.1f%%) - expected 100%%",
			detectedCount, expectedTotal, float64(detectedCount)/float64(expectedTotal)*100)
	}
}

// TestSuricataDHTPacketDetails provides detailed analysis of specific Suricata test packets
func TestSuricataDHTPacketDetails(t *testing.T) {
	f, err := os.Open("../../test/testdata/pcap/true-positive/suricata-dht.pcap")
	if err != nil {
		t.Skipf("Skipping detailed test - pcap not found: %v", err)
	}
	defer f.Close()

	reader, err := pcapgo.NewReader(f)
	if err != nil {
		t.Skipf("Failed to create pcap reader: %v", err)
	}

	analyzer := NewAnalyzer(DefaultConfig())

	// Specific test cases with expected bencode structure
	testCases := []struct {
		packetNum    int
		name         string
		expectedType string // q, r, or e
		expectedKey  string // Key to look for in payload
	}{
		{1, "ping query", "q", "4:ping"},
		{2, "ping response", "r", "1:y1:r"},
		{4, "error response", "e", "1:y1:e"},
		{5, "find_node query", "q", "9:find_node"},
		{7, "get_peers query", "q", "9:get_peers"},
		{11, "announce_peer query", "q", "13:announce_peer"},
		{15, "malformed packet", "q", "1:y1:q"}, // Still has DHT structure
	}

	packetNum := 0
	for {
		data, _, err := reader.ReadPacketData()
		if err != nil {
			break // End of file
		}

		packetNum++

		// Decode packet
		packet := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.Default)

		// Find matching test case
		var testCase *struct {
			packetNum    int
			name         string
			expectedType string
			expectedKey  string
		}
		for i := range testCases {
			if testCases[i].packetNum == packetNum {
				testCase = &testCases[i]
				break
			}
		}
		if testCase == nil {
			continue // Skip packets we're not testing
		}

		// Parse UDP layer
		udpLayer := packet.Layer(layers.LayerTypeUDP)
		if udpLayer == nil {
			t.Errorf("Packet %d (%s): No UDP layer found", packetNum, testCase.name)
			continue
		}

		udp, ok := udpLayer.(*layers.UDP)
		if !ok {
			t.Errorf("Packet %d (%s): Failed to cast UDP layer", packetNum, testCase.name)
			continue
		}

		payload := udp.Payload
		if len(payload) == 0 {
			t.Errorf("Packet %d (%s): Empty payload", packetNum, testCase.name)
			continue
		}

		// Analyze the packet
		result := analyzer.AnalyzePacket(payload, true)

		// Log details
		t.Logf("\n--- Packet %d: %s ---", packetNum, testCase.name)
		t.Logf("Payload length: %d bytes", len(payload))
		t.Logf("First 100 bytes: %q", string(payload[:minInt(100, len(payload))]))
		t.Logf("Detection result: %v", result.ShouldBlock)
		if result.ShouldBlock {
			t.Logf("Detection reason: %s", result.Reason)
		}

		// Validate detection
		if !result.ShouldBlock {
			t.Errorf("Packet %d (%s): Failed to detect DHT traffic", packetNum, testCase.name)
		}

		// Validate expected key is present
		if !contains(payload, []byte(testCase.expectedKey)) {
			t.Errorf("Packet %d (%s): Expected key '%s' not found in payload",
				packetNum, testCase.name, testCase.expectedKey)
		}
	}
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func contains(haystack, needle []byte) bool {
	for i := 0; i <= len(haystack)-len(needle); i++ {
		match := true
		for j := 0; j < len(needle); j++ {
			if haystack[i+j] != needle[j] {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}
