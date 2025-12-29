// Simple E2E test that tests packet analysis without nfqueue
package main

import (
	"fmt"
	"os"

	"github.com/example/BitTorrentBlocker/internal/blocker"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: test-analyzer <test_name>")
		os.Exit(1)
	}

	testName := os.Args[1]
	config := blocker.DefaultConfig()
	analyzer := blocker.NewAnalyzer(config)

	var payload []byte
	var isUDP bool
	var expectedBlock bool
	var description string

	switch testName {
	case "handshake":
		description = "BitTorrent Handshake"
		payload = buildBitTorrentHandshake()
		isUDP = false
		expectedBlock = true

	case "udp_tracker":
		description = "UDP Tracker Announce"
		payload = buildUDPTrackerAnnounce()
		isUDP = true
		expectedBlock = true

	case "dht":
		description = "DHT Get_Peers Query"
		payload = buildDHTQuery()
		isUDP = true
		expectedBlock = true

	case "utp":
		description = "uTP SYN Packet"
		payload = buildUTPSYN()
		isUDP = true
		expectedBlock = true

	case "mse":
		description = "MSE/PE Encrypted Stream"
		payload = buildMSEHandshake()
		isUDP = false
		expectedBlock = true

	case "https":
		description = "Normal HTTPS Traffic"
		payload = buildHTTPSTraffic()
		isUDP = false
		expectedBlock = false

	case "dns":
		description = "Normal DNS Query"
		payload = buildDNSQuery()
		isUDP = true
		expectedBlock = false

	default:
		fmt.Printf("Unknown test: %s\n", testName)
		os.Exit(1)
	}

	// Analyze the packet
	result := analyzer.AnalyzePacket(payload, isUDP)

	// Print results
	fmt.Printf("Test: %s\n", description)
	fmt.Printf("Payload size: %d bytes\n", len(payload))
	fmt.Printf("Expected: %v | Got: %v\n", expectedBlock, result.ShouldBlock)

	if result.ShouldBlock {
		fmt.Printf("Reason: %s\n", result.Reason)
	}

	// Verify result matches expectation
	if result.ShouldBlock == expectedBlock {
		fmt.Println("✓ PASS")
		os.Exit(0)
	} else {
		fmt.Println("✗ FAIL")
		os.Exit(1)
	}
}

// Helper functions to build realistic packets

func buildBitTorrentHandshake() []byte {
	handshake := make([]byte, 68)
	handshake[0] = 19
	copy(handshake[1:20], []byte("BitTorrent protocol"))
	copy(handshake[28:48], []byte("12345678901234567890"))
	copy(handshake[48:68], []byte("-UT3500-123456789012"))
	return handshake
}

func buildUDPTrackerAnnounce() []byte {
	packet := make([]byte, 98)
	copy(packet[0:8], []byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88})
	packet[8], packet[9], packet[10], packet[11] = 0x00, 0x00, 0x00, 0x01
	packet[12], packet[13], packet[14], packet[15] = 0x12, 0x34, 0x56, 0x78
	copy(packet[16:36], []byte("infohash12345678901"))
	copy(packet[36:39], []byte("-qB"))
	copy(packet[39:56], []byte("4150-12345678901"))
	packet[96], packet[97] = 0x1A, 0xE1
	return packet
}

func buildDHTQuery() []byte {
	query := "d1:ad2:id20:abcdefghij01234567896:target20:mnopqrstuvwxyz123456e1:q9:get_peers1:t2:aa1:y1:qe"
	return []byte(query)
}

func buildUTPSYN() []byte {
	packet := make([]byte, 20)
	packet[0] = 0x41
	packet[1] = 0x00
	return packet
}

func buildMSEHandshake() []byte {
	packet := make([]byte, 120)
	for i := 0; i < 96; i++ {
		packet[i] = byte((i * 37) % 256)
	}
	for i := 96; i < 104; i++ {
		packet[i] = byte((i * 13) % 256)
	}
	for i := 104; i < 112; i++ {
		packet[i] = 0x00
	}
	packet[112] = 0x00
	packet[113] = 0x00
	packet[114] = 0x00
	packet[115] = 0x03
	return packet
}

func buildHTTPSTraffic() []byte {
	traffic := make([]byte, 200)
	traffic[0] = 0x17
	traffic[1] = 0x03
	traffic[2] = 0x03
	traffic[3] = 0x00
	traffic[4] = 0xC3
	pattern := []byte{0xAB, 0xCD, 0xEF, 0x12, 0x34, 0x56, 0x78, 0x90}
	for i := 5; i < len(traffic); i++ {
		traffic[i] = pattern[(i-5)%len(pattern)]
	}
	return traffic
}

func buildDNSQuery() []byte {
	query := make([]byte, 33)
	query[0], query[1] = 0x12, 0x34
	query[2], query[3] = 0x01, 0x00
	query[4], query[5] = 0x00, 0x01
	query[6], query[7] = 0x00, 0x00
	query[8], query[9] = 0x00, 0x00
	query[10], query[11] = 0x00, 0x00
	copy(query[12:], []byte{0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0x03, 'c', 'o', 'm', 0x00})
	query[30], query[31] = 0x00, 0x01
	query[32] = 0x01
	return query
}
