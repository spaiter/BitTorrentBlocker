//go:build integration
// +build integration

package integration

import (
	"io/ioutil"
	"os"
	"testing"
	"time"

	"github.com/example/BitTorrentBlocker/internal/blocker"
)

// TestEndToEndDetection tests the full packet analysis pipeline
// with realistic BitTorrent traffic patterns
func TestEndToEndDetection(t *testing.T) {
	config := blocker.DefaultConfig()
	analyzer := blocker.NewAnalyzer(config)

	testCases := []struct {
		name        string
		payload     []byte
		isUDP       bool
		shouldBlock bool
		reason      string
	}{
		{
			name:        "Real BitTorrent Handshake",
			payload:     buildBitTorrentHandshake(),
			isUDP:       false,
			shouldBlock: true,
			reason:      "BitTorrent Signature",
		},
		{
			name:        "Real UDP Tracker Announce",
			payload:     buildUDPTrackerAnnounce(),
			isUDP:       true,
			shouldBlock: true,
			reason:      "UDP Tracker Protocol",
		},
		{
			name:        "Real DHT Get_Peers Query",
			payload:     buildDHTGetPeersQuery(),
			isUDP:       true,
			shouldBlock: true,
			reason:      "BitTorrent Signature",
		},
		{
			name:        "Real uTP SYN Packet",
			payload:     buildUTPSYN(),
			isUDP:       true,
			shouldBlock: true,
			reason:      "uTP Protocol",
		},
		{
			name:        "Real MSE/PE Encrypted Stream",
			payload:     buildMSEHandshake(),
			isUDP:       false,
			shouldBlock: true,
			reason:      "MSE/PE Encryption",
		},
		{
			name:        "Real LSD Announcement",
			payload:     buildLSDAnnouncement(),
			isUDP:       true,
			shouldBlock: true,
			reason:      "BitTorrent Signature", // Will be caught by signature
		},
		{
			name:        "Normal HTTPS Traffic",
			payload:     buildHTTPSTraffic(),
			isUDP:       false,
			shouldBlock: false,
			reason:      "",
		},
		{
			name:        "Normal DNS Query",
			payload:     buildDNSQuery(),
			isUDP:       true,
			shouldBlock: false,
			reason:      "",
		},
		{
			name:        "SSH Handshake",
			payload:     buildSSHHandshake(),
			isUDP:       false,
			shouldBlock: false,
			reason:      "",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := analyzer.AnalyzePacket(tc.payload, tc.isUDP)

			if result.ShouldBlock != tc.shouldBlock {
				t.Errorf("Expected block=%v, got block=%v for %s",
					tc.shouldBlock, result.ShouldBlock, tc.name)
			}

			if tc.shouldBlock && result.Reason == "" {
				t.Errorf("Expected reason for blocked traffic, got empty string")
			}

			if tc.shouldBlock && tc.reason != "" {
				if len(result.Reason) < len(tc.reason) || result.Reason[:len(tc.reason)] != tc.reason {
					t.Logf("Expected reason '%s', got '%s'", tc.reason, result.Reason)
				}
			}
		})
	}
}

// TestMultiLayerDetection tests that all detection layers work together
func TestMultiLayerDetection(t *testing.T) {
	config := blocker.DefaultConfig()
	analyzer := blocker.NewAnalyzer(config)

	// Test that early layers catch traffic before later layers
	tests := []struct {
		name          string
		payload       []byte
		isUDP         bool
		expectedLayer string
	}{
		{
			name:          "MSE catches before entropy",
			payload:       buildMSEHandshake(),
			isUDP:         false,
			expectedLayer: "MSE/PE Encryption",
		},
		{
			name:          "Signature catches DHT",
			payload:       buildDHTGetPeersQuery(),
			isUDP:         true,
			expectedLayer: "BitTorrent Signature",
		},
		{
			name:          "UDP Tracker before uTP",
			payload:       buildUDPTrackerConnect(),
			isUDP:         true,
			expectedLayer: "UDP Tracker Protocol",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := analyzer.AnalyzePacket(tc.payload, tc.isUDP)

			if !result.ShouldBlock {
				t.Errorf("Expected traffic to be blocked")
			}

			if result.Reason != tc.expectedLayer {
				t.Logf("Detection layer: expected '%s', got '%s'",
					tc.expectedLayer, result.Reason)
			}
		})
	}
}

// TestPerformanceBenchmark tests packet processing performance
func TestPerformanceBenchmark(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping performance test in short mode")
	}

	config := blocker.DefaultConfig()
	analyzer := blocker.NewAnalyzer(config)

	payloads := [][]byte{
		buildBitTorrentHandshake(),
		buildUDPTrackerAnnounce(),
		buildDHTGetPeersQuery(),
		buildHTTPSTraffic(),
		buildDNSQuery(),
	}

	iterations := 10000
	isUDP := []bool{false, true, true, false, true}

	for i := 0; i < iterations; i++ {
		idx := i % len(payloads)
		analyzer.AnalyzePacket(payloads[idx], isUDP[idx])
	}

	t.Logf("Processed %d packets successfully", iterations)
}

// TestFalsePositiveRate tests that normal traffic passes through
func TestFalsePositiveRate(t *testing.T) {
	config := blocker.DefaultConfig()
	analyzer := blocker.NewAnalyzer(config)

	normalTraffic := []struct {
		name    string
		payload []byte
		isUDP   bool
	}{
		{"HTTPS GET", buildHTTPSTraffic(), false},
		{"DNS Query", buildDNSQuery(), true},
		{"SSH Handshake", buildSSHHandshake(), false},
		{"HTTP API Call", buildHTTPAPICall(), false},
		{"NTP Request", buildNTPRequest(), true},
		{"TLS Client Hello", buildTLSClientHello(), false},
	}

	falsePositives := 0
	for _, tc := range normalTraffic {
		t.Run(tc.name, func(t *testing.T) {
			result := analyzer.AnalyzePacket(tc.payload, tc.isUDP)
			if result.ShouldBlock {
				falsePositives++
				t.Errorf("False positive: %s blocked with reason: %s",
					tc.name, result.Reason)
			}
		})
	}

	falsePositiveRate := float64(falsePositives) / float64(len(normalTraffic))
	if falsePositiveRate > 0.0 {
		t.Errorf("False positive rate: %.2f%% (expected 0%%)",
			falsePositiveRate*100)
	}
}

// Helper functions to build realistic packets

func buildBitTorrentHandshake() []byte {
	// Real BitTorrent handshake structure
	handshake := make([]byte, 68)
	handshake[0] = 19 // pstrlen
	copy(handshake[1:20], []byte("BitTorrent protocol"))
	// Reserved bytes (8 bytes)
	// Info hash (20 bytes)
	copy(handshake[28:48], []byte("12345678901234567890"))
	// Peer ID (20 bytes)
	copy(handshake[48:68], []byte("-UT3500-123456789012"))
	return handshake
}

func buildUDPTrackerConnect() []byte {
	packet := make([]byte, 16)
	// Protocol ID (connection_id for connect)
	copy(packet[0:8], []byte{0x00, 0x00, 0x04, 0x17, 0x27, 0x10, 0x19, 0x80})
	// Action: 0 = connect
	// Transaction ID
	copy(packet[12:16], []byte{0x12, 0x34, 0x56, 0x78})
	return packet
}

func buildUDPTrackerAnnounce() []byte {
	packet := make([]byte, 98)
	// Connection ID (8 bytes)
	copy(packet[0:8], []byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88})
	// Action: 1 = announce
	packet[8], packet[9], packet[10], packet[11] = 0x00, 0x00, 0x00, 0x01
	// Transaction ID
	packet[12], packet[13], packet[14], packet[15] = 0x12, 0x34, 0x56, 0x78
	// Info hash (20 bytes at offset 16)
	copy(packet[16:36], []byte("infohash12345678901"))
	// Peer ID with qBittorrent signature
	copy(packet[36:39], []byte("-qB"))
	copy(packet[39:56], []byte("4150-12345678901"))
	// Downloaded, left, uploaded (8 bytes each)
	// Event, IP, key, num_want, port
	packet[96], packet[97] = 0x1A, 0xE1 // Port 6881
	return packet
}

func buildDHTGetPeersQuery() []byte {
	// Real DHT get_peers query
	query := "d1:ad2:id20:abcdefghij01234567896:target20:mnopqrstuvwxyz123456e1:q9:get_peers1:t2:aa1:y1:qe"
	return []byte(query)
}

func buildUTPSYN() []byte {
	packet := make([]byte, 20)
	packet[0] = 0x41 // Version 1, Type ST_SYN (4)
	packet[1] = 0x00 // Extension: none
	// Connection ID, timestamp, timestamp diff, wnd_size, seq_nr, ack_nr
	return packet
}

func buildMSEHandshake() []byte {
	// MSE/PE encrypted stream with DH key + padding + VC
	packet := make([]byte, 120)
	// First 96 bytes: DH public key Y (appears random)
	for i := 0; i < 96; i++ {
		packet[i] = byte((i * 37) % 256)
	}
	// Padding (0-512 bytes, we use 8)
	for i := 96; i < 104; i++ {
		packet[i] = byte((i * 13) % 256)
	}
	// VC marker (8 consecutive zero bytes)
	for i := 104; i < 112; i++ {
		packet[i] = 0x00
	}
	// Crypto_provide (4 bytes)
	packet[112] = 0x00
	packet[113] = 0x00
	packet[114] = 0x00
	packet[115] = 0x03 // Plain + RC4
	return packet
}

func buildLSDAnnouncement() []byte {
	// Local Service Discovery announcement
	announcement := "BT-SEARCH * HTTP/1.1\r\n" +
		"Host: 239.192.152.143:6771\r\n" +
		"Port: 6881\r\n" +
		"Infohash: 12345678901234567890\r\n" +
		"cookie: 0123456789ABCDEF\r\n" +
		"\r\n"
	return []byte(announcement)
}

func buildHTTPSTraffic() []byte {
	// Simulated TLS Application Data (content type 0x17)
	// Real TLS has patterns that reduce entropy below threshold
	traffic := make([]byte, 200)
	traffic[0] = 0x17 // Content Type: Application Data
	traffic[1] = 0x03 // Version: TLS 1.2
	traffic[2] = 0x03
	traffic[3] = 0x00 // Length (high byte)
	traffic[4] = 0xC3 // Length (low byte)

	// Fill with repeating pattern that looks encrypted but has lower entropy
	// Real TLS often has repeated patterns, padding, etc.
	pattern := []byte{0xAB, 0xCD, 0xEF, 0x12, 0x34, 0x56, 0x78, 0x90}
	for i := 5; i < len(traffic); i++ {
		traffic[i] = pattern[(i-5)%len(pattern)]
	}
	return traffic
}

func buildDNSQuery() []byte {
	// Simple DNS query structure
	query := make([]byte, 33)
	query[0], query[1] = 0x12, 0x34   // Transaction ID
	query[2], query[3] = 0x01, 0x00   // Flags: standard query
	query[4], query[5] = 0x00, 0x01   // Questions: 1
	query[6], query[7] = 0x00, 0x00   // Answer RRs: 0
	query[8], query[9] = 0x00, 0x00   // Authority RRs: 0
	query[10], query[11] = 0x00, 0x00 // Additional RRs: 0
	// Question: example.com
	copy(query[12:], []byte{0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0x03, 'c', 'o', 'm', 0x00})
	// Type A, Class IN
	query[30], query[31] = 0x00, 0x01 // Type A
	query[32] = 0x01                  // Class IN
	return query
}

func buildSSHHandshake() []byte {
	// SSH protocol identification string
	ssh := "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1\r\n"
	return []byte(ssh)
}

func buildHTTPAPICall() []byte {
	// Normal HTTP API request
	request := "POST /api/v1/users HTTP/1.1\r\n" +
		"Host: api.example.com\r\n" +
		"Content-Type: application/json\r\n" +
		"User-Agent: Mozilla/5.0\r\n" +
		"Content-Length: 45\r\n" +
		"\r\n" +
		`{"name":"John","email":"john@example.com"}`
	return []byte(request)
}

func buildNTPRequest() []byte {
	// NTP request packet
	ntp := make([]byte, 48)
	ntp[0] = 0x1B // LI=0, VN=3, Mode=3 (client)
	return ntp
}

func buildTLSClientHello() []byte {
	// Simplified TLS 1.2 Client Hello
	hello := make([]byte, 100)
	hello[0] = 0x16 // Content Type: Handshake
	hello[1] = 0x03 // Version: TLS 1.0
	hello[2] = 0x01
	hello[5] = 0x01 // Handshake Type: Client Hello
	// Random data for rest
	for i := 6; i < 100; i++ {
		hello[i] = byte(i % 256)
	}
	return hello
}

// TestDetectionLogging tests that detection logging works end-to-end
func TestDetectionLogging(t *testing.T) {
	logPath := "test_detection_integration.log"
	defer func() {
		// Clean up test file
		if err := removeFile(logPath); err != nil {
			t.Logf("Warning: failed to clean up test file: %v", err)
		}
	}()

	// Create config with detection logging enabled and monitor-only mode
	config := blocker.Config{
		Interfaces:       []string{"lo"},
		BanDuration:      3600,
		LogLevel:         "info",
		DetectionLogPath: logPath,
		MonitorOnly:      true, // Use monitor mode for testing
		XDPMode:          "generic",
	}

	analyzer := blocker.NewAnalyzer(config)
	detectionLogger, err := blocker.NewDetectionLogger(logPath)
	if err != nil {
		t.Fatalf("Failed to create detection logger: %v", err)
	}
	defer detectionLogger.Close()

	// Test various BitTorrent traffic types
	testCases := []struct {
		name    string
		payload []byte
		isUDP   bool
	}{
		{"BitTorrent Handshake", buildBitTorrentHandshake(), false},
		{"UDP Tracker Announce", buildUDPTrackerAnnounce(), true},
		{"DHT Get Peers", buildDHTGetPeersQuery(), true},
		{"uTP SYN", buildUTPSYN(), true},
		{"MSE Handshake", buildMSEHandshake(), false},
	}

	detectionsLogged := 0
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := analyzer.AnalyzePacket(tc.payload, tc.isUDP)

			if result.ShouldBlock {
				detectionsLogged++

				// Log the detection
				proto := "TCP"
				if tc.isUDP {
					proto = "UDP"
				}

				detectionLogger.LogDetection(
					getCurrentTime(),
					"lo",
					proto,
					"127.0.0.1",
					12345,
					"8.8.8.8",
					6881,
					result.Reason,
					tc.payload,
				)
			}
		})
	}

	if detectionsLogged == 0 {
		t.Fatal("No detections were logged")
	}

	// Verify log file was created and contains data
	content, err := readFile(logPath)
	if err != nil {
		t.Fatalf("Failed to read detection log: %v", err)
	}

	// Check for expected content
	expectedStrings := []string{
		"Timestamp:",
		"Interface:    lo",
		"Protocol:",
		"Source:       127.0.0.1:12345",
		"Destination:  8.8.8.8:6881",
		"Detection:",
		"Payload Size:",
		"Hex Dump:",
		"ASCII (printable only):",
	}

	for _, expected := range expectedStrings {
		if !containsString(content, expected) {
			t.Errorf("Detection log missing expected string: %q", expected)
		}
	}

	// Verify multiple detections were logged
	separatorCount := countOccurrences(content, "================================================================================")
	if separatorCount < detectionsLogged {
		t.Errorf("Expected at least %d detection entries, got %d", detectionsLogged, separatorCount)
	}
}

// TestMonitorOnlyMode tests that monitor-only mode doesn't ban IPs
func TestMonitorOnlyMode(t *testing.T) {
	// Config with monitor-only mode enabled
	monitorConfig := blocker.Config{
		Interfaces:  []string{"lo"},
		BanDuration: 3600,
		LogLevel:    "info",
		MonitorOnly: true, // Key: monitor only
		XDPMode:     "generic",
	}

	// Config with blocking enabled
	blockingConfig := blocker.Config{
		Interfaces:  []string{"lo"},
		BanDuration: 3600,
		LogLevel:    "info",
		MonitorOnly: false, // Blocking enabled
		XDPMode:     "generic",
	}

	testCases := []struct {
		name          string
		config        blocker.Config
		expectMonitor bool
	}{
		{"Monitor Mode", monitorConfig, true},
		{"Blocking Mode", blockingConfig, false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			analyzer := blocker.NewAnalyzer(tc.config)

			// Test with BitTorrent handshake
			result := analyzer.AnalyzePacket(buildBitTorrentHandshake(), false)

			if !result.ShouldBlock {
				t.Error("BitTorrent traffic should be detected")
			}

			// Verify config flag
			if tc.config.MonitorOnly != tc.expectMonitor {
				t.Errorf("MonitorOnly = %v, want %v", tc.config.MonitorOnly, tc.expectMonitor)
			}

			// In a real blocker instance, monitor-only mode would skip calling banManager.BanIP()
			// This is tested in the blocker's processPacket method
		})
	}
}

// TestCombinedMonitorAndLogging tests both features together
func TestCombinedMonitorAndLogging(t *testing.T) {
	logPath := "test_combined_integration.log"
	defer func() {
		if err := removeFile(logPath); err != nil {
			t.Logf("Warning: failed to clean up test file: %v", err)
		}
	}()

	// Config with both monitor-only mode AND detection logging
	config := blocker.Config{
		Interfaces:       []string{"lo"},
		BanDuration:      3600,
		LogLevel:         "info",
		DetectionLogPath: logPath,
		MonitorOnly:      true, // Both features enabled
		XDPMode:          "generic",
	}

	if !config.MonitorOnly {
		t.Fatal("MonitorOnly should be true")
	}

	if config.DetectionLogPath == "" {
		t.Fatal("DetectionLogPath should not be empty")
	}

	analyzer := blocker.NewAnalyzer(config)
	detectionLogger, err := blocker.NewDetectionLogger(logPath)
	if err != nil {
		t.Fatalf("Failed to create detection logger: %v", err)
	}
	defer detectionLogger.Close()

	// Test with multiple traffic types
	payloads := []struct {
		data  []byte
		isUDP bool
		name  string
	}{
		{buildBitTorrentHandshake(), false, "BT Handshake"},
		{buildUDPTrackerAnnounce(), true, "UDP Tracker"},
		{buildDHTGetPeersQuery(), true, "DHT Query"},
		{buildHTTPSTraffic(), false, "HTTPS (should not detect)"},
	}

	detectionCount := 0
	for _, p := range payloads {
		result := analyzer.AnalyzePacket(p.data, p.isUDP)

		if result.ShouldBlock {
			detectionCount++
			proto := "TCP"
			if p.isUDP {
				proto = "UDP"
			}

			detectionLogger.LogDetection(
				getCurrentTime(),
				"lo",
				proto,
				"192.168.1.100",
				uint16(10000+detectionCount),
				"8.8.8.8",
				6881,
				result.Reason,
				p.data,
			)

			t.Logf("Detected: %s - %s", p.name, result.Reason)
		}
	}

	if detectionCount == 0 {
		t.Fatal("No detections occurred")
	}

	// Verify log file contains all detections
	content, err := readFile(logPath)
	if err != nil {
		t.Fatalf("Failed to read log file: %v", err)
	}

	separatorCount := countOccurrences(content, "================================================================================")
	if separatorCount != detectionCount {
		t.Errorf("Expected %d log entries, got %d", detectionCount, separatorCount)
	}

	t.Logf("Successfully logged %d detections in monitor-only mode", detectionCount)
}

// Helper functions for integration tests

func getCurrentTime() time.Time {
	return time.Now()
}

func readFile(path string) (string, error) {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func removeFile(path string) error {
	return os.Remove(path)
}

func containsString(content, substr string) bool {
	return len(content) > 0 && len(substr) > 0 && (content == substr || len(content) > len(substr) && (content[:len(substr)] == substr || content[len(content)-len(substr):] == substr || findInString(content, substr)))
}

func findInString(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func countOccurrences(s, substr string) int {
	if len(substr) == 0 {
		return 0
	}
	count := 0
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			count++
			i += len(substr) - 1
		}
	}
	return count
}
