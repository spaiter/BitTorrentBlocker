package blocker

import (
	"testing"
)

// TestFalsePositives tests that common non-BitTorrent traffic is not flagged
func TestFalsePositives(t *testing.T) {
	config := DefaultConfig()
	analyzer := NewAnalyzer(config)

	testCases := []struct {
		name    string
		payload []byte
		isUDP   bool
		reason  string
	}{
		{
			name:    "HTTPS Traffic",
			payload: buildHTTPSClientHello(),
			isUDP:   false,
			reason:  "Standard HTTPS handshake should not be blocked",
		},
		{
			name:    "DNS Query",
			payload: buildDNSQuery(),
			isUDP:   true,
			reason:  "DNS queries should not be blocked",
		},
		{
			name:    "HTTP GET Request",
			payload: []byte("GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Mozilla/5.0\r\n\r\n"),
			isUDP:   false,
			reason:  "Normal HTTP requests should not be blocked",
		},
		{
			name:    "SSH Handshake",
			payload: []byte("SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1\r\n"),
			isUDP:   false,
			reason:  "SSH traffic should not be blocked",
		},
		{
			name:    "JSON Data",
			payload: []byte(`{"key":"value","number":123,"nested":{"data":"test"}}`),
			isUDP:   false,
			reason:  "JSON data should not be blocked",
		},
		{
			name:    "Bencode Without DHT Context",
			payload: []byte("d4:test5:valued"),
			isUDP:   false,
			reason:  "Generic bencode without DHT context should not be blocked",
		},
		{
			name:    "High Entropy Without VC",
			payload: generateRandomBytes(200),
			isUDP:   false,
			reason:  "Random data without MSE structure should not be blocked",
		},
		{
			name:    "QUIC Initial Packet",
			payload: buildQUICInitial(),
			isUDP:   true,
			reason:  "QUIC protocol should not be blocked",
		},
		{
			name:    "WebRTC STUN",
			payload: buildSTUNBinding(),
			isUDP:   true,
			reason:  "WebRTC STUN messages should not be blocked",
		},
		{
			name:    "Generic UDP Tracker Format (Without Magic)",
			payload: buildGenericUDPPacket(),
			isUDP:   true,
			reason:  "UDP packets without BitTorrent magic number should not be blocked",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := analyzer.AnalyzePacket(tc.payload, tc.isUDP)
			if result.ShouldBlock {
				t.Errorf("%s: False positive detected! %s (Reason: %s)",
					tc.name, tc.reason, result.Reason)
			}
		})
	}
}

// TestSOCKSConfigOption tests that SOCKS detection respects configuration
func TestSOCKSConfigOption(t *testing.T) {
	socksPayload := []byte{0x05, 0x02, 0x00, 0x02} // SOCKS5 greeting

	// Test with SOCKS blocking disabled (default)
	configDisabled := DefaultConfig()
	configDisabled.BlockSOCKS = false
	analyzerDisabled := NewAnalyzer(configDisabled)

	result := analyzerDisabled.AnalyzePacket(socksPayload, false)
	if result.ShouldBlock {
		t.Error("SOCKS traffic should NOT be blocked when BlockSOCKS=false (default)")
	}

	// Test with SOCKS blocking enabled
	configEnabled := DefaultConfig()
	configEnabled.BlockSOCKS = true
	analyzerEnabled := NewAnalyzer(configEnabled)

	result = analyzerEnabled.AnalyzePacket(socksPayload, false)
	if !result.ShouldBlock {
		t.Error("SOCKS traffic SHOULD be blocked when BlockSOCKS=true")
	}
}

// TestMSEStricterValidation tests that MSE detection is strict
func TestMSEStricterValidation(t *testing.T) {
	config := DefaultConfig()
	analyzer := NewAnalyzer(config)

	testCases := []struct {
		name          string
		payload       []byte
		shouldBlock   bool
		description   string
	}{
		{
			name:          "High entropy only (no VC)",
			payload:       generateRandomBytes(200),
			shouldBlock:   false,
			description:   "High entropy alone should not trigger MSE detection",
		},
		{
			name:          "VC only (no high entropy DH key)",
			payload:       buildVCWithoutHighEntropy(),
			shouldBlock:   false,
			description:   "VC marker without high entropy DH key should not trigger",
		},
		{
			name:          "High entropy + VC without crypto field",
			payload:       buildMSEWithoutCryptoField(),
			shouldBlock:   false,
			description:   "MSE without valid crypto_provide field should not trigger",
		},
		{
			name:          "Valid MSE handshake",
			payload:       buildCompleteMSEHandshake(),
			shouldBlock:   true,
			description:   "Complete MSE handshake should be detected",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := analyzer.AnalyzePacket(tc.payload, false)
			if result.ShouldBlock != tc.shouldBlock {
				if tc.shouldBlock {
					t.Errorf("%s: Should have been blocked but wasn't. %s", tc.name, tc.description)
				} else {
					t.Errorf("%s: False positive! %s (Reason: %s)", tc.name, tc.description, result.Reason)
				}
			}
		})
	}
}

// Helper functions to build test packets

func buildHTTPSClientHello() []byte {
	// Simplified TLS 1.2 Client Hello
	hello := make([]byte, 100)
	hello[0] = 0x16 // Handshake
	hello[1] = 0x03 // Version: TLS 1.2
	hello[2] = 0x03
	hello[5] = 0x01 // Handshake Type: Client Hello
	// Fill rest with pseudo-random data
	for i := 6; i < 100; i++ {
		hello[i] = byte((i * 13) % 256)
	}
	return hello
}

func buildDNSQuery() []byte {
	// Simplified DNS query for example.com
	return []byte{
		0x12, 0x34, // Transaction ID
		0x01, 0x00, // Flags: standard query
		0x00, 0x01, // Questions: 1
		0x00, 0x00, // Answer RRs: 0
		0x00, 0x00, // Authority RRs: 0
		0x00, 0x00, // Additional RRs: 0
		// Query: example.com
		0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
		0x03, 'c', 'o', 'm',
		0x00,       // End of name
		0x00, 0x01, // Type: A
		0x00, 0x01, // Class: IN
	}
}

func generateRandomBytes(n int) []byte {
	// Generate pseudo-random bytes with high entropy
	data := make([]byte, n)
	for i := 0; i < n; i++ {
		data[i] = byte((i*173 + 17) % 256)
	}
	return data
}

func buildQUICInitial() []byte {
	// Simplified QUIC Initial packet header
	return []byte{
		0xc0, // Header form (1) + Fixed bit (1) + Long Header Type (00) + Reserved (00)
		0x00, 0x00, 0x00, 0x01, // Version
		0x08, // DCID Length
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, // Destination Connection ID
		0x00, // SCID Length
		// Token Length (varint)
		0x00,
		// Length (varint)
		0x40, 0x00,
		// Packet Number
		0x00, 0x00, 0x00, 0x00,
	}
}

func buildSTUNBinding() []byte {
	// STUN Binding Request
	return []byte{
		0x00, 0x01, // Message Type: Binding Request
		0x00, 0x08, // Message Length: 8 bytes
		0x21, 0x12, 0xa4, 0x42, // Magic Cookie
		0x01, 0x02, 0x03, 0x04, // Transaction ID
		0x05, 0x06, 0x07, 0x08,
		0x09, 0x0a, 0x0b, 0x0c,
	}
}

func buildGenericUDPPacket() []byte {
	// Generic UDP packet that looks like tracker format but without magic number
	data := make([]byte, 20)
	// Wrong magic number
	data[0] = 0xFF
	data[1] = 0xFF
	data[2] = 0xFF
	data[3] = 0xFF
	data[4] = 0xFF
	data[5] = 0xFF
	data[6] = 0xFF
	data[7] = 0xFF
	// Action-like field
	data[8] = 0x00
	data[9] = 0x00
	data[10] = 0x00
	data[11] = 0x00
	return data
}

func buildVCWithoutHighEntropy() []byte {
	// Low entropy data with VC marker
	data := make([]byte, 120)
	// First 96 bytes: low entropy (repeated pattern)
	for i := 0; i < 96; i++ {
		data[i] = byte(i % 4) // Low entropy pattern
	}
	// VC at position 96
	for i := 96; i < 104; i++ {
		data[i] = 0x00
	}
	return data
}

func buildMSEWithoutCryptoField() []byte {
	// High entropy DH key + VC but no crypto field
	data := make([]byte, 106)
	// First 96 bytes: high entropy
	for i := 0; i < 96; i++ {
		data[i] = byte((i*173 + 17) % 256)
	}
	// VC at position 96
	for i := 96; i < 104; i++ {
		data[i] = 0x00
	}
	// Only 2 bytes after VC, not enough for crypto field
	data[104] = 0xFF
	data[105] = 0xFF
	return data
}

func buildCompleteMSEHandshake() []byte {
	// Complete MSE handshake: DH key + VC + crypto_provide
	data := make([]byte, 120)
	// First 96 bytes: high entropy DH key
	for i := 0; i < 96; i++ {
		data[i] = byte((i*173 + 17) % 256)
	}
	// VC at position 96 (8 zero bytes)
	for i := 96; i < 104; i++ {
		data[i] = 0x00
	}
	// crypto_provide at position 104 (4 bytes)
	// Value: 0x00000002 (RC4)
	data[104] = 0x00
	data[105] = 0x00
	data[106] = 0x00
	data[107] = 0x02
	// Additional padding
	for i := 108; i < 120; i++ {
		data[i] = byte((i * 7) % 256)
	}
	return data
}
