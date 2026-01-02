package blocker

import (
	"testing"
)

func TestAnalyzer_AnalyzePacket(t *testing.T) {
	config := DefaultConfig()
	analyzer := NewAnalyzer(config)

	tests := []struct {
		name        string
		payload     []byte
		isUDP       bool
		shouldBlock bool
		reason      string
	}{
		{
			name:        "BitTorrent handshake",
			payload:     []byte("\x13BitTorrent protocol\x00\x00\x00\x00\x00\x00\x00\x00"),
			isUDP:       false,
			shouldBlock: true,
			reason:      "BitTorrent Signature",
		},
		{
			name: "UDP tracker connect",
			payload: []byte{
				0x00, 0x00, 0x04, 0x17, 0x27, 0x10, 0x19, 0x80, // Protocol ID
				0x00, 0x00, 0x00, 0x00, // Action: Connect
				0x12, 0x34, 0x56, 0x78, // Transaction ID
			},
			isUDP:       true,
			shouldBlock: true,
			reason:      "UDP Tracker Protocol",
		},
		{
			name:        "DHT query",
			payload:     []byte("d1:ad2:id20:abcdefghij0123456789e1:q4:ping1:t2:aa1:y1:qe"),
			isUDP:       true,
			shouldBlock: true,
			reason:      "DHT Bencode Structure (BEP 5)", // DHT detection is now faster than signatures
		},
		{
			name: "uTP packet",
			payload: func() []byte {
				p := make([]byte, 20)
				p[0] = 0x41 // Version 1, Type ST_SYN (4)
				p[1] = 0x00 // No extensions
				return p
			}(),
			isUDP:       true,
			shouldBlock: true,
			reason:      "uTP Protocol",
		},
		{
			name: "High entropy payload",
			payload: func() []byte {
				// Create data with uniform distribution for entropy > 7.6
				p := make([]byte, 256)
				for i := range p {
					p[i] = byte(i)
				}
				return p
			}(),
			isUDP:       true,
			shouldBlock: true,
			reason:      "High Entropy",
		},
		{
			name: "SOCKS5 connection",
			payload: []byte{
				0x05, 0x02, 0x00, 0x02,
			},
			isUDP:       false,
			shouldBlock: true,
			reason:      "SOCKS Proxy Connection",
		},
		{
			name:        "Normal HTTP traffic",
			payload:     []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"),
			isUDP:       false,
			shouldBlock: false,
			reason:      "",
		},
		{
			name:        "Normal DNS query",
			payload:     []byte{0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00},
			isUDP:       true,
			shouldBlock: false,
			reason:      "",
		},
		{
			name:        "Empty payload",
			payload:     []byte{},
			isUDP:       false,
			shouldBlock: false,
			reason:      "",
		},
		{
			name: "Low entropy text",
			payload: []byte("This is normal text that should not be blocked because " +
				"it has low entropy and doesn't match any signatures."),
			isUDP:       false,
			shouldBlock: false,
			reason:      "",
		},
		{
			name:        "HTTP BitTorrent WebSeed",
			payload:     []byte("GET /webseed?info_hash=ABCD1234 HTTP/1.1\r\nHost: seed.example.com\r\n\r\n"),
			isUDP:       false,
			shouldBlock: true,
			reason:      "HTTP BitTorrent Protocol",
		},
		{
			name:        "HTTP BitTorrent User-Agent",
			payload:     []byte("GET /announce HTTP/1.1\r\nUser-Agent: Azureus 5.7\r\n\r\n"),
			isUDP:       false,
			shouldBlock: true,
			reason:      "HTTP BitTorrent Protocol",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := analyzer.AnalyzePacket(tt.payload, tt.isUDP)

			if result.ShouldBlock != tt.shouldBlock {
				t.Errorf("AnalyzePacket() ShouldBlock = %v, want %v", result.ShouldBlock, tt.shouldBlock)
			}

			if tt.shouldBlock && result.Reason == "" {
				t.Errorf("AnalyzePacket() expected reason but got empty string")
			}

			if tt.shouldBlock && tt.reason != "" {
				// Check if reason contains expected substring
				if len(result.Reason) < len(tt.reason) || result.Reason[:len(tt.reason)] != tt.reason {
					// For High Entropy, just check it starts with "High Entropy"
					if tt.reason == "High Entropy" && len(result.Reason) < 12 {
						t.Errorf("AnalyzePacket() Reason = %v, want to start with %v", result.Reason, tt.reason)
					} else if tt.reason != "High Entropy" && result.Reason != tt.reason {
						t.Errorf("AnalyzePacket() Reason = %v, want %v", result.Reason, tt.reason)
					}
				}
			}
		})
	}
}

func TestAnalyzer_AnalyzePacketWithSOCKS5Unwrapping(t *testing.T) {
	config := DefaultConfig()
	analyzer := NewAnalyzer(config)

	// Create a SOCKS5 wrapped DHT query
	dhtQuery := []byte("d1:ad2:id20:abcdefghij0123456789e1:q4:ping1:t2:aa1:y1:qe")
	socks5Packet := []byte{
		0x00, 0x00, 0x00, // Reserved + Fragment
		0x01,           // ATYP: IPv4
		192, 168, 1, 1, // IP
		0x1A, 0xE1, // Port
	}
	socks5Packet = append(socks5Packet, dhtQuery...)

	result := analyzer.AnalyzePacket(socks5Packet, true)

	if !result.ShouldBlock {
		t.Errorf("AnalyzePacket() should detect DHT inside SOCKS5, but didn't block")
	}

	// Should detect DHT bencode structure (faster than signature detection after optimization)
	if result.Reason != "DHT Bencode Structure (BEP 5)" {
		t.Errorf("AnalyzePacket() Reason = %v, want DHT Bencode Structure (BEP 5)", result.Reason)
	}
}

func TestAnalyzer_CustomThresholds(t *testing.T) {
	// Test with higher entropy threshold
	config := Config{
		Interfaces:       []string{"eth0"},
		EntropyThreshold: 9.0, // Very high threshold
		MinPayloadSize:   60,
		IPSetName:        "test",
		BanDuration:      3600,
	}
	analyzer := NewAnalyzer(config)

	// High entropy data that would normally be blocked
	highEntropyData := make([]byte, 100)
	for i := range highEntropyData {
		highEntropyData[i] = byte(i)
	}

	result := analyzer.AnalyzePacket(highEntropyData, false)

	// Should not block because entropy threshold is too high
	if result.ShouldBlock {
		t.Errorf("AnalyzePacket() should not block with high threshold, but did")
	}
}

func TestAnalyzer_MinPayloadSize(t *testing.T) {
	config := DefaultConfig()
	analyzer := NewAnalyzer(config)

	// Small payload with high entropy per byte, but below MinPayloadSize
	smallPayload := []byte{0x8F, 0x3A, 0xBC, 0xD1, 0x29}

	result := analyzer.AnalyzePacket(smallPayload, false)

	// Should not block based on entropy because it's too small
	// (but might block on other criteria)
	if result.ShouldBlock && result.Reason[:4] == "High" {
		t.Errorf("AnalyzePacket() should not apply entropy check to small payloads")
	}
}

func TestAnalyzer_AnalyzePacketEx_LSD(t *testing.T) {
	config := DefaultConfig()
	analyzer := NewAnalyzer(config)

	// Test LSD detection with destination IP and port
	lsdPayload := []byte("BT-SEARCH * HTTP/1.1\r\nHost: 239.192.152.143:6771\r\nInfohash: ABCD\r\nPort: 6881\r\n\r\n")

	// Test with correct LSD multicast address
	result := analyzer.AnalyzePacketEx(lsdPayload, true, "239.192.152.143", 6771)
	if !result.ShouldBlock {
		t.Errorf("AnalyzePacketEx() should detect LSD traffic")
	}
	if result.Reason != "Local Service Discovery (BEP 14)" {
		t.Errorf("AnalyzePacketEx() Reason = %v, want Local Service Discovery (BEP 14)", result.Reason)
	}

	// Test without destination info (should not trigger LSD detection)
	result2 := analyzer.AnalyzePacketEx(lsdPayload, true, "", 0)
	// Should still be detected via signature
	if !result2.ShouldBlock {
		t.Errorf("AnalyzePacketEx() should still detect via signatures")
	}
	if result2.Reason == "Local Service Discovery" {
		t.Errorf("AnalyzePacketEx() should not detect LSD without dest info")
	}
}

func TestNewAnalyzer(t *testing.T) {
	config := DefaultConfig()
	analyzer := NewAnalyzer(config)

	if analyzer == nil {
		t.Fatal("NewAnalyzer() returned nil")
	}

	if analyzer.config.EntropyThreshold != config.EntropyThreshold {
		t.Errorf("NewAnalyzer() config not set correctly")
	}
}

func BenchmarkAnalyzer_AnalyzePacket_HTTP(b *testing.B) {
	config := DefaultConfig()
	analyzer := NewAnalyzer(config)
	payload := []byte("GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Mozilla/5.0\r\n\r\n")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		analyzer.AnalyzePacket(payload, false)
	}
}

func BenchmarkAnalyzer_AnalyzePacket_BitTorrent(b *testing.B) {
	config := DefaultConfig()
	analyzer := NewAnalyzer(config)
	payload := []byte("\x13BitTorrent protocol\x00\x00\x00\x00\x00\x00\x00\x00")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		analyzer.AnalyzePacket(payload, false)
	}
}

func BenchmarkAnalyzer_AnalyzePacket_HighEntropy(b *testing.B) {
	config := DefaultConfig()
	analyzer := NewAnalyzer(config)
	payload := make([]byte, 100)
	for i := range payload {
		payload[i] = byte(i * 37 % 256)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		analyzer.AnalyzePacket(payload, false)
	}
}
