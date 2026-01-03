package blocker

import (
	"testing"
)

func TestCheckSignatures(t *testing.T) {
	tests := []struct {
		name     string
		payload  []byte
		expected bool
	}{
		{
			name:     "BitTorrent handshake",
			payload:  []byte("\x13BitTorrent protocol"),
			expected: true,
		},
		{
			name:     "PEX extension",
			payload:  []byte("d1:md6:ut_pexi1ee"),
			expected: true,
		},
		{
			name:     "Libtorrent version",
			payload:  []byte("1:v4:LT20"),
			expected: true,
		},
		{
			name:     "DHT query",
			payload:  []byte("d1:ad2:id20:xxxxxxxxxxxxxxxxxxxe1:q4:ping1:y1:qe"),
			expected: true,
		},
		{
			name:     "Normal HTTP traffic",
			payload:  []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"),
			expected: false,
		},
		{
			name:     "Empty payload",
			payload:  []byte{},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := CheckSignatures(tt.payload)
			if result != tt.expected {
				t.Errorf("CheckSignatures() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestUnwrapSOCKS5(t *testing.T) {
	tests := []struct {
		name        string
		packet      []byte
		wantPayload []byte
		wantOk      bool
	}{
		{
			name: "SOCKS5 IPv4",
			packet: []byte{
				0x00, 0x00, 0x00, // Reserved + Fragment
				0x01,           // ATYP: IPv4
				192, 168, 1, 1, // IP
				0x1A, 0xE1, // Port
				0x64, 0x31, 0x3A, 0x61, // Payload: "d1:a"
			},
			wantPayload: []byte{0x64, 0x31, 0x3A, 0x61},
			wantOk:      true,
		},
		{
			name: "SOCKS5 IPv6",
			packet: []byte{
				0x00, 0x00, 0x00, // Reserved + Fragment
				0x04, // ATYP: IPv6
				0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, // IPv6
				0x1A, 0xE1, // Port
				0x64, 0x31, 0x3A, 0x61, // Payload
			},
			wantPayload: []byte{0x64, 0x31, 0x3A, 0x61},
			wantOk:      true,
		},
		{
			name:        "Not SOCKS5",
			packet:      []byte{0x01, 0x02, 0x03, 0x04},
			wantPayload: nil,
			wantOk:      false,
		},
		{
			name:        "Too short",
			packet:      []byte{0x00, 0x00, 0x00},
			wantPayload: nil,
			wantOk:      false,
		},
		{
			name: "SOCKS5 Domain",
			packet: []byte{
				0x00, 0x00, 0x00, // Reserved + Fragment
				0x03,                                                  // ATYP: Domain
				0x0B,                                                  // Domain length: 11
				'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm', // Domain: "example.com"
				0x1A, 0xE1, // Port
				0x64, 0x31, 0x3A, 0x61, // Payload: "d1:a"
			},
			wantPayload: []byte{0x64, 0x31, 0x3A, 0x61},
			wantOk:      true,
		},
		{
			name: "SOCKS5 Domain too short",
			packet: []byte{
				0x00, 0x00, 0x00, // Reserved + Fragment
				0x03, // ATYP: Domain
			},
			wantPayload: nil,
			wantOk:      false,
		},
		{
			name: "SOCKS5 invalid ATYP",
			packet: []byte{
				0x00, 0x00, 0x00, // Reserved + Fragment
				0x05, // ATYP: Invalid (not 1, 3, or 4)
				192, 168, 1, 1,
			},
			wantPayload: nil,
			wantOk:      false,
		},
		{
			name: "SOCKS5 IPv4 no payload",
			packet: []byte{
				0x00, 0x00, 0x00, // Reserved + Fragment
				0x01,           // ATYP: IPv4
				192, 168, 1, 1, // IP
				0x1A, 0xE1, // Port
			},
			wantPayload: nil,
			wantOk:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			payload, ok := UnwrapSOCKS5(tt.packet)
			if ok != tt.wantOk {
				t.Errorf("UnwrapSOCKS5() ok = %v, want %v", ok, tt.wantOk)
			}
			if ok && string(payload) != string(tt.wantPayload) {
				t.Errorf("UnwrapSOCKS5() payload = %v, want %v", payload, tt.wantPayload)
			}
		})
	}
}

func TestCheckSOCKSConnection(t *testing.T) {
	tests := []struct {
		name     string
		payload  []byte
		expected bool
	}{
		{
			name:     "SOCKS4 connect",
			payload:  []byte{0x04, 0x01, 0x00, 0x50, 192, 168, 1, 1},
			expected: true,
		},
		{
			name:     "SOCKS5 auth",
			payload:  []byte{0x05, 0x02, 0x00, 0x02},
			expected: true,
		},
		{
			name:     "Normal traffic",
			payload:  []byte("GET / HTTP/1.1"),
			expected: false,
		},
		{
			name:     "Too short",
			payload:  []byte{0x05},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := CheckSOCKSConnection(tt.payload)
			if result != tt.expected {
				t.Errorf("CheckSOCKSConnection() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestCheckUDPTrackerDeep(t *testing.T) {
	tests := []struct {
		name     string
		packet   []byte
		expected bool
	}{
		{
			name: "Valid connect request",
			packet: []byte{
				0x00, 0x00, 0x04, 0x17, 0x27, 0x10, 0x19, 0x80, // Protocol ID
				0x00, 0x00, 0x00, 0x00, // Action: Connect
				0x12, 0x34, 0x56, 0x78, // Transaction ID
			},
			expected: true,
		},
		{
			name: "Valid announce with qBittorrent PeerID",
			packet: func() []byte {
				p := make([]byte, 98)
				// Connection ID (8 bytes)
				copy(p[0:8], []byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88})
				// Action: Announce (4 bytes)
				p[8], p[9], p[10], p[11] = 0x00, 0x00, 0x00, 0x01
				// Transaction ID (4 bytes)
				p[12], p[13], p[14], p[15] = 0x12, 0x34, 0x56, 0x78
				// Info hash (20 bytes at offset 16)
				// PeerID at offset 36 with qBittorrent prefix
				copy(p[36:39], []byte("-qB"))
				return p
			}(),
			expected: true,
		},
		{
			name: "Valid scrape request",
			packet: func() []byte {
				p := make([]byte, 36)
				// Connection ID
				copy(p[0:8], []byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88})
				// Action: Scrape
				p[8], p[9], p[10], p[11] = 0x00, 0x00, 0x00, 0x02
				// Transaction ID
				p[12], p[13], p[14], p[15] = 0x12, 0x34, 0x56, 0x78
				return p
			}(),
			expected: true,
		},
		{
			name:     "Invalid packet - too short",
			packet:   []byte{0x00, 0x00, 0x04, 0x17},
			expected: false,
		},
		{
			name:     "Invalid protocol ID",
			packet:   []byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x12, 0x34, 0x56, 0x78},
			expected: false,
		},
		{
			name: "Valid announce without recognized PeerID prefix",
			packet: func() []byte {
				p := make([]byte, 98)
				// Connection ID (8 bytes)
				copy(p[0:8], []byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88})
				// Action: Announce (4 bytes)
				p[8], p[9], p[10], p[11] = 0x00, 0x00, 0x00, 0x01
				// Transaction ID (4 bytes)
				p[12], p[13], p[14], p[15] = 0x12, 0x34, 0x56, 0x78
				// Info hash (20 bytes at offset 16)
				// PeerID at offset 36 with unknown prefix
				copy(p[36:40], []byte("UNKN"))
				return p
			}(),
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := CheckUDPTrackerDeep(tt.packet)
			if result != tt.expected {
				t.Errorf("CheckUDPTrackerDeep() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestCheckUTPRobust(t *testing.T) {
	tests := []struct {
		name     string
		packet   []byte
		expected bool
	}{
		{
			name: "Valid uTP SYN packet",
			packet: func() []byte {
				p := make([]byte, 20)
				p[0] = 0x41 // Version 1, Type ST_SYN (4)
				p[1] = 0x00 // No extensions
				return p
			}(),
			expected: true,
		},
		{
			name: "Valid uTP with extension",
			packet: func() []byte {
				p := make([]byte, 25)
				p[0] = 0x21  // Version 1, Type ST_DATA (2)
				p[1] = 0x01  // Extension type 1
				p[20] = 0x00 // Next extension = 0 (end)
				p[21] = 0x03 // Length = 3
				return p
			}(),
			expected: true,
		},
		{
			name:     "Too short",
			packet:   []byte{0x41, 0x00, 0x01},
			expected: false,
		},
		{
			name:     "Invalid version",
			packet:   make([]byte, 20),
			expected: false,
		},
		{
			name: "Invalid type",
			packet: func() []byte {
				p := make([]byte, 20)
				p[0] = 0x51 // Version 1, Type 5 (invalid)
				return p
			}(),
			expected: false,
		},
		{
			name: "Extension offset exceeds packet length",
			packet: func() []byte {
				p := make([]byte, 21)
				p[0] = 0x21  // Version 1, Type ST_DATA (2)
				p[1] = 0x01  // Extension type 1
				p[20] = 0x00 // Next extension = 0 (end of chain, at offset 20)
				// Missing length byte at offset 21 (would be out of bounds)
				return p
			}(),
			expected: false,
		},
		{
			name: "Extension length exceeds packet",
			packet: func() []byte {
				p := make([]byte, 23)
				p[0] = 0x21  // Version 1, Type ST_DATA (2)
				p[1] = 0x01  // Extension type 1
				p[20] = 0x00 // Next extension = 0 (end)
				p[21] = 0xFF // Length = 255 (way more than packet size)
				return p
			}(),
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := CheckUTPRobust(tt.packet)
			if result != tt.expected {
				t.Errorf("CheckUTPRobust() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestCheckBencodeDHT(t *testing.T) {
	tests := []struct {
		name     string
		payload  []byte
		expected bool
	}{
		{
			name:     "Valid DHT query",
			payload:  []byte("d1:ad2:id20:abcdefghij0123456789e1:q4:ping1:t2:aa1:y1:qe"),
			expected: true,
		},
		{
			name:     "Valid DHT response",
			payload:  []byte("d1:rd2:id20:abcdefghij0123456789e1:t2:aa1:y1:re"),
			expected: true,
		},
		{
			name:     "DHT with nodes",
			payload:  []byte("d1:rd2:id20:abcdefghij01234567895:nodes26:aaaaaaaaaabbbbbbbbbbccccccccccee1:t2:aa1:y1:re"),
			expected: true,
		},
		{
			name:     "Not bencode",
			payload:  []byte("GET / HTTP/1.1"),
			expected: false,
		},
		{
			name:     "Bencode but not DHT",
			payload:  []byte("d4:spam4:eggse"),
			expected: false,
		},
		{
			name:     "Missing end marker",
			payload:  []byte("d1:y1:q1:t2:aa"),
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := CheckBencodeDHT(tt.payload)
			if result != tt.expected {
				t.Errorf("CheckBencodeDHT() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestCheckBencodeDHT_SuricataEnhancements(t *testing.T) {
	tests := []struct {
		name     string
		payload  []byte
		expected bool
	}{
		// Suricata-specific prefix tests
		{
			name:     "Suricata d1:ad prefix",
			payload:  []byte("d1:ad2:id20:12345678901234567890e1:q4:ping1:t2:aa1:y1:qe"),
			expected: true,
		},
		{
			name:     "Suricata d1:rd prefix",
			payload:  []byte("d1:rd2:id20:12345678901234567890e1:t2:aa1:y1:re"),
			expected: true,
		},
		{
			name:     "Suricata d2:ip prefix",
			payload:  []byte("d2:ip6:1.2.3.41:t2:aa1:y1:qe"),
			expected: true,
		},
		{
			name:     "Suricata d1:el prefix (error list)",
			payload:  []byte("d1:elli201e4:testee1:t2:aa1:y1:ee"),
			expected: true,
		},
		{
			name:     "DHT error type (1:y1:e)",
			payload:  []byte("d1:eli201e4:teste1:t2:aa1:y1:ee"),
			expected: true,
		},

		// Token and values tests
		{
			name:     "DHT with token",
			payload:  []byte("d1:rd2:id20:123456789012345678905:token8:abcdefghe1:t2:aa1:y1:re"),
			expected: true,
		},
		{
			name:     "DHT with values list",
			payload:  []byte("d1:rd2:id20:123456789012345678906:valuesl6:peer016:peer02ee1:t2:aa1:y1:re"),
			expected: true,
		},

		// Negative tests
		{
			name:     "No type field",
			payload:  []byte("d1:t2:aa2:id20:12345678901234567890e"),
			expected: false,
		},
		{
			name:     "Wrong prefix d3:ab",
			payload:  []byte("d3:abc4:teste"),
			expected: false,
		},
		{
			name:     "Too short (< 8 bytes)",
			payload:  []byte("d1:y1e"),
			expected: false,
		},
		{
			name:     "Missing start marker 'd'",
			payload:  []byte("1:y1:q1:t2:aae"),
			expected: false,
		},
		{
			name:     "Missing end marker 'e'",
			payload:  []byte("d1:y1:q1:t2:aa"),
			expected: false,
		},
		{
			name:     "DHT with transaction ID only (no nodes/values/token)",
			payload:  []byte("d1:t2:aa1:y1:qe"),
			expected: false, // Changed to false: queries must have a valid DHT method to reduce false positives
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := CheckBencodeDHT(tt.payload)
			if result != tt.expected {
				t.Errorf("CheckBencodeDHT() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestCheckDHTNodes(t *testing.T) {
	tests := []struct {
		name     string
		payload  []byte
		expected bool
	}{
		// IPv4 nodes tests (26 bytes per node)
		{
			name: "Valid IPv4 nodes - 1 node",
			payload: func() []byte {
				// Create bencode: d6:nodes26:<26 bytes>e
				result := []byte("d6:nodes26:")
				// 20-byte node ID
				result = append(result, []byte("12345678901234567890")...)
				// 4-byte IPv4
				result = append(result, 192, 168, 1, 1)
				// 2-byte port
				result = append(result, 0x1A, 0xE1) // Port 6881
				result = append(result, 'e')
				return result
			}(),
			expected: true,
		},
		{
			name: "Valid IPv4 nodes - 2 nodes",
			payload: func() []byte {
				result := []byte("d6:nodes52:")
				// First node (26 bytes)
				result = append(result, []byte("node1234567890123456")...)
				result = append(result, 192, 168, 1, 1)
				result = append(result, 0x1A, 0xE1)
				// Second node (26 bytes)
				result = append(result, []byte("node2234567890123456")...)
				result = append(result, 192, 168, 1, 2)
				result = append(result, 0x1A, 0xE2)
				result = append(result, 'e')
				return result
			}(),
			expected: true,
		},

		// IPv6 nodes tests (38 bytes per node)
		{
			name: "Valid IPv6 nodes - 1 node",
			payload: func() []byte {
				result := []byte("d7:nodes638:")
				// 20-byte node ID
				result = append(result, []byte("12345678901234567890")...)
				// 16-byte IPv6
				result = append(result, []byte("2001db800000000000000000000000001")[:16]...)
				// 2-byte port
				result = append(result, 0x1A, 0xE1)
				result = append(result, 'e')
				return result
			}(),
			expected: true,
		},

		// Negative tests
		{
			name:     "No nodes field",
			payload:  []byte("d1:rd2:id20:12345678901234567890e1:t2:aa1:y1:re"),
			expected: false,
		},
		{
			name:     "Invalid node size (not divisible by 26)",
			payload:  []byte("d6:nodes25:aaaaaaaaaaaaaaaaaaaaaaaaa1:t2:aae"),
			expected: false,
		},
		{
			name:     "Empty payload",
			payload:  []byte{},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := CheckDHTNodes(tt.payload)
			if result != tt.expected {
				t.Errorf("CheckDHTNodes() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestShannonEntropy(t *testing.T) {
	tests := []struct {
		name     string
		data     []byte
		minValue float64
		maxValue float64
	}{
		{
			name:     "All same byte",
			data:     []byte{0x00, 0x00, 0x00, 0x00, 0x00},
			minValue: 0.0,
			maxValue: 0.1,
		},
		{
			name:     "Low entropy text",
			data:     []byte("aaaaaaaaaa"),
			minValue: 0.0,
			maxValue: 1.0,
		},
		{
			name:     "Medium entropy text",
			data:     []byte("Hello World! This is a test."),
			minValue: 3.0,
			maxValue: 5.0,
		},
		{
			name: "High entropy (random-like)",
			data: func() []byte {
				// Create data with more uniform distribution for higher entropy
				d := make([]byte, 256)
				for i := range d {
					d[i] = byte(i)
				}
				return d
			}(),
			minValue: 7.8,
			maxValue: 8.1,
		},
		{
			name:     "Perfect distribution",
			data:     []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
			minValue: 3.9,
			maxValue: 4.1,
		},
		{
			name:     "Empty",
			data:     []byte{},
			minValue: 0.0,
			maxValue: 0.0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			entropy := ShannonEntropy(tt.data)
			if entropy < tt.minValue || entropy > tt.maxValue {
				t.Errorf("ShannonEntropy() = %v, want between %v and %v", entropy, tt.minValue, tt.maxValue)
			}
		})
	}
}

func BenchmarkCheckSignatures(b *testing.B) {
	payload := []byte("d1:md6:ut_pexi1ee5:added52:xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxe")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		CheckSignatures(payload)
	}
}

func BenchmarkShannonEntropy(b *testing.B) {
	data := make([]byte, 1024)
	for i := range data {
		data[i] = byte(i % 256)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ShannonEntropy(data)
	}
}

func BenchmarkCheckUDPTrackerDeep(b *testing.B) {
	packet := make([]byte, 98)
	// Connection ID
	copy(packet[0:8], []byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88})
	// Action: Announce
	packet[8], packet[9], packet[10], packet[11] = 0x00, 0x00, 0x00, 0x01
	// PeerID
	copy(packet[36:39], []byte("-qB"))

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		CheckUDPTrackerDeep(packet)
	}
}

func TestCheckMSEEncryption(t *testing.T) {
	tests := []struct {
		name     string
		payload  []byte
		expected bool
	}{
		{
			name: "MSE handshake with VC (8 zero bytes)",
			payload: func() []byte {
				p := make([]byte, 200)
				// Fill first 96 bytes with high-entropy data (simulating DH public key)
				// Use pseudo-random pattern to achieve entropy > 6.5
				for i := 0; i < 96; i++ {
					p[i] = byte((i*173 + 17) % 256)
				}
				// Add padding with varied data
				for i := 96; i < 110; i++ {
					p[i] = byte((i * 7) % 256)
				}
				// Insert VC (8 consecutive zero bytes) at offset 110
				for i := 110; i < 118; i++ {
					p[i] = 0x00
				}
				// Add crypto_provide field (4 bytes) after VC
				// 0x00000002 = RC4 encryption
				p[118] = 0x00
				p[119] = 0x00
				p[120] = 0x00
				p[121] = 0x02
				return p
			}(),
			expected: true,
		},
		{
			name: "MSE with VC at beginning of search window",
			payload: func() []byte {
				p := make([]byte, 150)
				// First 96 bytes = high-entropy DH key
				for i := 0; i < 96; i++ {
					p[i] = byte((i*173 + 17) % 256)
				}
				// VC right after DH key (at offset 96)
				for i := 96; i < 104; i++ {
					p[i] = 0x00
				}
				// Add crypto_provide field (4 bytes) after VC
				// 0x00000001 = plaintext allowed
				p[104] = 0x00
				p[105] = 0x00
				p[106] = 0x00
				p[107] = 0x01
				return p
			}(),
			expected: true,
		},
		{
			name:     "Not MSE - too short",
			payload:  []byte{0x00, 0x00, 0x00, 0x00},
			expected: false,
		},
		{
			name: "Not MSE - low entropy and no VC",
			payload: func() []byte {
				// Create payload with low entropy and no 8 consecutive zeros
				p := make([]byte, 120)
				for i := 0; i < 120; i++ {
					p[i] = byte(i%7 + 1) // Values 1-7, never 8 zeros in a row
				}
				return p
			}(),
			expected: false,
		},
		{
			name: "Not MSE - high entropy but no VC",
			payload: func() []byte {
				// High entropy data but missing the VC marker (like Hysteria2)
				p := make([]byte, 120)
				seed := uint32(0xABCDEF01)
				for i := 0; i < 120; i++ {
					seed = (seed*1664525 + 1013904223)
					p[i] = byte(seed >> 24)
				}
				// Ensure no 8 consecutive zeros
				for i := 0; i < 113; i++ {
					hasEightZeros := true
					for j := 0; j < 8; j++ {
						if p[i+j] != 0 {
							hasEightZeros = false
							break
						}
					}
					if hasEightZeros {
						p[i] = 0x01 // Break the sequence
					}
				}
				return p
			}(),
			expected: false,
		},
		{
			name: "Not MSE - has VC but low entropy",
			payload: func() []byte {
				// Low entropy DH key with VC marker
				p := make([]byte, 120)
				for i := 0; i < 96; i++ {
					p[i] = byte(i % 10) // Low entropy pattern
				}
				// Add VC at offset 96
				for i := 96; i < 104; i++ {
					p[i] = 0x00
				}
				return p
			}(),
			expected: false,
		},
		{
			name:     "Normal HTTP traffic",
			payload:  []byte("GET /announce?info_hash=xxxxx HTTP/1.1\r\nHost: tracker.example.com\r\n\r\n"),
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := CheckMSEEncryption(tt.payload)
			if result != tt.expected {
				t.Errorf("CheckMSEEncryption() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestCheckLSD(t *testing.T) {
	tests := []struct {
		name     string
		payload  []byte
		destIP   string
		destPort uint16
		expected bool
	}{
		{
			name:     "LSD to IPv4 multicast address",
			payload:  []byte("BT-SEARCH * HTTP/1.1\r\nHost: 239.192.152.143:6771\r\n"),
			destIP:   "239.192.152.143",
			destPort: 6771,
			expected: true,
		},
		{
			name:     "LSD to IPv6 multicast address",
			payload:  []byte("BT-SEARCH * HTTP/1.1\r\n"),
			destIP:   "ff15::efc0:988f",
			destPort: 6771,
			expected: true,
		},
		{
			name:     "LSD with BT-SEARCH signature",
			payload:  []byte("BT-SEARCH * HTTP/1.1\r\nHost: 239.192.152.143:6771\r\nInfohash: 0123456789ABCDEF0123456789ABCDEF01234567\r\nPort: 6881\r\n"),
			destIP:   "10.0.0.1",
			destPort: 12345,
			expected: true,
		},
		{
			name:     "LSD with Host header",
			payload:  []byte("Host: 239.192.152.143:6771\r\nInfohash: ABCD\r\n"),
			destIP:   "192.168.1.1",
			destPort: 8080,
			expected: true,
		},
		{
			name:     "LSD with Infohash and Port",
			payload:  []byte("Infohash: 0123456789ABCDEF0123456789ABCDEF01234567\r\nPort: 6881\r\n"),
			destIP:   "10.0.0.1",
			destPort: 9999,
			expected: true,
		},
		{
			name:     "Wrong port on multicast IP",
			payload:  []byte("Some data"),
			destIP:   "239.192.152.143",
			destPort: 8080,
			expected: false,
		},
		{
			name:     "Wrong IP on correct port",
			payload:  []byte("Some data"),
			destIP:   "192.168.1.1",
			destPort: 6771,
			expected: false,
		},
		{
			name:     "Normal HTTP traffic",
			payload:  []byte("GET / HTTP/1.1\r\nHost: example.com\r\n"),
			destIP:   "93.184.216.34",
			destPort: 80,
			expected: false,
		},
		{
			name:     "Has Infohash but no Port",
			payload:  []byte("Infohash: ABCD1234\r\n"),
			destIP:   "10.0.0.1",
			destPort: 9999,
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := CheckLSD(tt.payload, tt.destIP, tt.destPort)
			if result != tt.expected {
				t.Errorf("CheckLSD() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestCheckExtendedMessage(t *testing.T) {
	tests := []struct {
		name     string
		payload  []byte
		expected bool
	}{
		{
			name: "Extended handshake (msg ID 20, ext ID 0)",
			payload: []byte{
				0x00, 0x00, 0x00, 0x30, // Length: 48 bytes
				0x14, // Message ID: 20 (Extended)
				0x00, // Extended ID: 0 (handshake)
				'd',  // Bencode dictionary start
				'1', ':', 'm', 'd',
				'6', ':', 'u', 't', '_', 'p', 'e', 'x',
				'i', '1', 'e', 'e', 'e',
			},
			expected: true,
		},
		{
			name: "Extended message without bencode (still valid)",
			payload: []byte{
				0x00, 0x00, 0x00, 0x10,
				0x14, // Message ID: 20
				0x01, // Extended ID: 1 (not handshake)
				0x00, 0x01, 0x02,
			},
			expected: true,
		},
		{
			name: "Extended ut_metadata request",
			payload: []byte{
				0x00, 0x00, 0x00, 0x20,
				0x14, // Message ID: 20
				0x02, // Extended ID: 2 (ut_metadata)
				'd', '8', ':', 'm', 's', 'g', '_', 't', 'y', 'p', 'e',
				'i', '0', 'e', '5', ':', 'p', 'i', 'e', 'c', 'e',
				'i', '0', 'e', 'e',
			},
			expected: true,
		},
		{
			name:     "Too short for extended message",
			payload:  []byte{0x00, 0x00, 0x00, 0x01, 0x14},
			expected: false,
		},
		{
			name: "Wrong message ID",
			payload: []byte{
				0x00, 0x00, 0x00, 0x10,
				0x01, // Message ID: 1 (not extended)
				0x00, 0x00, 0x00,
			},
			expected: false,
		},
		{
			name: "Standard BitTorrent handshake (not extended)",
			payload: []byte{
				0x13, 'B', 'i', 't', 'T', 'o', 'r', 'r', 'e', 'n', 't',
				' ', 'p', 'r', 'o', 't', 'o', 'c', 'o', 'l',
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := CheckExtendedMessage(tt.payload)
			if result != tt.expected {
				t.Errorf("CheckExtendedMessage() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestCheckFASTExtension(t *testing.T) {
	tests := []struct {
		name     string
		payload  []byte
		expected bool
	}{
		{
			name: "Suggest Piece (ID 13)",
			payload: []byte{
				0x00, 0x00, 0x00, 0x05, // Length: 5
				0x0D,                   // Message ID: 13
				0x00, 0x00, 0x00, 0x2A, // Piece index: 42
			},
			expected: true,
		},
		{
			name: "Have All (ID 14)",
			payload: []byte{
				0x00, 0x00, 0x00, 0x01, // Length: 1
				0x0E, // Message ID: 14
			},
			expected: true,
		},
		{
			name: "Have None (ID 15)",
			payload: []byte{
				0x00, 0x00, 0x00, 0x01, // Length: 1
				0x0F, // Message ID: 15
			},
			expected: true,
		},
		{
			name: "Reject Request (ID 16)",
			payload: []byte{
				0x00, 0x00, 0x00, 0x0D, // Length: 13
				0x10,                   // Message ID: 16
				0x00, 0x00, 0x00, 0x05, // Index: 5
				0x00, 0x00, 0x00, 0x00, // Begin: 0
				0x00, 0x00, 0x40, 0x00, // Length: 16384
			},
			expected: true,
		},
		{
			name: "Allowed Fast (ID 17)",
			payload: []byte{
				0x00, 0x00, 0x00, 0x05, // Length: 5
				0x11,                   // Message ID: 17
				0x00, 0x00, 0x00, 0x0A, // Piece index: 10
			},
			expected: true,
		},
		{
			name:     "Too short",
			payload:  []byte{0x00, 0x00, 0x00, 0x01},
			expected: false,
		},
		{
			name: "Wrong message ID (standard request)",
			payload: []byte{
				0x00, 0x00, 0x00, 0x0D,
				0x06, // Message ID: 6 (Request, not FAST)
				0x00, 0x00, 0x00, 0x00,
			},
			expected: false,
		},
		{
			name: "Wrong length for Suggest Piece",
			payload: []byte{
				0x00, 0x00, 0x00, 0x06, // Length: 6 (should be 5)
				0x0D, // Message ID: 13
				0x00, 0x00, 0x00, 0x2A,
			},
			expected: false,
		},
		{
			name: "Wrong length for Have All",
			payload: []byte{
				0x00, 0x00, 0x00, 0x02, // Length: 2 (should be 1)
				0x0E, // Message ID: 14
				0x00,
			},
			expected: false,
		},
		{
			name: "Wrong length for Reject Request",
			payload: []byte{
				0x00, 0x00, 0x00, 0x0C, // Length: 12 (should be 13)
				0x10, // Message ID: 16
				0x00, 0x00, 0x00, 0x05,
				0x00, 0x00, 0x00, 0x00,
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := CheckFASTExtension(tt.payload)
			if result != tt.expected {
				t.Errorf("CheckFASTExtension() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func BenchmarkCheckMSEEncryption(b *testing.B) {
	payload := make([]byte, 120)
	for i := 0; i < 96; i++ {
		payload[i] = byte((i * 37) % 256)
	}
	// Add VC
	for i := 96; i < 104; i++ {
		payload[i] = 0x00
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		CheckMSEEncryption(payload)
	}
}

func BenchmarkCheckLSD(b *testing.B) {
	payload := []byte("BT-SEARCH * HTTP/1.1\r\nHost: 239.192.152.143:6771\r\nInfohash: ABCD\r\nPort: 6881\r\n")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		CheckLSD(payload, "239.192.152.143", 6771)
	}
}

func BenchmarkCheckExtendedMessage(b *testing.B) {
	payload := []byte{
		0x00, 0x00, 0x00, 0x30,
		0x14, 0x00, 'd', '1', ':', 'm', 'd',
		'6', ':', 'u', 't', '_', 'p', 'e', 'x',
		'i', '1', 'e', 'e', 'e',
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		CheckExtendedMessage(payload)
	}
}

func BenchmarkCheckFASTExtension(b *testing.B) {
	payload := []byte{
		0x00, 0x00, 0x00, 0x05,
		0x0D,
		0x00, 0x00, 0x00, 0x2A,
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		CheckFASTExtension(payload)
	}
}

func TestCheckHTTPBitTorrent(t *testing.T) {
	tests := []struct {
		name     string
		payload  []byte
		expected bool
	}{
		// WebSeed Protocol Tests (BEP 19)
		{
			name:     "WebSeed request valid",
			payload:  []byte("GET /webseed?info_hash=0123456789ABCDEF0123456789ABCDEF01234567&piece=0 HTTP/1.1\r\nHost: webseed.example.com\r\n\r\n"),
			expected: true,
		},
		{
			name:     "WebSeed request minimal",
			payload:  []byte("GET /webseed?info_hash=abc123 HTTP/1.1\r\n\r\n"),
			expected: true,
		},
		{
			name:     "WebSeed with additional parameters",
			payload:  []byte("GET /webseed?info_hash=ABC&piece=5&offset=16384 HTTP/1.1\r\n\r\n"),
			expected: true,
		},

		// Bitcomet Persistent Seed Tests
		{
			name:     "Bitcomet persistent seed valid",
			payload:  []byte("GET /data?fid=12345&size=1048576 HTTP/1.1\r\nHost: peer.example.com\r\n\r\n"),
			expected: true,
		},
		{
			name:     "Bitcomet persistent seed with additional params",
			payload:  []byte("GET /data?fid=abcdef&size=524288&offset=0 HTTP/1.1\r\n\r\n"),
			expected: true,
		},
		{
			name:     "Bitcomet persistent seed missing size parameter",
			payload:  []byte("GET /data?fid=12345 HTTP/1.1\r\n\r\n"),
			expected: false,
		},
		{
			name:     "Bitcomet persistent seed missing fid parameter",
			payload:  []byte("GET /data?size=1048576 HTTP/1.1\r\n\r\n"),
			expected: false,
		},

		// User-Agent Detection Tests
		{
			name:     "User-Agent Azureus",
			payload:  []byte("GET /announce HTTP/1.1\r\nHost: tracker.example.com\r\nUser-Agent: Azureus 5.7.6.0\r\n\r\n"),
			expected: true,
		},
		{
			name:     "User-Agent BitTorrent",
			payload:  []byte("GET /announce HTTP/1.1\r\nUser-Agent: BitTorrent/7.10.5\r\n\r\n"),
			expected: true,
		},
		{
			name:     "User-Agent BTWebClient",
			payload:  []byte("GET /file HTTP/1.1\r\nUser-Agent: BTWebClient/1.0\r\n\r\n"),
			expected: true,
		},
		{
			name:     "User-Agent Shareaza",
			payload:  []byte("GET /download HTTP/1.1\r\nUser-Agent: Shareaza 2.7.10.2\r\n\r\n"),
			expected: true,
		},
		{
			name:     "User-Agent FlashGet",
			payload:  []byte("GET /file HTTP/1.1\r\nUser-Agent: FlashGet 3.7\r\n\r\n"),
			expected: true,
		},

		// Negative Tests
		{
			name:     "Normal HTTP GET",
			payload:  []byte("GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Mozilla/5.0\r\n\r\n"),
			expected: false,
		},
		{
			name:     "Normal HTTP GET with User-Agent Chrome",
			payload:  []byte("GET /page HTTP/1.1\r\nUser-Agent: Chrome/90.0\r\n\r\n"),
			expected: false,
		},
		{
			name:     "HTTP POST request",
			payload:  []byte("POST /api HTTP/1.1\r\nHost: example.com\r\n\r\n"),
			expected: false,
		},
		{
			name:     "Too short payload",
			payload:  []byte("GET /"),
			expected: false,
		},
		{
			name:     "Empty payload",
			payload:  []byte{},
			expected: false,
		},
		{
			name:     "Non-HTTP payload",
			payload:  []byte("\x13BitTorrent protocol"),
			expected: false,
		},
		{
			name:     "WebSeed-like but not GET",
			payload:  []byte("POST /webseed?info_hash=abc HTTP/1.1\r\n\r\n"),
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := CheckHTTPBitTorrent(tt.payload)
			if result != tt.expected {
				t.Errorf("CheckHTTPBitTorrent() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func BenchmarkCheckHTTPBitTorrent(b *testing.B) {
	payload := []byte("GET /webseed?info_hash=0123456789ABCDEF0123456789ABCDEF01234567&piece=0 HTTP/1.1\r\nHost: webseed.example.com\r\n\r\n")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		CheckHTTPBitTorrent(payload)
	}
}

func BenchmarkCheckDHTNodes(b *testing.B) {
	node := make([]byte, 26)
	copy(node[0:20], []byte("12345678901234567890"))
	node[20], node[21], node[22], node[23] = 192, 168, 1, 1
	node[24], node[25] = 0x1A, 0xE1
	payload := []byte("d6:nodes26:" + string(node) + "e")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		CheckDHTNodes(payload)
	}
}

func BenchmarkCheckBencodeDHT(b *testing.B) {
	payload := []byte("d1:ad2:id20:abcdefghij0123456789e1:q4:ping1:t2:aa1:y1:qe")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		CheckBencodeDHT(payload)
	}
}
