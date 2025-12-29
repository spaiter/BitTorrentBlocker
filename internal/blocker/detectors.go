package blocker

import (
	"bytes"
	"encoding/binary"
	"math"
	"strings"
)

// CheckSignatures searches for BitTorrent signature patterns in payload
func CheckSignatures(payload []byte) bool {
	for _, sig := range BTSignatures {
		if bytes.Contains(payload, sig) {
			return true
		}
	}
	return false
}

// UnwrapSOCKS5 removes SOCKS5 UDP Associate header
func UnwrapSOCKS5(packet []byte) ([]byte, bool) {
	// Minimum header size: 10 bytes
	if len(packet) <= 10 || packet[0] != 0 || packet[1] != 0 {
		return nil, false
	}

	atyp := packet[3]
	headerLen := 0
	switch atyp {
	case 1: // IPv4
		headerLen = 10
	case 4: // IPv6
		headerLen = 22
	case 3: // Domain
		if len(packet) < 5 {
			return nil, false
		}
		headerLen = 4 + 1 + int(packet[4]) + 2
	default:
		return nil, false
	}

	if len(packet) <= headerLen {
		return nil, false
	}
	return packet[headerLen:], true
}

// CheckSOCKSConnection detects SOCKS proxy connection attempts
func CheckSOCKSConnection(payload []byte) bool {
	if len(payload) < 3 {
		return false
	}
	// SOCKS4: [4][1/2]...
	if payload[0] == 0x04 && (payload[1] == 0x01 || payload[1] == 0x02) {
		return true
	}
	// SOCKS5: [5][N methods]...
	if payload[0] == 0x05 && int(payload[1]) == len(payload)-2 {
		return true
	}
	return false
}

// CheckUDPTrackerDeep validates UDP tracker packet structure (Connect/Announce/Scrape)
func CheckUDPTrackerDeep(packet []byte) bool {
	if len(packet) < 16 {
		return false
	}

	// 1. Connect (Magic Number Check)
	if len(packet) >= 16 && len(packet) < minSizeScrape {
		if binary.BigEndian.Uint64(packet[:8]) == trackerProtocolID &&
			binary.BigEndian.Uint32(packet[8:12]) == actionConnect {
			return true
		}
	}

	// 2. Announce (Action + PeerID Check)
	if len(packet) >= minSizeAnnounce {
		if binary.BigEndian.Uint32(packet[8:12]) == actionAnnounce {
			// Check PeerID at offset 36 (from udp_tracker_connection.cpp)
			peerID := packet[36:40]
			for _, prefix := range PeerIDPrefixes {
				if bytes.HasPrefix(peerID, prefix) {
					return true
				}
			}
			return true // Even without prefix, Announce structure is unique
		}
	}

	// 3. Scrape
	if len(packet) >= minSizeScrape {
		if binary.BigEndian.Uint32(packet[8:12]) == actionScrape {
			return true
		}
	}
	return false
}

// CheckUTPRobust validates uTP header and extension chain
func CheckUTPRobust(packet []byte) bool {
	if len(packet) < 20 {
		return false
	}
	version := packet[0] & 0x0F
	typ := packet[0] >> 4
	if version != 1 || typ > 4 {
		return false
	}

	extension := packet[1]
	offset := 20
	// Walk through extension linked list
	for extension != 0 {
		if offset >= len(packet) {
			return false
		}
		nextExtension := packet[offset]
		offset++
		if offset >= len(packet) {
			return false
		}
		length := int(packet[offset])
		offset++
		extension = nextExtension
		offset += length
		if offset > len(packet) {
			return false
		}
	}
	return true
}

// CheckBencodeDHT looks for structural Bencode dictionary patterns
func CheckBencodeDHT(payload []byte) bool {
	if len(payload) < 8 {
		return false
	}
	// Must start with 'd' and end with 'e'
	if payload[0] != 'd' || payload[len(payload)-1] != 'e' {
		return false
	}

	s := string(payload)
	// Must contain query type (y) AND (transaction t OR specific keys)
	hasType := strings.Contains(s, "1:y1:q") || strings.Contains(s, "1:y1:r")
	if !hasType {
		return false
	}

	return strings.Contains(s, "1:t") ||
		strings.Contains(s, "5:nodes") ||
		strings.Contains(s, "6:values")
}

// ShannonEntropy calculates data randomness/entropy
func ShannonEntropy(data []byte) float64 {
	if len(data) == 0 {
		return 0
	}
	freq := make([]int, 256)
	for _, b := range data {
		freq[b]++
	}
	entropy := 0.0
	total := float64(len(data))
	for _, count := range freq {
		if count > 0 {
			p := float64(count) / total
			entropy -= p * math.Log2(p)
		}
	}
	return entropy
}

// CheckMSEEncryption detects Message Stream Encryption (MSE/PE) handshake
// This is critical for detecting encrypted BitTorrent traffic
func CheckMSEEncryption(payload []byte) bool {
	// MSE handshake structure:
	// 1. 96-byte DH public key
	// 2. 0-512 bytes random padding
	// 3. 96-byte DH response key
	// 4. Verification Constant (VC): 8 zero bytes
	// 5. crypto_provide/select (4 bytes)

	// Minimum: 96-byte DH key + VC (8 bytes)
	if len(payload) < 104 {
		return false
	}

	// Strategy 1: Look for Verification Constant (8 consecutive zero bytes)
	// Search window: bytes 96-628 (96 + max padding 512 + 20)
	searchEnd := 628
	if len(payload) < searchEnd {
		searchEnd = len(payload)
	}

	for i := 96; i <= searchEnd-8 && i < len(payload)-8; i++ {
		// Check for VC (8 consecutive zero bytes)
		isVC := true
		for j := 0; j < 8; j++ {
			if payload[i+j] != 0x00 {
				isVC = false
				break
			}
		}
		if isVC {
			return true
		}
	}

	// Strategy 2: Check if first 96 bytes have high entropy (DH public key characteristic)
	if len(payload) >= 96 {
		entropy := ShannonEntropy(payload[0:96])
		// DH public keys should have high entropy (> 7.0)
		// Combined with connection start = likely MSE
		if entropy > 7.0 {
			return true
		}
	}

	return false
}

// CheckLSD detects Local Service Discovery (LSD) traffic
// LSD uses multicast to discover peers on the local network
func CheckLSD(payload []byte, destIP string, destPort uint16) bool {
	// Check if destined to LSD multicast address and port
	if destPort == 6771 {
		if destIP == "239.192.152.143" || destIP == "ff15::efc0:988f" {
			return true
		}
	}

	// Check for BT-SEARCH HTTP-style message (LSD announce format)
	if bytes.Contains(payload, []byte("BT-SEARCH * HTTP/1.1")) {
		return true
	}

	if bytes.Contains(payload, []byte("Host: 239.192.152.143:6771")) {
		return true
	}

	// LSD messages must contain both Infohash and Port
	if bytes.Contains(payload, []byte("Infohash: ")) &&
		bytes.Contains(payload, []byte("Port: ")) {
		return true
	}

	return false
}

// CheckExtendedMessage detects BitTorrent Extension Protocol messages (BEP 10)
// Message ID 20 (0x14) indicates extended protocol usage
func CheckExtendedMessage(payload []byte) bool {
	// Minimum: 4-byte length + 1-byte msg ID + 1-byte ext ID + 1-byte bencode
	if len(payload) < 7 {
		return false
	}

	// BitTorrent messages have 4-byte length prefix
	// Check for message ID 20 (0x14) at offset 4
	if payload[4] == 0x14 {
		// Extended message should be followed by extended ID and bencode dictionary
		// Extended ID 0 = handshake (always starts with 'd')
		if len(payload) > 6 && payload[6] == 'd' {
			return true
		}
		// Message ID 20 alone is highly specific to BitTorrent
		return true
	}

	return false
}

// CheckFASTExtension detects FAST Extension messages (BEP 6)
// Message IDs 13-17 (0x0D-0x11) are FAST extension specific
func CheckFASTExtension(payload []byte) bool {
	// Minimum: 4-byte length + 1-byte msg ID
	if len(payload) < 5 {
		return false
	}

	// Check message ID
	msgID := payload[4]

	// FAST extension message IDs: 13-17 (0x0D-0x11)
	if msgID >= 0x0D && msgID <= 0x11 {
		// Validate message length matches expected for each type
		msgLen := binary.BigEndian.Uint32(payload[0:4])

		switch msgID {
		case 0x0D, 0x11: // Suggest Piece (13), Allowed Fast (17) - 5 bytes payload
			return msgLen == 5
		case 0x0E, 0x0F: // Have All (14), Have None (15) - 1 byte payload
			return msgLen == 1
		case 0x10: // Reject Request (16) - 13 bytes payload
			return msgLen == 13
		}
		// Unknown FAST message, still likely BitTorrent
		return true
	}

	return false
}

// CheckHTTPBitTorrent detects HTTP-based BitTorrent protocols
// Includes WebSeed, Bitcomet persistent seed, and User-Agent detection
func CheckHTTPBitTorrent(payload []byte) bool {
	// Minimum HTTP request size
	if len(payload) < 16 {
		return false
	}

	// Must be HTTP GET request
	if !bytes.HasPrefix(payload, []byte("GET ")) {
		return false
	}

	s := string(payload)

	// 1. WebSeed Protocol (BEP 19)
	// Format: GET /webseed?info_hash=<hash>&piece=<num>
	if strings.Contains(s, "GET /webseed?info_hash=") {
		return true
	}

	// 2. Bitcomet Persistent Seed Protocol
	// Format: GET /data?fid=<file_id>&size=<size>
	if strings.Contains(s, "GET /data?fid=") && strings.Contains(s, "&size=") {
		return true
	}

	// 3. User-Agent Detection (Common BitTorrent clients)
	// Check for known BitTorrent client User-Agent strings
	userAgentPatterns := []string{
		"User-Agent: Azureus",
		"User-Agent: BitTorrent",
		"User-Agent: BTWebClient",
		"User-Agent: Shareaza",
		"User-Agent: FlashGet",
	}

	for _, pattern := range userAgentPatterns {
		if strings.Contains(s, pattern) {
			return true
		}
	}

	return false
}
