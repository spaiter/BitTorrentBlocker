package blocker

import (
	"bytes"
	"encoding/binary"
	"math"
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

	// CRITICAL: Reject CAPWAP control packets
	// CAPWAP header: Preamble (1 byte) | HLEN (5 bits) | RID (5 bits) | WBID (5 bits) | T (1 bit) | F (1 bit) | L (1 bit) | W (1 bit) | M (1 bit) | K (1 bit) | Flags (3 bits)
	// Common pattern: 0x00 0x10 or 0x00 0x20 at start (preamble=0, HLEN=1 or 2)
	if packet[0] == 0x00 && (packet[1] == 0x10 || packet[1] == 0x20 || packet[1] == 0x00) {
		// Additional validation: check for structured TLV data typical of CAPWAP
		// CAPWAP uses Type-Length-Value encoding with specific patterns
		if len(packet) >= 14 && packet[12] == 0x00 && packet[13] == 0x00 {
			return false // This looks like CAPWAP, not BitTorrent
		}
	}

	// CRITICAL: Reject DTLS packets which can have similar structure
	// DTLS Content Types: 0x14=ChangeCipherSpec, 0x15=Alert, 0x16=Handshake, 0x17=ApplicationData
	// DTLS versions: 0xFEFF=1.0, 0xFEFD=1.2, 0xFEFC=1.3
	if len(packet) >= 3 {
		contentType := packet[0]
		version := binary.BigEndian.Uint16(packet[1:3])
		// Check if this is DTLS (content type 20-23, version 0xFEFF, 0xFEFD, or 0xFEFC)
		if (contentType >= 0x14 && contentType <= 0x17) &&
			(version == 0xFEFF || version == 0xFEFD || version == 0xFEFC) {
			return false // This is DTLS, not BitTorrent
		}
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
		action := binary.BigEndian.Uint32(packet[8:12])
		if action == actionAnnounce {
			// CRITICAL: Must validate connection_id (first 8 bytes)
			// Real tracker announces have a valid connection_id from previous connect response
			// Random data or other protocols (like CAPWAP) will have invalid connection_ids
			connectionID := binary.BigEndian.Uint64(packet[:8])

			// Connection IDs should not be zero or the magic number (that's the connect request)
			if connectionID == 0 || connectionID == trackerProtocolID {
				return false
			}

			// Check PeerID at offset 36 (from udp_tracker_connection.cpp)
			// A valid peer ID should start with a known client prefix
			peerID := packet[36:40]
			for _, prefix := range PeerIDPrefixes {
				if bytes.HasPrefix(peerID, prefix) {
					return true
				}
			}

			// Without a valid peer ID prefix, require additional validation
			// Check that info_hash (20 bytes at offset 16) looks like a hash
			// Real torrents won't have all zeros or all 0xFF
			infoHash := packet[16:36]
			allZero := true
			allFF := true
			for _, b := range infoHash {
				if b != 0 {
					allZero = false
				}
				if b != 0xFF {
					allFF = false
				}
			}
			if allZero || allFF {
				return false // Invalid info_hash
			}

			return true
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
// Based on sing-box implementation and BEP 29 specification
func CheckUTPRobust(packet []byte) bool {
	if len(packet) < 20 {
		return false
	}

	// CRITICAL: Reject STUN packets which start with similar bytes
	// STUN magic cookie is 0x2112A442 at offset 4-7
	// This prevents false positives with STUN/WebRTC traffic
	if len(packet) >= 8 {
		if packet[4] == 0x21 && packet[5] == 0x12 && packet[6] == 0xA4 && packet[7] == 0x42 {
			return false // This is a STUN packet, not uTP
		}
	}

	// CRITICAL: Reject DTLS/CAPWAP packets
	// DTLS versions: 0xFEFF (1.0), 0xFEFD (1.2), 0xFEFC (1.3)
	// CAPWAP often contains DTLS encapsulation
	if len(packet) >= 7 {
		version := binary.BigEndian.Uint16(packet[5:7])
		if version == 0xFEFF || version == 0xFEFD || version == 0xFEFC {
			return false // This is DTLS/CAPWAP, not uTP
		}
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

		// Validate extension type (must be 0-4 according to BEP 29)
		// 0 = SACK, 1 = Extension bits, 2 = Close reason, 3-4 reserved
		if nextExtension > 4 {
			return false
		}

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

// CheckDHTNodes validates DHT node list binary structure (Suricata logic)
// IPv4 nodes: 26 bytes per node (20-byte ID + 4-byte IP + 2-byte port)
// IPv6 nodes: 38 bytes per node (20-byte ID + 16-byte IP + 2-byte port)
func CheckDHTNodes(payload []byte) bool {
	// Look for "6:nodes" or "7:nodes6" followed by length and binary data
	// Format: "6:nodes<length>:<binary_data>"

	// Check for IPv4 nodes list: "6:nodes<len>:<data>"
	nodesIdx := bytes.Index(payload, []byte("6:nodes"))
	if nodesIdx != -1 && nodesIdx+7 < len(payload) {
		// Skip "6:nodes" and parse the length
		offset := nodesIdx + 7
		// Find the colon that separates length from data
		colonIdx := bytes.IndexByte(payload[offset:], ':')
		if colonIdx != -1 && colonIdx > 0 && colonIdx < 10 {
			// Extract and parse the length
			lengthStr := string(payload[offset : offset+colonIdx])
			// Simple length parsing (assume it's a valid number)
			nodeDataLen := 0
			for _, ch := range lengthStr {
				if ch >= '0' && ch <= '9' {
					nodeDataLen = nodeDataLen*10 + int(ch-'0')
				}
			}
			// Check if it's divisible by 26 (IPv4 node size)
			if nodeDataLen >= 26 && nodeDataLen%26 == 0 {
				return true
			}
		}
	}

	// Check for IPv6 nodes list: "7:nodes6<len>:<data>"
	nodes6Idx := bytes.Index(payload, []byte("7:nodes6"))
	if nodes6Idx != -1 && nodes6Idx+8 < len(payload) {
		offset := nodes6Idx + 8
		colonIdx := bytes.IndexByte(payload[offset:], ':')
		if colonIdx != -1 && colonIdx > 0 && colonIdx < 10 {
			lengthStr := string(payload[offset : offset+colonIdx])
			nodeDataLen := 0
			for _, ch := range lengthStr {
				if ch >= '0' && ch <= '9' {
					nodeDataLen = nodeDataLen*10 + int(ch-'0')
				}
			}
			// Check if it's divisible by 38 (IPv6 node size)
			if nodeDataLen >= 38 && nodeDataLen%38 == 0 {
				return true
			}
		}
	}

	// Only return true if we have valid structure or valid pattern match
	// Don't be too permissive - require proper bencode context
	return false
}

// CheckBencodeDHT looks for structural Bencode dictionary patterns
// Enhanced with Suricata-style validation
func CheckBencodeDHT(payload []byte) bool {
	if len(payload) < 8 {
		return false
	}
	// Must start with 'd' and end with 'e'
	if payload[0] != 'd' || payload[len(payload)-1] != 'e' {
		return false
	}

	// Optimized: use bytes.Contains instead of string conversion to avoid allocation
	// Check for Suricata-specific prefixes at start
	if bytes.HasPrefix(payload, []byte("d1:ad")) ||
		bytes.HasPrefix(payload, []byte("d1:rd")) ||
		bytes.HasPrefix(payload, []byte("d2:ip")) ||
		bytes.HasPrefix(payload, []byte("d1:el")) {
		return true
	}

	// Must contain query/response/error type
	hasType := bytes.Contains(payload, []byte("1:y1:q")) ||
		bytes.Contains(payload, []byte("1:y1:r")) ||
		bytes.Contains(payload, []byte("1:y1:e"))
	if !hasType {
		return false
	}

	// For queries, require a DHT-specific method name to reduce false positives
	hasDHTMethod := bytes.Contains(payload, []byte("4:ping")) ||
		bytes.Contains(payload, []byte("9:find_node")) ||
		bytes.Contains(payload, []byte("9:get_peers")) ||
		bytes.Contains(payload, []byte("13:announce_peer")) ||
		bytes.Contains(payload, []byte("3:get")) ||
		bytes.Contains(payload, []byte("3:put"))

	// Check for transaction ID AND (DHT method OR DHT-specific fields)
	if bytes.Contains(payload, []byte("1:t")) {
		// If it's a query, require a valid DHT method
		if bytes.Contains(payload, []byte("1:y1:q")) {
			return hasDHTMethod
		}
		// For responses/errors, also check for DHT-specific fields
		return hasDHTMethod ||
			CheckDHTNodes(payload) ||
			bytes.Contains(payload, []byte("6:values")) ||
			bytes.Contains(payload, []byte("5:token")) ||
			bytes.Contains(payload, []byte("6:nodes"))
	}

	// Check for DHT node validation
	if CheckDHTNodes(payload) {
		return true
	}

	return false
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

	// Minimum: 96-byte DH key + VC (8 bytes) + crypto field (4 bytes)
	if len(payload) < 108 {
		return false
	}

	// Check if first 96 bytes have high entropy (DH public key characteristic)
	hasHighEntropyKey := false
	if len(payload) >= 96 {
		entropy := ShannonEntropy(payload[0:96])
		// DH public keys should have high entropy (> 6.5)
		// Increased from 6.0 to 6.5 to reduce false positives
		// Typical values: DH keys ≈ 6.5-7.0, random protocols ≈ 6.0-6.3, structured data < 5.0
		if entropy > 6.5 {
			hasHighEntropyKey = true
		}
	}

	// Look for Verification Constant (8 consecutive zero bytes)
	// Search window: bytes 96-628 (96 + max padding 512 + 20)
	searchEnd := 628
	if len(payload) < searchEnd {
		searchEnd = len(payload)
	}

	hasVC := false
	vcPosition := -1
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
			hasVC = true
			vcPosition = i
			break
		}
	}

	// Additional validation: check crypto_provide/select field after VC
	// This field should be 4 bytes after VC and have specific values
	hasCryptoField := false
	if hasVC && vcPosition >= 0 && len(payload) >= vcPosition+12 {
		// crypto_provide/select is 4 bytes after VC
		// Valid values: 0x00000001 (plaintext), 0x00000002 (RC4)
		cryptoBytes := binary.BigEndian.Uint32(payload[vcPosition+8 : vcPosition+12])
		// Check if it's a valid crypto field (bits 1 or 2 set, not all zeros or all ones)
		if cryptoBytes > 0 && cryptoBytes <= 0x03 {
			hasCryptoField = true
		}
	}

	// Require ALL THREE conditions to minimize false positives:
	// 1. High entropy DH key (> 6.5)
	// 2. VC marker (8 zero bytes)
	// 3. Valid crypto_provide/select field
	return hasHighEntropyKey && hasVC && hasCryptoField
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

	// Optimize: use bytes.Contains instead of string conversion to avoid allocation
	// 1. WebSeed Protocol (BEP 19)
	// Format: GET /webseed?info_hash=<hash>&piece=<num>
	if bytes.Contains(payload, []byte("/webseed?info_hash=")) {
		return true
	}

	// 2. Bitcomet Persistent Seed Protocol
	// Format: GET /data?fid=<file_id>&size=<size>
	if bytes.Contains(payload, []byte("/data?fid=")) && bytes.Contains(payload, []byte("&size=")) {
		return true
	}

	// 3. User-Agent Detection (Common BitTorrent clients)
	// Check for known BitTorrent client User-Agent strings
	// Optimized: use bytes.Contains to avoid string allocation
	if bytes.Contains(payload, []byte("User-Agent: Azureus")) ||
		bytes.Contains(payload, []byte("User-Agent: BitTorrent")) ||
		bytes.Contains(payload, []byte("User-Agent: BTWebClient")) ||
		bytes.Contains(payload, []byte("User-Agent: Shareaza")) ||
		bytes.Contains(payload, []byte("User-Agent: FlashGet")) {
		return true
	}

	return false
}
