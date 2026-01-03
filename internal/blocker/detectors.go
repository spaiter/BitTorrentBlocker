package blocker

import (
	"bytes"
	"encoding/binary"
	"math"
)

// CheckSignatures searches for BitTorrent signature patterns in payload
func CheckSignatures(payload []byte) bool {
	// OPTIMIZATION: Fast-path for most common signatures (early exit)
	// These patterns account for ~80% of signature matches in real traffic

	// 1. BitTorrent protocol handshake (most common)
	if bytes.Contains(payload, []byte("BitTorrent protocol")) {
		return true
	}

	// 2. DHT queries/responses (very common in UDP traffic)
	// Pattern: d1:ad2:id20: or d1:rd2:id20:
	if len(payload) >= 13 && payload[0] == 'd' && payload[1] == '1' && payload[2] == ':' {
		if payload[3] == 'a' || payload[3] == 'r' {
			if payload[4] == 'd' && payload[5] == '2' && payload[6] == ':' {
				return true
			}
		}
	}

	// 3. Check remaining signatures
	for _, sig := range BTSignatures {
		// Skip signatures already checked above
		if len(sig) == 19 && sig[0] == 'B' { // "BitTorrent protocol"
			continue
		}
		if len(sig) == 13 && sig[0] == 'd' && sig[1] == '1' { // DHT patterns
			continue
		}

		// Length pre-filter: skip signatures longer than payload
		if len(sig) > len(payload) {
			continue
		}

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
	var headerLen int
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

	// CRITICAL: Reject DNS queries and responses
	// DNS header: Transaction ID (2) | Flags (2) | Questions (2) | Answers (2) | Authority (2) | Additional (2)
	// Standard query: flags & 0x8000 == 0 (QR bit = 0 for query)
	// Standard response: flags & 0x8000 != 0 (QR bit = 1 for response)
	if len(packet) >= 12 {
		flags := binary.BigEndian.Uint16(packet[2:4])
		qdcount := binary.BigEndian.Uint16(packet[4:6])

		// DNS queries typically have: QR=0, QDCOUNT >= 1
		// DNS responses typically have: QR=1
		isQuery := (flags&0x8000) == 0 && qdcount > 0 && qdcount < 100
		isResponse := (flags & 0x8000) != 0

		if isQuery || isResponse {
			// Additional validation: check OPCODE (bits 11-14 of flags)
			// Standard query = 0, Inverse query = 1, Status = 2
			opcode := (flags >> 11) & 0x0F
			if opcode <= 2 {
				return false // This is DNS, not BitTorrent
			}
		}
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

	// CRITICAL: Reject AFS RX protocol packets
	// RX protocol structure: Epoch (4) | Connection ID (4) | Call Number (4) | Sequence (4) | Serial (4) | Type (1) | Flags (1)
	// RX packets have:
	// - Call Number at offset 8-11 (often 1 or 2, coincidentally matching BT announce/scrape actions)
	// - Serial number at offset 16-19 (increments by 1, looks like transaction ID)
	// - Type byte at offset 20 (1-4 for data, 3 for ack, etc.)
	// Key discriminators from BitTorrent UDP tracker:
	// 1. RX has consistent packet type byte at offset 20-21
	// 2. RX sequence/serial increment patterns are different
	// 3. First 4 bytes (epoch) are usually recent Unix timestamps (0x6XXXXXXX range or newer 0xAXXXXXXX+)
	if len(packet) >= 24 {
		// Check if first 4 bytes look like a Unix epoch timestamp
		// Unix timestamps since Jan 1, 2010 are in range 0x4B3B4CA8 - current time
		// AFS RX epochs are typically recent timestamps (within a few years)
		epoch := binary.BigEndian.Uint32(packet[0:4])
		callNum := binary.BigEndian.Uint32(packet[8:12])
		seq := binary.BigEndian.Uint32(packet[12:16])
		serial := binary.BigEndian.Uint32(packet[16:20])
		packetType := packet[20]

		// RX protocol detection criteria:
		// 1. Epoch looks like a recent timestamp (0x50000000 to 0xFFFFFFFF, ~2012 onwards)
		// 2. Call number is small (1-100 typical)
		// 3. Sequence and serial are small incremental values (0-1000 typical)
		// 4. Packet type is in valid RX range (1-13)
		if epoch >= 0x50000000 && // Recent Unix timestamp
			callNum <= 100 && // Small call number
			seq <= 1000 && // Small sequence number
			serial <= 1000 && // Small serial number
			packetType >= 1 && packetType <= 13 { // Valid RX packet type
			return false // This is AFS RX protocol, not BitTorrent
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

			// CRITICAL: Reject connection IDs with too many trailing zero bytes
			// Real UDP tracker connection IDs are pseudo-random 64-bit values
			// Gaming protocols (GeForce Now, etc.) often have patterns like 0x90XX000000000000
			// Count trailing zero bytes in connection ID
			connIDBytes := packet[:8]
			trailingZeroBytes := 0
			for i := 7; i >= 0; i-- {
				if connIDBytes[i] == 0 {
					trailingZeroBytes++
				} else {
					break
				}
			}
			// Reject if more than 3 trailing zero bytes (real connection IDs are random)
			if trailingZeroBytes > 3 {
				return false // Connection ID has too many trailing zeros, not BitTorrent
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

			// Additional validation: Check full peer ID (20 bytes at offset 36-55)
			// Real BitTorrent peer IDs should not have excessive trailing zeros
			// Gaming protocols and other false positives often have many trailing zeros
			fullPeerID := packet[36:56]
			trailingZeros := 0
			for i := len(fullPeerID) - 1; i >= 0; i-- {
				if fullPeerID[i] == 0 {
					trailingZeros++
				} else {
					break
				}
			}
			// Reject if more than 3 trailing zeros (real peer IDs are random/structured)
			if trailingZeros > 3 {
				return false // Too many trailing zeros, likely not BitTorrent
			}

			return true
		}
	}

	// 3. Scrape
	if len(packet) >= minSizeScrape {
		action := binary.BigEndian.Uint32(packet[8:12])
		if action == actionScrape {
			// CRITICAL: Validate connection_id (same as announce)
			// Real tracker scrapes have a valid connection_id from previous connect response
			connectionID := binary.BigEndian.Uint64(packet[:8])

			// Connection IDs should not be zero or the magic number
			if connectionID == 0 || connectionID == trackerProtocolID {
				return false
			}

			// CRITICAL: Reject connection IDs with too many trailing zero bytes
			// Gaming protocols (GeForce Now, etc.) have patterns like 0x90XX000000000000
			connIDBytes := packet[:8]
			trailingZeroBytes := 0
			for i := 7; i >= 0; i-- {
				if connIDBytes[i] == 0 {
					trailingZeroBytes++
				} else {
					break
				}
			}
			// Reject if more than 3 trailing zero bytes
			if trailingZeroBytes > 3 {
				return false // Connection ID has too many trailing zeros, not BitTorrent
			}

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

	// CRITICAL: Reject DHCP/BOOTP packets (RFC 2131)
	// DHCP packets start with: op(1) htype(1) hlen(1) hops(1) xid(4) ...
	// Common pattern: 0x01 (BOOTREQUEST) or 0x02 (BOOTREPLY) at byte 0
	// And have magic cookie 0x63825363 at offset 236
	// DHCP is often misdetected because first byte can be 0x01 (like uTP version 1)
	if len(packet) >= 240 {
		op := packet[0]
		htype := packet[1]
		hlen := packet[2]
		// Check if this looks like DHCP: op=1 or 2, htype=1 (Ethernet), hlen=6
		if (op == 0x01 || op == 0x02) && htype == 0x01 && hlen == 0x06 {
			// Verify with magic cookie at offset 236
			if packet[236] == 0x63 && packet[237] == 0x82 && packet[238] == 0x53 && packet[239] == 0x63 {
				return false // This is DHCP, not uTP
			}
		}
	}

	// CRITICAL: Reject STUN packets which start with similar bytes
	// Modern STUN (RFC 5389): magic cookie 0x2112A442 at offset 4-7
	// Classic STUN (RFC 3489): valid message types 0x0001, 0x0101, 0x0111, etc.
	// This prevents false positives with STUN/WebRTC traffic
	if len(packet) >= 8 {
		// Check for modern STUN (RFC 5389)
		if packet[4] == 0x21 && packet[5] == 0x12 && packet[6] == 0xA4 && packet[7] == 0x42 {
			return false // This is a modern STUN packet, not uTP
		}
	}

	// CRITICAL: Reject classic STUN (RFC 3489) packets
	// Classic STUN format: [2 bytes type][2 bytes length][16 bytes transaction ID]
	// Valid message types: 0x0001 (Binding Request), 0x0101 (Binding Response),
	// 0x0111 (Binding Error), 0x0002 (Shared Secret Request), etc.
	// First 2 bits must be 00, and message type should be in valid range
	if len(packet) >= 20 {
		msgType := binary.BigEndian.Uint16(packet[0:2])
		msgLen := binary.BigEndian.Uint16(packet[2:4])

		// Check if this looks like classic STUN:
		// 1. First 2 bits are 00 (msgType < 0x4000)
		// 2. Valid message types: 0x0001, 0x0002, 0x0101, 0x0102, 0x0111, 0x0112
		// 3. Message length is reasonable (< 1500 bytes)
		if msgType < 0x4000 && msgLen < 1500 {
			// Check for known classic STUN message types
			if msgType == 0x0001 || msgType == 0x0101 || msgType == 0x0111 ||
				msgType == 0x0002 || msgType == 0x0102 || msgType == 0x0112 {
				return false // This is a classic STUN packet, not uTP
			}
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

	// Validate uTP version and type first (must be version=1, type 0-4)
	version := packet[0] & 0x0F
	typ := packet[0] >> 4
	if version != 1 || typ > 4 {
		return false
	}

	// CRITICAL: Additional uTP validation checks to prevent QUIC/VoIP false positives
	// Extract connection ID and window size for validation
	connectionID := binary.BigEndian.Uint16(packet[2:4])
	windowSize := binary.BigEndian.Uint32(packet[12:16])

	// CRITICAL: Reject packets with connection ID = 0
	// TeamViewer and other protocols can have all-zero connection IDs
	// Real uTP uses random non-zero connection IDs (16-bit)
	// Exception: ST_SYN packets (type=4) can have conn_id=0 on initial handshake
	if connectionID == 0 && typ != 4 {
		return false // Zero connection ID for non-SYN packet, not uTP
	}

	// CRITICAL: Reject packets with unrealistic window sizes
	// uTP window size is in bytes, typically 1-10 MB for BitTorrent
	// VoIP protocols (Zoom, etc.) often have values > 1 billion (garbage data)
	// Real maximum: 100MB is generous upper bound (most use 1-10MB)
	maxWindowSize := uint32(100 * 1024 * 1024) // 100MB
	if windowSize > maxWindowSize {
		return false // Unrealistically large window size, not uTP
	}

	// CRITICAL: Reject WireGuard handshake initiation packets
	// WireGuard format: 0x01 (message type) + 0x00 0x00 0x00 (reserved) + encrypted data
	// This looks like uTP: version=1, type=0 (DATA), extension=0
	// Distinguish by checking if bytes 1-3 are all zeros (reserved field in WireGuard)
	// Real uTP DATA packets (type=0) would have extension field at byte 1, not 0x00
	if typ == 0 && len(packet) >= 4 {
		if packet[1] == 0x00 && packet[2] == 0x00 && packet[3] == 0x00 {
			return false // This is WireGuard handshake, not uTP
		}
	}

	// CRITICAL: Reject VoIP/messaging/discovery protocols with unusual timestamp_diff
	// These protocols can have uTP-like headers but have distinctive patterns in timestamp_diff field:
	// uTP header: 0-1: ver/type/ext, 2-3: conn_id, 4-7: timestamp, 8-11: timestamp_diff
	// - Telegram: timestamp_diff often 0x00008000, 0x80000000 (symmetric padding)
	// - WhatsApp: timestamp_diff often 0x00050000, 0x00090000 (small counters with zero padding)
	// - Alexa: timestamp_diff often 0x00000000 (all zeros)
	// - Zoom: timestamp_diff often 0x00000000 (all zeros, even in smaller packets)
	// - Ubiquiti: timestamp_diff often > 1 billion (unrealistically large)
	// Real uTP timestamp_diff values are microsecond deltas, typically < 60 seconds
	// Check DATA packets (type=0 or 1) - Skip ST_SYN (type=4) which initializes connections
	if typ == 0 || typ == 1 {
		timestampDiff := packet[8:12]
		timestampDiffValue := binary.BigEndian.Uint32(timestampDiff)

		// Check for zero-heavy patterns (VoIP)
		zeroCount := 0
		for _, b := range timestampDiff {
			if b == 0 {
				zeroCount++
			}
		}
		// For large packets (>=200 bytes): 3+ zeros indicates VoIP
		// For smaller packets (>=100 bytes): all 4 zeros indicates VoIP (more strict to avoid false negatives)
		if len(packet) >= 200 && zeroCount >= 3 {
			return false // VoIP/messaging protocol, not uTP
		}
		if len(packet) >= 100 && zeroCount == 4 {
			return false // VoIP with all-zero timestamp_diff (Zoom, Alexa)
		}

		// CRITICAL: Reject packets with unrealistically large timestamp_diff
		// Real uTP timestamp_diff is microseconds since last packet
		// Discovery protocols (Ubiquiti, etc.) often have values > 2 billion microseconds
		// 2 billion microseconds = 2000 seconds = ~33 minutes
		// Real BitTorrent can have timestamp_diff up to ~1.5 billion in legitimate cases
		// Set threshold at 2 billion to allow real traffic while catching bogus discovery protocols
		if timestampDiffValue > 2000000000 {
			return false // Unrealistically large timestamp_diff, not uTP
		}
	}

	extension := packet[1]

	// CRITICAL: Validate initial extension field (must be 0-4 according to BEP 29)
	// Gaming protocols (Toca Boca, etc.) often have invalid extension values > 4
	// Valid extensions: 0=None, 1=SACK, 2=Extension bits, 3-4=Reserved
	if extension > 4 {
		return false // Invalid extension type, not uTP
	}

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
		bytes.Contains(payload, []byte("User-Agent: FlashGet")) {
		return true
	}

	// CRITICAL: Shareaza signature detection with Gnutella exclusion
	// Shareaza is both a Gnutella and BitTorrent client
	// Gnutella handshakes contain "GNUTELLA/" header - exclude these to prevent false positives
	// Example Gnutella: "GNUTELLA/0.6 200 OK\r\nUser-Agent: Shareaza..."
	// Example BitTorrent: "GET /announce?info_hash=...\r\nUser-Agent: Shareaza..."
	if bytes.Contains(payload, []byte("User-Agent: Shareaza")) {
		// Reject if this is a Gnutella handshake (contains "GNUTELLA/" protocol marker)
		if bytes.Contains(payload, []byte("GNUTELLA/")) {
			return false // This is Gnutella, not BitTorrent
		}
		return true // Shareaza without Gnutella marker = likely BitTorrent
	}

	return false
}

// CheckBitTorrentMessage detects BitTorrent TCP messages by structure
// BitTorrent message format: [length:4 bytes (big-endian)][message ID:1 byte][payload]
// This detects data transfer messages after the handshake
func CheckBitTorrentMessage(payload []byte) bool {
	// Need at least 5 bytes for a valid message
	if len(payload) < 5 {
		return false
	}

	// CRITICAL: Reject SSH protocol messages
	// SSH also uses length-prefixed messages: [length:4][type:1][payload]
	// SSH types: 1-49 for transport layer, 50-79 for authentication, 80-127 for connection
	// BitTorrent types: 0-9, 13-17, 20 (0x14), 21-23 (0x15-0x17)
	msgID := payload[4]

	// SSH user auth (50-79) and connection (80-127) - no overlap with BitTorrent
	if msgID >= 50 {
		return false // SSH range, not BitTorrent
	}

	// SSH transport layer (21-49): KEX, NEWKEYS, etc.
	// BitTorrent v2 hash messages are 21-23 (0x15-0x17)
	// To avoid false positives, only accept 21-23 in this range
	if msgID >= 21 && msgID <= 49 {
		if msgID > 23 {
			return false // SSH, not BitTorrent
		}
		// 21-23 could be BT v2, continue validation
	}

	// Parse message length (first 4 bytes, big-endian)
	msgLen := binary.BigEndian.Uint32(payload[0:4])

	// Message length validation
	// - Must be at least 1 (for message ID)
	// - Should not be unrealistically large (> 128KB for most messages, except piece messages)
	// - Piece messages can be up to 16KB + 9 bytes overhead = ~16400 bytes
	// - Extension messages can be larger, but let's cap at 256KB to avoid false positives
	if msgLen == 0 || msgLen > 262144 { // 256KB max
		return false
	}

	// Check if the full message fits in the payload
	// (may not fit due to TCP segmentation, but if it's too far off, it's suspicious)
	expectedLen := int(msgLen) + 4     // +4 for length prefix
	if expectedLen > len(payload)*10 { // If expected is >10x actual, likely not BitTorrent
		return false
	}

	// Valid BitTorrent message IDs (from BEP 3, BEP 5, BEP 10)
	// 0x00-0x09: Core protocol (choke, unchoke, interested, have, bitfield, request, piece, cancel, port)
	// 0x0D-0x11: Fast extension (BEP 6)
	// 0x14: Extended protocol (BEP 10)
	// 0x15: Hash request (BEP 52)
	// 0x16: Hashes (BEP 52)
	// 0x17: Hash reject (BEP 52)

	switch msgID {
	case 0x00, 0x01, 0x02, 0x03: // Choke, Unchoke, Interested, Not Interested
		// These should have length = 1 (just the ID, no payload)
		return msgLen == 1

	case 0x04: // Have
		// Length should be 5 (1 byte ID + 4 bytes piece index)
		return msgLen == 5

	case 0x05: // Bitfield (BitTorrent) vs other protocols (SSH, MSDO)
		// BitTorrent: Length = 1 + (number of pieces / 8), typically reasonable size
		// Most torrents have < 10000 pieces, so bitfield < 1250 bytes
		// Large torrents might have up to 100000 pieces = ~12500 bytes
		if msgLen <= 1 || msgLen > 65536 {
			return false
		}

		// CRITICAL: Message type 0x05 collides with multiple protocols:
		// - SSH_MSG_SERVICE_REQUEST (type 5)
		// - Microsoft Download Optimizer (MSDO) control messages
		// - Other proprietary protocols
		//
		// For VERY SHORT bitfield messages (< 20 bytes), be more conservative
		// Real BitTorrent bitfields this short would represent <160 pieces (very small torrent)
		// Such small torrents are rare, and short 0x05 messages are more likely protocol control
		if msgLen < 20 {
			// For short "bitfield" messages, check if this looks like a realistic small torrent
			// A 9-byte bitfield (8 bytes data) = 64 pieces = ~1GB file (assuming 16MB pieces)
			// However, most BitTorrent clients use adaptive piece sizes, and small files
			// (<1GB) typically use smaller pieces, so we'd see more bytes in the bitfield
			//
			// Additionally, check for suspicious patterns that indicate protocol messages:
			// MSDO example: 00 00 0f ff ff e0 00 03 - has pattern of aligned nibbles/fields
			// BitTorrent: More random distribution of set bits
			//
			// Simple heuristic: if length is suspiciously round (8, 9, 10, 12, 16 bytes)
			// AND we see field-like patterns (e.g., 0xFF or 0x00 in specific positions),
			// it's more likely a protocol message than a bitfield
			if msgLen >= 8 && msgLen <= 12 {
				// Check if payload has protocol-like structure (repeated patterns)
				if len(payload) >= 9 {
					data := payload[5:] // Bitfield data
					// Check for field alignment indicators: runs of 0xFF or 0x00
					// that suggest structured fields rather than random bitmap
					ffCount := 0
					zeroCount := 0
					for _, b := range data {
						if b == 0xFF {
							ffCount++
						} else if b == 0x00 {
							zeroCount++
						}
					}
					// If >60% of bytes are 0xFF or 0x00, suspicious for this size
					totalFieldBytes := ffCount + zeroCount
					if totalFieldBytes >= len(data)*6/10 {
						return false // Likely protocol message, not BitTorrent
					}
				}
			}
		}

		// For larger messages, use statistical analysis to distinguish encrypted SSH
		// CRITICAL: Distinguish from SSH encrypted packets (type 5 collision)
		// At this stage of SSH connection, packets are encrypted, so we can't inspect structure
		// However, we can use statistical properties:
		//
		// BitTorrent bitfield characteristics:
		// - BITMAP: each byte represents 8 pieces (bits)
		// - Often has patterns: 0x00 (no pieces), 0xFF (all pieces), or sparse patterns
		// - For partial downloads: many 0x00 bytes, some mixed bytes
		// - For seeds: all 0xFF bytes
		// - Typically NOT uniformly distributed random-looking data
		//
		// SSH encrypted characteristics:
		// - Encrypted with AES/ChaCha20: looks like uniformly random data
		// - High entropy throughout
		// - No obvious patterns of repeated bytes
		//
		// Heuristic: Check if payload looks like random encrypted data vs. bitmap
		// Lowered threshold from 100 to 40 to catch SSH encrypted packets
		if len(payload) >= 20 && msgLen > 40 {
			// For messages >40 bytes, check first 16 bytes of payload
			sample := payload[5:21] // Skip msgID, sample 16 bytes

			// Count unique byte values and repeated bytes
			uniqueBytes := make(map[byte]bool)
			repeatedCount := 0
			prevByte := sample[0]

			for _, b := range sample {
				uniqueBytes[b] = true
				if b == prevByte {
					repeatedCount++
				}
				prevByte = b
			}

			// BitTorrent bitfield: typically has many repeated bytes (0x00 or 0xFF runs)
			// SSH encrypted: typically has high unique byte count, few repeats
			// If we see >12 unique bytes out of 16 AND few repeats, likely encrypted SSH
			if len(uniqueBytes) >= 13 && repeatedCount <= 4 {
				return false // Likely encrypted SSH, not BitTorrent bitmap
			}
		}

		return true

	case 0x06: // Request
		// Length should be 13 (1 + 4 + 4 + 4: ID + index + begin + length)
		return msgLen == 13

	case 0x07: // Piece (BitTorrent) vs SSH key exchange (type 7)
		// BitTorrent Piece: Length = 9 + block_length (typically 16384 bytes)
		// Structure: [msgID:1][index:4][begin:4][block data]
		// Check reasonable range: 9 < length <= 16393
		if msgLen <= 9 || msgLen > 16393 {
			return false
		}

		// CRITICAL: SSH also uses type 7 for key exchange messages (SSH_MSG_KEXDH_INIT)
		// SSH key exchange contains algorithm names as ASCII strings
		// BitTorrent piece messages contain binary file data
		//
		// Heuristic: Check if payload contains readable ASCII text (suggests SSH)
		// BitTorrent piece data is typically binary (media files, executables, etc.)
		// SSH key exchange has comma-separated algorithm lists like:
		// "diffie-hellman-group-exchange-sha1,diffie-hellman-group14-sha1,..."
		if len(payload) >= 50 {
			// Sample 40 bytes after the header (skip msgID + index + begin = 9 bytes)
			sampleStart := 13 // Skip length(4) + msgID(1) + index(4) + begin(4)
			if sampleStart+40 <= len(payload) {
				sample := payload[sampleStart : sampleStart+40]

				// Count ASCII printable characters (0x20-0x7E, excluding DEL)
				printableCount := 0
				commaCount := 0
				for _, b := range sample {
					if b >= 0x20 && b <= 0x7E {
						printableCount++
						if b == ',' || b == '-' {
							commaCount++
						}
					}
				}

				// If >75% of sample is printable ASCII with commas/hyphens, likely SSH
				// BitTorrent piece data would have much lower printable ratio
				if printableCount >= 30 && commaCount >= 3 {
					return false // Likely SSH key exchange, not BitTorrent
				}
			}
		}

		return true

	case 0x08: // Cancel
		// Length should be 13 (same as Request)
		return msgLen == 13

	case 0x09: // Port (DHT)
		// Length should be 3 (1 byte ID + 2 bytes port)
		return msgLen == 3

	case 0x0D: // Suggest Piece (BEP 6)
		// Length should be 5 (1 + 4)
		return msgLen == 5

	case 0x0E, 0x0F: // Have All, Have None (BEP 6)
		// Length should be 1
		return msgLen == 1

	case 0x10: // Reject Request (BEP 6)
		// Length should be 13
		return msgLen == 13

	case 0x11: // Allowed Fast (BEP 6)
		// Length should be 5
		return msgLen == 5

	case 0x14: // Extended (BEP 10)
		// Length > 1 (has extended message ID), check for bencode or known patterns
		if msgLen <= 1 {
			return false
		}

		// Extended handshake (ID=0) or extension message (ID>0)
		// Extended messages often contain bencode dictionaries
		if len(payload) >= 6 {
			extID := payload[5]

			// Extended handshake (extID=0) must have bencode dictionary
			if extID == 0 {
				// Check for bencode dictionary start 'd'
				if len(payload) > 6 && payload[6] == 'd' {
					return true
				}
			} else {
				// Extension message - just validate it's reasonable
				return msgLen > 2 && msgLen < 131072 // < 128KB
			}
		}
		return msgLen > 1 && msgLen < 131072

	case 0x15, 0x16, 0x17: // Hash request, Hashes, Hash reject (BEP 52)
		// These are part of the v2 hash tree protocol
		// Lengths vary, but should be reasonable
		return msgLen > 1 && msgLen < 131072

	default:
		// Unknown message ID - not a standard BitTorrent message
		return false
	}
}
