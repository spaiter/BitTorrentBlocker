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
