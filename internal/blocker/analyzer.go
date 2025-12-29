package blocker

import "fmt"

// AnalysisResult contains the result of packet analysis
type AnalysisResult struct {
	ShouldBlock bool
	Reason      string
}

// Analyzer performs deep packet inspection for BitTorrent traffic
type Analyzer struct {
	config Config
}

// NewAnalyzer creates a new packet analyzer with the given configuration
func NewAnalyzer(config Config) *Analyzer {
	return &Analyzer{
		config: config,
	}
}

// AnalyzePacket performs comprehensive DPI analysis on a packet
// Returns whether the packet should be blocked and the reason
func (a *Analyzer) AnalyzePacket(payload []byte, isUDP bool) AnalysisResult {
	return a.AnalyzePacketEx(payload, isUDP, "", 0)
}

// AnalyzePacketEx performs comprehensive DPI analysis with destination info
// destIP and destPort are used for LSD detection
func (a *Analyzer) AnalyzePacketEx(payload []byte, isUDP bool, destIP string, destPort uint16) AnalysisResult {
	if len(payload) == 0 {
		return AnalysisResult{ShouldBlock: false}
	}

	// Preprocessing: unwrap SOCKS5 if present
	processingPayload := payload
	if isUDP {
		if unwrapped, ok := UnwrapSOCKS5(payload); ok {
			processingPayload = unwrapped
		}
	}

	// --- DPI ANALYZERS (Ordered by performance: fastest first) ---
	// Performance metrics from benchmarks (lower is faster):
	// CheckExtendedMessage: 0.19 ns/op, CheckFASTExtension: 0.38 ns/op
	// CheckLSD: 1.14 ns/op, CheckUDPTrackerDeep: 2.49 ns/op
	// CheckMSEEncryption: 2.59 ns/op, CheckBencodeDHT: 14.34 ns/op
	// CheckHTTPBitTorrent: 20.60 ns/op, CheckSignatures: 31.97 ns/op
	// ShannonEntropy: 925.4 ns/op

	// 1. Extended Protocol Detection (0.19 ns/op) - extremely fast, TCP only
	if !isUDP && CheckExtendedMessage(processingPayload) {
		return AnalysisResult{
			ShouldBlock: true,
			Reason:      "Extended Protocol Message (BEP 10)",
		}
	}

	// 2. FAST Extension Detection (0.38 ns/op) - extremely fast, TCP only
	if !isUDP && CheckFASTExtension(processingPayload) {
		return AnalysisResult{
			ShouldBlock: true,
			Reason:      "FAST Extension Message (BEP 6)",
		}
	}

	// 3. LSD Detection (1.14 ns/op) - very fast and specific, UDP only
	if isUDP && destIP != "" && CheckLSD(processingPayload, destIP, destPort) {
		return AnalysisResult{
			ShouldBlock: true,
			Reason:      "Local Service Discovery (BEP 14)",
		}
	}

	// 4. Deep UDP Tracker analysis (2.49 ns/op) - very fast, UDP only
	if isUDP && CheckUDPTrackerDeep(processingPayload) {
		return AnalysisResult{
			ShouldBlock: true,
			Reason:      "UDP Tracker Protocol",
		}
	}

	// 5. MSE/PE Encryption Detection (2.59 ns/op) - CRITICAL for encrypted traffic
	if CheckMSEEncryption(processingPayload) {
		return AnalysisResult{
			ShouldBlock: true,
			Reason:      "MSE/PE Encryption",
		}
	}

	// 6. Structural DHT analysis (14.34 ns/op) - fast bencode validation
	if CheckBencodeDHT(processingPayload) {
		return AnalysisResult{
			ShouldBlock: true,
			Reason:      "DHT Bencode Structure (BEP 5)",
		}
	}

	// 7. HTTP-based BitTorrent detection (20.60 ns/op) - WebSeed, Bitcomet, User-Agent
	if !isUDP && CheckHTTPBitTorrent(processingPayload) {
		return AnalysisResult{
			ShouldBlock: true,
			Reason:      "HTTP BitTorrent Protocol (BEP 19)",
		}
	}

	// 8. Signature analysis (31.97 ns/op) - catches common patterns
	if CheckSignatures(processingPayload) {
		return AnalysisResult{
			ShouldBlock: true,
			Reason:      "BitTorrent Signature",
		}
	}

	// 9. SOCKS proxy connections - blocks proxy tunneling
	if CheckSOCKSConnection(processingPayload) {
		return AnalysisResult{
			ShouldBlock: true,
			Reason:      "SOCKS Proxy Connection",
		}
	}

	// 10. uTP Protocol Analysis - UDP transport protocol
	if isUDP && CheckUTPRobust(processingPayload) {
		return AnalysisResult{
			ShouldBlock: true,
			Reason:      "uTP Protocol (BEP 29)",
		}
	}

	// 11. Entropy check (for fully encrypted traffic - last resort)
	if len(processingPayload) > a.config.MinPayloadSize {
		entropy := ShannonEntropy(processingPayload)
		if entropy > a.config.EntropyThreshold {
			return AnalysisResult{
				ShouldBlock: true,
				Reason:      fmt.Sprintf("High Entropy (%.2f)", entropy),
			}
		}
	}

	return AnalysisResult{ShouldBlock: false}
}
