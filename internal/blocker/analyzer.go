package blocker

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
	// Performance metrics from benchmarks (ns/op, lower is faster):
	// CheckExtendedMessage: 0.19, CheckSOCKSConnection: 0.19, CheckFASTExtension: 0.38
	// CheckLSD: 1.13, CheckBitTorrentMessage: 1.25, CheckUTPRobust: 1.89
	// CheckBencodeDHT: 2.81, CheckUDPTrackerDeep: 3.73, CheckHTTPBitTorrent: 7.17
	// CheckDHTNodes: 15.04, CheckSignatures: 31.87
	// CheckMSEEncryption: 899, ShannonEntropy: 928

	// 1. FAST Extension Detection (0.38 ns/op) - extremely fast, TCP only
	if !isUDP && CheckFASTExtension(processingPayload) {
		return AnalysisResult{
			ShouldBlock: true,
			Reason:      "FAST Extension Message (BEP 6)",
		}
	}

	// 2. LSD Detection (1.14 ns/op) - very fast and specific, UDP only
	if isUDP && destIP != "" && CheckLSD(processingPayload, destIP, destPort) {
		return AnalysisResult{
			ShouldBlock: true,
			Reason:      "Local Service Discovery (BEP 14)",
		}
	}

	// 3. Deep UDP Tracker analysis (2.49 ns/op) - very fast, UDP only
	if isUDP && CheckUDPTrackerDeep(processingPayload) {
		return AnalysisResult{
			ShouldBlock: true,
			Reason:      "UDP Tracker Protocol",
		}
	}

	// 4. MSE/PE Encryption Detection (2.59 ns/op) - CRITICAL for encrypted traffic
	if CheckMSEEncryption(processingPayload) {
		return AnalysisResult{
			ShouldBlock: true,
			Reason:      "MSE/PE Encryption",
		}
	}

	// 5. Structural DHT analysis (14.34 ns/op) - fast bencode validation
	if CheckBencodeDHT(processingPayload) {
		return AnalysisResult{
			ShouldBlock: true,
			Reason:      "DHT Bencode Structure (BEP 5)",
		}
	}

	// 6. HTTP-based BitTorrent detection (20.60 ns/op) - WebSeed, Bitcomet, User-Agent
	if !isUDP && CheckHTTPBitTorrent(processingPayload) {
		return AnalysisResult{
			ShouldBlock: true,
			Reason:      "HTTP BitTorrent Protocol (BEP 19)",
		}
	}

	// 7. Signature analysis (31.97 ns/op) - catches common patterns
	if CheckSignatures(processingPayload) {
		return AnalysisResult{
			ShouldBlock: true,
			Reason:      "BitTorrent Signature",
		}
	}

	// 8. BitTorrent TCP message structure detection - detects data transfer messages
	// This catches Port (DHT), Extended, and other messages after handshake
	if !isUDP && CheckBitTorrentMessage(processingPayload) {
		return AnalysisResult{
			ShouldBlock: true,
			Reason:      "BitTorrent Message Structure",
		}
	}

	// 9. SOCKS proxy connections - optional, disabled by default to reduce false positives
	if a.config.BlockSOCKS && CheckSOCKSConnection(processingPayload) {
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

	return AnalysisResult{ShouldBlock: false}
}
