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
	//
	// OPTIMIZATION Phase 2: Split UDP/TCP into separate fast paths
	// Benefits: Better branch prediction, fewer conditionals, more cache-friendly

	if isUDP {
		// === UDP FAST PATH ===
		// 1. LSD Detection (1.13 ns/op) - very fast and specific
		if destIP != "" && CheckLSD(processingPayload, destIP, destPort) {
			return AnalysisResult{
				ShouldBlock: true,
				Reason:      "Local Service Discovery (BEP 14)",
			}
		}

		// 2. uTP Protocol (1.89 ns/op) - fast, common for UDP
		if CheckUTPRobust(processingPayload) {
			return AnalysisResult{
				ShouldBlock: true,
				Reason:      "uTP Protocol (BEP 29)",
			}
		}

		// 3. DHT Bencode (2.81 ns/op) - fast, very common for DHT
		if CheckBencodeDHT(processingPayload) {
			return AnalysisResult{
				ShouldBlock: true,
				Reason:      "DHT Bencode Structure (BEP 5)",
			}
		}

		// 4. UDP Tracker (3.73 ns/op) - fast tracker detection
		if CheckUDPTrackerDeep(processingPayload) {
			return AnalysisResult{
				ShouldBlock: true,
				Reason:      "UDP Tracker Protocol",
			}
		}

		// 5. Signature check (catches remaining UDP patterns)
		if CheckSignatures(processingPayload) {
			return AnalysisResult{
				ShouldBlock: true,
				Reason:      "BitTorrent Signature",
			}
		}

		return AnalysisResult{ShouldBlock: false}
	}

	// === TCP FAST PATH ===
	// 1. FAST Extension (0.38 ns/op) - extremely fast
	if CheckFASTExtension(processingPayload) {
		return AnalysisResult{
			ShouldBlock: true,
			Reason:      "FAST Extension Message (BEP 6)",
		}
	}

	// 2. BitTorrent TCP message structure (1.25 ns/op) - HIGH HIT RATE (34%)
	if CheckBitTorrentMessage(processingPayload) {
		return AnalysisResult{
			ShouldBlock: true,
			Reason:      "BitTorrent Message Structure",
		}
	}

	// 3. DHT Bencode (2.81 ns/op) - DHT can be over TCP too
	if CheckBencodeDHT(processingPayload) {
		return AnalysisResult{
			ShouldBlock: true,
			Reason:      "DHT Bencode Structure (BEP 5)",
		}
	}

	// 4. HTTP-based BitTorrent (7.17 ns/op) - WebSeed, User-Agents
	if CheckHTTPBitTorrent(processingPayload) {
		return AnalysisResult{
			ShouldBlock: true,
			Reason:      "HTTP BitTorrent Protocol (BEP 19)",
		}
	}

	// 5. Signature analysis (optimized) - catches common TCP patterns
	if CheckSignatures(processingPayload) {
		return AnalysisResult{
			ShouldBlock: true,
			Reason:      "BitTorrent Signature",
		}
	}

	// 6. MSE/PE Encryption (899 ns/op) - expensive, check last
	if CheckMSEEncryption(processingPayload) {
		return AnalysisResult{
			ShouldBlock: true,
			Reason:      "MSE/PE Encryption",
		}
	}

	// 7. SOCKS proxy (optional, disabled by default)
	if a.config.BlockSOCKS && CheckSOCKSConnection(processingPayload) {
		return AnalysisResult{
			ShouldBlock: true,
			Reason:      "SOCKS Proxy Connection",
		}
	}

	return AnalysisResult{ShouldBlock: false}
}
