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

	// --- DPI ANALYZERS ---

	// 1. Block SOCKS proxy connections (nDPI logic)
	if CheckSOCKSConnection(processingPayload) {
		return AnalysisResult{
			ShouldBlock: true,
			Reason:      "SOCKS Proxy Connection",
		}
	}

	// 2. Deep UDP Tracker analysis (libtorrent logic)
	if isUDP && CheckUDPTrackerDeep(processingPayload) {
		return AnalysisResult{
			ShouldBlock: true,
			Reason:      "UDP Tracker Protocol",
		}
	}

	// 3. Signature analysis (PEX, DHT Keys, Handshakes)
	if CheckSignatures(processingPayload) {
		return AnalysisResult{
			ShouldBlock: true,
			Reason:      "BitTorrent Signature/PEX",
		}
	}

	// 4. uTP Protocol Analysis (Sing-box logic)
	if isUDP && CheckUTPRobust(processingPayload) {
		return AnalysisResult{
			ShouldBlock: true,
			Reason:      "uTP Protocol",
		}
	}

	// 5. Structural DHT analysis (Suricata logic)
	if CheckBencodeDHT(processingPayload) {
		return AnalysisResult{
			ShouldBlock: true,
			Reason:      "DHT Bencode Structure",
		}
	}

	// 6. Entropy check (for fully encrypted traffic)
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
