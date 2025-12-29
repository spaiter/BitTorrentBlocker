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

	// --- DPI ANALYZERS (Ordered by specificity and performance) ---

	// 1. LSD Detection (very specific, requires dest info)
	if isUDP && destIP != "" && CheckLSD(processingPayload, destIP, destPort) {
		return AnalysisResult{
			ShouldBlock: true,
			Reason:      "Local Service Discovery",
		}
	}

	// 2. MSE/PE Encryption Detection (CRITICAL - catches encrypted traffic)
	if CheckMSEEncryption(processingPayload) {
		return AnalysisResult{
			ShouldBlock: true,
			Reason:      "MSE/PE Encryption",
		}
	}

	// 3. Extended Protocol Detection (BEP 10)
	if !isUDP && CheckExtendedMessage(processingPayload) {
		return AnalysisResult{
			ShouldBlock: true,
			Reason:      "Extended Protocol Message",
		}
	}

	// 4. FAST Extension Detection (BEP 6)
	if !isUDP && CheckFASTExtension(processingPayload) {
		return AnalysisResult{
			ShouldBlock: true,
			Reason:      "FAST Extension Message",
		}
	}

	// 5. Block SOCKS proxy connections (nDPI logic)
	if CheckSOCKSConnection(processingPayload) {
		return AnalysisResult{
			ShouldBlock: true,
			Reason:      "SOCKS Proxy Connection",
		}
	}

	// 6. Deep UDP Tracker analysis (libtorrent logic)
	if isUDP && CheckUDPTrackerDeep(processingPayload) {
		return AnalysisResult{
			ShouldBlock: true,
			Reason:      "UDP Tracker Protocol",
		}
	}

	// 7. Signature analysis (PEX, DHT Keys, Handshakes, Extensions)
	if CheckSignatures(processingPayload) {
		return AnalysisResult{
			ShouldBlock: true,
			Reason:      "BitTorrent Signature",
		}
	}

	// 8. uTP Protocol Analysis (Sing-box logic)
	if isUDP && CheckUTPRobust(processingPayload) {
		return AnalysisResult{
			ShouldBlock: true,
			Reason:      "uTP Protocol",
		}
	}

	// 9. Structural DHT analysis (Suricata logic)
	if CheckBencodeDHT(processingPayload) {
		return AnalysisResult{
			ShouldBlock: true,
			Reason:      "DHT Bencode Structure",
		}
	}

	// 10. Entropy check (for fully encrypted traffic - last resort)
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
