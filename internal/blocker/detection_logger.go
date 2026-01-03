package blocker

import (
	"encoding/hex"
	"fmt"
	"os"
	"sync"
	"time"
)

// DetectionLogger logs detailed packet information for detected BitTorrent traffic
// This helps analyze false positives and improve detection algorithms
type DetectionLogger struct {
	file   *os.File
	mu     sync.Mutex
	active bool
}

// NewDetectionLogger creates a new detection logger
// If logPath is empty, detection logging is disabled
func NewDetectionLogger(logPath string) (*DetectionLogger, error) {
	if logPath == "" {
		return &DetectionLogger{active: false}, nil
	}

	file, err := os.OpenFile(logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return nil, fmt.Errorf("failed to open detection log file: %w", err)
	}

	return &DetectionLogger{
		file:   file,
		active: true,
	}, nil
}

// LogDetection logs detailed information about a detected packet
func (dl *DetectionLogger) LogDetection(
	timestamp time.Time,
	iface string,
	protocol string,
	srcIP string,
	srcPort uint16,
	dstIP string,
	dstPort uint16,
	reason string,
	payload []byte,
) {
	if !dl.active {
		return
	}

	dl.mu.Lock()
	defer dl.mu.Unlock()

	// Limit payload to first 512 bytes to keep logs manageable
	maxPayloadLen := 512
	payloadToLog := payload
	truncated := false
	if len(payload) > maxPayloadLen {
		payloadToLog = payload[:maxPayloadLen]
		truncated = true
	}

	// Write log entry
	fmt.Fprintf(dl.file, "================================================================================\n")
	fmt.Fprintf(dl.file, "Timestamp:    %s\n", timestamp.Format("2006-01-02 15:04:05.000"))
	fmt.Fprintf(dl.file, "Interface:    %s\n", iface)
	fmt.Fprintf(dl.file, "Protocol:     %s\n", protocol)
	fmt.Fprintf(dl.file, "Source:       %s:%d\n", srcIP, srcPort)
	fmt.Fprintf(dl.file, "Destination:  %s:%d\n", dstIP, dstPort)
	fmt.Fprintf(dl.file, "Detection:    %s\n", reason)
	fmt.Fprintf(dl.file, "Payload Size: %d bytes", len(payload))
	if truncated {
		fmt.Fprintf(dl.file, " (showing first %d bytes)\n", maxPayloadLen)
	} else {
		fmt.Fprintf(dl.file, "\n")
	}
	fmt.Fprintf(dl.file, "\n")

	// Write hex dump
	fmt.Fprintf(dl.file, "Hex Dump:\n")
	fmt.Fprintf(dl.file, "%s\n", hexDump(payloadToLog))
	fmt.Fprintf(dl.file, "\n")

	// Write ASCII representation (printable characters only)
	fmt.Fprintf(dl.file, "ASCII (printable only):\n")
	fmt.Fprintf(dl.file, "%s\n", asciiDump(payloadToLog))
	fmt.Fprintf(dl.file, "\n")
}

// Close closes the detection log file
func (dl *DetectionLogger) Close() error {
	if !dl.active || dl.file == nil {
		return nil
	}

	// Close the file and set it to nil to prevent double-close
	err := dl.file.Close()
	dl.file = nil
	dl.active = false
	return err
}

// hexDump creates a formatted hex dump similar to hexdump -C
func hexDump(data []byte) string {
	if len(data) == 0 {
		return "(empty)"
	}

	var result string
	for i := 0; i < len(data); i += 16 {
		// Offset
		result += fmt.Sprintf("%08x  ", i)

		// Hex bytes (two groups of 8)
		for j := 0; j < 16; j++ {
			if i+j < len(data) {
				result += fmt.Sprintf("%02x ", data[i+j])
			} else {
				result += "   "
			}
			if j == 7 {
				result += " "
			}
		}

		// ASCII representation
		result += " |"
		for j := 0; j < 16 && i+j < len(data); j++ {
			b := data[i+j]
			if b >= 32 && b <= 126 {
				result += string(b)
			} else {
				result += "."
			}
		}
		result += "|\n"
	}

	return result
}

// asciiDump extracts printable ASCII characters from the payload
func asciiDump(data []byte) string {
	if len(data) == 0 {
		return "(empty)"
	}

	var result []byte
	for _, b := range data {
		if b >= 32 && b <= 126 {
			result = append(result, b)
		} else if b == '\n' || b == '\r' || b == '\t' {
			result = append(result, b)
		} else {
			result = append(result, '.')
		}
	}

	str := string(result)
	if str == "" {
		return "(no printable characters)"
	}
	return str
}

// hexEncode returns hex-encoded string (for compact representation)
func hexEncode(data []byte) string {
	return hex.EncodeToString(data)
}
