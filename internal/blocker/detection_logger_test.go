package blocker

import (
	"os"
	"strings"
	"testing"
	"time"
)

func TestNewDetectionLogger(t *testing.T) {
	tests := []struct {
		name         string
		logPath      string
		expectError  bool
		expectActive bool
	}{
		{
			name:         "Empty path - disabled",
			logPath:      "",
			expectError:  false,
			expectActive: false,
		},
		{
			name:         "Valid path - enabled",
			logPath:      "test_detection.log",
			expectError:  false,
			expectActive: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Clean up any existing test file
			if tt.logPath != "" {
				defer os.Remove(tt.logPath)
			}

			logger, err := NewDetectionLogger(tt.logPath)
			if tt.expectError && err == nil {
				t.Errorf("Expected error but got none")
			}
			if !tt.expectError && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
			if logger == nil {
				t.Fatal("Logger should not be nil")
			}
			if logger.active != tt.expectActive {
				t.Errorf("Expected active=%v, got %v", tt.expectActive, logger.active)
			}

			// Clean up
			if logger != nil {
				logger.Close()
			}
		})
	}
}

func TestDetectionLogger_LogDetection(t *testing.T) {
	logPath := "test_detection_log.log"
	defer os.Remove(logPath)

	logger, err := NewDetectionLogger(logPath)
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}
	defer logger.Close()

	// Create test payload
	payload := []byte{
		0x00, 0x00, 0x04, 0x17, 0x27, 0x10, 0x19, 0x80,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
		0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0,
		'H', 'e', 'l', 'l', 'o', ' ', 'W', 'o',
		'r', 'l', 'd', '!', 0x00, 0xff, 0xaa, 0xbb,
	}

	timestamp := time.Date(2024, 1, 15, 18, 46, 57, 123000000, time.UTC)

	// Log detection
	logger.LogDetection(
		timestamp,
		"eth0",
		"TCP",
		"192.168.1.100",
		51234,
		"8.8.8.8",
		6881,
		"UDP Tracker Protocol",
		payload,
	)

	// Read log file
	content, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("Failed to read log file: %v", err)
	}

	logContent := string(content)

	// Verify log contains expected information
	expectedStrings := []string{
		"Timestamp:",
		"2024-01-15 18:46:57.123",
		"Interface:    eth0",
		"Protocol:     TCP",
		"Source:       192.168.1.100:51234",
		"Destination:  8.8.8.8:6881",
		"Detection:    UDP Tracker Protocol",
		"Payload Size:",
		"Hex Dump:",
		"00000000",
		"ASCII (printable only):",
		"Hello World",
	}

	for _, expected := range expectedStrings {
		if !strings.Contains(logContent, expected) {
			t.Errorf("Log content missing expected string: %q\nLog content:\n%s", expected, logContent)
		}
	}

	// Verify separator line is present
	if !strings.Contains(logContent, "================================================================================") {
		t.Error("Log content missing separator line")
	}
}

func TestDetectionLogger_LogDetection_LargePayload(t *testing.T) {
	logPath := "test_large_payload.log"
	defer os.Remove(logPath)

	logger, err := NewDetectionLogger(logPath)
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}
	defer logger.Close()

	// Create large payload (1024 bytes)
	payload := make([]byte, 1024)
	for i := range payload {
		payload[i] = byte(i % 256)
	}

	timestamp := time.Now()

	// Log detection
	logger.LogDetection(
		timestamp,
		"eth0",
		"UDP",
		"192.168.1.100",
		12345,
		"10.0.0.1",
		6881,
		"Test Detection",
		payload,
	)

	// Read log file
	content, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("Failed to read log file: %v", err)
	}

	logContent := string(content)

	// Verify payload was truncated
	if !strings.Contains(logContent, "Payload Size: 1024 bytes (showing first 512 bytes)") {
		t.Error("Log should indicate truncation for large payload")
	}

	// Verify hex dump doesn't contain all data
	// Hex dump for 512 bytes would end around offset 0x000001f0
	if strings.Contains(logContent, "00000400") {
		t.Error("Hex dump should not contain data beyond 512 bytes (offset 0x200)")
	}
}

func TestDetectionLogger_Disabled(t *testing.T) {
	// Create disabled logger
	logger, err := NewDetectionLogger("")
	if err != nil {
		t.Fatalf("Failed to create disabled logger: %v", err)
	}
	defer logger.Close()

	// Verify it's inactive
	if logger.active {
		t.Error("Logger should be inactive when created with empty path")
	}

	// Call LogDetection - should not panic
	logger.LogDetection(
		time.Now(),
		"eth0",
		"TCP",
		"192.168.1.1",
		1234,
		"8.8.8.8",
		80,
		"Test",
		[]byte("test"),
	)

	// No file should be created
	if logger.file != nil {
		t.Error("Disabled logger should not have a file handle")
	}
}

func TestDetectionLogger_Close(t *testing.T) {
	logPath := "test_close.log"
	defer os.Remove(logPath)

	logger, err := NewDetectionLogger(logPath)
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}

	// Close should not error
	if err := logger.Close(); err != nil {
		t.Errorf("Close returned error: %v", err)
	}

	// Second close should not panic
	if err := logger.Close(); err != nil {
		t.Errorf("Second close returned error: %v", err)
	}
}

func TestDetectionLogger_Close_Disabled(t *testing.T) {
	logger, err := NewDetectionLogger("")
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}

	// Closing disabled logger should not error
	if err := logger.Close(); err != nil {
		t.Errorf("Close returned error for disabled logger: %v", err)
	}
}

func TestHexDump(t *testing.T) {
	tests := []struct {
		name     string
		data     []byte
		expected []string // Strings that should be present in output
	}{
		{
			name:     "Empty data",
			data:     []byte{},
			expected: []string{"(empty)"},
		},
		{
			name:     "Single byte",
			data:     []byte{0x41},
			expected: []string{"00000000", "41", "|A|"},
		},
		{
			name: "16 bytes - single line",
			data: []byte{
				0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
				0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
			},
			expected: []string{
				"00000000",
				"00 01 02 03 04 05 06 07  08 09 0a 0b 0c 0d 0e 0f",
			},
		},
		{
			name: "Printable ASCII",
			data: []byte("Hello World!"),
			expected: []string{
				"00000000",
				"48 65 6c 6c 6f 20 57 6f  72 6c 64 21",
				"|Hello World!",
			},
		},
		{
			name: "Non-printable characters",
			data: []byte{0x00, 0x01, 0x1f, 0x7f, 0x80, 0xff},
			expected: []string{
				"00000000",
				"00 01 1f 7f 80 ff",
				"|......|", // Non-printables shown as dots
			},
		},
		{
			name: "Multiple lines",
			data: append(
				[]byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f},
				[]byte{0x10, 0x11, 0x12, 0x13}...,
			),
			expected: []string{
				"00000000",
				"00000010",
				"10 11 12 13",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			output := hexDump(tt.data)

			for _, expected := range tt.expected {
				if !strings.Contains(output, expected) {
					t.Errorf("hexDump output missing expected string: %q\nOutput:\n%s", expected, output)
				}
			}
		})
	}
}

func TestAsciiDump(t *testing.T) {
	tests := []struct {
		name     string
		data     []byte
		expected string
	}{
		{
			name:     "Empty data",
			data:     []byte{},
			expected: "(empty)",
		},
		{
			name:     "Only printable ASCII",
			data:     []byte("Hello World!"),
			expected: "Hello World!",
		},
		{
			name:     "Mixed printable and non-printable",
			data:     []byte{0x00, 0x41, 0x42, 0x43, 0xff, 0x44},
			expected: ".ABC.D",
		},
		{
			name:     "Whitespace characters",
			data:     []byte("Hello\nWorld\t!"),
			expected: "Hello\nWorld\t!",
		},
		{
			name:     "Only non-printable",
			data:     []byte{0x00, 0x01, 0x02, 0x1f, 0x7f},
			expected: ".....",
		},
		{
			name:     "All non-printable returns message",
			data:     []byte{0x00, 0x01, 0x02},
			expected: "...",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			output := asciiDump(tt.data)

			if !strings.Contains(output, tt.expected) && output != tt.expected {
				t.Errorf("asciiDump output incorrect:\nExpected substring: %q\nGot: %q", tt.expected, output)
			}
		})
	}
}

func TestDetectionLogger_ConcurrentWrites(t *testing.T) {
	logPath := "test_concurrent.log"
	defer os.Remove(logPath)

	logger, err := NewDetectionLogger(logPath)
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}
	defer logger.Close()

	// Write from multiple goroutines concurrently
	done := make(chan bool)
	for i := 0; i < 10; i++ {
		go func(id int) {
			logger.LogDetection(
				time.Now(),
				"eth0",
				"TCP",
				"192.168.1.100",
				uint16(1000+id),
				"8.8.8.8",
				6881,
				"Test Detection",
				[]byte("test payload"),
			)
			done <- true
		}(i)
	}

	// Wait for all goroutines
	for i := 0; i < 10; i++ {
		<-done
	}

	// Verify file was created and contains data
	content, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("Failed to read log file: %v", err)
	}

	// Should have 10 separator lines (one per detection)
	separatorCount := strings.Count(string(content), "================================================================================")
	if separatorCount != 10 {
		t.Errorf("Expected 10 detection entries, got %d", separatorCount)
	}
}

func TestHexEncode(t *testing.T) {
	tests := []struct {
		name     string
		data     []byte
		expected string
	}{
		{
			name:     "Empty",
			data:     []byte{},
			expected: "",
		},
		{
			name:     "Single byte",
			data:     []byte{0xff},
			expected: "ff",
		},
		{
			name:     "Multiple bytes",
			data:     []byte{0x12, 0x34, 0x56, 0x78},
			expected: "12345678",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			output := hexEncode(tt.data)
			if output != tt.expected {
				t.Errorf("hexEncode() = %q, want %q", output, tt.expected)
			}
		})
	}
}
