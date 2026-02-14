package blocker

import "testing"

func TestFormatDuration(t *testing.T) {
	tests := []struct {
		seconds  int
		expected string
	}{
		{0, "0h"},
		{3600, "1h"},
		{7200, "2h"},
		{18000, "5h"},
		{3660, "1h1m"},
		{5400, "1h30m"},
		{86400, "24h"},
		{90061, "25h1m"},
	}
	for _, tt := range tests {
		result := formatDuration(tt.seconds)
		if result != tt.expected {
			t.Errorf("formatDuration(%d) = %q, want %q", tt.seconds, result, tt.expected)
		}
	}
}

func TestParseBencodeLength(t *testing.T) {
	tests := []struct {
		name     string
		input    []byte
		expected int
	}{
		{"simple number", []byte("26"), 26},
		{"zero", []byte("0"), 0},
		{"large valid", []byte("2600"), 2600},
		{"IPv4 node list", []byte("416"), 416},       // 16 * 26
		{"IPv6 node list", []byte("608"), 608},       // 16 * 38
		{"overflow attack", []byte("9999999999"), 0}, // exceeds 1MB cap
		{"empty", []byte(""), 0},
		{"non-digit chars", []byte("abc"), 0},
		{"mixed", []byte("1a2b3"), 123},
		{"max cap boundary", []byte("1048576"), 1048576}, // exactly 1MB
		{"over cap", []byte("1048577"), 0},               // 1MB + 1
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseBencodeLength(tt.input)
			if result != tt.expected {
				t.Errorf("parseBencodeLength(%q) = %d, want %d", tt.input, result, tt.expected)
			}
		})
	}
}
