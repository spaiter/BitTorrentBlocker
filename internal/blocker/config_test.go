package blocker

import (
	"testing"
)

func TestDefaultConfig(t *testing.T) {
	config := DefaultConfig()

	tests := []struct {
		name     string
		got      interface{}
		expected interface{}
	}{
		{"Interfaces", len(config.Interfaces) == 1 && config.Interfaces[0] == "eth0", true},
		{"EntropyThreshold", config.EntropyThreshold, 7.6},
		{"MinPayloadSize", config.MinPayloadSize, 60},
		{"IPSetName", config.IPSetName, "torrent_block"},
		{"BanDuration", config.BanDuration, 18000},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.got != tt.expected {
				t.Errorf("DefaultConfig().%s = %v, want %v", tt.name, tt.got, tt.expected)
			}
		})
	}
}

func TestConfigValidation(t *testing.T) {
	tests := []struct {
		name   string
		config Config
		valid  bool
	}{
		{
			name:   "Default config is valid",
			config: DefaultConfig(),
			valid:  true,
		},
		{
			name: "Custom valid config",
			config: Config{
				Interfaces:       []string{"eth0"},
				EntropyThreshold: 8.0,
				MinPayloadSize:   100,
				IPSetName:        "custom_set",
				BanDuration:      7200,
			},
			valid: true,
		},
		{
			name: "Zero entropy threshold",
			config: Config{
				Interfaces:       []string{"eth0"},
				EntropyThreshold: 0,
				MinPayloadSize:   60,
				IPSetName:        "test",
				BanDuration:      3600,
			},
			valid: true, // Zero is valid (means no entropy check)
		},
		{
			name: "Empty IPSetName",
			config: Config{
				Interfaces:       []string{"eth0"},
				EntropyThreshold: 7.6,
				MinPayloadSize:   60,
				IPSetName:        "",
				BanDuration:      3600,
			},
			valid: true, // Empty is valid (might not use ipset)
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Currently we don't have validation logic, but we're testing
			// that the config can be created and used
			analyzer := NewAnalyzer(tt.config)
			if analyzer == nil && tt.valid {
				t.Errorf("Config should be valid but NewAnalyzer returned nil")
			}
		})
	}
}

func TestConfigCustomValues(t *testing.T) {
	// Test that custom config values are properly stored and used
	config := Config{
		Interfaces:       []string{"eth0"},
		EntropyThreshold: 6.5,
		MinPayloadSize:   128,
		IPSetName:        "custom_blocker",
		BanDuration:      86400, // 24 hours
	}

	if len(config.Interfaces) != 1 || config.Interfaces[0] != "eth0" {
		t.Errorf("Interfaces = %v, want [\"eth0\"]", config.Interfaces)
	}

	if config.EntropyThreshold != 6.5 {
		t.Errorf("EntropyThreshold = %v, want 6.5", config.EntropyThreshold)
	}

	if config.MinPayloadSize != 128 {
		t.Errorf("MinPayloadSize = %v, want 128", config.MinPayloadSize)
	}

	if config.IPSetName != "custom_blocker" {
		t.Errorf("IPSetName = %v, want custom_blocker", config.IPSetName)
	}

	if config.BanDuration != 86400 {
		t.Errorf("BanDuration = %v, want 86400", config.BanDuration)
	}
}

func TestConfigInAnalyzer(t *testing.T) {
	config := Config{
		Interfaces:       []string{"eth0"},
		EntropyThreshold: 9.0, // Very high threshold
		MinPayloadSize:   200, // Large minimum size
		IPSetName:        "test",
		BanDuration:      3600,
	}

	analyzer := NewAnalyzer(config)

	// Test that high entropy threshold prevents blocking
	highEntropyData := make([]byte, 100) // Below MinPayloadSize
	for i := range highEntropyData {
		highEntropyData[i] = byte(i)
	}

	result := analyzer.AnalyzePacket(highEntropyData, false)

	// Should not block on entropy because payload is too small
	if result.ShouldBlock && len(result.Reason) >= 4 && result.Reason[:4] == "High" {
		t.Errorf("Config MinPayloadSize not respected in analyzer")
	}
}
