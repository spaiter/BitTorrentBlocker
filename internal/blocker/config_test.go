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
		{"IPSetName", config.IPSetName, "torrent_block"},
		{"BanDuration", config.BanDuration, 18000},
		{"LogLevel", config.LogLevel, "info"},
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
				Interfaces:  []string{"eth0"},
				IPSetName:   "custom_set",
				BanDuration: 7200,
				LogLevel:    "debug",
			},
			valid: true,
		},
		{
			name: "Multiple interfaces",
			config: Config{
				Interfaces:  []string{"eth0", "wg0", "awg0"},
				IPSetName:   "test",
				BanDuration: 3600,
				LogLevel:    "info",
			},
			valid: true,
		},
		{
			name: "Empty IPSetName",
			config: Config{
				Interfaces:  []string{"eth0"},
				IPSetName:   "",
				BanDuration: 3600,
				LogLevel:    "info",
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
		Interfaces:  []string{"eth0", "wg0"},
		IPSetName:   "custom_blocker",
		BanDuration: 86400, // 24 hours
		LogLevel:    "debug",
	}

	if len(config.Interfaces) != 2 || config.Interfaces[0] != "eth0" || config.Interfaces[1] != "wg0" {
		t.Errorf("Interfaces = %v, want [\"eth0\", \"wg0\"]", config.Interfaces)
	}

	if config.IPSetName != "custom_blocker" {
		t.Errorf("IPSetName = %v, want custom_blocker", config.IPSetName)
	}

	if config.BanDuration != 86400 {
		t.Errorf("BanDuration = %v, want 86400", config.BanDuration)
	}

	if config.LogLevel != "debug" {
		t.Errorf("LogLevel = %v, want debug", config.LogLevel)
	}
}

func TestConfigInAnalyzer(t *testing.T) {
	config := Config{
		Interfaces:  []string{"eth0"},
		IPSetName:   "test",
		BanDuration: 3600,
		LogLevel:    "info",
	}

	analyzer := NewAnalyzer(config)

	// Test that random data doesn't trigger false positives
	randomData := make([]byte, 100)
	for i := range randomData {
		randomData[i] = byte(i)
	}

	result := analyzer.AnalyzePacket(randomData, false)

	// Should not block random data that doesn't match any BitTorrent patterns
	if result.ShouldBlock {
		t.Errorf("Config test: should not block non-BitTorrent data, got reason: %s", result.Reason)
	}
}
