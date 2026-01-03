package blocker

// Config holds the configuration for the BitTorrent blocker
type Config struct {
	Interfaces       []string // Network interfaces to monitor (e.g., ["eth0", "wg0"])
	IPSetName        string
	BanDuration      int    // Duration in seconds
	LogLevel         string // Logging level: error, warn, info, debug
	DetectionLogPath string // Path to detection log file (empty = disabled)
	MonitorOnly      bool   // If true, only log detections without banning IPs
}

// DefaultConfig returns a configuration with recommended defaults
func DefaultConfig() Config {
	return Config{
		Interfaces:       []string{"eth0"}, // Default interface
		IPSetName:        "torrent_block",
		BanDuration:      18000, // 5 hours in seconds
		LogLevel:         "info",
		DetectionLogPath: "",    // Disabled by default
		MonitorOnly:      false, // Enable blocking by default
	}
}
