package blocker

// Config holds the configuration for the BitTorrent blocker
type Config struct {
	Interfaces       []string // Network interfaces to monitor (e.g., ["eth0", "wg0"])
	IPSetName        string
	BanDuration      int    // Duration in seconds
	LogLevel         string // Logging level: error, warn, info, debug
	DetectionLogPath string // Path to detection log file (empty = disabled)
	MonitorOnly      bool   // If true, only log detections without banning IPs
	BlockSOCKS       bool   // If true, block SOCKS proxy connections (default: false to reduce false positives)

	// XDP configuration (two-tier architecture)
	EnableXDP       bool   // Enable XDP fast path for kernel-space blocking (requires Linux 4.18+)
	XDPMode         string // XDP mode: "generic" (compatible) or "native" (faster, driver support required)
	CleanupInterval int    // Cleanup interval for expired IPs in seconds (default: 300 = 5 minutes)
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
		BlockSOCKS:       false, // Disabled by default to avoid false positives with legitimate proxies

		// XDP defaults (two-tier architecture)
		EnableXDP:       false,     // Disabled by default for backward compatibility
		XDPMode:         "generic", // Generic mode for maximum compatibility
		CleanupInterval: 300,       // Cleanup every 5 minutes
	}
}
