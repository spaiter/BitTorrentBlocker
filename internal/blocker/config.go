package blocker

// Config holds the configuration for the BitTorrent blocker
type Config struct {
	QueueNum         uint16
	EntropyThreshold float64
	MinPayloadSize   int
	IPSetName        string
	BanDuration      string // Duration in seconds as string
	LogLevel         string // Logging level: error, warn, info, debug
}

// DefaultConfig returns a configuration with recommended defaults
func DefaultConfig() Config {
	return Config{
		QueueNum:         0,
		EntropyThreshold: 7.6, // Threshold for RC4/Encryption detection
		MinPayloadSize:   60,
		IPSetName:        "torrent_block",
		BanDuration:      "18000", // 5 hours in seconds
		LogLevel:         "info",
	}
}
