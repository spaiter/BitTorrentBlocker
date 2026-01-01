package blocker

import (
	"os/exec"
	"strconv"
	"sync"
	"time"
)

// IPBanManager manages IP banning with caching to avoid duplicate operations
type IPBanManager struct {
	cache     map[string]time.Time
	mu        sync.RWMutex
	ipSetName string
	duration  string
}

// NewIPBanManager creates a new IP ban manager
func NewIPBanManager(ipSetName string, duration int) *IPBanManager {
	return &IPBanManager{
		cache:     make(map[string]time.Time),
		ipSetName: ipSetName,
		duration:  strconv.Itoa(duration),
	}
}

// BanIP adds an IP to ipset with timeout (cached to avoid duplicate exec calls)
func (m *IPBanManager) BanIP(ip string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Cache check - don't spam ipset with duplicate adds
	if lastBan, exists := m.cache[ip]; exists {
		if time.Since(lastBan) < 1*time.Minute {
			return nil
		}
	}
	m.cache[ip] = time.Now()

	// Call system ipset utility
	cmd := exec.Command("ipset", "add", m.ipSetName, ip, "timeout", m.duration, "-exist")
	return cmd.Run()
}

// CleanCache removes expired entries from the cache
func (m *IPBanManager) CleanCache(maxAge time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now()
	for ip, lastBan := range m.cache {
		if now.Sub(lastBan) > maxAge {
			delete(m.cache, ip)
		}
	}
}
