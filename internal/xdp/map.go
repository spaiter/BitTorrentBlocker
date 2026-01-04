package xdp

import (
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/cilium/ebpf"
)

// BlockedIP represents an IP address in the XDP blocklist with expiration time
type BlockedIP struct {
	IP        net.IP
	ExpiresAt time.Time
}

// IPMapManager manages the XDP map for blocked IPs
type IPMapManager struct {
	bpfMap    *ebpf.Map
	mu        sync.RWMutex
	localMap  map[string]time.Time // Track expiration times in user space
	cleanupCh chan struct{}
}

// NewIPMapManager creates a new IP map manager
func NewIPMapManager(bpfMap *ebpf.Map) *IPMapManager {
	return &IPMapManager{
		bpfMap:    bpfMap,
		localMap:  make(map[string]time.Time),
		cleanupCh: make(chan struct{}, 1),
	}
}

// AddIP adds an IP address to the XDP blocklist
func (m *IPMapManager) AddIP(ip net.IP, duration time.Duration) error {
	if ip == nil {
		return fmt.Errorf("nil IP address")
	}

	// Convert to IPv4 if needed
	ip = ip.To4()
	if ip == nil {
		return fmt.Errorf("invalid IPv4 address")
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	// Convert IP to uint32 (big endian)
	ipKey := binary.BigEndian.Uint32(ip)

	// Calculate expiration time (seconds since epoch)
	expiresAt := time.Now().Add(duration)
	expiresAtSec := uint64(expiresAt.Unix())

	// Update XDP map (kernel space)
	if err := m.bpfMap.Put(&ipKey, &expiresAtSec); err != nil {
		return fmt.Errorf("failed to add IP to XDP map: %w", err)
	}

	// Update local tracking map (user space)
	m.localMap[ip.String()] = expiresAt

	return nil
}

// RemoveIP removes an IP address from the XDP blocklist
func (m *IPMapManager) RemoveIP(ip net.IP) error {
	if ip == nil {
		return fmt.Errorf("nil IP address")
	}

	// Convert to IPv4 if needed
	ip = ip.To4()
	if ip == nil {
		return fmt.Errorf("invalid IPv4 address")
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	// Convert IP to uint32 (big endian)
	ipKey := binary.BigEndian.Uint32(ip)

	// Remove from XDP map (kernel space)
	if err := m.bpfMap.Delete(&ipKey); err != nil {
		return fmt.Errorf("failed to remove IP from XDP map: %w", err)
	}

	// Remove from local tracking map (user space)
	delete(m.localMap, ip.String())

	return nil
}

// IsBlocked checks if an IP is currently blocked
func (m *IPMapManager) IsBlocked(ip net.IP) (bool, error) {
	if ip == nil {
		return false, fmt.Errorf("nil IP address")
	}

	// Convert to IPv4 if needed
	ip = ip.To4()
	if ip == nil {
		return false, fmt.Errorf("invalid IPv4 address")
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	// Check local map first (faster)
	if expiresAt, exists := m.localMap[ip.String()]; exists {
		if time.Now().Before(expiresAt) {
			return true, nil
		}
		// Expired but not yet cleaned up
		return false, nil
	}

	return false, nil
}

// GetBlockedCount returns the number of currently blocked IPs
func (m *IPMapManager) GetBlockedCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.localMap)
}

// CleanupExpired removes expired IP addresses from the XDP map
// This should be called periodically from user space
func (m *IPMapManager) CleanupExpired() (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now()
	removed := 0
	var errs []error

	// Iterate over local map to find expired entries
	for ipStr, expiresAt := range m.localMap {
		if now.After(expiresAt) {
			ip := net.ParseIP(ipStr)
			if ip == nil {
				continue
			}

			ip = ip.To4()
			if ip == nil {
				continue
			}

			// Convert IP to uint32 (big endian)
			ipKey := binary.BigEndian.Uint32(ip)

			// Remove from XDP map
			if err := m.bpfMap.Delete(&ipKey); err != nil {
				errs = append(errs, fmt.Errorf("failed to remove %s: %w", ipStr, err))
				continue
			}

			// Remove from local map
			delete(m.localMap, ipStr)
			removed++
		}
	}

	if len(errs) > 0 {
		return removed, fmt.Errorf("cleanup errors: %v", errs)
	}

	return removed, nil
}

// StartPeriodicCleanup starts a goroutine that periodically cleans up expired IPs
func (m *IPMapManager) StartPeriodicCleanup(interval time.Duration) {
	ticker := time.NewTicker(interval)
	go func() {
		for {
			select {
			case <-ticker.C:
				if removed, err := m.CleanupExpired(); err != nil {
					// Log error but continue
					fmt.Printf("XDP cleanup error: %v\n", err)
				} else if removed > 0 {
					fmt.Printf("XDP cleanup: removed %d expired IPs\n", removed)
				}
			case <-m.cleanupCh:
				ticker.Stop()
				return
			}
		}
	}()
}

// StopPeriodicCleanup stops the periodic cleanup goroutine
func (m *IPMapManager) StopPeriodicCleanup() {
	select {
	case m.cleanupCh <- struct{}{}:
	default:
	}
}

// Close stops periodic cleanup and releases resources
func (m *IPMapManager) Close() error {
	m.StopPeriodicCleanup()
	return nil
}

// GetAllBlockedIPs returns all currently blocked IPs with their expiration times
func (m *IPMapManager) GetAllBlockedIPs() []BlockedIP {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make([]BlockedIP, 0, len(m.localMap))
	for ipStr, expiresAt := range m.localMap {
		ip := net.ParseIP(ipStr)
		if ip != nil {
			result = append(result, BlockedIP{
				IP:        ip,
				ExpiresAt: expiresAt,
			})
		}
	}

	return result
}
