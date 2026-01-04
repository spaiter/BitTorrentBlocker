//go:build linux && integration

package integration

import (
	"net"
	"testing"
	"time"

	"github.com/example/BitTorrentBlocker/internal/xdp"
)

// TestXDPFilterLifecycle tests the basic lifecycle of XDP filter
func TestXDPFilterLifecycle(t *testing.T) {
	// Use loopback interface for testing (always available)
	iface := "lo"

	// Create XDP filter
	filter, err := xdp.NewXDPFilter(iface)
	if err != nil {
		t.Fatalf("Failed to create XDP filter: %v", err)
	}
	defer filter.Close()

	// Verify filter is active
	if filter == nil {
		t.Fatal("XDP filter is nil after creation")
	}

	// Close and verify no errors
	if err := filter.Close(); err != nil {
		t.Errorf("Failed to close XDP filter: %v", err)
	}
}

// TestXDPMapOperations tests IP map add/remove/lookup operations
func TestXDPMapOperations(t *testing.T) {
	iface := "lo"

	filter, err := xdp.NewXDPFilter(iface)
	if err != nil {
		t.Fatalf("Failed to create XDP filter: %v", err)
	}
	defer filter.Close()

	mapMgr := filter.GetMapManager()
	if mapMgr == nil {
		t.Fatal("Map manager is nil")
	}

	testIP := net.ParseIP("192.168.1.100")
	if testIP == nil {
		t.Fatal("Failed to parse test IP")
	}

	// Test 1: Add IP to blocklist
	banDuration := 1 * time.Hour
	if err := mapMgr.AddIP(testIP, banDuration); err != nil {
		t.Fatalf("Failed to add IP to blocklist: %v", err)
	}

	// Test 2: Verify IP is blocked
	blocked, err := mapMgr.IsBlocked(testIP)
	if err != nil {
		t.Fatalf("Failed to check if IP is blocked: %v", err)
	}
	if !blocked {
		t.Error("IP should be blocked but IsBlocked returned false")
	}

	// Test 3: Remove IP from blocklist
	if err := mapMgr.RemoveIP(testIP); err != nil {
		t.Fatalf("Failed to remove IP from blocklist: %v", err)
	}

	// Test 4: Verify IP is no longer blocked
	blocked, err = mapMgr.IsBlocked(testIP)
	if err != nil {
		t.Fatalf("Failed to check if IP is blocked after removal: %v", err)
	}
	if blocked {
		t.Error("IP should not be blocked after removal")
	}
}

// TestXDPMultipleIPs tests blocking multiple IPs simultaneously
func TestXDPMultipleIPs(t *testing.T) {
	iface := "lo"

	filter, err := xdp.NewXDPFilter(iface)
	if err != nil {
		t.Fatalf("Failed to create XDP filter: %v", err)
	}
	defer filter.Close()

	mapMgr := filter.GetMapManager()

	// Add multiple IPs
	testIPs := []string{
		"10.0.0.1",
		"10.0.0.2",
		"10.0.0.3",
		"10.0.0.4",
		"10.0.0.5",
	}

	banDuration := 2 * time.Hour

	// Add all IPs
	for _, ipStr := range testIPs {
		ip := net.ParseIP(ipStr)
		if ip == nil {
			t.Fatalf("Failed to parse IP: %s", ipStr)
		}
		if err := mapMgr.AddIP(ip, banDuration); err != nil {
			t.Fatalf("Failed to add IP %s: %v", ipStr, err)
		}
	}

	// Verify all IPs are blocked
	for _, ipStr := range testIPs {
		ip := net.ParseIP(ipStr)
		blocked, err := mapMgr.IsBlocked(ip)
		if err != nil {
			t.Fatalf("Failed to check IP %s: %v", ipStr, err)
		}
		if !blocked {
			t.Errorf("IP %s should be blocked", ipStr)
		}
	}

	// Remove all IPs
	for _, ipStr := range testIPs {
		ip := net.ParseIP(ipStr)
		if err := mapMgr.RemoveIP(ip); err != nil {
			t.Fatalf("Failed to remove IP %s: %v", ipStr, err)
		}
	}

	// Verify all IPs are unblocked
	for _, ipStr := range testIPs {
		ip := net.ParseIP(ipStr)
		blocked, err := mapMgr.IsBlocked(ip)
		if err != nil {
			t.Fatalf("Failed to check IP %s after removal: %v", ipStr, err)
		}
		if blocked {
			t.Errorf("IP %s should not be blocked after removal", ipStr)
		}
	}
}

// TestXDPExpiration tests that expired IPs are cleaned up
func TestXDPExpiration(t *testing.T) {
	iface := "lo"

	filter, err := xdp.NewXDPFilter(iface)
	if err != nil {
		t.Fatalf("Failed to create XDP filter: %v", err)
	}
	defer filter.Close()

	mapMgr := filter.GetMapManager()

	// Add IP with very short expiration
	testIP := net.ParseIP("172.16.0.1")
	shortDuration := 2 * time.Second

	if err := mapMgr.AddIP(testIP, shortDuration); err != nil {
		t.Fatalf("Failed to add IP: %v", err)
	}

	// Verify IP is blocked
	blocked, err := mapMgr.IsBlocked(testIP)
	if err != nil {
		t.Fatalf("Failed to check IP: %v", err)
	}
	if !blocked {
		t.Error("IP should be blocked initially")
	}

	// Wait for expiration
	time.Sleep(3 * time.Second)

	// Run cleanup
	removed, err := mapMgr.CleanupExpired()
	if err != nil {
		t.Fatalf("Failed to cleanup expired IPs: %v", err)
	}

	if removed == 0 {
		t.Error("Expected at least 1 expired IP to be removed")
	}

	// Verify IP is no longer blocked
	blocked, err = mapMgr.IsBlocked(testIP)
	if err != nil {
		t.Fatalf("Failed to check IP after cleanup: %v", err)
	}
	if blocked {
		t.Error("IP should not be blocked after expiration and cleanup")
	}
}

// TestXDPPeriodicCleanup tests automatic periodic cleanup
func TestXDPPeriodicCleanup(t *testing.T) {
	iface := "lo"

	filter, err := xdp.NewXDPFilter(iface)
	if err != nil {
		t.Fatalf("Failed to create XDP filter: %v", err)
	}
	defer filter.Close()

	mapMgr := filter.GetMapManager()

	// Start periodic cleanup with short interval
	cleanupInterval := 1 * time.Second
	mapMgr.StartPeriodicCleanup(cleanupInterval)
	defer mapMgr.StopPeriodicCleanup()

	// Add IP with short expiration
	testIP := net.ParseIP("192.168.100.50")
	shortDuration := 2 * time.Second

	if err := mapMgr.AddIP(testIP, shortDuration); err != nil {
		t.Fatalf("Failed to add IP: %v", err)
	}

	// Verify IP is blocked
	blocked, err := mapMgr.IsBlocked(testIP)
	if err != nil {
		t.Fatalf("Failed to check IP: %v", err)
	}
	if !blocked {
		t.Error("IP should be blocked initially")
	}

	// Wait for periodic cleanup to run (expiration + cleanup interval + buffer)
	time.Sleep(4 * time.Second)

	// Verify IP is automatically removed
	blocked, err = mapMgr.IsBlocked(testIP)
	if err != nil {
		t.Fatalf("Failed to check IP after periodic cleanup: %v", err)
	}
	if blocked {
		t.Error("IP should be automatically removed by periodic cleanup")
	}
}

// TestXDPIPv4Only tests that only IPv4 addresses are accepted
func TestXDPIPv4Only(t *testing.T) {
	iface := "lo"

	filter, err := xdp.NewXDPFilter(iface)
	if err != nil {
		t.Fatalf("Failed to create XDP filter: %v", err)
	}
	defer filter.Close()

	mapMgr := filter.GetMapManager()

	// Try to add IPv6 address (should fail or be rejected)
	ipv6 := net.ParseIP("2001:db8::1")
	if ipv6 == nil {
		t.Fatal("Failed to parse IPv6 address")
	}

	err = mapMgr.AddIP(ipv6, 1*time.Hour)
	// Expect error since XDP only supports IPv4
	if err == nil {
		t.Error("Adding IPv6 address should fail, but no error was returned")
	}
}

// TestXDPLargeScale tests handling many IPs (stress test)
func TestXDPLargeScale(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping large-scale test in short mode")
	}

	iface := "lo"

	filter, err := xdp.NewXDPFilter(iface)
	if err != nil {
		t.Fatalf("Failed to create XDP filter: %v", err)
	}
	defer filter.Close()

	mapMgr := filter.GetMapManager()

	// Add 1000 IPs
	numIPs := 1000
	banDuration := 1 * time.Hour

	t.Logf("Adding %d IPs to blocklist...", numIPs)
	start := time.Now()

	for i := 0; i < numIPs; i++ {
		// Generate IP: 10.0.X.Y
		ip := net.IPv4(10, 0, byte(i/256), byte(i%256))
		if err := mapMgr.AddIP(ip, banDuration); err != nil {
			t.Fatalf("Failed to add IP %s: %v", ip, err)
		}
	}

	elapsed := time.Since(start)
	t.Logf("Added %d IPs in %v (%.2f IPs/sec)", numIPs, elapsed, float64(numIPs)/elapsed.Seconds())

	// Verify random samples
	samples := []int{0, 100, 500, 999}
	for _, i := range samples {
		ip := net.IPv4(10, 0, byte(i/256), byte(i%256))
		blocked, err := mapMgr.IsBlocked(ip)
		if err != nil {
			t.Fatalf("Failed to check IP %s: %v", ip, err)
		}
		if !blocked {
			t.Errorf("IP %s should be blocked", ip)
		}
	}

	// Test cleanup performance
	t.Log("Testing cleanup performance...")
	cleanupStart := time.Now()
	removed, err := mapMgr.CleanupExpired()
	cleanupElapsed := time.Since(cleanupStart)

	if err != nil {
		t.Fatalf("Cleanup failed: %v", err)
	}

	t.Logf("Cleanup scanned %d entries in %v (removed: %d)", numIPs, cleanupElapsed, removed)
}

// TestXDPConcurrentOperations tests concurrent access to the map
func TestXDPConcurrentOperations(t *testing.T) {
	iface := "lo"

	filter, err := xdp.NewXDPFilter(iface)
	if err != nil {
		t.Fatalf("Failed to create XDP filter: %v", err)
	}
	defer filter.Close()

	mapMgr := filter.GetMapManager()

	// Run concurrent add/remove/lookup operations
	done := make(chan bool)
	numGoroutines := 10
	opsPerGoroutine := 100

	for g := 0; g < numGoroutines; g++ {
		go func(id int) {
			defer func() { done <- true }()

			for i := 0; i < opsPerGoroutine; i++ {
				// Generate unique IP per goroutine
				ip := net.IPv4(10, byte(id), byte(i/256), byte(i%256))

				// Add IP
				if err := mapMgr.AddIP(ip, 1*time.Hour); err != nil {
					t.Errorf("Goroutine %d: Failed to add IP: %v", id, err)
					return
				}

				// Check if blocked
				blocked, err := mapMgr.IsBlocked(ip)
				if err != nil {
					t.Errorf("Goroutine %d: Failed to check IP: %v", id, err)
					return
				}
				if !blocked {
					t.Errorf("Goroutine %d: IP should be blocked", id)
					return
				}

				// Remove IP
				if err := mapMgr.RemoveIP(ip); err != nil {
					t.Errorf("Goroutine %d: Failed to remove IP: %v", id, err)
					return
				}
			}
		}(g)
	}

	// Wait for all goroutines
	for i := 0; i < numGoroutines; i++ {
		<-done
	}
}

// TestXDPInterfaceValidation tests interface name validation
func TestXDPInterfaceValidation(t *testing.T) {
	// Test with non-existent interface
	_, err := xdp.NewXDPFilter("nonexistent999")
	if err == nil {
		t.Error("Expected error for non-existent interface, got nil")
	}

	// Test with empty interface name
	_, err = xdp.NewXDPFilter("")
	if err == nil {
		t.Error("Expected error for empty interface name, got nil")
	}
}
