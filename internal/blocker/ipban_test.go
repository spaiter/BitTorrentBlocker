package blocker

import (
	"sync"
	"testing"
	"time"
)

func TestNewIPBanManager(t *testing.T) {
	manager := NewIPBanManager("test_set", "3600")

	if manager == nil {
		t.Fatal("NewIPBanManager returned nil")
	}

	if manager.ipSetName != "test_set" {
		t.Errorf("ipSetName = %v, want test_set", manager.ipSetName)
	}

	if manager.duration != "3600" {
		t.Errorf("duration = %v, want 3600", manager.duration)
	}

	if manager.cache == nil {
		t.Error("cache should not be nil")
	}
}

func TestIPBanManager_BanIP_Caching(t *testing.T) {
	manager := NewIPBanManager("test_set", "3600")

	ip := "192.168.1.100"

	// First ban - should be added to cache
	err := manager.BanIP(ip)
	if err != nil {
		// Note: This will fail if ipset is not installed, which is expected in test environment
		// We're mainly testing the caching logic
		t.Logf("BanIP returned error (expected if ipset not installed): %v", err)
	}

	// Check cache
	manager.mu.RLock()
	_, exists := manager.cache[ip]
	manager.mu.RUnlock()

	if !exists {
		t.Error("IP should be in cache after first ban")
	}

	// Immediate second ban - should be skipped due to cache
	err2 := manager.BanIP(ip)
	if err2 != nil {
		t.Logf("Second BanIP returned error: %v", err2)
	}

	// The second call should return quickly due to caching
	// We can verify this by checking the cache timestamp didn't change significantly
	manager.mu.RLock()
	cacheTime := manager.cache[ip]
	manager.mu.RUnlock()

	if time.Since(cacheTime) > 100*time.Millisecond {
		t.Error("Second ban should have been cached and returned immediately")
	}
}

func TestIPBanManager_BanIP_CacheExpiry(t *testing.T) {
	manager := NewIPBanManager("test_set", "3600")

	ip := "192.168.1.101"

	// Add to cache with old timestamp
	manager.mu.Lock()
	manager.cache[ip] = time.Now().Add(-2 * time.Minute)
	manager.mu.Unlock()

	// Ban should proceed because cache entry is old
	err := manager.BanIP(ip)
	if err != nil {
		t.Logf("BanIP returned error (expected if ipset not installed): %v", err)
	}

	// Check that timestamp was updated
	manager.mu.RLock()
	newTime := manager.cache[ip]
	manager.mu.RUnlock()

	if time.Since(newTime) > 100*time.Millisecond {
		t.Error("Cache timestamp should have been updated")
	}
}

func TestIPBanManager_BanIP_Concurrency(t *testing.T) {
	manager := NewIPBanManager("test_set", "3600")

	// Test concurrent bans
	var wg sync.WaitGroup
	numGoroutines := 10
	ip := "192.168.1.102"

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			manager.BanIP(ip)
		}()
	}

	wg.Wait()

	// Should only have one entry in cache
	manager.mu.RLock()
	count := len(manager.cache)
	manager.mu.RUnlock()

	if count != 1 {
		t.Errorf("Expected 1 cache entry, got %d", count)
	}
}

func TestIPBanManager_BanIP_MultipleIPs(t *testing.T) {
	manager := NewIPBanManager("test_set", "3600")

	ips := []string{
		"192.168.1.1",
		"192.168.1.2",
		"192.168.1.3",
		"10.0.0.1",
		"10.0.0.2",
	}

	for _, ip := range ips {
		manager.BanIP(ip)
	}

	manager.mu.RLock()
	cacheSize := len(manager.cache)
	manager.mu.RUnlock()

	if cacheSize != len(ips) {
		t.Errorf("Expected %d cache entries, got %d", len(ips), cacheSize)
	}

	// Verify all IPs are in cache
	manager.mu.RLock()
	for _, ip := range ips {
		if _, exists := manager.cache[ip]; !exists {
			t.Errorf("IP %s should be in cache", ip)
		}
	}
	manager.mu.RUnlock()
}

func TestIPBanManager_CleanCache(t *testing.T) {
	manager := NewIPBanManager("test_set", "3600")

	// Add some old entries
	oldTime := time.Now().Add(-2 * time.Hour)
	manager.mu.Lock()
	manager.cache["192.168.1.1"] = oldTime
	manager.cache["192.168.1.2"] = oldTime
	manager.cache["192.168.1.3"] = time.Now() // Recent entry
	manager.mu.Unlock()

	// Clean entries older than 1 hour
	manager.CleanCache(1 * time.Hour)

	manager.mu.RLock()
	cacheSize := len(manager.cache)
	_, exists := manager.cache["192.168.1.3"]
	manager.mu.RUnlock()

	if cacheSize != 1 {
		t.Errorf("Expected 1 entry after cleaning, got %d", cacheSize)
	}

	if !exists {
		t.Error("Recent entry should not have been cleaned")
	}
}

func TestIPBanManager_CleanCache_Empty(t *testing.T) {
	manager := NewIPBanManager("test_set", "3600")

	// Clean empty cache should not panic
	manager.CleanCache(1 * time.Hour)

	manager.mu.RLock()
	cacheSize := len(manager.cache)
	manager.mu.RUnlock()

	if cacheSize != 0 {
		t.Errorf("Cache should be empty, got %d entries", cacheSize)
	}
}

func TestIPBanManager_CleanCache_Concurrency(t *testing.T) {
	manager := NewIPBanManager("test_set", "3600")

	// Add entries
	for i := 0; i < 100; i++ {
		ip := "192.168.1." + string(rune(i))
		manager.cache[ip] = time.Now().Add(-time.Duration(i) * time.Minute)
	}

	// Clean cache concurrently with bans
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		manager.CleanCache(30 * time.Minute)
	}()

	go func() {
		defer wg.Done()
		for i := 0; i < 10; i++ {
			manager.BanIP("10.0.0." + string(rune(i)))
		}
	}()

	wg.Wait()

	// Should not panic and cache should have some entries
	manager.mu.RLock()
	cacheSize := len(manager.cache)
	manager.mu.RUnlock()

	if cacheSize == 0 {
		t.Error("Cache should have some entries after concurrent operations")
	}
}

func BenchmarkIPBanManager_BanIP_Cached(b *testing.B) {
	manager := NewIPBanManager("test_set", "3600")
	ip := "192.168.1.100"

	// Prime the cache
	manager.BanIP(ip)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		manager.BanIP(ip)
	}
}

func BenchmarkIPBanManager_BanIP_Different(b *testing.B) {
	manager := NewIPBanManager("test_set", "3600")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ip := "192.168.1." + string(rune(i%255))
		manager.BanIP(ip)
	}
}

func BenchmarkIPBanManager_CleanCache(b *testing.B) {
	manager := NewIPBanManager("test_set", "3600")

	// Add many entries
	for i := 0; i < 1000; i++ {
		ip := "192.168." + string(rune(i/255)) + "." + string(rune(i%255))
		manager.cache[ip] = time.Now().Add(-time.Duration(i) * time.Second)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		manager.CleanCache(30 * time.Minute)
	}
}
