package ui

import (
	"fmt"
	"testing"
	"time"
)

// TestRDNSCacheBound verifies that the rdns cache is capped at maxRDNS entries.
// TDD: this test is written BEFORE the eviction logic exists, so it should fail
// (compile error) until rdnsPruneIfNeeded and maxRDNS are added to rdns.go.
func TestRDNSCacheBound(t *testing.T) {
	// Reset cache to a known state.
	rdnsCache.Lock()
	rdnsCache.entries = make(map[string]rdnsCacheEntry)

	// Insert 5000 distinct entries that are already expired.
	past := time.Now().Add(-time.Hour)
	for i := 0; i < 5000; i++ {
		ip := fmt.Sprintf("10.%d.%d.%d", i/65536, (i/256)%256, i%256)
		rdnsCache.entries[ip] = rdnsCacheEntry{name: ip, expires: past}
	}
	rdnsCache.Unlock()

	// Trigger the prune that bounds the cache.
	rdnsCache.Lock()
	rdnsPruneIfNeeded()
	rdnsCache.Unlock()

	rdnsCache.RLock()
	n := len(rdnsCache.entries)
	rdnsCache.RUnlock()

	if n > maxRDNS {
		t.Errorf("cache has %d entries after prune, want <= %d", n, maxRDNS)
	}
}

// TestRDNSCacheBoundMixed verifies eviction with a mix of expired and live entries.
func TestRDNSCacheBoundMixed(t *testing.T) {
	rdnsCache.Lock()
	rdnsCache.entries = make(map[string]rdnsCacheEntry)

	past := time.Now().Add(-time.Hour)
	future := time.Now().Add(time.Hour)

	// Insert 3000 expired + 1000 live entries (total 4000 > maxRDNS).
	for i := 0; i < 3000; i++ {
		ip := fmt.Sprintf("192.168.%d.%d", i/256, i%256)
		rdnsCache.entries[ip] = rdnsCacheEntry{name: ip, expires: past}
	}
	for i := 0; i < 1000; i++ {
		ip := fmt.Sprintf("172.16.%d.%d", i/256, i%256)
		rdnsCache.entries[ip] = rdnsCacheEntry{name: ip, expires: future}
	}
	rdnsCache.Unlock()

	rdnsCache.Lock()
	rdnsPruneIfNeeded()
	rdnsCache.Unlock()

	rdnsCache.RLock()
	n := len(rdnsCache.entries)
	rdnsCache.RUnlock()

	if n > maxRDNS {
		t.Errorf("cache has %d entries after mixed prune, want <= %d", n, maxRDNS)
	}
}
