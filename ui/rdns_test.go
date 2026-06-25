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

// TestRDNSOldestEvicted verifies that when the cache exceeds maxRDNS with only
// live entries, the second-pass eviction removes the OLDEST entries (earliest
// expires) rather than arbitrary ones.
func TestRDNSOldestEvicted(t *testing.T) {
	rdnsCache.Lock()
	rdnsCache.entries = make(map[string]rdnsCacheEntry)

	// Insert maxRDNS+100 live entries with staggered expiry times.
	// Entries 0..99   → expires in 1 minute  (oldest, should be evicted)
	// Entries 100..maxRDNS+99 → expires in 10 minutes (newer, should survive)
	total := maxRDNS + 100
	now := time.Now()
	for i := 0; i < total; i++ {
		ip := fmt.Sprintf("10.%d.%d.%d", i/65536, (i/256)%256, i%256)
		var exp time.Time
		if i < 100 {
			exp = now.Add(1 * time.Minute) // oldest
		} else {
			exp = now.Add(10 * time.Minute) // newer
		}
		rdnsCache.entries[ip] = rdnsCacheEntry{name: ip, expires: exp}
	}
	rdnsCache.Unlock()

	rdnsCache.Lock()
	rdnsPruneIfNeeded()
	rdnsCache.Unlock()

	rdnsCache.RLock()
	defer rdnsCache.RUnlock()

	// (a) cache must be at cap
	if got := len(rdnsCache.entries); got != maxRDNS {
		t.Errorf("cache len = %d, want %d", got, maxRDNS)
	}

	// (b) the 100 short-expiry entries must have been evicted; only 10-minute
	// entries should remain.
	for i := 0; i < 100; i++ {
		ip := fmt.Sprintf("10.%d.%d.%d", i/65536, (i/256)%256, i%256)
		if _, ok := rdnsCache.entries[ip]; ok {
			t.Errorf("entry %s (oldest) survived eviction but should have been removed", ip)
		}
	}
}
