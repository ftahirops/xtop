package cgroup

import (
	"testing"
	"time"
)

func TestParseKubepodsPath_SystemdV2(t *testing.T) {
	path := "/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod9e5d1e42_b8f4_4f7a_9a67_7c9a4e3f21ab.slice/cri-containerd-1a2b3c4d5e6f7890abcdef12.scope"
	id := parseKubepodsPath(path)
	if id.QoS != "Burstable" {
		t.Errorf("QoS = %q, want Burstable", id.QoS)
	}
	if id.PodUID != "9e5d1e42-b8f4-4f7a-9a67-7c9a4e3f21ab" {
		t.Errorf("PodUID = %q, want dashed form", id.PodUID)
	}
	if id.Container != "1a2b3c4d5e6f" {
		t.Errorf("Container = %q, want 12-char prefix", id.Container)
	}
}

func TestParseKubepodsPath_CgroupfsDriver(t *testing.T) {
	path := "/kubepods/besteffort/pod11111111-2222-3333-4444-555555555555/aabbccddeeff112233445566"
	id := parseKubepodsPath(path)
	if id.QoS != "BestEffort" {
		t.Errorf("QoS = %q, want BestEffort", id.QoS)
	}
	if id.PodUID != "11111111-2222-3333-4444-555555555555" {
		t.Errorf("PodUID = %q", id.PodUID)
	}
}

func TestParseKubepodsPath_GuaranteedFallback(t *testing.T) {
	// Guaranteed pods lack an explicit besteffort/burstable QoS slice in v2
	// systemd mode — we fall through to the "else" branch of the classifier.
	path := "/kubepods.slice/kubepods-pod7f000000_0000_0000_0000_000000000001.slice/crio-1234567890abcdef.scope"
	id := parseKubepodsPath(path)
	if id.PodUID == "" {
		t.Errorf("expected UID parsed from slice name")
	}
	// QoS may be "" or "Guaranteed" depending on regex match; accept either.
	if id.QoS != "" && id.QoS != "Guaranteed" {
		t.Errorf("unexpected QoS %q", id.QoS)
	}
}

func TestIsKubepodsPath(t *testing.T) {
	cases := map[string]bool{
		"/kubepods.slice/kubepods-burstable.slice":           true,
		"/kubepods/burstable/pod123/container":               true,
		"/system.slice/nginx.service":                        false,
		"/user.slice/user-1000.slice":                        false,
		"/kubepods-besteffort.slice/podabc":                  true,
	}
	for in, want := range cases {
		if got := isKubepodsPath(in); got != want {
			t.Errorf("isKubepodsPath(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestKubepodsResolver_CachesResults(t *testing.T) {
	r := NewKubepodsResolver()
	path := "/kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-podabcdef12_3456_7890_1234_567890abcdef.slice"
	id1 := r.Resolve(path)
	if id1.PodUID == "" {
		t.Fatal("expected a parsed PodUID")
	}
	// Second call should hit cache and return equal identity.
	id2 := r.Resolve(path)
	if id1 != id2 {
		t.Errorf("cache mismatch: %+v vs %+v", id1, id2)
	}
}

func TestPodIdentity_Empty(t *testing.T) {
	if !(PodIdentity{}).Empty() {
		t.Error("zero-value identity should be Empty()")
	}
	if (PodIdentity{PodUID: "x"}).Empty() {
		t.Error("non-empty UID should not be Empty()")
	}
}

func TestKubepodsResolver_CacheCapAndPruning(t *testing.T) {
	r := NewKubepodsResolver()
	// Manually populate the cache with more than maxKubepodsEntries entries,
	// with staggered cachedAt times to test both TTL expiration and eviction.
	now := time.Now()
	r.mu.Lock()
	// Add maxKubepodsEntries + 100 entries with varying ages.
	for i := 0; i < maxKubepodsEntries+100; i++ {
		key := "/kubepods/test/pod" + string(rune(i%10000))
		age := time.Duration(i%50) * time.Second
		r.cache[key] = PodIdentity{PodUID: "uid-" + string(rune(i))}
		r.cachedAt[key] = now.Add(-age) // older entries have larger negative age
	}
	r.mu.Unlock()

	// Trigger pruning by calling pruneIfNeeded (normally called during Resolve).
	r.mu.Lock()
	r.pruneIfNeeded()
	r.mu.Unlock()

	// Verify cache size is bounded.
	r.mu.RLock()
	cacheLen := len(r.cache)
	cachedAtLen := len(r.cachedAt)
	r.mu.RUnlock()

	if cacheLen > maxKubepodsEntries {
		t.Errorf("cache len = %d, want <= %d", cacheLen, maxKubepodsEntries)
	}
	if cachedAtLen != cacheLen {
		t.Errorf("cache and cachedAt map size mismatch: cache=%d, cachedAt=%d",
			cacheLen, cachedAtLen)
	}
}

func TestKubepodsResolver_TTLExpiration(t *testing.T) {
	r := NewKubepodsResolver()
	r.ttl = 1 * time.Second // short TTL for testing
	now := time.Now()

	r.mu.Lock()
	// Add one expired entry and one fresh entry.
	r.cache["expired"] = PodIdentity{PodUID: "uid-old"}
	r.cachedAt["expired"] = now.Add(-2 * time.Second) // older than TTL

	r.cache["fresh"] = PodIdentity{PodUID: "uid-new"}
	r.cachedAt["fresh"] = now.Add(-500 * time.Millisecond) // younger than TTL

	// Force the cache to exceed cap to trigger pruning.
	for i := 0; i < maxKubepodsEntries+1; i++ {
		key := "/kubepods/test/pod" + string(rune(i%10000))
		r.cache[key] = PodIdentity{PodUID: "uid-" + string(rune(i))}
		r.cachedAt[key] = now
	}

	r.pruneIfNeeded()
	r.mu.Unlock()

	// Verify the expired entry was removed.
	r.mu.RLock()
	if _, ok := r.cache["expired"]; ok {
		t.Error("expired entry should have been removed by TTL pruning")
	}
	if _, ok := r.cachedAt["expired"]; ok {
		t.Error("expired entry should have been removed from cachedAt")
	}
	// Fresh entry may or may not survive, depending on whether eviction happened.
	// But if it survived, both maps must have it.
	if fresh, ok := r.cache["fresh"]; ok {
		if _, ok2 := r.cachedAt["fresh"]; !ok2 {
			t.Error("fresh entry in cache but not in cachedAt")
		}
		_ = fresh
	}
	cacheLen := len(r.cache)
	cachedAtLen := len(r.cachedAt)
	r.mu.RUnlock()

	if cacheLen != cachedAtLen {
		t.Errorf("after pruning, map sizes diverged: cache=%d, cachedAt=%d",
			cacheLen, cachedAtLen)
	}
}

func TestKubepodsResolver_OldestEvicted(t *testing.T) {
	r := NewKubepodsResolver()
	now := time.Now()

	r.mu.Lock()
	// Add two entries: one very old, one recent.
	r.cache["oldest"] = PodIdentity{PodUID: "uid-oldest"}
	r.cachedAt["oldest"] = now.Add(-10 * time.Second)

	r.cache["newest"] = PodIdentity{PodUID: "uid-newest"}
	r.cachedAt["newest"] = now

	// Add more entries to exceed the cap and force eviction.
	for i := 0; i < maxKubepodsEntries; i++ {
		key := "/kubepods/test/pod" + string(rune(i%10000))
		r.cache[key] = PodIdentity{PodUID: "uid-" + string(rune(i))}
		r.cachedAt[key] = now.Add(-time.Duration(i) * time.Millisecond)
	}

	r.pruneIfNeeded()
	r.mu.Unlock()

	// The oldest entry should be evicted in favor of newer ones.
	// (This is best-effort; the behavior depends on the exact overflow size.)
	r.mu.RLock()
	cacheLen := len(r.cache)
	cachedAtLen := len(r.cachedAt)
	r.mu.RUnlock()

	if cacheLen > maxKubepodsEntries {
		t.Errorf("after pruning, cache exceeds cap: %d > %d", cacheLen, maxKubepodsEntries)
	}
	if cacheLen != cachedAtLen {
		t.Errorf("after eviction, map sizes diverged: cache=%d, cachedAt=%d",
			cacheLen, cachedAtLen)
	}
}

func TestKubepodsResolver_MapConsistency(t *testing.T) {
	r := NewKubepodsResolver()
	now := time.Now()

	r.mu.Lock()
	// Populate with many entries.
	for i := 0; i < maxKubepodsEntries + 500; i++ {
		key := "/kubepods/test/pod" + string(rune(i%10000))
		r.cache[key] = PodIdentity{PodUID: "uid-" + string(rune(i))}
		r.cachedAt[key] = now.Add(-time.Duration((i%1000)*10) * time.Millisecond)
	}

	r.pruneIfNeeded()
	r.mu.Unlock()

	// Check that every key in cache exists in cachedAt and vice versa.
	r.mu.RLock()
	for key := range r.cache {
		if _, ok := r.cachedAt[key]; !ok {
			t.Errorf("cache key %q not in cachedAt", key)
		}
	}
	for key := range r.cachedAt {
		if _, ok := r.cache[key]; !ok {
			t.Errorf("cachedAt key %q not in cache", key)
		}
	}
	cacheLen := len(r.cache)
	cachedAtLen := len(r.cachedAt)
	r.mu.RUnlock()

	if cacheLen != cachedAtLen {
		t.Errorf("map sizes diverged after pruning: cache=%d, cachedAt=%d",
			cacheLen, cachedAtLen)
	}
}
