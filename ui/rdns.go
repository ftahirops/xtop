package ui

import (
	"bufio"
	"context"
	"net"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

var rdnsCache = struct {
	sync.RWMutex
	entries map[string]rdnsCacheEntry
}{entries: make(map[string]rdnsCacheEntry)}

type rdnsCacheEntry struct {
	name    string
	expires time.Time
}

const rdnsTTL = 5 * time.Minute

// maxRDNS is the upper bound on the number of entries the rdns cache may hold.
// When exceeded, expired entries are purged first; if still over, the oldest
// entries (earliest expires) are dropped until the map is at or under the cap.
const maxRDNS = 2048

// rdnsPruneIfNeeded must be called under rdnsCache.Lock (write lock).
// It is a no-op when len(entries) <= maxRDNS.
func rdnsPruneIfNeeded() {
	if len(rdnsCache.entries) <= maxRDNS {
		return
	}
	// First pass: remove entries whose TTL has expired.
	now := time.Now()
	for k, e := range rdnsCache.entries {
		if now.After(e.expires) {
			delete(rdnsCache.entries, k)
		}
	}
	// Second pass: if still over cap, evict the oldest entries (earliest expiry)
	// in one sorted pass to avoid O(n^2) map iteration.
	if excess := len(rdnsCache.entries) - maxRDNS; excess > 0 {
		type kv struct {
			key     string
			expires time.Time
		}
		pairs := make([]kv, 0, len(rdnsCache.entries))
		for k, e := range rdnsCache.entries {
			pairs = append(pairs, kv{k, e.expires})
		}
		sort.Slice(pairs, func(i, j int) bool {
			return pairs[i].expires.Before(pairs[j].expires)
		})
		for _, p := range pairs[:excess] {
			delete(rdnsCache.entries, p.key)
		}
	}
}

var hostsMap = struct {
	sync.Once
	m map[string]string
}{}

func loadHostsFile() map[string]string {
	m := make(map[string]string)
	f, err := os.Open("/etc/hosts")
	if err != nil {
		return m
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		if _, exists := m[fields[0]]; !exists {
			m[fields[0]] = fields[1]
		}
	}
	return m
}

func getHostsMap() map[string]string {
	hostsMap.Do(func() {
		hostsMap.m = loadHostsFile()
	})
	return hostsMap.m
}

// resolveIP returns "hostname (IP)" if resolvable, or just the original string if not.
func resolveIP(ip string) string {
	if ip == "" {
		return ip
	}
	host := ip
	port := ""
	if idx := strings.LastIndex(ip, ":"); idx > 0 {
		if !strings.Contains(ip, "[") && strings.Count(ip, ":") == 1 {
			host = ip[:idx]
			port = ip[idx:]
		}
	}

	name := rdnsLookup(host)
	if name == "" || name == host {
		return ip // no resolution — just show IP
	}
	if port != "" {
		return name + " (" + host + ")" + port
	}
	return name + " (" + host + ")"
}

func rdnsLookup(ip string) string {
	rdnsCache.RLock()
	if e, ok := rdnsCache.entries[ip]; ok && time.Now().Before(e.expires) {
		rdnsCache.RUnlock()
		return e.name
	}
	rdnsCache.RUnlock()

	// /etc/hosts first
	if h, ok := getHostsMap()[ip]; ok {
		rdnsCache.Lock()
		rdnsCache.entries[ip] = rdnsCacheEntry{name: h, expires: time.Now().Add(rdnsTTL)}
		rdnsPruneIfNeeded()
		rdnsCache.Unlock()
		return h
	}

	// Reverse DNS
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	var name string
	names, err := net.DefaultResolver.LookupAddr(ctx, ip)
	if err == nil && len(names) > 0 {
		name = strings.TrimSuffix(names[0], ".")
	} else {
		name = ip // no PTR — return IP as-is
	}

	rdnsCache.Lock()
	rdnsCache.entries[ip] = rdnsCacheEntry{name: name, expires: time.Now().Add(rdnsTTL)}
	rdnsPruneIfNeeded()
	rdnsCache.Unlock()
	return name
}
