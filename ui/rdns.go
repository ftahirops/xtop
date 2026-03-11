package ui

import (
	"bufio"
	"context"
	"net"
	"os"
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
	rdnsCache.Unlock()
	return name
}
