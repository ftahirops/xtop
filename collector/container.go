package collector

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"
)

// ContainerResolver maps cgroup paths to human-readable container names.
type ContainerResolver struct {
	mu       sync.RWMutex
	cache    map[string]string // shortID → name
	lastLoad time.Time
	ttl      time.Duration
	client   *http.Client
}

// NewContainerResolver creates a resolver that queries the Docker socket.
func NewContainerResolver() *ContainerResolver {
	return &ContainerResolver{
		cache: make(map[string]string),
		ttl:   30 * time.Second,
		client: &http.Client{
			Transport: &http.Transport{
				DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
					return net.DialTimeout("unix", "/var/run/docker.sock", 2*time.Second)
				},
			},
			Timeout: 3 * time.Second,
		},
	}
}

var containerIDRegex = regexp.MustCompile(`(?:docker|containerd|cri-containerd|cri-o)-([a-f0-9]{12,64})`)

// Resolve takes a cgroup name and returns a human-readable name.
// If it's a container, returns the container name instead of the hash.
func (cr *ContainerResolver) Resolve(cgroupName string) string {
	matches := containerIDRegex.FindStringSubmatch(cgroupName)
	if len(matches) < 2 {
		return cgroupName
	}
	cid := matches[1]
	shortID := cid
	if len(shortID) > 12 {
		shortID = shortID[:12]
	}

	cr.mu.RLock()
	if name, ok := cr.cache[shortID]; ok {
		cr.mu.RUnlock()
		return name
	}
	cr.mu.RUnlock()

	cr.mu.Lock()
	defer cr.mu.Unlock()

	if name, ok := cr.cache[shortID]; ok {
		return name
	}

	if time.Since(cr.lastLoad) > cr.ttl {
		cr.loadContainers()
	}

	if name, ok := cr.cache[shortID]; ok {
		return name
	}
	return fmt.Sprintf("container:%s", shortID)
}

type dockerContainerInfo struct {
	ID    string   `json:"Id"`
	Names []string `json:"Names"`
}

func (cr *ContainerResolver) loadContainers() {
	cr.lastLoad = time.Now()
	resp, err := cr.client.Get("http://localhost/containers/json?all=true")
	if err != nil {
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return
	}
	var containers []dockerContainerInfo
	if err := json.NewDecoder(resp.Body).Decode(&containers); err != nil {
		return
	}
	for _, c := range containers {
		shortID := c.ID
		if len(shortID) > 12 {
			shortID = shortID[:12]
		}
		name := shortID
		if len(c.Names) > 0 {
			name = strings.TrimPrefix(c.Names[0], "/")
		}
		cr.cache[shortID] = name
	}
}
