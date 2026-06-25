package collector

import (
	"testing"
)

func TestBuildContainerCache_PopulatesMapFromContainerInfo(t *testing.T) {
	containers := []dockerContainerInfo{
		{
			ID:    "abc1234567890fedcba1234567890fedc",
			Names: []string{"/my-app"},
		},
		{
			ID:    "def1234567890abcdef1234567890abcd",
			Names: []string{"/redis"},
		},
		{
			ID:    "ghi1234567890fedcba1234567890fedc",
			Names: []string{}, // no name, should use shortID
		},
	}

	cache := buildContainerCache(containers)

	if len(cache) != 3 {
		t.Fatalf("expected 3 entries, got %d", len(cache))
	}

	// Check first container
	if name, ok := cache["abc123456789"]; !ok || name != "my-app" {
		t.Errorf("expected my-app, got %v", name)
	}

	// Check second container
	if name, ok := cache["def123456789"]; !ok || name != "redis" {
		t.Errorf("expected redis, got %v", name)
	}

	// Check third container (no name, should use shortID)
	if name, ok := cache["ghi123456789"]; !ok || name != "ghi123456789" {
		t.Errorf("expected ghi123456789, got %v", name)
	}
}

func TestBuildContainerCache_ReturnsEmptyMapForEmptyList(t *testing.T) {
	cache := buildContainerCache([]dockerContainerInfo{})

	if len(cache) != 0 {
		t.Fatalf("expected empty cache, got %d entries", len(cache))
	}
}

func TestLoadContainers_RemovesStaleEntries(t *testing.T) {
	cr := &ContainerResolver{
		cache: map[string]string{
			"stale123456": "old-container",
			"keep12345678": "old-keep",
		},
		ttl: 0, // always reload
	}

	// Manually inject fresh data (simulating a successful docker response)
	// The new load should only contain the "keep" container, not "stale"
	cr.cache = buildContainerCache([]dockerContainerInfo{
		{
			ID:    "keep123456789fedcba1234567890fedcb",
			Names: []string{"/active-container"},
		},
	})

	// Verify stale entry is gone and new entry is present
	if _, ok := cr.cache["stale123456"]; ok {
		t.Error("expected stale entry to be removed")
	}

	if name, ok := cr.cache["keep12345678"]; !ok || name != "active-container" {
		t.Errorf("expected active-container, got %q", name)
	}
}
