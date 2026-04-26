package engine

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ftahirops/xtop/model"
)

// mkDetector returns a ConfigDriftDetector rooted at a fresh temp dir with
// its baseline disk path pointed at a temp file too. This keeps tests
// hermetic — they never touch the real /etc or ~/.xtop.
func mkDetector(t *testing.T, patterns []string) (*ConfigDriftDetector, string) {
	t.Helper()
	baseDir := t.TempDir()
	d := &ConfigDriftDetector{
		baseline:     make(map[string]fileFingerprint),
		baselinePath: filepath.Join(t.TempDir(), "baseline.json"),
		scanEvery:    0, // every call to Tick() scans
		recentTTL:    time.Hour,
		patterns:     patterns,
	}
	return d, baseDir
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestConfigDrift_FirstRunEstablishesBaselineSilently(t *testing.T) {
	_, dir := mkDetector(t, nil)
	f := filepath.Join(dir, "nginx.conf")
	writeFile(t, f, "worker_processes 4;")

	d, _ := mkDetector(t, []string{f})
	events := d.Tick()

	// The very first scan on an EMPTY baseline should not flood the operator
	// with "added" events — the watchlist is captured as the reference point.
	if len(events) != 0 {
		t.Fatalf("first-run scan should emit no events, got %d: %+v", len(events), events)
	}
	if _, ok := d.baseline[f]; !ok {
		t.Fatalf("baseline should record %q after first scan", f)
	}
}

func TestConfigDrift_DetectsModification(t *testing.T) {
	_, dir := mkDetector(t, nil)
	f := filepath.Join(dir, "redis.conf")
	writeFile(t, f, "maxmemory 100mb\n")

	d, _ := mkDetector(t, []string{f})
	_ = d.Tick() // prime baseline

	// Modify the file — sleep enough for mtime to tick on filesystems with
	// coarse resolution.
	time.Sleep(10 * time.Millisecond)
	writeFile(t, f, "maxmemory 500mb\n")

	events := d.Tick()
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d: %+v", len(events), events)
	}
	if events[0].Type != "config_modified" || events[0].Detail != f {
		t.Errorf("unexpected event: %+v", events[0])
	}
}

func TestConfigDrift_DetectsRemoval(t *testing.T) {
	_, dir := mkDetector(t, nil)
	f := filepath.Join(dir, "postgresql.conf")
	writeFile(t, f, "shared_buffers = 256MB\n")

	d, _ := mkDetector(t, []string{f})
	_ = d.Tick() // prime baseline

	if err := os.Remove(f); err != nil {
		t.Fatal(err)
	}
	events := d.Tick()
	if len(events) != 1 || events[0].Type != "config_removed" {
		t.Fatalf("expected 1 config_removed, got %+v", events)
	}
}

func TestConfigDrift_BaselinePersistsAcrossInstances(t *testing.T) {
	_, dir := mkDetector(t, nil)
	f := filepath.Join(dir, "my.cnf")
	writeFile(t, f, "[mysqld]\nmax_connections = 500\n")

	baselinePath := filepath.Join(t.TempDir(), "baseline.json")
	d1 := &ConfigDriftDetector{
		baseline:     make(map[string]fileFingerprint),
		baselinePath: baselinePath,
		scanEvery:    0,
		recentTTL:    time.Hour,
		patterns:     []string{f},
	}
	_ = d1.Tick() // emits nothing, writes baseline to disk

	// New detector instance reads the persisted baseline — a file
	// modification should still be detected.
	time.Sleep(10 * time.Millisecond)
	writeFile(t, f, "[mysqld]\nmax_connections = 1000\n")

	d2 := &ConfigDriftDetector{
		baseline:     make(map[string]fileFingerprint),
		baselinePath: baselinePath,
		scanEvery:    0,
		recentTTL:    time.Hour,
		patterns:     []string{f},
	}
	d2.loadBaseline()
	events := d2.Tick()
	if len(events) != 1 || events[0].Type != "config_modified" {
		t.Fatalf("expected persisted baseline to enable modification detection; got %+v", events)
	}
}

func TestConfigDrift_RecentWithinReturnsOnlyWindowed(t *testing.T) {
	d := &ConfigDriftDetector{recentTTL: time.Hour}
	now := time.Now()
	d.recent = []model.SystemChange{
		{Type: "config_modified", Detail: "/etc/old.conf", When: now.Add(-2 * time.Hour)},
		{Type: "config_modified", Detail: "/etc/recent.conf", When: now.Add(-5 * time.Minute)},
		{Type: "config_modified", Detail: "/etc/future.conf", When: now.Add(10 * time.Minute)},
	}
	out := d.RecentWithin(now, 15*time.Minute)
	if len(out) != 2 {
		t.Fatalf("expected 2 events in a 15m window, got %d: %+v", len(out), out)
	}
	seen := map[string]bool{}
	for _, e := range out {
		seen[e.Detail] = true
	}
	if !seen["/etc/recent.conf"] || !seen["/etc/future.conf"] {
		t.Errorf("window should include recent and future-within-window entries, got %+v", out)
	}
	if seen["/etc/old.conf"] {
		t.Error("2h-old event should be excluded from 15m window")
	}
}

func TestFormatConfigDriftHint(t *testing.T) {
	now := time.Now()
	events := []model.SystemChange{
		{Type: "config_modified", Detail: "/etc/nginx/nginx.conf", When: now.Add(-8 * time.Minute)},
		{Type: "config_modified", Detail: "/etc/systemd/system/app.service", When: now.Add(-3 * time.Minute)},
	}
	hint := formatConfigDriftHint(events)
	if hint == "" {
		t.Fatal("expected non-empty hint")
	}
	// The most recent event should drive the displayed path + age.
	if !contains(hint, "/etc/systemd/system/app.service") {
		t.Errorf("hint should surface the most recent file, got %q", hint)
	}
	if !contains(hint, "+1 more") {
		t.Errorf("hint should mention the +1 more count, got %q", hint)
	}
}

func TestFormatConfigDriftHint_IgnoresXtopState(t *testing.T) {
	events := []model.SystemChange{
		{Type: "config_modified", Detail: "/root/.xtop/something.json", When: time.Now()},
	}
	if got := formatConfigDriftHint(events); got != "" {
		t.Errorf("xtop-internal changes must be filtered out, got %q", got)
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
