package engine

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/ftahirops/xtop/model"
)

// writeLog is a tiny helper so tests read as "given this log, expect that hint".
func writeLog(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

// buildLogTailerFor points a fresh tailer at a synthetic log path so tests
// never touch /var/log. Rate-limit is turned off so scans happen on every
// Observe call.
func buildLogTailerFor(t *testing.T, app string, paths []string) *LogTailer {
	t.Helper()
	re := regexp.MustCompile(`(?i)\b(error|slow query|timeout|oom|warning|fatal)\b`)
	return &LogTailer{
		rateLimit:   0,
		maxLinesPer: 5,
		maxPerTick:  100 * 1000 * 1000,
		lastScan:    make(map[string]time.Time),
		watches: map[string]appLogConfig{
			app: {
				Aliases:  []string{app},
				Paths:    paths,
				Severity: re,
			},
		},
	}
}

func mkAppIncident(app, process string) *model.AnalysisResult {
	return &model.AnalysisResult{
		Health:            model.HealthDegraded,
		PrimaryBottleneck: "io",
		PrimaryProcess:    process,
		PrimaryAppName:    app,
	}
}

func TestLogTailer_MatchesSeverityLinesOnly(t *testing.T) {
	path := filepath.Join(t.TempDir(), "error.log")
	writeLog(t, path, strings.Join([]string{
		"2026-04-19 14:02:00 [Note] everything is fine",
		"2026-04-19 14:02:01 [Warning] slow query took 5.2s: SELECT * FROM huge_table",
		"2026-04-19 14:02:02 [Note] another fine thing",
		"2026-04-19 14:02:03 [ERROR] Too many connections",
		"2026-04-19 14:02:04 [Note] still fine",
	}, "\n")+"\n")

	tl := buildLogTailerFor(t, "mysql", []string{path})
	excerpts := tl.Observe(mkAppIncident("mysql", "mysqld"))
	if len(excerpts) != 2 {
		t.Fatalf("expected 2 excerpts (slow + error), got %d: %+v", len(excerpts), excerpts)
	}
	// Most-recent-first order → "Too many connections" should come last because
	// the file tail is read in order; we keep the last N matches.
	got := excerpts[len(excerpts)-1].Line
	if !strings.Contains(got, "Too many connections") {
		t.Errorf("tail excerpt = %q, want it to contain 'Too many connections'", got)
	}
}

func TestLogTailer_SkipsWhenCulpritDoesNotMatch(t *testing.T) {
	path := filepath.Join(t.TempDir(), "error.log")
	writeLog(t, path, "ERROR very bad\n")
	tl := buildLogTailerFor(t, "mysql", []string{path})
	// Incident from nginx — no mysql alias hit, so tailer must return nil.
	if got := tl.Observe(mkAppIncident("nginx", "nginx")); got != nil {
		t.Errorf("expected nil when culprit app != watch app, got %+v", got)
	}
}

func TestLogTailer_SkipsWhenHealthy(t *testing.T) {
	path := filepath.Join(t.TempDir(), "error.log")
	writeLog(t, path, "ERROR\n")
	tl := buildLogTailerFor(t, "mysql", []string{path})
	healthy := &model.AnalysisResult{Health: model.HealthOK, PrimaryAppName: "mysql"}
	if got := tl.Observe(healthy); got != nil {
		t.Errorf("expected nil when health is OK, got %+v", got)
	}
}

func TestLogTailer_RateLimited(t *testing.T) {
	path := filepath.Join(t.TempDir(), "error.log")
	writeLog(t, path, "ERROR boom\n")
	tl := buildLogTailerFor(t, "mysql", []string{path})
	tl.rateLimit = 10 * time.Second
	inc := mkAppIncident("mysql", "mysqld")
	if got := tl.Observe(inc); len(got) == 0 {
		t.Fatalf("first call should return excerpts, got %+v", got)
	}
	if got := tl.Observe(inc); got != nil {
		t.Errorf("second call within rate-limit window should return nil, got %+v", got)
	}
}

func TestDetectSeverity(t *testing.T) {
	cases := map[string]string{
		"ERROR failed":               "ERROR",
		"WARNING something":          "WARN",
		"FATAL panic happened":       "FATAL",
		"slow query detected":        "SLOW",
		"out of memory killed":       "OOM",
		"connection timed out":       "SLOW",
		"just a normal info line":    "",
	}
	for line, want := range cases {
		if got := detectSeverity(line); got != want {
			t.Errorf("detectSeverity(%q) = %q, want %q", line, got, want)
		}
	}
}

func TestStripANSI(t *testing.T) {
	in := "\x1b[31mred error\x1b[0m occurred"
	got := stripANSI(in)
	if got != "red error occurred" {
		t.Errorf("stripANSI = %q, want 'red error occurred'", got)
	}
}

func TestClampLine(t *testing.T) {
	long := strings.Repeat("x", 300)
	got := clampLine(long, 240)
	if len([]rune(got)) != 241 { // 240 chars + ellipsis
		t.Errorf("clamp len = %d, want 241 runes (240 + ellipsis)", len([]rune(got)))
	}
	if !strings.HasSuffix(got, "…") {
		t.Error("expected trailing ellipsis")
	}
	short := "short"
	if clampLine(short, 240) != short {
		t.Error("short lines should pass through unchanged")
	}
}

func TestFormatLogExcerptHint(t *testing.T) {
	excerpts := []model.LogExcerpt{
		{App: "mysql", Path: "/var/log/mysql/error.log",
			Line: "[ERROR] Too many connections", Severity: "ERROR"},
		{App: "mysql", Path: "/var/log/mysql/error.log",
			Line: "[Warning] slow query", Severity: "WARN"},
	}
	got := formatLogExcerptHint(excerpts)
	if !strings.HasPrefix(got, "ERROR from mysql @ mysql/error.log: ") {
		t.Errorf("hint prefix wrong: %q", got)
	}
	if !strings.Contains(got, "+1 more") {
		t.Errorf("hint should mention +1 more, got %q", got)
	}
}

func TestShortPath(t *testing.T) {
	if got := shortPath("/var/log/mysql/error.log"); got != "mysql/error.log" {
		t.Errorf("shortPath = %q, want mysql/error.log", got)
	}
	if got := shortPath("journal://mysql.service"); got != "journal://mysql.service" {
		t.Errorf("journal URLs should pass through unchanged, got %q", got)
	}
	if got := shortPath("short.log"); got != "short.log" {
		t.Errorf("single-component paths pass through, got %q", got)
	}
}
