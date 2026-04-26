package engine

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/ftahirops/xtop/model"
)

// fmtMs renders trace durations as a short, human-scannable string ("1.2s",
// "450ms"). Used for narrative-evidence lines so they fit in one line.
func fmtMs(ms float64) string {
	switch {
	case ms >= 1000:
		return fmt.Sprintf("%.2fs", ms/1000)
	case ms >= 1:
		return fmt.Sprintf("%.0fms", ms)
	default:
		return fmt.Sprintf("%.2fms", ms)
	}
}

// TraceCorrelator tails a simple JSONL feed of OpenTelemetry trace summaries
// and returns samples that overlap the current incident window.
//
// Why a file feed instead of OTLP: shipping an OTLP receiver inside xtop
// would pull a heavy dependency tree (otel-collector, grpc, protobuf) that
// most operators don't need. A single JSONL file any collector pipeline can
// produce is sustainably portable — we stay a tiny binary and operators
// pick whichever OTel backend they already run.
//
// Feed file (default ~/.xtop/otel-samples.jsonl, overridable via
// $XTOP_OTEL_SAMPLES_FILE): one TraceSample JSON per line, appended by the
// operator's OTel collector. Lines older than 2 h are ignored. A sensible
// minimal recipe — using the otel-collector `file` exporter — is documented
// in packaging/otel/README.md.
type TraceCorrelator struct {
	mu          sync.Mutex
	path        string
	minDuration time.Duration // only keep spans longer than this (noise filter)
	maxKeep     int           // cap of samples held in memory
	recent      []model.TraceSample
	offset      int64 // last-read byte offset into the file
	lastSize    int64
	lastPoll    time.Time
	pollEvery   time.Duration
}

// NewTraceCorrelator returns a correlator with defaults. If the feed file
// doesn't exist we simply hold an empty sample set and stay cheap; no error,
// because the feed is fundamentally optional.
func NewTraceCorrelator() *TraceCorrelator {
	path := os.Getenv("XTOP_OTEL_SAMPLES_FILE")
	if path == "" {
		home, _ := os.UserHomeDir()
		path = filepath.Join(home, ".xtop", "otel-samples.jsonl")
	}
	return &TraceCorrelator{
		path:        path,
		minDuration: 100 * time.Millisecond,
		maxKeep:     500,
		pollEvery:   5 * time.Second,
	}
}

// Flush drops the in-memory ring of cached samples + resets the read
// offset so the next refresh re-tails from current EOF. Called by the
// Guardian under memory pressure. Cheap.
func (c *TraceCorrelator) Flush() {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.recent = nil
	c.offset = 0
	c.lastSize = 0
}

// Observe returns trace samples that overlap the incident's current window.
// Returns nil when the feed file is absent / unreadable — silent because
// OTel correlation is an optional feature.
func (c *TraceCorrelator) Observe(result *model.AnalysisResult) []model.TraceSample {
	if c == nil || result == nil || result.Health == model.HealthOK {
		return nil
	}
	c.refreshIfNeeded()

	c.mu.Lock()
	if len(c.recent) == 0 {
		c.mu.Unlock()
		return nil
	}
	// Filter to the last 2 min — the incident is by definition happening now.
	cutoff := time.Now().Add(-2 * time.Minute)
	var matches []model.TraceSample
	for _, s := range c.recent {
		if s.StartTime.Before(cutoff) {
			continue
		}
		matches = append(matches, s)
	}
	c.mu.Unlock()

	// Prefer errored traces, then by duration descending.
	sort.Slice(matches, func(i, j int) bool {
		ei := matches[i].StatusCode == "ERROR"
		ej := matches[j].StatusCode == "ERROR"
		if ei != ej {
			return ei // errored traces first
		}
		return matches[i].DurationMs > matches[j].DurationMs
	})
	// Cap at top 5 — the UI shouldn't be flooded.
	if len(matches) > 5 {
		matches = matches[:5]
	}
	// When culprit app is known, narrow further to matching services.
	if app := strings.ToLower(result.PrimaryAppName); app != "" {
		scoped := matches[:0]
		for _, s := range matches {
			if s.Service == "" || strings.Contains(strings.ToLower(s.Service), app) {
				scoped = append(scoped, s)
			}
		}
		// Only use the narrowed set if it kept at least one sample — a miss
		// means the culprit doesn't match any OTel service, in which case
		// showing the most recent traces regardless is still useful.
		if len(scoped) > 0 {
			matches = scoped
		}
	}
	return matches
}

// refreshIfNeeded tails the JSONL feed at most once per pollEvery. Handles
// file truncation (OTel collectors rotate) by resetting the offset.
func (c *TraceCorrelator) refreshIfNeeded() {
	c.mu.Lock()
	if time.Since(c.lastPoll) < c.pollEvery {
		c.mu.Unlock()
		return
	}
	c.lastPoll = time.Now()
	offset := c.offset
	c.mu.Unlock()

	info, err := os.Stat(c.path)
	if err != nil {
		return
	}

	if info.Size() < offset {
		// File truncated / rotated — start from 0.
		offset = 0
	}
	if info.Size() == offset {
		return // nothing new
	}
	f, err := os.Open(c.path)
	if err != nil {
		return
	}
	defer f.Close()
	if _, err := f.Seek(offset, 0); err != nil {
		return
	}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)

	var added []model.TraceSample
	for sc.Scan() {
		var s model.TraceSample
		if err := json.Unmarshal(sc.Bytes(), &s); err != nil {
			continue
		}
		if c.minDuration > 0 && s.DurationMs < float64(c.minDuration/time.Millisecond) {
			continue
		}
		added = append(added, s)
	}

	c.mu.Lock()
	c.offset = info.Size()
	c.lastSize = info.Size()
	c.recent = append(c.recent, added...)
	// Drop anything older than 2 h and cap the ring.
	cutoff := time.Now().Add(-2 * time.Hour)
	kept := c.recent[:0]
	for _, s := range c.recent {
		if s.StartTime.After(cutoff) {
			kept = append(kept, s)
		}
	}
	if len(kept) > c.maxKeep {
		kept = kept[len(kept)-c.maxKeep:]
	}
	c.recent = kept
	c.mu.Unlock()
}
