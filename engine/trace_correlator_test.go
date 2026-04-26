package engine

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ftahirops/xtop/model"
)

// tmpCorrelator builds a TraceCorrelator pointing at a temp JSONL file, with
// polling disabled so tests can drive it synchronously.
func tmpCorrelator(t *testing.T) (*TraceCorrelator, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "otel.jsonl")
	c := &TraceCorrelator{
		path:        path,
		minDuration: 100 * time.Millisecond,
		maxKeep:     500,
		pollEvery:   0, // every refresh checks the file
	}
	return c, path
}

func writeSamples(t *testing.T, path string, samples []model.TraceSample) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	for _, s := range samples {
		if err := enc.Encode(&s); err != nil {
			t.Fatal(err)
		}
	}
}

func TestTraceCorrelator_ReadsAndPicksErroredFirst(t *testing.T) {
	c, path := tmpCorrelator(t)
	now := time.Now()
	writeSamples(t, path, []model.TraceSample{
		{TraceID: "slow", Service: "api", Operation: "GET /x",
			DurationMs: 2000, StatusCode: "OK", StartTime: now.Add(-30 * time.Second)},
		{TraceID: "err", Service: "api", Operation: "GET /y",
			DurationMs: 800, StatusCode: "ERROR", StartTime: now.Add(-20 * time.Second)},
	})
	got := c.Observe(&model.AnalysisResult{
		Health:            model.HealthDegraded,
		PrimaryAppName:    "api",
		PrimaryBottleneck: "cpu",
	})
	if len(got) != 2 {
		t.Fatalf("expected 2 samples, got %d", len(got))
	}
	if got[0].TraceID != "err" {
		t.Errorf("errored trace should come first, got %s", got[0].TraceID)
	}
}

func TestTraceCorrelator_FiltersByMinDuration(t *testing.T) {
	c, path := tmpCorrelator(t)
	writeSamples(t, path, []model.TraceSample{
		{TraceID: "fast", DurationMs: 10, Service: "api", StartTime: time.Now()},
		{TraceID: "slow", DurationMs: 500, Service: "api", StartTime: time.Now()},
	})
	got := c.Observe(&model.AnalysisResult{Health: model.HealthDegraded, PrimaryAppName: "api"})
	if len(got) != 1 || got[0].TraceID != "slow" {
		t.Errorf("expected only 'slow', got %+v", got)
	}
}

func TestTraceCorrelator_ScopesToCulpritService(t *testing.T) {
	c, path := tmpCorrelator(t)
	writeSamples(t, path, []model.TraceSample{
		{TraceID: "a", Service: "api", DurationMs: 200, StartTime: time.Now()},
		{TraceID: "b", Service: "billing", DurationMs: 300, StartTime: time.Now()},
	})
	got := c.Observe(&model.AnalysisResult{Health: model.HealthDegraded, PrimaryAppName: "api"})
	if len(got) != 1 || got[0].Service != "api" {
		t.Errorf("expected only api-scoped sample, got %+v", got)
	}
}

func TestTraceCorrelator_ReturnsNilWhenHealthy(t *testing.T) {
	c, path := tmpCorrelator(t)
	writeSamples(t, path, []model.TraceSample{
		{TraceID: "x", DurationMs: 500, Service: "api", StartTime: time.Now()},
	})
	got := c.Observe(&model.AnalysisResult{Health: model.HealthOK})
	if got != nil {
		t.Errorf("expected nil when healthy, got %+v", got)
	}
}

func TestTraceCorrelator_IgnoresMissingFile(t *testing.T) {
	c := &TraceCorrelator{
		path:        filepath.Join(t.TempDir(), "does-not-exist.jsonl"),
		minDuration: 100 * time.Millisecond,
		maxKeep:     500,
		pollEvery:   0,
	}
	got := c.Observe(&model.AnalysisResult{Health: model.HealthDegraded})
	if got != nil {
		t.Errorf("expected nil when feed file missing, got %+v", got)
	}
}

func TestFmtMs(t *testing.T) {
	cases := map[float64]string{
		0.5:    "0.50ms",
		45:     "45ms",
		1234:   "1.23s",
		12000:  "12.00s",
	}
	for in, want := range cases {
		if got := fmtMs(in); got != want {
			t.Errorf("fmtMs(%v) = %q, want %q", in, got, want)
		}
	}
}
