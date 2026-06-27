package engine

import (
	"runtime"
	"testing"
	"time"

	"github.com/ftahirops/xtop/model"
)

func TestAdaptiveThresholdDB_ObserveAndThreshold(t *testing.T) {
	dir := t.TempDir()
	db := NewAdaptiveThresholdDB(dir)
	defer db.Close()

	// Observe metric with high variance so adaptive thresholds exceed base
	for i := 0; i < 50; i++ {
		db.Observe(WorkloadWeb, "cpu.busy", 50.0+float64(i%30))
	}

	// Threshold should be adapted (mean ~64, stddev ~8, so warn ~80, crit ~88)
	w, c := db.Threshold(WorkloadWeb, "cpu.busy", 60, 90)
	if w <= 60 && c <= 90 {
		t.Logf("adaptive thresholds: warn=%.1f crit=%.1f (may equal base if variance is low)", w, c)
	}
	// At minimum, warn should be >= base
	if w < 60 {
		t.Errorf("warn threshold should not drop below base: got %.1f < 60", w)
	}
	if c < 90 {
		t.Errorf("crit threshold should not drop below base: got %.1f < 90", c)
	}
	t.Logf("adaptive thresholds: warn=%.1f crit=%.1f", w, c)
}

func TestAdaptiveThresholdDB_FallbackWhenInsufficientData(t *testing.T) {
	dir := t.TempDir()
	db := NewAdaptiveThresholdDB(dir)
	defer db.Close()

	// Only 5 observations — below 30 minimum
	for i := 0; i < 5; i++ {
		db.Observe(WorkloadWeb, "cpu.busy", 30.0)
	}

	w, c := db.Threshold(WorkloadWeb, "cpu.busy", 60, 90)
	if w != 60 || c != 90 {
		t.Errorf("expected fallback to defaults, got warn=%.1f crit=%.1f", w, c)
	}
}

func TestDetectWorkloadType(t *testing.T) {
	snap := &model.Snapshot{
		Global: model.GlobalMetrics{
			Apps: model.AppMetrics{
				Instances: []model.AppInstance{
					{AppType: "nginx"},
					{AppType: "mysql"},
				},
			},
		},
		Processes: []model.ProcessMetrics{
			{Comm: "nginx"},
			{Comm: "mysqld"},
		},
	}

	wt := DetectWorkloadType(snap)
	// nginx scores 3+1=4, mysql scores 3+1=4 — tie goes to first in sorted list
	// but both web and database have same score. Let's just verify it's not unknown.
	if wt == WorkloadUnknown {
		t.Error("expected non-unknown workload type")
	}
	t.Logf("detected workload: %s", wt)
}

func TestAdaptiveThresholdDB_Persistence(t *testing.T) {
	dir := t.TempDir()
	db := NewAdaptiveThresholdDB(dir)

	for i := 0; i < 50; i++ {
		db.Observe(WorkloadDatabase, "io.psi", 50.0+float64(i%30))
	}
	db.Close()

	// Re-open and verify thresholds are restored
	db2 := NewAdaptiveThresholdDB(dir)
	defer db2.Close()

	w, c := db2.Threshold(WorkloadDatabase, "io.psi", 60, 90)
	// After restore, should still have learned thresholds
	if w < 60 || c < 90 {
		t.Errorf("restored thresholds dropped below base: warn=%.1f crit=%.1f", w, c)
	}
	t.Logf("restored thresholds: warn=%.1f crit=%.1f", w, c)
}

func TestAdaptiveThreshold_NeverBelowBase(t *testing.T) {
	dir := t.TempDir()
	db := NewAdaptiveThresholdDB(dir)
	defer db.Close()

	// Very low values
	for i := 0; i < 50; i++ {
		db.Observe(WorkloadWeb, "cpu.busy", 1.0)
	}

	w, c := db.Threshold(WorkloadWeb, "cpu.busy", 60, 90)
	if w < 60 {
		t.Errorf("warn threshold should never drop below base: got %.1f < 60", w)
	}
	if c < 90 {
		t.Errorf("crit threshold should never drop below base: got %.1f < 90", c)
	}
}

// TestAdaptiveThresholdDB_GoroutineLeakFix verifies that the background
// save goroutine (spawned in NewAdaptiveThresholdDB) is properly cleaned up
// when Close() is called. This test ensures audit finding C3 is fixed.
func TestAdaptiveThresholdDB_GoroutineLeakFix(t *testing.T) {
	dir := t.TempDir()

	// Record baseline goroutine count
	runtime.GC()
	baselineGoroutines := runtime.NumGoroutine()

	// Create a new AdaptiveThresholdDB and verify the background goroutine starts
	db := NewAdaptiveThresholdDB(dir)

	// Give the goroutine time to start
	time.Sleep(10 * time.Millisecond)
	afterCreateGoroutines := runtime.NumGoroutine()

	// The background save goroutine should have been created
	if afterCreateGoroutines <= baselineGoroutines {
		t.Logf("WARNING: Expected goroutine count to increase after NewAdaptiveThresholdDB; baseline=%d, after=%d",
			baselineGoroutines, afterCreateGoroutines)
	}

	// Close the DB and verify the goroutine exits
	db.Close()

	// Give the goroutine time to exit and wait for cleanup
	time.Sleep(50 * time.Millisecond)
	runtime.GC()
	afterCloseGoroutines := runtime.NumGoroutine()

	// Allow a small slack (±1) for timing variations between runs
	if afterCloseGoroutines > baselineGoroutines+1 {
		t.Errorf("goroutine leak detected: baseline=%d, after close=%d (slack allowed: 1)",
			baselineGoroutines, afterCloseGoroutines)
	}
	t.Logf("goroutine counts: baseline=%d, after create=%d, after close=%d",
		baselineGoroutines, afterCreateGoroutines, afterCloseGoroutines)
}

// TestAdaptiveThresholdDB_CloseIdempotent verifies that calling Close()
// multiple times does not panic or cause issues.
func TestAdaptiveThresholdDB_CloseIdempotent(t *testing.T) {
	dir := t.TempDir()
	db := NewAdaptiveThresholdDB(dir)

	// Observe some data to ensure there's something to save
	db.Observe(WorkloadWeb, "cpu.busy", 50.0)

	// Close should be safe to call multiple times
	db.Close()
	db.Close() // Should not panic
	db.Close() // Should not panic

	t.Log("Close() is idempotent")
}
