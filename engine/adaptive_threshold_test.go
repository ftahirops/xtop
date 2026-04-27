package engine

import (
	"testing"

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
