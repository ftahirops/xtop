package engine

import (
	"testing"

	"github.com/ftahirops/xtop/config"
)

// TestResolveRCAThresholds_DefaultPreservation verifies that a zero-value
// config.RCAThresholds resolves to the compiled-in const defaults.  This is
// the critical behavior-unchanged-by-default guarantee.
func TestResolveRCAThresholds_DefaultPreservation(t *testing.T) {
	got := resolveRCAThresholds(config.RCAThresholds{})

	cases := []struct {
		name string
		got  float64
		want float64
	}{
		{"ScoreCritical", float64(got.ScoreCritical), rcaScoreCritical},
		{"ScoreDegraded", float64(got.ScoreDegraded), rcaScoreDegraded},
		{"ScoreFloor", float64(got.ScoreFloor), rcaScoreFloor},
		{"MinIOPSForLatency", got.MinIOPSForLatency, minIOPSForLatency},
		{"IoFsFullFreePct", got.IoFsFullFreePct, ioFsFullFreePct},
		{"IoDstateBumpScore", float64(got.IoDstateBumpScore), ioDstateBumpScore},
		{"MemOOMMinScore", float64(got.MemOOMMinScore), memOOMMinScore},
		{"MemSafeAvailPct", got.MemSafeAvailPct, memSafeAvailPct},
		{"CpuSafeBusyPct", got.CpuSafeBusyPct, cpuSafeBusyPct},
		{"JvmHeapPressurePct", got.JvmHeapPressurePct, jvmHeapPressurePct},
	}
	for _, tc := range cases {
		if tc.got != tc.want {
			t.Errorf("%s: got %v, want %v (const default)", tc.name, tc.got, tc.want)
		}
	}
}

// TestResolveRCAThresholds_Override verifies that non-zero config values
// are used as-is, overriding the compiled-in defaults.
func TestResolveRCAThresholds_Override(t *testing.T) {
	cfg := config.RCAThresholds{
		ScoreCritical:      80,
		ScoreDegraded:      40,
		ScoreFloor:         10,
		MinIOPSForLatency:  5.0,
		IoFsFullFreePct:    20.0,
		IoDstateBumpScore:  50,
		MemOOMMinScore:     90,
		MemSafeAvailPct:    30.0,
		CpuSafeBusyPct:     60.0,
		JvmHeapPressurePct: 70.0,
	}
	got := resolveRCAThresholds(cfg)

	if got.ScoreCritical != 80 {
		t.Errorf("ScoreCritical: got %d, want 80", got.ScoreCritical)
	}
	if got.ScoreDegraded != 40 {
		t.Errorf("ScoreDegraded: got %d, want 40", got.ScoreDegraded)
	}
	if got.ScoreFloor != 10 {
		t.Errorf("ScoreFloor: got %d, want 10", got.ScoreFloor)
	}
	if got.MinIOPSForLatency != 5.0 {
		t.Errorf("MinIOPSForLatency: got %v, want 5.0", got.MinIOPSForLatency)
	}
	if got.IoFsFullFreePct != 20.0 {
		t.Errorf("IoFsFullFreePct: got %v, want 20.0", got.IoFsFullFreePct)
	}
	if got.IoDstateBumpScore != 50 {
		t.Errorf("IoDstateBumpScore: got %d, want 50", got.IoDstateBumpScore)
	}
	if got.MemOOMMinScore != 90 {
		t.Errorf("MemOOMMinScore: got %d, want 90", got.MemOOMMinScore)
	}
	if got.MemSafeAvailPct != 30.0 {
		t.Errorf("MemSafeAvailPct: got %v, want 30.0", got.MemSafeAvailPct)
	}
	if got.CpuSafeBusyPct != 60.0 {
		t.Errorf("CpuSafeBusyPct: got %v, want 60.0", got.CpuSafeBusyPct)
	}
	if got.JvmHeapPressurePct != 70.0 {
		t.Errorf("JvmHeapPressurePct: got %v, want 70.0", got.JvmHeapPressurePct)
	}
}

// TestEngineThresholdsMethod verifies that (*Engine)(nil).thresholds() returns defaults.
func TestEngineThresholdsMethod(t *testing.T) {
	got := (*Engine)(nil).thresholds()
	if got.ScoreCritical != rcaScoreCritical {
		t.Errorf("nil engine thresholds: ScoreCritical=%d, want %d", got.ScoreCritical, rcaScoreCritical)
	}
}
