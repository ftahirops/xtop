package engine

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// tmpCalibrator returns a calibrator whose persistence path is inside a
// TempDir — hermetic across test runs, no ~/.xtop pollution.
func tmpCalibrator(t *testing.T) *ConfidenceCalibrator {
	t.Helper()
	return &ConfidenceCalibrator{
		stats: make(map[string]*calibrationStats),
		path:  filepath.Join(t.TempDir(), "calibration.json"),
	}
}

func TestClassifyOutcome(t *testing.T) {
	cases := []struct {
		peak int
		dur  time.Duration
		want string
	}{
		{80, 60 * time.Second, "true_positive"}, // long + high → TP
		{30, 3 * time.Second, "false_positive"}, // short + low → FP
		{80, 3 * time.Second, "indeterminate"},  // short but high → ambiguous
		{30, 60 * time.Second, "indeterminate"}, // long but low → ambiguous
	}
	for _, tc := range cases {
		got := classifyOutcome(tc.peak, tc.dur)
		if got != tc.want {
			t.Errorf("classifyOutcome(%d, %v) = %q, want %q", tc.peak, tc.dur, got, tc.want)
		}
	}
}

func TestFactorFromStats_ThresholdBehaviour(t *testing.T) {
	// Below 5 labelled events → always 1.0.
	s := &calibrationStats{TruePositives: 4}
	if f := factorFromStats(s); f != 1.0 {
		t.Errorf("under-sampled factor = %v, want 1.0", f)
	}
	// 50/50 → 0.85 (bottom of band).
	s = &calibrationStats{TruePositives: 3, FalsePositives: 3}
	if f := factorFromStats(s); f != 0.85 {
		t.Errorf("precision=0.5 factor = %v, want 0.85", f)
	}
	// 10/10 → interpolated; precision=0.5 exactly, still 0.85.
	s = &calibrationStats{TruePositives: 10, FalsePositives: 10}
	if f := factorFromStats(s); f != 0.85 {
		t.Errorf("precision=0.5 factor = %v, want 0.85", f)
	}
	// High precision → 1.10.
	s = &calibrationStats{TruePositives: 9, FalsePositives: 1}
	if f := factorFromStats(s); f != 1.10 {
		t.Errorf("precision=0.9 factor = %v, want 1.10", f)
	}
}

func TestConfidenceCalibrator_PersistsAcrossRestart(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "calibration.json")
	c1 := &ConfidenceCalibrator{stats: map[string]*calibrationStats{}, path: path}
	// Record 6 true positives → factor should jump above 1.0 after the 5th.
	for i := 0; i < 6; i++ {
		c1.RecordOutcome("cpu", 80, 60*time.Second)
	}
	f := c1.Factor("cpu")
	if f <= 1.0 {
		t.Fatalf("post-learning factor = %v, want > 1.0", f)
	}
	// Sanity check persistence: file exists, non-empty.
	st, err := os.Stat(path)
	if err != nil || st.Size() == 0 {
		t.Fatalf("expected persisted file, stat=%v err=%v", st, err)
	}
	// Fresh calibrator should pick up the same factor.
	c2 := &ConfidenceCalibrator{stats: map[string]*calibrationStats{}, path: path}
	c2.load()
	if got := c2.Factor("cpu"); got != f {
		t.Errorf("reloaded factor = %v, want %v", got, f)
	}
}

func TestConfidenceCalibrator_ApplyTo_Bounds(t *testing.T) {
	c := tmpCalibrator(t)
	// Six FPs → factor 0.85.
	for i := 0; i < 6; i++ {
		c.RecordOutcome("io", 20, 2*time.Second)
	}
	if got := c.ApplyTo("io", 100); got >= 100 {
		t.Errorf("Apply(100) under down-bias = %d, want < 100", got)
	}
	// Clamp check: raw over 100 still clamps.
	if got := c.ApplyTo("io", 1000); got != 100 {
		t.Errorf("Apply(1000) = %d, want clamped to 100", got)
	}
	// Unknown bottleneck → factor 1.0.
	if got := c.ApplyTo("never-seen", 77); got != 77 {
		t.Errorf("unknown bottleneck should leave confidence unchanged: %d", got)
	}
}
