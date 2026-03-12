package engine

import (
	"math"
	"testing"
)

func TestBaselineUpdateAndAnomaly(t *testing.T) {
	b := NewBaselineTracker(0.05) // alpha=0.05

	// Feed 100 samples of steady value=10
	for i := 0; i < 100; i++ {
		b.Update("cpu.busy", 10.0)
	}

	// Baseline should be ~10, stddev small
	mean, std, ok := b.Get("cpu.busy")
	if !ok {
		t.Fatal("expected baseline to exist")
	}
	if math.Abs(mean-10.0) > 1.0 {
		t.Errorf("mean=%.2f, want ~10", mean)
	}
	if std > 2.0 {
		t.Errorf("std=%.2f, want <2", std)
	}

	// Value of 50 should be anomalous (>3 sigma)
	anom := b.IsAnomaly("cpu.busy", 50.0, 3.0)
	if !anom {
		t.Error("expected 50 to be anomalous vs baseline of 10")
	}

	// Value of 11 should NOT be anomalous
	anom = b.IsAnomaly("cpu.busy", 11.0, 3.0)
	if anom {
		t.Error("expected 11 to NOT be anomalous vs baseline of 10")
	}
}

func TestBaselineWarmup(t *testing.T) {
	b := NewBaselineTracker(0.05)

	// Before warmup, nothing should be anomalous
	b.Update("test", 5.0)
	if b.IsWarmedUp("test") {
		t.Error("should not be warmed up after 1 sample")
	}
	// Feed enough to warm up (100 samples)
	for i := 0; i < 99; i++ {
		b.Update("test", 5.0)
	}
	if !b.IsWarmedUp("test") {
		t.Error("should be warmed up after 100 samples")
	}
}

func TestBaselineZScore(t *testing.T) {
	b := NewBaselineTracker(0.05)
	for i := 0; i < 100; i++ {
		b.Update("m", 20.0+float64(i%3)) // 20, 21, 22 repeating
	}
	z := b.ZScore("m", 40.0)
	if z < 5.0 {
		t.Errorf("z=%.2f, expected >5 for value 40 vs baseline ~21", z)
	}
}
