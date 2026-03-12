package engine

import (
	"math"
	"testing"
)

func TestZWindowBasic(t *testing.T) {
	zw := NewZScoreTracker(60)

	// Feed 60 values of 10.0
	for i := 0; i < 60; i++ {
		zw.Push("cpu.busy", 10.0)
	}

	// z-score of 10 should be ~0
	z := zw.ZScore("cpu.busy", 10.0)
	if math.Abs(z) > 0.1 {
		t.Errorf("z=%.2f for same value, want ~0", z)
	}

	// z-score of 30 should be very high
	z = zw.ZScore("cpu.busy", 30.0)
	if z < 3.0 {
		t.Errorf("z=%.2f for outlier, want >3", z)
	}
}

func TestZWindowNotReady(t *testing.T) {
	zw := NewZScoreTracker(60)
	zw.Push("test", 5.0)
	z := zw.ZScore("test", 100.0)
	if z != 0 {
		t.Errorf("z=%.2f, want 0 when not enough data", z)
	}
}

func TestZWindowSliding(t *testing.T) {
	zw := NewZScoreTracker(10)
	// Fill window with 5.0
	for i := 0; i < 10; i++ {
		zw.Push("m", 5.0)
	}
	// Slide window with 15.0
	for i := 0; i < 10; i++ {
		zw.Push("m", 15.0)
	}
	// After full slide, baseline should be ~15, z-score of 15 ~= 0
	z := zw.ZScore("m", 15.0)
	if math.Abs(z) > 0.5 {
		t.Errorf("z=%.2f after window slide, want ~0", z)
	}
}
