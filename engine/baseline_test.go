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

	// Feed steady values — adaptive warmup should kick in before 100
	// with stable CV. Feed enough to guarantee warmup (100 samples total).
	for i := 0; i < 99; i++ {
		b.Update("test", 5.0)
	}
	if !b.IsWarmedUp("test") {
		t.Error("should be warmed up after 100 samples")
	}
}

func TestBaselineAdaptiveWarmup(t *testing.T) {
	b := NewBaselineTracker(0.05)

	// Feed stable values — should warm up before maxWarmupSamples
	for i := 0; i < minWarmupSamples; i++ {
		b.Update("stable", 10.0)
	}
	// Stable metric (CV ≈ 0) should be warmed up after minWarmupSamples
	if !b.IsWarmedUp("stable") {
		t.Error("stable metric should be warmed up after minWarmupSamples")
	}

	// Noisy metric should require more samples
	b2 := NewBaselineTracker(0.05)
	for i := 0; i < minWarmupSamples; i++ {
		// Alternate wildly to keep CV high
		v := 10.0
		if i%2 == 0 {
			v = 50.0
		}
		b2.Update("noisy", v)
	}
	// At maxWarmupSamples it must be warmed up regardless
	for i := minWarmupSamples; i < maxWarmupSamples; i++ {
		v := 10.0
		if i%2 == 0 {
			v = 50.0
		}
		b2.Update("noisy", v)
	}
	if !b2.IsWarmedUp("noisy") {
		t.Error("any metric should be warmed up at maxWarmupSamples")
	}
}

func TestBaselineOutlierRejection(t *testing.T) {
	b := NewBaselineTracker(0.05)

	// Feed 20 stable values to establish a baseline
	for i := 0; i < 20; i++ {
		b.Update("metric", 10.0)
	}
	mean1, _, _ := b.Get("metric")

	// Feed an extreme outlier — should be rejected during warmup
	b.Update("metric", 10000.0)
	mean2, _, _ := b.Get("metric")

	// Mean should not have moved significantly
	if math.Abs(mean2-mean1) > 1.0 {
		t.Errorf("outlier should have been rejected: mean moved from %.2f to %.2f", mean1, mean2)
	}

	// Verify outlier was counted
	b.mu.RLock()
	bl := b.baselines["metric"]
	rejected := bl.OutliersRejected
	b.mu.RUnlock()
	if rejected < 1 {
		t.Error("expected at least 1 outlier to be rejected")
	}
}

func TestDistributionAwareThresholds(t *testing.T) {
	// Right-skewed metrics should use lower sigma
	if anomalySigma(classifyDistribution("net.retrans")) != 2.0 {
		t.Error("retrans should use sigma=2.0")
	}
	if anomalySigma(classifyDistribution("net.drops")) != 2.0 {
		t.Error("drops should use sigma=2.0")
	}
	if anomalySigma(classifyDistribution("mem.oom")) != 2.0 {
		t.Error("oom should use sigma=2.0")
	}
	// PSI should use 2.5
	if anomalySigma(classifyDistribution("cpu.psi.some")) != 2.5 {
		t.Error("psi should use sigma=2.5")
	}
	// Normal metrics should use 3.0
	if anomalySigma(classifyDistribution("cpu.busy")) != 3.0 {
		t.Error("cpu.busy should use sigma=3.0")
	}
}

func TestCUSUMChangePoint(t *testing.T) {
	c := newCusumState(10.0, 1.0)

	// Values near the mean should not trigger
	for i := 0; i < 20; i++ {
		if c.Update(10.5) {
			t.Error("near-mean value should not trigger change-point")
		}
	}

	// A sudden sustained shift should trigger
	triggered := false
	for i := 0; i < 20; i++ {
		if c.Update(20.0) {
			triggered = true
			break
		}
	}
	if !triggered {
		t.Error("sustained shift from 10 to 20 should trigger CUSUM change-point")
	}
}

func TestCUSUMReWarmup(t *testing.T) {
	b := NewBaselineTracker(0.05)

	// Build baseline around 10.0
	for i := 0; i < maxWarmupSamples+10; i++ {
		b.Update("shift", 10.0)
	}
	if !b.IsWarmedUp("shift") {
		t.Fatal("should be warmed up")
	}

	// Feed a massive sustained shift — should trigger CUSUM and re-warmup
	for i := 0; i < 50; i++ {
		b.Update("shift", 100.0)
	}

	// After re-warmup with new values, the baseline should have shifted
	b.mu.RLock()
	bl := b.baselines["shift"]
	changed := bl.ChangePointDetected
	b.mu.RUnlock()
	if !changed {
		t.Error("expected ChangePointDetected to be set after distribution shift")
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
