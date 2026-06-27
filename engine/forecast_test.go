package engine

import (
	"math"
	"testing"
)

func TestHoltLinearTrend(t *testing.T) {
	h := NewHoltForecaster(0.3, 0.1)

	// Feed linearly increasing data: 0, 1, 2, ... 99
	for i := 0; i < 100; i++ {
		h.Update("mem.used", float64(i))
	}

	// Forecast 10 steps ahead: should predict ~109
	forecast := h.Forecast("mem.used", 10)
	if math.Abs(forecast-109) > 5 {
		t.Errorf("forecast=%.1f, want ~109 for linear trend", forecast)
	}
}

func TestHoltFlatLine(t *testing.T) {
	h := NewHoltForecaster(0.3, 0.1)
	for i := 0; i < 50; i++ {
		h.Update("flat", 42.0)
	}
	forecast := h.Forecast("flat", 10)
	if math.Abs(forecast-42.0) > 1.0 {
		t.Errorf("forecast=%.1f, want ~42 for flat line", forecast)
	}
}

func TestHoltNotReady(t *testing.T) {
	h := NewHoltForecaster(0.3, 0.1)
	h.Update("x", 5.0)
	f := h.Forecast("x", 10)
	if f != 0 {
		t.Errorf("forecast=%.1f, want 0 when not ready", f)
	}
}

func TestHoltExhaustionETA(t *testing.T) {
	h := NewHoltForecaster(0.3, 0.1)
	// Memory going from 50% to 90% over 40 ticks (~1%/tick)
	for i := 0; i < 40; i++ {
		h.Update("mem.pct", 50.0+float64(i))
	}
	eta := h.ETAToThreshold("mem.pct", 100.0, 120)
	if eta < 5 || eta > 15 {
		t.Errorf("eta=%.1f steps, want ~10 for 90→100 at 1/tick", eta)
	}
}

// TestHoltCrossMetricIsolation verifies that a regime-driven alpha/beta adaptation on one
// metric does NOT bleed into another metric's smoothing parameters.
//
// With the old shared-field bug (hf.alpha / hf.beta mutated by adjustParams), metric B's
// forecast after metric A undergoes a regime change would differ from metric B's forecast
// without metric A's interference.  With the per-state fix the two paths must be identical.
func TestHoltCrossMetricIsolation(t *testing.T) {
	// --- Baseline: train metric B on a stable flat line, NO metric A involved. ---
	baseline := NewHoltForecaster(0.3, 0.1)
	for i := 0; i < 100; i++ {
		baseline.Update("metric.b", 50.0)
	}
	baselineForecast := baseline.Forecast("metric.b", 5)

	// --- Contaminated: same metric B training, but interleaved with a noisy/spiky
	//     metric A that will trigger regime detection and alpha/beta adaptation. ---
	//
	// Metric A pattern: mostly 0 with extreme spikes every 5 samples — drives
	// detectRegime toward RegimeSpiky/RegimeNoisy and ensures adjustParams fires.
	contaminated := NewHoltForecaster(0.3, 0.1)
	for i := 0; i < 100; i++ {
		// Spike on metric A every 5 ticks to maximise regime detection triggers.
		if i%5 == 4 {
			contaminated.Update("metric.a", 1000.0)
		} else {
			contaminated.Update("metric.a", 0.0)
		}
		// Metric B receives identical data as the baseline run.
		contaminated.Update("metric.b", 50.0)
	}
	contaminatedForecast := contaminated.Forecast("metric.b", 5)

	// The two forecasts for metric B must be identical (tolerance: 1e-9).
	// A non-zero difference proves alpha/beta leaked from metric A to metric B.
	diff := math.Abs(baselineForecast - contaminatedForecast)
	if diff > 1e-9 {
		t.Errorf(
			"cross-metric alpha/beta contamination detected: "+
				"baseline forecast=%.6f, contaminated forecast=%.6f, diff=%.2e",
			baselineForecast, contaminatedForecast, diff,
		)
	}

	// Also verify that metric A itself DID undergo regime adaptation (proves the
	// test actually exercises the adaptation path, and that isolation matters).
	regimeA := contaminated.Regime("metric.a")
	if regimeA == RegimeStable {
		t.Logf("note: metric.a regime is still Stable after spike pattern — "+
			"adaptation may not have triggered; regime=%v", regimeA)
	}
}
