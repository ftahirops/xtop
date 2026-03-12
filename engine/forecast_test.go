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
