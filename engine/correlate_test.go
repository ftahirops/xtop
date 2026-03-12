package engine

import (
	"math"
	"testing"
)

func TestCorrelationPerfectPositive(t *testing.T) {
	c := NewCorrelator()
	for i := 0; i < 100; i++ {
		x := float64(i)
		c.Add("a", "b", x, x*2+1) // perfect linear
	}
	r := c.R("a", "b")
	if math.Abs(r-1.0) > 0.01 {
		t.Errorf("R=%.4f, want ~1.0 for perfect positive", r)
	}
}

func TestCorrelationPerfectNegative(t *testing.T) {
	c := NewCorrelator()
	for i := 0; i < 100; i++ {
		x := float64(i)
		c.Add("a", "b", x, 100-x)
	}
	r := c.R("a", "b")
	if math.Abs(r+1.0) > 0.01 {
		t.Errorf("R=%.4f, want ~-1.0 for perfect negative", r)
	}
}

func TestCorrelationUncorrelated(t *testing.T) {
	c := NewCorrelator()
	// Alternating — no correlation
	for i := 0; i < 100; i++ {
		x := float64(i)
		y := float64(i%2) * 100
		c.Add("a", "b", x, y)
	}
	r := c.R("a", "b")
	if math.Abs(r) > 0.3 {
		t.Errorf("R=%.4f, want ~0 for uncorrelated", r)
	}
}

func TestCorrelationMinSamples(t *testing.T) {
	c := NewCorrelator()
	c.Add("a", "b", 1, 2)
	r := c.R("a", "b")
	if r != 0 {
		t.Errorf("R=%.4f, want 0 with insufficient samples", r)
	}
}
