//go:build linux

package engine

import (
	"testing"

	"github.com/ftahirops/xtop/model"
)

// TestConfidenceReflectsStrength reproduces the decoupled-confidence bug: three
// barely-fired signals (strength ~0.35) produced the same ~98% confidence as
// three maxed signals, because domainConfidence used only the fired-group count
// and measurement confidence, never signal strength. A domain whose strongest
// evidence is weak must not be shown at 93%+.
func TestConfidenceReflectsStrength(t *testing.T) {
	mk := func(str float64) []model.Evidence {
		return []model.Evidence{
			{ID: "a", Strength: str, Confidence: 0.9},
			{ID: "b", Strength: str, Confidence: 0.9},
			{ID: "c", Strength: str, Confidence: 0.9},
		}
	}
	strong := domainConfidence(mk(0.95))
	weak := domainConfidence(mk(0.35))

	if weak >= strong {
		t.Fatalf("weak-evidence confidence %.3f should be below strong-evidence %.3f", weak, strong)
	}
	if weak > 0.7 {
		t.Fatalf("barely-fired evidence must not yield high confidence, got %.3f", weak)
	}
	if strong < 0.9 {
		t.Fatalf("strong evidence should keep high confidence, got %.3f", strong)
	}
}
