package engine

import (
	"testing"
	"time"

	"github.com/ftahirops/xtop/model"
)

// TestSignalOnsetPrune_RemovesInactivePreservesActive verifies that
// UpdateSignalOnsets removes onsets for evidence IDs that are no longer firing
// while leaving the onset time of still-active IDs unchanged.
//
// TDD: this test must be RED before the prune logic is added to UpdateSignalOnsets.
func TestSignalOnsetPrune_RemovesInactivePreservesActive(t *testing.T) {
	hist := NewHistory(10, 3)

	// Seed two onsets from the past.
	aOnset := time.Now().Add(-10 * time.Second)
	bOnset := time.Now().Add(-5 * time.Second)
	hist.signalOnsets["a"] = aOnset
	hist.signalOnsets["b"] = bOnset

	// This tick only "a" is firing; "b" has stopped.
	result := &model.AnalysisResult{
		RCA: []model.RCAEntry{{
			Bottleneck: BottleneckIO,
			EvidenceV2: []model.Evidence{
				{ID: "a", Strength: 0.8},
				{ID: "b", Strength: 0}, // not firing
			},
		}},
	}

	UpdateSignalOnsets(hist, result)

	// "b" must be gone — it is no longer firing.
	hist.mu.RLock()
	defer hist.mu.RUnlock()

	if _, ok := hist.signalOnsets["b"]; ok {
		t.Error("signalOnsets[b] must be removed when b is not firing this tick")
	}

	// "a" must still be present with its ORIGINAL onset (not reset to now).
	aGot, ok := hist.signalOnsets["a"]
	if !ok {
		t.Fatal("signalOnsets[a] must be preserved — a is still active")
	}
	if !aGot.Equal(aOnset) {
		t.Errorf("signalOnsets[a] = %v, want original onset %v (must not be reset)", aGot, aOnset)
	}
}

// TestSignalOnsetPrune_ClearsMapWhenNothingFires verifies that when no evidence
// fires the full-incident-reset path still wipes all onsets (existing behaviour).
func TestSignalOnsetPrune_ClearsMapWhenNothingFires(t *testing.T) {
	hist := NewHistory(10, 3)
	hist.signalOnsets["x"] = time.Now().Add(-30 * time.Second)

	result := &model.AnalysisResult{
		RCA: []model.RCAEntry{{
			Bottleneck: BottleneckIO,
			EvidenceV2: []model.Evidence{
				{ID: "x", Strength: 0},
			},
		}},
	}

	UpdateSignalOnsets(hist, result)

	hist.mu.RLock()
	defer hist.mu.RUnlock()

	if len(hist.signalOnsets) != 0 {
		t.Errorf("signalOnsets must be empty after full-incident-resolved tick, got %v", hist.signalOnsets)
	}
}
