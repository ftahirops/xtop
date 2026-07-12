//go:build linux

package engine

import (
	"strings"
	"testing"
	"time"

	"github.com/ftahirops/xtop/model"
)

// detectChanges must be callable and return an empty slice without panicking
// when the engine has no detectors configured (the common test path).
func TestDetectChangesNoDetectors(t *testing.T) {
	e := &Engine{} // no changeDetector / configDrift / paramDriftDetector
	got := e.detectChanges(&model.Snapshot{})
	if len(got) != 0 {
		t.Fatalf("expected no changes with no detectors, got %d", len(got))
	}
}

// TestConfigDriftBoostAffectsHealth pins the ordering invariant: correlating
// config drift BEFORE finalize must let the boost carry a near-threshold
// score across the degraded band so finalize reads the boosted score, not
// the pre-boost one. A no-drift control proves it's the boost — not the
// seeded score — that crosses the band.
func TestConfigDriftBoostAffectsHealth(t *testing.T) {
	now := time.Now()
	drift := []model.SystemChange{{
		Type:   "config_drift_memory",
		Detail: "vm.swappiness: 60 → 100",
		Domain: "memory",
		When:   now.Add(-45 * time.Second),
	}}

	// Seed a memory bottleneck whose score sits JUST below the degraded band.
	mk := func() *model.AnalysisResult {
		r := makeMemoryAnomalyResult(60) // arg is recentSec, not score
		r.RCA[0].Score = rcaScoreDegraded - 2 // 23
		r.PrimaryScore = rcaScoreDegraded - 2
		return r
	}

	// With a matching drift, the boost must carry the score across the band.
	boosted := mk()
	correlateConfigDrift(boosted, drift, now)
	if boosted.PrimaryScore < rcaScoreDegraded {
		t.Fatalf("config-drift boost did not cross the degraded band: %d < %d", boosted.PrimaryScore, rcaScoreDegraded)
	}

	// Control: no drift → score stays below the band (proves the boost, not the seed, crossed it).
	control := mk()
	correlateConfigDrift(control, nil, now)
	if control.PrimaryScore >= rcaScoreDegraded {
		t.Fatalf("control with no drift wrongly crossed the band: %d", control.PrimaryScore)
	}
}

// TestConfigDriftSuggestionSurvivesNilNarrative proves the "SUGGESTED: ..."
// remediation line is stashed on result.ConfigDriftSuggestions when
// correlateConfigDrift runs before the narrative exists (the real pipeline's
// ordering), so AnalyzeRCA can inject it into Narrative.Evidence afterward.
func TestConfigDriftSuggestionSurvivesNilNarrative(t *testing.T) {
	now := time.Now()
	result := makeMemoryAnomalyResult(60)
	result.Narrative = nil // matches the real pipeline at correlate time

	changes := []model.SystemChange{{
		Type:   "config_drift_memory",
		Detail: "vm.swappiness: 60 → 100", // maps to a non-empty suggestedRemediation
		Domain: "memory",
		When:   now.Add(-45 * time.Second),
	}}

	correlateConfigDrift(result, changes, now)

	found := false
	for _, s := range result.ConfigDriftSuggestions {
		if strings.HasPrefix(s, "SUGGESTED: ") {
			found = true
		}
	}
	if !found {
		t.Fatalf("config-drift remediation not stashed for post-narrative injection; got %v", result.ConfigDriftSuggestions)
	}
}
