//go:build linux

package engine

import (
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
// the pre-boost one.
func TestConfigDriftBoostAffectsHealth(t *testing.T) {
	now := time.Now()

	// Memory anomaly whose score sits just under the degraded band (25); the
	// config-drift boost should carry it over so finalize reads it as degraded.
	result := makeMemoryAnomalyResult(23)
	result.Health = model.HealthOK

	changes := []model.SystemChange{{
		Type:   "config_drift_memory",
		Detail: "vm.swappiness: 60 → 100",
		Domain: "memory",
		When:   now.Add(-45 * time.Second),
	}}

	// Order under test — correlate BEFORE finalize.
	correlateConfigDrift(result, changes, now)
	var ctx finalizationCtx
	if len(result.RCA) > 0 {
		ctx.primary = &result.RCA[0]
	}
	finalizeResult(result, &ctx, nil)

	if result.PrimaryScore < rcaScoreDegraded {
		t.Fatalf("config-drift boost did not lift PrimaryScore across the degraded band: score=%d health=%v",
			result.PrimaryScore, result.Health)
	}
}
