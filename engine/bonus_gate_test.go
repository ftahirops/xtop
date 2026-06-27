package engine

import (
	"testing"

	"github.com/ftahirops/xtop/model"
)

// TestBonusGate_ClampWhenInconclusive asserts that clampInconclusiveScore
// caps PrimaryScore below rcaScoreDegraded when Health==Inconclusive.
// This is the trust-gate bypass fix: forecast (+10) and deploy-correlation
// (+15) bonuses applied after finalize() must not push an Inconclusive
// result into the degraded/critical read range.
func TestBonusGate_ClampWhenInconclusive(t *testing.T) {
	result := &model.AnalysisResult{
		Health:       model.HealthInconclusive,
		PrimaryScore: 45, // inflated by bonuses after finalize — would be in degraded range
	}
	clampInconclusiveScore(result)

	if result.PrimaryScore >= rcaScoreDegraded {
		t.Errorf("bug: PrimaryScore=%d >= rcaScoreDegraded=%d with Health=Inconclusive (trust gate bypass)",
			result.PrimaryScore, rcaScoreDegraded)
	}
	if result.PrimaryScore != rcaScoreDegraded-1 {
		t.Errorf("expected PrimaryScore clamped to %d, got %d", rcaScoreDegraded-1, result.PrimaryScore)
	}
}

// TestBonusGate_CriticalScoreClamped asserts that a score in the critical
// range is also clamped to below rcaScoreDegraded when Inconclusive.
func TestBonusGate_CriticalScoreClamped(t *testing.T) {
	result := &model.AnalysisResult{
		Health:       model.HealthInconclusive,
		PrimaryScore: 75, // in critical range
	}
	clampInconclusiveScore(result)

	if result.PrimaryScore >= rcaScoreDegraded {
		t.Errorf("critical-range score not clamped: PrimaryScore=%d with Inconclusive health", result.PrimaryScore)
	}
	want := rcaScoreDegraded - 1
	if result.PrimaryScore != want {
		t.Errorf("want PrimaryScore=%d, got %d", want, result.PrimaryScore)
	}
}

// TestBonusGate_NoclampWhenDegraded asserts that gate-passing results
// (Health=Degraded) are NOT clamped — full bonus score must be preserved.
func TestBonusGate_NoclampWhenDegraded(t *testing.T) {
	result := &model.AnalysisResult{
		Health:       model.HealthDegraded,
		PrimaryScore: 45,
	}
	clampInconclusiveScore(result)

	if result.PrimaryScore != 45 {
		t.Errorf("gate-passing regression: PrimaryScore changed from 45 to %d for Degraded health", result.PrimaryScore)
	}
}

// TestBonusGate_NoclampWhenCritical asserts that Critical health results
// are also unaffected by the clamp.
func TestBonusGate_NoclampWhenCritical(t *testing.T) {
	result := &model.AnalysisResult{
		Health:       model.HealthCritical,
		PrimaryScore: 75,
	}
	clampInconclusiveScore(result)

	if result.PrimaryScore != 75 {
		t.Errorf("gate-passing regression: PrimaryScore changed from 75 to %d for Critical health", result.PrimaryScore)
	}
}

// TestBonusGate_NoclampWhenOK asserts that OK health results are unaffected.
func TestBonusGate_NoclampWhenOK(t *testing.T) {
	result := &model.AnalysisResult{
		Health:       model.HealthOK,
		PrimaryScore: 10,
	}
	clampInconclusiveScore(result)

	if result.PrimaryScore != 10 {
		t.Errorf("gate-passing regression: PrimaryScore changed from 10 to %d for OK health", result.PrimaryScore)
	}
}

// TestBonusGate_InvariantAcrossScenarios asserts the post-AnalyzeRCA invariant:
// whenever Health==Inconclusive, PrimaryScore must be below rcaScoreDegraded.
// Runs on the standard scenario set used by other comprehensive tests.
func TestBonusGate_InvariantAcrossScenarios(t *testing.T) {
	scenarios := []struct {
		name string
		fn   func() (*model.Snapshot, *model.RateSnapshot)
	}{
		{"healthy", healthySnap},
		{"cpuSaturated", cpuSaturatedSnap},
		{"cpuSteal", cpuStealSnap},
		{"memLow", memLowSnap},
		{"memOOM", memOOMSnap},
		{"ioSaturated", ioSaturatedSnap},
		{"ioFsFull", ioFsFullSnap},
		{"netDrops", netDropsSnap},
		{"netConntrackExhaust", netConntrackExhaustSnap},
	}
	inconclusiveCount := 0
	for _, sc := range scenarios {
		t.Run(sc.name, func(t *testing.T) {
			s, r := sc.fn()
			result := runRCA(s, r)
			if result.Health == model.HealthInconclusive {
				inconclusiveCount++
			}
			if result.Health == model.HealthInconclusive && result.PrimaryScore >= rcaScoreDegraded {
				t.Errorf("invariant violated: Health=Inconclusive but PrimaryScore=%d >= rcaScoreDegraded=%d",
					result.PrimaryScore, rcaScoreDegraded)
			}
		})
	}
	// Log vacuity warning if none of the standard scenarios produced Inconclusive
	if inconclusiveCount == 0 {
		t.Logf("INFO: no standard scenarios produced Health=Inconclusive (vacuous test path); see TestBonusGate_ClampInvariantTable for deterministic coverage")
	}
}

// TestBonusGate_ClampInvariantTable is a deterministic table-driven test that
// verifies clampInconclusiveScore enforces the core invariant: whenever
// Health==Inconclusive, PrimaryScore must remain below rcaScoreDegraded.
// This is the real guard against trust-gate bypass: any removal or weakening
// of clampInconclusiveScore will cause this test to fail.
func TestBonusGate_ClampInvariantTable(t *testing.T) {
	tests := []struct {
		name       string
		health     model.HealthLevel
		inputScore int
		wantScore  int // expected score after clamp
		desc       string
	}{
		{
			name:       "inconclusive_above_degraded_40",
			health:     model.HealthInconclusive,
			inputScore: 40,
			wantScore:  rcaScoreDegraded - 1, // must clamp from 40 to 24
			desc:       "Inconclusive with bonus-inflated score (40) must clamp to 24",
		},
		{
			name:       "inconclusive_critical_range_99",
			health:     model.HealthInconclusive,
			inputScore: 99,
			wantScore:  rcaScoreDegraded - 1, // must clamp from 99 to 24
			desc:       "Inconclusive with critical-range score (99) must clamp to 24",
		},
		{
			name:       "inconclusive_below_degraded_10",
			health:     model.HealthInconclusive,
			inputScore: 10,
			wantScore:  10, // already below threshold, unchanged
			desc:       "Inconclusive with sub-threshold score (10) remains unchanged",
		},
		{
			name:       "degraded_unchanged_40",
			health:     model.HealthDegraded,
			inputScore: 40,
			wantScore:  40, // gate-passing result, no clamp
			desc:       "Degraded result (gate-passing) is NOT clamped",
		},
		{
			name:       "critical_unchanged_80",
			health:     model.HealthCritical,
			inputScore: 80,
			wantScore:  80, // gate-passing result, no clamp
			desc:       "Critical result (gate-passing) is NOT clamped",
		},
		{
			name:       "ok_unchanged_5",
			health:     model.HealthOK,
			inputScore: 5,
			wantScore:  5, // gate-passing result, no clamp
			desc:       "OK result (gate-passing) is NOT clamped",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := &model.AnalysisResult{
				Health:       tt.health,
				PrimaryScore: tt.inputScore,
			}
			clampInconclusiveScore(result)

			if result.PrimaryScore != tt.wantScore {
				t.Errorf("%s: got score=%d, want %d", tt.desc, result.PrimaryScore, tt.wantScore)
			}

			// Hard invariant: after clamp, if Health==Inconclusive then PrimaryScore < rcaScoreDegraded
			if result.Health == model.HealthInconclusive && result.PrimaryScore >= rcaScoreDegraded {
				t.Errorf("INVARIANT VIOLATED: Health=Inconclusive but PrimaryScore=%d >= rcaScoreDegraded=%d (trust-gate bypass)",
					result.PrimaryScore, rcaScoreDegraded)
			}
		})
	}
}
