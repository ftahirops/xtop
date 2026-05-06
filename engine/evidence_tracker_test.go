package engine

import (
	"testing"
	"time"

	"github.com/ftahirops/xtop/model"
)

func makeEvidenceWithSustained(id string, strength, conf float64, measured bool, weight string, sustainedSec float64) model.Evidence {
	ev := makeEvidence(id, strength, conf, measured, weight)
	ev.SustainedForSec = sustainedSec
	if sustainedSec > 0 {
		ev.FirstSeenAt = time.Now().Add(-time.Duration(sustainedSec) * time.Second)
	} else {
		ev.FirstSeenAt = time.Now()
	}
	return ev
}

// TestConfirmedTrustGate_RejectsTickOneSpike verifies that a single bad tick
// (sustained=0) cannot pass the confirmed gate even when v2TrustGate would.
// This is the primary false-positive guard for verdict promotion.
func TestConfirmedTrustGate_RejectsTickOneSpike(t *testing.T) {
	evs := []model.Evidence{
		makeEvidenceWithSustained("io.psi", 0.8, 0.9, true, "psi", 0),
		makeEvidenceWithSustained("io.dstate", 0.6, 0.8, true, "queue", 0),
	}
	if !v2TrustGate(evs) {
		t.Fatal("precondition: v2TrustGate must pass for this fixture")
	}
	if confirmedTrustGate(evs) {
		t.Error("confirmedTrustGate must reject evidence with sustained=0 (tick-one spike)")
	}
}

// TestConfirmedTrustGate_AcceptsSustained verifies promotion succeeds once at
// least one piece of evidence has been sustained for >= minSustainedSec.
func TestConfirmedTrustGate_AcceptsSustained(t *testing.T) {
	evs := []model.Evidence{
		makeEvidenceWithSustained("io.psi", 0.8, 0.9, true, "psi", minSustainedSec+1),
		makeEvidenceWithSustained("io.dstate", 0.6, 0.8, true, "queue", 1),
	}
	if !confirmedTrustGate(evs) {
		t.Error("confirmedTrustGate must accept when at least one evidence is sustained")
	}
}

// TestConfirmedTrustGate_BelowSustainedThreshold ensures the gate rejects a
// borderline case where evidence has been firing but not long enough.
func TestConfirmedTrustGate_BelowSustainedThreshold(t *testing.T) {
	evs := []model.Evidence{
		makeEvidenceWithSustained("io.psi", 0.8, 0.9, true, "psi", minSustainedSec-0.5),
		makeEvidenceWithSustained("io.dstate", 0.6, 0.8, true, "queue", 1),
	}
	if confirmedTrustGate(evs) {
		t.Error("confirmedTrustGate must reject when no evidence has reached minSustainedSec")
	}
}

// TestConfirmedTrustGate_FailsIfV2Fails ensures the confirmed gate cannot pass
// when the underlying v2TrustGate fails (e.g. only one weight category).
func TestConfirmedTrustGate_FailsIfV2Fails(t *testing.T) {
	evs := []model.Evidence{
		// Two PSI items only — same weight category, fails diversity check.
		makeEvidenceWithSustained("cpu.psi", 0.8, 0.9, true, "psi", 30),
		makeEvidenceWithSustained("mem.psi", 0.6, 0.8, true, "psi", 30),
	}
	if v2TrustGate(evs) {
		t.Fatal("precondition: v2TrustGate should reject monoculture (single weight category)")
	}
	if confirmedTrustGate(evs) {
		t.Error("confirmedTrustGate must not bypass v2TrustGate failure")
	}
}

// TestStampSustainedDurations_FirstTick verifies the first time an evidence
// fires it gets SustainedForSec=0 and a non-zero FirstSeenAt.
func TestStampSustainedDurations_FirstTick(t *testing.T) {
	hist := NewHistory(10, 3)
	result := &model.AnalysisResult{
		RCA: []model.RCAEntry{{
			Bottleneck: BottleneckIO,
			EvidenceV2: []model.Evidence{
				{ID: "io.psi", Strength: 0.8},
			},
		}},
	}

	stampSustainedDurations(result, hist)

	got := result.RCA[0].EvidenceV2[0]
	if got.FirstSeenAt.IsZero() {
		t.Error("FirstSeenAt must be set on first tick")
	}
	if got.SustainedForSec != 0 {
		t.Errorf("SustainedForSec on first tick = %v, want 0", got.SustainedForSec)
	}
}

// TestStampSustainedDurations_SecondTick verifies the second time an evidence
// fires it picks up the existing onset and reports a non-zero duration.
func TestStampSustainedDurations_SecondTick(t *testing.T) {
	hist := NewHistory(10, 3)
	pastOnset := time.Now().Add(-7 * time.Second)
	hist.signalOnsets["io.psi"] = pastOnset

	result := &model.AnalysisResult{
		RCA: []model.RCAEntry{{
			Bottleneck: BottleneckIO,
			EvidenceV2: []model.Evidence{
				{ID: "io.psi", Strength: 0.8},
			},
		}},
	}

	stampSustainedDurations(result, hist)

	got := result.RCA[0].EvidenceV2[0]
	if !got.FirstSeenAt.Equal(pastOnset) {
		t.Errorf("FirstSeenAt = %v, want %v (preserved onset)", got.FirstSeenAt, pastOnset)
	}
	if got.SustainedForSec < 6 || got.SustainedForSec > 8 {
		t.Errorf("SustainedForSec = %v, want ~7", got.SustainedForSec)
	}
}

// TestStampSustainedDurations_NilHist ensures the function is safe to call
// without a history (one-shot CLI mode, tests).
func TestStampSustainedDurations_NilHist(t *testing.T) {
	result := &model.AnalysisResult{
		RCA: []model.RCAEntry{{
			EvidenceV2: []model.Evidence{
				{ID: "io.psi", Strength: 0.8},
			},
		}},
	}
	stampSustainedDurations(result, nil)
	if result.RCA[0].EvidenceV2[0].FirstSeenAt.IsZero() {
		t.Error("FirstSeenAt must be set even when hist is nil")
	}
	if result.RCA[0].EvidenceV2[0].SustainedForSec != 0 {
		t.Error("SustainedForSec must be 0 when hist is nil")
	}
}

// TestStampSustainedDurations_SkipsZeroStrength ensures we don't stamp evidence
// that didn't fire (strength == 0). This keeps zero-strength evidence — which
// represents "evaluated and rejected" — distinguishable from "fired but new."
func TestStampSustainedDurations_SkipsZeroStrength(t *testing.T) {
	hist := NewHistory(10, 3)
	result := &model.AnalysisResult{
		RCA: []model.RCAEntry{{
			EvidenceV2: []model.Evidence{
				{ID: "io.psi", Strength: 0},
			},
		}},
	}
	stampSustainedDurations(result, hist)
	if !result.RCA[0].EvidenceV2[0].FirstSeenAt.IsZero() {
		t.Error("FirstSeenAt must remain zero for non-firing evidence")
	}
}
