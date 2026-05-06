package engine

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/ftahirops/xtop/model"
)

// newTestRecorder returns an IncidentRecorder writing to a tmp dir so tests
// don't pollute ~/.xtop/rca-history.jsonl.
func newTestRecorder(t *testing.T) *IncidentRecorder {
	t.Helper()
	dir := t.TempDir()
	return &IncidentRecorder{
		path:           filepath.Join(dir, "rca-history.jsonl"),
		maxKeep:        100,
		signatureIndex: make(map[string][]int),
	}
}

func makeResult(bottleneck string, score int, evs []model.Evidence) *model.AnalysisResult {
	return &model.AnalysisResult{
		Health:            model.HealthDegraded,
		PrimaryBottleneck: bottleneck,
		PrimaryScore:      score,
		Confidence:        80,
		RCA: []model.RCAEntry{{
			Bottleneck: bottleneck,
			Score:      score,
			EvidenceV2: evs,
		}},
	}
}

// TestLifecycle_TickOneStaysSuspected: a single tick of pressure with sustained=0
// must NOT promote to Confirmed even though v2TrustGate would pass. This kills
// the "single bad sample" false positive.
func TestLifecycle_TickOneStaysSuspected(t *testing.T) {
	r := newTestRecorder(t)
	res := makeResult(BottleneckIO, 50, []model.Evidence{
		makeEvidenceWithSustained("io.psi", 0.8, 0.9, true, "psi", 0),
		makeEvidenceWithSustained("io.dstate", 0.6, 0.8, true, "queue", 0),
	})
	got := r.Record(res)
	if got == nil {
		t.Fatal("active incident must be returned (Suspected)")
	}
	if got.State != IncidentSuspected {
		t.Errorf("State = %q, want %q", got.State, IncidentSuspected)
	}
	if !got.ConfirmedAt.IsZero() {
		t.Error("ConfirmedAt must be zero while only Suspected")
	}
}

// TestLifecycle_PromotesAfterSustained: when the sustained gate passes, the
// active incident is promoted to Confirmed and ConfirmedAt is stamped.
func TestLifecycle_PromotesAfterSustained(t *testing.T) {
	r := newTestRecorder(t)

	// Tick 1: not yet sustained.
	res1 := makeResult(BottleneckIO, 50, []model.Evidence{
		makeEvidenceWithSustained("io.psi", 0.8, 0.9, true, "psi", 0),
		makeEvidenceWithSustained("io.dstate", 0.6, 0.8, true, "queue", 0),
	})
	r.Record(res1)

	// Tick 2: same evidence now reports sustained >= minSustainedSec.
	res2 := makeResult(BottleneckIO, 60, []model.Evidence{
		makeEvidenceWithSustained("io.psi", 0.8, 0.9, true, "psi", minSustainedSec+1),
		makeEvidenceWithSustained("io.dstate", 0.6, 0.8, true, "queue", minSustainedSec+1),
	})
	got := r.Record(res2)
	if got == nil {
		t.Fatal("active incident must be returned")
	}
	if got.State != IncidentConfirmed {
		t.Errorf("State after sustained = %q, want %q", got.State, IncidentConfirmed)
	}
	if got.ConfirmedAt.IsZero() {
		t.Error("ConfirmedAt must be stamped on promotion")
	}
}

// TestLifecycle_SuspectedOnlyDoesNotPersist: an episode that flickers from
// non-OK to OK without ever reaching Confirmed must NOT pollute JSONL history.
// This is the false-positive guard for persistence.
func TestLifecycle_SuspectedOnlyDoesNotPersist(t *testing.T) {
	r := newTestRecorder(t)

	res := makeResult(BottleneckIO, 50, []model.Evidence{
		makeEvidenceWithSustained("io.psi", 0.8, 0.9, true, "psi", 0),
		makeEvidenceWithSustained("io.dstate", 0.6, 0.8, true, "queue", 0),
	})
	r.Record(res)

	// Health flips back to OK before we ever confirmed.
	healthy := &model.AnalysisResult{Health: model.HealthOK}
	r.Record(healthy)

	if r.active != nil {
		t.Error("active must be cleared after recovery")
	}
	if len(r.history) != 0 {
		t.Errorf("history must be empty (Suspected-only must not persist), got %d entries", len(r.history))
	}
	if _, err := os.Stat(r.path); err == nil {
		t.Error("JSONL file must not exist for Suspected-only episode")
	}
}

// TestLifecycle_ConfirmedPersistsOnRecovery: a Confirmed incident is written to
// JSONL when health returns to OK, with State=Resolved.
func TestLifecycle_ConfirmedPersistsOnRecovery(t *testing.T) {
	r := newTestRecorder(t)

	// Tick 1
	r.Record(makeResult(BottleneckIO, 50, []model.Evidence{
		makeEvidenceWithSustained("io.psi", 0.8, 0.9, true, "psi", 0),
		makeEvidenceWithSustained("io.dstate", 0.6, 0.8, true, "queue", 0),
	}))
	// Tick 2 — promote to Confirmed.
	r.Record(makeResult(BottleneckIO, 60, []model.Evidence{
		makeEvidenceWithSustained("io.psi", 0.8, 0.9, true, "psi", minSustainedSec+1),
		makeEvidenceWithSustained("io.dstate", 0.6, 0.8, true, "queue", minSustainedSec+1),
	}))
	// Force the active incident to look "long enough" so appendToHistory accepts it.
	if r.active == nil || r.active.State != IncidentConfirmed {
		t.Fatal("setup: must be in Confirmed state")
	}
	r.active.PeakScore = 70 // appendToHistory rejects PeakScore < 30
	// Backdate StartedAt so DurationSec >= 10 when we close.
	r.active.StartedAt = r.active.StartedAt.Add(-30 * 1e9)

	// Recovery
	r.Record(&model.AnalysisResult{Health: model.HealthOK})

	if r.active != nil {
		t.Error("active must be nil after recovery")
	}
	if len(r.history) != 1 {
		t.Errorf("history must contain the resolved Confirmed incident, got %d", len(r.history))
	} else if r.history[0].State != IncidentResolved {
		t.Errorf("persisted state = %q, want %q", r.history[0].State, IncidentResolved)
	}
}

// TestLifecycle_FlappingNearBoundary: rapid OK↔Suspected oscillation must not
// emit any persisted incidents — the diversity gate + sustained requirement
// together keep it in Suspected, and Suspected does not persist.
func TestLifecycle_FlappingNearBoundary(t *testing.T) {
	r := newTestRecorder(t)
	healthy := &model.AnalysisResult{Health: model.HealthOK}
	flicker := makeResult(BottleneckIO, 28, []model.Evidence{
		makeEvidenceWithSustained("io.psi", 0.5, 0.9, true, "psi", 0),
		makeEvidenceWithSustained("io.dstate", 0.4, 0.8, true, "queue", 0),
	})

	for i := 0; i < 6; i++ {
		r.Record(flicker)
		r.Record(healthy)
	}

	if len(r.history) != 0 {
		t.Errorf("flapping must not persist any incidents, got %d", len(r.history))
	}
}
