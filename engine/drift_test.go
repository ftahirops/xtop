package engine

import (
	"testing"

	"github.com/ftahirops/xtop/model"
)

// makeDriftResult fakes an AnalysisResult carrying one evidence value for the
// given metric ID — that's the only thing UpdateDrift looks at.
func makeDriftResult(id string, value float64) *model.AnalysisResult {
	return &model.AnalysisResult{
		RCA: []model.RCAEntry{{
			EvidenceV2: []model.Evidence{{ID: id, Value: value, Strength: 0.5}},
		}},
	}
}

// TestDrift_SteadyNoWarning: a metric that holds steady at a value should
// produce no drift warning.
func TestDrift_SteadyNoWarning(t *testing.T) {
	hist := NewHistory(10, 3)
	for i := 0; i < 300; i++ {
		_ = UpdateDrift(makeDriftResult("cpu.busy", 30.0), hist, false)
	}
	got := UpdateDrift(makeDriftResult("cpu.busy", 30.5), hist, false)
	for _, w := range got {
		if w.Metric == "cpu.busy" {
			t.Errorf("steady metric must not produce drift warning, got %+v", w)
		}
	}
}

// TestDrift_SlowRiseTriggers: if a metric slowly drifts upward and short-vs-
// long catches up to each other while long has diverged from ref, a warning
// fires.
func TestDrift_SlowRiseTriggers(t *testing.T) {
	hist := NewHistory(10, 3)

	// Phase A: 250 samples at value 20.0 → ref is captured at long.count=200
	for i := 0; i < 250; i++ {
		UpdateDrift(makeDriftResult("cpu.busy", 20.0), hist, false)
	}

	// Phase B: 10000 samples at 50.0 → long fully migrates close to 50, short
	// has reset rollovers and tracks 50, ref stays at 20.
	for i := 0; i < 10000; i++ {
		UpdateDrift(makeDriftResult("cpu.busy", 50.0), hist, false)
	}

	got := UpdateDrift(makeDriftResult("cpu.busy", 50.0), hist, false)
	found := false
	for _, w := range got {
		if w.Metric == "cpu.busy" && w.Direction == "rising" {
			found = true
		}
	}
	if !found {
		t.Errorf("slow rise must trigger drift warning, got %+v", got)
	}
}

// TestDrift_FrozenDuringIncidentDoesNotUpdate: while frozen, the trackers
// don't absorb new values — verified by checking the long.mean stays flat.
func TestDrift_FrozenDuringIncidentDoesNotUpdate(t *testing.T) {
	hist := NewHistory(10, 3)
	for i := 0; i < 250; i++ {
		UpdateDrift(makeDriftResult("cpu.busy", 20.0), hist, false)
	}
	store := getDriftStore(hist)
	store.mu.Lock()
	preCount := store.trackers["cpu.busy"].long.count
	store.mu.Unlock()

	for i := 0; i < 100; i++ {
		UpdateDrift(makeDriftResult("cpu.busy", 95.0), hist, true) // frozen
	}

	store.mu.Lock()
	postCount := store.trackers["cpu.busy"].long.count
	postMean := store.trackers["cpu.busy"].long.mean
	store.mu.Unlock()

	if postCount != preCount {
		t.Errorf("frozen update must not bump count: pre=%d post=%d", preCount, postCount)
	}
	if postMean > 25 {
		t.Errorf("frozen update must not pull mean up: %v", postMean)
	}
}

// TestDrift_BelowMinValueIgnored: tiny values are ignored to avoid huge
// relative changes when crossing the noise floor.
func TestDrift_BelowMinValueIgnored(t *testing.T) {
	hist := NewHistory(10, 3)
	for i := 0; i < 300; i++ {
		UpdateDrift(makeDriftResult("cpu.busy", 0.5), hist, false)
	}
	got := UpdateDrift(makeDriftResult("cpu.busy", 0.5), hist, false)
	if len(got) > 0 {
		t.Errorf("sub-threshold metric must not produce drift warning, got %+v", got)
	}
}

// TestAbsRel_SymmetryAndZero: tiny safety check on the helper.
func TestAbsRel_SymmetryAndZero(t *testing.T) {
	if got := absRel(100, 0); got != 0 {
		t.Errorf("absRel(_,0)=%v, want 0 (defensive)", got)
	}
	if got := absRel(110, 100); got != 0.1 {
		t.Errorf("absRel(110,100)=%v, want 0.1", got)
	}
	if got := absRel(90, 100); got != 0.1 {
		t.Errorf("absRel(90,100)=%v, want 0.1", got)
	}
}
