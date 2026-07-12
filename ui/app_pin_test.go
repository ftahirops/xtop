//go:build linux

package ui

import (
	"testing"

	"github.com/ftahirops/xtop/model"
)

// TestDisplayFrameUsesPinned: when a pinned result is shown, the panels must use
// the snapshot/rates captured WITH that result, not live ones — otherwise live
// metrics (e.g. CPU 30.9%) render next to a pinned analysis (93%), contradicting
// each other in one frame.
func TestDisplayFrameUsesPinned(t *testing.T) {
	live, liveR := &model.Snapshot{}, &model.RateSnapshot{}
	pinS, pinR := &model.Snapshot{}, &model.RateSnapshot{}

	m := &Model{snap: live, rates: liveR,
		pinnedResult: &model.AnalysisResult{}, pinnedSnap: pinS, pinnedRates: pinR}
	if s, r := m.displayFrame(); s != pinS || r != pinR {
		t.Fatal("pinned frame not used when result is pinned")
	}

	m2 := &Model{snap: live, rates: liveR}
	if s, r := m2.displayFrame(); s != live || r != liveR {
		t.Fatal("live frame not used when nothing is pinned")
	}
}

// TestRepinOnCauseChange: a different current bottleneck must replace the pin
// even if its score isn't strictly higher, so a stale pin can't mask a new cause.
func TestRepinOnCauseChange(t *testing.T) {
	m := &Model{
		pinnedResult: &model.AnalysisResult{PrimaryBottleneck: "io", PrimaryScore: 30, Health: model.HealthDegraded},
		result:       &model.AnalysisResult{PrimaryBottleneck: "cpu", PrimaryScore: 28, Health: model.HealthDegraded},
		snap:         &model.Snapshot{}, rates: &model.RateSnapshot{},
	}
	m.updatePinnedRCA()
	if m.pinnedResult.PrimaryBottleneck != "cpu" {
		t.Fatalf("pin did not update to the new cause; still %q", m.pinnedResult.PrimaryBottleneck)
	}
}
