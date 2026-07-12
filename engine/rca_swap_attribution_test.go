//go:build linux

package engine

import (
	"testing"

	"github.com/ftahirops/xtop/model"
)

// firedResult builds an AnalysisResult whose fired evidence is exactly the given
// IDs at full strength, so MatchPattern / collectFiredEvidence see them.
func firedResult(ids ...string) *model.AnalysisResult {
	evs := make([]model.Evidence, 0, len(ids))
	for _, id := range ids {
		evs = append(evs, model.Evidence{ID: id, Strength: 1.0})
	}
	return &model.AnalysisResult{
		RCA: []model.RCAEntry{{Bottleneck: "io", Score: 80, EvidenceV2: evs}},
	}
}

// TestPureDiskIONotSwapStorm reproduces the CRITICAL misattribution: pure disk IO
// (io.psi + io.disk.latency fire, NO swap) must not be labeled "swap thrashing".
// The phantom mem.swap.activity evidence + MinMatch:2 let the two generic IO
// signals alone satisfy the P90 "Memory-Induced IO Storm" pattern.
func TestPureDiskIONotSwapStorm(t *testing.T) {
	res := firedResult("io.psi", "io.disk.latency") // no swap activity at all
	pat := MatchPattern(res)
	if pat != nil && pat.Name == "Memory-Induced IO Storm" {
		t.Fatalf("pure disk IO misattributed to swap: matched %q -> %q", pat.Name, pat.Narrative)
	}
}

// TestNarrativeNoSwapNotViaSwap reproduces the narrative-template twin: memory PSI +
// disk latency with NO swap must not produce a "...via swap" narrative.
func TestNarrativeNoSwapNotViaSwap(t *testing.T) {
	fired := map[string]model.Evidence{
		"mem.psi":          {ID: "mem.psi", Strength: 1.0},
		"io.disk.latency":  {ID: "io.disk.latency", Strength: 1.0},
	}
	got := matchNarrativeTemplate(fired)
	if got == "Memory pressure cascading into IO latency via swap" {
		t.Fatalf("no-swap scenario produced a 'via swap' narrative: %q", got)
	}
}

// TestRealSwapMatchesIOStorm guards the correct case: with genuine swap activity
// plus IO pressure, the swap-thrashing pattern SHOULD fire.
func TestRealSwapMatchesIOStorm(t *testing.T) {
	res := firedResult("mem.swap.activity", "io.psi", "io.disk.latency")
	pat := MatchPattern(res)
	if pat == nil || pat.Name != "Memory-Induced IO Storm" {
		got := "nil"
		if pat != nil {
			got = pat.Name
		}
		t.Fatalf("real swap+IO should match Memory-Induced IO Storm, got %s", got)
	}
}

// TestSwapActivityEvidenceEmitted proves the emitter fix: when swap is active the
// memory analysis must emit a fired mem.swap.activity evidence (the ID the whole
// pattern/narrative/causal layer consumes); when idle it must not fire.
func TestSwapActivityEvidenceEmitted(t *testing.T) {
	mkSnap := func() *model.Snapshot {
		s := &model.Snapshot{}
		s.Global.Memory.Total = 16 * 1024 * 1024 * 1024
		s.Global.Memory.Available = 8 * 1024 * 1024 * 1024
		return s
	}
	strengthOf := func(r model.RCAEntry, id string) (float64, bool) {
		for _, ev := range r.EvidenceV2 {
			if ev.ID == id {
				return ev.Strength, true
			}
		}
		return 0, false
	}

	// Active swap: 25 MB/s in + 5 MB/s out — well above the warn threshold.
	active := analyzeMemory(nil, mkSnap(), &model.RateSnapshot{SwapInRate: 25, SwapOutRate: 5}, systemProfile{}, effectiveRCAThresholds{})
	if s, ok := strengthOf(active, "mem.swap.activity"); !ok || s <= 0 {
		t.Fatalf("active swap did not emit a fired mem.swap.activity (ok=%v strength=%v)", ok, s)
	}

	// Idle: no swap — mem.swap.activity must not fire.
	idle := analyzeMemory(nil, mkSnap(), &model.RateSnapshot{}, systemProfile{}, effectiveRCAThresholds{})
	if s, ok := strengthOf(idle, "mem.swap.activity"); ok && s > 0 {
		t.Fatalf("idle host wrongly fired mem.swap.activity at strength %v", s)
	}
}
