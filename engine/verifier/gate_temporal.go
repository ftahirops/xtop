package verifier

import (
	"fmt"
	"time"

	"github.com/ftahirops/xtop/model"
)

// temporalOrderingGate asserts the supporting evidence has been active
// long enough to be a real cause, not a transient spike.
//
// Per NEXTGEN §5: "did the claimed cause start before the effect? did
// it sustain long enough?"
//
// Phase 4 implementation: we don't yet have effect-start timestamps
// (Phase 4 follow-up: candidate generators carry the effect's onset).
// What we DO have, on every Fact, is Duration — how long this signal
// has been observed crossing its threshold. The simplest temporal
// check is therefore: at least one supporting fact must show Duration
// ≥ minSustainedDuration.
//
// Rule:
//
//   - at least one supporting fact must have Duration ≥ 6s
//   - facts with zero Duration are tolerated (just-fired this tick) but
//     can't be the one that satisfies the threshold
//
// 6s matches the engine's existing `minSustainedSec` constant — a
// signal that sustained that long is unlikely to be a transient blip.
// Once Phase 5's replay corpus lands, this threshold becomes tunable
// per mechanism.
//
// Note on Phase 2 fact population: today most facts don't have a
// non-zero Duration field set — the domain analyzers don't fill it
// in yet. That migration is the "wire" step in task 4.7 below. Until
// then, this gate will fail-closed (return false) for most candidates,
// which is the correct conservative default: abstain when proof of
// duration is missing.
type temporalOrderingGate struct{}

func (temporalOrderingGate) ID() string { return "temporal_ordering" }

func (temporalOrderingGate) Evaluate(c Candidate, facts []model.Fact, _ *model.EntityGraph) model.GateResult {
	const minSustainedDuration = 6 * time.Second

	if len(c.SupportingFactIDs) == 0 {
		return model.GateResult{
			GateID: "temporal_ordering",
			Passed: false,
			Reason: "no supporting facts to check duration",
		}
	}

	byID := make(map[string]model.Fact, len(facts))
	for _, f := range facts {
		byID[f.ID] = f
	}

	var longest time.Duration
	var longestID string
	for _, fid := range c.SupportingFactIDs {
		f, ok := byID[fid]
		if !ok {
			continue
		}
		if f.Duration > longest {
			longest = f.Duration
			longestID = f.ID
		}
	}

	if longest >= minSustainedDuration {
		return model.GateResult{
			GateID:    "temporal_ordering",
			Passed:    true,
			Reason:    fmt.Sprintf("%s sustained %.1fs ≥ %.0fs threshold", longestID, longest.Seconds(), minSustainedDuration.Seconds()),
			FactsUsed: []string{longestID},
		}
	}

	return model.GateResult{
		GateID:    "temporal_ordering",
		Passed:    false,
		Reason:    fmt.Sprintf("longest fact duration %.1fs below %.0fs threshold (signals may be transient)", longest.Seconds(), minSustainedDuration.Seconds()),
		FactsUsed: c.SupportingFactIDs,
	}
}
