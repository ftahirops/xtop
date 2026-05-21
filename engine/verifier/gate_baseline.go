package verifier

import (
	"fmt"
	"math"

	"github.com/ftahirops/xtop/model"
)

// baselineDeviationGate asserts the supporting evidence is meaningfully
// abnormal compared to baseline — not just a routine working-set state.
//
// Per NEXTGEN §5: "is the signal abnormal for this host, service,
// entity, and time-of-week?"
//
// What this rules out: an alert that fires because thresholds were set
// too aggressively for a workload that ALWAYS runs at that level.
// Example: a Postgres warmup that legitimately spends 30 min at 80%
// CPU after restart — without a baseline check, every restart would
// raise a "CPU contention" alert. With baselines, the engine knows
// that level is normal for this workload-time-of-week combination.
//
// Phase 4 implementation: read Fact.BaselineDelta. A non-zero positive
// value means the fact's value is above the baseline; the larger the
// delta relative to the fact's value, the more anomalous.
//
// Rule:
//
//   - if NO supporting fact has BaselineDelta set, abstain (we have
//     no baseline data — can't tell)
//   - otherwise, at least one supporting fact must show a delta of
//     ≥ 20% of its Value (the signal is materially above baseline)
//
// "No baseline data" → fail is the conservative default. After Phase 5
// (replay corpus) we can calibrate the 20% threshold and the abstain
// behavior.
type baselineDeviationGate struct{}

func (baselineDeviationGate) ID() string { return "baseline_deviation" }

func (baselineDeviationGate) Evaluate(c Candidate, facts []model.Fact, _ *model.EntityGraph) model.GateResult {
	const minDeltaFraction = 0.20 // 20% above baseline

	if len(c.SupportingFactIDs) == 0 {
		return model.GateResult{
			GateID: "baseline_deviation",
			Passed: false,
			Reason: "no supporting facts to check baseline deviation",
		}
	}

	byID := make(map[string]model.Fact, len(facts))
	for _, f := range facts {
		byID[f.ID] = f
	}

	anyBaselined := false
	bestFraction := 0.0
	var bestID string
	for _, fid := range c.SupportingFactIDs {
		f, ok := byID[fid]
		if !ok {
			continue
		}
		if f.BaselineDelta == 0 {
			continue
		}
		anyBaselined = true
		// Avoid divide-by-zero when Value is 0 — use absolute delta
		// against an implicit floor of 1.0.
		denom := math.Abs(f.Value)
		if denom < 1.0 {
			denom = 1.0
		}
		frac := math.Abs(f.BaselineDelta) / denom
		if frac > bestFraction {
			bestFraction = frac
			bestID = f.ID
		}
	}

	if !anyBaselined {
		return model.GateResult{
			GateID: "baseline_deviation",
			Passed: false,
			Reason: "no supporting fact has baseline data — cannot prove abnormality",
		}
	}

	if bestFraction < minDeltaFraction {
		return model.GateResult{
			GateID:    "baseline_deviation",
			Passed:    false,
			Reason:    fmt.Sprintf("largest baseline deviation is %.0f%% (below %.0f%% threshold)", bestFraction*100, minDeltaFraction*100),
			FactsUsed: c.SupportingFactIDs,
		}
	}

	return model.GateResult{
		GateID:    "baseline_deviation",
		Passed:    true,
		Reason:    fmt.Sprintf("%s shows %.0f%% deviation from baseline (≥ %.0f%% threshold)", bestID, bestFraction*100, minDeltaFraction*100),
		FactsUsed: []string{bestID},
	}
}
