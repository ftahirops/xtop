package verifier

import (
	"fmt"

	"github.com/ftahirops/xtop/model"
)

// signalQualityGate asserts the candidate has enough high-confidence
// measured evidence to be argued over. Per NEXTGEN §5: "data complete
// enough? collection quality sufficient? source confidence acceptable?"
//
// This is the foundational gate — if it fails, every other gate's
// answer is moot. We can't reason about a cause when we don't have
// trustworthy data.
//
// Rule today (deliberately tunable):
//
//   - candidate must have at least 2 supporting facts
//   - average confidence of supporting facts must be ≥ 0.7
//   - at least one supporting fact must be a kernel-direct source
//     (confidence ≥ 0.85)
//
// These thresholds are NOT tuned for production yet — they're a
// reasonable starting point. Phase 7 (precision program) will tune
// based on the replay corpus.
type signalQualityGate struct{}

func (signalQualityGate) ID() string { return "signal_quality" }

func (signalQualityGate) Evaluate(c Candidate, facts []model.Fact, _ *model.EntityGraph) model.GateResult {
	const (
		minSupportingFacts = 2
		minAvgConfidence   = 0.7
		highSourceConfMin  = 0.85
	)

	if len(c.SupportingFactIDs) < minSupportingFacts {
		return model.GateResult{
			GateID:    "signal_quality",
			Passed:    false,
			Reason:    fmt.Sprintf("only %d supporting facts; need ≥ %d", len(c.SupportingFactIDs), minSupportingFacts),
			FactsUsed: c.SupportingFactIDs,
		}
	}

	// Index facts by ID for O(1) lookup of the supporting set.
	byID := make(map[string]model.Fact, len(facts))
	for _, f := range facts {
		byID[f.ID] = f
	}

	var sumConf float64
	matched := 0
	hasHighConf := false
	for _, fid := range c.SupportingFactIDs {
		f, ok := byID[fid]
		if !ok {
			continue
		}
		sumConf += float64(f.Confidence)
		matched++
		if float64(f.Confidence) >= highSourceConfMin {
			hasHighConf = true
		}
	}
	if matched == 0 {
		return model.GateResult{
			GateID:    "signal_quality",
			Passed:    false,
			Reason:    "no supporting facts resolved against the fact slice",
			FactsUsed: c.SupportingFactIDs,
		}
	}
	avgConf := sumConf / float64(matched)
	if avgConf < minAvgConfidence {
		return model.GateResult{
			GateID:    "signal_quality",
			Passed:    false,
			Reason:    fmt.Sprintf("average confidence %.2f below threshold %.2f", avgConf, minAvgConfidence),
			FactsUsed: c.SupportingFactIDs,
		}
	}
	if !hasHighConf {
		return model.GateResult{
			GateID:    "signal_quality",
			Passed:    false,
			Reason:    fmt.Sprintf("no supporting fact has confidence ≥ %.2f (need at least one kernel-direct source)", highSourceConfMin),
			FactsUsed: c.SupportingFactIDs,
		}
	}
	return model.GateResult{
		GateID:    "signal_quality",
		Passed:    true,
		Reason:    fmt.Sprintf("%d facts, avg confidence %.2f, at least one kernel-direct", matched, avgConf),
		FactsUsed: c.SupportingFactIDs,
	}
}
