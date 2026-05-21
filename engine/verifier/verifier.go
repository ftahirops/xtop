// Package verifier is the multi-level proof system defined by
// NEXTGEN_RCA_ARCHITECTURE.md §5.
//
// The verifier takes candidates produced by detectors + the
// hypothesis engine, runs them through a series of gates, and emits
// VerifiedCauses with a discrete tier (A/B/C/D). Tier A is the only
// output that counts toward the 0.1% precision target — everything
// weaker is abstention by design.
//
// Phase 4 ships the framework + the first two gates (signal-quality,
// ownership-consistency). Future commits add baseline-deviation,
// temporal-ordering, blast-radius, counter-evidence, and deep-probe.
//
// Design rules:
//
//  1. Gates are PURE FUNCTIONS of (Candidate, Facts, EntityGraph).
//     No side effects. Same input → same output. This is what makes
//     replay (Phase 5) possible.
//  2. Gates return a GateResult, never panic. Errors become
//     Passed=false with a Reason.
//  3. The verifier RUNS ALL GATES — it does NOT short-circuit on
//     first failure. Operators want the full audit trail.
//  4. Tier derivation is deterministic from the gates' outputs.
//     See classifyTier() for the rules.
//  5. The DEFAULT verdict on weak evidence is TierDInconclusive.
//     Per NEXTGEN: "If proof is weak, return INCONCLUSIVE."

package verifier

import (
	"time"

	"github.com/ftahirops/xtop/model"
)

// Candidate is the verifier's input — a proposed causal mechanism
// with the root entity and the facts that support it. The hypothesis
// engine (Phase 4 candidate generator) produces these; the verifier
// classifies them. For now, AnalyzeRCA produces simple candidates
// directly from its RCAEntries.
type Candidate struct {
	// Mechanism is the human-readable causal claim. Inherited verbatim
	// into VerifiedCause.Mechanism.
	Mechanism string

	// RootEntityID identifies the proposed root cause entity in the
	// EntityGraph. Empty when the candidate is host-scope.
	RootEntityID string

	// Domain is which resource class this candidate is about.
	Domain model.Domain

	// SupportingFactIDs is the list of Fact.ID values that the
	// detector cited as evidence FOR this mechanism. The verifier
	// uses these for the signal-quality + temporal gates.
	SupportingFactIDs []string

	// AffectedEntityIDs is what the candidate claims will be affected.
	// Used by the blast-radius gate (Phase 4 follow-up).
	AffectedEntityIDs []string
}

// Gate evaluates a candidate against one rule. Returns a GateResult
// recording the verdict + the evidence used. MUST be deterministic and
// have no side effects.
type Gate interface {
	// ID returns the stable gate identifier ("signal_quality",
	// "ownership_consistency", etc.).
	ID() string

	// Evaluate returns the gate's verdict for this candidate. Facts
	// and graph are read-only — never mutate them.
	Evaluate(c Candidate, facts []model.Fact, graph *model.EntityGraph) model.GateResult
}

// Verifier orchestrates a fixed sequence of gates. Construct once and
// reuse — the gate list is immutable after construction.
type Verifier struct {
	gates []Gate
}

// New returns a Verifier with the given gate sequence.
func New(gates ...Gate) *Verifier {
	return &Verifier{gates: gates}
}

// Default returns a Verifier with the Phase 4 gate set. As more gates
// land they're added here in deliberate evaluation order: signal quality
// first (foundational), then ownership (cheap), then temporal +
// baseline (need fact metadata), then the heavier gates.
func Default() *Verifier {
	return New(
		signalQualityGate{},
		ownershipConsistencyGate{},
		temporalOrderingGate{},
		baselineDeviationGate{},
		// Future:
		//   blastRadiusGate{}
		//   counterEvidenceGate{}
		//   deepProbeGate{}
	)
}

// Verify runs every gate against the candidate and returns a
// VerifiedCause with tier derived from the gate outputs.
//
// Facts is the full slice from AnalysisResult.Facts. The verifier
// scans by ID — gates may look beyond SupportingFactIDs to find
// counter-evidence (relevant in future gates).
//
// graph may be nil — gates that need it (ownership-consistency) will
// fail-closed with a clear Reason in that case.
func (v *Verifier) Verify(c Candidate, facts []model.Fact, graph *model.EntityGraph) model.VerifiedCause {
	now := time.Now()
	results := make([]model.GateResult, 0, len(v.gates))
	for _, g := range v.gates {
		results = append(results, g.Evaluate(c, facts, graph))
	}
	tier, confidence := classifyTier(results)
	return model.VerifiedCause{
		Mechanism:    c.Mechanism,
		Tier:         tier,
		RootEntityID: c.RootEntityID,
		BlastRadius:  c.AffectedEntityIDs,
		Confidence:   confidence,
		Gates:        results,
		EvaluatedAt:  now,
	}
}

// classifyTier derives the headline tier from the gate outputs.
//
// Rules (NEXTGEN Phase 4 — extended as gates land):
//
//   - Tier A — ALL gates passed
//   - Tier B — all gates that ran passed, but fewer than the full set
//     evaluated (some not applicable). With only 2 gates active today,
//     this tier is rarely produced; future gates make it common.
//   - Tier C — exactly one gate failed, and it wasn't signal-quality
//   - Tier D — signal-quality failed, OR ≥ 2 gates failed
//
// Confidence is a heuristic: starts at 90 for all-pass, subtracts 20
// per failed gate, floors at 10. This is NOT a probability — operators
// should use Tier as the trust signal.
func classifyTier(results []model.GateResult) (model.VerificationTier, int) {
	if len(results) == 0 {
		// No gates evaluated — abstain.
		return model.TierDInconclusive, 0
	}
	passed := 0
	failed := 0
	signalQualityFailed := false
	for _, r := range results {
		if r.Passed {
			passed++
		} else {
			failed++
			if r.GateID == "signal_quality" {
				signalQualityFailed = true
			}
		}
	}
	confidence := 90 - 20*failed
	if confidence < 10 {
		confidence = 10
	}
	switch {
	case signalQualityFailed:
		// Signal quality is foundational. Failing it means we don't
		// even have enough measured data to argue about — abstain.
		return model.TierDInconclusive, confidence
	case failed >= 2:
		return model.TierDInconclusive, confidence
	case failed == 1:
		return model.TierCProbable, confidence
	case passed == len(results) && len(results) >= 3:
		// Full Tier A requires the full gate suite (≥3). With only
		// 2 gates active today, Verify never produces TierA yet —
		// that's correct: precision must EARN tier A.
		return model.TierAConfirmed, confidence
	case passed == len(results):
		return model.TierBVerified, confidence
	default:
		return model.TierDInconclusive, confidence
	}
}
