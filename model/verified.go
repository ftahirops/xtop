// Verifier output types — NEXTGEN Phase 4.
//
// Per NEXTGEN_RCA_ARCHITECTURE.md §5 "Multi-Level Verification Layer",
// every RCA candidate must pass a series of gates. The output is a
// VerifiedCause with one of four discrete tiers — Confirmed, Verified,
// Probable, Inconclusive — and a record of which gates passed/failed.
//
// The 0.1% false-positive design target depends entirely on strict
// abstention: only Tier A Confirmed verdicts count toward "the engine
// said X and was right". Everything weaker is Inconclusive by default.
//
// Phase 4 ships the contract + the framework + the first two gates.
// Future commits implement the remaining 5 gates (baseline-deviation,
// temporal-ordering, blast-radius, counter-evidence, deep-probe).

package model

import "time"

// VerificationTier classifies how strongly we believe a candidate cause.
// Strict ordering: A > B > C > D. Only Tier A counts toward the
// 0.1% precision goal — everything else MUST be treated as "the engine
// abstained from a strong call."
type VerificationTier string

const (
	// TierAConfirmed requires:
	//   - 3 or more independent evidence families
	//   - correct temporal sequence (cause before effect, sustained)
	//   - owner match (claimed root entity owns the stressed resource)
	//   - no counter-evidence
	//   - deep-probe confirmation if the gate demanded one
	TierAConfirmed VerificationTier = "A_confirmed"

	// TierBVerified requires:
	//   - 2 strong evidence families
	//   - no major contradictions
	//   - ownership-consistency passes
	TierBVerified VerificationTier = "B_verified"

	// TierCProbable means the mechanism is plausible but at least one
	// proof gate did not pass strongly. Callers should treat as a
	// "best guess" — do not act on it without operator review.
	TierCProbable VerificationTier = "C_probable"

	// TierDInconclusive is the abstain output. Impact exists, but the
	// engine refuses to commit to a root cause. This is the HEALTHY
	// default for weak evidence. Per NEXTGEN: "If proof is weak,
	// return INCONCLUSIVE."
	TierDInconclusive VerificationTier = "D_inconclusive"
)

// GateResult is the outcome of one verifier gate evaluating one
// candidate. Carries the verdict + the evidence the verifier used so
// the operator can audit WHY a gate passed or failed.
type GateResult struct {
	// GateID identifies the gate ("signal_quality", "baseline_deviation",
	// "temporal_ordering", "ownership_consistency", "blast_radius",
	// "counter_evidence", "deep_probe"). Stable across versions.
	GateID string `json:"gate_id"`

	// Passed is true if the candidate cleared this gate.
	Passed bool `json:"passed"`

	// Reason is a single-sentence operator-facing explanation. When
	// Passed=false, this is the abstention reason.
	Reason string `json:"reason,omitempty"`

	// FactsUsed lists the Fact.ID values consulted. Lets the operator
	// re-run the gate against the same evidence in replay.
	FactsUsed []string `json:"facts_used,omitempty"`
}

// VerifiedCause is one verifier output — a candidate that's been put
// through every applicable gate, with the resulting tier.
//
// Phase 4 emits one of these per RCA candidate; AnalyzeRCA aggregates
// them into AnalysisResult.VerifiedCauses. Phase 5 (replay) serializes
// the full set so an offline harness can re-derive the same tier from
// the same facts + graph.
type VerifiedCause struct {
	// Mechanism is the proposed causal mechanism. Human-readable, e.g.
	// "CPU contention in service mongod" or "swap-induced disk stall
	// impacting nginx". The verifier doesn't generate this — the
	// hypothesis engine (Phase 4 candidate generator) does. The
	// verifier inherits it.
	Mechanism string `json:"mechanism"`

	// Tier is the headline output. Tier A = trust this. Tier D = the
	// engine refused to commit.
	Tier VerificationTier `json:"tier"`

	// RootEntityID is the claimed root cause's entity (from EntityGraph).
	// Empty when no root entity could be identified (Tier D outputs
	// often have an empty root).
	RootEntityID string `json:"root_entity_id,omitempty"`

	// BlastRadius lists the affected entities. Empty for host-scope
	// causes.
	BlastRadius []string `json:"blast_radius,omitempty"`

	// Confidence is a derived 0-100 score combining the gates that
	// passed. NOT a probability — a calibrated heuristic. Operators
	// should use Tier as the trust signal, not this number.
	Confidence int `json:"confidence"`

	// Gates is the full record of every gate that ran against this
	// candidate, in evaluation order. Tier-degradation can be traced
	// back to the first failing gate.
	Gates []GateResult `json:"gates"`

	// EvaluatedAt is when the verifier produced this output.
	EvaluatedAt time.Time `json:"evaluated_at"`
}
