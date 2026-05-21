package engine

import "github.com/ftahirops/xtop/model"

// finalize is the single, idempotent mutation point for the three
// "summary" fields on AnalysisResult: PrimaryScore, Health, and
// Confidence. Per NEXTGEN Phase 1 task 4 + Phase 1A task 3, all other
// pipeline stages should treat these as inputs to read, not values to
// write — and the last statement of AnalyzeRCA is e.finalize(result, hist).
//
// Properties this function guarantees (verified by tests):
//   - Idempotent: calling finalize twice on the same result is a no-op.
//   - Score-bounded: PrimaryScore is clamped to [0,100].
//   - Confidence-bounded: Confidence is clamped to [0,100].
//   - OK-when-zero invariant: PrimaryScore == 0 implies Health == OK
//     AND Confidence == rcaHealthOKConfidence (this is the I6 invariant
//     from rca_characterization_test.go, now enforced as a contract by
//     the finalizer rather than as a side-effect of scattered branches).
//
// Properties NOT yet enforced (Phase 1A follow-up):
//   - The Health-decision block at engine/rca.go L348-365 still runs
//     in-line. Migrating it requires introducing a finalizationCtx
//     carrying primary.DomainConf, hasCritEvidence, trust-gate output —
//     a meaningful design move. Until then, finalize and the inline
//     branches both compute the same values and finalize wins last.
//   - Deterministic Confidence (still subject to map-iteration order
//     upstream).
func (e *Engine) finalize(result *model.AnalysisResult, hist *History) {
	if result == nil {
		return
	}
	if result.PrimaryScore < 0 {
		result.PrimaryScore = 0
	}
	if result.PrimaryScore > 100 {
		result.PrimaryScore = 100
	}
	if result.Confidence < 0 {
		result.Confidence = 0
	}
	if result.Confidence > 100 {
		result.Confidence = 100
	}
	// OK-when-zero contract: a zero PrimaryScore means no bottleneck
	// fired — Health must be OK and Confidence must be the well-known
	// OK constant. This is the I6 invariant promoted from spot-check
	// to contract.
	if result.PrimaryScore == 0 {
		result.Health = model.HealthOK
		result.Confidence = rcaHealthOKConfidence
	}
}
