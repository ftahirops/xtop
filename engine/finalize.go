package engine

import "github.com/ftahirops/xtop/model"

// finalizationCtx carries the pipeline outputs that finalize needs to
// produce the canonical Health + Confidence values. NEXTGEN Phase 1B
// uses this to migrate decision logic out of AnalyzeRCA's body and
// into a single deterministic place.
//
// Today finalize only consumes `primary` (the top-scoring RCA entry).
// Future phases will extend this to include:
//   - hasCritEvidence (from OOM kills / disk-ETA scan)
//   - alignedAppDomain (from app-health-bridge)
//   - alertHysteresis (from hist.alert)
//
// Keep the struct flat and small — it is the *only* state that finalize
// is allowed to read besides the result itself.
type finalizationCtx struct {
	primary *model.RCAEntry // top-scoring RCA entry; may be nil
}

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
// finalize is a method to allow future expansion (per-engine state like
// calibration tables). Currently it reads nothing off the receiver, so
// callers may invoke (*Engine)(nil).finalize(...) safely — and the free
// function finalizeResult provides a nil-engine entry point.
func finalizeResult(result *model.AnalysisResult, ctx *finalizationCtx, hist *History) {
	(*Engine)(nil).finalize(result, ctx, hist)
}

// finalizeHysteresis is the second-stage finalizer. It applies the
// sustained-threshold alert state-machine after post-decision policy
// upgrades (app-health-bridge, hidden-latency) have had their chance.
//
// Split from finalize() because hysteresis depends on Health AFTER
// upgrades, not the raw score-band decision.
func finalizeHysteresis(result *model.AnalysisResult, hist *History, hasCritEvidence bool) {
	if result == nil || hist == nil || hist.alert == nil {
		return
	}
	result.Health = hist.alert.Update(result.Health, result.PrimaryScore, hasCritEvidence)
}

func (e *Engine) finalize(result *model.AnalysisResult, ctx *finalizationCtx, hist *History) {
	if result == nil {
		return
	}
	// 1. Clamp into bounds — input guard.
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

	// 2. Score-band Health decision. Migrated from engine/rca.go L340-361
	// into this single mutation site. The trust gate gates the verdict;
	// failing the gate downgrades the Health to Inconclusive while
	// preserving the Confidence number (so callers can still see WHY
	// the engine abstained).
	switch {
	case result.PrimaryScore >= rcaScoreCritical:
		if ctx != nil && ctx.primary != nil && v2TrustGate(ctx.primary.EvidenceV2) {
			result.Health = model.HealthCritical
		} else {
			result.Health = model.HealthInconclusive
		}
		if ctx != nil && ctx.primary != nil {
			result.Confidence = int(ctx.primary.DomainConf * 100)
		}
	case result.PrimaryScore >= rcaScoreDegraded:
		if ctx != nil && ctx.primary != nil && v2TrustGate(ctx.primary.EvidenceV2) {
			result.Health = model.HealthDegraded
		} else {
			result.Health = model.HealthInconclusive
		}
		if ctx != nil && ctx.primary != nil {
			result.Confidence = int(ctx.primary.DomainConf * 100)
		}
	}

	// 3. OK-when-zero contract: a zero PrimaryScore means no bottleneck
	// fired — Health must be OK and Confidence must be the well-known
	// OK constant. This is the I6 invariant promoted from spot-check
	// to contract. Runs LAST so it overrides any score-band branch
	// that may have set Health based on bonuses since cleared.
	if result.PrimaryScore == 0 {
		result.Health = model.HealthOK
		result.Confidence = rcaHealthOKConfidence
	} else if result.PrimaryScore < rcaScoreDegraded {
		// Score is positive but below the degraded threshold — same
		// effective contract: Health = OK, Confidence = OK-constant.
		// Matches the inline else-branch behavior at engine/rca.go L358.
		result.Health = model.HealthOK
		result.Confidence = rcaHealthOKConfidence
	}

	// 4. Re-clamp Confidence in case trust-gate path produced a value
	// out of bounds (DomainConf was unbounded historically).
	if result.Confidence < 0 {
		result.Confidence = 0
	}
	if result.Confidence > 100 {
		result.Confidence = 100
	}
}
