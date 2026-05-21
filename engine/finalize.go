package engine

import "github.com/ftahirops/xtop/model"

// finalize is the single, idempotent mutation point for the three
// "summary" fields on AnalysisResult: PrimaryScore, Health, and
// Confidence. Per NEXTGEN Phase 1 task 4, all other pipeline stages
// must treat these as inputs to read, not values to write — and the
// last statement of AnalyzeRCA is e.finalize(result, hist).
//
// This file deliberately starts MINIMAL. The current behavior of
// AnalyzeRCA mutates these fields at ~10 scattered sites; migrating
// each one is a separate, characterizable step. Phase 1 ships the
// SHAPE of the contract (a centralized hook + tests guarding its
// properties) without forcing a wholesale move that risks behavior
// regression.
//
// Properties this function guarantees (and the tests verify):
//   - Idempotent: calling finalize twice on the same result is a no-op.
//   - Score-bounded: PrimaryScore is clamped to [0,100] before return.
//   - Confidence-bounded: Confidence is clamped to [0,100].
//
// Properties this function does NOT yet enforce (Phase 1A follow-up):
//   - Single-source-of-truth for Health derivation. Currently scattered.
//   - Deterministic Confidence (currently subject to map-iteration order).
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
}
