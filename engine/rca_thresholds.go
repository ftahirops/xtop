package engine

import "github.com/ftahirops/xtop/config"

// effectiveRCAThresholds holds resolved threshold values used during scoring.
// All fields are guaranteed non-zero: resolveRCAThresholds fills zeros with
// the compiled-in const defaults, so behavior is identical when no config override exists.
type effectiveRCAThresholds struct {
	ScoreCritical      int
	ScoreDegraded      int
	ScoreFloor         int
	MinIOPSForLatency  float64
	IoFsFullFreePct    float64
	IoDstateBumpScore  int
	MemOOMMinScore     int
	MemSafeAvailPct    float64
	CpuSafeBusyPct     float64
	JvmHeapPressurePct float64
}

// resolveRCAThresholds returns an effectiveRCAThresholds where every zero
// field in t is replaced by the compiled-in const default.
func resolveRCAThresholds(t config.RCAThresholds) effectiveRCAThresholds {
	e := effectiveRCAThresholds{
		ScoreCritical:      t.ScoreCritical,
		ScoreDegraded:      t.ScoreDegraded,
		ScoreFloor:         t.ScoreFloor,
		MinIOPSForLatency:  t.MinIOPSForLatency,
		IoFsFullFreePct:    t.IoFsFullFreePct,
		IoDstateBumpScore:  t.IoDstateBumpScore,
		MemOOMMinScore:     t.MemOOMMinScore,
		MemSafeAvailPct:    t.MemSafeAvailPct,
		CpuSafeBusyPct:     t.CpuSafeBusyPct,
		JvmHeapPressurePct: t.JvmHeapPressurePct,
	}
	if e.ScoreCritical == 0 {
		e.ScoreCritical = rcaScoreCritical
	}
	if e.ScoreDegraded == 0 {
		e.ScoreDegraded = rcaScoreDegraded
	}
	if e.ScoreFloor == 0 {
		e.ScoreFloor = rcaScoreFloor
	}
	if e.MinIOPSForLatency == 0 {
		e.MinIOPSForLatency = minIOPSForLatency
	}
	if e.IoFsFullFreePct == 0 {
		e.IoFsFullFreePct = ioFsFullFreePct
	}
	if e.IoDstateBumpScore == 0 {
		e.IoDstateBumpScore = ioDstateBumpScore
	}
	if e.MemOOMMinScore == 0 {
		e.MemOOMMinScore = memOOMMinScore
	}
	if e.MemSafeAvailPct == 0 {
		e.MemSafeAvailPct = memSafeAvailPct
	}
	if e.CpuSafeBusyPct == 0 {
		e.CpuSafeBusyPct = cpuSafeBusyPct
	}
	if e.JvmHeapPressurePct == 0 {
		e.JvmHeapPressurePct = jvmHeapPressurePct
	}
	return e
}

// ApplyRCAThresholds resolves config thresholds (zero → const default) and
// stores them on the engine. Call once after NewEngine, before first Tick.
func (e *Engine) ApplyRCAThresholds(t config.RCAThresholds) {
	e.rcaT = resolveRCAThresholds(t)
}

// thresholds returns the engine's effective thresholds, falling back to
// compiled-in defaults when e is nil (unit-test code paths).
func (e *Engine) thresholds() effectiveRCAThresholds {
	if e == nil {
		return resolveRCAThresholds(config.RCAThresholds{})
	}
	return e.rcaT
}
