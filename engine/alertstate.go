package engine

import "github.com/ftahirops/xtop/model"

const sustainedWallClockSec = 15 // target wall-clock seconds for state transition

// AlertState implements a sustained-threshold alert state machine.
// State transitions (both escalation and de-escalation) require
// a sustained period (~15s wall-clock) at the new level.
// Critical evidence (OOM, disk ETA < 5m) can bypass the sustained requirement.
type AlertState struct {
	current           model.HealthLevel
	candidate         model.HealthLevel
	candidateTicks    int
	sustainedRequired int // ticks needed (computed from interval)
}

// NewAlertState creates an AlertState calibrated for the given collection interval.
// The sustained requirement is computed to approximate sustainedWallClockSec.
func NewAlertState(intervalSec int) *AlertState {
	ticks := sustainedWallClockSec / intervalSec
	if ticks < 3 {
		ticks = 3 // minimum 3 ticks to avoid flapping
	}
	return &AlertState{sustainedRequired: ticks}
}

// Update processes a new tick and returns the authoritative health level.
// health is the pre-computed health level (already respects v2 trust gate).
// hasCritEvidence is true if instant-escalation evidence is present (e.g. OOM).
func (as *AlertState) Update(health model.HealthLevel, hasCritEvidence bool) model.HealthLevel {
	required := as.sustainedRequired
	if required == 0 {
		required = 10 // fallback for zero-value struct
	}

	// Instant override: critical evidence bypasses sustained requirement
	if hasCritEvidence && health >= model.HealthCritical {
		as.current = model.HealthCritical
		as.candidate = model.HealthCritical
		as.candidateTicks = 0
		return as.current
	}

	// Check if health matches current candidate
	if health == as.candidate {
		as.candidateTicks++
	} else {
		// New candidate
		as.candidate = health
		as.candidateTicks = 1
	}

	// Transition if sustained long enough
	if as.candidateTicks >= required && as.candidate != as.current {
		as.current = as.candidate
	}

	return as.current
}
