package engine

import "github.com/ftahirops/xtop/model"

const sustainedWallClockSec = 15 // target wall-clock seconds for state transition

const healthHistoryLen = 20

// AlertState implements a sustained-threshold alert state machine.
// State transitions (both escalation and de-escalation) require
// a sustained period (~15s wall-clock) at the new level.
// Critical evidence (OOM, disk ETA < 5m) can bypass the sustained requirement.
type AlertState struct {
	current           model.HealthLevel
	candidate         model.HealthLevel
	candidateTicks    int
	sustainedRequired int // ticks needed (computed from interval)

	// Hysteresis & oscillation detection
	recentHealthHistory [healthHistoryLen]model.HealthLevel
	historyIdx          int
	oscillationCount    int // transitions in recent history window

	// NoHysteresis disables the sustained-threshold requirement.
	// Use this for one-shot CLI/API mode where you want immediate health
	// reflection of the current score.
	NoHysteresis bool
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
// score is the raw RCA score used for hysteresis thresholds.
// hasCritEvidence is true if instant-escalation evidence is present (e.g. OOM).
func (as *AlertState) Update(health model.HealthLevel, score int, hasCritEvidence bool) model.HealthLevel {
	required := as.sustainedRequired
	if required == 0 {
		required = 10 // fallback for zero-value struct
	}

	// Instant override: critical evidence bypasses sustained requirement
	if hasCritEvidence && health >= model.HealthCritical {
		as.current = model.HealthCritical
		as.candidate = model.HealthCritical
		as.candidateTicks = 0
		as.trackHistory(health)
		return as.current
	}

	// --- Score hysteresis band (~5 points below entry threshold) ---
	// Entry: CRIT at score>=60, exit CRIT only when score<55
	if as.current == model.HealthCritical && score >= 55 {
		health = model.HealthCritical
	}
	// Entry: WARN at score>=25, exit WARN only when score<20
	if as.current == model.HealthDegraded && score >= 20 {
		health = model.HealthDegraded
	}

	// Bypass hysteresis for one-shot mode
	if as.NoHysteresis {
		as.current = health
		as.trackHistory(health)
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
	// Escalation is fast (2 ticks); de-escalation is slower to prevent flapping.
	needed := required
	isEscalation := as.candidate > as.current
	isDeescalation := as.candidate < as.current

	if isEscalation {
		// Fast escalation: 2 consecutive ticks at the higher level
		needed = 2
	} else if isDeescalation {
		if as.current == model.HealthCritical {
			// CRIT → WARN/OK: slow de-escalation (4 ticks)
			needed = 4
		} else {
			// WARN → OK: moderate de-escalation (3 ticks)
			needed = 3
		}
	}

	if as.candidateTicks >= needed && as.candidate != as.current {
		as.current = as.candidate
	}

	// Track history and detect oscillation
	as.trackHistory(health)

	// Oscillation damping: if 3+ transitions in recent window, hold at DEGRADED minimum
	if as.oscillationCount >= 3 && as.current < model.HealthDegraded {
		as.current = model.HealthDegraded
	}

	return as.current
}

// trackHistory records the health value in the circular buffer and counts transitions.
func (as *AlertState) trackHistory(health model.HealthLevel) {
	as.recentHealthHistory[as.historyIdx] = health
	as.historyIdx = (as.historyIdx + 1) % healthHistoryLen

	// Count transitions in recent history
	transitions := 0
	for i := 1; i < healthHistoryLen; i++ {
		if as.recentHealthHistory[i] != as.recentHealthHistory[i-1] &&
			as.recentHealthHistory[i-1] != 0 { // 0 = not yet filled
			transitions++
		}
	}
	as.oscillationCount = transitions
}
