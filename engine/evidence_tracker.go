package engine

import (
	"time"

	"github.com/ftahirops/xtop/model"
)

// minSustainedSec is the minimum duration an evidence must have been firing
// before the confirmed trust gate accepts it. 6s ≈ 2 ticks at the default
// 3s collection interval — i.e. seen on this tick AND at least one prior tick.
const minSustainedSec = 6.0

// stampSustainedDurations annotates each Evidence in result.RCA with FirstSeenAt
// and SustainedForSec, reading from History.signalOnsets as cross-tick memory.
//
// Read-only against History; UpdateSignalOnsets handles writes at end of tick.
// On the first tick a new evidence appears, signalOnsets has no entry yet, so
// FirstSeenAt is set to now and SustainedForSec=0. On the next tick (after
// UpdateSignalOnsets ran at end of previous tick), the onset is read back and
// SustainedForSec reflects the real wall-clock duration.
//
// Must be called BEFORE the health decision so confirmedTrustGate can use
// SustainedForSec. Safe to call with nil hist — all evidence gets
// SustainedForSec=0, preserving the existing v2TrustGate behavior for callers
// that don't opt into the confirmed gate.
func stampSustainedDurations(result *model.AnalysisResult, hist *History) {
	if result == nil {
		return
	}
	now := time.Now()

	if hist == nil {
		for di := range result.RCA {
			for ei := range result.RCA[di].EvidenceV2 {
				ev := &result.RCA[di].EvidenceV2[ei]
				if ev.Strength > 0 && ev.FirstSeenAt.IsZero() {
					ev.FirstSeenAt = now
				}
			}
		}
		return
	}

	hist.mu.RLock()
	fp := hist.FastPulse
	for di := range result.RCA {
		for ei := range result.RCA[di].EvidenceV2 {
			ev := &result.RCA[di].EvidenceV2[ei]
			if ev.Strength <= 0 {
				continue
			}
			if onset, ok := hist.signalOnsets[ev.ID]; ok {
				ev.FirstSeenAt = onset
				ev.SustainedForSec = now.Sub(onset).Seconds()
			} else {
				ev.FirstSeenAt = now
				ev.SustainedForSec = 0
			}
		}
	}
	hist.mu.RUnlock()

	// FastPulse refinement: PSI evidence IDs can have a sub-second onset that
	// the coarse signalOnsets (sampled at tick cadence) underreports. Take the
	// max of both — the longer streak is the more honest answer.
	if fp != nil {
		for di := range result.RCA {
			for ei := range result.RCA[di].EvidenceV2 {
				ev := &result.RCA[di].EvidenceV2[ei]
				if ev.Strength <= 0 {
					continue
				}
				if d, ok := fp.SustainedAbove(ev.ID); ok {
					fpSec := d.Seconds()
					if fpSec > ev.SustainedForSec {
						ev.SustainedForSec = fpSec
						ev.FirstSeenAt = now.Add(-d)
					}
				}
			}
		}
	}
}

// confirmedTrustGate is a stricter version of v2TrustGate used by the incident
// recorder to decide when a Suspected incident may be promoted to Confirmed.
//
// Requirements (in addition to v2TrustGate):
//   - At least one fired evidence (strength >= evidenceStrengthMin) has been
//     sustained for >= minSustainedSec.
//
// Per-domain detectors continue to use v2TrustGate (which is duration-agnostic)
// for score-bump decisions; only lifecycle promotion uses this stricter gate.
func confirmedTrustGate(evs []model.Evidence) bool {
	if !v2TrustGate(evs) {
		return false
	}
	for _, e := range evs {
		if e.Strength >= evidenceStrengthMin && e.SustainedForSec >= minSustainedSec {
			return true
		}
	}
	return false
}
