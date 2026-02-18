package util

import "time"

// Rate computes the per-second rate between two counter values.
func Rate(prev, curr uint64, dt time.Duration) float64 {
	if dt <= 0 || curr < prev {
		return 0
	}
	return float64(curr-prev) / dt.Seconds()
}

// RatePct computes the percentage utilization between two counter values
// given a time delta and a total capacity in the same unit.
func RatePct(prev, curr uint64, dt time.Duration, capacity float64) float64 {
	if dt <= 0 || capacity <= 0 || curr < prev {
		return 0
	}
	r := float64(curr-prev) / dt.Seconds()
	pct := (r / capacity) * 100
	if pct > 100 {
		return 100
	}
	return pct
}

// CPUPct computes CPU usage percentage from two tick values and total ticks.
func CPUPct(prevActive, currActive, prevTotal, currTotal uint64) float64 {
	dtotal := currTotal - prevTotal
	if dtotal == 0 {
		return 0
	}
	dactive := currActive - prevActive
	return float64(dactive) / float64(dtotal) * 100
}

// Delta returns curr - prev, or 0 if curr < prev (counter wrap).
func Delta(prev, curr uint64) uint64 {
	if curr < prev {
		return 0
	}
	return curr - prev
}
