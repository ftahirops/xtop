package engine

import (
	"time"

	"github.com/ftahirops/xtop/model"
)

// MountGrowthTracker smooths filesystem growth rates using EWMA.
type MountGrowthTracker struct {
	ewma         map[string]float64   // mount -> smoothed growth bytes/sec
	growthStart  map[string]time.Time // mount -> when sustained growth first detected
}

// NewMountGrowthTracker creates a new tracker.
func NewMountGrowthTracker() *MountGrowthTracker {
	return &MountGrowthTracker{
		ewma:        make(map[string]float64),
		growthStart: make(map[string]time.Time),
	}
}

// Smooth applies EWMA to growth rates and recomputes ETA and state.
func (t *MountGrowthTracker) Smooth(rates []model.MountRate) {
	const alpha = 0.3

	now := time.Now()

	for i := range rates {
		r := &rates[i]
		key := r.MountPoint

		raw := r.GrowthBytesPerSec
		prevSmoothed, hasPrev := t.ewma[key]
		if hasPrev {
			r.PrevGrowthBPS = prevSmoothed
			r.GrowthBytesPerSec = alpha*raw + (1-alpha)*prevSmoothed
		}
		t.ewma[key] = r.GrowthBytesPerSec

		// Track when growth started
		if r.GrowthBytesPerSec > 1024 { // > 1 KB/s = real growth
			if _, ok := t.growthStart[key]; !ok {
				t.growthStart[key] = now
			}
			r.GrowthStarted = t.growthStart[key]
		} else {
			// Growth stopped
			delete(t.growthStart, key)
			r.GrowthStarted = time.Time{}
		}

		// Recompute ETA
		if r.GrowthBytesPerSec > 0 && r.FreeBytes > 0 {
			r.ETASeconds = float64(r.FreeBytes) / r.GrowthBytesPerSec
		} else {
			r.ETASeconds = -1
		}

		// Recompute state
		r.State = diskGuardState(r.FreePct, r.ETASeconds, r.InodeUsedPct)
	}
}

// diskGuardState returns the mount state based on thresholds.
func diskGuardState(freePct, etaSec, inodePct float64) string {
	// CRIT: free% < 5 OR ETA < 1800s OR inode% > 95
	if freePct < 5 {
		return "CRIT"
	}
	if etaSec > 0 && etaSec < 1800 {
		return "CRIT"
	}
	if inodePct > 95 {
		return "CRIT"
	}

	// WARN: free% < 15 OR ETA < 7200s OR inode% > 85
	if freePct < 15 {
		return "WARN"
	}
	if etaSec > 0 && etaSec < 7200 {
		return "WARN"
	}
	if inodePct > 85 {
		return "WARN"
	}

	return "OK"
}

// WorstDiskGuardState returns the worst state across all mounts.
func WorstDiskGuardState(rates []model.MountRate) string {
	worst := "OK"
	for _, r := range rates {
		if r.State == "CRIT" {
			return "CRIT"
		}
		if r.State == "WARN" {
			worst = "WARN"
		}
	}
	return worst
}
