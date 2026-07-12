//go:build linux

package engine

import (
	"time"

	"github.com/ftahirops/xtop/model"
)

// detectChanges runs change detection, config-drift, and kernel-parameter
// drift detection for this tick, returning the merged change list. This is
// extracted (copied verbatim) from the detection logic inline in Tick; Tick
// itself is left untouched for now.
func (e *Engine) detectChanges(snap *model.Snapshot) []model.SystemChange {
	var changes []model.SystemChange

	// Change detection: track new/stopped processes and recent package changes
	if e.changeDetector != nil {
		changes = e.changeDetector.DetectChanges(snap)
	}
	// Config drift: walk the watchlist of /etc/* configs; merge any newly-
	// detected modifications into Changes so they appear in Recent Activity.
	if e.configDrift != nil {
		changes = append(changes, e.configDrift.Tick()...)
	}

	// P4.5 — kernel-parameter drift (sysctl / /proc/sys).
	// Runs every 30 ticks (~30 s at 1 Hz). Best-effort: panics are
	// recovered so a bad Snapshot() never aborts the tick.
	e.tickCount++
	if e.configDriftEnabled && e.paramDriftDetector != nil && e.tickCount%30 == 0 {
		func() {
			defer func() { recover() }() //nolint:errcheck
			live, err := e.configSnapshotFn()
			if err != nil || len(live) == 0 {
				return
			}
			now := time.Now()
			paramChanges, newBaselines := e.paramDriftDetector.Detect(live, now)
			if len(newBaselines) > 0 {
				// Stage for the next SaveBaselineState flush.
				e.pendingParamBaselines = append(e.pendingParamBaselines, newBaselines...)
			}
			if len(paramChanges) > 0 {
				changes = append(changes, paramChanges...)
			}
		}()
	}

	return changes
}
