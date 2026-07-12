//go:build linux

package engine

import (
	"testing"

	"github.com/ftahirops/xtop/model"
)

// TestRunQueueUsesInstantaneousRunnable reproduces SEED-B: run-queue saturation
// must be measured from instantaneous runnable tasks (procs_running), not the
// Load1 EWMA. The xgen1 screen showed 13 runnable on 6 cores (ratio 2.17,
// saturated) while Load1 was only 3.2 (ratio 0.53), so the cpu.runqueue
// evidence never fired and the correct oversubscription narrative was starved.
func TestRunQueueUsesInstantaneousRunnable(t *testing.T) {
	curr := &model.Snapshot{}
	curr.Global.CPU.NumCPUs = 6
	curr.Global.CPU.LoadAvg = model.LoadAvg{Load1: 3.2, Running: 13, Total: 220}

	entry := analyzeCPU(nil, curr, &model.RateSnapshot{}, systemProfile{}, effectiveRCAThresholds{})

	var strength float64
	found := false
	for _, ev := range entry.EvidenceV2 {
		if ev.ID == "cpu.runqueue" {
			strength = ev.Strength
			found = true
		}
	}
	if !found {
		t.Fatal("no cpu.runqueue evidence emitted")
	}
	if strength <= 0 {
		t.Fatalf("cpu.runqueue did not fire for 13 runnable/6 cores (strength=%v); "+
			"still using Load1-based ratio instead of procs_running", strength)
	}
}

// TestRunQueueQuietDoesNotFire guards the low end: 2 runnable on 8 cores is not
// saturation and must not fire.
func TestRunQueueQuietDoesNotFire(t *testing.T) {
	curr := &model.Snapshot{}
	curr.Global.CPU.NumCPUs = 8
	curr.Global.CPU.LoadAvg = model.LoadAvg{Load1: 1.5, Running: 2, Total: 300}

	entry := analyzeCPU(nil, curr, &model.RateSnapshot{}, systemProfile{}, effectiveRCAThresholds{})
	for _, ev := range entry.EvidenceV2 {
		if ev.ID == "cpu.runqueue" && ev.Strength > 0 {
			t.Fatalf("cpu.runqueue wrongly fired for 2 runnable/8 cores (strength=%v)", ev.Strength)
		}
	}
}
