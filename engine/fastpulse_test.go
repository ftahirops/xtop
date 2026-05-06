//go:build linux

package engine

import (
	"testing"
	"time"

	"github.com/ftahirops/xtop/model"
)

func TestFastPulse_StreakAccrues(t *testing.T) {
	fp := NewFastPulse(50)
	// Backdate the streak start so SustainedAbove reports a non-trivial duration.
	streakStart := time.Now().Add(-2 * time.Second)
	fp.observe("cpu.psi", 10.0, streakStart)
	d, ok := fp.SustainedAbove("cpu.psi")
	if !ok {
		t.Fatal("expected streak after first above-threshold sample")
	}
	if d < 1500*time.Millisecond {
		t.Errorf("duration = %v, want >=1.5s", d)
	}

	// A later same-streak observation must not move firstAboveAt (we want the
	// duration to keep growing relative to the original start).
	fp.observe("cpu.psi", 12.0, time.Now())
	d2, _ := fp.SustainedAbove("cpu.psi")
	if d2 < d {
		t.Errorf("duration regressed across same-streak observe: was %v, now %v", d, d2)
	}
}

func TestFastPulse_BelowThresholdResets(t *testing.T) {
	fp := NewFastPulse(50)
	now := time.Now()
	fp.observe("cpu.psi", 10.0, now)
	if _, ok := fp.SustainedAbove("cpu.psi"); !ok {
		t.Fatal("expected streak")
	}
	// Drop below threshold
	fp.observe("cpu.psi", 0.5, now.Add(time.Second))
	if _, ok := fp.SustainedAbove("cpu.psi"); ok {
		t.Error("streak must reset when value drops below threshold")
	}
}

func TestFastPulse_StartStopIdempotent(t *testing.T) {
	fp := NewFastPulse(50)
	fp.Start()
	fp.Start() // second call must not panic or leak goroutine
	fp.Stop()
	fp.Stop() // second call must not panic
}

// TestFastPulse_RefinesSustainedFor verifies the integration with
// stampSustainedDurations: when FastPulse has been tracking a streak longer
// than the coarse signalOnsets, the evidence's SustainedForSec is bumped up.
func TestFastPulse_RefinesSustainedFor(t *testing.T) {
	hist := NewHistory(10, 3)
	hist.FastPulse = NewFastPulse(100)
	// Simulate: FastPulse has been streaking for 8s, but signalOnsets only
	// recorded the evidence ID 2s ago.
	hist.FastPulse.observe("cpu.psi", 10.0, time.Now().Add(-8*time.Second))
	hist.signalOnsets["cpu.psi"] = time.Now().Add(-2 * time.Second)

	result := &model.AnalysisResult{
		RCA: []model.RCAEntry{{
			EvidenceV2: []model.Evidence{
				{ID: "cpu.psi", Strength: 0.8},
			},
		}},
	}
	stampSustainedDurations(result, hist)

	got := result.RCA[0].EvidenceV2[0].SustainedForSec
	if got < 7 {
		t.Errorf("SustainedForSec = %v, want >=7 (FastPulse should win over coarse onset)", got)
	}
}
