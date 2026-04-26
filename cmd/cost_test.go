package cmd

import (
	"testing"
	"time"

	"github.com/ftahirops/xtop/engine"
)

// mkRollups returns a synthetic N-minute history with the given per-dim
// constant values. Used to drive the verdict/decision logic without touching
// disk.
func mkRollups(minutes int, cpu, mem, io float64, numCPUs int, memBytes uint64) []engine.UsageRollup {
	start := time.Now().UTC().Add(-time.Duration(minutes) * time.Minute)
	out := make([]engine.UsageRollup, minutes)
	flat := func(v float64) engine.UsageStat {
		return engine.UsageStat{Max: v, P95: v, P50: v, Avg: v}
	}
	for i := 0; i < minutes; i++ {
		out[i] = engine.UsageRollup{
			Minute:    start.Add(time.Duration(i) * time.Minute),
			Samples:   20,
			NumCPUs:   numCPUs,
			MemTotal:  memBytes,
			CPU:       flat(cpu),
			Mem:       flat(mem),
			IO:        flat(io),
			LoadRatio: flat(cpu / 100),
		}
	}
	return out
}

func TestBuildCostReport_InsufficientData(t *testing.T) {
	// 60 minutes < 72h threshold.
	rep := buildCostReport(mkRollups(60, 40, 50, 10, 4, 16*1024*1024*1024), 7)
	if rep.Action != "insufficient_data" {
		t.Errorf("action = %q, want insufficient_data", rep.Action)
	}
	if len(rep.Reasoning) == 0 {
		t.Error("expected reasoning explaining the data gap")
	}
}

func TestBuildCostReport_RecommendsDownsizeWhenIdle(t *testing.T) {
	// 4 days of very light utilization → downsize.
	rs := mkRollups(60*24*4, 12, 35, 5, 8, 32*1024*1024*1024)
	rep := buildCostReport(rs, 7)
	if rep.Action != "downsize" {
		t.Fatalf("action = %q, want downsize; reasoning=%v", rep.Action, rep.Reasoning)
	}
	if rep.Savings == nil {
		t.Fatal("expected Savings populated for downsize action")
	}
	if rep.Savings.FromTier != "8 vCPU" || rep.Savings.ToTier != "4 vCPU" {
		t.Errorf("savings tiers = %q → %q, want 8 → 4 vCPU",
			rep.Savings.FromTier, rep.Savings.ToTier)
	}
	if rep.Savings.PercentSaved != 50 {
		t.Errorf("PercentSaved = %d, want 50", rep.Savings.PercentSaved)
	}
}

func TestBuildCostReport_RecommendsUpsizeWhenCPUHot(t *testing.T) {
	// 4 days of constant 95 % CPU — unambiguously CPU-bound.
	rs := mkRollups(60*24*4, 95, 60, 40, 4, 16*1024*1024*1024)
	rep := buildCostReport(rs, 7)
	if rep.Action != "upsize" {
		t.Fatalf("action = %q, want upsize", rep.Action)
	}
	if rep.CPU.State != "hot" {
		t.Errorf("CPU state = %q, want hot", rep.CPU.State)
	}
	// Upsize recommendation should suggest 2x vCPUs.
	if rep.Savings == nil || rep.Savings.ToTier != "8 vCPU" {
		t.Errorf("expected upsize suggestion 4 → 8 vCPU, got %+v", rep.Savings)
	}
}

func TestBuildCostReport_HoldsWhenBalanced(t *testing.T) {
	// 4 days of 55 % CPU, 55 % Mem — comfortable but not idle.
	rs := mkRollups(60*24*4, 55, 55, 30, 4, 16*1024*1024*1024)
	rep := buildCostReport(rs, 7)
	if rep.Action != "hold" {
		t.Errorf("action = %q, want hold; verdicts cpu=%s mem=%s",
			rep.Action, rep.CPU.State, rep.Memory.State)
	}
}

func TestVerdict_StateThresholds(t *testing.T) {
	// 100 samples at 80 → max 80, p95 80, p50 80 — should be "hot" (>= warm 70).
	v := verdict(fillN(100, 80), fillN(100, 50), 30, 70, 90)
	if v.State != "hot" {
		t.Errorf("state = %q, want hot for p95=80", v.State)
	}
	// 100 samples at 45 → should be "warm" (>= cold 30).
	v = verdict(fillN(100, 45), fillN(100, 30), 30, 70, 90)
	if v.State != "warm" {
		t.Errorf("state = %q, want warm for p95=45", v.State)
	}
	// 100 samples at 20 → "cold".
	v = verdict(fillN(100, 20), fillN(100, 15), 30, 70, 90)
	if v.State != "cold" {
		t.Errorf("state = %q, want cold for p95=20", v.State)
	}
	// 100 samples at 5 → "idle".
	v = verdict(fillN(100, 5), fillN(100, 3), 30, 70, 90)
	if v.State != "idle" {
		t.Errorf("state = %q, want idle for p95=5", v.State)
	}
}

func fillN(n int, v float64) []float64 {
	out := make([]float64, n)
	for i := range out {
		out[i] = v
	}
	return out
}

func TestFmtMinutes(t *testing.T) {
	cases := map[int]string{
		30:       "30m",
		120:      "2h",
		60 * 25:  "1.0d",
		60 * 24 * 7: "7.0d",
	}
	for m, want := range cases {
		if got := fmtMinutes(m); got != want {
			t.Errorf("fmtMinutes(%d) = %q, want %q", m, got, want)
		}
	}
}
