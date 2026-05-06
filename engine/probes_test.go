package engine

import (
	"strings"
	"testing"
	"time"

	"github.com/ftahirops/xtop/model"
)

// TestProbeRunner_DisabledByDefault: with XTOP_PROBES unset, MaybeRun is a no-op.
func TestProbeRunner_DisabledByDefault(t *testing.T) {
	r := NewProbeRunner()
	r.SetEnabled(false) // explicit, in case env was set in CI
	res := r.MaybeRun(&model.AnalysisResult{
		RCA: []model.RCAEntry{{
			EvidenceV2: []model.Evidence{
				{ID: "cpu.busy", Strength: 0.9},
			},
		}},
	})
	if len(res) != 0 {
		t.Errorf("disabled runner must produce no results, got %d", len(res))
	}
}

// TestProbeRunner_RunsOnTrigger: when enabled and a triggering evidence is
// present, the matching probe runs and produces output.
func TestProbeRunner_RunsOnTrigger(t *testing.T) {
	r := NewProbeRunner()
	r.SetEnabled(true)

	// Replace builtin probes with a deterministic test probe.
	r.probes = []Probe{{
		Name:        "echo_test",
		Triggers:    []string{"cpu.busy"},
		MinStrength: 0.5,
		Cmd:         "sh",
		Args:        []string{"-c", "echo HELLO"},
	}}

	res := r.MaybeRun(&model.AnalysisResult{
		RCA: []model.RCAEntry{{
			EvidenceV2: []model.Evidence{
				{ID: "cpu.busy", Strength: 0.9},
			},
		}},
	})
	if len(res) != 1 {
		t.Fatalf("expected 1 result, got %d", len(res))
	}
	if !strings.Contains(res[0].Output, "HELLO") {
		t.Errorf("probe output missing HELLO: %q", res[0].Output)
	}
	if res[0].EvidenceID != "cpu.busy" {
		t.Errorf("trigger ID = %q, want cpu.busy", res[0].EvidenceID)
	}
	if res[0].DurationMs < 0 {
		t.Errorf("DurationMs = %d", res[0].DurationMs)
	}
}

// TestProbeRunner_RateLimit: same probe class won't fire twice in 30s.
func TestProbeRunner_RateLimit(t *testing.T) {
	r := NewProbeRunner()
	r.SetEnabled(true)
	r.probes = []Probe{{
		Name: "echo_test", Triggers: []string{"cpu.busy"},
		MinStrength: 0.5,
		Cmd:         "sh", Args: []string{"-c", "echo X"},
	}}
	res1 := r.MaybeRun(&model.AnalysisResult{RCA: []model.RCAEntry{{
		EvidenceV2: []model.Evidence{{ID: "cpu.busy", Strength: 0.9}},
	}}})
	res2 := r.MaybeRun(&model.AnalysisResult{RCA: []model.RCAEntry{{
		EvidenceV2: []model.Evidence{{ID: "cpu.busy", Strength: 0.9}},
	}}})
	if len(res1) != 1 || len(res2) != 0 {
		t.Errorf("rate-limit broken: first=%d second=%d (expected 1 then 0)", len(res1), len(res2))
	}
}

// TestProbeRunner_BelowMinStrength: weak evidence does not trigger.
func TestProbeRunner_BelowMinStrength(t *testing.T) {
	r := NewProbeRunner()
	r.SetEnabled(true)
	r.probes = []Probe{{
		Name: "echo_test", Triggers: []string{"cpu.busy"},
		MinStrength: 0.7,
		Cmd:         "sh", Args: []string{"-c", "echo X"},
	}}
	res := r.MaybeRun(&model.AnalysisResult{RCA: []model.RCAEntry{{
		EvidenceV2: []model.Evidence{{ID: "cpu.busy", Strength: 0.5}},
	}}})
	if len(res) != 0 {
		t.Errorf("below-strength evidence must not trigger, got %d", len(res))
	}
}

// TestProbeRunner_TimeoutBudgetEnforced: a probe that hangs must be killed
// within probeDeadline.
func TestProbeRunner_TimeoutBudgetEnforced(t *testing.T) {
	r := NewProbeRunner()
	r.SetEnabled(true)
	r.probes = []Probe{{
		Name: "hang_test", Triggers: []string{"cpu.busy"},
		MinStrength: 0.5,
		Cmd:         "sh", Args: []string{"-c", "sleep 30"},
	}}
	start := time.Now()
	res := r.MaybeRun(&model.AnalysisResult{RCA: []model.RCAEntry{{
		EvidenceV2: []model.Evidence{{ID: "cpu.busy", Strength: 0.9}},
	}}})
	elapsed := time.Since(start)
	if elapsed > probeDeadline+2*time.Second {
		t.Errorf("probe exceeded deadline budget: elapsed=%v deadline=%v", elapsed, probeDeadline)
	}
	if len(res) != 1 {
		t.Fatalf("expected 1 result (hung probe should still produce one), got %d", len(res))
	}
	// Either Error is non-empty (context cancelled) or ExitCode is non-zero.
	if res[0].Error == "" && res[0].ExitCode == 0 {
		t.Errorf("hung probe must produce error or non-zero exit, got %+v", res[0])
	}
}

// TestEBPFProbes_OffByDefault: builtinProbes must not include eBPF entries
// unless XTOP_PROBES_EBPF=1. Even when XTOP_PROBES is on.
func TestEBPFProbes_OffByDefault(t *testing.T) {
	t.Setenv("XTOP_PROBES_EBPF", "")
	probes := builtinProbes()
	for _, p := range probes {
		if p.Name == "ebpf_offcpu_stacks" || p.Name == "ebpf_syscall_top" || p.Name == "perf_top_short" {
			t.Errorf("eBPF probe %q must be disabled by default", p.Name)
		}
	}
}

// TestEBPFProbes_OptIn: with XTOP_PROBES_EBPF=1, builtinProbes includes eBPF
// entries IF a supported helper (bpftrace or perf) is on PATH. Otherwise
// the set just stays the same as default — no error.
func TestEBPFProbes_OptIn(t *testing.T) {
	t.Setenv("XTOP_PROBES_EBPF", "1")
	probes := builtinProbes()
	// We don't assert specifics — host may not have bpftrace/perf. Just check
	// that builtinProbes is callable without panic and returns at least the
	// 4 default probes.
	if len(probes) < 4 {
		t.Errorf("builtinProbes() returned %d probes, expected at least 4", len(probes))
	}
}

func TestProbeItoa(t *testing.T) {
	cases := map[int]string{0: "0", 2: "2", 30: "30", -7: "-7"}
	for in, want := range cases {
		if got := probeItoa(in); got != want {
			t.Errorf("probeItoa(%d) = %q, want %q", in, got, want)
		}
	}
}

// TestProbeRunner_OutputCapped: large output is truncated at 64KB and flagged.
func TestProbeRunner_OutputCapped(t *testing.T) {
	r := NewProbeRunner()
	r.SetEnabled(true)
	r.probes = []Probe{{
		Name: "flood_test", Triggers: []string{"cpu.busy"},
		MinStrength: 0.5,
		Cmd:         "sh",
		// 200 KB of 'x'
		Args: []string{"-c", "for i in $(seq 1 200); do printf 'x%.0s' $(seq 1 1024); done"},
	}}
	res := r.MaybeRun(&model.AnalysisResult{RCA: []model.RCAEntry{{
		EvidenceV2: []model.Evidence{{ID: "cpu.busy", Strength: 0.9}},
	}}})
	if len(res) != 1 {
		t.Fatalf("expected 1 result, got %d", len(res))
	}
	if len(res[0].Output) > probeStdoutCap {
		t.Errorf("output exceeded cap: %d > %d", len(res[0].Output), probeStdoutCap)
	}
	if !res[0].Truncated {
		t.Error("Truncated flag must be set when stdout was capped")
	}
}
