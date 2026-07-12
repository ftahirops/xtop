//go:build linux

package engine

import (
	"testing"

	"github.com/ftahirops/xtop/model"
)

// TestBlameMemorySlabLeak: when the cause is a kernel slab leak, WHO must point
// at kernel slab, not an innocent top-RSS userspace process (WHO/WHY must agree).
func TestBlameMemorySlabLeak(t *testing.T) {
	result := &model.AnalysisResult{RCA: []model.RCAEntry{{
		Bottleneck: BottleneckMemory,
		EvidenceV2: []model.Evidence{{ID: "mem.slab.leak", Strength: 0.8, Severity: model.SeverityCrit}},
	}}}
	rates := &model.RateSnapshot{ProcessRates: []model.ProcessRate{
		{Comm: "innocent-app", PID: 42, MemPct: 40, RSS: 1 << 30},
	}}

	entries := blameMemory(result, rates)
	if len(entries) == 0 {
		t.Fatal("no blame entries")
	}
	if entries[0].Comm == "innocent-app" {
		t.Fatalf("slab leak blamed on innocent userspace process %q instead of kernel slab", entries[0].Comm)
	}
	if entries[0].Comm != "kernel-slab" {
		t.Fatalf("expected kernel-slab as top blame, got %q", entries[0].Comm)
	}
}

// TestBlameMemoryNoSlab: without a slab leak, normal top-RSS blame stands.
func TestBlameMemoryNoSlab(t *testing.T) {
	result := &model.AnalysisResult{RCA: []model.RCAEntry{{
		Bottleneck: BottleneckMemory,
		EvidenceV2: []model.Evidence{{ID: "mem.available.low", Strength: 0.8, Severity: model.SeverityCrit}},
	}}}
	rates := &model.RateSnapshot{ProcessRates: []model.ProcessRate{
		{Comm: "hungry-app", PID: 42, MemPct: 40, RSS: 1 << 30},
	}}
	entries := blameMemory(result, rates)
	if len(entries) == 0 || entries[0].Comm != "hungry-app" {
		t.Fatalf("expected hungry-app as top blame without slab leak, got %v", entries)
	}
}

// TestBlameCPUStealAlignsWithNarrative: when the cpu.steal evidence is active
// (so the narrative says hypervisor), WHO must include the hypervisor entry —
// even in the band where steal% <= busy%*0.3, which the old ad-hoc threshold
// missed, producing a WHO/WHY contradiction.
func TestBlameCPUStealAlignsWithNarrative(t *testing.T) {
	result := &model.AnalysisResult{RCA: []model.RCAEntry{{
		Bottleneck: BottleneckCPU,
		EvidenceV2: []model.Evidence{{ID: "cpu.steal", Strength: 0.3, Severity: model.SeverityWarn}},
	}}}
	// steal 6% with busy 90%: 6 <= 90*0.3 (27), so the old threshold added no
	// hypervisor entry despite the steal narrative.
	rates := &model.RateSnapshot{CPUStealPct: 6, CPUBusyPct: 90}

	entries := blameCPU(result, rates)
	found := false
	for _, e := range entries {
		if e.Comm == "hypervisor-steal" {
			found = true
		}
	}
	if !found {
		t.Fatal("cpu.steal narrative active but WHO has no hypervisor-steal entry (WHO/WHY diverge)")
	}
}
