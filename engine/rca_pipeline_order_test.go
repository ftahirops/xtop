//go:build linux

package engine

import (
	"testing"

	"github.com/ftahirops/xtop/model"
)

// TestProxmoxEvidenceCountedInScoring reproduces readiness-review Finding #1:
// Proxmox VM memory evidence was appended AFTER scoring / EvidenceGroups / Checks
// were computed, so a VM OOM could show in EvidenceV2 but never affect the memory
// verdict. On a healthy host (no base memory evidence fires), the VM's OOM +
// mem-PSI evidence must still be counted.
func TestProxmoxEvidenceCountedInScoring(t *testing.T) {
	curr := &model.Snapshot{}
	curr.Global.Memory.Total = 16 * 1024 * 1024 * 1024
	curr.Global.Memory.Available = 8 * 1024 * 1024 * 1024 // healthy: no base evidence fires
	curr.Global.Proxmox = &model.ProxmoxMetrics{
		IsProxmoxHost: true,
		VMs: []model.ProxmoxVM{{
			VMID: 100, Name: "db", Status: "running",
			MemOOMKills: 3,  // fires pve.vm.oom
			PSIMemSome:  50, // fires pve.vm.mempsi (> pvePSIMemMinSome=10)
		}},
	}

	entry := analyzeMemory(nil, curr, &model.RateSnapshot{}, systemProfile{}, effectiveRCAThresholds{})

	if entry.EvidenceGroups < 1 {
		t.Fatalf("Proxmox VM OOM/PSI evidence not counted in EvidenceGroups (got %d) — "+
			"evidence emitted after scoring", entry.EvidenceGroups)
	}
	// The pve evidence must also be present in Checks (derived alongside EvidenceGroups).
	if len(entry.Checks) == 0 {
		t.Fatal("Proxmox VM evidence produced no Checks — computed before the pve block")
	}
}
