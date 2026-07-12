//go:build linux

package engine

import (
	"testing"

	"github.com/ftahirops/xtop/model"
)

func ioEvidence(entry model.RCAEntry, id string) (model.Evidence, bool) {
	for _, ev := range entry.EvidenceV2 {
		if ev.ID == id {
			return ev, true
		}
	}
	return model.Evidence{}, false
}

// TestWritebackThresholdUnit reproduces the unit bug: mem.Writeback is in BYTES
// but io.writeback used warn/crit of 5/20, so any writeback above 20 bytes
// pinned strength at 1.0 on every host. A few MB of writeback is normal and
// must not fire; a large flush must.
func TestWritebackThresholdUnit(t *testing.T) {
	mk := func(wb uint64) model.RCAEntry {
		curr := &model.Snapshot{}
		curr.Global.Memory.Total = 16 * 1024 * 1024 * 1024
		curr.Global.Memory.Writeback = wb
		return analyzeIO(nil, curr, &model.RateSnapshot{}, systemProfile{}, effectiveRCAThresholds{})
	}

	// 2 MB writeback — normal, must not fire.
	small, ok := ioEvidence(mk(2*1024*1024), "io.writeback")
	if !ok {
		t.Fatal("no io.writeback evidence emitted")
	}
	if small.Strength > 0 {
		t.Fatalf("2MB writeback wrongly fired (strength=%v) — threshold still in bytes", small.Strength)
	}

	// 60 MB writeback — genuine flush pressure, must fire.
	big, _ := ioEvidence(mk(60*1024*1024), "io.writeback")
	if big.Strength <= 0 {
		t.Fatalf("60MB writeback did not fire (strength=%v)", big.Strength)
	}
}

// TestFsFullDampenerStaticMount reproduces the FREE%-vs-USED% dampener bug: a
// filesystem that is full-ish (88% used) but NOT growing should have its
// confidence dampened, so it doesn't hijack the narrative at 0.9. The dampener
// compared worstFreePct (12) > 95 — always false — so it was dead code.
func TestFsFullDampenerStaticMount(t *testing.T) {
	curr := &model.Snapshot{}
	rcaT := effectiveRCAThresholds{IoFsFullFreePct: 15} // fsFull when free < 15%
	// 88% used (free 12%), no growth.
	rates := &model.RateSnapshot{MountRates: []model.MountRate{
		{MountPoint: "/data", FreePct: 12, UsedPct: 88, GrowthBytesPerSec: 0},
	}}

	entry := analyzeIO(nil, curr, rates, systemProfile{}, rcaT)
	ev, ok := ioEvidence(entry, "io.fsfull")
	if !ok {
		t.Fatal("io.fsfull evidence not emitted for an 88%-used mount")
	}
	if ev.Confidence >= 0.9 {
		t.Fatalf("static 88%%-full mount kept high confidence %v — dampener is dead code", ev.Confidence)
	}
}

// TestFsFullGrowingMountStaysConfident guards the other side: a full filesystem
// that IS actively growing must keep high confidence.
func TestFsFullGrowingMountStaysConfident(t *testing.T) {
	curr := &model.Snapshot{}
	rcaT := effectiveRCAThresholds{IoFsFullFreePct: 15}
	rates := &model.RateSnapshot{MountRates: []model.MountRate{
		{MountPoint: "/data", FreePct: 12, UsedPct: 88, GrowthBytesPerSec: 5 * 1024 * 1024},
	}}

	entry := analyzeIO(nil, curr, rates, systemProfile{}, rcaT)
	ev, ok := ioEvidence(entry, "io.fsfull")
	if !ok {
		t.Fatal("io.fsfull evidence not emitted")
	}
	if ev.Confidence < 0.9 {
		t.Fatalf("actively-growing full mount was wrongly dampened to %v", ev.Confidence)
	}
}
