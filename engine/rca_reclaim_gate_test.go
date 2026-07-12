//go:build linux

package engine

import (
	"testing"

	"github.com/ftahirops/xtop/model"
)

// TestReclaimGatedByPSI reproduces the reclaim-without-PSI misfire: direct
// reclaim without any memory PSI is normal cache pressure, not a "reclaim
// storm". The PSI dampener previously only lowered CONFIDENCE, but the matcher
// keys off STRENGTH — so Direct Reclaim Storm could fire with PSI=0. The
// reclaim evidence must not fire (strength 0) when PSI is absent, and must fire
// when PSI confirms real pressure.
func TestReclaimGatedByPSI(t *testing.T) {
	mk := func(psiSomeAvg10 float64) model.RCAEntry {
		curr := &model.Snapshot{}
		curr.Global.Memory.Total = 16 * 1024 * 1024 * 1024
		curr.Global.Memory.Available = 8 * 1024 * 1024 * 1024
		curr.Global.PSI.Memory.Some.Avg10 = psiSomeAvg10
		rates := &model.RateSnapshot{DirectReclaimRate: 1000} // well above warn
		return analyzeMemory(nil, curr, rates, systemProfile{}, effectiveRCAThresholds{})
	}
	strengthOf := func(r model.RCAEntry) float64 {
		for _, ev := range r.EvidenceV2 {
			if ev.ID == "mem.reclaim.direct" {
				return ev.Strength
			}
		}
		return -1
	}

	// No PSI: reclaim must not fire.
	if s := strengthOf(mk(0)); s > 0 {
		t.Fatalf("direct reclaim fired with no PSI (strength=%v) — gated on confidence not strength", s)
	}
	// Real PSI pressure: reclaim should fire.
	if s := strengthOf(mk(50)); s <= 0 {
		t.Fatalf("direct reclaim did not fire under real PSI pressure (strength=%v)", s)
	}
}
