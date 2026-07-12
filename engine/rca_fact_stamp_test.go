//go:build linux

package engine

import (
	"testing"
	"time"

	"github.com/ftahirops/xtop/model"
)

// TestStampFactDurationsPSISuffix reproduces readiness-review Finding #5: PSI
// evidence uses ID "cpu.psi" but the paired Fact uses "cpu.psi.avg10", so the
// by-ID join never stamped PSI fact durations — weakening the temporal-ordering
// verifier on the core pressure signals.
func TestStampFactDurationsPSISuffix(t *testing.T) {
	result := &model.AnalysisResult{RCA: []model.RCAEntry{{
		EvidenceV2: []model.Evidence{
			{ID: "cpu.psi", SustainedForSec: 30},
			{ID: "mem.reclaim.direct", SustainedForSec: 10}, // exact-match control
		},
		Facts: []model.Fact{
			{ID: "cpu.psi.avg10"},
			{ID: "mem.reclaim.direct"},
		},
	}}}

	stampFactDurations(result)

	if got := result.RCA[0].Facts[0].Duration; got != 30*time.Second {
		t.Fatalf("PSI fact (cpu.psi.avg10) duration not stamped from cpu.psi evidence: got %v", got)
	}
	if got := result.RCA[0].Facts[1].Duration; got != 10*time.Second {
		t.Fatalf("exact-match fact duration regressed: got %v", got)
	}
}
