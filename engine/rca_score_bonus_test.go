//go:build linux

package engine

import (
	"testing"

	"github.com/ftahirops/xtop/model"
)

// TestApplyScoreBonus pins the ordering fix: a domain bonus (steal, drops) must
// be applied AFTER the score floor and only to a score that already cleared it,
// so a sub-threshold domain can't be resurrected into a bottleneck by the bonus.
func TestApplyScoreBonus(t *testing.T) {
	cases := []struct {
		name              string
		score, bonus, floor int
		gate              bool
		want              int
	}{
		{"below floor cannot be resurrected by bonus", 15, 10, 20, true, 0},
		{"below floor, no gate", 15, 10, 20, false, 0},
		{"above floor augmented when gated", 25, 10, 20, true, 35},
		{"above floor untouched when not gated", 25, 10, 20, false, 25},
		{"zero score stays zero", 0, 10, 1, true, 0},
		{"cap at 100", 98, 10, 20, true, 100},
	}
	for _, tc := range cases {
		got := applyScoreBonus(tc.score, tc.bonus, tc.floor, tc.gate)
		if got != tc.want {
			t.Errorf("%s: applyScoreBonus(%d,%d,%d,%v)=%d want %d",
				tc.name, tc.score, tc.bonus, tc.floor, tc.gate, got, tc.want)
		}
	}
}

// TestEvidenceFired covers the gate helper.
func TestEvidenceFired(t *testing.T) {
	evs := []model.Evidence{
		{ID: "cpu.steal", Strength: 0.0},
		{ID: "cpu.busy", Strength: 0.9},
	}
	if evidenceFired(evs, "cpu.steal") {
		t.Error("cpu.steal has strength 0 — must not count as fired")
	}
	if !evidenceFired(evs, "cpu.busy") {
		t.Error("cpu.busy has strength 0.9 — must count as fired")
	}
	if evidenceFired(evs, "cpu.missing") {
		t.Error("absent evidence must not count as fired")
	}
}
