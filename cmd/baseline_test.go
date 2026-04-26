package cmd

import (
	"testing"
)

func TestCmpDim_MaterialityThresholds(t *testing.T) {
	// +5pp is below the 10pp absolute and 25% relative thresholds → not material.
	d := cmpDim("cpu", 40, 45)
	if d.Material {
		t.Errorf("delta 40→45 should not be material: %+v", d)
	}
	// +11pp absolute crosses the 10pp threshold → material.
	d = cmpDim("cpu", 40, 51)
	if !d.Material {
		t.Errorf("delta 40→51 (+11pp) should be material: %+v", d)
	}
	// +6pp absolute but 30% relative crosses the 25% threshold → material.
	d = cmpDim("cpu", 20, 26)
	if !d.Material {
		t.Errorf("delta 20 to 26 (+30 pct) should be material: %+v", d)
	}
	// Baseline zero — no % anchor, small absolute move is not material.
	d = cmpDim("cpu", 0, 3)
	if d.Material {
		t.Errorf("delta 0 to 3 should not be material without a pct anchor: %+v", d)
	}
}

func TestCmpDim_DirectionLabels(t *testing.T) {
	up := cmpDim("mem", 40, 60)
	if up.Direction != "up" {
		t.Errorf("direction for 40→60 = %q, want up", up.Direction)
	}
	down := cmpDim("mem", 60, 40)
	if down.Direction != "down" {
		t.Errorf("direction for 60→40 = %q, want down", down.Direction)
	}
	stable := cmpDim("mem", 40.0, 40.05)
	if stable.Direction != "stable" {
		t.Errorf("direction for ~no-op = %q, want stable", stable.Direction)
	}
}

func TestSummarizeBaselineVerdict_AllCases(t *testing.T) {
	cases := map[string][]baselineDiff{
		"stable": {
			{Direction: "up", Material: false},
			{Direction: "down", Material: false},
		},
		"degraded": {
			{Direction: "up", Material: true},
			{Direction: "up", Material: true},
		},
		"improved": {
			{Direction: "down", Material: true},
		},
		"mixed": {
			{Direction: "up", Material: true},
			{Direction: "down", Material: true},
		},
	}
	for want, diffs := range cases {
		if got := summarizeBaselineVerdict(diffs); got != want {
			t.Errorf("verdict %v = %q, want %q", diffs, got, want)
		}
	}
}

func TestBaselinePath_RejectsTraversal(t *testing.T) {
	bad := []string{"", "../evil", "a/b", ".", "..", "x\\y"}
	for _, n := range bad {
		if _, err := baselinePath(n); err == nil {
			t.Errorf("expected error for invalid name %q", n)
		}
	}
	if _, err := baselinePath("ok_name-1"); err != nil {
		t.Errorf("valid name rejected: %v", err)
	}
}

func TestHoistFlags_AndFirstPositional(t *testing.T) {
	// "save pre-deploy --days 7 --note hello"
	args := []string{"save", "pre-deploy", "--days", "7", "--note", "hello"}
	// Skip the "save" verb; remainder is what runBaseline passes in.
	rest := args[1:]
	flags := hoistFlags(rest)
	want := []string{"--days", "7", "--note", "hello"}
	if !stringSlicesEqual(flags, want) {
		t.Errorf("hoistFlags = %v, want %v", flags, want)
	}
	pos, ok := firstPositional(rest)
	if !ok || pos != "pre-deploy" {
		t.Errorf("firstPositional = %q/%v, want pre-deploy/true", pos, ok)
	}

	// With = syntax: --days=7 doesn't consume the next arg.
	args2 := []string{"--days=7", "my-base", "--note", "x"}
	pos2, ok2 := firstPositional(args2)
	if !ok2 || pos2 != "my-base" {
		t.Errorf("firstPositional with = syntax = %q/%v, want my-base/true", pos2, ok2)
	}
}

func stringSlicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
