//go:build linux

package ui

import "testing"

// TestFmtRankQuad verifies the Ranks column spells out dimensions and shows only
// the ones an app is actually ranked in — self-explanatory without a legend.
func TestFmtRankQuad(t *testing.T) {
	cases := []struct {
		c, m, io, n int
		want        string
	}{
		{3, 4, 1, 0, "CPU#3 Mem#4 IO#1"},        // unranked Net (0) omitted
		{0, 1, 0, 0, "Mem#1"},                    // only the ranked dim shown
		{1, 2, 2, 1, "CPU#1 Mem#2 IO#2 Net#1"},   // all four
		{0, 0, 0, 0, "—"},                        // unranked everywhere
	}
	for _, tc := range cases {
		if got := fmtRankQuad(tc.c, tc.m, tc.io, tc.n); got != tc.want {
			t.Errorf("fmtRankQuad(%d,%d,%d,%d) = %q, want %q", tc.c, tc.m, tc.io, tc.n, got, tc.want)
		}
	}
}
