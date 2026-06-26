package ui

import "testing"

// TestPageInnerW verifies that pageInnerW never returns a width wider than the
// terminal on narrow terminals, and returns the expected value for wide ones.
func TestPageInnerW(t *testing.T) {
	cases := []struct {
		termWidth int
		wantMax   int // result must be <= wantMax
		wantExact int // if > 0, result must equal this exactly
	}{
		// Narrow terminals: must not exceed termWidth
		{termWidth: 20, wantMax: 20},
		{termWidth: 30, wantMax: 30},
		{termWidth: 40, wantMax: 40},
		{termWidth: 50, wantMax: 50},
		{termWidth: 60, wantMax: 60},
		// Floor: very narrow terminal returns at least 20
		{termWidth: 10, wantMax: 20, wantExact: 20},
		{termWidth: 15, wantMax: 20, wantExact: 20},
		// Wide terminals: expected exact value (termWidth - 6)
		{termWidth: 80, wantMax: 80, wantExact: 74},
		{termWidth: 120, wantMax: 120, wantExact: 114},
		{termWidth: 200, wantMax: 200, wantExact: 194},
		// Transition: exactly 66 cols uses normal path -> 66-6=60
		{termWidth: 66, wantMax: 66, wantExact: 60},
		// Just below transition
		{termWidth: 65, wantMax: 65},
	}

	for _, tc := range cases {
		got := pageInnerW(tc.termWidth)
		if got > tc.wantMax {
			t.Errorf("pageInnerW(%d) = %d; want <= %d (would overflow terminal)", tc.termWidth, got, tc.wantMax)
		}
		if tc.wantExact > 0 && got != tc.wantExact {
			t.Errorf("pageInnerW(%d) = %d; want %d", tc.termWidth, got, tc.wantExact)
		}
	}
}

// TestOverlayWidth verifies the overlay width formula used in renderSignalOverlay.
func TestOverlayWidth(t *testing.T) {
	overlayW := func(termWidth int) int {
		w := min(termWidth-4, 80)
		if w < 20 {
			w = 20
		}
		return w
	}

	cases := []struct {
		termWidth int
		want      int
	}{
		{termWidth: 10, want: 20},  // floor
		{termWidth: 20, want: 20},  // floor (20-4=16 < 20)
		{termWidth: 24, want: 20},  // 24-4=20, exactly at floor
		{termWidth: 40, want: 36},
		{termWidth: 80, want: 76},
		{termWidth: 84, want: 80},  // 84-4=80 = cap
		{termWidth: 120, want: 80}, // capped at 80
		{termWidth: 200, want: 80}, // capped at 80
	}

	for _, tc := range cases {
		got := overlayW(tc.termWidth)
		if got != tc.want {
			t.Errorf("overlayW(%d) = %d; want %d", tc.termWidth, got, tc.want)
		}
	}
}
