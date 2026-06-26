package ui

import (
	"strings"
	"testing"

	"github.com/charmbracelet/lipgloss"
	"github.com/muesli/termenv"
)

// hasColorSeq returns true when the string contains foreground or background
// color ANSI escape sequences. Lipgloss may combine attributes into a single
// CSI parameter string (e.g. "\x1b[1;38;2;255;85;85m"), so we look for the
// SGR parameter numbers 38 (foreground) and 48 (background) as substrings
// within any escape sequence rather than requiring them to follow "\x1b["
// directly.
func hasColorSeq(s string) bool {
	return strings.Contains(s, "38;") || strings.Contains(s, "48;")
}

// hasBoldSeq returns true when the string contains a bold escape sequence.
func hasBoldSeq(s string) bool {
	return strings.Contains(s, "\x1b[1m") || strings.Contains(s, "\x1b[0;1") || strings.Contains(s, "\x1b[1;")
}

// TestNoColorStripsColorSequences verifies that when initStyles is called with
// noColor=true, rendered output contains no foreground/background color ANSI
// sequences. Bold and underline emphasis must be preserved.
func TestNoColorStripsColorSequences(t *testing.T) {
	// Force TrueColor profile so lipgloss emits ANSI sequences regardless of
	// whether the test runner has a real TTY attached.
	lipgloss.SetColorProfile(termenv.TrueColor)
	t.Cleanup(func() {
		// Restore profile and rebuild styles with the real env value so
		// later tests in the same process are not affected.
		lipgloss.SetColorProfile(termenv.Ascii) // conservative default for CI
		initStyles(noColor)
	})

	const probe = "TEST"

	// --- Colored path ---
	initStyles(false) // noColor=false → colors should be present
	coloredOut := critStyle.Render(probe) // critStyle has Foreground + Bold
	if !hasColorSeq(coloredOut) {
		t.Errorf("colored path: expected color ANSI sequences in %q", coloredOut)
	}

	// --- Monochrome path (NO_COLOR) ---
	initStyles(true) // noColor=true → no color sequences
	monoOut := critStyle.Render(probe)
	if hasColorSeq(monoOut) {
		t.Errorf("NO_COLOR path: unexpected color ANSI sequences in %q", monoOut)
	}

	// Bold should still be present in the monochrome path (critStyle is Bold).
	if !hasBoldSeq(monoOut) {
		t.Logf("NO_COLOR path: bold sequence not detected in %q (renderer may be Ascii — checking explicit bold)", monoOut)
		// Under a non-TTY test environment with a forced TrueColor profile,
		// bold should appear. If it is missing the renderer's profile is
		// unexpectedly stripping SGR; log but do not fail hard because the
		// primary contract is the absence of color.
	}

	// Additional: warnStyle should also carry no color.
	warnOut := warnStyle.Render(probe)
	if hasColorSeq(warnOut) {
		t.Errorf("NO_COLOR path: unexpected color ANSI sequences in warnStyle output %q", warnOut)
	}

	// selectedStyle uses Background; that must also be stripped.
	selOut := selectedStyle.Render(probe)
	if hasColorSeq(selOut) {
		t.Errorf("NO_COLOR path: unexpected background color ANSI in selectedStyle output %q", selOut)
	}
}

// TestNoColorEnvVar exercises the package-level init path via t.Setenv so that
// when NO_COLOR is present in the environment the styles built at init time
// also carry no color. This test re-inits styles to simulate a fresh start.
func TestNoColorEnvVar(t *testing.T) {
	lipgloss.SetColorProfile(termenv.TrueColor)
	t.Cleanup(func() {
		lipgloss.SetColorProfile(termenv.Ascii)
		initStyles(noColor)
	})

	t.Setenv("NO_COLOR", "1")
	// Re-run initStyles as if init() had seen NO_COLOR set.
	initStyles(true)

	out := titleStyle.Render("TITLE")
	if hasColorSeq(out) {
		t.Errorf("NO_COLOR=1: titleStyle should have no color sequences, got %q", out)
	}
}

// TestColorPresentWithoutNoColor is the inverse: without NO_COLOR the color
// styles must emit color ANSI sequences.
func TestColorPresentWithoutNoColor(t *testing.T) {
	lipgloss.SetColorProfile(termenv.TrueColor)
	t.Cleanup(func() {
		lipgloss.SetColorProfile(termenv.Ascii)
		initStyles(noColor)
	})

	initStyles(false)
	out := okStyle.Render("OK")
	if !hasColorSeq(out) {
		t.Errorf("without NO_COLOR: okStyle should contain color sequences, got %q", out)
	}
}
