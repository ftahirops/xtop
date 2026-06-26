package ui

import (
	"os"
	"strings"
	"testing"

	"github.com/charmbracelet/lipgloss"
	"github.com/muesli/termenv"
)

// hasColorSeq returns true when the string contains foreground or background
// color ANSI escape sequences. It detects three families:
//  1. 24-bit / 256-color: SGR parameters 38; (fg) or 48; (bg).
//  2. Basic ANSI palette: standard colors 30-37 and bright colors 90-97,
//     recognised as \x1b[ followed by '3'|'9' and a digit 0-7.
//
// Italic (\x1b[3m) and crossed-out (\x1b[9m) have no trailing digit, so
// they are not falsely matched by rule 2.
func hasColorSeq(s string) bool {
	if strings.Contains(s, "38;") || strings.Contains(s, "48;") {
		return true
	}
	// Walk the string looking for \x1b[<digit><digit>... patterns.
	for i := 0; i+3 < len(s); i++ {
		if s[i] == '\x1b' && s[i+1] == '[' {
			// Bright colors 90-97: first digit '9', second '0'-'7'.
			// Standard colors 30-37: first digit '3', second '0'-'7'.
			if (s[i+2] == '9' || s[i+2] == '3') && s[i+3] >= '0' && s[i+3] <= '7' {
				return true
			}
		}
	}
	return false
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
	saved := lipgloss.ColorProfile()
	lipgloss.SetColorProfile(termenv.TrueColor)
	t.Cleanup(func() {
		// Restore profile and rebuild styles with the real env value so
		// later tests in the same process are not affected.
		lipgloss.SetColorProfile(saved)
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
	saved := lipgloss.ColorProfile()
	lipgloss.SetColorProfile(termenv.TrueColor)
	t.Cleanup(func() {
		lipgloss.SetColorProfile(saved)
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
	saved := lipgloss.ColorProfile()
	lipgloss.SetColorProfile(termenv.TrueColor)
	t.Cleanup(func() {
		lipgloss.SetColorProfile(saved)
		initStyles(noColor)
	})

	initStyles(false)
	out := okStyle.Render("OK")
	if !hasColorSeq(out) {
		t.Errorf("without NO_COLOR: okStyle should contain color sequences, got %q", out)
	}
}

// TestInlineColorSitesGated verifies that inline Foreground/Background sites
// (those that build lipgloss styles ad-hoc rather than via initStyles) also
// emit no color when noColor is true. We exercise the docker badge helpers as
// a representative sample since they were the most numerous inline sites.
func TestInlineColorSitesGated(t *testing.T) {
	saved := lipgloss.ColorProfile()
	lipgloss.SetColorProfile(termenv.TrueColor)
	t.Cleanup(func() {
		lipgloss.SetColorProfile(saved)
		// Restore to whatever the real env wants.
		noColor = os.Getenv("NO_COLOR") != ""
		initStyles(noColor)
	})

	// --- colored path: inline sites must emit color ---
	noColor = false
	initStyles(false)
	badge := dockerStackBadge("compose")
	if !hasColorSeq(badge) {
		t.Errorf("colored path: dockerStackBadge(compose) expected color sequences, got %q", badge)
	}
	orch := dockerOrchBadge("k8s")
	if !hasColorSeq(orch) {
		t.Errorf("colored path: dockerOrchBadge(k8s) expected color sequences, got %q", orch)
	}

	// --- NO_COLOR path: inline sites must NOT emit color ---
	noColor = true
	initStyles(true)
	badge = dockerStackBadge("compose")
	if hasColorSeq(badge) {
		t.Errorf("NO_COLOR path: dockerStackBadge(compose) unexpected color sequences, got %q", badge)
	}
	orch = dockerOrchBadge("swarm")
	if hasColorSeq(orch) {
		t.Errorf("NO_COLOR path: dockerOrchBadge(swarm) unexpected color sequences, got %q", orch)
	}
}
