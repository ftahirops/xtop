package ui

import (
	"testing"

	"github.com/charmbracelet/lipgloss"
)

// ---------------------------------------------------------------------------
// wrapText (Task 6.4) — ANSI-safe text wrap
// ---------------------------------------------------------------------------

// TestWrapText_PlainLongString verifies that a plain ASCII string is wrapped
// at the correct display width.
func TestWrapText_PlainLongString(t *testing.T) {
	const maxW = 20
	input := "The quick brown fox jumps over the lazy dog and keeps going on"
	lines := wrapText(input, maxW)
	if len(lines) < 2 {
		t.Fatalf("expected multiple lines for long input, got %d: %v", len(lines), lines)
	}
	for i, line := range lines {
		w := lipgloss.Width(line)
		if w > maxW {
			t.Errorf("line %d display width %d exceeds maxW %d: %q", i, w, maxW, line)
		}
	}
}

// TestWrapText_ANSIColorCodes verifies that text containing ANSI escape
// sequences is wrapped correctly — each output line's display width (measured
// by lipgloss.Width, which strips ANSI) must not exceed the wrap width.
// The old len()-based approach would overcount ANSI bytes and produce lines
// that are too wide or miss breaks entirely.
func TestWrapText_ANSIColorCodes(t *testing.T) {
	const maxW = 30
	// Build a string with words that include ANSI color codes.
	// "\033[31m" = red, "\033[0m" = reset — 7+4 = 11 invisible bytes per word.
	ansiWord := "\033[31mhello\033[0m"    // display width 5
	plainWord := "world"                  // display width 5
	// Repeat enough times to force wrapping: 8 pairs = 16 words × ~6 chars = ~96 display chars
	var text string
	for i := 0; i < 8; i++ {
		if i > 0 {
			text += " "
		}
		text += ansiWord + " " + plainWord
	}

	lines := wrapText(text, maxW)
	if len(lines) < 2 {
		t.Fatalf("expected multiple lines for long ANSI input, got %d; text display width=%d",
			len(lines), lipgloss.Width(text))
	}
	for i, line := range lines {
		w := lipgloss.Width(line)
		if w > maxW {
			t.Errorf("line %d display width %d exceeds maxW %d (ANSI not stripped correctly): %q",
				i, w, maxW, line)
		}
	}
}

// TestWrapText_ShortTextUnchanged verifies that text shorter than maxW is
// returned as a single line without modification.
func TestWrapText_ShortTextUnchanged(t *testing.T) {
	const maxW = 80
	input := "Short text"
	lines := wrapText(input, maxW)
	if len(lines) != 1 {
		t.Fatalf("expected 1 line for short text, got %d: %v", len(lines), lines)
	}
	if lines[0] != input {
		t.Errorf("expected short text unchanged, got %q", lines[0])
	}
}

// TestWrapText_IndentPreserved verifies that leading spaces on the first line
// are preserved as indent on continuation lines.
func TestWrapText_IndentPreserved(t *testing.T) {
	const maxW = 20
	input := "  word1 word2 word3 word4 word5 word6"
	lines := wrapText(input, maxW)
	if len(lines) < 2 {
		t.Fatalf("expected multiple lines, got %d", len(lines))
	}
	// All lines after the first should preserve the 2-space indent
	for i, line := range lines {
		if len(line) < 2 || line[0] != ' ' || line[1] != ' ' {
			t.Errorf("line %d missing leading indent: %q", i, line)
		}
		w := lipgloss.Width(line)
		if w > maxW {
			t.Errorf("line %d display width %d exceeds maxW %d", i, w, maxW)
		}
	}
}
