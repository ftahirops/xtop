package ui

import (
	"strings"
	"testing"

	"github.com/charmbracelet/lipgloss"
)

// ---------------------------------------------------------------------------
// padRight (Fix #22) — rune-aware right-padding with ellipsis truncation
// ---------------------------------------------------------------------------

func TestPadRight_ASCIIShorterThanWidth(t *testing.T) {
	got := padRight("abc", 10)
	if len(got) != 10 {
		t.Errorf("padRight(%q, 10): expected len 10, got %d (%q)", "abc", len(got), got)
	}
	if got != "abc       " {
		t.Errorf("padRight(%q, 10) = %q, want %q", "abc", got, "abc       ")
	}
}

func TestPadRight_ASCIIExactWidth(t *testing.T) {
	got := padRight("abcde", 5)
	if got != "abcde" {
		t.Errorf("padRight(%q, 5) = %q, want %q", "abcde", got, "abcde")
	}
}

func TestPadRight_ASCIILongerTruncatedWithEllipsis(t *testing.T) {
	got := padRight("hello world", 8)
	// width=8, > 3, so truncate to [:5] + "..." = "hello..."
	want := "hello..."
	if got != want {
		t.Errorf("padRight(%q, 8) = %q, want %q", "hello world", got, want)
	}
}

func TestPadRight_ASCIILongerWidthLE3_NoEllipsis(t *testing.T) {
	got := padRight("hello", 3)
	want := "hel"
	if got != want {
		t.Errorf("padRight(%q, 3) = %q, want %q", "hello", got, want)
	}
}

func TestPadRight_UTF8MultiByte(t *testing.T) {
	// "日本語" has 3 runes, each 3 bytes (9 bytes total).
	input := "日本語"
	// Pad to width 6: 3 runes + 3 spaces
	got := padRight(input, 6)
	runes := []rune(got)
	if len(runes) != 6 {
		t.Errorf("padRight(%q, 6): expected 6 runes, got %d (%q)", input, len(runes), got)
	}
	if string(runes[:3]) != "日本語" {
		t.Errorf("padRight(%q, 6): first 3 runes should be original, got %q", input, string(runes[:3]))
	}
	// Trailing spaces
	if string(runes[3:]) != "   " {
		t.Errorf("padRight(%q, 6): trailing should be 3 spaces, got %q", input, string(runes[3:]))
	}
}

func TestPadRight_UTF8TruncatesWithEllipsis(t *testing.T) {
	// "日本語テスト" = 6 runes. Width 5, > 3, so [:2] + "..." = "日本..."
	input := "日本語テスト"
	got := padRight(input, 5)
	want := "日本..."
	if got != want {
		t.Errorf("padRight(%q, 5) = %q, want %q", input, got, want)
	}
}

func TestPadRight_EmptyString(t *testing.T) {
	got := padRight("", 5)
	if got != "     " {
		t.Errorf("padRight(%q, 5) = %q, want %q", "", got, "     ")
	}
}

func TestPadRight_ZeroWidth(t *testing.T) {
	got := padRight("abc", 0)
	// len(runes)=3 > 0, width <= 3, so runes[:0] = ""
	if got != "" {
		t.Errorf("padRight(%q, 0) = %q, want %q", "abc", got, "")
	}
}

// ---------------------------------------------------------------------------
// truncate (Fix #22) — rune-aware truncation with ellipsis
// ---------------------------------------------------------------------------

func TestTruncate_ShortStringUnchanged(t *testing.T) {
	got := truncate("hi", 10)
	if got != "hi" {
		t.Errorf("truncate(%q, 10) = %q, want %q", "hi", got, "hi")
	}
}

func TestTruncate_ExactLengthUnchanged(t *testing.T) {
	got := truncate("hello", 5)
	if got != "hello" {
		t.Errorf("truncate(%q, 5) = %q, want %q", "hello", got, "hello")
	}
}

func TestTruncate_NormalTruncation(t *testing.T) {
	got := truncate("hello world", 8)
	want := "hello..."
	if got != want {
		t.Errorf("truncate(%q, 8) = %q, want %q", "hello world", got, want)
	}
}

func TestTruncate_MaxLenLE3_NoEllipsis(t *testing.T) {
	tests := []struct {
		maxLen int
		want   string
	}{
		{3, "hel"},
		{2, "he"},
		{1, "h"},
	}
	for _, tt := range tests {
		got := truncate("hello", tt.maxLen)
		if got != tt.want {
			t.Errorf("truncate(%q, %d) = %q, want %q", "hello", tt.maxLen, got, tt.want)
		}
	}
}

func TestTruncate_UTF8(t *testing.T) {
	input := "日本語テスト" // 6 runes
	got := truncate(input, 5)
	want := "日本..."
	if got != want {
		t.Errorf("truncate(%q, 5) = %q, want %q", input, got, want)
	}
}

// ---------------------------------------------------------------------------
// padLeft — left-padding with rune-aware width
// ---------------------------------------------------------------------------

func TestPadLeft_Padding(t *testing.T) {
	got := padLeft("42", 6)
	want := "    42"
	if got != want {
		t.Errorf("padLeft(%q, 6) = %q, want %q", "42", got, want)
	}
}

func TestPadLeft_AlreadyWideEnough(t *testing.T) {
	got := padLeft("hello", 5)
	if got != "hello" {
		t.Errorf("padLeft(%q, 5) = %q, want %q", "hello", got, "hello")
	}
}

func TestPadLeft_TruncatesWhenTooLong(t *testing.T) {
	got := padLeft("hello world", 5)
	want := "hello"
	if got != want {
		t.Errorf("padLeft(%q, 5) = %q, want %q", "hello world", got, want)
	}
}

// ---------------------------------------------------------------------------
// sparkline (Fix #31, #41) — handles empty data, single value, multiple vals
// ---------------------------------------------------------------------------

func TestSparkline_EmptyData_ReturnsPlaceholder(t *testing.T) {
	got := sparkline(nil, 10, 0, 100)
	// The result should contain "no data" in visible text.
	vis := stripANSI(got)
	if !strings.Contains(vis, "no data") {
		t.Errorf("sparkline(nil, 10, 0, 100) visible text = %q, expected to contain 'no data'", vis)
	}
	// Also check with empty (non-nil) slice
	got2 := sparkline([]float64{}, 10, 0, 100)
	vis2 := stripANSI(got2)
	if !strings.Contains(vis2, "no data") {
		t.Errorf("sparkline([]float64{}, 10, 0, 100) visible text = %q, expected to contain 'no data'", vis2)
	}
}

func TestSparkline_EmptyData_ContainsPlaceholderBars(t *testing.T) {
	got := sparkline(nil, 10, 0, 100)
	vis := stripANSI(got)
	// Should contain 10 "░" placeholder characters
	count := strings.Count(vis, "░")
	if count != 10 {
		t.Errorf("sparkline(nil, 10, 0, 100): expected 10 placeholder bars, got %d in %q", count, vis)
	}
}

func TestSparkline_SingleValue_NoPanic(t *testing.T) {
	// Should not panic and should produce some output.
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("sparkline with single value panicked: %v", r)
		}
	}()
	got := sparkline([]float64{50.0}, 10, 0, 100)
	if got == "" {
		t.Error("sparkline([]float64{50.0}, 10, 0, 100) returned empty string")
	}
	vis := stripANSI(got)
	if !strings.Contains(vis, "now=50.0") {
		t.Errorf("sparkline single value: visible text %q should contain 'now=50.0'", vis)
	}
}

func TestSparkline_MultipleValues(t *testing.T) {
	data := []float64{10, 30, 50, 70, 90}
	got := sparkline(data, 5, 0, 100)
	if got == "" {
		t.Error("sparkline with multiple values returned empty string")
	}
	vis := stripANSI(got)
	// Should end with "now=90.0" (the last value)
	if !strings.Contains(vis, "now=90.0") {
		t.Errorf("sparkline multiple values: visible text %q should contain 'now=90.0'", vis)
	}
}

func TestSparkline_MultipleValues_NoPanic(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("sparkline with multiple values panicked: %v", r)
		}
	}()
	data := make([]float64, 100)
	for i := range data {
		data[i] = float64(i)
	}
	// Width smaller than data length triggers resampling
	got := sparkline(data, 20, 0, 100)
	if got == "" {
		t.Error("sparkline with resampling returned empty string")
	}
}

func TestSparkline_EqualMinMax(t *testing.T) {
	// When maxVal == minVal, the function should adjust to avoid division by zero.
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("sparkline with equal min/max panicked: %v", r)
		}
	}()
	data := []float64{50, 50, 50}
	got := sparkline(data, 5, 50, 50)
	if got == "" {
		t.Error("sparkline with equal min/max returned empty string")
	}
}

// ---------------------------------------------------------------------------
// fmtBytes — human-readable byte formatting
// ---------------------------------------------------------------------------

func TestFmtBytes(t *testing.T) {
	tests := []struct {
		input uint64
		want  string
	}{
		{0, "0B"},
		{512, "512B"},
		{1023, "1023B"},
		{1024, "1.0K"},
		{1536, "1.5K"},
		{1048576, "1.0M"},        // 1 MiB
		{1073741824, "1.0G"},     // 1 GiB
		{2147483648, "2.0G"},     // 2 GiB
		{1572864, "1.5M"},        // 1.5 MiB
	}
	for _, tt := range tests {
		got := fmtBytes(tt.input)
		if got != tt.want {
			t.Errorf("fmtBytes(%d) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

// ---------------------------------------------------------------------------
// fmtDuration — seconds to human-readable duration
// ---------------------------------------------------------------------------

func TestFmtDuration_SecondsOnly(t *testing.T) {
	tests := []struct {
		sec  int
		want string
	}{
		{0, "0s"},
		{1, "1s"},
		{59, "59s"},
	}
	for _, tt := range tests {
		got := fmtDuration(tt.sec)
		if got != tt.want {
			t.Errorf("fmtDuration(%d) = %q, want %q", tt.sec, got, tt.want)
		}
	}
}

func TestFmtDuration_Minutes(t *testing.T) {
	tests := []struct {
		sec  int
		want string
	}{
		{60, "1m0s"},
		{90, "1m30s"},
		{3599, "59m59s"},
	}
	for _, tt := range tests {
		got := fmtDuration(tt.sec)
		if got != tt.want {
			t.Errorf("fmtDuration(%d) = %q, want %q", tt.sec, got, tt.want)
		}
	}
}

func TestFmtDuration_Hours(t *testing.T) {
	tests := []struct {
		sec  int
		want string
	}{
		{3600, "1h0m"},
		{3661, "1h1m"},
		{7200, "2h0m"},
		{86400, "24h0m"},
	}
	for _, tt := range tests {
		got := fmtDuration(tt.sec)
		if got != tt.want {
			t.Errorf("fmtDuration(%d) = %q, want %q", tt.sec, got, tt.want)
		}
	}
}

// ---------------------------------------------------------------------------
// Helper: strip ANSI escape codes for visible-content assertions
// ---------------------------------------------------------------------------

// stripANSI removes ANSI escape sequences so we can inspect visible text.
// We use lipgloss.Width to measure visual width, but for string content
// assertions we strip ESC[...m sequences.
func stripANSI(s string) string {
	var out strings.Builder
	i := 0
	for i < len(s) {
		if s[i] == '\x1b' && i+1 < len(s) && s[i+1] == '[' {
			// Skip until we hit a letter (the terminator of the escape sequence)
			j := i + 2
			for j < len(s) && !((s[j] >= 'A' && s[j] <= 'Z') || (s[j] >= 'a' && s[j] <= 'z')) {
				j++
			}
			if j < len(s) {
				j++ // skip the terminator letter
			}
			i = j
			continue
		}
		out.WriteByte(s[i])
		i++
	}
	return out.String()
}

// ---------------------------------------------------------------------------
// Bonus: verify lipgloss.Width works as expected for ANSI-styled strings
// ---------------------------------------------------------------------------

func TestStyledPad_ANSIAware(t *testing.T) {
	styled := critStyle.Render("RED")
	padded := styledPad(styled, 10)
	visW := lipgloss.Width(padded)
	if visW != 10 {
		t.Errorf("styledPad(critStyle.Render('RED'), 10): visual width = %d, want 10", visW)
	}
}

func TestStyledPad_AlreadyWideEnough(t *testing.T) {
	styled := critStyle.Render("REALLY LONG TEXT")
	padded := styledPad(styled, 5)
	// Should return the original styled string unchanged (visW >= width)
	if padded != styled {
		t.Errorf("styledPad should return original when visual width >= target width")
	}
}
