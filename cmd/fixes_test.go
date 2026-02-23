package cmd

import (
	"strings"
	"testing"
	"time"
)

// ── Fix #8: safeSlice ────────────────────────────────────────────────────────

func TestSafeSlice_Normal(t *testing.T) {
	got := safeSlice("hello world", 0, 5)
	if got != "hello" {
		t.Errorf("safeSlice(\"hello world\", 0, 5) = %q; want %q", got, "hello")
	}
}

func TestSafeSlice_MidRange(t *testing.T) {
	got := safeSlice("hello world", 6, 11)
	if got != "world" {
		t.Errorf("safeSlice(\"hello world\", 6, 11) = %q; want %q", got, "world")
	}
}

func TestSafeSlice_EndLessThanStart(t *testing.T) {
	got := safeSlice("hello", 3, 1)
	if got != "" {
		t.Errorf("safeSlice with end < start = %q; want \"\"", got)
	}
}

func TestSafeSlice_EndNegative(t *testing.T) {
	got := safeSlice("hello", 0, -5)
	if got != "" {
		t.Errorf("safeSlice with end < 0 = %q; want \"\"", got)
	}
}

func TestSafeSlice_StartBeyondLength(t *testing.T) {
	got := safeSlice("hi", 10, 15)
	if got != "" {
		t.Errorf("safeSlice with start beyond length = %q; want \"\"", got)
	}
}

func TestSafeSlice_EndBeyondLengthClamped(t *testing.T) {
	got := safeSlice("hello", 3, 100)
	if got != "lo" {
		t.Errorf("safeSlice(\"hello\", 3, 100) = %q; want %q", got, "lo")
	}
}

func TestSafeSlice_StartNegativeClamped(t *testing.T) {
	got := safeSlice("hello", -3, 5)
	if got != "hello" {
		t.Errorf("safeSlice(\"hello\", -3, 5) = %q; want %q", got, "hello")
	}
}

func TestSafeSlice_EmptyString(t *testing.T) {
	got := safeSlice("", 0, 5)
	if got != "" {
		t.Errorf("safeSlice(\"\", 0, 5) = %q; want \"\"", got)
	}
}

func TestSafeSlice_EqualStartEnd(t *testing.T) {
	got := safeSlice("hello", 2, 2)
	if got != "" {
		t.Errorf("safeSlice with start == end = %q; want \"\"", got)
	}
}

// ── Fix #10: parseSarTimeWithDay ─────────────────────────────────────────────

func TestParseSarTimeWithDay_Known(t *testing.T) {
	got := parseSarTimeWithDay("14:30:00", 15)
	now := time.Now()

	if got.Hour() != 14 || got.Minute() != 30 || got.Second() != 0 {
		t.Errorf("parseSarTimeWithDay time = %v; want 14:30:00", got)
	}
	if got.Day() != 15 {
		t.Errorf("parseSarTimeWithDay day = %d; want 15", got.Day())
	}
	if got.Year() != now.Year() {
		t.Errorf("parseSarTimeWithDay year = %d; want %d", got.Year(), now.Year())
	}
	if got.Month() != now.Month() {
		t.Errorf("parseSarTimeWithDay month = %v; want %v", got.Month(), now.Month())
	}
}

func TestParseSarTimeWithDay_InvalidFallback(t *testing.T) {
	before := time.Now()
	got := parseSarTimeWithDay("not-a-time", 10)
	after := time.Now()

	// Should fall back to approximately now
	if got.Before(before) || got.After(after) {
		t.Errorf("parseSarTimeWithDay with invalid input should return ~now; got %v", got)
	}
}

// ── extractSarDay ────────────────────────────────────────────────────────────

func TestExtractSarDay_Sa22(t *testing.T) {
	got := extractSarDay("/var/log/sa/sa22")
	if got != 22 {
		t.Errorf("extractSarDay(\"sa22\") = %d; want 22", got)
	}
}

func TestExtractSarDay_Sa01(t *testing.T) {
	got := extractSarDay("/var/log/sysstat/sa01")
	if got != 1 {
		t.Errorf("extractSarDay(\"sa01\") = %d; want 1", got)
	}
}

func TestExtractSarDay_Sa99Invalid(t *testing.T) {
	got := extractSarDay("/var/log/sa/sa99")
	today := time.Now().Day()
	if got != today {
		t.Errorf("extractSarDay(\"sa99\") = %d; want current day %d", got, today)
	}
}

func TestExtractSarDay_NotANumber(t *testing.T) {
	got := extractSarDay("/var/log/sa/saXX")
	today := time.Now().Day()
	if got != today {
		t.Errorf("extractSarDay(\"saXX\") = %d; want current day %d", got, today)
	}
}

func TestExtractSarDay_Sa00Invalid(t *testing.T) {
	got := extractSarDay("/var/log/sa/sa00")
	today := time.Now().Day()
	if got != today {
		t.Errorf("extractSarDay(\"sa00\") = %d; want current day %d (day 0 is invalid)", got, today)
	}
}

// ── Fix #20: parseDmesgLine ──────────────────────────────────────────────────

func TestParseDmesgLine_ISOTimestamp(t *testing.T) {
	line := "2026-02-22T14:22:15,000000+0000 some kernel error message"
	ts, msg := parseDmesgLine(line)

	if ts.Year() != 2026 || ts.Month() != time.February || ts.Day() != 22 {
		t.Errorf("parseDmesgLine date = %v; want 2026-02-22", ts)
	}
	if ts.Hour() != 14 || ts.Minute() != 22 || ts.Second() != 15 {
		t.Errorf("parseDmesgLine time = %v; want 14:22:15", ts)
	}
	if msg != "some kernel error message" {
		t.Errorf("parseDmesgLine msg = %q; want %q", msg, "some kernel error message")
	}
}

func TestParseDmesgLine_ISOTimestampWithColonTZ(t *testing.T) {
	line := "2026-02-22T10:05:30,123456+05:30 hardware error detected"
	ts, msg := parseDmesgLine(line)

	if ts.Year() != 2026 || ts.Month() != time.February || ts.Day() != 22 {
		t.Errorf("parseDmesgLine date = %v; want 2026-02-22", ts)
	}
	if ts.Hour() != 10 || ts.Minute() != 5 || ts.Second() != 30 {
		t.Errorf("parseDmesgLine time = %v; want 10:05:30", ts)
	}
	if msg != "hardware error detected" {
		t.Errorf("parseDmesgLine msg = %q; want %q", msg, "hardware error detected")
	}
}

func TestParseDmesgLine_UnparseableFallback(t *testing.T) {
	line := "totally unparseable garbage line"
	before := time.Now()
	ts, msg := parseDmesgLine(line)
	after := time.Now()

	// Timestamp should be approximately now (fallback)
	if ts.Before(before) || ts.After(after) {
		t.Errorf("parseDmesgLine fallback timestamp should be ~now; got %v", ts)
	}
	// Message should be the entire original line
	if msg != line {
		t.Errorf("parseDmesgLine fallback msg = %q; want %q", msg, line)
	}
}

func TestParseDmesgLine_ShortLineFallback(t *testing.T) {
	line := "short"
	before := time.Now()
	ts, msg := parseDmesgLine(line)
	after := time.Now()

	if ts.Before(before) || ts.After(after) {
		t.Errorf("parseDmesgLine short line timestamp should be ~now; got %v", ts)
	}
	if msg != line {
		t.Errorf("parseDmesgLine short line msg = %q; want %q", msg, line)
	}
}

// ── truncateForensics ────────────────────────────────────────────────────────

func TestTruncateForensics_ShortString(t *testing.T) {
	input := "hello"
	got := truncateForensics(input, 100)
	if got != input {
		t.Errorf("truncateForensics short string = %q; want %q", got, input)
	}
}

func TestTruncateForensics_ExactLength(t *testing.T) {
	input := "hello"
	got := truncateForensics(input, 5)
	if got != input {
		t.Errorf("truncateForensics exact length = %q; want %q", got, input)
	}
}

func TestTruncateForensics_Truncated(t *testing.T) {
	input := "hello world, this is a long string"
	got := truncateForensics(input, 10)

	// Should be 10 chars total: 7 chars of content + "..."
	if len(got) != 10 {
		t.Errorf("truncateForensics length = %d; want 10", len(got))
	}
	if !strings.HasSuffix(got, "...") {
		t.Errorf("truncateForensics should end with \"...\"; got %q", got)
	}
	expected := "hello w..."
	if got != expected {
		t.Errorf("truncateForensics = %q; want %q", got, expected)
	}
}

func TestTruncateForensics_MaxLenThreeOrLess(t *testing.T) {
	input := "hello"
	got := truncateForensics(input, 3)

	// When maxLen <= 3, just truncate without "..."
	if got != "hel" {
		t.Errorf("truncateForensics maxLen=3 = %q; want %q", got, "hel")
	}
}

func TestTruncateForensics_MaxLenOne(t *testing.T) {
	input := "hello"
	got := truncateForensics(input, 1)
	if got != "h" {
		t.Errorf("truncateForensics maxLen=1 = %q; want %q", got, "h")
	}
}

// ── Fix #36: ExitCodeError ───────────────────────────────────────────────────

func TestExitCodeError_ImplementsError(t *testing.T) {
	var err error = ExitCodeError{Code: 2}

	if err == nil {
		t.Fatal("ExitCodeError should not be nil when assigned to error interface")
	}

	// Verify it produces a meaningful error string
	if err.Error() != "exit 2" {
		t.Errorf("ExitCodeError{Code:2}.Error() = %q; want %q", err.Error(), "exit 2")
	}
}

func TestExitCodeError_CodePreserved(t *testing.T) {
	tests := []struct {
		code int
		want string
	}{
		{0, "exit 0"},
		{1, "exit 1"},
		{2, "exit 2"},
		{127, "exit 127"},
	}
	for _, tt := range tests {
		e := ExitCodeError{Code: tt.code}
		if e.Code != tt.code {
			t.Errorf("ExitCodeError.Code = %d; want %d", e.Code, tt.code)
		}
		if e.Error() != tt.want {
			t.Errorf("ExitCodeError{Code:%d}.Error() = %q; want %q", tt.code, e.Error(), tt.want)
		}
	}
}

func TestExitCodeError_TypeAssertion(t *testing.T) {
	var err error = ExitCodeError{Code: 42}

	ece, ok := err.(ExitCodeError)
	if !ok {
		t.Fatal("type assertion to ExitCodeError should succeed")
	}
	if ece.Code != 42 {
		t.Errorf("asserted ExitCodeError.Code = %d; want 42", ece.Code)
	}
}
