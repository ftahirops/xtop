package journal

import (
	"testing"
	"time"
)

// sampleLines mimics real journald JSON output: one JSON object per line.
// Includes:
//   - PRIORITY as string "3" (warning)
//   - __REALTIME_TIMESTAMP as string of microseconds
//   - _PID as string
//   - a line with _SYSTEMD_UNIT absent (falls back to UNIT)
//   - a garbage/malformed line that must be skipped
const sampleLines = `{"PRIORITY":"3","MESSAGE":"kernel: Out of memory: Kill process 1234","_PID":"1234","SYSLOG_IDENTIFIER":"kernel","_SYSTEMD_UNIT":"kernel.service","__REALTIME_TIMESTAMP":"1700000000000000"}
{"PRIORITY":"2","MESSAGE":"mysqld crashed","_PID":"5678","SYSLOG_IDENTIFIER":"mysqld","UNIT":"mysql.service","__REALTIME_TIMESTAMP":"1700000001500000"}
THIS IS NOT JSON AT ALL
{"PRIORITY":"4","MESSAGE":"config reloaded","_PID":"","SYSLOG_IDENTIFIER":"nginx","_SYSTEMD_UNIT":"nginx.service","__REALTIME_TIMESTAMP":"1700000002000000"}
`

func TestParseJSONLines_Fields(t *testing.T) {
	entries := parseJSONLines([]byte(sampleLines))

	// Garbage line must be skipped → 3 entries.
	if len(entries) != 3 {
		t.Fatalf("expected 3 entries, got %d", len(entries))
	}

	e0 := entries[0]
	if e0.Priority != 3 {
		t.Errorf("e0.Priority: want 3, got %d", e0.Priority)
	}
	if e0.Message != "kernel: Out of memory: Kill process 1234" {
		t.Errorf("e0.Message wrong: %q", e0.Message)
	}
	if e0.PID != 1234 {
		t.Errorf("e0.PID: want 1234, got %d", e0.PID)
	}
	if e0.Ident != "kernel" {
		t.Errorf("e0.Ident: want kernel, got %q", e0.Ident)
	}
	if e0.Unit != "kernel.service" {
		t.Errorf("e0.Unit: want kernel.service, got %q", e0.Unit)
	}

	// __REALTIME_TIMESTAMP 1700000000000000 µs → 2023-11-14T...
	wantAt := time.Unix(0, 1700000000000000*int64(time.Microsecond)).UTC()
	if !e0.At.Equal(wantAt) {
		t.Errorf("e0.At: want %v, got %v", wantAt, e0.At)
	}

	// Second entry: UNIT fallback (no _SYSTEMD_UNIT), priority 2.
	e1 := entries[1]
	if e1.Priority != 2 {
		t.Errorf("e1.Priority: want 2, got %d", e1.Priority)
	}
	if e1.Unit != "mysql.service" {
		t.Errorf("e1.Unit: want mysql.service, got %q", e1.Unit)
	}
	// Timestamp: 1700000001500000 µs
	wantAt1 := time.Unix(0, 1700000001500000*int64(time.Microsecond)).UTC()
	if !e1.At.Equal(wantAt1) {
		t.Errorf("e1.At: want %v, got %v", wantAt1, e1.At)
	}

	// Third entry: _PID is empty string → PID should be 0, no crash.
	e2 := entries[2]
	if e2.PID != 0 {
		t.Errorf("e2.PID: want 0 for empty string, got %d", e2.PID)
	}
	if e2.Unit != "nginx.service" {
		t.Errorf("e2.Unit: want nginx.service, got %q", e2.Unit)
	}
}

func TestParseJSONLines_EmptyInput(t *testing.T) {
	entries := parseJSONLines([]byte(""))
	if len(entries) != 0 {
		t.Errorf("expected 0 entries for empty input, got %d", len(entries))
	}
}

func TestParseJSONLines_AllGarbage(t *testing.T) {
	entries := parseJSONLines([]byte("not json\nalso not json\n{broken"))
	if len(entries) != 0 {
		t.Errorf("expected 0 entries for all-garbage input, got %d", len(entries))
	}
}
