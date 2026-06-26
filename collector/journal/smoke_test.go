//go:build linux

package journal

// smoke_test.go — Real-journalctl smoke test for P2.7.
//
// This test calls the actual journal.Query() against a known-present systemd
// unit on the host. Its only goal is to prove the real subprocess path works:
// no panic, no unexpected error, and the parser doesn't corrupt entries.
//
// Gating strategy:
//   1. Skip if journalctl is not in PATH (non-Linux or stripped containers).
//   2. Skip if journalctl returns a permission-denied error (rootless CI).
//   3. Accept an empty result — the chosen unit may have no recent entries in
//      the 2-minute window; that is not a failure.
//
// The unit under test is "systemd-journald.service" which is always present on
// a systemd host.  A 2-minute --since window is used to keep the test fast.

import (
	"context"
	"errors"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func TestJournalQuery_LiveSmoke(t *testing.T) {
	// Gate 1: journalctl must exist in PATH.
	if _, err := exec.LookPath("journalctl"); err != nil {
		t.Skip("journalctl not available in PATH; skipping live smoke test")
	}

	const unit = "systemd-journald.service"
	since := time.Now().Add(-2 * time.Minute)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	entries, err := Query(ctx, unit, since)

	if err != nil {
		// Gate 2: permission errors in rootless environments are acceptable.
		if isPermErr(err) {
			t.Skipf("journalctl returned permission error (%v); skipping in rootless env", err)
		}
		// Any other error (unit not found returns empty, not an error per the
		// implementation) is a real failure.
		t.Fatalf("journal.Query(%q) returned unexpected error: %v", unit, err)
	}

	// Empty result is fine — the unit just may have no warn+ entries recently.
	t.Logf("Live smoke: Query(%q, since=%s) returned %d entries (no error)", unit, since.Format("15:04:05"), len(entries))

	// Validate every returned entry has sane fields (no zero-value corruption).
	for i, e := range entries {
		if e.Priority < 0 || e.Priority > 7 {
			t.Errorf("entry[%d]: unexpected Priority %d (want 0-7)", i, e.Priority)
		}
		if e.At.IsZero() {
			t.Errorf("entry[%d]: At is zero (timestamp parse failed)", i)
		}
		if e.At.After(time.Now().Add(5 * time.Minute)) {
			t.Errorf("entry[%d]: At=%v is unreasonably far in the future", i, e.At)
		}
	}
}

// isPermErr returns true if the error string suggests a permission/access problem.
func isPermErr(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	for _, kw := range []string{"permission denied", "access denied", "not permitted", "authorization"} {
		if strings.Contains(msg, kw) {
			return true
		}
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		out := strings.ToLower(string(exitErr.Stderr))
		if strings.Contains(out, "permission") || strings.Contains(out, "access") {
			return true
		}
	}
	return false
}
