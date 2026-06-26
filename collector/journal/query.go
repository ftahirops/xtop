//go:build linux

package journal

import (
	"context"
	"os/exec"
	"time"
)

// Query executes journalctl for the given systemd unit, returning all WARNING
// and above entries (priority ≤ 4) since the provided time.
// At most 2000 lines are returned to keep memory bounded.
func Query(ctx context.Context, unit string, since time.Time) ([]Entry, error) {
	args := []string{
		"-u", unit,
		"-p", "warning",
		"-o", "json",
		"--since", since.Format("2006-01-02 15:04:05"),
		"--no-pager",
		"--lines=2000",
	}
	cmd := exec.CommandContext(ctx, "journalctl", args...)
	out, err := cmd.Output()
	if err != nil {
		// journalctl exits non-zero when the unit is unknown or has no journal
		// namespace, but may still write valid (possibly empty) output.
		// Return the error only if we got no usable output.
		if len(out) == 0 {
			return nil, err
		}
	}
	return parseJSONLines(out), nil
}
