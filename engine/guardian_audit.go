package engine

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"github.com/ftahirops/xtop/collector"
)

// Guardian budget defaults per mode. Lean is for daemon/agent use where
// the hub does the heavy analytics; the agent should never be a noisy
// neighbor on the host it's monitoring. Rich is for the TUI where the
// operator is actively looking; some headroom is fine. Hub holds real
// state (Postgres connection pools, SSE subscribers, in-memory dedupe
// maps) and gets the most generous budget.
func guardianSoftHeapMB(m collector.Mode) float64 {
	if v, err := strconv.ParseFloat(os.Getenv("XTOP_GUARDIAN_HEAP_SOFT_MB"), 64); err == nil && v > 0 {
		return v
	}
	if m == collector.ModeLean {
		return 150
	}
	return 400
}

func guardianHardHeapMB(m collector.Mode) float64 {
	if v, err := strconv.ParseFloat(os.Getenv("XTOP_GUARDIAN_HEAP_HARD_MB"), 64); err == nil && v > 0 {
		return v
	}
	if m == collector.ModeLean {
		return 300
	}
	return 800
}

// guardianAuditPath returns the file the guardian appends every action to.
// Operators can read it after the fact ("why did xtop restart at 3am?")
// without needing trace-level logging on by default.
func guardianAuditPath() string {
	if v := os.Getenv("XTOP_GUARDIAN_AUDIT_PATH"); v != "" {
		return v
	}
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return "/tmp/xtop-guardian.log"
	}
	dir := filepath.Join(home, ".xtop")
	_ = os.MkdirAll(dir, 0o755)
	return filepath.Join(dir, "guardian.log")
}

var guardianAuditMu sync.Mutex

// guardianAudit appends a single timestamped line to the audit log. Best
// effort — file errors are swallowed to keep the agent running even if
// the disk is full.
func guardianAudit(path, msg string) {
	guardianAuditMu.Lock()
	defer guardianAuditMu.Unlock()
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o640)
	if err != nil {
		return
	}
	defer f.Close()
	_, _ = fmt.Fprintf(f, "%s  %s\n", time.Now().UTC().Format(time.RFC3339), msg)
}

// guardianRestartAllowed implements the rate-limiter for the self-preserving
// restart action. We track restart timestamps in a small JSON file next to
// the audit log. Default: no more than 3 restarts in any rolling hour. Above
// that threshold, we refuse to exit so the host doesn't enter a restart
// loop that's worse than just leaving xtop fat.
func guardianRestartAllowed(auditPath string) bool {
	max := 3
	if v, err := strconv.Atoi(os.Getenv("XTOP_GUARDIAN_RESTARTS_PER_HOUR")); err == nil && v > 0 {
		max = v
	}
	statePath := auditPath + ".restarts"
	now := time.Now().UTC()

	data, _ := os.ReadFile(statePath)
	var stamps []time.Time
	for _, line := range splitLines(string(data)) {
		if line == "" {
			continue
		}
		if t, err := time.Parse(time.RFC3339, line); err == nil {
			if now.Sub(t) < time.Hour {
				stamps = append(stamps, t)
			}
		}
	}
	if len(stamps) >= max {
		return false
	}
	stamps = append(stamps, now)
	var out string
	for _, t := range stamps {
		out += t.Format(time.RFC3339) + "\n"
	}
	_ = os.WriteFile(statePath, []byte(out), 0o640)
	return true
}

func splitLines(s string) []string {
	var out []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	if start < len(s) {
		out = append(out, s[start:])
	}
	return out
}
