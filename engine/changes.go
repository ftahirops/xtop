package engine

import (
	"os/exec"
	"strings"
	"time"

	"github.com/ftahirops/xtop/model"
)

// ChangeDetector tracks system changes between ticks.
type ChangeDetector struct {
	prevProcesses map[string]bool // comm names seen last tick
	initialized   bool
	lastPkgCheck  time.Time // rate-limit package log checks
	cachedPkgs    []model.SystemChange
}

// NewChangeDetector creates a new change detector.
func NewChangeDetector() *ChangeDetector {
	return &ChangeDetector{
		prevProcesses: make(map[string]bool),
	}
}

// DetectChanges compares current state to previous and returns changes.
func (cd *ChangeDetector) DetectChanges(snap *model.Snapshot) []model.SystemChange {
	var changes []model.SystemChange

	currentProcesses := make(map[string]bool)
	for _, p := range snap.Processes {
		currentProcesses[p.Comm] = true
	}

	if cd.initialized {
		// New processes (by comm name)
		for comm := range currentProcesses {
			if !cd.prevProcesses[comm] {
				changes = append(changes, model.SystemChange{
					Type:   "new_process",
					Detail: comm,
					When:   time.Now(),
				})
			}
		}
		// Stopped processes
		for comm := range cd.prevProcesses {
			if !currentProcesses[comm] {
				changes = append(changes, model.SystemChange{
					Type:   "stopped_process",
					Detail: comm,
					When:   time.Now(),
				})
			}
		}
	}

	cd.prevProcesses = currentProcesses
	cd.initialized = true

	// Recent package changes (rate-limited: check at most once per 30s)
	now := time.Now()
	if now.Sub(cd.lastPkgCheck) > 30*time.Second {
		cd.cachedPkgs = detectRecentPackages()
		cd.lastPkgCheck = now
	}
	changes = append(changes, cd.cachedPkgs...)

	return changes
}

// detectRecentPackages checks dpkg/apt/yum/dnf logs for recent package changes
// (last 30 min). Output capped at 20 entries total to keep results bounded.
func detectRecentPackages() []model.SystemChange {
	var changes []model.SystemChange
	cutoff := time.Now().Add(-30 * time.Minute)

	// Debian/Ubuntu — /var/log/dpkg.log
	if out, err := exec.Command("sh", "-c",
		"tail -200 /var/log/dpkg.log 2>/dev/null | grep -E 'install|upgrade|remove' | tail -20").Output(); err == nil {
		for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
			if line == "" {
				continue
			}
			parts := strings.SplitN(line, " ", 4)
			if len(parts) < 4 {
				continue
			}
			ts, err := time.Parse("2006-01-02 15:04:05", parts[0]+" "+parts[1])
			if err != nil {
				continue
			}
			if ts.After(cutoff) {
				changes = append(changes, model.SystemChange{
					Type:   "package_" + parts[2],
					Detail: parts[3],
					When:   ts,
				})
			}
		}
	}

	// RHEL/CentOS/Fedora — yum/dnf history. dnf history list output has the
	// transaction time in human-readable format; we just grep the most recent
	// entries. Best-effort: missing dnf is normal on Debian.
	if out, err := exec.Command("sh", "-c",
		"dnf history list 2>/dev/null | head -10 || yum history list 2>/dev/null | head -10").Output(); err == nil {
		for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
			line = strings.TrimSpace(line)
			// Skip header lines and dividers.
			if line == "" || strings.HasPrefix(line, "ID") || strings.HasPrefix(line, "-") {
				continue
			}
			// dnf history list lines look like:
			//   "  102 | install package | 2026-03-23 14:30 | I, U   |  3 EE"
			// Cheap parse: find a date that looks like 2026-MM-DD HH:MM.
			cols := strings.Split(line, "|")
			if len(cols) < 3 {
				continue
			}
			tsStr := strings.TrimSpace(cols[2])
			ts, err := time.Parse("2006-01-02 15:04", tsStr)
			if err != nil {
				continue
			}
			if !ts.After(cutoff) {
				continue
			}
			changes = append(changes, model.SystemChange{
				Type:   "package_" + strings.TrimSpace(cols[1]),
				Detail: line,
				When:   ts,
			})
			if len(changes) >= 20 {
				break
			}
		}
	}

	return changes
}
