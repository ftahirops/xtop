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

// detectRecentPackages checks dpkg log for recent installs/upgrades (last 10 min).
func detectRecentPackages() []model.SystemChange {
	var changes []model.SystemChange
	out, err := exec.Command("sh", "-c",
		"tail -50 /var/log/dpkg.log 2>/dev/null | grep -E 'install|upgrade' | tail -5").Output()
	if err != nil {
		return nil
	}
	cutoff := time.Now().Add(-10 * time.Minute)
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if line == "" {
			continue
		}
		// Parse timestamp from dpkg log: "2026-03-23 14:30:05 install package version"
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
	return changes
}
