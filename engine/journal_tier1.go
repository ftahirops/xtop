package engine

// journal_tier1.go — Tier-1 on-demand journal evidence for services under
// active RCA investigation (P2.4).
//
// Design:
//   - JournalQueryFn is injectable: tests replace it with a stub; on Linux the
//     default is journal.Query; on non-Linux journal.Query is a no-op stub in
//     the journal package so no build tags are needed here.
//   - Per-unit 30s cache avoids re-forking journalctl every tick when the same
//     unit stays suspect.
//   - A 1.5s per-unit context deadline ensures a slow journalctl can't stall
//     the tick.
//   - Best-effort: any error from the query func is silently skipped.
//   - Suspect set is capped at suspectCap (3) to bound cost.
//
// Suspect-service seam (engine/rca.go):
//   After AnalyzeRCA builds result.RCA, it calls injectJournalTier1(result,
//   curr, e). We look at the top suspectCap RCAEntries whose Score > 0 and
//   derive the systemd unit name from, in priority order:
//     1. TopCgroup  — extract trailing "foo.service" component if present
//     2. TopAppName — sanitise + append ".service"
//     3. TopProcess — append ".service"
//   This covers the dominant patterns in real hosts (cgroup-supervised services
//   and directly-named apps) and degrades gracefully when none are available.

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/ftahirops/xtop/collector/journal"
	"github.com/ftahirops/xtop/model"
)

// JournalQueryFn is the injectable journalctl query function used by the Tier-1
// journal pipeline. Default is journal.Query (which is a no-op stub on
// non-Linux via collector/journal/query_stub.go).
type JournalQueryFn func(ctx context.Context, unit string, since time.Time) ([]journal.Entry, error)

const (
	suspectCap        = 3             // max suspects to investigate per tick
	journalLookback   = 5 * time.Minute
	journalDeadline   = 1500 * time.Millisecond
	journalCacheTTL   = 30 * time.Second
	minSuspectScore   = 1 // only investigate entries with Score ≥ this
)

// journalCacheEntry holds the cached findings for one unit.
type journalCacheEntry struct {
	queriedAt time.Time
	findings  []journal.JournalFinding
}

// journalTier1Cache is stored on the Engine (see engine.go field addition).
// Access is serialized by Engine.tickMu so no extra lock is needed.
type journalTier1Cache struct {
	mu      sync.Mutex
	entries map[string]journalCacheEntry
}

func newJournalTier1Cache() *journalTier1Cache {
	return &journalTier1Cache{entries: make(map[string]journalCacheEntry)}
}

// get returns cached findings for unit if still within TTL. ok=false means
// cache miss.
func (c *journalTier1Cache) get(unit string) ([]journal.JournalFinding, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.entries[unit]
	if !ok || time.Since(e.queriedAt) > journalCacheTTL {
		return nil, false
	}
	return e.findings, true
}

// set stores findings for unit.
func (c *journalTier1Cache) set(unit string, findings []journal.JournalFinding) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries[unit] = journalCacheEntry{queriedAt: time.Now(), findings: findings}
}

// unitFromRCAEntry derives the best systemd unit name candidate from an
// RCAEntry. Returns "" if no useful identifier is available.
//
// Priority:
//  1. TopCgroup: if it ends in a ".service" component, use that.
//  2. TopAppName: sanitise (to lower, collapse spaces → "-") + ".service".
//  3. TopProcess: as-is + ".service".
func unitFromRCAEntry(entry model.RCAEntry) string {
	// 1. Cgroup path — scan components right-to-left for a *.service suffix.
	if entry.TopCgroup != "" {
		parts := strings.Split(entry.TopCgroup, "/")
		for i := len(parts) - 1; i >= 0; i-- {
			if strings.HasSuffix(parts[i], ".service") {
				return parts[i]
			}
		}
	}

	// 2. App name (resolved from identity service).
	if entry.TopAppName != "" {
		name := strings.ToLower(strings.TrimSpace(entry.TopAppName))
		name = strings.ReplaceAll(name, " ", "-")
		if !strings.HasSuffix(name, ".service") {
			name += ".service"
		}
		return name
	}

	// 3. Process comm.
	if entry.TopProcess != "" {
		name := strings.ToLower(strings.TrimSpace(entry.TopProcess))
		if !strings.HasSuffix(name, ".service") {
			name += ".service"
		}
		return name
	}

	return ""
}

// entityIDForUnit builds a best-effort entity ID for the given unit. If the
// entity graph exists and contains a matching entity, we use that ID;
// otherwise we fall back to "svc:<unit>" so InjectJournalEvidence can still
// emit valid (host-fallback) Facts.
func entityIDForUnit(graph *model.EntityGraph, unit string) string {
	// Try the unit name as-is, then without ".service" suffix.
	for _, candidate := range []string{unit, strings.TrimSuffix(unit, ".service")} {
		if graph != nil && graph.Lookup(candidate) != nil {
			return candidate
		}
	}
	return "svc:" + unit
}

// baselineRateForUnit returns the error rate baseline for unit from snap's
// LogMetrics, or 0 if not available.
func baselineRateForUnit(curr *model.Snapshot, unit string) float64 {
	if curr == nil {
		return 0
	}
	bare := strings.TrimSuffix(unit, ".service")
	for _, svc := range curr.Global.Logs.Services {
		if svc.Unit == unit || svc.Unit == bare ||
			strings.EqualFold(svc.Name, bare) {
			return svc.ErrorRate
		}
	}
	return 0
}

// queryOneSuspect wraps journalQueryFn with a per-call deadline. The defer
// ensures cancel() fires even if journalQueryFn panics.
func (e *Engine) queryOneSuspect(unit string, since time.Time) ([]journal.Entry, error) {
	ctx, cancel := context.WithTimeout(context.Background(), journalDeadline)
	defer cancel()
	return e.journalQueryFn(ctx, unit, since)
}

// injectJournalTier1 is called from AnalyzeRCA after suspects are known. It
// fetches journal evidence for the top suspect services, classifies it, and
// attaches the resulting Facts + DiagFindings to result.
//
// e may be nil (unit tests that build a bare result without an engine), in
// which case this is a no-op.
func injectJournalTier1(result *model.AnalysisResult, curr *model.Snapshot, e *Engine) {
	if e == nil || e.journalQueryFn == nil || result == nil {
		return
	}

	// Build the suspect list: top N entries with score ≥ minSuspectScore.
	// result.RCA is already sorted score-descending by AnalyzeRCA.
	type suspect struct {
		unit     string
		entityID string
		rcaIdx   int
	}
	var suspects []suspect
	for i, entry := range result.RCA {
		if entry.Score < minSuspectScore {
			continue
		}
		unit := unitFromRCAEntry(entry)
		if unit == "" {
			continue
		}
		suspects = append(suspects, suspect{
			unit:     unit,
			entityID: entityIDForUnit(result.Entities, unit),
			rcaIdx:   i,
		})
		if len(suspects) >= suspectCap {
			break
		}
	}

	if len(suspects) == 0 {
		return
	}

	now := time.Now()
	since := now.Add(-journalLookback)

	for _, s := range suspects {
		// Cache check.
		findings, hit := e.journalCache.get(s.unit)
		if !hit {
			entries, err := e.queryOneSuspect(s.unit, since)
			if err != nil {
				// best-effort: skip on error
				continue
			}

			baseline := baselineRateForUnit(curr, s.unit)
			findings = journal.Classify(entries, baseline)
			e.journalCache.set(s.unit, findings)
		}

		if len(findings) == 0 {
			continue
		}

		// Convert to Facts.
		facts := InjectJournalEvidence(result.Entities, s.entityID, findings, now)

		// Attach to top-level result.Facts.
		result.Facts = append(result.Facts, facts...)

		// Attach to the matching RCAEntry.Facts.
		result.RCA[s.rcaIdx].Facts = append(result.RCA[s.rcaIdx].Facts, facts...)

		// Attach DiagFindings for the UI layer.
		for _, f := range findings {
			sev := model.DiagWarn
			if f.Severity == model.DiagCrit {
				sev = model.DiagCrit
			}
			result.JournalFindings = append(result.JournalFindings, model.DiagFinding{
				Severity: sev,
				Category: "logs",
				Summary:  fmt.Sprintf("[%s] %s (%d events)", s.unit, f.Signature, f.Count),
				Detail:   f.Sample,
			})
		}
	}
}
