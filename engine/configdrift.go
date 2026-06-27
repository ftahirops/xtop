package engine

// configdrift.go — kernel-parameter drift detector (Phase 4, P4.3).
//
// This file is distinct from config_drift.go (which fingerprints config FILES
// on disk via SHA256). Here we track OS/kernel runtime parameters — sysctl
// values, hugepage settings, CPU governor, etc. — sourced from the
// collector/configdrift.Keys registry and compared against a persisted
// store.ConfigBaselineRow baseline.
//
// Design decisions:
//   - Detect does NOT mutate the in-memory baseline on drift. A changed value
//     keeps re-emitting drift changes on every call until the operator acks it
//     (P4.4/P4.5 will handle ack). This ensures the operator cannot miss a
//     config change that correlates with an incident.
//   - Keys absent from the live snapshot (e.g. cpu.governor on a VM without
//     cpufreq) are silently ignored — "unknown" is not "drift".
//   - Keys present in live but absent from the baseline are first-ever-seen:
//     they are returned as newBaselines (to be persisted by the caller) and
//     do NOT produce drift events.

import (
	"fmt"
	"time"

	"github.com/ftahirops/xtop/collector/configdrift"
	"github.com/ftahirops/xtop/model"
	"github.com/ftahirops/xtop/store"
)

// configBaselineEntry holds the in-memory view of one baseline key.
type configBaselineEntry struct {
	value     string
	domain    string
	firstSeen time.Time
}

// ParamDriftDetector compares live kernel-parameter snapshots against a
// persisted baseline and emits model.SystemChange events for drifted values.
//
// Thread-safety: not concurrent-safe by design — the engine calls Detect
// synchronously on the tick goroutine. Wrap with a mutex if that changes.
type ParamDriftDetector struct {
	// baseline is the in-memory copy loaded from store at startup.
	// Detect never mutates it; mutations happen via returned newBaselines
	// that the caller persists and then reloads on the next startup.
	baseline map[string]configBaselineEntry // key → {value, domain, firstSeen}

	// domainByKey is built once from configdrift.Keys for O(1) lookups.
	domainByKey map[string]string
}

// NewParamDriftDetector initialises a detector from the persisted baseline rows
// (typically loaded via store.LoadConfigBaseline). Passing nil or an empty
// slice starts with an empty baseline — every first-seen key will be collected
// as a newBaseline entry on the first Detect call.
func NewParamDriftDetector(rows []store.ConfigBaselineRow) *ParamDriftDetector {
	d := &ParamDriftDetector{
		baseline:    make(map[string]configBaselineEntry, len(rows)),
		domainByKey: buildDomainMap(),
	}
	for _, r := range rows {
		d.baseline[r.Key] = configBaselineEntry{
			value:     r.Value,
			domain:    r.Domain,
			firstSeen: r.FirstSeen,
		}
	}
	return d
}

// buildDomainMap indexes configdrift.Keys by Name → Domain for O(1) lookups.
func buildDomainMap() map[string]string {
	m := make(map[string]string, len(configdrift.Keys))
	for _, k := range configdrift.Keys {
		m[k.Name] = k.Domain
	}
	return m
}

// Detect compares live key→value pairs against the baseline and returns:
//   - changes: drift SystemChanges for keys whose value differs from baseline.
//     Type is "config_drift_<domain>"; Detail is "key: old → new".
//   - newBaselines: entries for keys not yet in the baseline (first-ever-seen).
//     The caller should persist these via store.SaveConfigBaseline.
//
// Keys present in the baseline but absent from live are silently ignored
// (treat as "unknown", not "drift") — this respects the P4.1 graceful-skip
// contract for optional kernel features.
//
// The baseline is NOT mutated on drift — the caller (P4.4) handles ack/update.
func (d *ParamDriftDetector) Detect(live map[string]string, now time.Time) (changes []model.SystemChange, newBaselines []store.ConfigBaselineRow) {
	for key, liveVal := range live {
		entry, inBaseline := d.baseline[key]
		if !inBaseline {
			// First-ever-seen: record as new baseline, do not emit drift.
			domain := d.domainFor(key)
			newBaselines = append(newBaselines, store.ConfigBaselineRow{
				Key:       key,
				Value:     liveVal,
				Domain:    domain,
				FirstSeen: now,
				Acked:     false,
			})
			continue
		}

		if liveVal == entry.value {
			// No change — all good.
			continue
		}

		// Value changed vs baseline → drift.
		domain := entry.domain
		if domain == "" {
			domain = d.domainFor(key)
		}
		changes = append(changes, model.SystemChange{
			Type:   "config_drift_" + domain,
			Detail: fmt.Sprintf("%s: %s → %s", key, entry.value, liveVal),
			Domain: domain,
			When:   now,
		})
		// Intentionally NOT updating d.baseline[key] — keep emitting drift
		// until the operator acks (P4.4/P4.5). This is the "sticky drift"
		// policy: emit on every Detect call until the baseline is updated
		// externally via SaveConfigBaseline + a fresh NewParamDriftDetector.
	}
	return changes, newBaselines
}

// domainFor returns the RCA domain for a key name, falling back to "unknown"
// for keys not in the configdrift.Keys registry (e.g. custom sysctl values).
func (d *ParamDriftDetector) domainFor(key string) string {
	if dom, ok := d.domainByKey[key]; ok {
		return dom
	}
	return "unknown"
}
