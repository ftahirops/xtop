package journal

import (
	"sort"
	"strings"
	"time"

	"github.com/ftahirops/xtop/model"
)

// JournalFinding is an aggregated classification result for a set of journal entries.
type JournalFinding struct {
	Signature string
	Severity  model.DiagSeverity
	Count     int
	Sample    string // representative message, truncated to ~120 chars
	PID       int
	FirstSeen time.Time
	LastSeen  time.Time
}

// sigDef defines one signature: its name, severity, and a list of required
// case-insensitive substrings (any one match is sufficient).
type sigDef struct {
	name     string
	severity model.DiagSeverity
	markers  []string
}

// signatures are evaluated in order (crit first, then warn) — first match wins per entry.
var signatures = []sigDef{
	{
		name:     "crash_restart_loop",
		severity: model.DiagCrit,
		markers: []string{
			"main process exited",
			"failed with result",
			"start request repeated too quickly",
			"scheduled restart",
		},
	},
	{
		name:     "oom_killed",
		severity: model.DiagCrit,
		markers: []string{
			"out of memory: killed process",
			"oom-kill",
			"killed process",
		},
	},
	{
		name:     "segfault_panic",
		severity: model.DiagCrit,
		markers: []string{
			"segfault at",
			"general protection",
			"panic:",
			"fatal error:",
		},
	},
	{
		name:     "resource_exhaustion",
		severity: model.DiagWarn,
		markers: []string{
			"too many open files",
			"cannot allocate memory",
			"no space left",
			"pool exhausted",
		},
	},
	{
		name:     "dependency_failure",
		severity: model.DiagWarn,
		markers: []string{
			"connection refused",
			"timeout connecting",
			"upstream connect",
			"upstream timed out",
			"tls handshake",
			"dns resolution failed",
			"name resolution",
		},
	},
	{
		name:     "config_auth_error",
		severity: model.DiagWarn,
		markers: []string{
			"permission denied",
			"invalid configuration",
			"failed to bind",
		},
	},
}

// matchSig returns the signature name for the given (lower-cased) message, or "".
// Evaluation is ordered crit→warn; first match wins.
func matchSig(lc string) (string, model.DiagSeverity) {
	for _, sig := range signatures {
		for _, m := range sig.markers {
			if strings.Contains(lc, m) {
				return sig.name, sig.severity
			}
		}
	}
	return "", ""
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	runes := []rune(s)
	if len(runes) <= n {
		return s
	}
	return string(runes[:n])
}

// Classify classifies a slice of journal entries into typed JournalFindings.
//
// baselineRate is the expected count of priority≤3 entries per collection window.
// If baselineRate > 0 and the observed count exceeds 3× baseline, an extra
// error_rate_spike finding (DiagWarn) is appended.
//
// Output is deterministic: findings are sorted by severity (crit before warn)
// then by signature name.
func Classify(entries []Entry, baselineRate float64) []JournalFinding {
	type agg struct {
		sig      string
		sev      model.DiagSeverity
		count    int
		sample   string
		pid      int
		first    time.Time
		last     time.Time
		hasFirst bool
	}

	byName := map[string]*agg{}

	var highPrioCount int

	for _, e := range entries {
		if e.Priority <= 3 {
			highPrioCount++
		}

		lc := strings.ToLower(e.Message)
		name, sev := matchSig(lc)
		if name == "" {
			continue
		}

		a, ok := byName[name]
		if !ok {
			a = &agg{sig: name, sev: sev}
			byName[name] = a
		}
		a.count++
		if !a.hasFirst || e.At.Before(a.first) {
			a.first = e.At
			a.hasFirst = true
		}
		if e.At.After(a.last) {
			a.last = e.At
		}
		// Use first matched message as sample; truncate to 120 chars.
		if a.sample == "" {
			a.sample = truncate(e.Message, 120)
			a.pid = e.PID
		}
	}

	// Check for error_rate_spike.
	if baselineRate > 0 && float64(highPrioCount) > 3*baselineRate {
		if _, exists := byName["error_rate_spike"]; !exists {
			byName["error_rate_spike"] = &agg{
				sig:   "error_rate_spike",
				sev:   model.DiagWarn,
				count: highPrioCount,
			}
		}
	}

	// Collect and sort deterministically: crit < warn (by severity weight), then by name.
	sevOrder := map[model.DiagSeverity]int{
		model.DiagCrit: 0,
		model.DiagWarn: 1,
		model.DiagInfo: 2,
		model.DiagOK:   3,
	}

	findings := make([]JournalFinding, 0, len(byName))
	for _, a := range byName {
		findings = append(findings, JournalFinding{
			Signature: a.sig,
			Severity:  a.sev,
			Count:     a.count,
			Sample:    a.sample,
			PID:       a.pid,
			FirstSeen: a.first,
			LastSeen:  a.last,
		})
	}

	sort.Slice(findings, func(i, j int) bool {
		oi := sevOrder[findings[i].Severity]
		oj := sevOrder[findings[j].Severity]
		if oi != oj {
			return oi < oj
		}
		return findings[i].Signature < findings[j].Signature
	})

	return findings
}
