package engine

// configdrift_evidence.go — Phase 4.4: turn config-drift SystemChanges into
// scoped model.Facts and correlate them with anomaly onset.
//
// Design:
//   - InjectConfigDriftEvidence converts config_drift_* SystemChanges into
//     host-scoped model.Facts (EntityID="host") with Kind=FactKindConfigChange.
//     Confidence is moderate (~0.6) because config drift is a derived/interpreted
//     signal; onset correlation is what gives it RCA weight.
//   - correlateConfigDrift implements the onset-correlation seam: when a drift
//     change's When is within the correlation window (driftCorrelationWindow)
//     AND its Domain matches an active bottleneck's domain, the matching
//     RCAEntry's score is boosted and the drift Fact is attached to result.Facts.
//   - The boost is deliberately modest (8–12 points, capped at 100) and gated
//     on both timing AND domain match, so a stale or off-domain drift never
//     inflates the score.

import (
	"fmt"
	"strings"
	"time"

	"github.com/ftahirops/xtop/model"
)

// driftCorrelationWindow is the look-back window for considering a config-drift
// change "recent enough" to correlate with an anomaly onset.
// 5 minutes balances "operator just changed something" vs. "ancient baseline drift".
const driftCorrelationWindow = 5 * time.Minute

// driftDomainToModel maps a config_drift domain string (as stored in
// model.SystemChange.Domain) to the model.Domain enum used by the verifier.
// "limits" (cgroup/ulimit) maps to DomainProcess as the closest category.
// "unknown" is left unmapped so it is never correlated (avoids noise).
func driftDomainToModel(s string) (model.Domain, bool) {
	switch strings.ToLower(s) {
	case "memory":
		return model.DomainMemory, true
	case "cpu":
		return model.DomainCPU, true
	case "io":
		return model.DomainIO, true
	case "network":
		return model.DomainNetwork, true
	case "limits":
		return model.DomainProcess, true
	default:
		return "", false
	}
}

// bottleneckDomain maps a bottleneck display name to the equivalent model.Domain.
// Only the four primary RCA bottlenecks are mapped; gaps are returned as "".
func bottleneckDomain(bottleneck string) model.Domain {
	switch bottleneck {
	case BottleneckMemory:
		return model.DomainMemory
	case BottleneckCPU:
		return model.DomainCPU
	case BottleneckIO:
		return model.DomainIO
	case BottleneckNetwork:
		return model.DomainNetwork
	default:
		return ""
	}
}

// Separator constants for parseDetailParts. arrowUnicode is U+2192 (→) which
// encodes to 3 bytes in UTF-8, making the full token " → " 5 bytes — NOT 3.
// Using len(sep) in the slice avoids off-by-N bugs when the rune width changes.
const (
	arrowUnicode = " → " // 5 bytes: 0x20 0xE2 0x86 0x92 0x20
	arrowASCII   = " -> " // 4 bytes
)

// parseDetailParts splits a Detail string of the form "key: old → new" into
// (key, old, new). Falls back gracefully when the format is unexpected.
func parseDetailParts(detail string) (key, oldVal, newVal string) {
	// Format: "key: old → new"
	colonIdx := strings.Index(detail, ": ")
	if colonIdx < 0 {
		return detail, "", ""
	}
	key = strings.TrimSpace(detail[:colonIdx])
	rest := strings.TrimSpace(detail[colonIdx+2:])

	// Arrow can be "→" (UTF-8, 5-byte token) or "->" (ASCII fallback, 4-byte token).
	// Advance by len(sep) so the slice never lands mid-rune.
	if arrowIdx := strings.Index(rest, arrowUnicode); arrowIdx >= 0 {
		oldVal = strings.TrimSpace(rest[:arrowIdx])
		newVal = strings.TrimSpace(rest[arrowIdx+len(arrowUnicode):])
		return
	}
	if arrowIdx := strings.Index(rest, arrowASCII); arrowIdx >= 0 {
		oldVal = strings.TrimSpace(rest[:arrowIdx])
		newVal = strings.TrimSpace(rest[arrowIdx+len(arrowASCII):])
		return
	}
	// Can't split — leave old/new empty
	oldVal = rest
	return
}

// InjectConfigDriftEvidence converts a slice of model.SystemChange (only
// config_drift_* types are processed; others are silently skipped) into
// host-scoped model.Facts.
//
// Each emitted Fact has:
//   - Kind = FactKindConfigChange
//   - Source = "config"
//   - EntityID = "host" (config drift is always host-level)
//   - Domain mapped from the change's Domain string (memory→DomainMemory, etc.)
//   - Metric = the config key extracted from Detail
//   - Value = 1.0 (presence signal — the magnitude is in the tags)
//   - Confidence ≈ 0.6 (derived/interpreted per the FactConfidence rubric)
//   - Tags: "key", "old", "new", "domain"
//
// The graph parameter is accepted for API compatibility (future: graph-aware
// entity resolution). Currently unused because config drift is always host-scoped.
func InjectConfigDriftEvidence(
	_ *model.EntityGraph,
	changes []model.SystemChange,
	measuredAt time.Time,
) []model.Fact {
	if len(changes) == 0 {
		return nil
	}

	const (
		driftConfidence        = 0.6 // derived/interpreted per FactConfidence rubric
		driftUnknownConfidence = 0.3 // lower confidence when domain can't be routed
		driftPresenceValue     = 1.0 // presence magnitude (dimensionless)
	)

	var facts []model.Fact

	for _, ch := range changes {
		if !strings.HasPrefix(ch.Type, "config_drift_") {
			continue
		}

		dom, knownDomain := driftDomainToModel(ch.Domain)
		if !knownDomain {
			// Unknown domain — emit as DomainProcess to land in verifier rather
			// than being silently lost. Confidence is lower because we can't
			// route the domain and it is therefore weaker RCA evidence.
			dom = model.DomainProcess
		}

		key, oldVal, newVal := parseDetailParts(ch.Detail)

		// Stable Fact ID: (type, key) so the same drift doesn't
		// appear as two distinct facts across ticks.
		id := fmt.Sprintf("config.drift.%s.%s", ch.Domain, key)

		// Measurement timestamp: prefer the change's When (when drift was
		// detected), fall back to the caller's measuredAt.
		ts := ch.When
		if ts.IsZero() {
			ts = measuredAt
		}

		tags := map[string]string{
			"key":    key,
			"old":    oldVal,
			"new":    newVal,
			"domain": ch.Domain,
		}

		conf := driftConfidence
		if !knownDomain {
			conf = driftUnknownConfidence
		}

		f := buildFactScoped(
			id,
			key,
			dom,
			driftPresenceValue, // Value: presence magnitude (dimensionless)
			"",                 // Unit: dimensionless
			driftPresenceValue, // warnThreshold: any drift event is ≥ warn
			conf,
			ts,
			"config",
			"host",
			tags,
		)

		// Override Kind — buildFactScoped defaults to FactKindSaturation.
		f.Kind = model.FactKindConfigChange

		facts = append(facts, f)
	}

	return facts
}

// correlateConfigDrift implements the onset-correlation seam for config-drift
// events. It is called by the engine after anomaly tracking and after
// result.Changes is populated.
//
// For each RCAEntry with a known domain:
//  1. Check all config_drift_* changes whose When is within driftCorrelationWindow
//     of now AND whose domain matches the entry's domain.
//  2. If a match is found, boost the entry's Score by a modest amount (8–12 pts,
//     capped at 100) and attach the corresponding Fact to result.Facts.
//
// The gate conditions (domain match + timing window) prevent over-inflation.
// An unrelated-domain or stale drift is never correlated.
//
// Analogous to the deploy-correlation path in anomaly.go (~lines 86-101) but
// implemented as a focused helper rather than inlined to keep anomaly.go
// unchanged and to make the config-drift seam independently testable.
func correlateConfigDrift(result *model.AnalysisResult, changes []model.SystemChange, now time.Time) {
	if result == nil || result.PrimaryScore == 0 {
		// No active anomaly — nothing to correlate.
		return
	}
	if len(changes) == 0 {
		return
	}

	// Filter changes to recent config_drift_* only once.
	type recentDrift struct {
		ch  model.SystemChange
		dom model.Domain
	}
	var recent []recentDrift
	for _, ch := range changes {
		if !strings.HasPrefix(ch.Type, "config_drift_") {
			continue
		}
		age := now.Sub(ch.When)
		if age < 0 {
			age = -age // tolerate minor clock skew
		}
		if age > driftCorrelationWindow {
			continue
		}
		dom, ok := driftDomainToModel(ch.Domain)
		if !ok {
			continue
		}
		recent = append(recent, recentDrift{ch: ch, dom: dom})
	}
	if len(recent) == 0 {
		return
	}

	// Correlate with each RCAEntry by domain.
	for i := range result.RCA {
		entry := &result.RCA[i]
		entryDomain := bottleneckDomain(entry.Bottleneck)
		if entryDomain == "" {
			continue
		}

		for _, rd := range recent {
			if rd.dom != entryDomain {
				continue
			}

			// Match found: boost score and attach fact.
			// Boost mirrors the deploy-correlation (anomaly.go ~90): ~10%,
			// clamped to [8, 12] to keep it modest.
			bonus := entry.Score / 10
			if bonus < 8 {
				bonus = 8
			}
			if bonus > 12 {
				bonus = 12
			}
			entry.Score += bonus
			if entry.Score > 100 {
				entry.Score = 100
			}

			// Also bump the primary score if this is the primary bottleneck.
			if entry.Bottleneck == result.PrimaryBottleneck {
				result.PrimaryScore = entry.Score
			}

			// Attach the drift Fact to result.Facts for the verifier and UI.
			driftFacts := InjectConfigDriftEvidence(nil, []model.SystemChange{rd.ch}, now)
			result.Facts = append(result.Facts, driftFacts...)

			// Surface a suggested (never applied) remediation in the narrative
			// when this drift is the primary or a contributing bottleneck.
			if result.Narrative != nil {
				key, oldVal, _ := parseDetailParts(rd.ch.Detail)
				if hint := suggestedRemediation(key, oldVal); hint != "" {
					result.Narrative.Evidence = append(
						result.Narrative.Evidence,
						"SUGGESTED: "+hint,
					)
				}
			}

			// Only apply the first matching drift per entry to avoid double-boosting.
			break
		}
	}
}
