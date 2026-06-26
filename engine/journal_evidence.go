package engine

import (
	"fmt"
	"strconv"
	"time"

	"github.com/ftahirops/xtop/collector/journal"
	"github.com/ftahirops/xtop/model"
)

// confidenceForSignature returns the measurement-trust score for a journal
// signature per the NEXTGEN FactConfidence rubric.
//
//   - crash_restart_loop / oom_killed / segfault_panic  → HIGH (~0.9):
//     these are direct init/kernel-reported events with no interpretation.
//   - resource_exhaustion / dependency_failure / config_auth_error → DERIVED (~0.6):
//     real signals but require log-parsing and some classification heuristic.
//   - error_rate_spike → INTERPRETED (~0.4):
//     rate comparison against a baseline — indirect and context-dependent.
func confidenceForSignature(sig string) float64 {
	switch sig {
	case "crash_restart_loop", "oom_killed", "segfault_panic":
		return 0.9
	case "resource_exhaustion", "dependency_failure", "config_auth_error":
		return 0.6
	case "error_rate_spike":
		return 0.4
	default:
		return 0.4 // unknown signatures treated as interpreted
	}
}

// diagSevToFactSev maps a model.DiagSeverity from the journal classifier to
// the equivalent model.FactSeverity used in the Fact layer.
func diagSevToFactSev(s model.DiagSeverity) model.FactSeverity {
	switch s {
	case model.DiagCrit:
		return model.FactSeverityCrit
	case model.DiagWarn:
		return model.FactSeverityWarn
	default:
		return model.FactSeverityInfo
	}
}

// InjectJournalEvidence converts a slice of journal.JournalFinding into
// model.Facts scoped to serviceEntityID.
//
// Entity scoping decision:
//   - If graph != nil and serviceEntityID is present in the graph, the Fact's
//     EntityID is set to serviceEntityID (preferred — tight scoping).
//   - If graph != nil and serviceEntityID is ABSENT, EntityID falls back to
//     "host" so the fact still lands in the verifier rather than being dropped.
//   - If graph is nil, serviceEntityID is used as-is (caller takes
//     responsibility for validity).
//
// Findings are never dropped; the host fallback is a safety net for units
// not yet catalogued in the entity graph (e.g. transient kernel units).
//
// Callers (P2.4 / P2.5) decide where to attach the returned Facts; this
// function only builds and returns them.
func InjectJournalEvidence(
	graph *model.EntityGraph,
	serviceEntityID string,
	findings []journal.JournalFinding,
	measuredAt time.Time,
) []model.Fact {
	if len(findings) == 0 {
		return nil
	}

	// Resolve the entity ID to use for all Facts in this batch.
	entityID := serviceEntityID
	if graph != nil {
		if graph.Lookup(serviceEntityID) == nil {
			// Entity not in graph — fall back to host-level so the fact lands.
			entityID = "host"
		}
	}

	facts := make([]model.Fact, 0, len(findings))

	for _, finding := range findings {
		// Prefer finding.LastSeen as the measurement timestamp; fall back to
		// the caller-supplied measuredAt (e.g. when finding times are zero).
		ts := finding.LastSeen
		if ts.IsZero() {
			ts = measuredAt
		}

		conf := confidenceForSignature(finding.Signature)

		// Stable ID scoped to (service, signature) for cross-tick dedup.
		id := fmt.Sprintf("journal.%s.%s", serviceEntityID, finding.Signature)

		// Build via the shared factory (sets Kind=FactKindSaturation, Source,
		// EntityID, Domain, Metric, Value, Unit, Severity, Confidence).
		// We override Kind, Source, Severity, and EntityID immediately after.
		tags := map[string]string{
			"unit":      serviceEntityID,
			"signature": finding.Signature,
			"sample":    finding.Sample,
			"pid":       strconv.Itoa(finding.PID),
		}

		f := buildFactScoped(
			id,
			"journal."+finding.Signature,
			model.DomainProcess,
			float64(finding.Count),
			"events",
			1,    // warnThreshold: any event is at least warn
			conf, // confidence
			ts,
			"journald",
			entityID,
			tags,
		)

		// Override the fields buildFactScoped defaulted:
		f.Kind = model.FactKindLogEvidence
		f.Source = "journald"
		f.EntityID = entityID
		f.Severity = diagSevToFactSev(finding.Severity)

		facts = append(facts, f)
	}

	return facts
}
