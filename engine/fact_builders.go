package engine

import (
	"time"

	"github.com/ftahirops/xtop/model"
)

// buildFact is the shared constructor used by every domain analyzer
// when emitting model.Fact in parallel to legacy Evidence. Severity is
// inferred from value vs warn threshold; verifier gates (NEXTGEN
// Phase 4) will refine. Confidence is per-metric per the
// model.FactConfidence rubric (kernel direct > derived > interpreted).
//
// Keeping one builder ensures every Fact emitted by the engine has
// consistent provenance fields — required for the replay corpus
// (Phase 5).
func buildFact(
	id, metric string,
	domain model.Domain,
	value float64,
	unit string,
	warnThreshold float64,
	confidence float64,
	measuredAt time.Time,
	source string,
	tags map[string]string,
) model.Fact {
	sev := model.FactSeverityInfo
	if warnThreshold > 0 && value >= warnThreshold {
		sev = model.FactSeverityWarn
	}
	if measuredAt.IsZero() {
		measuredAt = time.Now()
	}
	if source == "" {
		source = "procfs"
	}
	return model.Fact{
		ID:         id,
		Kind:       model.FactKindSaturation,
		Source:     source,
		EntityID:   "host",
		Domain:     domain,
		Metric:     metric,
		Value:      value,
		Unit:       unit,
		MeasuredAt: measuredAt,
		Severity:   sev,
		Confidence: model.FactConfidence(confidence),
		Tags:       tags,
	}
}

// buildFactScoped is buildFact + an explicit EntityID for facts that
// are NOT host-scoped (e.g. cgroup throttle pct, per-device disk
// latency). The entityID should match an entity ID in the EntityGraph
// so the verifier can walk the ancestor chain.
//
// Empty entityID falls back to "host" — callers can pass cgroupEntityID
// or deviceEntityID unconditionally without nil-guarding.
func buildFactScoped(
	id, metric string,
	domain model.Domain,
	value float64,
	unit string,
	warnThreshold float64,
	confidence float64,
	measuredAt time.Time,
	source string,
	entityID string,
	tags map[string]string,
) model.Fact {
	f := buildFact(id, metric, domain, value, unit, warnThreshold, confidence, measuredAt, source, tags)
	if entityID != "" {
		f.EntityID = entityID
	}
	return f
}

// cgroupEntityID returns the canonical entity ID for a cgroup path, or
// "host" if path is empty/root. Mirrors the format BuildEntityGraph uses.
func cgroupEntityID(path string) string {
	if path == "" || path == "/" {
		return "host"
	}
	return "cgroup:" + path
}

// deviceEntityID returns the canonical entity ID for a block device.
// Falls back to "host" if device name is empty.
func deviceEntityID(dev string) string {
	if dev == "" {
		return "host"
	}
	return "device:" + dev
}
