// This file (model/fact.go) defines the typed evidence layer for
// NEXTGEN xtop.
//
// Per NEXTGEN_RCA_ARCHITECTURE.md §2 "Evidence Normalization Layer",
// every raw signal becomes a Fact — a typed observation with full
// provenance. Facts replace the implicit "everything is a number" model
// inherited from the original engine; they are the substrate the
// hypothesis engine + verifier gates will reason over.
//
// Phase 2 ships the type. Phase 4 (candidate/verifier split) consumes
// it as input. Phase 5 (incident ledger + replay) serializes it for
// deterministic re-runs.
//
// Design rules:
//
//  1. Facts are VALUE types — copy them freely, no shared state.
//  2. Facts are IMMUTABLE in spirit — once emitted, never mutated.
//     We don't enforce this with private fields because Go composite
//     literals are too useful; tests + verifier checks rely on them.
//  3. Every field is JSON-serializable for replay.
//  4. No methods that allocate or do I/O — purely a data carrier.

package model

import "time"

// FactKind tags a Fact by its evidence class. Per NEXTGEN §2 "Evidence
// classes", facts fall into six buckets. The kind determines which
// verifier gates apply and what counter-evidence to look for.
type FactKind string

const (
	// FactKindSymptom is a user-visible impact signal (latency, error rate,
	// queue depth from the requesting process's POV).
	FactKindSymptom FactKind = "symptom"

	// FactKindSaturation is a resource-pressure signal (CPU%, mem%, PSI,
	// disk %util, conntrack fill).
	FactKindSaturation FactKind = "saturation"

	// FactKindOwnership is an attribution signal (this PID is the top CPU
	// consumer; this cgroup owns the disk IO).
	FactKindOwnership FactKind = "ownership"

	// FactKindDependency is a relational signal (service X talks to Y;
	// process P holds lock L).
	FactKindDependency FactKind = "dependency"

	// FactKindChange is a "something changed" signal (config drift, deploy,
	// package upgrade, service restart).
	FactKindChange FactKind = "change"

	// FactKindProbe is the output of an active confirmation probe — never
	// passive observation. Triggered only by the verifier when needed.
	FactKindProbe FactKind = "probe"

	// FactKindLogEvidence is a structured finding extracted from journald /
	// syslog entries — e.g. crash-restart loops, OOM kills, segfaults, or
	// dependency-connection failures. Produced by InjectJournalEvidence.
	FactKindLogEvidence FactKind = "log_evidence"

	// FactKindConfigChange is a "something changed" signal specifically for
	// OS/kernel runtime parameter drift — sysctl values, hugepage settings,
	// CPU governor, cgroup limits, etc. Produced by InjectConfigDriftEvidence.
	// Confidence is moderate (~0.6) because config drift is derived/interpreted;
	// onset-correlation (Phase 4.4) is what gives it RCA weight.
	FactKindConfigChange FactKind = "config_change"
)

// FactConfidence is how much we trust this fact's measurement, on [0,1].
// Distinct from the verifier's downstream "this fact supports cause X"
// reasoning — FactConfidence is about the MEASUREMENT itself.
//
// Guidance:
//
//	1.00 — direct kernel counter (procfs, sysfs, cgroup)
//	0.90 — derived from kernel counters with simple arithmetic
//	0.80 — eBPF event stream
//	0.70 — secondary metrics needing interpretation
//	0.50 — single-sample heuristics (snapshot-only)
//	0.30 — log-line parsing / unstructured input
//	0.10 — wild guess, present mostly for completeness
type FactConfidence float64

// FactSeverity describes how serious THIS fact is — independent of how
// it combines with others. The verifier rolls severities up.
//
// Note: distinct from the pre-existing Severity type (which uses
// integer levels for HealthLevel transitions). FactSeverity is a
// string for the line-delimited replay format.
type FactSeverity string

const (
	FactSeverityInfo FactSeverity = "info"
	FactSeverityWarn FactSeverity = "warn"
	FactSeverityCrit FactSeverity = "crit"
)

// Fact is one typed observation with provenance. Every field is
// settable from a composite literal; no required helpers.
//
// Field naming uses snake_case JSON tags for compatibility with the
// future replay format (line-delimited JSON, one Fact per line).
type Fact struct {
	// ID is a stable, unique identifier. Convention:
	// "<domain>.<metric>" for raw signals, "<domain>.<metric>.<entity>"
	// when scoped. Example: "cpu.psi.avg10", "cpu.runqueue.host".
	ID string `json:"id"`

	// Kind buckets this fact for verifier dispatch.
	Kind FactKind `json:"kind"`

	// Source identifies the producer (collector name, eBPF program,
	// adapter). Used by the verifier to weight conflicting facts.
	// Example: "procfs", "eBPF/biolatency", "mongo-adapter".
	Source string `json:"source"`

	// EntityID is the thing this fact is ABOUT. Empty when host-scope.
	// Conventions:
	//   "host"          — global host fact
	//   "pid:1234"      — about a specific process
	//   "cgroup:/sys/fs/cgroup/system.slice/mongod.service"
	//   "service:mongod"
	//   "mount:/var/lib/mysql"
	EntityID string `json:"entity_id,omitempty"`

	// OwnerID, when set, identifies the owner of EntityID — the upward
	// pointer in the entity graph. Example: a process's cgroup, a
	// mount's owning service.
	OwnerID string `json:"owner_id,omitempty"`

	// Domain routes this fact to the right detector / verifier gates.
	Domain Domain `json:"domain"`

	// Metric is the human-readable name of what is being measured.
	// Example: "psi.avg10", "rss_bytes", "queue_depth".
	Metric string `json:"metric"`

	// Value is the measurement. Float so we can represent rates,
	// percentages, counts, and durations uniformly. NaN is reserved
	// for "explicitly unknown" — prefer omitting the fact.
	Value float64 `json:"value"`

	// Unit names the unit of Value. "%", "bytes", "ms", "count".
	// Empty when dimensionless or when carried in Tags.
	Unit string `json:"unit,omitempty"`

	// MeasuredAt is the wall-clock time the measurement was taken.
	// Required; zero value indicates a malformed Fact.
	MeasuredAt time.Time `json:"measured_at"`

	// FirstSeenAt is when this signal first crossed its threshold.
	// Tracked by the engine across ticks; for a brand-new fact it
	// equals MeasuredAt. Pointer so omitempty works (zero time.Time
	// isn't treated as empty by encoding/json).
	FirstSeenAt *time.Time `json:"first_seen_at,omitempty"`

	// LastSeenAt is when this signal was last observed above threshold.
	// Distinct from MeasuredAt so the verifier can detect "still active"
	// vs "transient spike". Pointer for omitempty semantics.
	LastSeenAt *time.Time `json:"last_seen_at,omitempty"`

	// Duration is the cumulative time this signal has been active.
	// Used by the temporal-ordering gate (cause must precede effect
	// by at least Duration).
	Duration time.Duration `json:"duration,omitempty"`

	// Severity is how serious this single fact is.
	Severity FactSeverity `json:"severity"`

	// Confidence is the measurement-quality score in [0,1]. See the
	// FactConfidence type docstring for the rubric.
	Confidence FactConfidence `json:"confidence"`

	// BaselineDelta, when set, is how far above baseline this value is.
	// Units match Value's Unit. Used by the baseline-deviation gate.
	// Zero when no baseline is available — distinguish from "exactly
	// at baseline" via Tags["baseline_known"]="true".
	BaselineDelta float64 `json:"baseline_delta,omitempty"`

	// Tags carries free-form metadata that doesn't fit the schema.
	// Examples: device name, cgroup path, weight class, app type.
	Tags map[string]string `json:"tags,omitempty"`
}

// IsValid returns true if this Fact has the required fields set.
// A fact missing ID, Domain, or MeasuredAt is malformed; downstream
// stages should reject it.
func (f Fact) IsValid() bool {
	return f.ID != "" && f.Domain != "" && !f.MeasuredAt.IsZero()
}
