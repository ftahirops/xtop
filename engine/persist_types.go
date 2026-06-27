package engine

// persist_types.go — engine-local persistence types and interfaces.
//
// These types mirror the store package structs (store.ConfigBaselineRow, etc.)
// WITHOUT importing the store package. This keeps modernc.org/sqlite out of
// the agent's import graph.
//
// The concrete sqlite-backed implementation of DaemonStore lives in cmd/
// (cmd/daemonwire.go), which is NOT imported by cmd/xtop-agent. The engine
// only knows about the interfaces; callers provide the implementations.

import (
	"time"

	"github.com/ftahirops/xtop/model"
)

// ──────────────────────────────────────────────────────────────────────────────
// Engine-local record types (no store import needed)
// ──────────────────────────────────────────────────────────────────────────────

// ConfigBaselineRecord is the engine-local view of one persisted kernel-param
// baseline entry. Mirrors store.ConfigBaselineRow without importing store.
type ConfigBaselineRecord struct {
	Key       string
	Value     string
	Domain    string
	FirstSeen time.Time
	Acked     bool
}

// AppBaselineRecord is the engine-local view of one persisted Welford bucket
// for application baselines. Mirrors store.AppBaselineRow.
type AppBaselineRecord struct {
	App        string
	Metric     string
	HourOfWeek int
	Count      int64
	Mean       float64
	M2         float64
}

// DriftTrackerRecord is the engine-local view of one persisted Welford bucket
// within a drift window. Mirrors store.DriftTrackerRow.
type DriftTrackerRecord struct {
	Metric string
	Window string // "short" | "long" | "ref"
	Count  int64
	Mean   float64
	M2     float64
	RefSet bool
}

// DaemonAggregateSample is the engine-local view of a 10s aggregate sample.
// Mirrors store.AggregateSample.
type DaemonAggregateSample struct {
	Health  string
	Score   int
	CPUBusy float64
	MemPct  float64
	IOPSI   float64
	TopPID  int
	TopComm string
}

// IncidentFingerprint is the engine-local view of an incident fingerprint row.
// Mirrors store.Fingerprint.
type IncidentFingerprint struct {
	FP          string
	FirstSeen   time.Time
	LastSeen    time.Time
	Count       int
	AvgDuration int
	SymptomType string
	RootClass   string
	TopOffender string
}

// ──────────────────────────────────────────────────────────────────────────────
// Persistence interfaces
// ──────────────────────────────────────────────────────────────────────────────

// DaemonStore is the full persistence interface used by the engine daemon path.
// Implementations live in cmd/ (never in engine/ or agent-reachable packages).
// Passing nil to any engine function that accepts DaemonStore is always safe —
// callers guard with `if s != nil`.
type DaemonStore interface {
	// Baseline Welford state (app performance baselines)
	SaveAppBaselines(rows []AppBaselineRecord) error
	LoadAppBaselines() ([]AppBaselineRecord, error)

	// Drift tracker Welford state
	SaveDriftTrackers(rows []DriftTrackerRecord) error
	LoadDriftTrackers() ([]DriftTrackerRecord, error)

	// Kernel-param config baseline (P4.2 / P4.3)
	SaveConfigBaseline(rows []ConfigBaselineRecord) error
	LoadConfigBaseline() ([]ConfigBaselineRecord, error)

	// Incident tracking
	InsertIncident(e model.Event, fingerprint string, offenders []model.ImpactScore) error
	UpdateIncident(id string, e model.Event) error
	InsertAggregate(ts time.Time, agg DaemonAggregateSample) error
	UpsertFingerprint(fp IncidentFingerprint) error
	Prune(cutoff time.Time) (int, error)
}

// DaemonAPIServer abstracts the Unix-socket API server so daemon.go need not
// import the api package directly. The concrete implementation (api.Server +
// api.DaemonSnapshotProvider) is created in cmd/daemonwire.go.
type DaemonAPIServer interface {
	// Update pushes the latest snapshot to the API snapshot provider.
	Update(snap *model.Snapshot, rates *model.RateSnapshot, result *model.AnalysisResult, scores []model.ImpactScore)
	// Serve starts the HTTP handler loop; returns http.ErrServerClosed on normal shutdown.
	Serve() error
	// Close shuts down the listener.
	Close() error
}
