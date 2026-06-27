package cmd

// daemonwire.go — concrete adapters wiring engine.DaemonStore and
// engine.DaemonAPIServer to the sqlite store and api packages.
//
// This file is in package cmd (NOT package engine) so that the concrete
// import of modernc.org/sqlite (via store/) and api/ never reaches the
// engine package. The xtop-agent binary does NOT import cmd, so these
// heavy imports stay out of its binary.
//
// The engine package only knows about the engine.DaemonStore and
// engine.DaemonAPIServer interfaces (defined in engine/persist_types.go).

import (
	"errors"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/ftahirops/xtop/api"
	"github.com/ftahirops/xtop/engine"
	"github.com/ftahirops/xtop/model"
	"github.com/ftahirops/xtop/store"
)

// ─────────────────────────────────────────────────────────────────────────────
// storePersistenceAdapter — implements engine.DaemonStore via *store.Store
// ─────────────────────────────────────────────────────────────────────────────

type storePersistenceAdapter struct {
	s *store.Store
}

// NewDaemonPersistence opens (or creates) the SQLite incident database at
// dbPath, runs migrations, and returns an engine.DaemonStore adapter. The
// caller is responsible for calling Close() on the returned engine.DaemonStore
// via the returned cleanup func — or simply by casting to io.Closer.
//
// On error (e.g. SQLite init failure) it returns nil, nil — the daemon
// degrades to JSONL-only without crashing.
func NewDaemonPersistence(dbPath string) (engine.DaemonStore, func(), error) {
	st, err := store.Open(dbPath)
	if err != nil {
		return nil, nil, fmt.Errorf("open sqlite: %w", err)
	}
	if err := st.Migrate(); err != nil {
		st.Close()
		return nil, nil, fmt.Errorf("migrate sqlite: %w", err)
	}
	adapter := &storePersistenceAdapter{s: st}
	cleanup := func() { st.Close() }
	return adapter, cleanup, nil
}

// ── DaemonStore: baseline persistence ────────────────────────────────────────

func (a *storePersistenceAdapter) SaveAppBaselines(rows []engine.AppBaselineRecord) error {
	return a.s.SaveAppBaselines(toStoreAppBaselineRows(rows))
}

func (a *storePersistenceAdapter) LoadAppBaselines() ([]engine.AppBaselineRecord, error) {
	rows, err := a.s.LoadAppBaselines()
	if err != nil {
		return nil, err
	}
	return fromStoreAppBaselineRows(rows), nil
}

func (a *storePersistenceAdapter) SaveDriftTrackers(rows []engine.DriftTrackerRecord) error {
	return a.s.SaveDriftTrackers(toStoreDriftTrackerRows(rows))
}

func (a *storePersistenceAdapter) LoadDriftTrackers() ([]engine.DriftTrackerRecord, error) {
	rows, err := a.s.LoadDriftTrackers()
	if err != nil {
		return nil, err
	}
	return fromStoreDriftTrackerRows(rows), nil
}

func (a *storePersistenceAdapter) SaveConfigBaseline(rows []engine.ConfigBaselineRecord) error {
	return a.s.SaveConfigBaseline(toStoreConfigBaselineRows(rows))
}

func (a *storePersistenceAdapter) LoadConfigBaseline() ([]engine.ConfigBaselineRecord, error) {
	rows, err := a.s.LoadConfigBaseline()
	if err != nil {
		return nil, err
	}
	return fromStoreConfigBaselineRows(rows), nil
}

// ── DaemonStore: incident operations ─────────────────────────────────────────

func (a *storePersistenceAdapter) InsertIncident(e model.Event, fingerprint string, offenders []model.ImpactScore) error {
	return a.s.InsertIncident(e, fingerprint, offenders)
}

func (a *storePersistenceAdapter) UpdateIncident(id string, e model.Event) error {
	return a.s.UpdateIncident(id, e)
}

func (a *storePersistenceAdapter) InsertAggregate(ts time.Time, agg engine.DaemonAggregateSample) error {
	return a.s.InsertAggregate(ts, store.AggregateSample{
		Health:  agg.Health,
		Score:   agg.Score,
		CPUBusy: agg.CPUBusy,
		MemPct:  agg.MemPct,
		IOPSI:   agg.IOPSI,
		TopPID:  agg.TopPID,
		TopComm: agg.TopComm,
	})
}

func (a *storePersistenceAdapter) UpsertFingerprint(fp engine.IncidentFingerprint) error {
	return a.s.UpsertFingerprint(store.Fingerprint{
		FP:          fp.FP,
		FirstSeen:   fp.FirstSeen,
		LastSeen:    fp.LastSeen,
		Count:       fp.Count,
		AvgDuration: fp.AvgDuration,
		SymptomType: fp.SymptomType,
		RootClass:   fp.RootClass,
		TopOffender: fp.TopOffender,
	})
}

func (a *storePersistenceAdapter) Prune(cutoff time.Time) (int, error) {
	return a.s.Prune(cutoff)
}

// ─────────────────────────────────────────────────────────────────────────────
// Type conversion helpers (engine ↔ store)
// ─────────────────────────────────────────────────────────────────────────────

func toStoreAppBaselineRows(in []engine.AppBaselineRecord) []store.AppBaselineRow {
	if len(in) == 0 {
		return nil
	}
	out := make([]store.AppBaselineRow, len(in))
	for i, r := range in {
		out[i] = store.AppBaselineRow{
			App:        r.App,
			Metric:     r.Metric,
			HourOfWeek: r.HourOfWeek,
			Count:      r.Count,
			Mean:       r.Mean,
			M2:         r.M2,
		}
	}
	return out
}

func fromStoreAppBaselineRows(in []store.AppBaselineRow) []engine.AppBaselineRecord {
	if len(in) == 0 {
		return nil
	}
	out := make([]engine.AppBaselineRecord, len(in))
	for i, r := range in {
		out[i] = engine.AppBaselineRecord{
			App:        r.App,
			Metric:     r.Metric,
			HourOfWeek: r.HourOfWeek,
			Count:      r.Count,
			Mean:       r.Mean,
			M2:         r.M2,
		}
	}
	return out
}

func toStoreDriftTrackerRows(in []engine.DriftTrackerRecord) []store.DriftTrackerRow {
	if len(in) == 0 {
		return nil
	}
	out := make([]store.DriftTrackerRow, len(in))
	for i, r := range in {
		out[i] = store.DriftTrackerRow{
			Metric: r.Metric,
			Window: r.Window,
			Count:  r.Count,
			Mean:   r.Mean,
			M2:     r.M2,
			RefSet: r.RefSet,
		}
	}
	return out
}

func fromStoreDriftTrackerRows(in []store.DriftTrackerRow) []engine.DriftTrackerRecord {
	if len(in) == 0 {
		return nil
	}
	out := make([]engine.DriftTrackerRecord, len(in))
	for i, r := range in {
		out[i] = engine.DriftTrackerRecord{
			Metric: r.Metric,
			Window: r.Window,
			Count:  r.Count,
			Mean:   r.Mean,
			M2:     r.M2,
			RefSet: r.RefSet,
		}
	}
	return out
}

func toStoreConfigBaselineRows(in []engine.ConfigBaselineRecord) []store.ConfigBaselineRow {
	if len(in) == 0 {
		return nil
	}
	out := make([]store.ConfigBaselineRow, len(in))
	for i, r := range in {
		out[i] = store.ConfigBaselineRow{
			Key:       r.Key,
			Value:     r.Value,
			Domain:    r.Domain,
			FirstSeen: r.FirstSeen,
			Acked:     r.Acked,
		}
	}
	return out
}

func fromStoreConfigBaselineRows(in []store.ConfigBaselineRow) []engine.ConfigBaselineRecord {
	if len(in) == 0 {
		return nil
	}
	out := make([]engine.ConfigBaselineRecord, len(in))
	for i, r := range in {
		out[i] = engine.ConfigBaselineRecord{
			Key:       r.Key,
			Value:     r.Value,
			Domain:    r.Domain,
			FirstSeen: r.FirstSeen,
			Acked:     r.Acked,
		}
	}
	return out
}

// ─────────────────────────────────────────────────────────────────────────────
// apiServerAdapter — implements engine.DaemonAPIServer via api.Server
// ─────────────────────────────────────────────────────────────────────────────

type apiServerAdapter struct {
	srv      *api.Server
	provider *api.DaemonSnapshotProvider
}

// NewDaemonAPIServer creates a Unix-socket API server at sockPath and returns
// an engine.DaemonAPIServer. The persistence adapter's underlying *store.Store
// is retrieved via type assertion so the api package can use it for incident
// queries. Returns (nil, nil) on failure — callers treat nil as "no API".
func NewDaemonAPIServer(sockPath string, persistence engine.DaemonStore, dbPath string) (engine.DaemonAPIServer, error) {
	// Open the raw *store.Store for the api package. The persistence adapter
	// already has one open; the cheapest approach is to use the adapter's
	// internal store. Since we control both types, type-assert.
	var rawStore *store.Store
	if adapter, ok := persistence.(*storePersistenceAdapter); ok && adapter != nil {
		rawStore = adapter.s
	}
	// rawStore may be nil if persistence is nil or a different implementation;
	// api.NewServer handles nil gracefully (incidents endpoint returns empty).

	provider := api.NewDaemonSnapshotProvider()
	srv, err := api.NewServer(sockPath, provider, rawStore)
	if err != nil {
		return nil, err
	}
	return &apiServerAdapter{srv: srv, provider: provider}, nil
}

func (a *apiServerAdapter) Update(snap *model.Snapshot, rates *model.RateSnapshot, result *model.AnalysisResult, scores []model.ImpactScore) {
	a.provider.Update(snap, rates, result, scores)
}

func (a *apiServerAdapter) Serve() error {
	return a.srv.Serve()
}

func (a *apiServerAdapter) Close() error {
	a.srv.Close()
	return nil
}

// ─────────────────────────────────────────────────────────────────────────────
// BuildDaemonBackends constructs and wires persistence + API for RunDaemon.
// Returns the backends and a cleanup func; on partial failure it logs and
// degrades gracefully (nil backends mean JSONL-only / no API socket).
// ─────────────────────────────────────────────────────────────────────────────

// BuildDaemonBackends opens the SQLite store and API server and returns the
// engine interfaces to pass into DaemonConfig. cleanup must be called on
// daemon shutdown (after eng.Close()).
func BuildDaemonBackends(dataDir string) (persistence engine.DaemonStore, apiSrv engine.DaemonAPIServer, cleanup func()) {
	dbPath := dataDir + "/incidents.db"
	dbCleanup := func() {}

	var p engine.DaemonStore
	if pst, cl, err := NewDaemonPersistence(dbPath); err != nil {
		log.Printf("SQLite init failed (JSONL fallback): %v", err)
	} else {
		p = pst
		dbCleanup = cl
		log.Printf("SQLite incident store: %s", dbPath)
	}

	sockPath := api.DefaultSockPath()
	var srv engine.DaemonAPIServer
	if p != nil {
		if s, err := NewDaemonAPIServer(sockPath, p, dbPath); err != nil {
			log.Printf("API server init failed: %v", err)
		} else {
			srv = s
			log.Printf("API server will listen on %s", sockPath)
		}
	}

	cleanup = func() {
		if srv != nil {
			if err := srv.Close(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				log.Printf("API server close: %v", err)
			}
		}
		dbCleanup()
	}
	return p, srv, cleanup
}
