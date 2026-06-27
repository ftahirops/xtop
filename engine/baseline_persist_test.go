package engine

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/ftahirops/xtop/model"
	"github.com/ftahirops/xtop/store"
)

// testStoreAdapter wraps *store.Store to implement engine.DaemonStore for tests.
// Lives here (package engine) to avoid importing cmd/ which would be circular.
type testStoreAdapter struct {
	s *store.Store
}

func (a *testStoreAdapter) SaveAppBaselines(rows []AppBaselineRecord) error {
	sr := make([]store.AppBaselineRow, len(rows))
	for i, r := range rows {
		sr[i] = store.AppBaselineRow{
			App:        r.App,
			Metric:     r.Metric,
			HourOfWeek: r.HourOfWeek,
			Count:      r.Count,
			Mean:       r.Mean,
			M2:         r.M2,
		}
	}
	return a.s.SaveAppBaselines(sr)
}

func (a *testStoreAdapter) LoadAppBaselines() ([]AppBaselineRecord, error) {
	rows, err := a.s.LoadAppBaselines()
	if err != nil {
		return nil, err
	}
	out := make([]AppBaselineRecord, len(rows))
	for i, r := range rows {
		out[i] = AppBaselineRecord{
			App:        r.App,
			Metric:     r.Metric,
			HourOfWeek: r.HourOfWeek,
			Count:      r.Count,
			Mean:       r.Mean,
			M2:         r.M2,
		}
	}
	return out, nil
}

func (a *testStoreAdapter) SaveDriftTrackers(rows []DriftTrackerRecord) error {
	sr := make([]store.DriftTrackerRow, len(rows))
	for i, r := range rows {
		sr[i] = store.DriftTrackerRow{
			Metric: r.Metric,
			Window: r.Window,
			Count:  r.Count,
			Mean:   r.Mean,
			M2:     r.M2,
			RefSet: r.RefSet,
		}
	}
	return a.s.SaveDriftTrackers(sr)
}

func (a *testStoreAdapter) LoadDriftTrackers() ([]DriftTrackerRecord, error) {
	rows, err := a.s.LoadDriftTrackers()
	if err != nil {
		return nil, err
	}
	out := make([]DriftTrackerRecord, len(rows))
	for i, r := range rows {
		out[i] = DriftTrackerRecord{
			Metric: r.Metric,
			Window: r.Window,
			Count:  r.Count,
			Mean:   r.Mean,
			M2:     r.M2,
			RefSet: r.RefSet,
		}
	}
	return out, nil
}

func (a *testStoreAdapter) SaveConfigBaseline(rows []ConfigBaselineRecord) error {
	sr := make([]store.ConfigBaselineRow, len(rows))
	for i, r := range rows {
		sr[i] = store.ConfigBaselineRow{
			Key:       r.Key,
			Value:     r.Value,
			Domain:    r.Domain,
			FirstSeen: r.FirstSeen,
			Acked:     r.Acked,
		}
	}
	return a.s.SaveConfigBaseline(sr)
}

func (a *testStoreAdapter) LoadConfigBaseline() ([]ConfigBaselineRecord, error) {
	rows, err := a.s.LoadConfigBaseline()
	if err != nil {
		return nil, err
	}
	out := make([]ConfigBaselineRecord, len(rows))
	for i, r := range rows {
		out[i] = ConfigBaselineRecord{
			Key:       r.Key,
			Value:     r.Value,
			Domain:    r.Domain,
			FirstSeen: r.FirstSeen,
			Acked:     r.Acked,
		}
	}
	return out, nil
}

// Stub out incident operations — not exercised by baseline persistence tests.
func (a *testStoreAdapter) InsertIncident(e model.Event, fp string, offenders []model.ImpactScore) error {
	return nil
}
func (a *testStoreAdapter) UpdateIncident(id string, e model.Event) error { return nil }
func (a *testStoreAdapter) InsertAggregate(ts time.Time, agg DaemonAggregateSample) error {
	return nil
}
func (a *testStoreAdapter) UpsertFingerprint(fp IncidentFingerprint) error { return nil }
func (a *testStoreAdapter) Prune(cutoff time.Time) (int, error)            { return 0, nil }

// ─────────────────────────────────────────────────────────────────────────────

// TestBaselinePersist_Roundtrip: in-memory state persisted to SQLite then
// loaded back into a fresh History reproduces the same Welford values.
func TestBaselinePersist_Roundtrip(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")
	raw, err := store.Open(dbPath)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer raw.Close()
	if err := raw.Migrate(); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	s := &testStoreAdapter{s: raw}

	hist1 := NewHistory(10, 3)
	bs1 := getAppBaselineStore(hist1)
	bs1.mu.Lock()
	bs1.buckets[appKey("postgres", "cpu_pct", 39)] = &appBaselineBucket{count: 100, mean: 30.5, m2: 12.3}
	bs1.buckets[appKey("redis", "rss_mb", 39)] = &appBaselineBucket{count: 50, mean: 220.0, m2: 80.0}
	bs1.mu.Unlock()

	ds1 := getDriftStore(hist1)
	ds1.mu.Lock()
	ds1.trackers["cpu.busy"] = &driftTracker{
		short:  appBaselineBucket{count: 200, mean: 25.0, m2: 100.0},
		long:   appBaselineBucket{count: 5000, mean: 22.0, m2: 9000.0},
		ref:    appBaselineBucket{count: 200, mean: 18.0, m2: 80.0},
		refSet: true,
	}
	ds1.mu.Unlock()

	eng1 := &Engine{History: hist1}
	if err := eng1.SaveBaselineState(s); err != nil {
		t.Fatalf("save: %v", err)
	}

	// Fresh history. Load. Verify values match.
	hist2 := NewHistory(10, 3)
	eng2 := &Engine{History: hist2}
	if err := eng2.LoadBaselineState(s); err != nil {
		t.Fatalf("load: %v", err)
	}

	bs2 := getAppBaselineStore(hist2)
	bs2.mu.Lock()
	defer bs2.mu.Unlock()
	got, ok := bs2.buckets[appKey("postgres", "cpu_pct", 39)]
	if !ok || got.count != 100 || got.mean != 30.5 || got.m2 != 12.3 {
		t.Errorf("postgres cpu_pct not round-tripped: %+v", got)
	}
	got, ok = bs2.buckets[appKey("redis", "rss_mb", 39)]
	if !ok || got.count != 50 || got.mean != 220.0 || got.m2 != 80.0 {
		t.Errorf("redis rss_mb not round-tripped: %+v", got)
	}

	ds2 := getDriftStore(hist2)
	ds2.mu.Lock()
	defer ds2.mu.Unlock()
	dt, ok := ds2.trackers["cpu.busy"]
	if !ok {
		t.Fatal("cpu.busy drift tracker not loaded")
	}
	if dt.short.count != 200 || dt.long.count != 5000 || !dt.refSet {
		t.Errorf("drift tracker not round-tripped: short=%+v long=%+v refSet=%v",
			dt.short, dt.long, dt.refSet)
	}
}

func TestFmtSscanInt(t *testing.T) {
	cases := map[string]int{"039": 39, "0": 0, "167": 167, "1": 1}
	for in, want := range cases {
		var got int
		if _, err := fmtSscanInt(in, &got); err != nil || got != want {
			t.Errorf("fmtSscanInt(%q) = %d (err=%v), want %d", in, got, err, want)
		}
	}
	var bad int
	if _, err := fmtSscanInt("xyz", &bad); err == nil {
		t.Error("fmtSscanInt(\"xyz\") must error")
	}
}
