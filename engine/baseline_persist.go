package engine

import (
	"strings"

	"github.com/ftahirops/xtop/store"
)

// TODO #1: bridge between in-memory Welford stores (Phase 4 app baselines,
// Phase 5 drift trackers) and the SQLite store/ package.
//
// Engine calls SaveBaselineState periodically and on Close; calls
// LoadBaselineState once on startup before the first Tick.

// dumpAppBaselineRows serializes the in-memory app baseline store into rows.
// Locks the store internally; safe to call from any goroutine.
func dumpAppBaselineRows(hist *History) []store.AppBaselineRow {
	if hist == nil {
		return nil
	}
	s, ok := func() (*appBaselineStore, bool) {
		appBaselinesMu.Lock()
		defer appBaselinesMu.Unlock()
		s, ok := appBaselines[hist]
		return s, ok
	}()
	if !ok {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	rows := make([]store.AppBaselineRow, 0, len(s.buckets))
	for key, b := range s.buckets {
		// Key format: "app:<role>:<metric>:<how>" (see appKey).
		parts := strings.SplitN(key, ":", 4)
		if len(parts) != 4 || parts[0] != "app" {
			continue
		}
		var how int
		// %03d format — fmt.Sscanf is fine here.
		if _, err := fmtSscanInt(parts[3], &how); err != nil {
			continue
		}
		rows = append(rows, store.AppBaselineRow{
			App:        parts[1],
			Metric:     parts[2],
			HourOfWeek: how,
			Count:      b.count,
			Mean:       b.mean,
			M2:         b.m2,
		})
	}
	return rows
}

// loadAppBaselineRows seeds the in-memory app baseline store from rows
// previously written to SQLite. Idempotent — overwrites any existing
// in-memory state for keys present in `rows`.
func loadAppBaselineRows(hist *History, rows []store.AppBaselineRow) {
	if hist == nil || len(rows) == 0 {
		return
	}
	s := getAppBaselineStore(hist)
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, r := range rows {
		key := appKey(r.App, r.Metric, r.HourOfWeek)
		s.buckets[key] = &appBaselineBucket{
			count: r.Count, mean: r.Mean, m2: r.M2,
		}
	}
}

// dumpDriftRows serializes drift trackers into store rows.
func dumpDriftRows(hist *History) []store.DriftTrackerRow {
	if hist == nil {
		return nil
	}
	ds, ok := func() (*driftStore, bool) {
		driftStoresMu.Lock()
		defer driftStoresMu.Unlock()
		ds, ok := driftStores[hist]
		return ds, ok
	}()
	if !ok {
		return nil
	}
	ds.mu.Lock()
	defer ds.mu.Unlock()

	rows := make([]store.DriftTrackerRow, 0, len(ds.trackers)*3)
	for metric, t := range ds.trackers {
		rows = append(rows, store.DriftTrackerRow{
			Metric: metric, Window: "short",
			Count: t.short.count, Mean: t.short.mean, M2: t.short.m2,
		})
		rows = append(rows, store.DriftTrackerRow{
			Metric: metric, Window: "long",
			Count: t.long.count, Mean: t.long.mean, M2: t.long.m2,
		})
		if t.refSet {
			rows = append(rows, store.DriftTrackerRow{
				Metric: metric, Window: "ref", RefSet: true,
				Count: t.ref.count, Mean: t.ref.mean, M2: t.ref.m2,
			})
		}
	}
	return rows
}

// loadDriftRows seeds drift trackers from previously persisted rows.
func loadDriftRows(hist *History, rows []store.DriftTrackerRow) {
	if hist == nil || len(rows) == 0 {
		return
	}
	ds := getDriftStore(hist)
	ds.mu.Lock()
	defer ds.mu.Unlock()
	for _, r := range rows {
		t, ok := ds.trackers[r.Metric]
		if !ok {
			t = &driftTracker{}
			ds.trackers[r.Metric] = t
		}
		switch r.Window {
		case "short":
			t.short = appBaselineBucket{count: r.Count, mean: r.Mean, m2: r.M2}
		case "long":
			t.long = appBaselineBucket{count: r.Count, mean: r.Mean, m2: r.M2}
		case "ref":
			t.ref = appBaselineBucket{count: r.Count, mean: r.Mean, m2: r.M2}
			t.refSet = true
		}
	}
}

// SaveBaselineState writes the in-memory Welford state for app baselines
// and drift trackers to the supplied store. Engine calls this periodically
// and on Close. Safe to call with nil store (no-op).
func (e *Engine) SaveBaselineState(s *store.Store) error {
	if e == nil || s == nil || e.History == nil {
		return nil
	}
	if err := s.SaveAppBaselines(dumpAppBaselineRows(e.History)); err != nil {
		return err
	}
	return s.SaveDriftTrackers(dumpDriftRows(e.History))
}

// LoadBaselineState reads previously persisted Welford state and seeds the
// in-memory stores. Engine calls this once on startup, before the first
// Tick. Safe with nil store (no-op).
func (e *Engine) LoadBaselineState(s *store.Store) error {
	if e == nil || s == nil || e.History == nil {
		return nil
	}
	apps, err := s.LoadAppBaselines()
	if err != nil {
		return err
	}
	loadAppBaselineRows(e.History, apps)

	drifts, err := s.LoadDriftTrackers()
	if err != nil {
		return err
	}
	loadDriftRows(e.History, drifts)
	return nil
}

// fmtSscanInt is a tiny helper around fmt.Sscanf to parse "039" style keys.
// Kept inline so the file stays in package engine without a fmt import bloat.
func fmtSscanInt(s string, dst *int) (int, error) {
	n := 0
	sign := 1
	i := 0
	if i < len(s) && s[i] == '-' {
		sign = -1
		i++
	}
	if i >= len(s) {
		return 0, errInvalidInt
	}
	for ; i < len(s); i++ {
		c := s[i]
		if c < '0' || c > '9' {
			return 0, errInvalidInt
		}
		n = n*10 + int(c-'0')
	}
	*dst = sign * n
	return 1, nil
}

var errInvalidInt = sentinelErr("invalid int")

type sentinelErr string

func (e sentinelErr) Error() string { return string(e) }
