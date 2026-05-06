package engine

import (
	"path/filepath"
	"testing"

	"github.com/ftahirops/xtop/store"
)

// TestBaselinePersist_Roundtrip: in-memory state persisted to SQLite then
// loaded back into a fresh History reproduces the same Welford values.
func TestBaselinePersist_Roundtrip(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")
	s, err := store.Open(dbPath)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer s.Close()
	if err := s.Migrate(); err != nil {
		t.Fatalf("migrate: %v", err)
	}

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
