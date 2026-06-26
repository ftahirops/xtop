package engine

// journal_tier1_test.go — TDD tests for P2.4 Tier-1 journal RCA.
//
// All tests use a stub JournalQueryFn so no live journalctl is required.
// They compile and run on all platforms (the journal package already provides
// a no-op stub for non-Linux via query_stub.go).

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ftahirops/xtop/collector/journal"
	"github.com/ftahirops/xtop/config"
	"github.com/ftahirops/xtop/model"
)

// ─── stub helpers ────────────────────────────────────────────────────────────

// stubQuery returns a JournalQueryFn that records which units it was called
// with and returns crashEntries for the target unit, nil for all others.
func stubQuery(target string, crashEntries []journal.Entry) (JournalQueryFn, *[]string) {
	var mu sync.Mutex
	var called []string
	fn := func(_ context.Context, unit string, _ time.Time) ([]journal.Entry, error) {
		mu.Lock()
		called = append(called, unit)
		mu.Unlock()
		if unit == target {
			return crashEntries, nil
		}
		return nil, nil
	}
	return fn, &called
}

// crashEntries returns two crash-loop journal entries for the given unit.
func crashEntriesFor(unit string) []journal.Entry {
	now := time.Now()
	return []journal.Entry{
		{
			Priority: 3, // ERR
			Message:  "start request repeated too quickly for " + unit,
			Unit:     unit,
			At:       now.Add(-30 * time.Second),
		},
		{
			Priority: 3,
			Message:  "main process exited with result: exit-code",
			Unit:     unit,
			At:       now.Add(-10 * time.Second),
		},
	}
}

// makeEngineWithStub creates a minimal Engine (no real collectors) with the
// injectable stub query function set.
func makeEngineWithStub(fn JournalQueryFn) *Engine {
	e := &Engine{
		History:      NewHistory(10, 3),
		journalQueryFn: fn,
		journalCache:   newJournalTier1Cache(),
		rcaT:           resolveRCAThresholds(config.RCAThresholds{}),
	}
	// Wire the per-engine adaptive DB and causal graph so AnalyzeRCA doesn't
	// nil-deref on e.adaptiveThresholdDB / e.probabilisticCausalGraph.
	e.adaptiveThresholdDB = NewAdaptiveThresholdDB("")
	e.probabilisticCausalGraph = NewProbabilisticCausalGraph()
	e.topologyCorrelator = NewTopologyCorrelator()
	return e
}

// ─── snapshot builder for CPU saturation with a cgroup-supervised service ─────

// cpuSnapWithCgroup returns a CPU-saturated snapshot where the top process
// belongs to a specific cgroup (e.g. "/system.slice/mysql.service").
func cpuSnapWithCgroup(cgroupPath string, appName string) (*model.Snapshot, *model.RateSnapshot) {
	s, r := cpuSaturatedSnap()
	// Add a cgroup rate so the analyzer can identify the service.
	r.CgroupRates = []model.CgroupRate{
		{Path: cgroupPath, Name: appName, CPUPct: 95, ThrottlePct: 30},
	}
	// Set the top process to belong to the cgroup by convention (name match).
	r.ProcessRates[0] = model.ProcessRate{
		PID:    1234,
		Comm:   appName,
		CPUPct: 95.0,
		State:  "R",
		RSS:    512 * 1024 * 1024,
	}
	s.Processes[0] = model.ProcessMetrics{
		PID:   1234,
		Comm:  appName,
		State: "R",
		RSS:   512 * 1024 * 1024,
	}
	return s, r
}

// ─── TestJournalTier1_SuspectUnitQueried ─────────────────────────────────────
//
// Verifies that when a service is the top suspect (highest RCA score > 0),
// its unit IS queried and the resulting Facts appear in the AnalysisResult.

func TestJournalTier1_SuspectUnitQueried(t *testing.T) {
	const targetUnit = "mysql.service"
	entries := crashEntriesFor(targetUnit)
	fn, called := stubQuery(targetUnit, entries)

	e := makeEngineWithStub(fn)
	snap, rates := cpuSnapWithCgroup("/system.slice/mysql.service", "mysql")
	h := newTestHistory()
	feedHistory(h, snap, rates, 10)

	result := AnalyzeRCA(snap, rates, h, nil, e)

	// The stub should have been called with the target unit.
	if len(*called) == 0 {
		t.Fatal("expected journal stub to be called for suspect unit, got no calls")
	}
	found := false
	for _, u := range *called {
		if u == targetUnit {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected stub to be called with %q, got calls: %v", targetUnit, *called)
	}

	// The result must contain a FactKindLogEvidence fact.
	var logFacts []model.Fact
	for _, f := range result.Facts {
		if f.Kind == model.FactKindLogEvidence {
			logFacts = append(logFacts, f)
		}
	}
	if len(logFacts) == 0 {
		t.Errorf("expected at least one FactKindLogEvidence in result.Facts, got none; all facts: %+v", result.Facts)
	}

	// The result must contain a JournalFinding for the "logs" category.
	if len(result.JournalFindings) == 0 {
		t.Error("expected JournalFindings to be populated, got none")
	}
	for _, jf := range result.JournalFindings {
		if jf.Category != "logs" {
			t.Errorf("unexpected JournalFinding category %q (want \"logs\")", jf.Category)
		}
	}

	// The crash_restart_loop signature must appear.
	sigFound := false
	for _, jf := range result.JournalFindings {
		if strings.Contains(jf.Summary, "crash_restart_loop") {
			sigFound = true
			break
		}
	}
	if !sigFound {
		t.Errorf("expected crash_restart_loop signature in JournalFindings, got: %v", result.JournalFindings)
	}
}

// ─── TestJournalTier1_NonSuspectNotQueried ────────────────────────────────────
//
// Verifies that units NOT in the suspect set are never queried (unrelated unit
// absent from the snapshot entirely).

func TestJournalTier1_NonSuspectNotQueried(t *testing.T) {
	const targetUnit = "mysql.service"
	const unrelatedUnit = "unrelated-daemon.service"
	entries := crashEntriesFor(targetUnit)
	fn, called := stubQuery(targetUnit, entries)

	e := makeEngineWithStub(fn)
	snap, rates := cpuSnapWithCgroup("/system.slice/mysql.service", "mysql")
	h := newTestHistory()
	feedHistory(h, snap, rates, 10)

	AnalyzeRCA(snap, rates, h, nil, e)

	for _, u := range *called {
		if u == unrelatedUnit {
			t.Errorf("stub was unexpectedly called for non-suspect unit %q", unrelatedUnit)
		}
	}
}

// ─── TestJournalTier1_ScoreFilterGatesQuery ───────────────────────────────────
//
// Verifies the minSuspectScore gate: a unit that appears in result.RCA with
// Score < minSuspectScore must NEVER be queried, while a unit with a high
// score IS queried. This is tested by driving injectJournalTier1 directly
// with a hand-crafted AnalysisResult so we can set exact scores.

func TestJournalTier1_ScoreFilterGatesQuery(t *testing.T) {
	const highUnit = "highscore-daemon.service"
	const lowUnit = "lowscore-daemon.service"

	var mu sync.Mutex
	queriedUnits := map[string]int{}
	fn := func(_ context.Context, unit string, _ time.Time) ([]journal.Entry, error) {
		mu.Lock()
		queriedUnits[unit]++
		mu.Unlock()
		return nil, nil
	}

	e := makeEngineWithStub(fn)

	// Craft a result with one high-score entry and one zero-score entry.
	result := &model.AnalysisResult{
		RCA: []model.RCAEntry{
			{
				Bottleneck: "CPU Contention",
				Score:      80, // above minSuspectScore → must be queried
				TopCgroup:  "/system.slice/" + highUnit,
			},
			{
				Bottleneck: "Disk I/O",
				Score:      0, // below minSuspectScore → must NOT be queried
				TopCgroup:  "/system.slice/" + lowUnit,
			},
		},
	}

	// Use a minimal snapshot and call injectJournalTier1 directly.
	injectJournalTier1(result, nil, e)

	mu.Lock()
	defer mu.Unlock()

	if queriedUnits[lowUnit] > 0 {
		t.Errorf("low-score unit %q was queried %d time(s); score filter not working",
			lowUnit, queriedUnits[lowUnit])
	}
	if queriedUnits[highUnit] == 0 {
		t.Errorf("high-score unit %q was never queried; expected at least one call", highUnit)
	}
}

// ─── TestJournalTier1_DeadlineExpiry ─────────────────────────────────────────
//
// A blocking stub (that respects ctx cancellation) should be cut off by the
// 1.5 s journalDeadline. The overall tick must return in well under 1.7 s,
// proving the deadline fired rather than the 5 s timer.

func TestJournalTier1_DeadlineExpiry(t *testing.T) {
	fn := func(ctx context.Context, _ string, _ time.Time) ([]journal.Entry, error) {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(5 * time.Second):
			return nil, nil
		}
	}

	e := makeEngineWithStub(fn)
	snap, rates := cpuSnapWithCgroup("/system.slice/mysql.service", "mysql")
	h := newTestHistory()
	feedHistory(h, snap, rates, 10)

	start := time.Now()
	AnalyzeRCA(snap, rates, h, nil, e)
	elapsed := time.Since(start)

	const maxExpected = 1700 * time.Millisecond
	if elapsed > maxExpected {
		t.Errorf("AnalyzeRCA took %v; expected deadline to fire within ~%v", elapsed, maxExpected)
	}
}

// ─── TestJournalTier1_NoSuspects_NoQuery ─────────────────────────────────────
//
// A healthy snapshot has no suspects (all scores = 0). The query func should
// not be called at all.

func TestJournalTier1_NoSuspects_NoQuery(t *testing.T) {
	fn, called := stubQuery("", nil)
	e := makeEngineWithStub(fn)
	snap, rates := healthySnap()
	h := newTestHistory()
	feedHistory(h, snap, rates, 5)

	result := AnalyzeRCA(snap, rates, h, nil, e)

	if len(*called) != 0 {
		t.Errorf("expected no query calls on healthy system, got: %v", *called)
	}
	if len(result.JournalFindings) != 0 {
		t.Errorf("expected no JournalFindings on healthy system, got: %v", result.JournalFindings)
	}
}

// ─── TestJournalTier1_DeadlineHappyPath ──────────────────────────────────────
//
// A stub that returns normally (well within the 1.5s deadline) should produce
// facts without error.

func TestJournalTier1_DeadlineHappyPath(t *testing.T) {
	const targetUnit = "mysql.service"
	entries := crashEntriesFor(targetUnit)
	// Stub with a tiny sleep (5ms) — well within the 1500ms deadline.
	called := 0
	fn := func(_ context.Context, unit string, _ time.Time) ([]journal.Entry, error) {
		called++
		time.Sleep(5 * time.Millisecond)
		if unit == targetUnit {
			return entries, nil
		}
		return nil, nil
	}

	e := makeEngineWithStub(fn)
	snap, rates := cpuSnapWithCgroup("/system.slice/mysql.service", "mysql")
	h := newTestHistory()
	feedHistory(h, snap, rates, 10)

	result := AnalyzeRCA(snap, rates, h, nil, e)

	if called == 0 {
		t.Error("stub was never called")
	}

	// Expect facts from the happy path.
	hasLogFact := false
	for _, f := range result.Facts {
		if f.Kind == model.FactKindLogEvidence {
			hasLogFact = true
			break
		}
	}
	if !hasLogFact {
		t.Error("expected FactKindLogEvidence in result.Facts after happy-path stub")
	}
}

// ─── TestJournalTier1_CachePreventsDuplicateQuery ────────────────────────────
//
// Running AnalyzeRCA twice in a row should only query the journal once for the
// same unit within the 30s TTL window.

func TestJournalTier1_CachePreventsDuplicateQuery(t *testing.T) {
	const targetUnit = "mysql.service"
	entries := crashEntriesFor(targetUnit)
	var mu sync.Mutex
	callCount := 0
	fn := func(_ context.Context, unit string, _ time.Time) ([]journal.Entry, error) {
		mu.Lock()
		callCount++
		mu.Unlock()
		if unit == targetUnit {
			return entries, nil
		}
		return nil, nil
	}

	e := makeEngineWithStub(fn)
	snap, rates := cpuSnapWithCgroup("/system.slice/mysql.service", "mysql")
	h := newTestHistory()
	feedHistory(h, snap, rates, 10)

	// First tick.
	AnalyzeRCA(snap, rates, h, nil, e)
	after1 := func() int { mu.Lock(); defer mu.Unlock(); return callCount }()

	// Second tick — within TTL window, should use cache.
	feedHistory(h, snap, rates, 1)
	AnalyzeRCA(snap, rates, h, nil, e)
	after2 := func() int { mu.Lock(); defer mu.Unlock(); return callCount }()

	if after2 > after1 {
		t.Errorf("expected cache to prevent second query (calls tick1=%d, tick2=%d)", after1, after2)
	}
}

// ─── TestJournalTier1_UnitFromCgroup ─────────────────────────────────────────
//
// unitFromRCAEntry should extract the ".service" component from a cgroup path.

func TestJournalTier1_UnitFromCgroup(t *testing.T) {
	cases := []struct {
		entry model.RCAEntry
		want  string
	}{
		{
			entry: model.RCAEntry{TopCgroup: "/system.slice/mysql.service"},
			want:  "mysql.service",
		},
		{
			entry: model.RCAEntry{TopCgroup: "/system.slice/user-1000.slice"},
			want:  "", // no .service component → fall through
		},
		{
			entry: model.RCAEntry{TopAppName: "PostgreSQL"},
			want:  "postgresql.service",
		},
		{
			entry: model.RCAEntry{TopProcess: "nginx"},
			want:  "nginx.service",
		},
		{
			entry: model.RCAEntry{}, // nothing available
			want:  "",
		},
	}

	for _, tc := range cases {
		got := unitFromRCAEntry(tc.entry)
		// For the slice case: cgroup has no .service, so falls through to
		// TopAppName (empty) then TopProcess (empty) → "".
		if got != tc.want {
			t.Errorf("unitFromRCAEntry(%+v) = %q, want %q", tc.entry, got, tc.want)
		}
	}
}

// ─── TestJournalTier1_NilEngine ──────────────────────────────────────────────
//
// injectJournalTier1 must be a no-op when called with a nil engine.

func TestJournalTier1_NilEngine(t *testing.T) {
	result := &model.AnalysisResult{
		RCA: []model.RCAEntry{{Bottleneck: "CPU Contention", Score: 50, TopProcess: "mysql"}},
	}
	// Must not panic.
	injectJournalTier1(result, nil, nil)
	if len(result.JournalFindings) != 0 {
		t.Error("expected no JournalFindings with nil engine")
	}
}

// ─── TestJournalTier1_RCAEntryFacts ──────────────────────────────────────────
//
// The facts must also appear in the matching RCAEntry.Facts, not just
// result.Facts.

func TestJournalTier1_RCAEntryFacts(t *testing.T) {
	const targetUnit = "mysql.service"
	entries := crashEntriesFor(targetUnit)
	fn, _ := stubQuery(targetUnit, entries)

	e := makeEngineWithStub(fn)
	snap, rates := cpuSnapWithCgroup("/system.slice/mysql.service", "mysql")
	h := newTestHistory()
	feedHistory(h, snap, rates, 10)

	result := AnalyzeRCA(snap, rates, h, nil, e)

	// At least one RCAEntry should have Facts populated.
	anyRCAFact := false
	for _, entry := range result.RCA {
		for _, f := range entry.Facts {
			if f.Kind == model.FactKindLogEvidence {
				anyRCAFact = true
				break
			}
		}
	}
	if !anyRCAFact {
		t.Error("expected FactKindLogEvidence in at least one RCAEntry.Facts")
	}
}

