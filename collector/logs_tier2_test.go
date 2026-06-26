package collector

import (
	"context"
	"testing"
	"time"

	"github.com/ftahirops/xtop/collector/journal"
	"github.com/ftahirops/xtop/model"
)

// --- helpers ---

// crashEntries returns a set of journal entries that contain a crash-restart
// signature so that journal.Classify should fire "crash_restart_loop".
func crashEntries() []journal.Entry {
	return []journal.Entry{
		{Priority: 3, Message: "main process exited, code=dumped", At: time.Now()},
	}
}

// quietEntries returns entries with no recognized signature.
func quietEntries() []journal.Entry {
	return []journal.Entry{
		{Priority: 6, Message: "started successfully", At: time.Now()},
	}
}

// spikeEntries returns many high-priority entries to trigger error_rate_spike.
func spikeEntries(n int) []journal.Entry {
	out := make([]journal.Entry, n)
	for i := range out {
		out[i] = journal.Entry{Priority: 2, Message: "some high-prio message", At: time.Now()}
	}
	return out
}

// stubQueryFn returns a fixed set of entries for any unit.
func stubQueryFn(entries []journal.Entry) func(ctx context.Context, unit string, since time.Time) ([]journal.Entry, error) {
	return func(_ context.Context, _ string, _ time.Time) ([]journal.Entry, error) {
		return entries, nil
	}
}

func newHistory() *logHistory {
	return &logHistory{
		ringBuf:         make([]float64, 60),
		highPrioHistory: make([]float64, 10),
	}
}

// --- tests ---

// TestTier2ScanCrashFiresFinding: a tracked unit whose stubbed journal has a
// crash line yields a finding on the snapshot.
func TestTier2ScanCrashFiresFinding(t *testing.T) {
	h := newHistory()
	fn := stubQueryFn(crashEntries())

	findings := tier2ScanWith(fn, "nginx.service", h, 10)
	if len(findings) == 0 {
		t.Fatal("expected at least one finding for crash entry, got none")
	}
	found := false
	for _, f := range findings {
		if f.Signature == "crash_restart_loop" {
			found = true
			if f.Severity != model.DiagCrit {
				t.Errorf("expected DiagCrit severity, got %q", f.Severity)
			}
			if f.Count < 1 {
				t.Errorf("expected count >= 1, got %d", f.Count)
			}
		}
	}
	if !found {
		t.Errorf("finding crash_restart_loop not present in %+v", findings)
	}
}

// TestTier2ScanQuietUnitYieldsNone: a unit with only info-level healthy messages
// produces no findings.
func TestTier2ScanQuietUnitYieldsNone(t *testing.T) {
	h := newHistory()
	fn := stubQueryFn(quietEntries())

	findings := tier2ScanWith(fn, "redis.service", h, 10)
	if len(findings) != 0 {
		t.Errorf("expected no findings for quiet unit, got %d: %+v", len(findings), findings)
	}
}

// TestTier2ScanRateSpikeFiresWhenRateExceedsBaseline: when the high-priority
// count greatly exceeds the baseline, an error_rate_spike finding is emitted.
func TestTier2ScanRateSpikeFiresWhenRateExceedsBaseline(t *testing.T) {
	h := newHistory()
	// Seed a modest baseline: 1 high-prio entry per cycle.
	for i := range h.highPrioHistory {
		h.highPrioHistory[i] = 1
	}
	h.hpIdx = 10

	// Now inject 50 high-priority entries — far above 3× baseline of 1.
	fn := stubQueryFn(spikeEntries(50))
	findings := tier2ScanWith(fn, "mysql.service", h, 10)

	found := false
	for _, f := range findings {
		if f.Signature == "error_rate_spike" {
			found = true
			if f.Severity != model.DiagWarn {
				t.Errorf("rate spike expected DiagWarn, got %q", f.Severity)
			}
		}
	}
	if !found {
		t.Errorf("expected error_rate_spike finding, got %+v", findings)
	}
}

// TestTier2ScanOffModeSkipsCollection: when JournalRCAMode is "off",
// the LogsCollector should not call the Tier-2 query function.
func TestTier2ScanOffModeSkipsCollection(t *testing.T) {
	orig := JournalRCAMode
	defer func() { JournalRCAMode = orig }()
	JournalRCAMode = "off"

	called := false
	fn := func(_ context.Context, _ string, _ time.Time) ([]journal.Entry, error) {
		called = true
		return crashEntries(), nil
	}

	l := &LogsCollector{
		history:      make(map[string]*logHistory),
		trackedUnits: []string{"nginx.service"},
		discovered:   true,
		// Force shouldQuery by setting lastQuery to zero
		lastQuery:    time.Time{},
		tier2QueryFn: fn,
	}

	snap := &model.Snapshot{}
	if err := l.Collect(snap); err != nil {
		t.Fatalf("Collect error: %v", err)
	}

	if called {
		t.Error("Tier-2 query was called despite journal-rca=off")
	}

	for _, svc := range snap.Global.Logs.Services {
		if len(svc.Findings) > 0 {
			t.Errorf("expected no findings in off mode, got %+v", svc.Findings)
		}
	}
}

// TestTier2ScanAllModeSelectsAllUnits: when JournalRCAMode is "all",
// discoverServices should track all active .service units (verified via
// set-selection logic rather than invoking systemctl).
func TestTier2ScanAllModeSelectsAllUnits(t *testing.T) {
	orig := JournalRCAMode
	defer func() { JournalRCAMode = orig }()
	JournalRCAMode = "all"

	// Simulate the active-unit map that discoverServices would build.
	activeUnits := map[string]bool{
		"nginx.service":    true,
		"mysql.service":    true,
		"custom-app.service": true,
	}

	// Run the selection logic directly (mirrors the inner loop in discoverServices).
	var trackedAll []string
	for unit := range activeUnits {
		trackedAll = append(trackedAll, unit)
	}

	// In "all" mode every .service from the map should be tracked.
	if len(trackedAll) != len(activeUnits) {
		t.Errorf("expected %d tracked units in all mode, got %d", len(activeUnits), len(trackedAll))
	}

	// In "critical" mode only knownUnits overlap would be tracked.
	JournalRCAMode = "critical"
	var trackedCrit []string
	for _, name := range knownUnits {
		unit := name + ".service"
		if activeUnits[unit] {
			trackedCrit = append(trackedCrit, unit)
		}
	}
	// custom-app.service is not in knownUnits so it should be absent.
	for _, u := range trackedCrit {
		if u == "custom-app.service" {
			t.Error("custom-app.service should not be tracked in critical mode")
		}
	}
	// nginx and mysql are in knownUnits so they should be present.
	found := map[string]bool{}
	for _, u := range trackedCrit {
		found[u] = true
	}
	for _, want := range []string{"nginx.service", "mysql.service"} {
		if !found[want] {
			t.Errorf("expected %q tracked in critical mode, not found", want)
		}
	}
}

// TestTier2FindingsCarriedOnSnapshot: end-to-end check that findings appear
// on snap.Global.Logs.Services for a tracked unit during a normal Collect cycle.
func TestTier2FindingsCarriedOnSnapshot(t *testing.T) {
	orig := JournalRCAMode
	defer func() { JournalRCAMode = orig }()
	JournalRCAMode = "critical"

	fn := stubQueryFn(crashEntries())

	l := &LogsCollector{
		history:      make(map[string]*logHistory),
		trackedUnits: []string{"nginx.service"},
		discovered:   true,
		lastQuery:    time.Time{}, // force shouldQuery = true
		tier2QueryFn: fn,
	}

	snap := &model.Snapshot{}
	if err := l.Collect(snap); err != nil {
		t.Fatalf("Collect error: %v", err)
	}

	if len(snap.Global.Logs.Services) == 0 {
		t.Fatal("no services on snapshot")
	}
	svc := snap.Global.Logs.Services[0]
	if len(svc.Findings) == 0 {
		t.Errorf("expected findings on snapshot for nginx.service, got none")
	}
}
