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

// TestTier2ScanAllModeSelectsAllUnits: verifies the real selectTrackedUnits
// helper (called by discoverServices) correctly distinguishes "all" from
// "critical" mode. This exercises the production code path — if the all-mode
// branch logic is wrong the assertions below will fail.
func TestTier2ScanAllModeSelectsAllUnits(t *testing.T) {
	// Simulate what discoverServices builds from systemctl output.
	allServices := []string{"nginx.service", "mysql.service", "custom-app.service"}
	// criticalSvcs is the knownUnits ∩ allServices (custom-app is not a known unit).
	criticalSvcs := []string{"nginx.service", "mysql.service"}

	// --- "all" mode: every discovered .service unit must be returned ---
	gotAll := selectTrackedUnits("all", allServices, criticalSvcs)
	if len(gotAll) != len(allServices) {
		t.Errorf("all mode: expected %d units, got %d: %v", len(allServices), len(gotAll), gotAll)
	}
	allSet := make(map[string]bool, len(gotAll))
	for _, u := range gotAll {
		allSet[u] = true
	}
	for _, u := range allServices {
		if !allSet[u] {
			t.Errorf("all mode: expected %q in result, not found", u)
		}
	}

	// --- "critical" mode: only knownUnits overlap is returned ---
	gotCrit := selectTrackedUnits("critical", allServices, criticalSvcs)
	if len(gotCrit) != len(criticalSvcs) {
		t.Errorf("critical mode: expected %d units, got %d: %v", len(criticalSvcs), len(gotCrit), gotCrit)
	}
	// custom-app.service must not appear in critical mode.
	for _, u := range gotCrit {
		if u == "custom-app.service" {
			t.Error("critical mode: custom-app.service should not be tracked")
		}
	}
	// nginx and mysql must be present.
	critSet := make(map[string]bool, len(gotCrit))
	for _, u := range gotCrit {
		critSet[u] = true
	}
	for _, want := range []string{"nginx.service", "mysql.service"} {
		if !critSet[want] {
			t.Errorf("critical mode: expected %q tracked, not found", want)
		}
	}

	// "all" must select strictly more units than "critical".
	if len(gotAll) <= len(gotCrit) {
		t.Errorf("all mode should track more units than critical (%d vs %d)", len(gotAll), len(gotCrit))
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
