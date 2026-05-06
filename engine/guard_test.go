package engine

import (
	"testing"
)

// newGuardForTest builds a guard with fixed thresholds and the env-read
// disabled, so tests are deterministic regardless of CI environment.
func newGuardForTest(numCPUs int) *ResourceGuard {
	g := &ResourceGuard{
		enabled:         true,
		ownCPUBudgetPct: 2.0,
		loadWarnRatio:   1.5,
		loadCritRatio:   3.0,
		hostBusyWarnPct: 75,
		hostBusyCritPct: 92,
		baseIntervalSec: 3,
		maxIntervalSec:  6,
		numCPUs:         numCPUs,
	}
	g.intervalSec.Store(3)
	// Stub /proc/self/stat reader so tests don't depend on the runtime's
	// real CPU usage — we drive ownCPU via the classify path directly.
	return g
}

func TestGuard_DisabledReturnsLevel0(t *testing.T) {
	g := newGuardForTest(4)
	g.enabled = false
	adv := g.Advise(100, 99) // extreme signals
	if adv.Level != 0 {
		t.Errorf("disabled guard should always report level 0, got %d", adv.Level)
	}
	if adv.SkipLogTailer || adv.SkipTraces || adv.SkipDeepScan {
		t.Errorf("disabled guard should set no skip flags: %+v", adv)
	}
}

func TestGuard_ClassifyMatrix(t *testing.T) {
	g := newGuardForTest(4)
	cases := []struct {
		name      string
		loadRatio float64
		busy      float64
		own       float64
		want      int
	}{
		{"idle host",       0.2, 5,   0,   0},
		{"mild load",       1.6, 40,  0,   1}, // loadRatio > warn
		{"busy cpu",        0.5, 80,  0,   1}, // busy > warn
		{"heavy load",      3.5, 60,  0,   2}, // loadRatio > crit
		{"saturated cpu",   0.4, 95,  0,   2},
		{"extreme load",    5.0, 90,  0,   3},
		{"own runaway",     0.3, 30,  7,   3}, // own cpu 3x budget
		{"own over budget", 0.3, 30,  2.5, 1}, // own > budget (1x)
		{"own 2x",          0.2, 20,  4.1, 2},
	}
	for _, tc := range cases {
		got := g.classify(tc.loadRatio, tc.busy, tc.own)
		if got != tc.want {
			t.Errorf("%s: classify(%.2f,%.1f,%.1f) = %d, want %d",
				tc.name, tc.loadRatio, tc.busy, tc.own, got, tc.want)
		}
	}
}

func TestGuard_EscalatesAfter3Ticks(t *testing.T) {
	g := newGuardForTest(4)
	// Load ratio 4.0 (> crit 3.0) → wants level 2. First 2 ticks stay at 0.
	for i := 1; i <= 2; i++ {
		adv := g.Advise(16, 60) // load=16, numCPUs=4 → ratio=4.0
		if adv.Level != 0 {
			t.Errorf("tick %d: level = %d, want 0 (before escalation)", i, adv.Level)
		}
	}
	// Third tick pops.
	adv := g.Advise(16, 60)
	if adv.Level != 2 {
		t.Errorf("tick 3: level = %d, want 2 (escalated)", adv.Level)
	}
}

func TestGuard_DeEscalatesAfter10CleanTicks(t *testing.T) {
	g := newGuardForTest(4)
	// Push up to level 2.
	for i := 0; i < 3; i++ {
		g.Advise(16, 60)
	}
	if g.level.Load() != 2 {
		t.Fatalf("precondition: level should be 2, got %d", g.level.Load())
	}
	// Clean signals — first 9 should stay at 2.
	for i := 1; i <= 9; i++ {
		g.Advise(0.5, 5) // tiny load + tiny busy
		if g.level.Load() != 2 {
			t.Errorf("clean tick %d: level dropped too fast to %d", i, g.level.Load())
		}
	}
	// 10th clean tick → back to 0.
	g.Advise(0.5, 5)
	if g.level.Load() != 0 {
		t.Errorf("after 10 clean ticks: level = %d, want 0", g.level.Load())
	}
}

func TestGuard_IntervalExtendsOnSevereLoad(t *testing.T) {
	g := newGuardForTest(4)
	// Drive to level 3 (requires ratio > crit*1.5 = 4.5).
	for i := 0; i < 3; i++ {
		g.Advise(25, 95) // ratio 6.25
	}
	adv := g.Advise(25, 95)
	if adv.Level != 3 {
		t.Fatalf("precondition: level should be 3, got %d", adv.Level)
	}
	// At L3 the guard caps the tick interval at maxIntervalSec, which is
	// 4× base in v0.46.3+ (was 2×). The aggressive default is deliberate
	// — on a box thrashing at load 80, 1.5× isn't meaningful relief; 4×
	// is (12 s vs the default 3 s).
	if adv.IntervalSec != 12 {
		t.Errorf("level 3 interval = %d, want 4×base=12", adv.IntervalSec)
	}
}

func TestBuildGuardStatus_ListsSkippedFeatures(t *testing.T) {
	adv := GuardAdvice{
		Level:         2,
		IntervalSec:   5,
		Reason:        "host busy 95%",
		SkipAppDeep:   true,
		SkipLogTailer: true,
		SkipTraces:    true,
		SkipWatchdog:  true,
	}
	s := buildGuardStatus(adv)
	if s.Level != 2 {
		t.Errorf("level = %d, want 2", s.Level)
	}
	wantSkip := []string{"app-deep-metrics", "log-tailer", "otel-traces", "watchdog-probes"}
	if len(s.Skipped) != len(wantSkip) {
		t.Fatalf("skipped count = %d, want %d: %v", len(s.Skipped), len(wantSkip), s.Skipped)
	}
	for i := range wantSkip {
		if s.Skipped[i] != wantSkip[i] {
			t.Errorf("Skipped[%d] = %q, want %q", i, s.Skipped[i], wantSkip[i])
		}
	}
}

func TestSplitFields_HandlesStatFormat(t *testing.T) {
	// /proc/self/stat post-comm contains many fields separated by single
	// spaces. Our splitFields must return them in the same order, skipping
	// leading whitespace.
	in := " S 1 100 100 0 -1 4194304 123 0 0 0 456 789 0 0 20 0 1"
	fields := splitFields(in)
	if len(fields) < 13 {
		t.Fatalf("got %d fields, want >=13", len(fields))
	}
	if fields[11] != "456" || fields[12] != "789" {
		t.Errorf("utime/stime at expected offsets: %q/%q", fields[11], fields[12])
	}
}
