package engine

import (
	"fmt"
	"os"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/ftahirops/xtop/model"
)

// ResourceGuard throttles xtop's own resource usage when the host is busy.
// The goal: never make a bad day worse by having the observability tool
// compete with the workload it's supposed to be observing.
//
// Three signals drive the decision:
//
//  1. Host load ratio — LoadAvg1 / NumCPUs. > 1.5 is "stressed", > 3.0 is
//     "thrashing". These thresholds are per-core so a 32-core box doesn't
//     trip just because its load is 12.
//  2. Host CPU-busy% — rolled-up from rates. Useful when LoadAvg1 lies
//     (e.g. many D-state procs pile up load without using CPU).
//  3. xtop's own CPU% — parsed from /proc/self/stat between ticks. When
//     WE are the cause of the pain, we self-throttle more aggressively.
//
// Four levels of response:
//
//   Level 0 (normal):      everything runs at full cadence
//   Level 1 (caution):     skip app deep-metric probes + log tailer
//   Level 2 (degraded):    also skip trace correlator + eBPF watchdog triggers
//   Level 3 (minimal):     also skip deep scan; interval up to 2× base
//
// Hysteresis: we escalate after 3 consecutive ticks above threshold, and
// de-escalate only after 10 consecutive ticks below. Prevents flapping
// when load is noisy.
//
// Opt-in: must be enabled via XTOP_GUARD=1 (or explicit Enable()). Default
// off so existing deployments see no behavior change.
type ResourceGuard struct {
	// Config (set at construction, read-only thereafter)
	enabled          bool
	ownCPUBudgetPct  float64 // we consider ourselves "greedy" above this
	loadWarnRatio    float64 // load/NumCPUs threshold for level 1
	loadCritRatio    float64 // load/NumCPUs threshold for level 2
	hostBusyWarnPct  float64 // host CPU-busy threshold for level 1
	hostBusyCritPct  float64 // host CPU-busy threshold for level 2
	baseIntervalSec  int
	maxIntervalSec   int
	numCPUs          int

	// Live state
	level          atomic.Int32 // 0..3
	highTicks      atomic.Int32 // consecutive ticks above threshold (for escalation)
	lowTicks       atomic.Int32 // consecutive ticks clean (for de-escalation)
	intervalSec    atomic.Int32 // currently-recommended tick interval

	// Self-measurement
	lastSelfTickAt    time.Time
	lastSelfCPUTicks  uint64
	lastOwnCPUPct     float64
}

// GuardAdvice is the per-tick output consumed by Engine.Tick. Everything
// the engine needs to decide what to skip lives on this struct.
type GuardAdvice struct {
	Level             int     // 0..3
	Reason            string  // short, human-readable
	IntervalSec       int     // suggested tick interval
	SkipAppDeep       bool    // skip expensive app deep-metric probes
	SkipLogTailer     bool    // skip app-log correlation (file IO)
	SkipTraces        bool    // skip OTel trace correlator
	SkipWatchdog      bool    // skip auto-triggering eBPF watchdogs
	SkipDeepScan      bool    // pause the full-FS polite scanner
	OwnCPUPct         float64 // our own CPU%, for display
	HostLoadRatio     float64 // load/NumCPUs, for display
}

// NewResourceGuard constructs a guard with sensible defaults, then overlays
// any environment variables. Returns a disabled guard when XTOP_GUARD is
// anything other than "1" — the caller can still use Advice(), but the
// returned level will always be 0.
func NewResourceGuard(numCPUs, baseIntervalSec int) *ResourceGuard {
	if numCPUs <= 0 {
		numCPUs = 1
	}
	g := &ResourceGuard{
		enabled:         os.Getenv("XTOP_GUARD") == "1",
		ownCPUBudgetPct: 2.0,  // self-throttle when we exceed 2% of one core
		loadWarnRatio:   1.5,  // load > 1.5 × NumCPUs → caution
		loadCritRatio:   3.0,  // load > 3.0 × NumCPUs → degraded
		hostBusyWarnPct: 75,
		hostBusyCritPct: 92,
		baseIntervalSec: baseIntervalSec,
		maxIntervalSec:  baseIntervalSec * 2,
		numCPUs:         numCPUs,
	}
	overlayEnvFloat("XTOP_GUARD_OWN_CPU_PCT", &g.ownCPUBudgetPct)
	overlayEnvFloat("XTOP_GUARD_LOAD_WARN", &g.loadWarnRatio)
	overlayEnvFloat("XTOP_GUARD_LOAD_CRIT", &g.loadCritRatio)
	overlayEnvFloat("XTOP_GUARD_HOST_BUSY_WARN_PCT", &g.hostBusyWarnPct)
	overlayEnvFloat("XTOP_GUARD_HOST_BUSY_CRIT_PCT", &g.hostBusyCritPct)
	if v, err := strconv.Atoi(os.Getenv("XTOP_GUARD_MAX_INTERVAL_SEC")); err == nil && v > 0 {
		g.maxIntervalSec = v
	}
	g.intervalSec.Store(int32(baseIntervalSec))
	return g
}

// Enabled reports whether the guard is active. When false, Advise returns
// a level-0 advice with no skips so callers can uniformly consult it.
func (g *ResourceGuard) Enabled() bool { return g.enabled }

// Advise is called once per tick. It reads the host signals plus xtop's
// own CPU consumption and returns what to skip this cycle. The returned
// IntervalSec is authoritative — callers should sleep that many seconds
// until the next Tick.
func (g *ResourceGuard) Advise(loadAvg1, hostBusyPct float64) GuardAdvice {
	ownCPU := g.measureOwnCPU()

	if !g.enabled {
		return GuardAdvice{
			Level:       0,
			IntervalSec: g.baseIntervalSec,
			OwnCPUPct:   ownCPU,
			HostLoadRatio: loadAvg1 / float64(g.numCPUs),
		}
	}

	loadRatio := loadAvg1 / float64(g.numCPUs)
	wantLevel := g.classify(loadRatio, hostBusyPct, ownCPU)

	cur := int(g.level.Load())
	// Hysteresis: escalate fast (3 ticks), de-escalate slow (10 ticks).
	if wantLevel > cur {
		h := int(g.highTicks.Add(1))
		g.lowTicks.Store(0)
		if h >= 3 {
			g.level.Store(int32(wantLevel))
			g.highTicks.Store(0)
			cur = wantLevel
		}
	} else if wantLevel < cur {
		l := int(g.lowTicks.Add(1))
		g.highTicks.Store(0)
		if l >= 10 {
			g.level.Store(int32(wantLevel))
			g.lowTicks.Store(0)
			cur = wantLevel
		}
	} else {
		g.highTicks.Store(0)
		g.lowTicks.Store(0)
	}

	// Interval: base at L0/L1, extend at L2, double at L3.
	interval := g.baseIntervalSec
	switch cur {
	case 2:
		interval = g.baseIntervalSec * 3 / 2
	case 3:
		interval = g.maxIntervalSec
	}
	g.intervalSec.Store(int32(interval))

	return GuardAdvice{
		Level:         cur,
		Reason:        reasonFor(cur, loadRatio, hostBusyPct, ownCPU, g),
		IntervalSec:   interval,
		SkipAppDeep:   cur >= 1,
		SkipLogTailer: cur >= 1,
		SkipTraces:    cur >= 2,
		SkipWatchdog:  cur >= 2,
		SkipDeepScan:  cur >= 3,
		OwnCPUPct:     ownCPU,
		HostLoadRatio: loadRatio,
	}
}

// classify picks the desired level for the current signals. Each rung
// requires EITHER the host signal OR our-own-cpu signal to be exceeded —
// so a thrashing host escalates even if xtop is tiny, and a runaway xtop
// escalates even if the host is idle (self-policing).
func (g *ResourceGuard) classify(loadRatio, hostBusyPct, ownCPU float64) int {
	// Level 3: extreme host pressure OR we're clearly the problem.
	if loadRatio > g.loadCritRatio*1.5 || hostBusyPct > g.hostBusyCritPct+3 ||
		ownCPU > g.ownCPUBudgetPct*3 {
		return 3
	}
	// Level 2: sustained degraded host or we're 2× our budget.
	if loadRatio > g.loadCritRatio || hostBusyPct > g.hostBusyCritPct ||
		ownCPU > g.ownCPUBudgetPct*2 {
		return 2
	}
	// Level 1: mild pressure — start skipping expensive non-essential work.
	if loadRatio > g.loadWarnRatio || hostBusyPct > g.hostBusyWarnPct ||
		ownCPU > g.ownCPUBudgetPct {
		return 1
	}
	return 0
}

// buildGuardStatus is the one place that maps a GuardAdvice into the
// model.GuardStatus the engine attaches to AnalysisResult. Lives with the
// guard so the skipped-list stays in sync with the Skip* fields above.
func buildGuardStatus(a GuardAdvice) *model.GuardStatus {
	s := &model.GuardStatus{
		Level:         a.Level,
		Reason:        a.Reason,
		IntervalSec:   a.IntervalSec,
		OwnCPUPct:     a.OwnCPUPct,
		HostLoadRatio: a.HostLoadRatio,
	}
	if a.SkipAppDeep {
		s.Skipped = append(s.Skipped, "app-deep-metrics")
	}
	if a.SkipLogTailer {
		s.Skipped = append(s.Skipped, "log-tailer")
	}
	if a.SkipTraces {
		s.Skipped = append(s.Skipped, "otel-traces")
	}
	if a.SkipWatchdog {
		s.Skipped = append(s.Skipped, "watchdog-probes")
	}
	if a.SkipDeepScan {
		s.Skipped = append(s.Skipped, "deep-scan")
	}
	return s
}

// CurrentIntervalSec exposes the live interval for daemons/tickers that
// need to sleep between ticks. Readers atomic so no lock needed.
func (g *ResourceGuard) CurrentIntervalSec() int {
	if g == nil || !g.enabled {
		return 0
	}
	return int(g.intervalSec.Load())
}

// ── Self-measurement ────────────────────────────────────────────────────────

// measureOwnCPU parses /proc/self/stat to compute our own CPU% since the
// last call. Returns 0 on the first call (no baseline yet).
func (g *ResourceGuard) measureOwnCPU() float64 {
	now := time.Now()
	ticks, err := readSelfCPUTicks()
	if err != nil {
		return 0
	}
	if g.lastSelfTickAt.IsZero() {
		g.lastSelfTickAt = now
		g.lastSelfCPUTicks = ticks
		return 0
	}
	dt := now.Sub(g.lastSelfTickAt).Seconds()
	dTicks := ticks - g.lastSelfCPUTicks
	g.lastSelfTickAt = now
	g.lastSelfCPUTicks = ticks
	if dt < 0.01 {
		return g.lastOwnCPUPct
	}
	// CLK_TCK is almost universally 100 on Linux.
	pct := (float64(dTicks) / 100.0) / dt * 100.0
	g.lastOwnCPUPct = pct
	return pct
}

// readSelfCPUTicks returns utime+stime from /proc/self/stat in clock ticks.
// Broken out so tests can replace it with a stub.
var readSelfCPUTicks = func() (uint64, error) {
	b, err := os.ReadFile("/proc/self/stat")
	if err != nil {
		return 0, err
	}
	// /proc/self/stat format has a (comm) field that can contain spaces, so
	// we find the closing paren and parse from there.
	s := string(b)
	end := -1
	for i := len(s) - 1; i >= 0; i-- {
		if s[i] == ')' {
			end = i
			break
		}
	}
	if end < 0 {
		return 0, fmt.Errorf("malformed /proc/self/stat")
	}
	fields := splitFields(s[end+1:])
	// Fields after the closing paren are 1-indexed from state. utime is
	// field 14 overall → offset 11 after-paren; stime is 15 → offset 12.
	if len(fields) < 13 {
		return 0, fmt.Errorf("short /proc/self/stat: %d fields", len(fields))
	}
	utime, err1 := strconv.ParseUint(fields[11], 10, 64)
	stime, err2 := strconv.ParseUint(fields[12], 10, 64)
	if err1 != nil {
		return 0, err1
	}
	if err2 != nil {
		return 0, err2
	}
	return utime + stime, nil
}

// splitFields is strings.Fields inlined to avoid pulling strings into a
// file that already has a lot of imports. Whitespace-only split.
func splitFields(s string) []string {
	out := make([]string, 0, 20)
	i := 0
	for i < len(s) {
		for i < len(s) && (s[i] == ' ' || s[i] == '\t' || s[i] == '\n') {
			i++
		}
		if i >= len(s) {
			break
		}
		start := i
		for i < len(s) && s[i] != ' ' && s[i] != '\t' && s[i] != '\n' {
			i++
		}
		out = append(out, s[start:i])
	}
	return out
}

// ── Helpers ──────────────────────────────────────────────────────────────────

func overlayEnvFloat(name string, dst *float64) {
	if v, err := strconv.ParseFloat(os.Getenv(name), 64); err == nil && v > 0 {
		*dst = v
	}
}

func reasonFor(level int, loadRatio, hostBusy, ownCPU float64, g *ResourceGuard) string {
	if level == 0 {
		return ""
	}
	// Prefer the signal that's actually over threshold in the summary so
	// the UI can show "why am I throttled".
	switch {
	case ownCPU > g.ownCPUBudgetPct*2:
		return fmt.Sprintf("self-throttle: xtop CPU %.1f%% > %.1f%% budget", ownCPU, g.ownCPUBudgetPct)
	case loadRatio > g.loadCritRatio:
		return fmt.Sprintf("host load %.1fx CPUs (%.1f crit)", loadRatio, g.loadCritRatio)
	case hostBusy > g.hostBusyCritPct:
		return fmt.Sprintf("host busy %.0f%% > %.0f%% crit", hostBusy, g.hostBusyCritPct)
	case loadRatio > g.loadWarnRatio:
		return fmt.Sprintf("host load %.1fx CPUs (%.1f warn)", loadRatio, g.loadWarnRatio)
	case hostBusy > g.hostBusyWarnPct:
		return fmt.Sprintf("host busy %.0f%% > %.0f%% warn", hostBusy, g.hostBusyWarnPct)
	case ownCPU > g.ownCPUBudgetPct:
		return fmt.Sprintf("xtop CPU %.1f%% > %.1f%% budget", ownCPU, g.ownCPUBudgetPct)
	}
	return ""
}
