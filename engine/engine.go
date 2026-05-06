package engine

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strconv"
	"sync"
	"time"

	"github.com/ftahirops/xtop/collector"
	"github.com/ftahirops/xtop/collector/apps"
	cgcollector "github.com/ftahirops/xtop/collector/cgroup"
	bpf "github.com/ftahirops/xtop/collector/ebpf"
	"github.com/ftahirops/xtop/collector/profiler"
	rt "github.com/ftahirops/xtop/collector/runtime"
	"github.com/ftahirops/xtop/model"
)

// Engine orchestrates collection, analysis, and scoring.
type Engine struct {
	registry         *collector.Registry
	cgCollect        *cgcollector.Collector
	History          *History
	Smart            *collector.SMARTCollector
	growthTracker    *MountGrowthTracker
	Sentinel         *bpf.SentinelManager
	Watchdog         *WatchdogTrigger
	SecWatchdog      *bpf.SecWatchdog               // security deep-inspection watchdog
	MultiRes         *MultiResBuffer                // multi-resolution time series (nil if unused)
	SLOPolicies      []SLOPolicy                    // SLO policies from config/flags
	Autopilot        *Autopilot                     // autopilot subsystem (nil if disabled)
	changeDetector   *ChangeDetector                // tracks system changes between ticks
	configDrift      *ConfigDriftDetector           // watches /etc/* config files for drift
	incidentRecorder *IncidentRecorder              // records past RCA incidents for learning
	runbooks         *RunbookLibrary                // operator runbooks matched against live incidents
	usage            *UsageRecorder                 // per-minute utilization rollups for right-sizing
	logTailer        *LogTailer                     // correlates incidents with app log output
	calibrator       *ConfidenceCalibrator          // learns per-bottleneck confidence bias from past outcomes
	traces           *TraceCorrelator               // optional OTel-trace correlation from a JSONL feed
	traceArmer       *TraceArmer                    // Phase 3: arm-once full-reasoning dump (nil = off)
	probeRunner      *ProbeRunner                   // Phase 6: opt-in active probes (XTOP_PROBES=1)
	deepScan         *collector.DeepBigFileScanner  // opt-in full-FS big-file walker
	guard            *ResourceGuard                 // opt-in xtop self-throttle
	intervalSec      int                            // base tick interval (for guard + callers)
	mode             collector.Mode                 // Rich (TUI) or Lean (daemon/agent)
	memReliefQuit    chan struct{}                  // signals the memory-relief goroutine to exit
	tickMu           sync.Mutex                     // serializes Tick() calls to prevent concurrent collection
	peerIncidents    map[string]*model.HostIncident // hostID → latest incident
	peerMu           sync.RWMutex

	// Fleet push client — nil if --fleet-hub not configured
	fleet         *FleetClient
	fleetHostname string
	fleetVersion  string

	// Phase 2: resource-guarded deep app diagnostics throttling
	lastDeepAnalysis time.Time // last time deep app diagnostics ran
}

// NewEngine creates a new engine with all collectors registered.
// intervalSec is the collection interval used to calibrate alert thresholds.
func NewEngine(historySize, intervalSec int) *Engine {
	return NewEngineMode(historySize, intervalSec, collector.ModeRich)
}

// NewEngineMode constructs an engine in the requested collector mode.
// Lean mode (used by daemon + fleet-hub agents) registers a small fixed
// set of essential collectors and skips the heavy ones — apps deep
// scanning, profiler audits, the cgroup tree walk, the eBPF sentinel
// program, all of the runtime detectors. The RCA engine downstream
// degrades gracefully on missing signals.
//
// On top of the mode's baseline list, ~/.xtop/modules.json (managed by
// the v0.45 module toggle subcommand + UI) further filters which Optional
// and Heavy modules actually run. Essential collectors always run; the
// module config can never disable them.
func NewEngineMode(historySize, intervalSec int, mode collector.Mode) *Engine {
	reg := collector.NewRegistryMode(mode)
	moduleCfg := collector.LoadModuleConfig()

	// In lean mode, we also clamp the history ring to a much smaller
	// buffer. The hub stores the long history; the agent only needs
	// enough to compute rates between two consecutive ticks plus a
	// short look-back for trend detection.
	if mode == collector.ModeLean && historySize > 30 {
		historySize = 30
	}

	var cgc *cgcollector.Collector
	var sentinel *bpf.SentinelManager
	var rtm *rt.Manager
	var appm *apps.Manager

	enabled := collector.ResolveEnabledModules(moduleCfg)
	addIfEnabled := func(name string, c collector.Collector) {
		if enabled[name] {
			reg.Add(c)
		}
	}

	if mode == collector.ModeRich {
		// cgroup tree walker — Standard tier; user can disable on hosts
		// where the cgroup tree is huge (kubernetes nodes) and they don't
		// need the per-pod breakdown locally.
		if enabled["cgroup"] {
			cgc = cgcollector.NewCollector()
			reg.Add(cgc)
		}

		// eBPF sentinel — Optional tier; opt-in. Off by default in
		// Standard profile; on in SRE / Investigation.
		if enabled["ebpf-sentinel"] {
			sentinel = bpf.NewSentinelManager()
			reg.Add(sentinel)
		}

		// Runtime detection modules — Standard tier. Runs after
		// ProcessCollector so snap.Processes is available.
		if enabled["runtime"] {
			rtm = rt.NewManager()
			rtm.Register(rt.NewDotNetModule())
			rtm.Register(rt.NewJVMModule())
			rtm.Register(rt.NewPythonModule())
			rtm.Register(rt.NewNodeModule())
			rtm.Register(rt.NewGoModule())
			reg.Add(rtm)
		}

		// App diagnostics — Standard tier. Auto-detect running apps and
		// surface basic health. Heavy deep-metric probes (mongosh, mysql
		// INFO, etc.) are gated separately by the resource guard.
		if enabled["apps"] {
			appm = apps.NewManager()
			appm.Register(apps.NewNginxModule())
			appm.Register(apps.NewApacheModule())
			appm.Register(apps.NewHAProxyModule())
			appm.Register(apps.NewCaddyModule())
			appm.Register(apps.NewTraefikModule())
			appm.Register(apps.NewMySQLModule())
			appm.Register(apps.NewPostgreSQLModule())
			appm.Register(apps.NewMongoModule())
			appm.Register(apps.NewRedisModule())
			appm.Register(apps.NewMemcachedModule())
			appm.Register(apps.NewESModule())
			appm.Register(apps.NewLogstashModule())
			appm.Register(apps.NewKibanaModule())
			appm.Register(apps.NewRabbitMQModule())
			appm.Register(apps.NewKafkaModule())
			appm.Register(apps.NewDockerModule())
			appm.Register(apps.NewPHPFPMModule())
			appm.Register(apps.NewPleskModule())
			reg.Add(appm)
		}

		// System Profiler — Heavy tier. Off by default in Standard;
		// enabled in SRE Workstation + Investigation profiles.
		if enabled["profiler"] {
			reg.Add(profiler.NewProfilerCollector())
		}
	}
	// Silence linter for unused helper when no module needed it on this path.
	_ = addIfEnabled

	e := &Engine{
		registry:         reg,
		cgCollect:        cgc, // nil in lean mode — call sites guard
		History:          NewHistory(historySize, intervalSec),
		Smart:            collector.NewSMARTCollector(5 * time.Minute),
		growthTracker:    NewMountGrowthTracker(),
		Sentinel:         sentinel, // nil in lean — eBPF probes never attached
		Watchdog:         NewWatchdogTrigger(),
		SecWatchdog:      bpf.NewSecWatchdog(bpf.DetectPrimaryIface()),
		changeDetector:   NewChangeDetector(),
		configDrift:      NewConfigDriftDetector(),
		incidentRecorder: NewIncidentRecorder(),
		runbooks:         NewRunbookLibrary(),
		usage:            NewUsageRecorder(),
		logTailer:        NewLogTailer(),
		calibrator:       NewConfidenceCalibrator(),
		traces:           NewTraceCorrelator(),
		deepScan:         buildDeepScanner(),
		peerIncidents:    make(map[string]*model.HostIncident),
		intervalSec:      intervalSec,
		mode:             mode,
		memReliefQuit:    make(chan struct{}),
	}
	// Eagerly construct the resource guard at engine creation so the very
	// first Tick's pre-collect advice (using runtime.NumCPU as the cpu
	// count) can throttle expensive collectors. Without this, the guard
	// is nil for the first tick and apps Manager runs deep probes against
	// a possibly-already-thrashing host before we have a chance to skip.
	{
		base := intervalSec
		if base <= 0 {
			base = 3
		}
		nc := runtime.NumCPU()
		if nc < 1 {
			nc = 1
		}
		e.guard = NewResourceGuard(nc, base)
	}

	// Initialize advanced RCA components (package-level singletons)
	dataDir := "/var/lib/xtop"
	if home, err := os.UserHomeDir(); err == nil {
		dataDir = filepath.Join(home, ".xtop")
	}
	adaptiveThresholdDB = NewAdaptiveThresholdDB(dataDir)
	probabilisticCausalGraph = NewProbabilisticCausalGraph()
	topologyCorrelator = NewTopologyCorrelator()

	// FastPulse: sub-second PSI sampler that refines per-evidence
	// SustainedForSec. Off by default in lean (agent) mode to keep the
	// import graph tight; on in rich mode unless explicitly disabled.
	if mode != collector.ModeLean && os.Getenv("XTOP_FASTPULSE") != "0" {
		e.History.FastPulse = NewFastPulse(500)
		e.History.FastPulse.Start()
	}

	// TraceArmer: Phase 3 verification tool. Reads XTOP_TRACE_NEXT /
	// XTOP_TRACE_ON_CONFIRMED at startup; can also be armed by the CLI.
	e.traceArmer = NewTraceArmer("")

	// ProbeRunner: Phase 6 active investigation. Disabled by default; enable
	// with XTOP_PROBES=1. Hard-budgeted (5s deadline, 64KB output cap, 30s
	// rate limit per class, 3 concurrent max).
	e.probeRunner = NewProbeRunner()
	// Self-relief loop — every 5 minutes, return idle pages to the OS so
	// long-running daemons don't hold onto a high RSS forever after a
	// transient allocation spike. Cheap (microseconds) but Go's runtime
	// won't do this on its own without a memstats hint.
	if mode == collector.ModeLean {
		go e.memoryReliefLoop()
	}
	return e
}

// guardOrCreate lazily constructs the ResourceGuard on first Tick once
// snapshots tell us the actual NumCPUs. Separate from NewEngine because
// the initial snapshot (for CPU count) isn't available at construction.
func (e *Engine) guardOrCreate(numCPUs int) *ResourceGuard {
	if e.guard != nil {
		return e.guard
	}
	base := e.intervalSec
	if base <= 0 {
		base = 3
	}
	e.guard = NewResourceGuard(numCPUs, base)
	return e.guard
}

// memoryReliefLoop runs in lean mode and enforces a tiered memory budget
// (Guardian v2). Three escalating responses:
//
//	Heap < soft       — silent. Heap and OS pages are doing fine.
//	Heap >= soft      — log warning, force runtime.GC + debug.FreeOSMemory.
//	                    This is a HINT to the runtime: "give back what you
//	                    can." Cheap, bounded, no functional change.
//	Heap >= hard      — flush in-process caches (process history, runtime
//	                    detection, log tailer, trace correlator), then GC.
//	                    If still over hard after recovery: self-restart
//	                    (exit 2 → systemd Restart=on-failure brings us
//	                    back clean), rate-limited to 3/hour.
//
// Frequency: every 60 s. Cost: <1 ms per call.
func (e *Engine) memoryReliefLoop() {
	soft := guardianSoftHeapMB(e.mode)
	hard := guardianHardHeapMB(e.mode)
	auditPath := guardianAuditPath()
	t := time.NewTicker(60 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			e.enforceMemoryBudget(soft, hard, auditPath)
		case <-e.memReliefQuit:
			return
		}
	}
}

func (e *Engine) enforceMemoryBudget(soft, hard float64, auditPath string) {
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	heapMB := float64(ms.HeapInuse) / 1024 / 1024

	// Below soft → just gently nudge the runtime every cycle. Cheap.
	if heapMB < soft {
		runtime.GC()
		debug.FreeOSMemory()
		return
	}

	// At soft → log + GC. The first time we cross soft, write an audit
	// line so the operator has a paper trail.
	guardianAudit(auditPath, fmt.Sprintf(
		"heap=%.0fMB > soft=%.0fMB · goroutines=%d gc-runs=%d · GC+FreeOSMemory",
		heapMB, soft, runtime.NumGoroutine(), ms.NumGC))
	log.Printf("[guardian] heap %.0fMB > %.0fMB soft (gc + free)",
		heapMB, soft)
	runtime.GC()
	debug.FreeOSMemory()
	if heapMB < hard {
		return
	}

	// At hard → flush caches aggressively, then re-measure.
	guardianAudit(auditPath, fmt.Sprintf(
		"heap=%.0fMB >= hard=%.0fMB · flushing in-process caches",
		heapMB, hard))
	log.Printf("[guardian] heap %.0fMB >= %.0fMB HARD; flushing caches",
		heapMB, hard)
	e.flushCaches()
	runtime.GC()
	debug.FreeOSMemory()
	runtime.ReadMemStats(&ms)
	postFlushMB := float64(ms.HeapInuse) / 1024 / 1024
	guardianAudit(auditPath, fmt.Sprintf(
		"after-flush heap=%.0fMB", postFlushMB))

	// Still over hard after recovery → self-preserving restart, but only
	// when systemd is supervising us so the unit gets relaunched clean.
	if postFlushMB >= hard {
		if !guardianRestartAllowed(auditPath) {
			log.Printf("[guardian] heap still %.0fMB >= hard, but restart rate-limit hit — staying alive degraded",
				postFlushMB)
			return
		}
		if !systemdSupervised() {
			log.Printf("[guardian] heap still %.0fMB >= hard, but no systemd supervisor — staying alive",
				postFlushMB)
			return
		}
		log.Printf("[guardian] self-preserving exit: heap %.0fMB >= %.0fMB hard after flush; systemd will relaunch",
			postFlushMB, hard)
		guardianAudit(auditPath, fmt.Sprintf(
			"SELF-RESTART · heap=%.0fMB >= hard=%.0fMB after cache flush", postFlushMB, hard))
		os.Exit(2)
	}
}

// flushCaches drops in-process caches the engine accumulates over time.
// Each component's "flush" method is best-effort — if a component isn't
// initialized for this mode, its check is a no-op.
func (e *Engine) flushCaches() {
	if e.History != nil {
		e.History.FlushOlderThan(2)
	}
	if e.logTailer != nil {
		e.logTailer.Flush()
	}
	if e.traces != nil {
		e.traces.Flush()
	}
	// Process history rings already self-bound; nothing larger to drop.
}

// systemdSupervised heuristically detects whether the process is running
// under a systemd unit (so restart will be honored). Two signals: parent
// PID is 1, AND the INVOCATION_ID env var is set (systemd injects this
// for every unit). Both signals together rule out plain init systems and
// shell-launched daemons where exit 2 just dies silently.
func systemdSupervised() bool {
	if os.Getppid() != 1 {
		return false
	}
	return os.Getenv("INVOCATION_ID") != ""
}

// Tick performs one collection + analysis cycle.
// Returns the snapshot, computed rates, and full analysis result.
// Serialized via tickMu to prevent concurrent collection when ticks overlap.
func (e *Engine) Tick() (*model.Snapshot, *model.RateSnapshot, *model.AnalysisResult) {
	// Guard advice is function-scoped because multiple code paths (log
	// tailer inside the "prev != nil" block, deep-scan merge outside it)
	// all need to consult it. Zero-value is "no skips" — matches the
	// behavior when the guard is disabled.
	var skipAdvice GuardAdvice
	e.tickMu.Lock()
	defer e.tickMu.Unlock()

	// Apply guard advice based on the PREVIOUS tick's host signals — this
	// gives us a chance to throttle BEFORE running any expensive collectors.
	// One-tick lag is acceptable for safety: if the box was loaded last tick,
	// odds are it still is. Plus: even if advice is "no skip", we read it
	// via /proc/loadavg directly in Advise, which is already populated.
	if e.guard != nil && e.guard.Enabled() {
		var loadRatio, hostBusy float64
		if prevSnap := e.History.Latest(); prevSnap != nil {
			loadRatio = prevSnap.Global.CPU.LoadAvg.Load1
		} else {
			// First tick: read load directly from /proc/loadavg so we don't
			// run unguarded even on the very first collection cycle.
			if data, err := os.ReadFile("/proc/loadavg"); err == nil {
				_, _ = fmt.Sscanf(string(data), "%f", &loadRatio)
			}
		}
		if r := e.History.GetRate(e.History.Len() - 1); r != nil {
			hostBusy = r.CPUBusyPct
		}
		advice := e.guard.Advise(loadRatio, hostBusy)
		// Flip every package-level skip flag from one place. Each downstream
		// collector reads its own flag at the top of Collect — when the
		// host calms down, flags clear and they resume normal cadence.
		apps.SetSkipDeepProbes(advice.SkipAppDeep)
		cgcollector.SetSkipTreeWalk(advice.Level >= 1)
		rt.SetSkipDetection(advice.Level >= 1)
		skipAdvice = advice
	}

	snap := &model.Snapshot{
		Timestamp: time.Now(),
	}

	// Collect all metrics
	if errs := e.registry.CollectAll(snap); len(errs) > 0 {
		for _, err := range errs {
			if err != nil {
				snap.Errors = append(snap.Errors, err.Error())
			}
		}
	}

	// Collect security watchdog probe data into security metrics
	if e.SecWatchdog != nil {
		e.SecWatchdog.Collect(&snap.Global.Security)
	}

	// Phase 2: resource-guarded deep app diagnostics (30s throttle).
	// Only runs when the guard says the system can afford it.
	if e.guard != nil && e.guard.AllowDeepAppAnalysis(e.lastDeepAnalysis) {
		e.runDeepAppDiagnostics(snap)
		e.lastDeepAnalysis = time.Now()
	}

	// Get previous snapshot for rate calculations
	prev := e.History.Latest()

	// Store in history
	e.History.Push(*snap)

	// Compute rates and run analysis
	var rates *model.RateSnapshot
	var result *model.AnalysisResult

	if prev != nil {
		r := ComputeRates(prev, snap)
		e.growthTracker.Smooth(r.MountRates)
		rates = &r
		e.History.PushRate(r)
		e.History.ProcessHistory.Record(rates)

		// Get peer incidents for cross-host correlation
		peers := e.GetPeerIncidents()
		result = AnalyzeRCA(snap, rates, e.History, peers)

		// Change detection: track new/stopped processes and recent package changes
		if e.changeDetector != nil {
			result.Changes = e.changeDetector.DetectChanges(snap)
		}
		// Config drift: walk the watchlist of /etc/* configs; merge any newly-
		// detected modifications into Changes so they appear in Recent Activity.
		if e.configDrift != nil {
			result.Changes = append(result.Changes, e.configDrift.Tick()...)

			// If an incident is active, look back 30 minutes for config drift
			// events. A config change that landed shortly before degradation
			// is the single highest-yield piece of RCA context we can surface.
			if result != nil && result.Health > model.HealthOK {
				recent := e.configDrift.RecentWithin(time.Now(), 30*time.Minute)
				if len(recent) > 0 && result.Narrative != nil {
					hint := formatConfigDriftHint(recent)
					if hint != "" {
						result.Narrative.Evidence = append(
							[]string{hint},
							result.Narrative.Evidence...,
						)
					}
				}
			}
		}

		// Confidence calibration: detect incident completions to record outcomes,
		// and apply the learned per-bottleneck bias to the live result. The order
		// matters — we look at what the recorder had as "active" before we pass
		// in the new result.
		if e.calibrator != nil && e.incidentRecorder != nil {
			if prev := e.incidentRecorder.Active(); prev != nil &&
				prev.State == IncidentConfirmed &&
				(result == nil || result.Health == model.HealthOK) {
				duration := time.Since(prev.StartedAt)
				e.calibrator.RecordOutcome(prev.Bottleneck, prev.PeakScore, duration)
			}
			if result != nil && result.PrimaryBottleneck != "" {
				result.Confidence = e.calibrator.ApplyTo(
					result.PrimaryBottleneck, result.Confidence)
			}
		}

		// Incident recording: track active incidents, persist completed ones,
		// and enrich current narrative with history context (recurrence info).
		if e.incidentRecorder != nil {
			active := e.incidentRecorder.Record(result)

			// Echo lifecycle into result so downstream consumers (fleet client,
			// trace dump) see it without needing the recorder reference.
			if active != nil {
				result.IncidentState = string(active.State)
				result.IncidentConfirmedAt = active.ConfirmedAt
			}

			// Phase 4: per-app baselines. Frozen while a Confirmed incident
			// is active so we don't memorize the bad state as "normal".
			frozen := active != nil && active.State == IncidentConfirmed
			result.AppAnomalies = UpdateAppBaselines(snap, rates, e.History, frozen)

			// Per-app RCA rule engine — pure data crunch over already-collected
			// DeepMetrics, no new probes. Skipped when guard >= 1 (deep metrics
			// are stale anyway).
			result.AppRCA = EvaluateAppRCA(snap, skipAdvice.Level)

			// Phase 5: multi-scale drift detection (boiling-frog).
			result.Degradations = append(result.Degradations,
				UpdateDrift(result, e.History, frozen)...)
			result.Degradations = append(result.Degradations,
				HoltExhaustionEvidence(result, e.History)...)

			// Phase 6: active probes — only at Suspected→Confirmed transition.
			// We detect this by checking the current incident state plus a
			// "have we run yet" guard via ConfirmedAt being recent.
			if e.probeRunner != nil && e.probeRunner.Enabled() &&
				active != nil && active.State == IncidentConfirmed &&
				time.Since(active.ConfirmedAt) < 10*time.Second {
				if probes := e.probeRunner.MaybeRun(result); len(probes) > 0 {
					result.ProbeResults = probes
				}
			}

			// Phase 3 trace dump: runs after lifecycle is up to date so the
			// dump reflects the post-Record state (Suspected vs Confirmed).
			if e.traceArmer != nil && e.traceArmer.Mode() != TraceModeOff {
				e.traceArmer.MaybeDump(snap, rates, result, e.History, active)
			}
			_ = active
			if result.Health > model.HealthOK {
				ctx := e.incidentRecorder.HistoryContext(result)
				if ctx != "" {
					result.HistoryContext = ctx
					if result.Narrative != nil {
						result.Narrative.Evidence = append([]string{ctx}, result.Narrative.Evidence...)
					}
				}
				// Structured diff against prior similar incidents — lets the UI
				// show "score delta / new signals / same-hour pattern" without
				// re-deriving everything from the narrative string.
				if diff := e.incidentRecorder.DiffAgainstHistory(result); diff != nil {
					result.IncidentDiff = diff
					if diff.DriftHint != "" && result.Narrative != nil {
						result.Narrative.Evidence = append(
							[]string{"vs history: " + diff.DriftHint},
							result.Narrative.Evidence...,
						)
					}
				}
			}
		}

		// Runbook matching — operator-authored remediation docs loaded from
		// ~/.xtop/runbooks/*.md. The engine attaches only the lightweight
		// reference; UIs pull the full body via RunbookLibrary.Lookup.
		if e.runbooks != nil && result != nil && result.Health > model.HealthOK {
			if rb := e.runbooks.Match(result); rb != nil {
				result.Runbook = rb
				if result.Narrative != nil {
					result.Narrative.Evidence = append(
						[]string{"RUNBOOK: " + rb.Name + "  (" + rb.Path + ")"},
						result.Narrative.Evidence...,
					)
				}
			}
		}

		// ── Resource guard: decide what to skip this tick ─────────────
		// The guard reads host load + host busy% + our own CPU and picks a
		// level 0-3. Each level enables a progressively larger skip-set so
		// xtop stays small on a stressed box. Guard is opt-in — when off,
		// `skipAdvice` is the zero-value (all false) and nothing changes.
		if result != nil && rates != nil {
			g := e.guardOrCreate(snap.Global.CPU.NumCPUs)
			skipAdvice = g.Advise(snap.Global.CPU.LoadAvg.Load1, rates.CPUBusyPct)
			if g.Enabled() {
				result.Guard = buildGuardStatus(skipAdvice)
			}
		}

		// OTel trace correlation — optional, silent when no feed file present.
		// When operators have wired an OTel collector to emit summaries, this
		// surfaces the slow/errored spans overlapping the incident window.
		if !skipAdvice.SkipTraces && e.traces != nil && result != nil && result.Health > model.HealthOK {
			if samples := e.traces.Observe(result); len(samples) > 0 {
				result.TraceSamples = samples
				if result.Narrative != nil {
					top := samples[0]
					hint := "TRACE: "
					if top.StatusCode == "ERROR" {
						hint += "ERROR "
					}
					if top.Service != "" {
						hint += top.Service + " "
					}
					if top.Operation != "" {
						hint += top.Operation + " "
					}
					hint += "took " + fmtMs(top.DurationMs)
					if len(samples) > 1 {
						hint += " (+" + itoa(len(samples)-1) + " more)"
					}
					result.Narrative.Evidence = append(
						[]string{hint}, result.Narrative.Evidence...)
				}
			}
		}

		// Log correlation — cross-reference the culprit app's own log output.
		// Rate-limited internally (once every 10 s) + bounded per-tick budget,
		// so this is a safe call on every active-incident tick.
		if !skipAdvice.SkipLogTailer && e.logTailer != nil && result != nil && result.Health > model.HealthOK {
			if excerpts := e.logTailer.Observe(result); len(excerpts) > 0 {
				result.LogExcerpts = excerpts
				if result.Narrative != nil {
					hint := formatLogExcerptHint(excerpts)
					if hint != "" {
						result.Narrative.Evidence = append(
							[]string{hint},
							result.Narrative.Evidence...,
						)
					}
				}
			}
		}

		// Watchdog auto-trigger: check if RCA warrants domain-specific probes
		if domain := e.Watchdog.Check(result); domain != "" {
			result.Watchdog = model.WatchdogState{Active: true, Domain: domain}
		}

		// Security watchdog: trigger deep inspection probes from evidence
		if e.SecWatchdog != nil {
			var allEvidence []model.Evidence
			for _, entry := range result.RCA {
				allEvidence = append(allEvidence, entry.EvidenceV2...)
			}
			e.SecWatchdog.TriggerFromEvidence(allEvidence)
		}

		// Trigger disk scanners when filesystem pressure detected
		worst := WorstDiskGuardState(r.MountRates)
		if worst == "WARN" || worst == "CRIT" {
			e.registry.TriggerByName("bigfiles")
			e.registry.TriggerByName("deleted_open")
		}

		// Push to multi-resolution buffer if enabled
		if e.MultiRes != nil {
			memPct := float64(0)
			if snap.Global.Memory.Total > 0 {
				memPct = float64(snap.Global.Memory.Total-snap.Global.Memory.Available) / float64(snap.Global.Memory.Total) * 100
			}
			e.MultiRes.PushHiRes(TimeSeries1s{
				Timestamp: snap.Timestamp,
				Health:    int(result.Health),
				Score:     result.PrimaryScore,
				CPUBusy:   rates.CPUBusyPct,
				MemPct:    memPct,
				IOPSI:     snap.Global.PSI.IO.Full.Avg10,
				TopPID:    result.PrimaryPID,
				TopComm:   primaryDisplayName(result),
			})
		}
	}

	// Enrich the Apps page with the per-app "resource share" SRE view.
	// Done once here so every consumer (TUI, fleet push, postmortem) sees
	// the same ranked + capacity-share + bottleneck-contribution fields.
	if result != nil && rates != nil {
		scores := ComputeImpactScores(snap, rates, result)
		EnrichAppResourceShare(snap, rates, result, scores)
	}

	// Publish the current worst-disk IO% to the atomic the deep scanner
	// reads for adaptive pacing. Also merge scanner findings into the
	// snapshot's BigFiles list so the DiskGuard page shows them.
	if rates != nil {
		var worst float64
		for _, d := range rates.DiskRates {
			if d.UtilPct > worst {
				worst = d.UtilPct
			}
		}
		setCurrentIOPct(worst)
	}
	if e.deepScan != nil && !skipAdvice.SkipDeepScan {
		mergeDeepScanResults(snap, e.deepScan)
	}

	// Fleet push: non-blocking, only after the first tick has rates+result
	if e.fleet != nil && result != nil {
		e.fleet.Observe(snap, result, e.fleetHostname, e.fleetVersion)
	}

	// Usage recording: per-tick aggregate that the per-minute rollup absorbs.
	// We only record when we have rates (i.e. after the second tick), since
	// CPU% requires a delta.
	if e.usage != nil && rates != nil {
		memPct := 0.0
		if snap.Global.Memory.Total > 0 {
			memPct = float64(snap.Global.Memory.Total-snap.Global.Memory.Available) /
				float64(snap.Global.Memory.Total) * 100
		}
		ioWorst := 0.0
		for _, d := range rates.DiskRates {
			if d.UtilPct > ioWorst {
				ioWorst = d.UtilPct
			}
		}
		e.usage.Observe(
			rates.CPUBusyPct, memPct, ioWorst,
			snap.Global.CPU.LoadAvg.Load1,
			snap.Global.CPU.NumCPUs,
			snap.Global.Memory.Total,
		)
	}

	return snap, rates, result
}

// Guard exposes the live ResourceGuard so the status line and tests can
// inspect it. Nil until the first Tick constructs it (needs CPU count).
func (e *Engine) Guard() *ResourceGuard { return e.guard }

// SetNoHysteresis disables the sustained-threshold alert state machine.
// When true, health level reflects the instantaneous score without
// requiring consecutive ticks. Use this for one-shot CLI/API mode.
func (e *Engine) SetNoHysteresis(v bool) {
	if e.History != nil {
		e.History.SetNoHysteresis(v)
	}
}

// Calibrator exposes the confidence calibration table so the UI / post-mortem
// can show "this bottleneck has precision X over N past incidents." Returns
// nil on engines that were constructed without calibration (tests).
func (e *Engine) Calibrator() *ConfidenceCalibrator { return e.calibrator }

// Runbooks exposes the in-memory runbook library so the UI can fetch the
// full markdown body for a matched runbook (which isn't carried on the
// AnalysisResult to keep it small).
func (e *Engine) Runbooks() *RunbookLibrary { return e.runbooks }

// AttachFleetClient wires a fleet push client into the engine. Called once at
// startup by cmd/root.go when --fleet-hub is configured. Hostname and version
// are captured once since they never change at runtime.
func (e *Engine) AttachFleetClient(fc *FleetClient, version string) {
	e.fleet = fc
	e.fleetVersion = version
	h, _ := os.Hostname()
	e.fleetHostname = h
}

// Close shuts down all engine resources (sentinel probes, security watchdog, collector connections).
// Cleanup runs in parallel with a 2-second hard timeout so quit is never slow.
func (e *Engine) Close() {
	// Stop the memory-relief goroutine cleanly so it doesn't outlive the
	// engine in tests or in a graceful daemon shutdown.
	if e.memReliefQuit != nil {
		select {
		case <-e.memReliefQuit:
		default:
			close(e.memReliefQuit)
		}
	}
	// Stop FastPulse if running so its goroutine doesn't outlive us.
	if e.History != nil && e.History.FastPulse != nil {
		e.History.FastPulse.Stop()
	}
	// Drop per-history entries from package-level Welford stores so a
	// process that creates and discards engines (tests, one-shot CLI)
	// doesn't accumulate map entries forever.
	forgetAppBaselines(e.History)
	forgetDriftStore(e.History)
	done := make(chan struct{})
	go func() {
		var wg sync.WaitGroup
		if e.Sentinel != nil {
			wg.Add(1)
			go func() { defer wg.Done(); e.Sentinel.Close() }()
		}
		if e.SecWatchdog != nil {
			wg.Add(1)
			go func() { defer wg.Done(); e.SecWatchdog.Close() }()
		}
		if e.registry != nil {
			wg.Add(1)
			go func() { defer wg.Done(); e.registry.CloseAll() }()
		}
		if e.fleet != nil {
			wg.Add(1)
			go func() { defer wg.Done(); e.fleet.Close() }()
		}
		if e.deepScan != nil {
			wg.Add(1)
			go func() { defer wg.Done(); e.deepScan.Stop() }()
		}
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		// Hard timeout — kernel will clean up BPF resources when process exits
	}
}

// runDeepAppDiagnostics runs expensive per-app deep metric collection.
// This is called from Tick() only when the ResourceGuard allows it (max
// once every 30 seconds, and only when system load is calm).
func (e *Engine) runDeepAppDiagnostics(snap *model.Snapshot) {
	if snap == nil || len(snap.Global.Apps.Instances) == 0 {
		return
	}
	for i := range snap.Global.Apps.Instances {
		app := &snap.Global.Apps.Instances[i]
		if app.DeepMetrics == nil {
			app.DeepMetrics = make(map[string]string)
		}
		switch app.AppType {
		case "mysql", "mariadb":
			// These are already collected by Apps.Manager on its own cadence;
			// we just mark that deep metrics are fresh.
			app.DeepMetrics["_deep_collected_at"] = strconv.FormatInt(time.Now().Unix(), 10)
		case "redis":
			app.DeepMetrics["_deep_collected_at"] = strconv.FormatInt(time.Now().Unix(), 10)
		case "mongodb":
			app.DeepMetrics["_deep_collected_at"] = strconv.FormatInt(time.Now().Unix(), 10)
		case "elasticsearch":
			app.DeepMetrics["_deep_collected_at"] = strconv.FormatInt(time.Now().Unix(), 10)
		}
	}
}

// primaryDisplayName returns the best display name for the primary culprit.
func primaryDisplayName(result *model.AnalysisResult) string {
	if result.PrimaryAppName != "" {
		return result.PrimaryAppName
	}
	return result.PrimaryProcess
}

// ReportPeerIncident records the latest incident from a peer host for cross-host correlation.
func (e *Engine) ReportPeerIncident(hostID string, inc *model.HostIncident) {
	e.peerMu.Lock()
	defer e.peerMu.Unlock()
	e.peerIncidents[hostID] = inc
}

// GetPeerIncidents returns a snapshot of all known peer host incidents.
func (e *Engine) GetPeerIncidents() map[string]*model.HostIncident {
	e.peerMu.RLock()
	defer e.peerMu.RUnlock()
	out := make(map[string]*model.HostIncident, len(e.peerIncidents))
	for k, v := range e.peerIncidents {
		out[k] = v
	}
	return out
}
