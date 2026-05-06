package apps

import (
	"fmt"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ftahirops/xtop/model"
)

// skipDeepProbes is flipped on by the engine when the host is loaded
// (Guardian level >= 1). When set, Manager.Collect returns the cached
// "tier1" instance metadata only — NO mongosh / mysql / redis-cli
// subprocesses get spawned. Reset to 0 when the host calms down.
//
// This is the difference between xtop being a passive observer and a
// contributor on a stressed host: deep probes spawn external runtimes
// (mongosh = Node.js) that compound load on already-saturated services.
var skipDeepProbes atomic.Bool

// SetSkipDeepProbes is called by the engine once per tick after evaluating
// the resource guard. The apps Manager honors it on the next Collect.
func SetSkipDeepProbes(v bool) { skipDeepProbes.Store(v) }

// scanAllProcesses reads /proc to build a lightweight process list for app detection.
// This is independent of ProcessCollector's top-N filtering, ensuring idle apps are found.
func scanAllProcesses() []model.ProcessMetrics {
	pids, err := procEntries()
	if err != nil {
		return nil
	}
	procs := make([]model.ProcessMetrics, 0, len(pids))
	for _, pid := range pids {
		ppid, comm := readPPIDComm(pid)
		if comm == "" {
			continue
		}
		procs = append(procs, model.ProcessMetrics{
			PID:  pid,
			Comm: comm,
			PPID: ppid,
		})
	}
	return procs
}

const appScanInterval = 30 * time.Second

// AppCloser is an optional interface for app modules that hold resources.
type AppCloser interface {
	Close()
}

// Manager manages all app detection modules.
type Manager struct {
	mu       sync.Mutex
	modules  []AppModule
	detected []detectedEntry // last detection results
	lastScan time.Time
	// tickCount: skip deep metric probes (mongosh, mysql INFO, redis CLI,
	// etc.) on the very first Collect() call so the TUI's first render
	// isn't blocked by 5–10 s of subprocess spawns. After tick 1 the apps
	// scanner runs at its normal cadence with full deep metrics.
	tickCount int
}

type detectedEntry struct {
	module      AppModule
	app         DetectedApp
	prevMetrics map[string]string
	prevTime    time.Time
	prevTicks   uint64
	prevTicksT  time.Time
}

// NewManager creates a new app detection manager.
func NewManager() *Manager {
	return &Manager{}
}

// Register adds an app module.
func (m *Manager) Register(mod AppModule) {
	m.modules = append(m.modules, mod)
}

// Name returns the collector name.
func (m *Manager) Name() string { return "apps" }

// MaxMsPerTick declares a generous budget for the apps Manager because
// each module's deep probe (mongosh, mysql, redis-cli, etc.) spawns a
// subprocess that legitimately takes seconds on a busy host. Without this,
// the registry's default 50 ms budget would mark apps as "over budget"
// after 3 ticks and SKIP IT PERMANENTLY for the rest of the session —
// which is exactly the bug that made the apps panel go empty after ~12 s.
//
// 30 000 ms = 30 s. Long enough for any single tier-2 query to finish.
// If a module repeatedly takes longer it has its own per-module overload
// protection (see mongoModule.skipUntil) — the registry doesn't need to
// disable the whole Manager.
func (m *Manager) MaxMsPerTick() int { return 30000 }

// Collect runs detection (every 30s) and collection (every tick).
//
// CRITICAL: snap.Global.Apps assignment is deferred to the very top of the
// function so it runs LAST (LIFO), even if any code below panics. Without
// this, a panic in one module's Collect() (mongosh hang, slabtop crash, etc.)
// caused safeCollect to swallow the panic but the final assignment line
// never executed → snap.Global.Apps.Instances stayed nil → the TUI's apps
// panel showed "no apps detected" for the rest of the session.
func (m *Manager) Collect(snap *model.Snapshot) error {
	var instances []model.AppInstance
	defer func() {
		// This runs even on panic. Whatever we managed to build before the
		// panic gets surfaced; nothing is silently lost.
		snap.Global.Apps = model.AppMetrics{Instances: instances}
	}()

	m.mu.Lock()
	defer m.mu.Unlock()
	// File-based debug log — TUI hides stderr, so use a file. Activated by
	// XTOP_DEBUG_APPS_TUI=1 (same flag as the UI panel debug).
	dbg := os.Getenv("XTOP_DEBUG_APPS_TUI") == "1"
	if dbg {
		if f, ferr := os.OpenFile("/tmp/xtop_apps_mgr.log",
			os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644); ferr == nil {
			fmt.Fprintf(f, "[%s] Collect ENTER modules=%d detected=%d tickCount=%d\n",
				time.Now().Format("15:04:05.000"),
				len(m.modules), len(m.detected), m.tickCount)
			f.Close()
		}
	}
	defer func() {
		if dbg {
			if f, ferr := os.OpenFile("/tmp/xtop_apps_mgr.log",
				os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644); ferr == nil {
				fmt.Fprintf(f, "[%s] Collect EXIT  detected=%d instances=%d\n",
					time.Now().Format("15:04:05.000"),
					len(m.detected), len(instances))
				f.Close()
			}
		}
	}()

	// Run detection scan periodically using a full /proc scan
	// (snap.Processes is filtered to top N by CPU/IO — idle apps would be missed)
	if time.Since(m.lastScan) >= appScanInterval || m.detected == nil {
		allProcs := scanAllProcesses()
		if dbg {
			if f, ferr := os.OpenFile("/tmp/xtop_apps_mgr.log",
				os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644); ferr == nil {
				mongo := 0
				for _, p := range allProcs {
					if p.Comm == "mongod" || p.Comm == "mongos" {
						mongo++
					}
				}
				fmt.Fprintf(f, "[%s]   detection: scanAllProcesses got %d procs, %d are mongod\n",
					time.Now().Format("15:04:05.000"), len(allProcs), mongo)
				f.Close()
			}
		}
		// Bug fix: a single transient /proc read failure used to wipe
		// m.detected entirely (apps would vanish from the UI for up to 30s
		// until the next scan). Only rebuild detection if the new scan
		// actually found something — otherwise keep the previous list and
		// retry next cycle.
		var fresh []detectedEntry
		for _, mod := range m.modules {
			detApps := mod.Detect(allProcs)
			for _, da := range detApps {
				fresh = append(fresh, detectedEntry{module: mod, app: da})
			}
		}
		if len(fresh) > 0 {
			// Carry over per-entry rate state (prevTicks, prevMetrics) when
			// PID matches so CPU%/counter-rates don't reset to 0 on every
			// rescan. Without this, every 30s the apps panel briefly went
			// to 0% CPU which contributed to "apps disappearing".
			prev := make(map[int]detectedEntry, len(m.detected))
			for _, e := range m.detected {
				prev[e.app.PID] = e
			}
			for i, e := range fresh {
				if old, ok := prev[e.app.PID]; ok {
					fresh[i].prevMetrics = old.prevMetrics
					fresh[i].prevTime = old.prevTime
					fresh[i].prevTicks = old.prevTicks
					fresh[i].prevTicksT = old.prevTicksT
				}
			}
			m.detected = fresh
		}
		// If fresh is empty (e.g. scanAllProcesses returned nil because of
		// a transient /proc walk error), keep m.detected as-is. UI will
		// continue to show the previously-detected apps.
		m.lastScan = time.Now()
	}

	// Collect metrics from all detected apps. On the very first Collect()
	// (tickCount == 0) we skip the per-module .Collect() — that's where
	// each module spawns subprocesses (mongosh, mysql, redis-cli, etc.).
	// On a busy host with 350+ Mongo connections the mongosh round trip
	// alone can be 5+ seconds; multiplied across all modules, the first
	// tick blocks the TUI for ~10 s. We instead surface a lightweight
	// "detected, deep metrics pending" instance and let tick #2 fill in
	// real numbers. The user gets a populated Apps panel ~250 ms after
	// startup instead of ~10 s.
	m.tickCount++
	// First tick: always skip deep (avoids 10 s startup block).
	// Guardian-level skip: also skip whenever the host is stressed —
	// every deep probe spawns a subprocess (mongosh/mysql/redis-cli)
	// that adds load to the very service we're observing. On a busy
	// box that becomes a feedback loop.
	skipDeep := m.tickCount == 1 || skipDeepProbes.Load()

	secrets := loadSecrets()
	now := time.Now()
	for i := range m.detected {
		entry := &m.detected[i]
		// Each iteration is wrapped in its own panic recovery so one bad
		// module (mongosh hang causing a panic, malformed deep metric, etc.)
		// can't drop other detected apps from the list.
		func() {
			defer func() {
				if r := recover(); r != nil {
					instances = append(instances, model.AppInstance{
						ID:          fmt.Sprintf("%s-%d", entry.module.Type(), entry.app.Index),
						AppType:     entry.module.Type(),
						DisplayName: entry.module.Type() + " (panic recovered)",
						PID:         entry.app.PID,
						Port:        entry.app.Port,
						HealthScore: -1,
					})
				}
			}()
			var inst model.AppInstance
			if skipDeep {
				inst = model.AppInstance{
					ID:          fmt.Sprintf("%s-%d", entry.module.Type(), entry.app.Index),
					AppType:     entry.module.Type(),
					DisplayName: entry.module.Type(),
					PID:         entry.app.PID,
					Port:        entry.app.Port,
					Status:      "active",
					HealthScore: 100,
					DeepMetrics: map[string]string{"tier2_skipped": "first-tick-fast-path"},
				}
			} else {
				inst = entry.module.Collect(&entry.app, secrets)
			}
			// Set ID
			if inst.ID == "" {
				inst.ID = fmt.Sprintf("%s-%d", entry.module.Type(), entry.app.Index)
			}
			// Compute delta-based CPU% (real-time, not lifetime average)
			curTicks := readProcCPUTicks(entry.app.PID)
			if entry.prevTicks > 0 && curTicks >= entry.prevTicks {
				dtSec := now.Sub(entry.prevTicksT).Seconds()
				if dtSec > 0 {
					deltaTicks := curTicks - entry.prevTicks
					cpuPct := float64(deltaTicks) / 100.0 / dtSec * 100.0
					inst.CPUPct = cpuPct
				}
			}
			entry.prevTicks = curTicks
			entry.prevTicksT = now
			if entry.prevMetrics != nil && inst.DeepMetrics != nil {
				elapsed := now.Sub(entry.prevTime).Seconds()
				if elapsed > 0 {
					computeCounterRates(inst.DeepMetrics, entry.prevMetrics, elapsed)
				}
			}
			if inst.DeepMetrics != nil {
				cp := make(map[string]string, len(inst.DeepMetrics))
				for k, v := range inst.DeepMetrics {
					cp[k] = v
				}
				entry.prevMetrics = cp
				entry.prevTime = now
			}
			instances = append(instances, inst)
		}()
	}
	// snap.Global.Apps assignment is in the deferred function at the top of
	// Collect — that ensures it runs even if any iteration above panics.
	return nil
}

// counterRateFields lists DeepMetric keys whose delta/sec should be computed.
var counterRateFields = []string{
	"op_insert", "op_query", "op_update", "op_delete", "op_command", "op_getmore",
	"doc_inserted", "doc_returned", "doc_updated", "doc_deleted",
	"net_bytes_in", "net_bytes_out", "net_num_requests",
	"page_faults", "cursor_timed_out", "collection_scans",
	"conn_total_created", "scanned_keys", "scanned_objects",
	"ttl_deleted", "ttl_passes",
	"killed_disconnect", "killed_maxtime", "scan_and_order",
	"total_read_ops", "total_write_ops",
	"cache_reads", "cache_writes",
}

func computeCounterRates(curr, prev map[string]string, elapsed float64) {
	for _, f := range counterRateFields {
		c, _ := strconv.ParseFloat(curr[f], 64)
		p, _ := strconv.ParseFloat(prev[f], 64)
		if c >= p && elapsed > 0 {
			rate := (c - p) / elapsed
			curr[f+"_rate"] = fmt.Sprintf("%.1f", rate)
		}
	}
}

// Close cleans up all modules that hold resources.
func (m *Manager) Close() {
	m.mu.Lock()
	defer m.mu.Unlock()

	for _, mod := range m.modules {
		if c, ok := mod.(AppCloser); ok {
			c.Close()
		}
	}
}
