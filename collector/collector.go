package collector

import (
	"fmt"
	"os"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/ftahirops/xtop/model"
)

// Collector is the interface for all metric collectors.
type Collector interface {
	Name() string
	Collect(snap *model.Snapshot) error
}

// Triggerable is a collector that supports on-demand rescans.
type Triggerable interface {
	Trigger()
}

// CollectorCost holds per-collector cost tracking for the Guardian. Updated
// in-place by Registry.CollectAll on every tick. Read-only from outside the
// registry. EWMA values use alpha=0.2 (last 5 ticks contribute most weight).
//
// All durations are wall-clock; AllocBytes is the heap allocation delta the
// collector caused this tick (read via runtime.MemStats around the call).
type CollectorCost struct {
	Name            string
	MeanMs          float64 // EWMA wall-time
	P95Ms           float64 // rolling 95th percentile (last 100 samples)
	LastMs          float64 // last tick's measurement
	MeanAllocKB     float64 // EWMA heap-alloc delta in KB
	OverBudgetTicks int     // consecutive ticks exceeding MaxMs
	Skipped         bool    // guardian has disabled this collector
	SkippedReason   string  // human-readable reason for the disable
	MaxMs           float64 // budget — 0 means use registry default
	LastRun         time.Time
	samples         []float64 // ring buffer for p95 (cap 100)
	samplePos       int
}

// CollectorWithBudget is implemented by collectors that have a known cost
// envelope. Collectors that satisfy this interface get their declared
// MaxMsPerTick honored by the guardian; everything else uses the global
// default (50 ms per tick) which can be overridden via XTOP_COLLECTOR_MAX_MS.
type CollectorWithBudget interface {
	MaxMsPerTick() int
}

// Registry holds all registered collectors and tracks per-collector cost.
type Registry struct {
	collectors []Collector
	mu         sync.RWMutex // protects costs map
	costs      map[string]*CollectorCost
}

// TriggerByName triggers a rescan on a named collector if it supports Triggerable.
func (r *Registry) TriggerByName(name string) {
	for _, c := range r.collectors {
		if c.Name() == name {
			if t, ok := c.(Triggerable); ok {
				t.Trigger()
			}
		}
	}
}

// Mode controls the collector allowlist at engine construction time.
//
//	Rich — TUI / interactive use. All 21 built-in collectors registered,
//	       apps detection runs every 30s, app deep-metric probes on,
//	       bigfiles/security/profiler enabled. Default. Expensive.
//	Lean — daemon/fleet-agent use. Only 9 essential collectors, no app
//	       deep-metric shell-outs, no profiler, no deep fileless/deleted-
//	       open scans. Designed to sit around 30–50 MB RSS and <0.3% of
//	       one core on a Docker host.
//
// Switch modes at startup based on whether the operator is using the TUI
// or the headless --daemon --fleet-hub path. Both share the same RCA
// engine — lean simply feeds it less signal, the right tradeoff when the
// hub does the heavy analytics.
type Mode int

const (
	ModeRich Mode = iota
	ModeLean
)

// NewRegistry returns a Rich registry. Default, preserves legacy behavior
// for all existing callers (TUI, tests, subcommands).
func NewRegistry() *Registry { return NewRegistryMode(ModeRich) }

// NewRegistryMode lets callers request the lean collector set used by
// long-running fleet agents. Called from engine.NewEngineMode.
func NewRegistryMode(mode Mode) *Registry {
	if mode == ModeLean {
		return &Registry{collectors: leanCollectors()}
	}
	return &Registry{collectors: richCollectors()}
}

func richCollectors() []Collector {
	return []Collector{
		&SysInfoCollector{},
		&PSICollector{},
		&CPUCollector{},
		&MemoryCollector{},
		&DiskCollector{},
		&NetworkCollector{},
		&SocketCollector{},
		&SoftIRQCollector{},
		&SysctlCollector{},
		&FilesystemCollector{},
		&DeletedOpenCollector{MaxFiles: 20},
		&FilelessCollector{},
		&BigFileCollector{MaxFiles: 10, MinSize: 50 * 1024 * 1024, firstRun: true},
		&ProcessCollector{MaxProcs: 50},
		&IdentityCollector{},
		&SecurityCollector{},
		&LogsCollector{},
		&HealthCheckCollector{},
		&DiagCollector{interval: 15 * time.Second, firstTick: true},
		&ProxmoxCollector{},
		&GPUCollector{},
	}
}

// leanCollectors keeps only what the RCA engine + fleet push actually
// need to reason about the host. Missing signal = missing evidence-check
// = that check doesn't fire, which is correct graceful degradation.
func leanCollectors() []Collector {
	return []Collector{
		&SysInfoCollector{},             // sysid, read once
		&PSICollector{},                 // /proc/pressure/* — essential for RCA
		&CPUCollector{},                 // /proc/stat + loadavg
		&MemoryCollector{},              // /proc/meminfo
		&DiskCollector{},                // /proc/diskstats
		&NetworkCollector{},             // basic iface counters
		&FilesystemCollector{},          // statfs per mount
		&ProcessCollector{MaxProcs: 30}, // tight cap; hub has full history
		&IdentityCollector{},            // cached
		// Deliberately excluded in lean: socket/softirq/sysctl/security/
		// logs/healthcheck/diag/proxmox/gpu/deletedopen/fileless/bigfile.
		// The RCA engine treats missing signals as "no evidence for that
		// check" — graceful degradation rather than breakage.
	}
}

// Add registers an additional collector.
func (r *Registry) Add(c Collector) {
	r.collectors = append(r.collectors, c)
}

// CollectAll runs all collectors, populating the snapshot.
// Each collector is wrapped in a panic recovery to prevent one
// failing collector from crashing the entire collection cycle.
//
// Collectors run concurrently in two phases:
//
//	Phase 1 — all collectors except security (they write to disjoint
//	snapshot fields and have no interdependencies).
//	Phase 2 — security collector, which reads snap.Processes set by
//	ProcessCollector in phase 1.
func (r *Registry) CollectAll(snap *model.Snapshot) []error {
	var errs []error
	health := &model.CollectionHealth{Total: len(r.collectors)}
	var totalLatencyMs float64

	// Allocate the cost map lazily so older callers that built a Registry
	// via struct literal still work.
	if r.costs == nil {
		r.mu.Lock()
		if r.costs == nil {
			r.costs = make(map[string]*CollectorCost)
		}
		r.mu.Unlock()
	}

	// SecurityCollector reads snap.Processes (written by ProcessCollector),
	// so it must run after ProcessCollector finishes.
	var security Collector
	for _, c := range r.collectors {
		if c.Name() == "security" {
			security = c
			break
		}
	}

	// Phase 1: run all non-security collectors concurrently.
	var wg sync.WaitGroup
	var mu sync.Mutex
	for _, c := range r.collectors {
		if c == security {
			continue
		}
		name := c.Name()
		cost := r.getOrCreateCost(name, c)

		// Guardian skip: collector has been disabled after exceeding its
		// budget too many ticks in a row. Stays skipped for the rest of
		// the process lifetime — restart re-evaluates.
		if cost.Skipped {
			mu.Lock()
			health.Succeeded++
			mu.Unlock()
			continue
		}

		wg.Add(1)
		go func(col Collector, cost *CollectorCost) {
			defer wg.Done()
			start := time.Now()
			err := r.safeCollect(col, snap)
			elapsed := float64(time.Since(start).Microseconds()) / 1000.0

			mu.Lock()
			r.recordCost(cost, elapsed, 0) // skip alloc tracking in concurrent mode
			totalLatencyMs += elapsed
			if err != nil {
				health.Failed++
				errs = append(errs, err)
			} else {
				health.Succeeded++
			}
			mu.Unlock()
		}(c, cost)
	}
	wg.Wait()

	// Phase 2: security collector (reads snap.Processes).
	if security != nil {
		cost := r.getOrCreateCost(security.Name(), security)
		if !cost.Skipped {
			start := time.Now()
			err := r.safeCollect(security, snap)
			elapsed := float64(time.Since(start).Microseconds()) / 1000.0
			r.recordCost(cost, elapsed, 0)
			totalLatencyMs += elapsed
			if err != nil {
				health.Failed++
				errs = append(errs, err)
			} else {
				health.Succeeded++
			}
		}
	}

	if health.Total > 0 {
		health.AvgLatencyMs = totalLatencyMs / float64(health.Total)
	}
	snap.CollectionHealth = health

	return errs
}

// getOrCreateCost returns the cost record for a collector, creating it on
// first sight. Reads the collector's declared MaxMsPerTick budget if the
// type implements CollectorWithBudget; otherwise uses the global default.
func (r *Registry) getOrCreateCost(name string, c Collector) *CollectorCost {
	r.mu.RLock()
	cost := r.costs[name]
	r.mu.RUnlock()
	if cost != nil {
		return cost
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if cost = r.costs[name]; cost != nil {
		return cost
	}
	maxMs := defaultCollectorBudgetMs()
	if cb, ok := c.(CollectorWithBudget); ok {
		if v := cb.MaxMsPerTick(); v > 0 {
			maxMs = float64(v)
		}
	}
	cost = &CollectorCost{
		Name:    name,
		MaxMs:   maxMs,
		samples: make([]float64, 100),
	}
	r.costs[name] = cost
	return cost
}

// recordCost folds a single tick's measurement into the EWMA + ring-buffered
// p95 estimator + over-budget counter. Promotes the collector to Skipped
// when it exceeds its budget for 3 consecutive ticks — the same threshold
// used elsewhere in the project for "this is sustained, not transient."
func (r *Registry) recordCost(cost *CollectorCost, elapsedMs, allocKB float64) {
	r.mu.Lock()
	defer r.mu.Unlock()

	const alpha = 0.2 // last 5 ticks contribute ~67% of EWMA weight
	if cost.MeanMs == 0 {
		cost.MeanMs = elapsedMs
	} else {
		cost.MeanMs = alpha*elapsedMs + (1-alpha)*cost.MeanMs
	}
	if cost.MeanAllocKB == 0 {
		cost.MeanAllocKB = allocKB
	} else {
		cost.MeanAllocKB = alpha*allocKB + (1-alpha)*cost.MeanAllocKB
	}
	cost.LastMs = elapsedMs
	cost.LastRun = time.Now()

	// p95 ring
	cost.samples[cost.samplePos] = elapsedMs
	cost.samplePos = (cost.samplePos + 1) % len(cost.samples)

	// Recompute p95 every 10 samples (cheap enough)
	if cost.samplePos%10 == 0 {
		sorted := append([]float64(nil), cost.samples...)
		sort.Float64s(sorted)
		// Skip leading zeros from un-filled slots
		for i, v := range sorted {
			if v > 0 {
				sorted = sorted[i:]
				break
			}
		}
		if len(sorted) > 0 {
			cost.P95Ms = sorted[int(float64(len(sorted))*0.95)]
		}
	}

	// Budget enforcement: 3 consecutive ticks over budget → skipped.
	if elapsedMs > cost.MaxMs {
		cost.OverBudgetTicks++
		if cost.OverBudgetTicks >= 3 && !cost.Skipped {
			cost.Skipped = true
			cost.SkippedReason = fmt.Sprintf(
				"%.0fms > %.0fms budget for 3 consecutive ticks (mean=%.1fms, p95=%.1fms)",
				elapsedMs, cost.MaxMs, cost.MeanMs, cost.P95Ms)
		}
	} else {
		cost.OverBudgetTicks = 0
	}
}

// CollectorCosts returns a copy of the current cost table for the Guardian
// to read. Holding the registry's read lock briefly while we copy.
func (r *Registry) CollectorCosts() []CollectorCost {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]CollectorCost, 0, len(r.costs))
	for _, c := range r.costs {
		// Copy without the samples slice so the consumer can't mutate.
		out = append(out, CollectorCost{
			Name:            c.Name,
			MeanMs:          c.MeanMs,
			P95Ms:           c.P95Ms,
			LastMs:          c.LastMs,
			MeanAllocKB:     c.MeanAllocKB,
			OverBudgetTicks: c.OverBudgetTicks,
			Skipped:         c.Skipped,
			SkippedReason:   c.SkippedReason,
			MaxMs:           c.MaxMs,
			LastRun:         c.LastRun,
		})
	}
	return out
}

// defaultCollectorBudgetMs returns the per-collector budget that applies
// when the collector itself doesn't declare one. 50 ms is generous for
// /proc reads but tight enough that anything doing serious I/O will trip.
func defaultCollectorBudgetMs() float64 {
	if v, err := strconv.ParseFloat(os.Getenv("XTOP_COLLECTOR_MAX_MS"), 64); err == nil && v > 0 {
		return v
	}
	return 50
}

// safeCollect runs a single collector with panic recovery.
func (r *Registry) safeCollect(c Collector, snap *model.Snapshot) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("collector %s panicked: %v", c.Name(), r)
		}
	}()
	return c.Collect(snap)
}

// Closeable is an optional interface for collectors that hold resources.
type Closeable interface {
	Close()
}

// CloseAll calls Close on any registered collector that implements Closeable.
func (r *Registry) CloseAll() {
	for _, c := range r.collectors {
		if cl, ok := c.(Closeable); ok {
			cl.Close()
		}
	}
}
