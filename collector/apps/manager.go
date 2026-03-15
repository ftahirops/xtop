package apps

import (
	"fmt"
	"strconv"
	"sync"
	"time"

	"github.com/ftahirops/xtop/model"
)

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
	mu        sync.Mutex
	modules   []AppModule
	detected  []detectedEntry // last detection results
	lastScan  time.Time
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

// Collect runs detection (every 30s) and collection (every tick).
func (m *Manager) Collect(snap *model.Snapshot) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Run detection scan periodically using a full /proc scan
	// (snap.Processes is filtered to top N by CPU/IO — idle apps would be missed)
	if time.Since(m.lastScan) >= appScanInterval || m.detected == nil {
		m.detected = nil
		allProcs := scanAllProcesses()
		for _, mod := range m.modules {
			apps := mod.Detect(allProcs)
			for _, app := range apps {
				m.detected = append(m.detected, detectedEntry{
					module: mod,
					app:    app,
				})
			}
		}
		m.lastScan = time.Now()
	}

	// Collect metrics from all detected apps
	secrets := loadSecrets()
	now := time.Now()
	var instances []model.AppInstance
	for i := range m.detected {
		entry := &m.detected[i]
		inst := entry.module.Collect(&entry.app, secrets)
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
				// CLK_TCK = 100 on Linux
				cpuPct := float64(deltaTicks) / 100.0 / dtSec * 100.0
				inst.CPUPct = cpuPct
			}
		}
		entry.prevTicks = curTicks
		entry.prevTicksT = now
		// Compute rates for counter metrics
		if entry.prevMetrics != nil && inst.DeepMetrics != nil {
			elapsed := now.Sub(entry.prevTime).Seconds()
			if elapsed > 0 {
				computeCounterRates(inst.DeepMetrics, entry.prevMetrics, elapsed)
			}
		}
		// Store current for next rate computation
		if inst.DeepMetrics != nil {
			cp := make(map[string]string, len(inst.DeepMetrics))
			for k, v := range inst.DeepMetrics {
				cp[k] = v
			}
			entry.prevMetrics = cp
			entry.prevTime = now
		}
		instances = append(instances, inst)
	}

	snap.Global.Apps = model.AppMetrics{Instances: instances}
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
