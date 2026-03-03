package runtime

import (
	"time"

	"github.com/ftahirops/xtop/model"
)

const scanInterval = 30 * time.Second

// Manager is a collector that manages all runtime detection modules.
// It implements collector.Collector so it can be registered with the engine.
type Manager struct {
	modules  []RuntimeModule
	lastScan time.Time
}

// NewManager creates a new runtime detection manager.
func NewManager() *Manager {
	return &Manager{}
}

// Register adds a runtime module to the manager.
func (m *Manager) Register(mod RuntimeModule) {
	m.modules = append(m.modules, mod)
}

// Name returns the collector name.
func (m *Manager) Name() string { return "runtime" }

// Collect runs detection (every 30s) and collection (every tick for active modules).
// It populates snap.Global.Runtimes and maintains backward compat with snap.Global.DotNet.
func (m *Manager) Collect(snap *model.Snapshot) error {
	// Run detection scan every 30s
	if time.Since(m.lastScan) >= scanInterval {
		for _, mod := range m.modules {
			mod.Detect(snap.Processes)
		}
		m.lastScan = time.Now()
	}

	// Collect from active modules every tick
	var entries []model.RuntimeEntry
	for _, mod := range m.modules {
		if !mod.Active() {
			continue
		}
		procs := mod.Collect()
		entries = append(entries, model.RuntimeEntry{
			Name:        mod.Name(),
			DisplayName: mod.DisplayName(),
			Active:      true,
			Processes:   procs,
		})

		// Backward compat: populate snap.Global.DotNet from dotnet module
		if mod.Name() == "dotnet" {
			for _, p := range procs {
				snap.Global.DotNet = append(snap.Global.DotNet, model.DotNetProcessMetrics{
					PID:          p.PID,
					Comm:         p.Comm,
					GCHeapSizeMB: p.GCHeapMB,
					TimeInGCPct:  p.GCPausePct,
					AllocRateMBs: p.AllocRateMBs,
					WorkingSetMB: p.WorkingSetMB,
					ThreadPoolCount: atoi(p.Extra["threadpool_count"]),
					ThreadPoolQueue: atoi(p.Extra["threadpool_queue"]),
					ExceptionCount:  atoui64(p.Extra["exception_count"]),
					MonitorLockCount: atoui64(p.Extra["monitor_lock_count"]),
					RequestsPerSec:  atof(p.Extra["requests_per_sec"]),
					CurrentRequests: atoi(p.Extra["current_requests"]),
				})
			}
		}
	}

	// Also include inactive modules (so UI can show them as detected-but-idle)
	for _, mod := range m.modules {
		if mod.Active() {
			continue // already added above
		}
		entries = append(entries, model.RuntimeEntry{
			Name:        mod.Name(),
			DisplayName: mod.DisplayName(),
			Active:      false,
		})
	}

	snap.Global.Runtimes = model.RuntimeMetrics{Entries: entries}
	return nil
}

// ActiveModules returns the names of currently active runtime modules.
func (m *Manager) ActiveModules() []string {
	var names []string
	for _, mod := range m.modules {
		if mod.Active() {
			names = append(names, mod.Name())
		}
	}
	return names
}
