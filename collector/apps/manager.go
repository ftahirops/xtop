package apps

import (
	"fmt"
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
	module AppModule
	app    DetectedApp
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
	var instances []model.AppInstance
	for i := range m.detected {
		entry := &m.detected[i]
		inst := entry.module.Collect(&entry.app, secrets)
		// Set ID
		if inst.ID == "" {
			inst.ID = fmt.Sprintf("%s-%d", entry.module.Type(), entry.app.Index)
		}
		instances = append(instances, inst)
	}

	snap.Global.Apps = model.AppMetrics{Instances: instances}
	return nil
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
