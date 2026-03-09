package apps

import (
	"fmt"
	"sync"
	"time"

	"github.com/ftahirops/xtop/model"
)

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

	// Run detection scan periodically
	if time.Since(m.lastScan) >= appScanInterval || m.detected == nil {
		m.detected = nil
		for _, mod := range m.modules {
			apps := mod.Detect(snap.Processes)
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
