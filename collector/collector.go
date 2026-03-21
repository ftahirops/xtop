package collector

import (
	"fmt"
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

// Registry holds all registered collectors.
type Registry struct {
	collectors []Collector
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

// NewRegistry creates a registry with all default collectors.
func NewRegistry() *Registry {
	return &Registry{
		collectors: []Collector{
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
			&BigFileCollector{MaxFiles: 10, MinSize: 50 * 1024 * 1024},
			&ProcessCollector{MaxProcs: 50},
			&IdentityCollector{},
			&SecurityCollector{},
			&LogsCollector{},
			&HealthCheckCollector{},
			&DiagCollector{interval: 15 * time.Second},
			&ProxmoxCollector{},
			&GPUCollector{},
		},
	}
}

// Add registers an additional collector.
func (r *Registry) Add(c Collector) {
	r.collectors = append(r.collectors, c)
}

// CollectAll runs all collectors, populating the snapshot.
// Each collector is wrapped in a panic recovery to prevent one
// failing collector from crashing the entire collection cycle.
func (r *Registry) CollectAll(snap *model.Snapshot) []error {
	var errs []error
	for _, c := range r.collectors {
		if err := r.safeCollect(c, snap); err != nil {
			errs = append(errs, err)
		}
	}
	return errs
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
