package collector

import "github.com/ftahirops/xtop/model"

// Collector is the interface for all metric collectors.
type Collector interface {
	Name() string
	Collect(snap *model.Snapshot) error
}

// Registry holds all registered collectors.
type Registry struct {
	collectors []Collector
}

// NewRegistry creates a registry with all default collectors.
func NewRegistry() *Registry {
	return &Registry{
		collectors: []Collector{
			&PSICollector{},
			&CPUCollector{},
			&MemoryCollector{},
			&DiskCollector{},
			&NetworkCollector{},
			&SocketCollector{},
			&SoftIRQCollector{},
			&SysctlCollector{},
			&ProcessCollector{MaxProcs: 50},
		},
	}
}

// Add registers an additional collector.
func (r *Registry) Add(c Collector) {
	r.collectors = append(r.collectors, c)
}

// CollectAll runs all collectors, populating the snapshot.
func (r *Registry) CollectAll(snap *model.Snapshot) []error {
	var errs []error
	for _, c := range r.collectors {
		if err := c.Collect(snap); err != nil {
			errs = append(errs, err)
		}
	}
	return errs
}
