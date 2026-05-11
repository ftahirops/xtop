//go:build !linux

package phpfpm

import "github.com/ftahirops/xtop/model"

type Collector struct{}

func NewCollector() *Collector            { return &Collector{} }
func (c *Collector) Name() string         { return "phpfpm" }
func (c *Collector) MaxMsPerTick() int    { return 50 }
func (c *Collector) Collect(_ *model.Snapshot) error { return nil }

func SetSkipDeepProbes(_ bool) {}
