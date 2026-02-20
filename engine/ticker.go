package engine

import "github.com/ftahirops/xtop/model"

// Ticker abstracts a data source that can produce snapshots.
type Ticker interface {
	Tick() (*model.Snapshot, *model.RateSnapshot, *model.AnalysisResult)
	Base() *Engine
}

// Base returns itself for the default engine ticker.
func (e *Engine) Base() *Engine {
	return e
}
