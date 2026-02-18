package engine

import (
	"time"

	"github.com/ftahirops/xtop/collector"
	cgcollector "github.com/ftahirops/xtop/collector/cgroup"
	"github.com/ftahirops/xtop/model"
)

// Engine orchestrates collection, analysis, and scoring.
type Engine struct {
	registry  *collector.Registry
	cgCollect *cgcollector.Collector
	History   *History
	Smart     *collector.SMARTCollector
}

// NewEngine creates a new engine with all collectors registered.
func NewEngine(historySize int) *Engine {
	reg := collector.NewRegistry()
	cgc := cgcollector.NewCollector()
	reg.Add(cgc)

	return &Engine{
		registry:  reg,
		cgCollect: cgc,
		History:   NewHistory(historySize),
		Smart:     collector.NewSMARTCollector(5 * time.Minute),
	}
}

// Tick performs one collection + analysis cycle.
// Returns the snapshot, computed rates, and full analysis result.
func (e *Engine) Tick() (*model.Snapshot, *model.RateSnapshot, *model.AnalysisResult) {
	snap := &model.Snapshot{
		Timestamp: time.Now(),
	}

	// Collect all metrics
	e.registry.CollectAll(snap)

	// Get previous snapshot for rate calculations
	prev := e.History.Latest()

	// Store in history
	e.History.Push(*snap)

	// Compute rates and run analysis
	var rates *model.RateSnapshot
	var result *model.AnalysisResult

	if prev != nil {
		r := ComputeRates(prev, snap)
		rates = &r
		e.History.PushRate(r)
		result = AnalyzeRCA(snap, rates, e.History)
	}

	return snap, rates, result
}
