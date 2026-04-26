package collector

import (
	"errors"
	"testing"
	"time"

	"github.com/ftahirops/xtop/model"
)

// fakeCollector is a stub Collector that takes a controllable amount of
// wall-clock time per Collect call. Used to exercise the cost tracker
// + per-collector budget enforcement without depending on real I/O.
type fakeCollector struct {
	name string
	dur  time.Duration
	max  int
}

func (f *fakeCollector) Name() string                       { return f.name }
func (f *fakeCollector) Collect(_ *model.Snapshot) error    { time.Sleep(f.dur); return nil }
func (f *fakeCollector) MaxMsPerTick() int                  { return f.max }

func TestCollectorCost_RecordsTimingAndAlloc(t *testing.T) {
	r := &Registry{collectors: []Collector{
		&fakeCollector{name: "fake-fast", dur: 1 * time.Millisecond, max: 100},
	}}
	snap := &model.Snapshot{}
	r.CollectAll(snap)
	r.CollectAll(snap)
	costs := r.CollectorCosts()
	if len(costs) != 1 {
		t.Fatalf("want 1 cost record, got %d", len(costs))
	}
	c := costs[0]
	if c.Name != "fake-fast" {
		t.Errorf("name = %q, want fake-fast", c.Name)
	}
	if c.MeanMs <= 0 {
		t.Errorf("MeanMs = %.3f, want > 0", c.MeanMs)
	}
	if c.MaxMs != 100 {
		t.Errorf("MaxMs = %.0f, want 100 (declared via MaxMsPerTick)", c.MaxMs)
	}
	if c.Skipped {
		t.Error("fast collector should not be skipped")
	}
}

func TestCollectorCost_AutoSkipsAfter3OverBudget(t *testing.T) {
	// Sleeps 30 ms; budget is 5 ms, so each tick is over budget.
	slow := &fakeCollector{name: "slow", dur: 30 * time.Millisecond, max: 5}
	fast := &fakeCollector{name: "fast", dur: 0, max: 100}
	r := &Registry{collectors: []Collector{slow, fast}}
	snap := &model.Snapshot{}
	for i := 0; i < 5; i++ {
		r.CollectAll(snap)
	}
	costs := byName(r.CollectorCosts())
	if !costs["slow"].Skipped {
		t.Errorf("expected 'slow' to be skipped after 3 overruns; cost=%+v", costs["slow"])
	}
	if costs["slow"].SkippedReason == "" {
		t.Error("skipped collector should carry a human-readable reason")
	}
	if costs["fast"].Skipped {
		t.Error("fast collector should not be affected by slow's skip")
	}
}

func TestCollectorCost_EWMAConverges(t *testing.T) {
	// Run a steady-cost collector for many ticks. EWMA should settle near
	// the true mean (allowing for measurement jitter).
	c := &fakeCollector{name: "steady", dur: 5 * time.Millisecond, max: 100}
	r := &Registry{collectors: []Collector{c}}
	snap := &model.Snapshot{}
	for i := 0; i < 30; i++ {
		r.CollectAll(snap)
	}
	costs := r.CollectorCosts()
	if len(costs) == 0 {
		t.Fatal("no costs recorded")
	}
	mean := costs[0].MeanMs
	// Allow a wide band — 5ms sleep can take 4-15ms in CI.
	if mean < 3 || mean > 30 {
		t.Errorf("EWMA mean = %.2f ms; expected within [3,30] ms for 5ms-sleep collector", mean)
	}
}

// errorCollector verifies cost tracking still records timing for a failing
// collector — operators need to see "collector X failed AND took 200ms".
type errorCollector struct{}

func (errorCollector) Name() string                    { return "errfail" }
func (errorCollector) Collect(_ *model.Snapshot) error { time.Sleep(2 * time.Millisecond); return errors.New("boom") }

func TestCollectorCost_TracksErroringCollectors(t *testing.T) {
	r := &Registry{collectors: []Collector{errorCollector{}}}
	snap := &model.Snapshot{}
	errs := r.CollectAll(snap)
	if len(errs) != 1 {
		t.Fatalf("want 1 error, got %d", len(errs))
	}
	costs := r.CollectorCosts()
	if len(costs) != 1 || costs[0].MeanMs <= 0 {
		t.Errorf("erroring collector should still be timed: %+v", costs)
	}
}

func byName(costs []CollectorCost) map[string]CollectorCost {
	m := make(map[string]CollectorCost, len(costs))
	for _, c := range costs {
		m[c.Name] = c
	}
	return m
}
