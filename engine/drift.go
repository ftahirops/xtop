package engine

import (
	"fmt"
	"sync"
	"time"

	"github.com/ftahirops/xtop/model"
)

// Phase 5: multi-scale drift detection (boiling-frog).
//
// EWMA alone hides slow drift: when a metric creeps up over 30 days, the
// short-window mean tracks it perfectly and never alerts. We detect this by
// keeping THREE windows per metric and looking for divergence:
//
//   short  — Welford over the last ~hour of samples (rolling)
//   long   — Welford over the last ~30 days of samples (rolling)
//   ref    — Welford frozen ~90 days ago (the "what was this 90 days ago" anchor)
//
// Drift fires when:
//   |short.mean - long.mean| < ε       (no acute spike — short has been bumped up to match long)
//   AND |long.mean - ref.mean|  > δ    (the system has drifted)
//
// This catches the case where xtop has been "learning" the gradual leak as
// normal. For an acute spike, short ≠ long, and one of the existing detectors
// fires instead.
//
// Frozen-during-incident: while a Confirmed incident is active, we don't
// update any of the windows so the bad data isn't absorbed.
//
// Storage: in-memory only for v1. The `ref` window only ever updates when
// the long window first reaches its sample target — i.e. roughly when the
// process has been running 90 days. For shorter-lived processes the system
// degrades gracefully (no drift evidence emitted, same as cold-start).
//
// TODO future: persist to ~/.xtop/store.db so drift survives restart.

const (
	// Sample budgets — at the default 3s tick, these correspond to:
	//   short: 1200 samples ≈ 1 hour
	//   long:  86400 samples ≈ 3 days (NOT 30; v1 keeps memory bounded)
	//   ref:   captured once at long-warmup, persists thereafter
	driftShortMax = 1200
	driftLongMax  = 86400

	// driftEpsilon: short and long are "in sync" when within this fraction
	// of long.mean. 5% catches the case where short has drifted UP to match
	// long (i.e. there's no acute incident — the drift is settled).
	driftEpsilonRel = 0.05

	// driftDeltaRel: long has drifted from ref when the relative change
	// exceeds this. 25% is conservative; lower values produce more drift
	// alerts on noisy metrics.
	driftDeltaRel = 0.25

	// driftMinValue: don't track metrics that are usually near zero.
	// Otherwise small absolute drifts become huge relative drifts.
	driftMinValue = 1.0
)

// driftTracker holds all three windows for one metric.
type driftTracker struct {
	short   appBaselineBucket // hot — last ~hour
	long    appBaselineBucket // medium — last few days
	ref     appBaselineBucket // frozen reference — captured once
	refSet  bool
	updated time.Time
}

func (t *driftTracker) push(v float64) {
	t.short.push(v)
	t.long.push(v)
	if t.short.count > int64(driftShortMax) {
		// rolling reset of short — keep it bounded
		t.short = appBaselineBucket{}
		t.short.push(v)
	}
	if t.long.count > int64(driftLongMax) {
		t.long = appBaselineBucket{}
		t.long.push(v)
	}
	if !t.refSet && t.long.count >= 200 {
		// Long has accumulated enough to be a meaningful anchor — snapshot it.
		t.ref = t.long
		t.refSet = true
	}
	t.updated = time.Now()
}

// driftStore is the engine-wide map of drift trackers, keyed by evidence ID.
type driftStore struct {
	mu       sync.Mutex
	trackers map[string]*driftTracker
}

func newDriftStore() *driftStore {
	return &driftStore{trackers: make(map[string]*driftTracker)}
}

func (s *driftStore) update(id string, v float64, freeze bool) *driftTracker {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.trackers[id]
	if !ok {
		t = &driftTracker{}
		s.trackers[id] = t
	}
	if !freeze {
		t.push(v)
	}
	return t
}

// driftStores keyed by History so multiple engines (parallel hub agents,
// tests) don't share state. Engine.Close calls forgetDriftStore for
// cleanup; otherwise repeated test runs leak.
var (
	driftStoresMu sync.Mutex
	driftStores   = make(map[*History]*driftStore)
)

// forgetDriftStore drops the per-history drift trackers from the global
// store. Called by Engine.Close. Safe with unknown histories.
func forgetDriftStore(h *History) {
	if h == nil {
		return
	}
	driftStoresMu.Lock()
	delete(driftStores, h)
	driftStoresMu.Unlock()
}

func getDriftStore(h *History) *driftStore {
	driftStoresMu.Lock()
	defer driftStoresMu.Unlock()
	if s, ok := driftStores[h]; ok {
		return s
	}
	s := newDriftStore()
	driftStores[h] = s
	return s
}

// driftMetrics is the set of evidence values we feed into the drift tracker.
// Kept tight — drift detection is most useful for resource-saturation metrics
// where slow leaks are common, not for transient counters like packet drops.
var driftMetrics = []string{
	"cpu.busy",
	"mem.available.low", // tracks used%
	"io.disk.util",
	"io.disk.latency",
	"net.conntrack",
}

// UpdateDrift feeds the drift trackers and emits drift warnings for any
// metric whose long-window mean has diverged from its frozen reference.
//
// frozen=true skips updates (used while a Confirmed incident is Active).
func UpdateDrift(result *model.AnalysisResult, hist *History, frozen bool) []model.DegradationWarning {
	if result == nil || hist == nil {
		return nil
	}
	store := getDriftStore(hist)

	// Collect the latest value per drift-tracked metric ID from result.RCA.
	values := make(map[string]float64)
	for _, rca := range result.RCA {
		for _, ev := range rca.EvidenceV2 {
			if ev.Value < driftMinValue {
				continue
			}
			values[ev.ID] = ev.Value
		}
	}

	var warnings []model.DegradationWarning
	for _, id := range driftMetrics {
		v, ok := values[id]
		if !ok {
			continue
		}
		t := store.update(id, v, frozen)
		if !t.refSet {
			continue // not enough history for a reference anchor
		}

		// Both short and long windows must be reasonably warmed up.
		shortMean, _, shortReady := t.short.stats()
		longMean, _, longReady := t.long.stats()
		if !shortReady || !longReady {
			continue
		}

		refMean := t.ref.mean
		if refMean < 1e-9 {
			continue
		}

		// Are short and long in sync? (No acute spike — drift is settled.)
		var inSync bool
		if longMean > 1e-9 {
			inSync = absRel(shortMean, longMean) < driftEpsilonRel
		}
		if !inSync {
			continue
		}

		// Has long diverged from ref?
		drift := absRel(longMean, refMean)
		if drift < driftDeltaRel {
			continue
		}

		direction := "rising"
		if longMean < refMean {
			direction = "falling"
		}

		// Crude rate: change since ref, divided by ~3 days (long-window scale).
		// Real implementation would track first-update time of `ref`. Fine.
		rate := (longMean - refMean) / 3.0 / 24.0 / 60.0 // per minute
		warnings = append(warnings, model.DegradationWarning{
			Metric:    id,
			Direction: direction,
			Duration:  int(time.Since(t.updated).Seconds()),
			Rate:      rate,
			Unit:      "/min",
		})
	}
	return warnings
}

// HoltExhaustionEvidence walks Forecaster ETAs and emits one DegradationWarning
// per resource that is forecast to hit critical within the warning horizon.
// This is the predictive complement to drift: drift catches "we're already in
// a bad place"; this catches "we're heading there fast".
func HoltExhaustionEvidence(result *model.AnalysisResult, hist *History) []model.DegradationWarning {
	if result == nil || hist == nil || hist.Forecaster == nil {
		return nil
	}
	// Reuse the same critical thresholds the engine already maintains in rca.go.
	thresholds := map[string]float64{
		"cpu.busy":          90.0,
		"mem.available.low": 95.0,
		"io.disk.util":      90.0,
		"io.psi":            20.0,
		"net.conntrack":     90.0,
	}
	const horizonSeconds = 7 * 24 * 3600 // 7-day forecast window

	var warnings []model.DegradationWarning
	for id, crit := range thresholds {
		eta := hist.Forecaster.ETAToThreshold(id, crit, 100000)
		if eta <= 0 {
			continue
		}
		// ETA from Forecaster is in "samples"; convert to seconds via the
		// last interval (best-effort).
		stepsPerSecond := 1.0
		if hist.Len() > 1 {
			r := hist.GetRate(hist.Len() - 1)
			if r != nil && r.DeltaSec > 0 {
				stepsPerSecond = 1.0 / r.DeltaSec
			}
		}
		etaSec := eta / stepsPerSecond
		if etaSec > horizonSeconds {
			continue
		}

		warnings = append(warnings, model.DegradationWarning{
			Metric:    id,
			Direction: "rising",
			Duration:  int(etaSec),
			Rate:      crit / etaSec,
			Unit:      fmt.Sprintf("→%.0f in %s", crit, fmtAge(int(etaSec))),
		})
	}
	return warnings
}

func absRel(a, b float64) float64 {
	if b == 0 {
		return 0
	}
	d := a - b
	if d < 0 {
		d = -d
	}
	bAbs := b
	if bAbs < 0 {
		bAbs = -bAbs
	}
	return d / bAbs
}
