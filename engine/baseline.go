package engine

import (
	"math"
	"sync"
)

// ewmaBaseline tracks a single metric's EWMA mean and variance using Welford's online algorithm.
type ewmaBaseline struct {
	Mean     float64
	Variance float64
	Count    int64
	Alpha    float64
}

func (b *ewmaBaseline) update(v float64) {
	b.Count++
	diff := v - b.Mean
	b.Mean += b.Alpha * diff
	b.Variance = (1 - b.Alpha) * (b.Variance + b.Alpha*diff*diff)
}

func (b *ewmaBaseline) stddev() float64 {
	return math.Sqrt(b.Variance)
}

func (b *ewmaBaseline) zScore(v float64) float64 {
	sd := b.stddev()
	if sd < 1e-9 {
		return 0
	}
	return (v - b.Mean) / sd
}

// minWarmup is the number of samples before baselines are trusted.
const minWarmup = 100

// BaselineTracker maintains EWMA baselines for all evidence metrics.
type BaselineTracker struct {
	mu        sync.RWMutex
	alpha     float64
	baselines map[string]*ewmaBaseline
}

// NewBaselineTracker creates a tracker with the given EWMA decay factor.
// Alpha 0.01-0.05 is typical (smaller = slower adaptation).
func NewBaselineTracker(alpha float64) *BaselineTracker {
	return &BaselineTracker{
		alpha:     alpha,
		baselines: make(map[string]*ewmaBaseline),
	}
}

// Update feeds a new value for a metric, updating its EWMA baseline.
func (bt *BaselineTracker) Update(id string, value float64) {
	bt.mu.Lock()
	defer bt.mu.Unlock()
	b, ok := bt.baselines[id]
	if !ok {
		b = &ewmaBaseline{Mean: value, Variance: 0, Count: 0, Alpha: bt.alpha}
		bt.baselines[id] = b
	}
	b.update(value)
}

// Get returns the current baseline mean and stddev for a metric.
func (bt *BaselineTracker) Get(id string) (mean, stddev float64, ok bool) {
	bt.mu.RLock()
	defer bt.mu.RUnlock()
	b, exists := bt.baselines[id]
	if !exists {
		return 0, 0, false
	}
	return b.Mean, b.stddev(), true
}

// IsWarmedUp returns true if enough samples have been collected for reliable baselines.
func (bt *BaselineTracker) IsWarmedUp(id string) bool {
	bt.mu.RLock()
	defer bt.mu.RUnlock()
	b, ok := bt.baselines[id]
	if !ok {
		return false
	}
	return b.Count >= minWarmup
}

// minStddevFraction is the minimum stddev expressed as a fraction of the mean,
// used to avoid false anomalies on perfectly stable baselines.
const minStddevFraction = 0.05

// IsAnomaly returns true if value is more than nSigma standard deviations from baseline.
// Returns false if baseline is not warmed up.
// Uses a minimum stddev floor of minStddevFraction * |mean| to handle near-zero variance.
func (bt *BaselineTracker) IsAnomaly(id string, value, nSigma float64) bool {
	bt.mu.RLock()
	defer bt.mu.RUnlock()
	b, ok := bt.baselines[id]
	if !ok || b.Count < minWarmup {
		return false
	}
	sd := b.stddev()
	// Apply a minimum stddev floor so that perfectly stable baselines still
	// use nSigma semantics (e.g. 3σ of 5% of mean = 15% deviation threshold).
	floor := minStddevFraction * math.Abs(b.Mean)
	if floor < 1e-9 {
		floor = 1e-9
	}
	if sd < floor {
		sd = floor
	}
	return math.Abs(value-b.Mean) > nSigma*sd
}

// ZScore returns the z-score for a value against the baseline.
// Returns 0 if not warmed up.
func (bt *BaselineTracker) ZScore(id string, value float64) float64 {
	bt.mu.RLock()
	defer bt.mu.RUnlock()
	b, ok := bt.baselines[id]
	if !ok || b.Count < minWarmup {
		return 0
	}
	return b.zScore(value)
}

// UpdateAll feeds all fired evidence values into baselines.
func (bt *BaselineTracker) UpdateAll(ids []string, values []float64) {
	for i, id := range ids {
		bt.Update(id, values[i])
	}
}

// SeasonalTracker maintains per-hour-of-day baselines for key metrics.
// This allows the engine to learn that "CPU is always high at 2AM during backups".
type SeasonalTracker struct {
	mu     sync.RWMutex
	hourly map[string]*[24]ewmaBaseline // metric → 24 per-hour baselines
	alpha  float64
}

// NewSeasonalTracker creates a tracker with per-hour EWMA baselines.
func NewSeasonalTracker(alpha float64) *SeasonalTracker {
	return &SeasonalTracker{
		hourly: make(map[string]*[24]ewmaBaseline),
		alpha:  alpha,
	}
}

// Update feeds a value for the current hour of day.
func (st *SeasonalTracker) Update(id string, value float64, hour int) {
	st.mu.Lock()
	defer st.mu.Unlock()
	h, ok := st.hourly[id]
	if !ok {
		h = &[24]ewmaBaseline{}
		for i := range h {
			h[i].Alpha = st.alpha
		}
		st.hourly[id] = h
	}
	h[hour].update(value)
}

// IsSuppressed returns true if the value is within normal range for this hour.
// Used to suppress alerts for known recurring patterns (e.g. nightly backups).
func (st *SeasonalTracker) IsSuppressed(id string, value float64, hour int, nSigma float64) bool {
	st.mu.RLock()
	defer st.mu.RUnlock()
	h, ok := st.hourly[id]
	if !ok || h[hour].Count < minWarmup {
		return false // not enough seasonal data — don't suppress
	}
	b := &h[hour]
	sd := b.stddev()
	if sd < 1e-9 {
		return false
	}
	// Value is within nSigma of this hour's baseline = expected, suppress
	return math.Abs(value-b.Mean) < nSigma*sd
}

// SeasonalBaseline returns the baseline mean+std for a specific hour.
func (st *SeasonalTracker) SeasonalBaseline(id string, hour int) (mean, std float64, ok bool) {
	st.mu.RLock()
	defer st.mu.RUnlock()
	h, exists := st.hourly[id]
	if !exists || h[hour].Count < minWarmup {
		return 0, 0, false
	}
	return h[hour].Mean, h[hour].stddev(), true
}
