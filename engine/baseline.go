package engine

import (
	"math"
	"strings"
	"sync"
)

// Adaptive warmup constants (Item 4).
const (
	minWarmupSamples  = 30   // minimum before checking stability
	maxWarmupSamples  = 100  // original hard limit
	cvStableThreshold = 0.15 // coefficient of variation < 15% = stable enough
)

// Outlier rejection during warmup (Item 13).
const tukeyfenceK = 5.0 // reject values > 5σ from mean during warmup

// MetricDistribution classifies the expected statistical distribution of a metric (Item 15).
type MetricDistribution int

const (
	DistNormal      MetricDistribution = iota
	DistRightSkewed                    // retrans, drops, OOM kills — mostly 0, occasional spikes
	DistBimodal                        // PSI — either 0 or significant
)

// classifyDistribution returns the likely distribution based on metric ID.
func classifyDistribution(metricID string) MetricDistribution {
	switch {
	case strings.Contains(metricID, "retrans"),
		strings.Contains(metricID, "drops"),
		strings.Contains(metricID, "oom"),
		strings.Contains(metricID, "reset"):
		return DistRightSkewed
	case strings.Contains(metricID, "psi"):
		return DistBimodal
	default:
		return DistNormal
	}
}

// anomalySigma returns the appropriate sigma threshold for a given distribution.
func anomalySigma(dist MetricDistribution) float64 {
	switch dist {
	case DistRightSkewed:
		return 2.0 // more sensitive to spikes on right-skewed metrics
	case DistBimodal:
		return 2.5 // slightly more sensitive for bimodal
	default:
		return 3.0 // standard for normal distributions
	}
}

// cusumState tracks cumulative sum for change-point detection (Item 20).
type cusumState struct {
	SH    float64 // upper CUSUM
	SL    float64 // lower CUSUM
	Mean  float64 // target mean (from baseline)
	Sigma float64 // target sigma (from baseline)
	K     float64 // allowance (typically 0.5 * shift to detect)
	H     float64 // decision threshold (typically 4-5 * sigma)
}

// CUSUMTuning controls change-point sensitivity. Expressed as multipliers of
// the metric's stddev so the same config works across vastly different metric
// magnitudes. KMul is the drift allowance; higher values ignore slow drifts.
// HMul is the alarm threshold in sigma units; higher values demand a larger
// cumulative deviation before firing.
//
// Defaults are Page/Hinkley textbook values (K=0.5σ, H=4σ). Right-skewed
// metrics tolerate higher thresholds because their "normal" already includes
// occasional spikes — otherwise we'd churn baselines on every packet drop.
type CUSUMTuning struct {
	KMul float64
	HMul float64
}

// Module-level defaults: operators can override via environment at startup
// (see init() below). The config is per-distribution so spiky signals don't
// use the same thresholds as smooth CPU utilization.
var (
	cusumNormal      = CUSUMTuning{KMul: 0.5, HMul: 4.0}
	cusumRightSkewed = CUSUMTuning{KMul: 1.0, HMul: 6.0}
	cusumBimodal     = CUSUMTuning{KMul: 0.75, HMul: 5.0}
)

// cusumFor returns the tuning for a metric's classified distribution.
func cusumFor(dist MetricDistribution) CUSUMTuning {
	switch dist {
	case DistRightSkewed:
		return cusumRightSkewed
	case DistBimodal:
		return cusumBimodal
	default:
		return cusumNormal
	}
}

// newCusumState constructs a state using the *normal-distribution* tuning.
// Callers with a specific metric classification should prefer
// newCusumStateForMetric to pick up the right K/H multipliers.
func newCusumState(mean, sigma float64) cusumState {
	return newCusumStateTuned(mean, sigma, cusumNormal)
}

// newCusumStateForMetric picks tuning based on the metric ID's classification.
func newCusumStateForMetric(metricID string, mean, sigma float64) cusumState {
	return newCusumStateTuned(mean, sigma, cusumFor(classifyDistribution(metricID)))
}

func newCusumStateTuned(mean, sigma float64, t CUSUMTuning) cusumState {
	return cusumState{
		Mean:  mean,
		Sigma: sigma,
		K:     t.KMul * sigma,
		H:     t.HMul * sigma,
	}
}

// Update returns true if change-point detected.
func (c *cusumState) Update(value float64) bool {
	z := value - c.Mean
	c.SH = math.Max(0, c.SH+z-c.K)
	c.SL = math.Max(0, c.SL-z-c.K)

	if c.SH > c.H || c.SL > c.H {
		// Change-point detected — reset
		c.SH = 0
		c.SL = 0
		return true
	}
	return false
}

// ewmaBaseline tracks a single metric's EWMA mean and variance using Welford's online algorithm.
type ewmaBaseline struct {
	MetricID            string // used to pick distribution-aware CUSUM tuning
	Mean                float64
	Variance            float64
	Count               int64
	Alpha               float64
	OutliersRejected    int  // Item 13: count of rejected outliers during warmup
	ChangePointDetected bool // Item 20: set when CUSUM detects a shift
	cusum               cusumState
	cusumInitialized    bool
}

// isWarmedUp checks if this individual baseline has enough stable samples (Item 4).
func (b *ewmaBaseline) isWarmedUp() bool {
	if b.Count < int64(minWarmupSamples) {
		return false
	}
	if b.Count >= int64(maxWarmupSamples) {
		return true
	}
	// Early exit if variance has stabilized
	mean := b.Mean
	if mean == 0 {
		return b.Count >= int64(maxWarmupSamples)
	}
	cv := b.stddev() / math.Abs(mean)
	return cv < cvStableThreshold
}

// shouldRejectOutlier returns true if value is an extreme outlier during warmup (Item 13).
func (b *ewmaBaseline) shouldRejectOutlier(value float64) bool {
	if b.Count < 10 {
		return false // not enough data to detect outliers
	}
	std := b.stddev()
	if std == 0 {
		// All values identical — reject if value differs by >50% of mean
		if b.Mean != 0 {
			return math.Abs(value-b.Mean)/math.Abs(b.Mean) > 0.5
		}
		return value != 0 && value != b.Mean
	}
	zscore := math.Abs(value-b.Mean) / std
	return zscore > tukeyfenceK // reject extreme outliers (5σ during warmup only)
}

// resetForReWarmup resets the baseline for re-learning after a change-point (Item 20).
func (b *ewmaBaseline) resetForReWarmup(seedValue float64) {
	b.Count = 1
	b.Mean = seedValue
	b.Variance = 0 // M2 equivalent reset
	b.cusum = cusumState{}
	b.cusumInitialized = false
	b.ChangePointDetected = true
}

func (b *ewmaBaseline) update(v float64) {
	// Item 13: reject extreme outliers during warmup
	if !b.isWarmedUp() && b.shouldRejectOutlier(v) {
		b.OutliersRejected++
		return
	}

	b.Count++
	diff := v - b.Mean
	b.Mean += b.Alpha * diff
	b.Variance = (1 - b.Alpha) * (b.Variance + b.Alpha*diff*diff)

	// Item 20: initialize CUSUM after warmup completes, with distribution-
	// aware tuning so right-skewed metrics (packet drops, OOM kills) aren't
	// constantly tripping change-points on their natural spikes.
	if b.isWarmedUp() && !b.cusumInitialized {
		sd := b.stddev()
		if sd > 1e-9 {
			if b.MetricID != "" {
				b.cusum = newCusumStateForMetric(b.MetricID, b.Mean, sd)
			} else {
				b.cusum = newCusumState(b.Mean, sd)
			}
			b.cusumInitialized = true
		}
	}

	// Item 20: check for change-point after warmup
	if b.isWarmedUp() && b.cusumInitialized {
		if b.cusum.Update(v) {
			// Distribution has shifted — reset baseline for re-learning
			b.resetForReWarmup(v)
		}
	}
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
		b = &ewmaBaseline{MetricID: id, Mean: value, Variance: 0, Count: 0, Alpha: bt.alpha}
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
// Uses adaptive warmup: stops early when coefficient of variation stabilizes (Item 4).
func (bt *BaselineTracker) IsWarmedUp(id string) bool {
	bt.mu.RLock()
	defer bt.mu.RUnlock()
	b, ok := bt.baselines[id]
	if !ok {
		return false
	}
	return b.isWarmedUp()
}

// minStddevFraction is the minimum stddev expressed as a fraction of the mean,
// used to avoid false anomalies on perfectly stable baselines.
const minStddevFraction = 0.05

// IsAnomaly returns true if value is more than nSigma standard deviations from baseline.
// Returns false if baseline is not warmed up.
// Uses a minimum stddev floor of minStddevFraction * |mean| to handle near-zero variance.
// The nSigma parameter is adjusted by distribution-aware thresholds (Item 15):
// if nSigma <= 0 the classified sigma for the metric ID is used automatically.
func (bt *BaselineTracker) IsAnomaly(id string, value, nSigma float64) bool {
	bt.mu.RLock()
	defer bt.mu.RUnlock()
	b, ok := bt.baselines[id]
	if !ok || !b.isWarmedUp() {
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
	// Item 15: use distribution-aware sigma when caller passes the default 3.0
	effectiveSigma := nSigma
	dist := classifyDistribution(id)
	classified := anomalySigma(dist)
	if effectiveSigma == 3.0 && classified != 3.0 {
		effectiveSigma = classified
	}
	return math.Abs(value-b.Mean) > effectiveSigma*sd
}

// ZScore returns the z-score for a value against the baseline.
// Returns 0 if not warmed up.
func (bt *BaselineTracker) ZScore(id string, value float64) float64 {
	bt.mu.RLock()
	defer bt.mu.RUnlock()
	b, ok := bt.baselines[id]
	if !ok || !b.isWarmedUp() {
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

// BaselineReadiness returns the fraction of tracked metrics that have >= 30 samples
// (0.0 = all metrics warming up, 1.0 = fully ready).
func (bt *BaselineTracker) BaselineReadiness() float64 {
	bt.mu.RLock()
	defer bt.mu.RUnlock()
	if len(bt.baselines) == 0 {
		return 0
	}
	ready := 0
	for _, b := range bt.baselines {
		if b.Count >= minWarmupSamples {
			ready++
		}
	}
	return float64(ready) / float64(len(bt.baselines))
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
	if !ok || !h[hour].isWarmedUp() {
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
	if !exists || !h[hour].isWarmedUp() {
		return 0, 0, false
	}
	return h[hour].Mean, h[hour].stddev(), true
}
