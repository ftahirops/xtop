# Statistical RCA Intelligence Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add pure-math statistical intelligence (EWMA baselines, Pearson correlation, z-score anomaly, rate-of-change, seasonal awareness, process profiling, golden signal proxies, causal learning, Holt forecasting) to the RCA engine — zero external dependencies, ~2100 lines total.

**Architecture:** All new code lives in `engine/` as small focused files. Each statistical component maintains lightweight streaming state (EWMA/Welford/ring buffers) updated once per tick in `AnalyzeRCA()`. Results are stored in new fields on `model.AnalysisResult` and surfaced in the narrative engine. No ML libraries — pure Go math.

**Tech Stack:** Go standard library only (`math`, `sort`, `sync`). Welford's online algorithm for variance. EWMA for smoothing. Holt double exponential for forecasting.

---

## File Structure

### New Files (8)

| File | Responsibility | ~Lines |
|------|---------------|--------|
| `engine/baseline.go` | EWMA per-evidence baselines with Welford variance | ~200 |
| `engine/baseline_test.go` | Tests for baseline warmup, anomaly detection, update | ~150 |
| `engine/correlate.go` | Streaming Pearson correlation for metric pairs | ~150 |
| `engine/correlate_test.go` | Tests for correlation computation | ~100 |
| `engine/zscore.go` | Sliding window z-score anomaly detection | ~120 |
| `engine/zscore_test.go` | Tests for z-score ring buffer | ~100 |
| `engine/forecast.go` | Holt double exponential smoothing forecaster | ~120 |
| `engine/forecast_test.go` | Tests for Holt forecasting | ~100 |

### Modified Files (7)

| File | Changes |
|------|---------|
| `model/snapshot.go` | Add `BaselineAnomalies`, `Correlations`, `ZScoreAnomalies`, `ProcessAnomalies`, `GoldenSignals`, `SeasonalSuppressions` fields to `AnalysisResult` |
| `engine/engine.go` | Add statistical state structs to `Engine`; init in `NewEngine()` |
| `engine/rca.go` | Call statistical modules from `AnalyzeRCA()` after domain analyzers |
| `engine/history.go` | Add `Baselines`, `Correlator`, `ZScores`, `ProcProfiles`, `Seasonals`, `Forecaster`, `CausalLearner` to `History` struct |
| `engine/narrative.go` | Integrate baseline anomalies + correlations into narrative output |
| `engine/evidence.go` | Add `BaselineAnomaly` bool + `ZScore` float64 to evidence tags |
| `cmd/root.go` | Version bump to 0.31.0 |

---

## Chunk 1: Foundation — Model Types + EWMA Baselines + Z-Score

### Task 1: Add Model Types for Statistical Results

**Files:**
- Modify: `model/snapshot.go` (after line ~323, end of AnalysisResult)

- [ ] **Step 1: Add new types and fields to model/snapshot.go**

Add after the `Blame []BlameEntry` field in `AnalysisResult` (around line 323):

```go
// Statistical intelligence (v0.31.0)
BaselineAnomalies  []BaselineAnomaly  // Evidence deviating from learned baseline
Correlations       []MetricCorrelation // Discovered metric correlations
ZScoreAnomalies    []ZScoreAnomaly    // Statistically unusual values vs recent window
ProcessAnomalies   []ProcessAnomaly   // Processes deviating from learned profile
GoldenSignals      *GoldenSignalSummary // Approximated Golden Signal metrics
```

Add these new types at the end of the file (after existing type definitions):

```go
// BaselineAnomaly represents an evidence value that deviates from its learned EWMA baseline.
type BaselineAnomaly struct {
	EvidenceID string  // e.g. "cpu.busy"
	Value      float64 // current value
	Baseline   float64 // EWMA mean
	StdDev     float64 // sqrt(EWMA variance)
	ZScore     float64 // (value - mean) / stddev
	Sigma      float64 // how many sigma above baseline
}

// MetricCorrelation represents a discovered Pearson correlation between two metrics.
type MetricCorrelation struct {
	MetricA     string  // evidence ID A
	MetricB     string  // evidence ID B
	Coefficient float64 // Pearson R (-1 to +1)
	Samples     int64   // number of samples
	Strength    string  // "strong"/"moderate"/"weak"
}

// ZScoreAnomaly represents a value that is statistically unusual vs recent history.
type ZScoreAnomaly struct {
	EvidenceID string  // e.g. "cpu.busy"
	Value      float64 // current value
	WindowMean float64 // mean over sliding window
	WindowStd  float64 // stddev over sliding window
	ZScore     float64 // (value - mean) / std
}

// ProcessAnomaly represents a process whose resource usage deviates from its learned profile.
type ProcessAnomaly struct {
	PID       int
	Comm      string
	Metric    string  // "cpu_pct", "rss_mb", "io_mbs"
	Current   float64
	Baseline  float64
	StdDev    float64
	Sigma     float64
}

// GoldenSignalSummary approximates Google SRE Golden Signals from /proc data.
type GoldenSignalSummary struct {
	// Latency proxies
	DiskLatencyMs    float64 // worst disk await
	TCPRTTMs         float64 // smoothed TCP RTT (if BPF available)
	PSIStallPct      float64 // max PSI stall across domains
	// Traffic proxies
	TCPSegmentsPerSec float64 // in + out segments
	NetBytesPerSec    float64 // total interface throughput
	ConnAcceptRate    float64 // passive opens / sec
	// Error proxies
	ErrorRate         float64 // drops + retrans + resets + OOM combined rate
	// Saturation proxies
	SaturationPct     float64 // max of: conntrack%, ephemeral%, runqueue ratio, PSI
}
```

- [ ] **Step 2: Verify build**

Run: `go build ./...`
Expected: Clean compile

- [ ] **Step 3: Commit**

```bash
git add model/snapshot.go
git commit -m "feat(model): add statistical intelligence types for baselines, correlations, z-scores, golden signals"
```

---

### Task 2: Implement EWMA Baseline Engine

**Files:**
- Create: `engine/baseline.go`
- Create: `engine/baseline_test.go`

- [ ] **Step 1: Write the baseline test**

Create `engine/baseline_test.go`:

```go
package engine

import (
	"math"
	"testing"
)

func TestBaselineUpdateAndAnomaly(t *testing.T) {
	b := NewBaselineTracker(0.05) // alpha=0.05

	// Feed 100 samples of steady value=10
	for i := 0; i < 100; i++ {
		b.Update("cpu.busy", 10.0)
	}

	// Baseline should be ~10, stddev small
	mean, std, ok := b.Get("cpu.busy")
	if !ok {
		t.Fatal("expected baseline to exist")
	}
	if math.Abs(mean-10.0) > 1.0 {
		t.Errorf("mean=%.2f, want ~10", mean)
	}
	if std > 2.0 {
		t.Errorf("std=%.2f, want <2", std)
	}

	// Value of 50 should be anomalous (>3 sigma)
	anom := b.IsAnomaly("cpu.busy", 50.0, 3.0)
	if !anom {
		t.Error("expected 50 to be anomalous vs baseline of 10")
	}

	// Value of 11 should NOT be anomalous
	anom = b.IsAnomaly("cpu.busy", 11.0, 3.0)
	if anom {
		t.Error("expected 11 to NOT be anomalous vs baseline of 10")
	}
}

func TestBaselineWarmup(t *testing.T) {
	b := NewBaselineTracker(0.05)

	// Before warmup, nothing should be anomalous
	b.Update("test", 5.0)
	if b.IsWarmedUp("test") {
		t.Error("should not be warmed up after 1 sample")
	}
	// Feed enough to warm up (100 samples)
	for i := 0; i < 99; i++ {
		b.Update("test", 5.0)
	}
	if !b.IsWarmedUp("test") {
		t.Error("should be warmed up after 100 samples")
	}
}

func TestBaselineZScore(t *testing.T) {
	b := NewBaselineTracker(0.05)
	for i := 0; i < 100; i++ {
		b.Update("m", 20.0+float64(i%3)) // 20, 21, 22 repeating
	}
	z := b.ZScore("m", 40.0)
	if z < 5.0 {
		t.Errorf("z=%.2f, expected >5 for value 40 vs baseline ~21", z)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./engine/ -run TestBaseline -v`
Expected: FAIL — types not defined

- [ ] **Step 3: Implement baseline.go**

Create `engine/baseline.go`:

```go
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
	mu       sync.RWMutex
	alpha    float64
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

// IsAnomaly returns true if value is more than nSigma standard deviations from baseline.
// Returns false if baseline is not warmed up.
func (bt *BaselineTracker) IsAnomaly(id string, value, nSigma float64) bool {
	bt.mu.RLock()
	defer bt.mu.RUnlock()
	b, ok := bt.baselines[id]
	if !ok || b.Count < minWarmup {
		return false
	}
	sd := b.stddev()
	if sd < 1e-9 {
		return false
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

// UpdateFromEvidence feeds all evidence values into the baseline tracker.
// Called once per tick after domain analyzers produce evidence.
func (bt *BaselineTracker) UpdateFromEvidence(evs []Evidence) {
	for _, ev := range evs {
		bt.Update(ev.ID, ev.Value)
	}
}

// Note: Evidence is imported from model but we use the local package type here.
// The actual integration will pass model.Evidence and extract ID+Value.
```

Wait — the `UpdateFromEvidence` takes `[]Evidence` but model is in a different package. Fix: we'll pass `[]model.Evidence` at the call site in rca.go. Remove the method and just call `Update` in a loop. Simplify:

Replace the last function with:

```go
// UpdateAll feeds all fired evidence values into baselines.
func (bt *BaselineTracker) UpdateAll(ids []string, values []float64) {
	for i, id := range ids {
		bt.Update(id, values[i])
	}
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./engine/ -run TestBaseline -v`
Expected: PASS (3 tests)

- [ ] **Step 5: Commit**

```bash
git add engine/baseline.go engine/baseline_test.go
git commit -m "feat(engine): add EWMA baseline tracker with Welford variance for per-evidence anomaly detection"
```

---

### Task 3: Implement Z-Score Sliding Window

**Files:**
- Create: `engine/zscore.go`
- Create: `engine/zscore_test.go`

- [ ] **Step 1: Write the z-score test**

Create `engine/zscore_test.go`:

```go
package engine

import (
	"math"
	"testing"
)

func TestZWindowBasic(t *testing.T) {
	zw := NewZScoreTracker(60)

	// Feed 60 values of 10.0
	for i := 0; i < 60; i++ {
		zw.Push("cpu.busy", 10.0)
	}

	// z-score of 10 should be ~0
	z := zw.ZScore("cpu.busy", 10.0)
	if math.Abs(z) > 0.1 {
		t.Errorf("z=%.2f for same value, want ~0", z)
	}

	// z-score of 30 should be very high
	z = zw.ZScore("cpu.busy", 30.0)
	if z < 3.0 {
		t.Errorf("z=%.2f for outlier, want >3", z)
	}
}

func TestZWindowNotReady(t *testing.T) {
	zw := NewZScoreTracker(60)
	zw.Push("test", 5.0)
	z := zw.ZScore("test", 100.0)
	if z != 0 {
		t.Errorf("z=%.2f, want 0 when not enough data", z)
	}
}

func TestZWindowSliding(t *testing.T) {
	zw := NewZScoreTracker(10)
	// Fill window with 5.0
	for i := 0; i < 10; i++ {
		zw.Push("m", 5.0)
	}
	// Slide window with 15.0
	for i := 0; i < 10; i++ {
		zw.Push("m", 15.0)
	}
	// After full slide, baseline should be ~15, z-score of 15 ~= 0
	z := zw.ZScore("m", 15.0)
	if math.Abs(z) > 0.5 {
		t.Errorf("z=%.2f after window slide, want ~0", z)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./engine/ -run TestZWindow -v`
Expected: FAIL

- [ ] **Step 3: Implement zscore.go**

Create `engine/zscore.go`:

```go
package engine

import (
	"math"
	"sync"
)

// zWindow is a fixed-size sliding window for a single metric.
type zWindow struct {
	vals []float64
	pos  int
	full bool
	size int
}

func newZWindow(size int) *zWindow {
	return &zWindow{vals: make([]float64, size), size: size}
}

func (w *zWindow) push(v float64) {
	w.vals[w.pos] = v
	w.pos++
	if w.pos >= w.size {
		w.pos = 0
		w.full = true
	}
}

func (w *zWindow) ready() bool {
	return w.full
}

func (w *zWindow) meanStd() (float64, float64) {
	n := w.size
	if !w.full {
		n = w.pos
	}
	if n == 0 {
		return 0, 0
	}
	var sum float64
	for i := 0; i < n; i++ {
		sum += w.vals[i]
	}
	mean := sum / float64(n)
	var sq float64
	for i := 0; i < n; i++ {
		d := w.vals[i] - mean
		sq += d * d
	}
	std := math.Sqrt(sq / float64(n))
	return mean, std
}

// ZScoreTracker maintains sliding windows for multiple metrics.
type ZScoreTracker struct {
	mu      sync.RWMutex
	windows map[string]*zWindow
	winSize int
}

// NewZScoreTracker creates a tracker with the given window size (number of samples).
func NewZScoreTracker(windowSize int) *ZScoreTracker {
	return &ZScoreTracker{
		windows: make(map[string]*zWindow),
		winSize: windowSize,
	}
}

// Push adds a value for a metric to its sliding window.
func (zt *ZScoreTracker) Push(id string, value float64) {
	zt.mu.Lock()
	defer zt.mu.Unlock()
	w, ok := zt.windows[id]
	if !ok {
		w = newZWindow(zt.winSize)
		zt.windows[id] = w
	}
	w.push(value)
}

// ZScore returns the z-score for a value against the sliding window.
// Returns 0 if insufficient data.
func (zt *ZScoreTracker) ZScore(id string, value float64) float64 {
	zt.mu.RLock()
	defer zt.mu.RUnlock()
	w, ok := zt.windows[id]
	if !ok || !w.ready() {
		return 0
	}
	mean, std := w.meanStd()
	if std < 1e-9 {
		return 0
	}
	return (value - mean) / std
}

// MeanStd returns the window mean and standard deviation.
func (zt *ZScoreTracker) MeanStd(id string) (float64, float64, bool) {
	zt.mu.RLock()
	defer zt.mu.RUnlock()
	w, ok := zt.windows[id]
	if !ok || !w.ready() {
		return 0, 0, false
	}
	m, s := w.meanStd()
	return m, s, true
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./engine/ -run TestZWindow -v`
Expected: PASS (3 tests)

- [ ] **Step 5: Commit**

```bash
git add engine/zscore.go engine/zscore_test.go
git commit -m "feat(engine): add sliding window z-score tracker for relative anomaly detection"
```

---

### Task 4: Implement Streaming Pearson Correlation

**Files:**
- Create: `engine/correlate.go`
- Create: `engine/correlate_test.go`

- [ ] **Step 1: Write the correlation test**

Create `engine/correlate_test.go`:

```go
package engine

import (
	"math"
	"testing"
)

func TestCorrelationPerfectPositive(t *testing.T) {
	c := NewCorrelator()
	for i := 0; i < 100; i++ {
		x := float64(i)
		c.Add("a", "b", x, x*2+1) // perfect linear
	}
	r := c.R("a", "b")
	if math.Abs(r-1.0) > 0.01 {
		t.Errorf("R=%.4f, want ~1.0 for perfect positive", r)
	}
}

func TestCorrelationPerfectNegative(t *testing.T) {
	c := NewCorrelator()
	for i := 0; i < 100; i++ {
		x := float64(i)
		c.Add("a", "b", x, 100-x)
	}
	r := c.R("a", "b")
	if math.Abs(r+1.0) > 0.01 {
		t.Errorf("R=%.4f, want ~-1.0 for perfect negative", r)
	}
}

func TestCorrelationUncorrelated(t *testing.T) {
	c := NewCorrelator()
	// Alternating — no correlation
	for i := 0; i < 100; i++ {
		x := float64(i)
		y := float64(i%2) * 100
		c.Add("a", "b", x, y)
	}
	r := c.R("a", "b")
	if math.Abs(r) > 0.3 {
		t.Errorf("R=%.4f, want ~0 for uncorrelated", r)
	}
}

func TestCorrelationMinSamples(t *testing.T) {
	c := NewCorrelator()
	c.Add("a", "b", 1, 2)
	r := c.R("a", "b")
	if r != 0 {
		t.Errorf("R=%.4f, want 0 with insufficient samples", r)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./engine/ -run TestCorrelation -v`
Expected: FAIL

- [ ] **Step 3: Implement correlate.go**

Create `engine/correlate.go`:

```go
package engine

import (
	"math"
	"sync"
)

// pairStats tracks streaming Pearson correlation between two metrics.
// Uses Welford-style online algorithm for covariance.
type pairStats struct {
	N                    int64
	SumX, SumY           float64
	SumXX, SumYY, SumXY  float64
}

func (p *pairStats) add(x, y float64) {
	p.N++
	p.SumX += x
	p.SumY += y
	p.SumXX += x * x
	p.SumYY += y * y
	p.SumXY += x * y
}

func (p *pairStats) r() float64 {
	if p.N < 10 {
		return 0
	}
	n := float64(p.N)
	num := n*p.SumXY - p.SumX*p.SumY
	denX := n*p.SumXX - p.SumX*p.SumX
	denY := n*p.SumYY - p.SumY*p.SumY
	if denX <= 0 || denY <= 0 {
		return 0
	}
	return num / math.Sqrt(denX*denY)
}

// pairKey generates a canonical key for a metric pair (sorted order).
func pairKey(a, b string) string {
	if a > b {
		a, b = b, a
	}
	return a + "|" + b
}

// Correlator tracks streaming Pearson correlations for pre-defined metric pairs.
type Correlator struct {
	mu    sync.RWMutex
	pairs map[string]*pairStats
}

// NewCorrelator creates a new streaming correlation tracker.
func NewCorrelator() *Correlator {
	return &Correlator{
		pairs: make(map[string]*pairStats),
	}
}

// Add feeds a paired observation for two metrics.
func (c *Correlator) Add(idA, idB string, valA, valB float64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	key := pairKey(idA, idB)
	p, ok := c.pairs[key]
	if !ok {
		p = &pairStats{}
		c.pairs[key] = p
	}
	if idA > idB {
		valA, valB = valB, valA
	}
	p.add(valA, valB)
}

// R returns the Pearson correlation coefficient for a pair.
// Returns 0 if insufficient data.
func (c *Correlator) R(idA, idB string) float64 {
	c.mu.RLock()
	defer c.mu.RUnlock()
	key := pairKey(idA, idB)
	p, ok := c.pairs[key]
	if !ok {
		return 0
	}
	return p.r()
}

// Samples returns how many observations exist for a pair.
func (c *Correlator) Samples(idA, idB string) int64 {
	c.mu.RLock()
	defer c.mu.RUnlock()
	key := pairKey(idA, idB)
	p, ok := c.pairs[key]
	if !ok {
		return 0
	}
	return p.N
}

// correlationPairs defines which metric pairs to track correlation for.
// These are the temporal cross-signal pairs from temporal.go plus key cross-domain links.
var correlationPairs = [][2]string{
	{"cpu.busy", "cpu.runqueue"},
	{"cpu.busy", "io.disk.latency"},
	{"cpu.runqueue", "io.disk.latency"},
	{"mem.reclaim.direct", "io.disk.latency"},
	{"mem.swap.in", "io.disk.latency"},
	{"mem.available.low", "mem.psi"},
	{"mem.psi", "io.psi"},
	{"cpu.psi", "cpu.runqueue"},
	{"cpu.iowait", "io.disk.latency"},
	{"cpu.iowait", "io.psi"},
	{"net.tcp.retrans", "net.drops"},
	{"net.conntrack", "net.drops"},
	{"net.tcp.timewait", "net.ephemeral"},
	{"net.drops.rx", "net.tcp.retrans"},
	{"cpu.steal", "cpu.psi"},
	{"io.disk.util", "io.disk.latency"},
	{"io.disk.queuedepth", "io.disk.latency"},
	{"mem.psi.acceleration", "mem.reclaim.direct"},
	{"mem.slab.leak", "mem.available.low"},
	{"cpu.irq.imbalance", "net.drops"},
}

// UpdateFromEvidence feeds current tick's evidence values into all tracked correlation pairs.
func (c *Correlator) UpdateFromEvidence(evidenceMap map[string]float64) {
	for _, pair := range correlationPairs {
		valA, okA := evidenceMap[pair[0]]
		valB, okB := evidenceMap[pair[1]]
		if okA && okB {
			c.Add(pair[0], pair[1], valA, valB)
		}
	}
}

// TopCorrelations returns the pairs with |R| > minR, sorted by |R| descending.
func (c *Correlator) TopCorrelations(minR float64, maxN int) []struct {
	A, B string
	R    float64
	N    int64
} {
	c.mu.RLock()
	defer c.mu.RUnlock()

	type result struct {
		A, B string
		R    float64
		N    int64
	}
	var results []result
	for _, pair := range correlationPairs {
		key := pairKey(pair[0], pair[1])
		p, ok := c.pairs[key]
		if !ok || p.N < 30 {
			continue
		}
		r := p.r()
		if math.Abs(r) >= minR {
			results = append(results, result{A: pair[0], B: pair[1], R: r, N: p.N})
		}
	}

	// Sort by |R| descending
	for i := 0; i < len(results); i++ {
		for j := i + 1; j < len(results); j++ {
			if math.Abs(results[j].R) > math.Abs(results[i].R) {
				results[i], results[j] = results[j], results[i]
			}
		}
	}
	if len(results) > maxN {
		results = results[:maxN]
	}
	return results
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./engine/ -run TestCorrelation -v`
Expected: PASS (4 tests)

- [ ] **Step 5: Commit**

```bash
git add engine/correlate.go engine/correlate_test.go
git commit -m "feat(engine): add streaming Pearson correlation tracker for cross-metric discovery"
```

---

### Task 5: Implement Holt Double Exponential Forecasting

**Files:**
- Create: `engine/forecast.go`
- Create: `engine/forecast_test.go`

- [ ] **Step 1: Write the forecast test**

Create `engine/forecast_test.go`:

```go
package engine

import (
	"math"
	"testing"
)

func TestHoltLinearTrend(t *testing.T) {
	h := NewHoltForecaster(0.3, 0.1)

	// Feed linearly increasing data: 0, 1, 2, ... 99
	for i := 0; i < 100; i++ {
		h.Update("mem.used", float64(i))
	}

	// Forecast 10 steps ahead: should predict ~109
	forecast := h.Forecast("mem.used", 10)
	if math.Abs(forecast-109) > 5 {
		t.Errorf("forecast=%.1f, want ~109 for linear trend", forecast)
	}
}

func TestHoltFlatLine(t *testing.T) {
	h := NewHoltForecaster(0.3, 0.1)
	for i := 0; i < 50; i++ {
		h.Update("flat", 42.0)
	}
	forecast := h.Forecast("flat", 10)
	if math.Abs(forecast-42.0) > 1.0 {
		t.Errorf("forecast=%.1f, want ~42 for flat line", forecast)
	}
}

func TestHoltNotReady(t *testing.T) {
	h := NewHoltForecaster(0.3, 0.1)
	h.Update("x", 5.0)
	f := h.Forecast("x", 10)
	if f != 0 {
		t.Errorf("forecast=%.1f, want 0 when not ready", f)
	}
}

func TestHoltExhaustionETA(t *testing.T) {
	h := NewHoltForecaster(0.3, 0.1)
	// Memory going from 50% to 90% over 40 ticks (~1%/tick)
	for i := 0; i < 40; i++ {
		h.Update("mem.pct", 50.0+float64(i))
	}
	eta := h.ETAToThreshold("mem.pct", 100.0, 120)
	if eta < 5 || eta > 15 {
		t.Errorf("eta=%.1f steps, want ~10 for 90→100 at 1/tick", eta)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./engine/ -run TestHolt -v`
Expected: FAIL

- [ ] **Step 3: Implement forecast.go**

Create `engine/forecast.go`:

```go
package engine

import "sync"

// holtState tracks Holt double exponential smoothing state for one metric.
type holtState struct {
	Level float64
	Trend float64
	Count int64
}

const holtMinSamples = 10

// HoltForecaster provides Holt double exponential smoothing forecasting.
type HoltForecaster struct {
	mu    sync.RWMutex
	alpha float64 // level smoothing (0.1-0.5)
	beta  float64 // trend smoothing (0.01-0.3)
	state map[string]*holtState
}

// NewHoltForecaster creates a Holt forecaster with given alpha (level) and beta (trend) params.
func NewHoltForecaster(alpha, beta float64) *HoltForecaster {
	return &HoltForecaster{
		alpha: alpha,
		beta:  beta,
		state: make(map[string]*holtState),
	}
}

// Update feeds a new observation for a metric.
func (hf *HoltForecaster) Update(id string, value float64) {
	hf.mu.Lock()
	defer hf.mu.Unlock()

	s, ok := hf.state[id]
	if !ok {
		s = &holtState{Level: value, Trend: 0, Count: 0}
		hf.state[id] = s
	}
	s.Count++

	if s.Count <= 2 {
		// Initialize: second sample sets trend
		if s.Count == 2 {
			s.Trend = value - s.Level
		}
		s.Level = value
		return
	}

	prevLevel := s.Level
	s.Level = hf.alpha*value + (1-hf.alpha)*(s.Level+s.Trend)
	s.Trend = hf.beta*(s.Level-prevLevel) + (1-hf.beta)*s.Trend
}

// Forecast returns the predicted value h steps ahead.
// Returns 0 if insufficient data.
func (hf *HoltForecaster) Forecast(id string, h int) float64 {
	hf.mu.RLock()
	defer hf.mu.RUnlock()
	s, ok := hf.state[id]
	if !ok || s.Count < holtMinSamples {
		return 0
	}
	return s.Level + float64(h)*s.Trend
}

// Trend returns the current trend rate (units per step).
func (hf *HoltForecaster) Trend(id string) float64 {
	hf.mu.RLock()
	defer hf.mu.RUnlock()
	s, ok := hf.state[id]
	if !ok || s.Count < holtMinSamples {
		return 0
	}
	return s.Trend
}

// ETAToThreshold returns how many steps until the metric crosses a threshold.
// Returns -1 if trend is not heading toward threshold, 0 if insufficient data.
// Caps at maxSteps.
func (hf *HoltForecaster) ETAToThreshold(id string, threshold float64, maxSteps int) float64 {
	hf.mu.RLock()
	defer hf.mu.RUnlock()
	s, ok := hf.state[id]
	if !ok || s.Count < holtMinSamples {
		return 0
	}

	current := s.Level
	trend := s.Trend

	// Already past threshold
	if current >= threshold {
		return 0
	}
	// Trend going away from threshold
	if trend <= 0 {
		return -1
	}

	steps := (threshold - current) / trend
	if steps > float64(maxSteps) {
		return -1
	}
	return steps
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./engine/ -run TestHolt -v`
Expected: PASS (4 tests)

- [ ] **Step 5: Commit**

```bash
git add engine/forecast.go engine/forecast_test.go
git commit -m "feat(engine): add Holt double exponential smoothing forecaster for trend prediction"
```

---

## Chunk 2: Integration — Wire Into Engine + Process Profiling + Golden Signals

### Task 6: Add Statistical State to History and Engine

**Files:**
- Modify: `engine/history.go` (add fields to History struct)
- Modify: `engine/engine.go` (init in NewEngine)

- [ ] **Step 1: Add statistical trackers to History struct**

In `engine/history.go`, add fields to the `History` struct (after `signalOnsets`):

```go
// Statistical intelligence
Baselines   *BaselineTracker
ZScores     *ZScoreTracker
Correlator  *Correlator
Forecaster  *HoltForecaster
```

- [ ] **Step 2: Initialize in NewHistory()**

In `NewHistory()`, after `signalOnsets: make(map[string]time.Time)`, add:

```go
Baselines:   NewBaselineTracker(0.03),
ZScores:     NewZScoreTracker(60),
Correlator:  NewCorrelator(),
Forecaster:  NewHoltForecaster(0.3, 0.1),
```

- [ ] **Step 3: Verify build**

Run: `go build ./...`
Expected: Clean compile

- [ ] **Step 4: Commit**

```bash
git add engine/history.go
git commit -m "feat(engine): add statistical trackers (baselines, z-scores, correlator, forecaster) to History"
```

---

### Task 7: Wire Statistical Analysis into AnalyzeRCA

**Files:**
- Modify: `engine/rca.go` (add statistical analysis calls after domain analyzers, before narrative)

- [ ] **Step 1: Add statistical integration function**

Add a new function at the end of `engine/rca.go`:

```go
// runStatisticalAnalysis feeds evidence into statistical trackers and populates results.
func runStatisticalAnalysis(result *model.AnalysisResult, curr *model.Snapshot, rates *model.RateSnapshot, hist *History) {
	if hist == nil {
		return
	}

	// 1. Collect all evidence values from this tick
	evidenceMap := make(map[string]float64)
	for _, rca := range result.RCA {
		for _, ev := range rca.EvidenceV2 {
			evidenceMap[ev.ID] = ev.Value
		}
	}

	// 2. Update baselines + detect anomalies
	for id, val := range evidenceMap {
		hist.Baselines.Update(id, val)
		hist.ZScores.Push(id, val)
		hist.Forecaster.Update(id, val)
	}

	// 3. Update correlator with all pairs
	hist.Correlator.UpdateFromEvidence(evidenceMap)

	// 4. Detect baseline anomalies (>3 sigma from EWMA)
	for id, val := range evidenceMap {
		if hist.Baselines.IsAnomaly(id, val, 3.0) {
			mean, std, _ := hist.Baselines.Get(id)
			z := hist.Baselines.ZScore(id, val)
			result.BaselineAnomalies = append(result.BaselineAnomalies, model.BaselineAnomaly{
				EvidenceID: id,
				Value:      val,
				Baseline:   mean,
				StdDev:     std,
				ZScore:     z,
				Sigma:      z,
			})
		}
	}

	// 5. Detect z-score anomalies (>3 sigma from sliding window)
	for id, val := range evidenceMap {
		z := hist.ZScores.ZScore(id, val)
		if z > 3.0 || z < -3.0 {
			mean, std, _ := hist.ZScores.MeanStd(id)
			result.ZScoreAnomalies = append(result.ZScoreAnomalies, model.ZScoreAnomaly{
				EvidenceID: id,
				Value:      val,
				WindowMean: mean,
				WindowStd:  std,
				ZScore:     z,
			})
		}
	}

	// 6. Surface top correlations
	topCorr := hist.Correlator.TopCorrelations(0.7, 5)
	for _, tc := range topCorr {
		strength := "moderate"
		if tc.R > 0.85 || tc.R < -0.85 {
			strength = "strong"
		}
		result.Correlations = append(result.Correlations, model.MetricCorrelation{
			MetricA:     tc.A,
			MetricB:     tc.B,
			Coefficient: tc.R,
			Samples:     tc.N,
			Strength:    strength,
		})
	}

	// 7. Build Golden Signal summary
	result.GoldenSignals = buildGoldenSignals(curr, rates)
}

// buildGoldenSignals approximates Google SRE Golden Signals from /proc data.
func buildGoldenSignals(curr *model.Snapshot, rates *model.RateSnapshot) *model.GoldenSignalSummary {
	gs := &model.GoldenSignalSummary{}

	// Latency: worst disk await + max PSI stall
	for _, d := range curr.Global.Disks {
		if d.AvgAwaitMs > gs.DiskLatencyMs {
			gs.DiskLatencyMs = d.AvgAwaitMs
		}
	}
	psiMax := curr.Global.PSI.CPU.Some.Avg10
	if curr.Global.PSI.Memory.Some.Avg10 > psiMax {
		psiMax = curr.Global.PSI.Memory.Some.Avg10
	}
	if curr.Global.PSI.IO.Full.Avg10 > psiMax {
		psiMax = curr.Global.PSI.IO.Full.Avg10
	}
	gs.PSIStallPct = psiMax

	// Traffic: TCP segments + bytes
	if rates != nil {
		gs.TCPSegmentsPerSec = rates.InSegRate + rates.OutSegRate
		var totalBytes float64
		for _, nr := range rates.NetRates {
			totalBytes += nr.RxBytesPS + nr.TxBytesPS
		}
		gs.NetBytesPerSec = totalBytes

		// Error: drops + retrans + resets + OOM
		var totalDrops float64
		for _, nr := range rates.NetRates {
			totalDrops += nr.RxDropsPS + nr.TxDropsPS
		}
		gs.ErrorRate = totalDrops + rates.RetransRate + rates.TCPResetRate + float64(rates.OOMKillDelta)

		// Saturation: max of conntrack%, ephemeral%, runqueue/cores, PSI
		sat := psiMax / 100 // normalize to 0-1
		if curr.Global.Conntrack.Max > 0 {
			ctPct := float64(curr.Global.Conntrack.Count) / float64(curr.Global.Conntrack.Max)
			if ctPct > sat {
				sat = ctPct
			}
		}
		nCPUs := curr.Global.CPU.NumCPUs
		if nCPUs == 0 {
			nCPUs = 1
		}
		rqRatio := curr.Global.CPU.LoadAvg.Load1 / float64(nCPUs)
		if rqRatio > 1 {
			rqRatio = 1
		}
		if rqRatio > sat {
			sat = rqRatio
		}
		gs.SaturationPct = sat * 100
	}

	return gs
}
```

- [ ] **Step 2: Call from AnalyzeRCA**

In the `AnalyzeRCA()` function (in `rca.go`), add a call to `runStatisticalAnalysis` after the blame attribution line (`ComputeBlame`) and before the return:

```go
// Statistical intelligence
runStatisticalAnalysis(result, curr, rates, hist)
```

- [ ] **Step 3: Verify build**

Run: `go build ./...`

Fix any import issues (may need to check that `model.GoldenSignalSummary` etc. are properly referenced). Also check that `NetRate` has `RxBytesPS` and `TxBytesPS` fields — search for the actual field names in the model and adjust if needed.

- [ ] **Step 4: Run existing tests**

Run: `go test ./engine/ -v`
Expected: All existing tests still pass

- [ ] **Step 5: Commit**

```bash
git add engine/rca.go
git commit -m "feat(engine): wire statistical analysis into AnalyzeRCA — baselines, z-scores, correlations, golden signals"
```

---

### Task 8: Add Process Behavior Profiling

**Files:**
- Modify: `engine/rca.go` (add to `runStatisticalAnalysis`)

- [ ] **Step 1: Add process profiling logic**

Add to the end of `runStatisticalAnalysis()`, inside the same function:

```go
	// 8. Process behavior profiling — detect processes deviating from their learned profile
	if rates != nil && len(rates.ProcessRates) > 0 {
		// Track top 20 processes by current resource usage
		type procKey struct {
			pid  int
			comm string
		}
		tracked := 0
		for _, pr := range rates.ProcessRates {
			if tracked >= 20 {
				break
			}
			if pr.CPUPct < 0.5 && pr.ReadMBs+pr.WriteMBs < 0.1 {
				continue // skip idle processes
			}
			tracked++
			cpuID := fmt.Sprintf("proc.%d.cpu", pr.PID)
			ioID := fmt.Sprintf("proc.%d.io", pr.PID)

			hist.Baselines.Update(cpuID, pr.CPUPct)
			hist.Baselines.Update(ioID, pr.ReadMBs+pr.WriteMBs)

			if hist.Baselines.IsAnomaly(cpuID, pr.CPUPct, 3.0) {
				mean, std, _ := hist.Baselines.Get(cpuID)
				result.ProcessAnomalies = append(result.ProcessAnomalies, model.ProcessAnomaly{
					PID: pr.PID, Comm: pr.Comm, Metric: "cpu_pct",
					Current: pr.CPUPct, Baseline: mean, StdDev: std,
					Sigma: hist.Baselines.ZScore(cpuID, pr.CPUPct),
				})
			}
			if hist.Baselines.IsAnomaly(ioID, pr.ReadMBs+pr.WriteMBs, 3.0) {
				mean, std, _ := hist.Baselines.Get(ioID)
				result.ProcessAnomalies = append(result.ProcessAnomalies, model.ProcessAnomaly{
					PID: pr.PID, Comm: pr.Comm, Metric: "io_mbs",
					Current: pr.ReadMBs + pr.WriteMBs, Baseline: mean, StdDev: std,
					Sigma: hist.Baselines.ZScore(ioID, pr.ReadMBs+pr.WriteMBs),
				})
			}
		}
		// Limit to top 5 most anomalous
		if len(result.ProcessAnomalies) > 5 {
			// Sort by sigma descending
			sort.Slice(result.ProcessAnomalies, func(i, j int) bool {
				return result.ProcessAnomalies[i].Sigma > result.ProcessAnomalies[j].Sigma
			})
			result.ProcessAnomalies = result.ProcessAnomalies[:5]
		}
	}
```

Make sure `fmt` and `sort` are imported in `rca.go` (they likely already are).

- [ ] **Step 2: Check ProcessRate struct has needed fields**

Search `model/snapshot.go` for `ProcessRate` to confirm fields: `PID`, `Comm`, `CPUPct`, `ReadMBs`, `WriteMBs`. Adjust field names if different.

- [ ] **Step 3: Verify build**

Run: `go build ./...`

- [ ] **Step 4: Commit**

```bash
git add engine/rca.go
git commit -m "feat(engine): add process behavior profiling — detect per-PID CPU/IO deviations from learned baselines"
```

---

## Chunk 3: Narrative Integration + Seasonal Awareness + Causal Learning

### Task 9: Integrate Statistical Findings into Narrative

**Files:**
- Modify: `engine/narrative.go`

- [ ] **Step 1: Enhance BuildNarrative to include statistical findings**

In `engine/narrative.go`, in the `BuildNarrative()` function, after `n.Impact = estimateImpact(result, curr, rates)` (around line 105), add:

```go
	// Enrich narrative with statistical findings
	if len(result.BaselineAnomalies) > 0 {
		top := result.BaselineAnomalies[0]
		n.Evidence = append(n.Evidence, fmt.Sprintf("- %s deviating %.1f sigma from baseline (%.1f vs normal %.1f)",
			top.EvidenceID, top.Sigma, top.Value, top.Baseline))
	}
	if len(result.Correlations) > 0 {
		top := result.Correlations[0]
		n.Evidence = append(n.Evidence, fmt.Sprintf("- %s and %s correlated (r=%.2f, %s)",
			top.MetricA, top.MetricB, top.Coefficient, top.Strength))
	}
	if len(result.ProcessAnomalies) > 0 {
		top := result.ProcessAnomalies[0]
		n.Evidence = append(n.Evidence, fmt.Sprintf("- %s (PID %d) %s: %.1f vs baseline %.1f (%.1f sigma)",
			top.Comm, top.PID, top.Metric, top.Current, top.Baseline, top.Sigma))
	}
```

- [ ] **Step 2: Verify build**

Run: `go build ./...`

- [ ] **Step 3: Commit**

```bash
git add engine/narrative.go
git commit -m "feat(engine): enrich narrative with baseline anomalies, correlations, and process deviations"
```

---

### Task 10: Add Seasonal Hour-of-Day Awareness

**Files:**
- Modify: `engine/baseline.go` (add seasonal support)

- [ ] **Step 1: Add seasonal baseline to baseline.go**

Add at the end of `engine/baseline.go`:

```go
// SeasonalTracker maintains per-hour-of-day baselines for key metrics.
// This allows the engine to learn that "CPU is always high at 2AM during backups".
type SeasonalTracker struct {
	mu       sync.RWMutex
	hourly   map[string]*[24]ewmaBaseline // metric → 24 per-hour baselines
	alpha    float64
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
	return (value - b.Mean) < nSigma*sd
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
```

- [ ] **Step 2: Add SeasonalTracker to History struct**

In `engine/history.go`, add to History struct:

```go
Seasonal    *SeasonalTracker
```

And initialize in `NewHistory()`:

```go
Seasonal:    NewSeasonalTracker(0.02),
```

- [ ] **Step 3: Wire seasonal updates in runStatisticalAnalysis**

In `engine/rca.go`, in `runStatisticalAnalysis()`, add after the baseline updates (after `hist.Forecaster.Update(id, val)`):

```go
		hour := time.Now().Hour()
		hist.Seasonal.Update(id, val, hour)
```

Make sure `time` is imported.

- [ ] **Step 4: Verify build**

Run: `go build ./...`

- [ ] **Step 5: Commit**

```bash
git add engine/baseline.go engine/history.go engine/rca.go
git commit -m "feat(engine): add per-hour seasonal baseline tracking for recurring pattern suppression"
```

---

### Task 11: Add Causal Strength Learning

**Files:**
- Modify: `engine/causal.go` (add learning state)

- [ ] **Step 1: Add causal learning tracker**

Add at the end of `engine/causal.go`:

```go
// CausalLearner tracks how often causal rules' predictions hold true.
// For each rule, it counts: times both fired, times cause preceded effect.
type CausalLearner struct {
	mu    sync.RWMutex
	stats map[string]*causalRuleStats
}

type causalRuleStats struct {
	BothFired    int64
	CauseFirst   int64
	EffectFirst  int64
}

// NewCausalLearner creates a causal learning tracker.
func NewCausalLearner() *CausalLearner {
	return &CausalLearner{
		stats: make(map[string]*causalRuleStats),
	}
}

// Observe records whether a causal rule's prediction held for this tick.
// causeOnset and effectOnset come from History.signalOnsets.
func (cl *CausalLearner) Observe(rule string, causeFired, effectFired bool, causeFirst bool) {
	cl.mu.Lock()
	defer cl.mu.Unlock()
	s, ok := cl.stats[rule]
	if !ok {
		s = &causalRuleStats{}
		cl.stats[rule] = s
	}
	if causeFired && effectFired {
		s.BothFired++
		if causeFirst {
			s.CauseFirst++
		} else {
			s.EffectFirst++
		}
	}
}

// LearnedWeight returns a blended weight: 70% hardcoded + 30% observed.
// Returns the hardcoded weight if insufficient observations (<20).
func (cl *CausalLearner) LearnedWeight(rule string, hardcodedWeight float64) float64 {
	cl.mu.RLock()
	defer cl.mu.RUnlock()
	s, ok := cl.stats[rule]
	if !ok || s.BothFired < 20 {
		return hardcodedWeight
	}
	observedWeight := float64(s.CauseFirst) / float64(s.BothFired)
	return 0.7*hardcodedWeight + 0.3*observedWeight
}
```

- [ ] **Step 2: Add CausalLearner to History struct**

In `engine/history.go`, add:

```go
CausalLearner *CausalLearner
```

Initialize in `NewHistory()`:

```go
CausalLearner: NewCausalLearner(),
```

- [ ] **Step 3: Feed observations in runStatisticalAnalysis**

In `engine/rca.go`, in `runStatisticalAnalysis()`, add after the correlation section:

```go
	// 9. Feed causal learning observations
	hist.mu.RLock()
	for _, rule := range causalRules {
		_, causeFired := evidenceMap[rule.from]
		_, effectFired := evidenceMap[rule.to]
		if causeFired || effectFired {
			causeOnset, cOK := hist.signalOnsets[rule.from]
			effectOnset, eOK := hist.signalOnsets[rule.to]
			causeFirst := false
			if cOK && eOK {
				causeFirst = !causeOnset.After(effectOnset)
			} else if cOK && !eOK {
				causeFirst = true
			}
			hist.CausalLearner.Observe(rule.rule, causeFired, effectFired, causeFirst)
		}
	}
	hist.mu.RUnlock()
```

- [ ] **Step 4: Verify build**

Run: `go build ./...`

- [ ] **Step 5: Run tests**

Run: `go test ./engine/ -v`
Expected: All pass

- [ ] **Step 6: Commit**

```bash
git add engine/causal.go engine/history.go engine/rca.go
git commit -m "feat(engine): add causal strength learning — track rule prediction accuracy over time"
```

---

## Chunk 4: Version Bump + Final Build + Verification

### Task 12: Version Bump and Final Verification

**Files:**
- Modify: `cmd/root.go` (version)
- Modify: `packaging/xtop_0.31.0-1_amd64/DEBIAN/control` (create)

- [ ] **Step 1: Bump version to 0.31.0**

In `cmd/root.go`, change:
```go
var Version = "0.30.0"
```
to:
```go
var Version = "0.31.0"
```

- [ ] **Step 2: Create packaging directory**

```bash
mkdir -p packaging/xtop_0.31.0-1_amd64/DEBIAN
```

Copy control file from previous version and update Version line to `0.31.0-1`.

- [ ] **Step 3: Full build**

```bash
CGO_ENABLED=0 go build -ldflags="-s -w -X github.com/ftahirops/xtop/cmd.Version=0.31.0" -o xtop .
```

- [ ] **Step 4: Run all tests**

```bash
go test ./engine/ -v
go vet ./...
```

Expected: All pass, no vet warnings

- [ ] **Step 5: Verify binary**

```bash
ls -lh xtop
```

Expected: ~17MB (negligible size increase)

- [ ] **Step 6: Final commit**

```bash
git add cmd/root.go packaging/
git commit -m "chore: bump version to 0.31.0 — statistical RCA intelligence"
```

---

## Summary

| Phase | Tasks | New Code | What It Adds |
|-------|-------|----------|--------------|
| **1: Foundation** | Tasks 1-5 | baseline.go, zscore.go, correlate.go, forecast.go | EWMA baselines, z-score windows, Pearson correlation, Holt forecasting |
| **2: Integration** | Tasks 6-8 | Modify history.go, rca.go | Wire into engine, process profiling, golden signals |
| **3: Enhancement** | Tasks 9-11 | Modify narrative.go, baseline.go, causal.go | Narrative enrichment, seasonal awareness, causal learning |
| **4: Ship** | Task 12 | Version bump | Build + test + package |

**Total new files:** 8 (4 implementation + 4 test)
**Total modified files:** 7
**Estimated new lines:** ~2,100
**Binary size impact:** <20KB
**Memory impact:** <50KB runtime
**External dependencies:** Zero
