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
	// Sample variance (divide by n-1) — unbiased estimator.
	// Consistent with Welford's method in baseline.go.
	denom := float64(n)
	if n > 1 {
		denom = float64(n - 1)
	}
	std := math.Sqrt(sq / denom)
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
		if math.Abs(value-mean) < 1e-9 {
			return 0
		}
		// Baseline is flat but value deviates — treat as extreme outlier.
		return math.Copysign(10.0, value-mean)
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
