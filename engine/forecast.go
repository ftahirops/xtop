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
