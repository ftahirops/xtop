package engine

import (
	"math"
	"sync"
)

// holtWintersState tracks Holt-Winters triple exponential smoothing state for one metric.
type holtWintersState struct {
	Level    float64
	Trend    float64
	Seasonal [24]float64 // hourly seasonal factors
	Count    int64
	Ready    bool

	// Forecast accuracy tracking (RMSE)
	lastForecast float64
	errorSum     float64
	errorCount   int64
}

const (
	holtMinSamples = 10
	holtGamma      = 0.1 // seasonal smoothing factor
)

// HoltForecaster provides Holt-Winters triple exponential smoothing forecasting
// with 24-hour seasonal cycle and accuracy tracking.
type HoltForecaster struct {
	mu    sync.RWMutex
	alpha float64 // level smoothing (0.1-0.5)
	beta  float64 // trend smoothing (0.01-0.3)
	state map[string]*holtWintersState
}

// NewHoltForecaster creates a Holt forecaster with given alpha (level) and beta (trend) params.
func NewHoltForecaster(alpha, beta float64) *HoltForecaster {
	return &HoltForecaster{
		alpha: alpha,
		beta:  beta,
		state: make(map[string]*holtWintersState),
	}
}

// Update feeds a new observation for a metric.
func (hf *HoltForecaster) Update(id string, value float64) {
	hf.UpdateWithHour(id, value, -1)
}

// UpdateWithHour feeds a new observation for a metric with the current hour (0-23)
// for seasonal adjustment. Pass hour < 0 to skip seasonality.
func (hf *HoltForecaster) UpdateWithHour(id string, value float64, hour int) {
	hf.mu.Lock()
	defer hf.mu.Unlock()

	s, ok := hf.state[id]
	if !ok {
		s = &holtWintersState{Level: value, Trend: 0, Count: 0}
		// Initialize seasonal factors to 1.0 (neutral)
		for i := range s.Seasonal {
			s.Seasonal[i] = 1.0
		}
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

	// Track forecast accuracy before updating state
	if s.Ready && s.errorCount > 0 {
		err := value - s.lastForecast
		s.errorSum += err * err
	}
	s.errorCount++

	if !s.Ready && s.Count >= holtMinSamples {
		s.Ready = true
	}

	// Deseasonalize if hour is provided
	seasonIdx := -1
	seasonFactor := 1.0
	if hour >= 0 {
		seasonIdx = hour % 24
		seasonFactor = s.Seasonal[seasonIdx]
		if seasonFactor == 0 {
			seasonFactor = 1.0
		}
	}

	deseasonalized := value
	if seasonFactor != 0 {
		deseasonalized = value / seasonFactor
	}

	// Standard Holt update on deseasonalized value
	prevLevel := s.Level
	s.Level = hf.alpha*deseasonalized + (1-hf.alpha)*(s.Level+s.Trend)
	s.Trend = hf.beta*(s.Level-prevLevel) + (1-hf.beta)*s.Trend

	// Update seasonal factor if hour is provided
	if seasonIdx >= 0 && s.Level != 0 {
		s.Seasonal[seasonIdx] = holtGamma*(value/s.Level) + (1-holtGamma)*seasonFactor
	}

	// Store 1-step-ahead forecast for accuracy tracking
	s.lastForecast = s.Level + s.Trend
	if seasonIdx >= 0 {
		// Next observation likely same hour bucket
		s.lastForecast *= seasonFactor
	}
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

// ForecastSeasonal returns the predicted value h steps ahead with seasonal adjustment.
// futureHour is the hour (0-23) of the forecast target.
func (hf *HoltForecaster) ForecastSeasonal(id string, h int, futureHour int) float64 {
	hf.mu.RLock()
	defer hf.mu.RUnlock()
	s, ok := hf.state[id]
	if !ok || s.Count < holtMinSamples {
		return 0
	}
	base := s.Level + float64(h)*s.Trend
	seasonIdx := futureHour % 24
	seasonFactor := s.Seasonal[seasonIdx]
	if seasonFactor == 0 {
		seasonFactor = 1.0
	}
	return base * seasonFactor
}

// ForecastCI returns forecast with 95% confidence interval bounds.
// futureHour is the hour (0-23) of the forecast target; pass -1 to skip seasonality.
func (hf *HoltForecaster) ForecastCI(id string, h int, futureHour int) (mean, lower, upper float64) {
	hf.mu.RLock()
	defer hf.mu.RUnlock()
	s, ok := hf.state[id]
	if !ok || s.Count < holtMinSamples {
		return 0, 0, 0
	}

	if futureHour >= 0 {
		base := s.Level + float64(h)*s.Trend
		seasonIdx := futureHour % 24
		seasonFactor := s.Seasonal[seasonIdx]
		if seasonFactor == 0 {
			seasonFactor = 1.0
		}
		mean = base * seasonFactor
	} else {
		mean = s.Level + float64(h)*s.Trend
	}

	rmse := s.rmse()
	if rmse == 0 {
		rmse = math.Abs(mean) * 0.1 // 10% default uncertainty
	}

	// Error grows with forecast horizon
	stdErr := rmse * math.Sqrt(1.0+float64(h)*0.1)
	z := 1.96 // 95% CI
	lower = mean - z*stdErr
	upper = mean + z*stdErr
	return
}

// RMSE returns the root mean squared error of past forecasts for a metric.
func (hf *HoltForecaster) RMSE(id string) float64 {
	hf.mu.RLock()
	defer hf.mu.RUnlock()
	s, ok := hf.state[id]
	if !ok {
		return 0
	}
	return s.rmse()
}

// rmse computes RMSE from accumulated error (must hold lock).
func (s *holtWintersState) rmse() float64 {
	if s.errorCount < 2 {
		return 0
	}
	return math.Sqrt(s.errorSum / float64(s.errorCount))
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
