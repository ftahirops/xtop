package engine

import (
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// ConfidenceCalibrator learns from incident outcomes whether the RCA's raw
// confidence score tends to be overstated or understated, per bottleneck, and
// multiplies future confidences by a correction factor.
//
// Outcome labels:
//
//   - true_positive: incident lasted ≥ 30 s AND peak_score ≥ 60 → a real event
//   - false_positive: incident ended in < 8 s AND peak_score < 40 → noise
//   - indeterminate: everything in between — excluded from calibration math
//
// The correction factor is a smooth function of observed precision:
//
//   - precision < 0.5  → factor 0.85 (down-weight: too many false positives)
//   - precision ≥ 0.9  → factor 1.10 (up-weight: RCA is reliably right)
//   - in between       → linear interpolation
//
// We cap the factor to [0.6, 1.2] so a single bad day can't silence the RCA
// and a lucky week can't push reported confidence past ceiling. At least 5
// labelled incidents per bottleneck are required before any bias is applied.
//
// Persisted to ~/.xtop/confidence-calibration.json so calibration survives
// restarts. Loaded on startup, saved after each outcome.
type ConfidenceCalibrator struct {
	mu    sync.RWMutex
	stats map[string]*calibrationStats
	path  string
}

type calibrationStats struct {
	TruePositives  int       `json:"tp"`
	FalsePositives int       `json:"fp"`
	Indeterminate  int       `json:"indet"`
	LastOutcomeAt  time.Time `json:"last_at"`
}

// NewConfidenceCalibrator loads any existing calibration state from disk.
func NewConfidenceCalibrator() *ConfidenceCalibrator {
	home, _ := os.UserHomeDir()
	path := filepath.Join(home, ".xtop", "confidence-calibration.json")
	_ = os.MkdirAll(filepath.Dir(path), 0o755)
	c := &ConfidenceCalibrator{
		stats: make(map[string]*calibrationStats),
		path:  path,
	}
	c.load()
	return c
}

// RecordOutcome classifies a completed incident and updates calibration state.
// No-op for incidents without enough signal to classify (returns early on
// indeterminate outcomes so noise can't flatten the bias).
func (c *ConfidenceCalibrator) RecordOutcome(bottleneck string, peakScore int, duration time.Duration) {
	if c == nil || bottleneck == "" {
		return
	}
	label := classifyOutcome(peakScore, duration)
	c.mu.Lock()
	s, ok := c.stats[bottleneck]
	if !ok {
		s = &calibrationStats{}
		c.stats[bottleneck] = s
	}
	switch label {
	case "true_positive":
		s.TruePositives++
	case "false_positive":
		s.FalsePositives++
	default:
		s.Indeterminate++
	}
	s.LastOutcomeAt = time.Now().UTC()
	c.mu.Unlock()
	_ = c.save()
}

// Factor returns the multiplier to apply to a raw confidence score for the
// given bottleneck. Always returns 1.0 until at least 5 labelled incidents
// (TP+FP) have been recorded for that bottleneck.
func (c *ConfidenceCalibrator) Factor(bottleneck string) float64 {
	if c == nil {
		return 1
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	s, ok := c.stats[bottleneck]
	if !ok {
		return 1
	}
	return factorFromStats(s)
}

// ApplyTo returns the calibrated confidence given the raw engine output. The
// result is clamped to [0, 100] to match the model's nominal range.
func (c *ConfidenceCalibrator) ApplyTo(bottleneck string, rawConfidence int) int {
	adj := float64(rawConfidence) * c.Factor(bottleneck)
	switch {
	case adj < 0:
		return 0
	case adj > 100:
		return 100
	}
	return int(math.Round(adj))
}

// Summary returns a human-readable snapshot for use in the post-mortem UI.
func (c *ConfidenceCalibrator) Summary() map[string]CalibrationSummary {
	if c == nil {
		return nil
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	out := make(map[string]CalibrationSummary, len(c.stats))
	for k, s := range c.stats {
		out[k] = CalibrationSummary{
			Bottleneck:     k,
			TruePositives:  s.TruePositives,
			FalsePositives: s.FalsePositives,
			Indeterminate:  s.Indeterminate,
			Factor:         factorFromStats(s),
			Precision:      precisionOf(s),
			LastOutcomeAt:  s.LastOutcomeAt,
		}
	}
	return out
}

// CalibrationSummary is what the post-mortem / fleet UI reads.
type CalibrationSummary struct {
	Bottleneck     string    `json:"bottleneck"`
	TruePositives  int       `json:"tp"`
	FalsePositives int       `json:"fp"`
	Indeterminate  int       `json:"indet"`
	Factor         float64   `json:"factor"`
	Precision      float64   `json:"precision"`
	LastOutcomeAt  time.Time `json:"last_at"`
}

// ── Internals ────────────────────────────────────────────────────────────────

func classifyOutcome(peakScore int, duration time.Duration) string {
	switch {
	case duration >= 30*time.Second && peakScore >= 60:
		return "true_positive"
	case duration < 8*time.Second && peakScore < 40:
		return "false_positive"
	default:
		return "indeterminate"
	}
}

func precisionOf(s *calibrationStats) float64 {
	total := s.TruePositives + s.FalsePositives
	if total == 0 {
		return 0
	}
	return float64(s.TruePositives) / float64(total)
}

func factorFromStats(s *calibrationStats) float64 {
	total := s.TruePositives + s.FalsePositives
	if total < 5 {
		return 1.0 // not enough data to bias
	}
	p := precisionOf(s)
	// Piecewise-linear map: precision [0.5,0.9] → factor [0.85,1.10]
	switch {
	case p <= 0.5:
		return 0.85
	case p >= 0.9:
		return 1.10
	default:
		// Linear interpolation across the useful range.
		t := (p - 0.5) / (0.9 - 0.5)
		return 0.85 + t*(1.10-0.85)
	}
}

// ── Persistence ──────────────────────────────────────────────────────────────

func (c *ConfidenceCalibrator) load() {
	f, err := os.Open(c.path)
	if err != nil {
		return
	}
	defer f.Close()
	var m map[string]*calibrationStats
	if err := json.NewDecoder(f).Decode(&m); err != nil {
		return
	}
	if m != nil {
		c.stats = m
	}
}

func (c *ConfidenceCalibrator) save() error {
	c.mu.RLock()
	snapshot := make(map[string]*calibrationStats, len(c.stats))
	for k, v := range c.stats {
		cp := *v
		snapshot[k] = &cp
	}
	c.mu.RUnlock()
	tmp := c.path + ".tmp"
	f, err := os.Create(tmp)
	if err != nil {
		return err
	}
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	if err := enc.Encode(snapshot); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	f.Close()
	return os.Rename(tmp, c.path)
}
