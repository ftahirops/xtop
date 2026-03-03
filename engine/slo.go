package engine

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/ftahirops/xtop/model"
)

// SLOPolicy defines a service level objective.
type SLOPolicy struct {
	Name      string  // e.g. "p95<200ms"
	Metric    string  // "p95", "p99", "cpu", "mem", "io_psi", "cpu_psi"
	Operator  string  // "<", ">", "<=", ">="
	Threshold float64 // threshold value
	Unit      string  // "ms", "%", ""
}

// SLOResult holds the evaluation of one SLO policy.
type SLOResult struct {
	Policy   SLOPolicy
	Current  float64
	Passed   bool
	Message  string
	CheckedAt time.Time
}

// SLOConfig holds SLO configuration.
type SLOConfig struct {
	Policies []SLOPolicyConfig `json:"policies,omitempty"`
}

// SLOPolicyConfig is a serializable SLO policy.
type SLOPolicyConfig struct {
	Name string `json:"name"` // e.g. "cpu<80%", "io_psi<5%"
}

// ParseSLOFlag parses a flag string like "p95<200ms" or "cpu<80%" into an SLOPolicy.
func ParseSLOFlag(s string) (SLOPolicy, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return SLOPolicy{}, fmt.Errorf("empty SLO")
	}

	// Find operator position
	opIdx := -1
	opLen := 0
	for i, c := range s {
		switch c {
		case '<':
			opIdx = i
			opLen = 1
			if i+1 < len(s) && s[i+1] == '=' {
				opLen = 2
			}
		case '>':
			opIdx = i
			opLen = 1
			if i+1 < len(s) && s[i+1] == '=' {
				opLen = 2
			}
		}
		if opIdx >= 0 {
			break
		}
	}
	if opIdx < 0 {
		return SLOPolicy{}, fmt.Errorf("no operator in SLO %q (use <, >, <=, >=)", s)
	}

	metric := strings.TrimSpace(s[:opIdx])
	op := s[opIdx : opIdx+opLen]
	valueStr := strings.TrimSpace(s[opIdx+opLen:])

	// Parse value and unit
	unit := ""
	numStr := valueStr
	for _, u := range []string{"ms", "%", "s", "MB", "GB"} {
		if strings.HasSuffix(valueStr, u) {
			unit = u
			numStr = strings.TrimSuffix(valueStr, u)
			break
		}
	}
	threshold, err := strconv.ParseFloat(numStr, 64)
	if err != nil {
		return SLOPolicy{}, fmt.Errorf("invalid threshold in SLO %q: %w", s, err)
	}

	return SLOPolicy{
		Name:      s,
		Metric:    strings.ToLower(metric),
		Operator:  op,
		Threshold: threshold,
		Unit:      unit,
	}, nil
}

// EvaluateSLOs evaluates a list of SLO policies against current metrics.
func EvaluateSLOs(policies []SLOPolicy, snap *model.Snapshot, rates *model.RateSnapshot, result *model.AnalysisResult) []SLOResult {
	results := make([]SLOResult, 0, len(policies))
	now := time.Now()

	for _, pol := range policies {
		current := metricValue(pol.Metric, snap, rates, result)
		passed := checkThreshold(current, pol.Operator, pol.Threshold)

		msg := fmt.Sprintf("%s=%s%.1f%s %s %.1f%s",
			pol.Metric, colorSLO(passed), current, "", pol.Operator, pol.Threshold, pol.Unit)
		if !passed {
			msg += " VIOLATED"
		}

		results = append(results, SLOResult{
			Policy:    pol,
			Current:   current,
			Passed:    passed,
			Message:   msg,
			CheckedAt: now,
		})
	}
	return results
}

// metricValue returns the current value for a named metric.
func metricValue(name string, snap *model.Snapshot, rates *model.RateSnapshot, result *model.AnalysisResult) float64 {
	switch name {
	case "cpu", "cpu_busy":
		if rates != nil {
			return rates.CPUBusyPct
		}
	case "mem", "mem_pct":
		if snap.Global.Memory.Total > 0 {
			return float64(snap.Global.Memory.Total-snap.Global.Memory.Available) / float64(snap.Global.Memory.Total) * 100
		}
	case "io_psi":
		return snap.Global.PSI.IO.Full.Avg10
	case "cpu_psi":
		return snap.Global.PSI.CPU.Some.Avg10
	case "mem_psi":
		return snap.Global.PSI.Memory.Full.Avg10
	case "iowait":
		if rates != nil {
			return rates.CPUIOWaitPct
		}
	case "retrans":
		if rates != nil {
			return rates.RetransRate
		}
	case "score":
		if result != nil {
			return float64(result.PrimaryScore)
		}
	case "load1":
		return snap.Global.CPU.LoadAvg.Load1
	case "load5":
		return snap.Global.CPU.LoadAvg.Load5
	}
	return 0
}

// checkThreshold evaluates value <op> threshold.
func checkThreshold(value float64, op string, threshold float64) bool {
	switch op {
	case "<":
		return value < threshold
	case "<=":
		return value <= threshold
	case ">":
		return value > threshold
	case ">=":
		return value >= threshold
	}
	return false
}

func colorSLO(passed bool) string {
	if passed {
		return ""
	}
	return ""
}
