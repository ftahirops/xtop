package engine

import (
	"fmt"
	"time"

	"github.com/ftahirops/xtop/model"
)

// AnomalyState tracks when bottlenecks first appeared.
type AnomalyState struct {
	// When the current primary bottleneck first crossed threshold
	PrimaryStart   time.Time
	PrimaryTrigger string // which signal first crossed
	PrimaryName    string // which bottleneck

	// When the current culprit became top
	CulpritStart time.Time
	CulpritName  string

	// Stability: when did health last become OK
	StableStart time.Time
}

// trackAnomaly updates anomaly timing in the analysis result.
func trackAnomaly(result *model.AnalysisResult, hist *History) {
	if hist == nil || hist.anomaly == nil {
		return
	}
	a := hist.anomaly

	now := time.Now()

	if result.PrimaryScore > 0 && result.PrimaryBottleneck != "" {
		// Check if this is the same bottleneck as before
		if a.PrimaryName == result.PrimaryBottleneck {
			// Same bottleneck — report how long it's been active
			result.AnomalyStartedAgo = int(now.Sub(a.PrimaryStart).Seconds())
			result.AnomalyTrigger = a.PrimaryTrigger
		} else {
			// New bottleneck — record start time
			a.PrimaryStart = now
			a.PrimaryName = result.PrimaryBottleneck
			a.PrimaryTrigger = findTrigger(result)
			result.AnomalyStartedAgo = 0
			result.AnomalyTrigger = a.PrimaryTrigger
		}

		// Track culprit
		culpritKey := result.PrimaryCulprit
		if culpritKey == "" {
			culpritKey = result.PrimaryProcess
		}
		if culpritKey != "" {
			if a.CulpritName == culpritKey {
				result.CulpritSinceAgo = int(now.Sub(a.CulpritStart).Seconds())
			} else {
				a.CulpritStart = now
				a.CulpritName = culpritKey
				result.CulpritSinceAgo = 0
			}
		}
	} else {
		// No bottleneck — clear tracking
		a.PrimaryName = ""
		a.PrimaryTrigger = ""
		a.CulpritName = ""
	}

	// Stability tracking
	if result.Health == model.HealthOK {
		if a.StableStart.IsZero() {
			a.StableStart = now
		}
		result.StableSince = int(now.Sub(a.StableStart).Seconds())
	} else {
		a.StableStart = time.Time{} // reset
		result.StableSince = 0
	}

	// Change detection: compare current to ~30s ago
	trackBiggestChange(result, hist)

	// Predictive exhaustion
	trackExhaustion(result, hist)
}

// findTrigger identifies which signal likely triggered the bottleneck.
func findTrigger(result *model.AnalysisResult) string {
	if len(result.RCA) == 0 {
		return ""
	}
	primary := result.RCA[0]
	for _, bottleneck := range result.RCA {
		if bottleneck.Bottleneck == result.PrimaryBottleneck {
			primary = bottleneck
			break
		}
	}
	// Return the first passing check as the trigger
	for _, check := range primary.Checks {
		if check.Passed {
			return fmt.Sprintf("%s: %s", check.Label, check.Value)
		}
	}
	if len(primary.Evidence) > 0 {
		return primary.Evidence[0]
	}
	return ""
}

// trackBiggestChange compares current snapshot to ~30s ago and finds the
// largest metric change. Reports it in result.BiggestChange.
func trackBiggestChange(result *model.AnalysisResult, hist *History) {
	if hist == nil || hist.Len() < 10 {
		return
	}

	// Look back ~30 samples (30s at 1s interval)
	backIdx := hist.Len() - 30
	if backIdx < 0 {
		backIdx = 0
	}
	old := hist.Get(backIdx)
	curr := hist.Latest()
	if old == nil || curr == nil {
		return
	}

	type change struct {
		name string
		pct  float64
	}

	var best change

	// CPU PSI
	if old.Global.PSI.CPU.Some.Avg10 > 0.1 || curr.Global.PSI.CPU.Some.Avg10 > 0.1 {
		diff := curr.Global.PSI.CPU.Some.Avg10 - old.Global.PSI.CPU.Some.Avg10
		if abs(diff) > abs(best.pct) {
			best = change{name: fmt.Sprintf("CPU PSI %+.1f%%", diff), pct: diff}
		}
	}

	// MEM PSI
	if old.Global.PSI.Memory.Full.Avg10 > 0.1 || curr.Global.PSI.Memory.Full.Avg10 > 0.1 {
		diff := curr.Global.PSI.Memory.Full.Avg10 - old.Global.PSI.Memory.Full.Avg10
		if abs(diff) > abs(best.pct) {
			best = change{name: fmt.Sprintf("MEM PSI %+.1f%%", diff), pct: diff}
		}
	}

	// IO PSI
	if old.Global.PSI.IO.Full.Avg10 > 0.1 || curr.Global.PSI.IO.Full.Avg10 > 0.1 {
		diff := curr.Global.PSI.IO.Full.Avg10 - old.Global.PSI.IO.Full.Avg10
		if abs(diff) > abs(best.pct) {
			best = change{name: fmt.Sprintf("IO PSI %+.1f%%", diff), pct: diff}
		}
	}

	// Memory used %
	if old.Global.Memory.Total > 0 && curr.Global.Memory.Total > 0 {
		oldPct := float64(old.Global.Memory.Total-old.Global.Memory.Available) / float64(old.Global.Memory.Total) * 100
		curPct := float64(curr.Global.Memory.Total-curr.Global.Memory.Available) / float64(curr.Global.Memory.Total) * 100
		diff := curPct - oldPct
		if abs(diff) > abs(best.pct) {
			best = change{name: fmt.Sprintf("MEM usage %+.1f%%", diff), pct: diff}
		}
	}

	// Load average
	oldLoad := old.Global.CPU.LoadAvg.Load1
	curLoad := curr.Global.CPU.LoadAvg.Load1
	nCPU := curr.Global.CPU.NumCPUs
	if nCPU == 0 {
		nCPU = 1
	}
	if oldLoad > 0.1 || curLoad > 0.1 {
		// Convert to % of cores
		diffPct := (curLoad - oldLoad) / float64(nCPU) * 100
		if abs(diffPct) > abs(best.pct) {
			best = change{name: fmt.Sprintf("CPU load %+.1f%%", diffPct), pct: diffPct}
		}
	}

	if abs(best.pct) > 2 { // Only report changes > 2%
		result.BiggestChange = best.name
		result.BiggestChangePct = best.pct
	}
}

// trackExhaustion predicts when key resources will be exhausted based on trend.
func trackExhaustion(result *model.AnalysisResult, hist *History) {
	if hist == nil || hist.Len() < 30 {
		return
	}

	curr := hist.Latest()
	if curr == nil {
		return
	}

	// Look back 60 samples for trend
	backIdx := hist.Len() - 60
	if backIdx < 0 {
		backIdx = 0
	}
	old := hist.Get(backIdx)
	if old == nil {
		return
	}

	elapsed := curr.Timestamp.Sub(old.Timestamp).Seconds()
	if elapsed < 10 {
		return
	}

	// Memory available % (decreasing = bad)
	if curr.Global.Memory.Total > 0 && old.Global.Memory.Total > 0 {
		curAvailPct := float64(curr.Global.Memory.Available) / float64(curr.Global.Memory.Total) * 100
		oldAvailPct := float64(old.Global.Memory.Available) / float64(old.Global.Memory.Total) * 100
		trendPerSec := (curAvailPct - oldAvailPct) / elapsed
		if trendPerSec < -0.01 { // Memory decreasing
			minutesLeft := curAvailPct / (-trendPerSec) / 60
			if minutesLeft < 60 && minutesLeft > 0 {
				result.Exhaustions = append(result.Exhaustions, model.ExhaustionPrediction{
					Resource:   "Memory",
					CurrentPct: 100 - curAvailPct,
					TrendPerS:  -trendPerSec,
					EstMinutes: minutesLeft,
				})
			}
		}
	}

	// Swap usage (increasing = bad)
	if curr.Global.Memory.SwapTotal > 0 {
		curPct := float64(curr.Global.Memory.SwapUsed) / float64(curr.Global.Memory.SwapTotal) * 100
		oldPct := float64(0)
		if old.Global.Memory.SwapTotal > 0 {
			oldPct = float64(old.Global.Memory.SwapUsed) / float64(old.Global.Memory.SwapTotal) * 100
		}
		trendPerSec := (curPct - oldPct) / elapsed
		remaining := 100 - curPct
		if trendPerSec > 0.01 && remaining > 0 {
			minutesLeft := remaining / trendPerSec / 60
			if minutesLeft < 60 && minutesLeft > 0 {
				result.Exhaustions = append(result.Exhaustions, model.ExhaustionPrediction{
					Resource:   "Swap",
					CurrentPct: curPct,
					TrendPerS:  trendPerSec,
					EstMinutes: minutesLeft,
				})
			}
		}
	}

	// Conntrack
	if curr.Global.Conntrack.Max > 0 && old.Global.Conntrack.Max > 0 {
		curPct := float64(curr.Global.Conntrack.Count) / float64(curr.Global.Conntrack.Max) * 100
		oldPct := float64(old.Global.Conntrack.Count) / float64(old.Global.Conntrack.Max) * 100
		trendPerSec := (curPct - oldPct) / elapsed
		remaining := 100 - curPct
		if trendPerSec > 0.01 && remaining > 0 {
			minutesLeft := remaining / trendPerSec / 60
			if minutesLeft < 60 && minutesLeft > 0 {
				result.Exhaustions = append(result.Exhaustions, model.ExhaustionPrediction{
					Resource:   "Conntrack",
					CurrentPct: curPct,
					TrendPerS:  trendPerSec,
					EstMinutes: minutesLeft,
				})
			}
		}
	}
}

func abs(x float64) float64 {
	if x < 0 {
		return -x
	}
	return x
}
