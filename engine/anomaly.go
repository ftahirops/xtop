package engine

import (
	"fmt"
	"sort"
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
// largest metric changes. Reports top 5 in result.TopChanges.
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

	oldRates := hist.GetRate(backIdx)
	currRates := hist.GetRate(hist.Len() - 1)

	var changes []model.MetricChange

	addChange := func(name string, oldVal, curVal float64, unit string) {
		diff := curVal - oldVal
		if abs(diff) < 0.5 {
			return
		}
		pct := float64(0)
		if oldVal > 0.1 {
			pct = diff / oldVal * 100
		} else if curVal > 0.1 {
			pct = 100 // new from zero
		}
		changes = append(changes, model.MetricChange{
			Name:     name,
			Delta:    diff,
			DeltaPct: pct,
			Current:  fmt.Sprintf("%.1f%s", curVal, unit),
			Unit:     unit,
			Rising:   diff > 0,
		})
	}

	// System-wide metrics
	addChange("CPU PSI", old.Global.PSI.CPU.Some.Avg10, curr.Global.PSI.CPU.Some.Avg10, "%")
	addChange("MEM PSI", old.Global.PSI.Memory.Full.Avg10, curr.Global.PSI.Memory.Full.Avg10, "%")
	addChange("IO PSI", old.Global.PSI.IO.Full.Avg10, curr.Global.PSI.IO.Full.Avg10, "%")

	if old.Global.Memory.Total > 0 && curr.Global.Memory.Total > 0 {
		oldPct := float64(old.Global.Memory.Total-old.Global.Memory.Available) / float64(old.Global.Memory.Total) * 100
		curPct := float64(curr.Global.Memory.Total-curr.Global.Memory.Available) / float64(curr.Global.Memory.Total) * 100
		addChange("MEM usage", oldPct, curPct, "%")
	}

	nCPU := curr.Global.CPU.NumCPUs
	if nCPU == 0 {
		nCPU = 1
	}
	oldLoadPct := old.Global.CPU.LoadAvg.Load1 / float64(nCPU) * 100
	curLoadPct := curr.Global.CPU.LoadAvg.Load1 / float64(nCPU) * 100
	addChange("run queue", oldLoadPct, curLoadPct, "%")

	// Rate-based metrics (need both old and current rates)
	if oldRates != nil && currRates != nil {
		addChange("swap in", oldRates.SwapInRate, currRates.SwapInRate, " MB/s")
		addChange("retransmits", oldRates.RetransRate, currRates.RetransRate, "/s")
		addChange("ctx switches", oldRates.CtxSwitchRate, currRates.CtxSwitchRate, "/s")

		// Worst disk latency
		oldWorstAwait := float64(0)
		for _, d := range oldRates.DiskRates {
			if d.AvgAwaitMs > oldWorstAwait {
				oldWorstAwait = d.AvgAwaitMs
			}
		}
		curWorstAwait := float64(0)
		curWorstDisk := ""
		for _, d := range currRates.DiskRates {
			if d.AvgAwaitMs > curWorstAwait {
				curWorstAwait = d.AvgAwaitMs
				curWorstDisk = d.Name
			}
		}
		if curWorstDisk != "" {
			addChange(curWorstDisk+" latency", oldWorstAwait, curWorstAwait, "ms")
		}

		// Network drops
		oldDrops := float64(0)
		curDrops := float64(0)
		for _, n := range oldRates.NetRates {
			oldDrops += n.RxDropsPS + n.TxDropsPS
		}
		for _, n := range currRates.NetRates {
			curDrops += n.RxDropsPS + n.TxDropsPS
		}
		addChange("net drops", oldDrops, curDrops, "/s")

		// Per-process IO changes: find biggest IO movers
		oldIO := make(map[string]float64) // comm -> total IO MB/s
		for _, p := range oldRates.ProcessRates {
			oldIO[p.Comm] += p.ReadMBs + p.WriteMBs
		}
		for _, p := range currRates.ProcessRates {
			curIO := p.ReadMBs + p.WriteMBs
			prevIO := oldIO[p.Comm]
			diff := curIO - prevIO
			if abs(diff) > 0.5 {
				pct := float64(0)
				if prevIO > 0.1 {
					pct = diff / prevIO * 100
				} else if curIO > 0.5 {
					pct = 100
				}
				changes = append(changes, model.MetricChange{
					Name:     p.Comm + " IO",
					Delta:    diff,
					DeltaPct: pct,
					Current:  fmt.Sprintf("%.1f MB/s", curIO),
					Unit:     "MB/s",
					Rising:   diff > 0,
				})
			}
		}

		// Per-process CPU changes
		oldCPU := make(map[string]float64)
		for _, p := range oldRates.ProcessRates {
			oldCPU[p.Comm] += p.CPUPct
		}
		for _, p := range currRates.ProcessRates {
			prevCPU := oldCPU[p.Comm]
			diff := p.CPUPct - prevCPU
			if abs(diff) > 5 { // only report >5% CPU changes
				changes = append(changes, model.MetricChange{
					Name:     p.Comm + " CPU",
					Delta:    diff,
					DeltaPct: diff, // already in %
					Current:  fmt.Sprintf("%.1f%%", p.CPUPct),
					Unit:     "%",
					Rising:   diff > 0,
				})
			}
		}
	}

	// Sort by absolute magnitude
	sort.Slice(changes, func(i, j int) bool {
		return abs(changes[i].DeltaPct) > abs(changes[j].DeltaPct)
	})

	// Deduplicate by name prefix (keep most significant)
	seen := make(map[string]bool)
	var top []model.MetricChange
	for _, c := range changes {
		if seen[c.Name] {
			continue
		}
		seen[c.Name] = true
		top = append(top, c)
		if len(top) >= 7 {
			break
		}
	}

	result.TopChanges = top

	// Backwards compat: keep BiggestChange as first entry
	if len(top) > 0 {
		sign := "+"
		if !top[0].Rising {
			sign = ""
		}
		result.BiggestChange = fmt.Sprintf("%s %s%.0f%%", top[0].Name, sign, top[0].DeltaPct)
		result.BiggestChangePct = top[0].DeltaPct
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

	// File descriptors
	if curr.Global.FD.Max > 0 && old.Global.FD.Max > 0 {
		curPct := float64(curr.Global.FD.Allocated) / float64(curr.Global.FD.Max) * 100
		oldPct := float64(old.Global.FD.Allocated) / float64(old.Global.FD.Max) * 100
		trendPerSec := (curPct - oldPct) / elapsed
		remaining := 100 - curPct
		if trendPerSec > 0.01 && remaining > 0 {
			minutesLeft := remaining / trendPerSec / 60
			if minutesLeft < 60 && minutesLeft > 0 {
				result.Exhaustions = append(result.Exhaustions, model.ExhaustionPrediction{
					Resource:   "File descriptors",
					CurrentPct: curPct,
					TrendPerS:  trendPerSec,
					EstMinutes: minutesLeft,
				})
			}
		}
	}

	// Disk filesystem space
	oldMountMap := make(map[string]model.MountStats)
	for _, m := range old.Global.Mounts {
		oldMountMap[m.MountPoint] = m
	}
	for _, m := range curr.Global.Mounts {
		if m.TotalBytes == 0 {
			continue
		}
		om, ok := oldMountMap[m.MountPoint]
		if !ok || om.TotalBytes == 0 {
			continue
		}
		curUsedPct := float64(m.UsedBytes) / float64(m.TotalBytes) * 100
		oldUsedPct := float64(om.UsedBytes) / float64(om.TotalBytes) * 100
		trendPerSec := (curUsedPct - oldUsedPct) / elapsed
		remaining := 100 - curUsedPct
		if trendPerSec > 0.001 && remaining > 0 {
			minutesLeft := remaining / trendPerSec / 60
			if minutesLeft < 120 && minutesLeft > 0 {
				result.Exhaustions = append(result.Exhaustions, model.ExhaustionPrediction{
					Resource:   "Disk " + m.MountPoint,
					CurrentPct: curUsedPct,
					TrendPerS:  trendPerSec,
					EstMinutes: minutesLeft,
				})
			}
		}
	}

	// Ephemeral ports
	curEph := curr.Global.EphemeralPorts
	oldEph := old.Global.EphemeralPorts
	if curEph.RangeHi > 0 && oldEph.RangeHi > 0 {
		ephRange := curEph.RangeHi - curEph.RangeLo + 1
		if ephRange > 0 {
			curPct := float64(curEph.InUse) / float64(ephRange) * 100
			oldPct := float64(oldEph.InUse) / float64(ephRange) * 100
			trendPerSec := (curPct - oldPct) / elapsed
			remaining := 100 - curPct
			if trendPerSec > 0.01 && remaining > 0 {
				minutesLeft := remaining / trendPerSec / 60
				if minutesLeft < 60 && minutesLeft > 0 {
					result.Exhaustions = append(result.Exhaustions, model.ExhaustionPrediction{
						Resource:   "Ephemeral ports",
						CurrentPct: curPct,
						TrendPerS:  trendPerSec,
						EstMinutes: minutesLeft,
					})
				}
			}
		}
	}

	// Slow degradation detection
	trackDegradation(result, hist)
}

// trackDegradation detects slowly worsening trends over 5+ minutes.
func trackDegradation(result *model.AnalysisResult, hist *History) {
	n := hist.Len()
	if n < 300 { // need ~5 minutes of data
		return
	}

	// Compare 5-minute-ago rates to now
	backIdx := n - 300
	if backIdx < 0 {
		backIdx = 0
	}
	oldR := hist.GetRate(backIdx)
	curR := hist.GetRate(n - 1)
	if oldR == nil || curR == nil {
		return
	}

	old := hist.Get(backIdx)
	curr := hist.Latest()
	if old == nil || curr == nil {
		return
	}

	elapsed := curr.Timestamp.Sub(old.Timestamp).Minutes()
	if elapsed < 3 {
		return
	}

	addDeg := func(metric, dir string, ratePerMin float64, unit string) {
		result.Degradations = append(result.Degradations, model.DegradationWarning{
			Metric:    metric,
			Direction: dir,
			Duration:  int(elapsed * 60),
			Rate:      ratePerMin,
			Unit:      unit,
		})
	}

	// IO latency trend
	oldWorstAwait := float64(0)
	curWorstAwait := float64(0)
	for _, d := range oldR.DiskRates {
		if d.AvgAwaitMs > oldWorstAwait {
			oldWorstAwait = d.AvgAwaitMs
		}
	}
	for _, d := range curR.DiskRates {
		if d.AvgAwaitMs > curWorstAwait {
			curWorstAwait = d.AvgAwaitMs
		}
	}
	if curWorstAwait > oldWorstAwait+2 && curWorstAwait > 5 {
		ratePerMin := (curWorstAwait - oldWorstAwait) / elapsed
		if ratePerMin > 0.5 {
			addDeg("IO latency", "rising", ratePerMin, "ms/min")
		}
	}

	// Memory available % trend (decreasing)
	if old.Global.Memory.Total > 0 && curr.Global.Memory.Total > 0 {
		oldAvail := float64(old.Global.Memory.Available) / float64(old.Global.Memory.Total) * 100
		curAvail := float64(curr.Global.Memory.Available) / float64(curr.Global.Memory.Total) * 100
		if curAvail < oldAvail-2 {
			ratePerMin := (oldAvail - curAvail) / elapsed
			if ratePerMin > 0.1 {
				addDeg("Memory available", "falling", ratePerMin, "%/min")
			}
		}
	}

	// Swap usage trend (increasing)
	if curr.Global.Memory.SwapTotal > 0 {
		curSwapPct := float64(curr.Global.Memory.SwapUsed) / float64(curr.Global.Memory.SwapTotal) * 100
		oldSwapPct := float64(0)
		if old.Global.Memory.SwapTotal > 0 {
			oldSwapPct = float64(old.Global.Memory.SwapUsed) / float64(old.Global.Memory.SwapTotal) * 100
		}
		if curSwapPct > oldSwapPct+1 {
			ratePerMin := (curSwapPct - oldSwapPct) / elapsed
			if ratePerMin > 0.05 {
				addDeg("Swap usage", "rising", ratePerMin, "%/min")
			}
		}
	}

	// Retransmit trend
	if curR.RetransRate > oldR.RetransRate+5 && curR.RetransRate > 10 {
		ratePerMin := (curR.RetransRate - oldR.RetransRate) / elapsed
		if ratePerMin > 1 {
			addDeg("TCP retransmits", "rising", ratePerMin, "/s/min")
		}
	}
}

func abs(x float64) float64 {
	if x < 0 {
		return -x
	}
	return x
}
