package engine

import (
	"fmt"
	"math"
	"os"
	"sort"
	"strings"
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

	// Deployment correlation: find recently started processes near anomaly onset
	if result.PrimaryScore > 0 && result.AnomalyStartedAgo > 0 && result.AnomalyStartedAgo < 120 {
		trackDeployCorrelation(result, hist)
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

	addChange := func(name string, oldVal, curVal float64, unit string, minAbsDiff float64) {
		diff := curVal - oldVal
		if abs(diff) < minAbsDiff {
			return
		}
		pct := float64(0)
		if oldVal > 0.1 {
			pct = diff / oldVal * 100
		} else if curVal > 0.1 {
			pct = 100 // new from zero
		}
		// Skip small percentage changes — reduces noise from normal fluctuations
		if abs(pct) < 30 {
			return
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
	addChange("CPU PSI", old.Global.PSI.CPU.Some.Avg10, curr.Global.PSI.CPU.Some.Avg10, "%", 2)
	addChange("MEM PSI", old.Global.PSI.Memory.Full.Avg10, curr.Global.PSI.Memory.Full.Avg10, "%", 2)
	addChange("IO PSI", old.Global.PSI.IO.Full.Avg10, curr.Global.PSI.IO.Full.Avg10, "%", 2)

	if old.Global.Memory.Total > 0 && curr.Global.Memory.Total > 0 {
		oldPct := float64(old.Global.Memory.Total-old.Global.Memory.Available) / float64(old.Global.Memory.Total) * 100
		curPct := float64(curr.Global.Memory.Total-curr.Global.Memory.Available) / float64(curr.Global.Memory.Total) * 100
		addChange("MEM usage", oldPct, curPct, "%", 3)
	}

	nCPU := curr.Global.CPU.NumCPUs
	if nCPU == 0 {
		nCPU = 1
	}
	// Use Load5 instead of Load1 for smoother run queue tracking
	oldLoadPct := old.Global.CPU.LoadAvg.Load5 / float64(nCPU) * 100
	curLoadPct := curr.Global.CPU.LoadAvg.Load5 / float64(nCPU) * 100
	addChange("run queue", oldLoadPct, curLoadPct, "%", 10)

	// Rate-based metrics (need both old and current rates)
	if oldRates != nil && currRates != nil {
		addChange("swap in", oldRates.SwapInRate, currRates.SwapInRate, " MB/s", 0.5)
		addChange("retransmits", oldRates.RetransRate, currRates.RetransRate, "/s", 5)
		addChange("ctx switches", oldRates.CtxSwitchRate, currRates.CtxSwitchRate, "/s", 5000)

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
			addChange(curWorstDisk+" latency", oldWorstAwait, curWorstAwait, "ms", 5)
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
		addChange("net drops", oldDrops, curDrops, "/s", 1)

		// CLOSE_WAIT count change
		addChange("CLOSE_WAIT", float64(old.Global.TCPStates.CloseWait),
			float64(curr.Global.TCPStates.CloseWait), " sockets", 10)

		// Per-process IO changes: find biggest IO movers
		oldIO := make(map[string]float64) // comm -> total IO MB/s
		for _, p := range oldRates.ProcessRates {
			oldIO[p.Comm] += p.ReadMBs + p.WriteMBs
		}
		for _, p := range currRates.ProcessRates {
			curIO := p.ReadMBs + p.WriteMBs
			prevIO := oldIO[p.Comm]
			// Only report if at least one side had meaningful IO (>1 MB/s)
			if curIO < 1 && prevIO < 1 {
				continue
			}
			addChange(p.Comm+" IO", prevIO, curIO, " MB/s", 1)
		}

		// Per-process CPU changes
		oldCPU := make(map[string]float64)
		for _, p := range oldRates.ProcessRates {
			oldCPU[p.Comm] += p.CPUPct
		}
		for _, p := range currRates.ProcessRates {
			prevCPU := oldCPU[p.Comm]
			addChange(p.Comm+" CPU", prevCPU, p.CPUPct, "%", 20)
		}
	}

	// New process detection: flag processes that appeared since ~30s ago
	// with meaningful CPU or IO activity
	if oldRates != nil && currRates != nil {
		oldComms := make(map[string]bool)
		for _, p := range oldRates.ProcessRates {
			oldComms[p.Comm] = true
		}
		for _, p := range currRates.ProcessRates {
			if oldComms[p.Comm] {
				continue
			}
			if isKernelThread(p.Comm) {
				continue
			}
			if p.CPUPct > 5 || (p.ReadMBs+p.WriteMBs) > 1 {
				desc := fmt.Sprintf("%.1f%% CPU", p.CPUPct)
				if p.ReadMBs+p.WriteMBs > 0.1 {
					desc = fmt.Sprintf("%.1f MB/s IO", p.ReadMBs+p.WriteMBs)
				}
				changes = append(changes, model.MetricChange{
					Name:     p.Comm + " NEW",
					Delta:    p.CPUPct,
					DeltaPct: 100, // new = 100% change
					Current:  desc,
					Unit:     "",
					Rising:   true,
				})
			}
		}
	}

	// Compute z-scores across all changes for statistical significance
	if len(changes) > 1 {
		// Mean and stddev of absolute DeltaPct
		var sum, sumSq float64
		for _, c := range changes {
			v := abs(c.DeltaPct)
			sum += v
			sumSq += v * v
		}
		n := float64(len(changes))
		mean := sum / n
		variance := sumSq/n - mean*mean
		if variance < 0 {
			variance = 0
		}
		stddev := math.Sqrt(variance)
		if stddev > 0.01 {
			for i := range changes {
				changes[i].ZScore = (abs(changes[i].DeltaPct) - mean) / stddev
			}
		}
	}

	// Sort by z-score (falling back to DeltaPct if z-scores are zero)
	sort.Slice(changes, func(i, j int) bool {
		if changes[i].ZScore != 0 || changes[j].ZScore != 0 {
			return changes[i].ZScore > changes[j].ZScore
		}
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

	// CLOSE_WAIT exhaustion prediction
	cwCur := curr.Global.TCPStates.CloseWait
	cwOld := old.Global.TCPStates.CloseWait
	if cwCur > 50 && cwCur > cwOld {
		cwGrowthPerSec := float64(cwCur-cwOld) / elapsed
		if cwGrowthPerSec > 0.01 {
			remaining := float64(10000 - cwCur) // predict time to 10K sockets
			if remaining > 0 {
				minutesLeft := remaining / cwGrowthPerSec / 60
				if minutesLeft < 120 && minutesLeft > 0 {
					result.Exhaustions = append(result.Exhaustions, model.ExhaustionPrediction{
						Resource:   "CLOSE_WAIT sockets",
						CurrentPct: float64(cwCur),
						TrendPerS:  cwGrowthPerSec,
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

// trackDeployCorrelation finds processes that started recently (within 2 minutes
// of anomaly onset) and reports them as potential deployment triggers.
func trackDeployCorrelation(result *model.AnalysisResult, hist *History) {
	curr := hist.Latest()
	if curr == nil {
		return
	}

	// Read system uptime to convert starttime ticks to wall-clock age
	uptimeContent, err := readFileString("/proc/uptime")
	if err != nil {
		return
	}
	fields := strings.Fields(uptimeContent)
	if len(fields) < 1 {
		return
	}
	uptimeSec := parseFloat(fields[0])
	if uptimeSec < 1 {
		return
	}

	const hz = 100.0 // USER_HZ
	bestAge := 999999.0
	bestComm := ""
	bestPID := 0

	for _, p := range curr.Processes {
		if p.StartTimeTicks == 0 {
			continue
		}
		if isKernelThread(p.Comm) {
			continue
		}
		// Process age in seconds
		procAge := uptimeSec - float64(p.StartTimeTicks)/hz
		if procAge < 0 {
			continue
		}
		// Only consider processes started in the last 5 minutes
		if procAge > 300 {
			continue
		}
		// Skip very short-lived processes (< 2 seconds)
		if procAge < 2 {
			continue
		}
		// Prefer the most recently started non-trivial process
		if procAge < bestAge {
			bestAge = procAge
			bestComm = p.Comm
			bestPID = p.PID
		}
	}

	if bestComm != "" {
		result.RecentDeploy = bestComm
		result.RecentDeployPID = bestPID
		result.RecentDeployAge = int(bestAge)
	}
}

// readFileString reads a file to string (for /proc files in engine package).
func readFileString(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// parseFloat parses a float64 from string, returning 0 on error.
func parseFloat(s string) float64 {
	f := 0.0
	fmt.Sscanf(s, "%f", &f)
	return f
}

func abs(x float64) float64 {
	if x < 0 {
		return -x
	}
	return x
}
