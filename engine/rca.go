package engine

import (
	"fmt"
	"sort"
	"strings"

	"github.com/ftahirops/xtop/model"
)

const (
	BottleneckIO      = "IO Starvation"
	BottleneckMemory  = "Memory Pressure"
	BottleneckCPU     = "CPU Contention"
	BottleneckNetwork = "Network Overload"

	// Minimum evidence groups required to declare a bottleneck
	minEvidenceGroups = 2
)

// AnalyzeRCA runs all bottleneck detectors and builds the full analysis result.
func AnalyzeRCA(curr *model.Snapshot, rates *model.RateSnapshot, hist *History) *model.AnalysisResult {
	result := &model.AnalysisResult{}

	result.RCA = []model.RCAEntry{
		analyzeIO(curr, rates),
		analyzeMemory(curr, rates),
		analyzeCPU(curr, rates),
		analyzeNetwork(curr, rates),
	}
	sort.Slice(result.RCA, func(i, j int) bool {
		return result.RCA[i].Score > result.RCA[j].Score
	})

	// Primary + secondary
	if len(result.RCA) > 0 && result.RCA[0].Score > 0 {
		primary := result.RCA[0]
		result.PrimaryBottleneck = primary.Bottleneck
		result.PrimaryScore = primary.Score
		result.PrimaryEvidence = primary.Evidence
		result.PrimaryChain = primary.Chain
		result.PrimaryCulprit = primary.TopCgroup
		result.PrimaryPID = primary.TopPID
		result.PrimaryProcess = primary.TopProcess
	}

	// Health level — based on score AND evidence quality
	if result.PrimaryScore >= 60 {
		primary := result.RCA[0]
		if primary.EvidenceGroups >= minEvidenceGroups {
			result.Health = model.HealthCritical
			result.Confidence = computeConfidence(primary)
		} else {
			// High score but insufficient evidence → inconclusive
			result.Health = model.HealthInconclusive
			result.Confidence = computeConfidence(primary)
		}
	} else if result.PrimaryScore >= 25 {
		primary := result.RCA[0]
		if primary.EvidenceGroups >= minEvidenceGroups {
			result.Health = model.HealthDegraded
			result.Confidence = computeConfidence(primary)
		} else {
			result.Health = model.HealthInconclusive
			result.Confidence = computeConfidence(primary)
		}
	} else {
		result.Health = model.HealthOK
		result.Confidence = 95
	}

	// Propagate system identity
	result.SysInfo = curr.SysInfo

	// DiskGuard state
	if rates != nil && len(rates.MountRates) > 0 {
		result.DiskGuardMounts = rates.MountRates
		result.DiskGuardWorst = WorstDiskGuardState(rates.MountRates)
	}
	result.DiskGuardMode = "Monitor"

	// Capacity
	result.Capacities = ComputeCapacity(curr, rates)

	// Top owners
	result.CPUOwners, result.MemOwners, result.IOOwners, result.NetOwners = ComputeOwners(curr, rates)

	// Warnings
	result.Warnings = ComputeWarnings(curr, rates)

	// Next risk
	for _, w := range result.Warnings {
		if w.Severity == "warn" || w.Severity == "crit" {
			result.NextRisk = fmt.Sprintf("%s: %s (%s)", w.Signal, w.Detail, w.Value)
			break
		}
	}
	if result.NextRisk == "" && len(result.Warnings) > 0 {
		w := result.Warnings[0]
		result.NextRisk = fmt.Sprintf("%s trend (%s)", w.Signal, w.Value)
	}

	// Causal chain — only if sufficient evidence
	if result.PrimaryScore > 0 && len(result.RCA) > 0 && result.RCA[0].EvidenceGroups >= minEvidenceGroups {
		result.CausalChain = buildCausalChain(curr, rates, result)
	}

	// Anomaly tracking
	trackAnomaly(result, hist)

	// Actions
	result.Actions = SuggestActions(result)

	return result
}

// clamp returns min(v/max, 1.0)
func clamp(v, max float64) float64 {
	if max <= 0 {
		return 0
	}
	r := v / max
	if r > 1 {
		return 1
	}
	if r < 0 {
		return 0
	}
	return r
}

// computeConfidence uses evidence group count.
// 1 group = 30%, 2 groups = 50%, 3 = 65%, 4 = 80%, 5+ = 90%+
func computeConfidence(rca model.RCAEntry) int {
	g := rca.EvidenceGroups
	if g <= 0 {
		return 20
	}
	conf := 30 + 20*(g-1)
	if conf > 98 {
		conf = 98
	}
	return conf
}

// ---------- IO Score ----------
// Evidence groups: PSI, D-state, Disk latency, Dirty pages
func analyzeIO(curr *model.Snapshot, rates *model.RateSnapshot) model.RCAEntry {
	r := model.RCAEntry{Bottleneck: BottleneckIO}

	ioSome := curr.Global.PSI.IO.Some.Avg10 / 100
	ioFull := curr.Global.PSI.IO.Full.Avg10 / 100

	dCount := 0
	var dProcs []string
	for _, p := range curr.Processes {
		if p.State == "D" {
			dCount++
			if len(dProcs) < 3 {
				dProcs = append(dProcs, fmt.Sprintf("%s(%d)", p.Comm, p.PID))
			}
		}
	}

	var worstAwait, worstUtil float64
	var worstDev string
	if rates != nil {
		for _, d := range rates.DiskRates {
			if d.AvgAwaitMs > worstAwait {
				worstAwait = d.AvgAwaitMs
				worstDev = d.Name
			}
			if d.UtilPct > worstUtil {
				worstUtil = d.UtilPct
			}
		}
	}

	// Dirty pages
	mem := curr.Global.Memory
	var dirtyPct float64
	if mem.Total > 0 {
		dirtyPct = float64(mem.Dirty) / float64(mem.Total) * 100
	}

	// --- Evidence group checks ---
	groupsPassed := 0

	// Group 1: PSI
	psiPassed := ioSome > 0.05 || ioFull > 0.01
	r.Checks = append(r.Checks, model.EvidenceCheck{
		Group: "PSI", Label: "IO PSI elevated",
		Passed: psiPassed,
		Value:  fmt.Sprintf("some=%.1f%% full=%.1f%%", ioSome*100, ioFull*100),
		Confidence: "M", Source: "procfs", Strength: clamp(ioSome, 0.5),
	})
	if psiPassed {
		groupsPassed++
	}

	// Group 2: D-state
	dPassed := dCount > 0
	r.Checks = append(r.Checks, model.EvidenceCheck{
		Group: "D-state", Label: "D-state tasks",
		Passed: dPassed,
		Value:  fmt.Sprintf("%d tasks", dCount),
		Confidence: "M", Source: "procfs", Strength: clamp(float64(dCount), 10),
	})
	if dPassed {
		groupsPassed++
	}

	// Group 3: Disk latency
	diskPassed := worstAwait > 10 || worstUtil > 80
	devStr := worstDev
	if devStr == "" {
		devStr = "none"
	}
	r.Checks = append(r.Checks, model.EvidenceCheck{
		Group: "Disk", Label: "Disk latency/util",
		Passed: diskPassed,
		Value:  fmt.Sprintf("%s await=%.0fms util=%.0f%%", devStr, worstAwait, worstUtil),
		Confidence: "M", Source: "sysfs", Strength: clamp(worstAwait, 50),
	})
	if diskPassed {
		groupsPassed++
	}

	// Group 4: Dirty/writeback
	dirtyPassed := dirtyPct > 5
	r.Checks = append(r.Checks, model.EvidenceCheck{
		Group: "Dirty", Label: "Dirty pages elevated",
		Passed: dirtyPassed,
		Value:  fmt.Sprintf("%.1f%% of RAM", dirtyPct),
		Confidence: "L", Source: "procfs", Strength: clamp(dirtyPct, 20),
	})
	if dirtyPassed {
		groupsPassed++
	}

	// Group 5: Filesystem full
	var worstFreePct float64 = 100
	var worstMount string
	if rates != nil {
		for _, mr := range rates.MountRates {
			if mr.FreePct < worstFreePct {
				worstFreePct = mr.FreePct
				worstMount = mr.MountPoint
			}
		}
	}
	fsFull := worstFreePct < 15
	fsVal := "all OK"
	if worstMount != "" {
		fsVal = fmt.Sprintf("%s %.0f%% free", worstMount, worstFreePct)
	}
	r.Checks = append(r.Checks, model.EvidenceCheck{
		Group: "FSFull", Label: "Filesystem space low",
		Passed: fsFull,
		Value:  fsVal,
		Confidence: "M", Source: "sysfs", Strength: clamp(100-worstFreePct, 90),
	})
	if fsFull {
		groupsPassed++
	}

	r.EvidenceGroups = groupsPassed

	// Compute weighted score
	score := 35*clamp(ioSome, 0.5) +
		25*clamp(ioFull, 0.1) +
		15*clamp(float64(dCount), 10) +
		15*clamp(worstAwait, 50) +
		10*clamp(worstUtil, 95)

	// Filesystem full contributes to IO bottleneck
	if fsFull {
		score += 10 * clamp(100-worstFreePct, 90)
	}

	r.Score = int(score)

	// TRUST GATE: require minimum 2 evidence groups to report
	if groupsPassed < minEvidenceGroups {
		r.Score = 0
	}

	// D-state high boost (only if other evidence too)
	if dCount >= 10 && groupsPassed >= minEvidenceGroups && r.Score < 60 {
		r.Score = 60
	}

	// Noise suppression
	if r.Score < 20 {
		r.Score = 0
	}

	cap100(&r.Score)

	// Evidence strings (for display)
	if ioSome > 0.05 {
		r.Evidence = append(r.Evidence, fmt.Sprintf("IO PSI some=%.1f%%", ioSome*100))
	}
	if ioFull > 0.01 {
		r.Evidence = append(r.Evidence, fmt.Sprintf("IO PSI full=%.1f%%", ioFull*100))
	}
	if dCount > 0 {
		r.Evidence = append(r.Evidence, fmt.Sprintf("%d D-state tasks [%s]", dCount, strings.Join(dProcs, ", ")))
	}
	if worstAwait > 5 {
		r.Evidence = append(r.Evidence, fmt.Sprintf("Disk %s await=%.0fms util=%.0f%%", worstDev, worstAwait, worstUtil))
	}
	if dirtyPct > 5 {
		r.Evidence = append(r.Evidence, fmt.Sprintf("Dirty=%.1f%% of RAM (%s)", dirtyPct, formatB(mem.Dirty)))
	}
	if fsFull {
		r.Evidence = append(r.Evidence, fmt.Sprintf("%s %.0f%% full (%.0f%% free)", worstMount, 100-worstFreePct, worstFreePct))
	}

	// Chain
	if r.Score > 0 && groupsPassed >= minEvidenceGroups {
		if worstAwait > 20 {
			r.Chain = append(r.Chain, fmt.Sprintf("%s latency %.0fms", worstDev, worstAwait))
		}
		if ioFull > 0.01 {
			r.Chain = append(r.Chain, fmt.Sprintf("IO PSI full=%.1f%%", ioFull*100))
		}
		if dCount > 0 {
			r.Chain = append(r.Chain, fmt.Sprintf("D-state=%d", dCount))
		}
		r.Chain = append(r.Chain, "app latency risk")
	}

	// Culprit
	findIOCulprit(curr, rates, &r)
	return r
}

// ---------- Memory Score ----------
// Evidence groups: PSI, Low available, Swap active, Direct reclaim, Major faults, OOM
func analyzeMemory(curr *model.Snapshot, rates *model.RateSnapshot) model.RCAEntry {
	r := model.RCAEntry{Bottleneck: BottleneckMemory}

	memSome := curr.Global.PSI.Memory.Some.Avg10 / 100
	memFull := curr.Global.PSI.Memory.Full.Avg10 / 100

	mem := curr.Global.Memory
	if mem.Total == 0 {
		return r
	}
	availPct := float64(mem.Available) / float64(mem.Total) * 100

	var swapIOMBs, directPct, majFaultRate, directReclaimRate float64
	if rates != nil {
		swapIOMBs = rates.SwapInRate + rates.SwapOutRate
		totalScan := rates.DirectReclaimRate + rates.KswapdRate
		if totalScan > 0 {
			directPct = rates.DirectReclaimRate / totalScan
		}
		majFaultRate = rates.MajFaultRate
		directReclaimRate = rates.DirectReclaimRate
	}

	// --- Evidence group checks ---
	groupsPassed := 0

	// Group 1: PSI
	psiPassed := memSome > 0.05 || memFull > 0.01
	r.Checks = append(r.Checks, model.EvidenceCheck{
		Group: "PSI", Label: "MEM PSI elevated",
		Passed: psiPassed,
		Value:  fmt.Sprintf("some=%.1f%% full=%.1f%%", memSome*100, memFull*100),
		Confidence: "M", Source: "procfs", Strength: clamp(memSome, 0.5),
	})
	if psiPassed {
		groupsPassed++
	}

	// Group 2: Available low
	availLow := availPct < 20
	r.Checks = append(r.Checks, model.EvidenceCheck{
		Group: "Available", Label: "MemAvailable low",
		Passed: availLow,
		Value:  fmt.Sprintf("%.1f%% (%s free)", availPct, formatB(mem.Available)),
		Confidence: "M", Source: "procfs", Strength: clamp(100-availPct, 100),
	})
	if availLow {
		groupsPassed++
	}

	// Group 3: Swap active
	swapActive := swapIOMBs > 0.1
	r.Checks = append(r.Checks, model.EvidenceCheck{
		Group: "Swap", Label: "Swap IO active",
		Passed: swapActive,
		Value:  fmt.Sprintf("%.1f MB/s", swapIOMBs),
		Confidence: "M", Source: "procfs", Strength: clamp(swapIOMBs, 50),
	})
	if swapActive {
		groupsPassed++
	}

	// Group 4: Direct reclaim
	reclaimActive := directReclaimRate > 0
	r.Checks = append(r.Checks, model.EvidenceCheck{
		Group: "Reclaim", Label: "Direct reclaim active",
		Passed: reclaimActive,
		Value:  fmt.Sprintf("%.0f pages/s (ratio=%.0f%%)", directReclaimRate, directPct*100),
		Confidence: "M", Source: "procfs", Strength: clamp(directReclaimRate, 1000),
	})
	if reclaimActive {
		groupsPassed++
	}

	// Group 5: Major faults
	majFaultHigh := majFaultRate > 10
	r.Checks = append(r.Checks, model.EvidenceCheck{
		Group: "MajFault", Label: "Major faults elevated",
		Passed: majFaultHigh,
		Value:  fmt.Sprintf("%.0f/s", majFaultRate),
		Confidence: "M", Source: "procfs", Strength: clamp(majFaultRate, 500),
	})
	if majFaultHigh {
		groupsPassed++
	}

	// Group 6: OOM
	oomDetected := curr.Global.VMStat.OOMKill > 0
	r.Checks = append(r.Checks, model.EvidenceCheck{
		Group: "OOM", Label: "OOM kills detected",
		Passed: oomDetected,
		Value:  fmt.Sprintf("%d cumulative", curr.Global.VMStat.OOMKill),
		Confidence: "H", Source: "procfs", Strength: 1.0,
	})
	if oomDetected {
		groupsPassed++
	}

	r.EvidenceGroups = groupsPassed

	// Weighted score
	score := 30*clamp(memSome, 0.5) +
		25*clamp(memFull, 0.1) +
		20*clamp(swapIOMBs, 50) +
		15*clamp(directPct, 0.6) +
		10*clamp(majFaultRate, 500)

	r.Score = int(score)

	// TRUST GATE: require minimum 2 evidence groups to report
	if groupsPassed < minEvidenceGroups {
		r.Score = 0
	}

	// Gate: if avail > 25% and PSI low → cap 20
	if availPct > 25 && memSome < 0.1 && memFull < 0.02 {
		if r.Score > 20 {
			r.Score = 20
		}
	}

	// OOM override: if OOM detected and other evidence, floor at 70
	if oomDetected && groupsPassed >= minEvidenceGroups && r.Score < 70 {
		r.Score = 70
	}

	if r.Score < 20 {
		r.Score = 0
	}

	cap100(&r.Score)

	// Evidence strings
	if memSome > 0.05 {
		r.Evidence = append(r.Evidence, fmt.Sprintf("MEM PSI some=%.1f%%", memSome*100))
	}
	if memFull > 0.01 {
		r.Evidence = append(r.Evidence, fmt.Sprintf("MEM PSI full=%.1f%%", memFull*100))
	}
	if availPct < 15 {
		r.Evidence = append(r.Evidence, fmt.Sprintf("MemAvailable=%.1f%% (%s)", availPct, formatB(mem.Available)))
	}
	if swapIOMBs > 0.1 {
		r.Evidence = append(r.Evidence, fmt.Sprintf("Swap IO=%.1f MB/s", swapIOMBs))
	}
	if directReclaimRate > 0 {
		r.Evidence = append(r.Evidence, fmt.Sprintf("Direct reclaim=%.0f pages/s (ratio=%.0f%%)", directReclaimRate, directPct*100))
	}
	if majFaultRate > 10 {
		r.Evidence = append(r.Evidence, fmt.Sprintf("Major faults=%.0f/s", majFaultRate))
	}
	if oomDetected {
		r.Evidence = append(r.Evidence, fmt.Sprintf("OOM kill counter=%d", curr.Global.VMStat.OOMKill))
	}

	// Chain
	if r.Score > 0 && groupsPassed >= minEvidenceGroups {
		r.Chain = append(r.Chain, "Memory pressure detected")
		if swapActive {
			r.Chain = append(r.Chain, "System actively swapping")
		}
		if reclaimActive {
			r.Chain = append(r.Chain, "Kernel reclaiming pages synchronously")
		}
		r.Chain = append(r.Chain, "Allocation stall risk")
	}

	// Top offender: cgroup closest to limit (skip root)
	var bestRatio float64
	for _, cg := range curr.Cgroups {
		if cg.Path == "/" || cg.Path == "" {
			continue
		}
		if cg.MemLimit > 0 && cg.MemCurrent > 0 {
			ratio := float64(cg.MemCurrent) / float64(cg.MemLimit)
			if ratio > bestRatio {
				bestRatio = ratio
				r.TopCgroup = cg.Path
			}
		}
	}

	// Top process by RSS (skip kernel threads)
	var maxRSS uint64
	for _, p := range curr.Processes {
		if isKernelThread(p.Comm) {
			continue
		}
		if p.RSS > maxRSS {
			maxRSS = p.RSS
			r.TopProcess = p.Comm
			r.TopPID = p.PID
		}
	}

	return r
}

// ---------- CPU Score ----------
// Evidence groups: PSI, Run queue, Context switches, Throttling, Steal
func analyzeCPU(curr *model.Snapshot, rates *model.RateSnapshot) model.RCAEntry {
	r := model.RCAEntry{Bottleneck: BottleneckCPU}

	cpuSome := curr.Global.PSI.CPU.Some.Avg10 / 100
	cpuFull := curr.Global.PSI.CPU.Full.Avg10 / 100

	nCPUs := curr.Global.CPU.NumCPUs
	if nCPUs == 0 {
		nCPUs = 1
	}
	running := float64(curr.Global.CPU.LoadAvg.Running)
	rqRatio := running / float64(nCPUs)

	var ctxRate, busyPct, stealPct float64
	var maxThrottlePct float64
	var maxThrottleCg string

	if rates != nil {
		ctxRate = rates.CtxSwitchRate
		busyPct = rates.CPUBusyPct
		stealPct = rates.CPUStealPct
		for _, cg := range rates.CgroupRates {
			if cg.ThrottlePct > maxThrottlePct {
				maxThrottlePct = cg.ThrottlePct
				maxThrottleCg = cg.Path
			}
		}
	}

	// --- Evidence group checks ---
	groupsPassed := 0

	// Group 1: PSI
	psiPassed := cpuSome > 0.05 || cpuFull > 0.01
	r.Checks = append(r.Checks, model.EvidenceCheck{
		Group: "PSI", Label: "CPU PSI elevated",
		Passed: psiPassed,
		Value:  fmt.Sprintf("some=%.1f%% full=%.1f%%", cpuSome*100, cpuFull*100),
		Confidence: "M", Source: "procfs", Strength: clamp(cpuSome, 0.5),
	})
	if psiPassed {
		groupsPassed++
	}

	// Group 2: Run queue saturation
	rqPassed := rqRatio > 1.5
	r.Checks = append(r.Checks, model.EvidenceCheck{
		Group: "RunQueue", Label: "Run queue saturated",
		Passed: rqPassed,
		Value:  fmt.Sprintf("%.1f ratio (%d runnable / %d cores)", rqRatio, int(running), nCPUs),
		Confidence: "M", Source: "procfs", Strength: clamp(rqRatio, 3.0),
	})
	if rqPassed {
		groupsPassed++
	}

	// Group 3: Context switches
	csPerCore := ctxRate / float64(nCPUs)
	csPassed := csPerCore > 30000
	r.Checks = append(r.Checks, model.EvidenceCheck{
		Group: "CtxSwitch", Label: "Context switches high",
		Passed: csPassed,
		Value:  fmt.Sprintf("%.0f/s (%.0f/core)", ctxRate, csPerCore),
		Confidence: "L", Source: "procfs", Strength: clamp(csPerCore, 100000),
	})
	if csPassed {
		groupsPassed++
	}

	// Group 4: Throttling
	thrPassed := maxThrottlePct > 5
	thrVal := "none"
	if maxThrottleCg != "" {
		thrVal = fmt.Sprintf("%s %.1f%%", maxThrottleCg, maxThrottlePct)
	}
	r.Checks = append(r.Checks, model.EvidenceCheck{
		Group: "Throttle", Label: "Cgroup throttling",
		Passed: thrPassed,
		Value:  thrVal,
		Confidence: "M", Source: "sysfs", Strength: clamp(maxThrottlePct, 50),
	})
	if thrPassed {
		groupsPassed++
	}

	// Group 5: Steal
	stealPassed := stealPct > 5
	r.Checks = append(r.Checks, model.EvidenceCheck{
		Group: "Steal", Label: "CPU steal (hypervisor)",
		Passed: stealPassed,
		Value:  fmt.Sprintf("%.1f%%", stealPct),
		Confidence: "H", Source: "procfs", Strength: clamp(stealPct, 25),
	})
	if stealPassed {
		groupsPassed++
	}

	r.EvidenceGroups = groupsPassed

	// Weighted score
	score := 35*clamp(cpuSome, 0.5) +
		20*clamp(cpuFull, 0.1) +
		15*clamp(rqRatio, 3.0) +
		15*clamp(ctxRate, 150000) +
		15*clamp(maxThrottlePct/100, 0.5)

	r.Score = int(score)

	// TRUST GATE: require minimum 2 evidence groups to report
	if groupsPassed < minEvidenceGroups {
		r.Score = 0
	}

	// Gate: if busy < 50% and PSI low → cap at 30
	if busyPct < 50 && cpuSome < 0.10 && cpuFull < 0.02 {
		if r.Score > 30 {
			r.Score = 30
		}
	}

	// Noise suppression: need real signals
	if cpuSome < 0.03 && cpuFull < 0.01 && rqRatio < 1.2 && maxThrottlePct < 5 && ctxRate < 30000 {
		r.Score = 0
	}

	// Steal bonus (only with other evidence)
	if stealPassed && groupsPassed >= minEvidenceGroups {
		r.Score += 10
	}

	if r.Score < 20 {
		r.Score = 0
	}

	cap100(&r.Score)

	// Evidence strings
	if cpuSome > 0.05 {
		r.Evidence = append(r.Evidence, fmt.Sprintf("CPU PSI some=%.1f%%", cpuSome*100))
	}
	if cpuFull > 0.01 {
		r.Evidence = append(r.Evidence, fmt.Sprintf("CPU PSI full=%.1f%%", cpuFull*100))
	}
	if rqPassed {
		r.Evidence = append(r.Evidence, fmt.Sprintf("Run queue ratio=%.1f (%d runnable / %d cores)", rqRatio, int(running), nCPUs))
	}
	if csPassed {
		r.Evidence = append(r.Evidence, fmt.Sprintf("Context switches=%.0f/s (%.0f/core)", ctxRate, csPerCore))
	}
	if thrPassed {
		r.Evidence = append(r.Evidence, fmt.Sprintf("Cgroup %s throttled %.1f%%", maxThrottleCg, maxThrottlePct))
		r.TopCgroup = maxThrottleCg
	}
	if stealPassed {
		r.Evidence = append(r.Evidence, fmt.Sprintf("CPU steal=%.1f%% (hypervisor)", stealPct))
	}

	// Chain
	if r.Score > 0 && groupsPassed >= minEvidenceGroups {
		r.Chain = append(r.Chain, "CPU contention detected")
		if rqPassed {
			r.Chain = append(r.Chain, fmt.Sprintf("More runnable threads (%d) than CPUs (%d)", int(running), nCPUs))
		}
		r.Chain = append(r.Chain, "Scheduling latency risk")
	}

	// Top CPU process (skip kernel threads)
	if rates != nil {
		var maxCPU float64
		for _, p := range rates.ProcessRates {
			if isKernelThread(p.Comm) {
				continue
			}
			if p.CPUPct > maxCPU {
				maxCPU = p.CPUPct
				r.TopProcess = p.Comm
				r.TopPID = p.PID
			}
		}
	}

	return r
}

// ---------- Network Score ----------
// Evidence groups: Drops, Retransmits, Conntrack, SoftIRQ, TCP state issues
func analyzeNetwork(curr *model.Snapshot, rates *model.RateSnapshot) model.RCAEntry {
	r := model.RCAEntry{Bottleneck: BottleneckNetwork}
	if rates == nil {
		return r
	}

	// Compute aggregates
	var totalDrops, totalErrors float64
	for _, nr := range rates.NetRates {
		totalDrops += nr.RxDropsPS + nr.TxDropsPS
		totalErrors += nr.RxErrorsPS + nr.TxErrorsPS
	}
	retransRate := rates.RetransRate

	var conntrackPct float64
	ct := curr.Global.Conntrack
	if ct.Max > 0 {
		conntrackPct = float64(ct.Count) / float64(ct.Max)
	}

	softirqPct := rates.CPUSoftIRQPct / 100
	st := curr.Global.TCPStates

	// --- Evidence group checks ---
	groupsPassed := 0

	// Group 1: Drops
	dropsPassed := totalDrops > 1
	r.Checks = append(r.Checks, model.EvidenceCheck{
		Group: "Drops", Label: "Packet drops",
		Passed: dropsPassed,
		Value:  fmt.Sprintf("%.0f/s", totalDrops),
		Confidence: "M", Source: "procfs", Strength: clamp(totalDrops, 100),
	})
	if dropsPassed {
		groupsPassed++
	}

	// Group 2: Retransmits
	retransPassed := retransRate > 5
	r.Checks = append(r.Checks, model.EvidenceCheck{
		Group: "Retrans", Label: "TCP retransmits",
		Passed: retransPassed,
		Value:  fmt.Sprintf("%.0f/s", retransRate),
		Confidence: "M", Source: "procfs", Strength: clamp(retransRate, 100),
	})
	if retransPassed {
		groupsPassed++
	}

	// Group 3: Conntrack
	ctPassed := conntrackPct > 0.7
	r.Checks = append(r.Checks, model.EvidenceCheck{
		Group: "Conntrack", Label: "Conntrack table pressure",
		Passed: ctPassed,
		Value:  fmt.Sprintf("%.0f%% (%d/%d)", conntrackPct*100, ct.Count, ct.Max),
		Confidence: "M", Source: "procfs", Strength: clamp(conntrackPct, 1.0),
	})
	if ctPassed {
		groupsPassed++
	}

	// Group 4: SoftIRQ
	siPassed := rates.CPUSoftIRQPct > 5
	r.Checks = append(r.Checks, model.EvidenceCheck{
		Group: "SoftIRQ", Label: "SoftIRQ CPU overhead",
		Passed: siPassed,
		Value:  fmt.Sprintf("%.1f%%", rates.CPUSoftIRQPct),
		Confidence: "L", Source: "procfs", Strength: clamp(rates.CPUSoftIRQPct, 25),
	})
	if siPassed {
		groupsPassed++
	}

	// Group 5: TCP state issues
	tcpStatePassed := st.TimeWait > 5000 || st.CloseWait > 100 || st.SynSent > 50
	tcpStateVal := fmt.Sprintf("TW=%d CW=%d SYN=%d", st.TimeWait, st.CloseWait, st.SynSent)
	r.Checks = append(r.Checks, model.EvidenceCheck{
		Group: "TCPState", Label: "TCP state anomaly",
		Passed: tcpStatePassed,
		Value:  tcpStateVal,
		Confidence: "L", Source: "procfs", Strength: clamp(float64(st.TimeWait), 10000),
	})
	if tcpStatePassed {
		groupsPassed++
	}

	// Group 6: Errors
	errorsPassed := totalErrors > 1
	r.Checks = append(r.Checks, model.EvidenceCheck{
		Group: "Errors", Label: "Network errors",
		Passed: errorsPassed,
		Value:  fmt.Sprintf("%.0f/s", totalErrors),
		Confidence: "M", Source: "procfs", Strength: clamp(totalErrors, 100),
	})
	if errorsPassed {
		groupsPassed++
	}

	// Group 7: Ephemeral port exhaustion
	eph := curr.Global.EphemeralPorts
	ephRange := eph.RangeHi - eph.RangeLo + 1
	var ephPct float64
	if ephRange > 0 {
		ephPct = float64(eph.InUse) / float64(ephRange) * 100
	}
	ephPassed := ephPct > 50
	r.Checks = append(r.Checks, model.EvidenceCheck{
		Group: "Ephemeral", Label: "Ephemeral port pressure",
		Passed: ephPassed,
		Value:  fmt.Sprintf("%.0f%% (%d/%d)", ephPct, eph.InUse, ephRange),
		Confidence: "M", Source: "procfs", Strength: clamp(ephPct, 100),
	})
	if ephPassed {
		groupsPassed++
	}

	r.EvidenceGroups = groupsPassed

	// Weighted score
	score := 35*clamp(totalDrops, 100) +
		25*clamp(retransRate, 100) +
		15*clamp(conntrackPct, 1.0) +
		15*clamp(softirqPct, 0.25) +
		10*clamp(float64(curr.Global.Sockets.TCPOrphan), 1000)

	r.Score = int(score)

	// TRUST GATE: require minimum 2 evidence groups to report
	if groupsPassed < minEvidenceGroups {
		r.Score = 0
	}

	// Gate: drops and retrans near zero → cap 25
	if totalDrops < 1 && retransRate < 5 {
		if r.Score > 25 {
			r.Score = 25
		}
	}

	// Boost: drops high + softirq high (only with evidence)
	if dropsPassed && siPassed && groupsPassed >= minEvidenceGroups {
		r.Score += 10
	}

	if r.Score < 20 {
		r.Score = 0
	}

	cap100(&r.Score)

	// Evidence strings
	if dropsPassed {
		r.Evidence = append(r.Evidence, fmt.Sprintf("Network drops=%.0f/s", totalDrops))
	}
	if retransPassed {
		r.Evidence = append(r.Evidence, fmt.Sprintf("TCP retransmits=%.0f/s", retransRate))
	}
	if ctPassed {
		r.Evidence = append(r.Evidence, fmt.Sprintf("Conntrack=%.0f%% (%d/%d)", conntrackPct*100, ct.Count, ct.Max))
	}
	if siPassed {
		r.Evidence = append(r.Evidence, fmt.Sprintf("SoftIRQ CPU=%.1f%%", rates.CPUSoftIRQPct))
	}
	if tcpStatePassed {
		if st.TimeWait > 5000 {
			r.Evidence = append(r.Evidence, fmt.Sprintf("TIME_WAIT=%d (port exhaustion risk)", st.TimeWait))
		}
		if st.CloseWait > 100 {
			r.Evidence = append(r.Evidence, fmt.Sprintf("CLOSE_WAIT=%d (app not closing)", st.CloseWait))
		}
	}
	if errorsPassed {
		r.Evidence = append(r.Evidence, fmt.Sprintf("Network errors=%.0f/s", totalErrors))
	}
	if ephPassed {
		r.Evidence = append(r.Evidence, fmt.Sprintf("Ephemeral ports=%.0f%% (%d/%d)", ephPct, eph.InUse, ephRange))
	}

	// Chain
	if r.Score > 0 && groupsPassed >= minEvidenceGroups {
		if retransPassed {
			r.Chain = append(r.Chain, fmt.Sprintf("retrans=%.0f/s", retransRate))
		}
		if dropsPassed {
			r.Chain = append(r.Chain, fmt.Sprintf("drops=%.0f/s", totalDrops))
		}
		r.Chain = append(r.Chain, "connection quality risk")
	}

	return r
}

func findIOCulprit(curr *model.Snapshot, rates *model.RateSnapshot, r *model.RCAEntry) {
	// Find top cgroup (skip root)
	if rates != nil {
		var maxIO float64
		for _, cg := range rates.CgroupRates {
			if cg.Path == "/" || cg.Path == "" {
				continue
			}
			total := cg.IORateMBs + cg.IOWRateMBs
			if total > maxIO {
				maxIO = total
				r.TopCgroup = cg.Path
			}
		}
	}

	// 1st priority: find top IO user-space process by actual IO rate
	if rates != nil {
		var maxIO float64
		for _, pr := range rates.ProcessRates {
			if isKernelThread(pr.Comm) {
				continue
			}
			total := pr.ReadMBs + pr.WriteMBs
			if total > maxIO {
				maxIO = total
				r.TopProcess = pr.Comm
				r.TopPID = pr.PID
			}
		}
		if r.TopProcess != "" {
			return
		}
	}

	// 2nd priority: D-state user-space process
	for _, p := range curr.Processes {
		if p.State == "D" && !isKernelThread(p.Comm) {
			r.TopProcess = p.Comm
			r.TopPID = p.PID
			return
		}
	}

	// 3rd: any user-space process with high IO bytes
	var maxIO uint64
	for _, p := range curr.Processes {
		if isKernelThread(p.Comm) {
			continue
		}
		total := p.ReadBytes + p.WriteBytes
		if total > maxIO {
			maxIO = total
			r.TopProcess = p.Comm
			r.TopPID = p.PID
		}
	}
}

// isKernelThread returns true for kernel workers and filesystem daemons
// that do IO on behalf of user processes (not the real culprits).
func isKernelThread(comm string) bool {
	// Kernel threads typically have / in name or known prefixes
	kernelPrefixes := []string{
		"kworker/", "jbd2/", "ksoftirqd/", "kswapd", "khugepaged",
		"kcompactd", "writeback", "flush-", "dm-", "md/", "loop",
		"irq/", "migration/", "rcu_", "watchdog/", "cpuhp/",
		"netns", "kdevtmpfs", "oom_reaper", "kauditd", "kthreadd",
		"scsi_", "nvme-", "blkcg_punt",
	}
	for _, prefix := range kernelPrefixes {
		if strings.HasPrefix(comm, prefix) {
			return true
		}
	}
	// Brackets indicate kernel thread: [kworker/0:1]
	if strings.HasPrefix(comm, "[") && strings.HasSuffix(comm, "]") {
		return true
	}
	return false
}

func buildCausalChain(snap *model.Snapshot, rates *model.RateSnapshot, result *model.AnalysisResult) string {
	if result.PrimaryScore == 0 {
		return ""
	}
	var parts []string
	switch result.PrimaryBottleneck {
	case BottleneckIO:
		if rates != nil {
			for _, d := range rates.DiskRates {
				if d.UtilPct > 50 || d.AvgAwaitMs > 20 {
					parts = append(parts, fmt.Sprintf("%s latency %.0fms", d.Name, d.AvgAwaitMs))
					break
				}
			}
		}
		if snap.Global.PSI.IO.Full.Avg10 > 0 {
			parts = append(parts, fmt.Sprintf("IO PSI full=%.1f%%", snap.Global.PSI.IO.Full.Avg10))
		}
		dCount := 0
		for _, p := range snap.Processes {
			if p.State == "D" {
				dCount++
			}
		}
		if dCount > 0 {
			parts = append(parts, fmt.Sprintf("D-state=%d", dCount))
		}
		parts = append(parts, fmt.Sprintf("load=%.1f", snap.Global.CPU.LoadAvg.Load1))
		parts = append(parts, "app latency risk")
	case BottleneckMemory:
		if snap.Global.PSI.Memory.Full.Avg10 > 0 {
			parts = append(parts, fmt.Sprintf("MEM PSI full=%.1f%%", snap.Global.PSI.Memory.Full.Avg10))
		}
		if rates != nil && rates.DirectReclaimRate > 0 {
			parts = append(parts, "direct reclaim active")
		}
		if rates != nil && (rates.SwapInRate > 0 || rates.SwapOutRate > 0) {
			parts = append(parts, fmt.Sprintf("swap in=%.1f out=%.1f MB/s", rates.SwapInRate, rates.SwapOutRate))
		}
		var availPct float64
		if snap.Global.Memory.Total > 0 {
			availPct = float64(snap.Global.Memory.Available) / float64(snap.Global.Memory.Total) * 100
		}
		parts = append(parts, fmt.Sprintf("avail=%.0f%%", availPct))
		parts = append(parts, "allocation stall risk")
	case BottleneckCPU:
		if snap.Global.PSI.CPU.Some.Avg10 > 0 {
			parts = append(parts, fmt.Sprintf("CPU PSI some=%.1f%%", snap.Global.PSI.CPU.Some.Avg10))
		}
		parts = append(parts, fmt.Sprintf("runnable=%d vs %d cores", snap.Global.CPU.LoadAvg.Running, snap.Global.CPU.NumCPUs))
		if rates != nil && rates.CtxSwitchRate > 50000 {
			parts = append(parts, fmt.Sprintf("ctxsw=%.0f/s", rates.CtxSwitchRate))
		}
		parts = append(parts, "scheduling latency risk")
	case BottleneckNetwork:
		if rates != nil && rates.RetransRate > 5 {
			parts = append(parts, fmt.Sprintf("retrans=%.0f/s", rates.RetransRate))
		}
		if rates != nil {
			for _, nr := range rates.NetRates {
				if nr.RxDropsPS+nr.TxDropsPS > 0 {
					parts = append(parts, fmt.Sprintf("%s drops=%.0f/s", nr.Name, nr.RxDropsPS+nr.TxDropsPS))
					break
				}
			}
		}
		parts = append(parts, "connection quality risk")
	}
	// Build culprit string: prefer process(PID), fallback to cgroup name
	culprit := ""
	if result.PrimaryProcess != "" && result.PrimaryPID > 0 {
		culprit = fmt.Sprintf("%s(%d)", result.PrimaryProcess, result.PrimaryPID)
	} else if result.PrimaryCulprit != "" && result.PrimaryCulprit != "/" {
		culprit = cleanCgroupName(result.PrimaryCulprit)
	}
	if culprit != "" {
		parts = append(parts, fmt.Sprintf("culprit: %s", culprit))
	}
	if len(parts) == 0 {
		return ""
	}
	return strings.Join(parts, " -> ")
}

// cleanCgroupName extracts a human-readable name from a cgroup path.
// "/system.slice/docker-abc123.scope" → "docker-abc123"
// "/user.slice/user-1000.slice" → "user-1000"
func cleanCgroupName(path string) string {
	if path == "" || path == "/" {
		return path
	}
	// Take the last path component
	parts := strings.Split(strings.TrimSuffix(path, "/"), "/")
	name := parts[len(parts)-1]
	// Remove common suffixes
	name = strings.TrimSuffix(name, ".scope")
	name = strings.TrimSuffix(name, ".service")
	name = strings.TrimSuffix(name, ".slice")
	if name == "" {
		return path
	}
	return name
}

func cap100(score *int) {
	if *score > 100 {
		*score = 100
	}
}

