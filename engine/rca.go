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

	// Compute v2 domain confidence for each entry
	for i := range result.RCA {
		result.RCA[i].DomainConf = domainConfidence(result.RCA[i].EvidenceV2)
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

	// Health level — v2: uses trust gate + domain confidence
	if result.PrimaryScore >= 60 {
		primary := result.RCA[0]
		if v2TrustGate(primary.EvidenceV2) {
			result.Health = model.HealthCritical
			result.Confidence = int(primary.DomainConf * 100)
		} else {
			result.Health = model.HealthInconclusive
			result.Confidence = int(primary.DomainConf * 100)
		}
	} else if result.PrimaryScore >= 25 {
		primary := result.RCA[0]
		if v2TrustGate(primary.EvidenceV2) {
			result.Health = model.HealthDegraded
			result.Confidence = int(primary.DomainConf * 100)
		} else {
			result.Health = model.HealthInconclusive
			result.Confidence = int(primary.DomainConf * 100)
		}
	} else {
		result.Health = model.HealthOK
		result.Confidence = 95
	}

	// Alert state machine: apply sustained-threshold filtering
	if hist != nil && hist.alert != nil {
		hasCritEvidence := false
		if len(result.RCA) > 0 {
			for _, e := range result.RCA[0].EvidenceV2 {
				if e.ID == "mem.oom.kills" && e.Strength >= 0.35 && e.Value > 0 {
					hasCritEvidence = true
					break
				}
			}
			if rates != nil {
				for _, mr := range rates.MountRates {
					if mr.ETASeconds > 0 && mr.ETASeconds < 300 {
						hasCritEvidence = true
						break
					}
				}
			}
		}
		result.Health = hist.alert.Update(result.Health, hasCritEvidence)
	}

	// Propagate system identity
	result.SysInfo = curr.SysInfo

	// Copy CLOSE_WAIT leakers for actions access
	result.CloseWaitLeakers = curr.Global.CloseWaitLeakers

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

	// Causal chain — v2 DAG
	if result.PrimaryScore > 0 && len(result.RCA) > 0 && result.RCA[0].EvidenceGroups >= minEvidenceGroups {
		if dag := buildCausalDAG(result); dag != nil {
			result.CausalDAG = dag
			result.CausalChain = dag.LinearChain
		}
	}

	// Anomaly tracking
	trackAnomaly(result, hist)

	// Hidden latency detection: metrics look fine but threads are waiting
	detectHiddenLatency(curr, rates, result)

	// Actions
	result.Actions = SuggestActions(result)

	// Narrative engine: build human-readable root cause explanation
	result.Narrative = BuildNarrative(result, curr, rates)

	// Temporal causality: update signal onsets and build chain
	UpdateSignalOnsets(hist, result)
	result.TemporalChain = BuildTemporalChain(result, hist)
	if result.Narrative != nil && result.TemporalChain != nil {
		result.Narrative.Temporal = result.TemporalChain.Summary
	}

	// Blame attribution: identify top offenders
	result.Blame = ComputeBlame(result, curr, rates)

	return result
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

	// Filesystem space
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

	// --- v2 evidence ---
	w, c := threshold("io.psi", 5, 20)
	r.EvidenceV2 = append(r.EvidenceV2, emitEvidence("io.psi", model.DomainIO,
		ioSome*100, w, c, true, 0.9,
		fmt.Sprintf("IO PSI some=%.1f%% full=%.1f%%", ioSome*100, ioFull*100), "avg10",
		nil, nil))
	w, c = threshold("io.dstate", 1, 10)
	r.EvidenceV2 = append(r.EvidenceV2, emitEvidence("io.dstate", model.DomainIO,
		float64(dCount), w, c, true, 0.7,
		fmt.Sprintf("%d D-state tasks", dCount), "1s",
		nil, nil))
	w, c = threshold("io.disk.latency", 20, 80)
	r.EvidenceV2 = append(r.EvidenceV2, emitEvidence("io.disk.latency", model.DomainIO,
		worstAwait, w, c, false, 0.7,
		fmt.Sprintf("%s await=%.0fms", worstDev, worstAwait), "1s",
		nil, map[string]string{"device": worstDev}))
	w, c = threshold("io.disk.util", 70, 95)
	r.EvidenceV2 = append(r.EvidenceV2, emitEvidence("io.disk.util", model.DomainIO,
		worstUtil, w, c, false, 0.7,
		fmt.Sprintf("%s util=%.0f%%", worstDev, worstUtil), "1s",
		nil, map[string]string{"device": worstDev}))
	w, c = threshold("io.writeback", 5, 20)
	r.EvidenceV2 = append(r.EvidenceV2, emitEvidence("io.writeback", model.DomainIO,
		dirtyPct, w, c, false, 0.6,
		fmt.Sprintf("dirty pages=%.1f%% of RAM", dirtyPct), "1s",
		nil, nil))
	w, c = threshold("io.fsfull", 85, 95)
	r.EvidenceV2 = append(r.EvidenceV2, emitEvidence("io.fsfull", model.DomainIO,
		100-worstFreePct, w, c, true, 0.9,
		fmt.Sprintf("%s %.0f%% used", worstMount, 100-worstFreePct), "1s",
		nil, map[string]string{"mount": worstMount}))

	// v2 switchover: weighted scoring replaces clamp-based
	v2Score := weightedDomainScore(r.EvidenceV2)
	if !v2TrustGate(r.EvidenceV2) {
		v2Score = 0
	}
	r.Score = int(v2Score)
	if dCount >= 10 && v2TrustGate(r.EvidenceV2) && r.Score < 60 {
		r.Score = 60
	}
	if r.Score < 20 {
		r.Score = 0
	}
	cap100(&r.Score)
	r.EvidenceGroups = evidenceGroupsFired(r.EvidenceV2, 0.35)
	r.Checks = evidenceToChecks(r.EvidenceV2)

	// Evidence strings
	if ioSome > 0.05 {
		r.Evidence = append(r.Evidence, fmt.Sprintf("IO PSI some=%.1f%%", ioSome*100))
	}
	if ioFull > 0.01 {
		r.Evidence = append(r.Evidence, fmt.Sprintf("IO PSI full=%.1f%%", ioFull*100))
	}
	if dCount > 0 {
		r.Evidence = append(r.Evidence, fmt.Sprintf("D-state tasks=%d (%s)", dCount, strings.Join(dProcs, ", ")))
	}
	if worstAwait > 20 {
		r.Evidence = append(r.Evidence, fmt.Sprintf("%s await=%.0fms", worstDev, worstAwait))
	}
	if worstUtil > 70 {
		r.Evidence = append(r.Evidence, fmt.Sprintf("%s util=%.0f%%", worstDev, worstUtil))
	}
	if dirtyPct > 5 {
		r.Evidence = append(r.Evidence, fmt.Sprintf("Dirty pages=%.1f%% of RAM", dirtyPct))
	}
	if fsFull {
		r.Evidence = append(r.Evidence, fmt.Sprintf("%s %.0f%% used", worstMount, 100-worstFreePct))
	}

	// Chain
	if r.Score > 0 && r.EvidenceGroups >= minEvidenceGroups {
		r.Chain = append(r.Chain, "IO starvation detected")
		if dCount > 0 {
			r.Chain = append(r.Chain, fmt.Sprintf("%d tasks in D-state", dCount))
		}
		if worstAwait > 20 {
			r.Chain = append(r.Chain, fmt.Sprintf("%s latency=%.0fms", worstDev, worstAwait))
		}
		r.Chain = append(r.Chain, "Application latency risk")
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

	// --- v2 evidence ---
	usedPct := 100 - availPct

	// Use delta-based OOM detection: only fire if OOM kills happened since last tick
	var oomDelta uint64
	if rates != nil {
		oomDelta = rates.OOMKillDelta
	}
	oomDetected := oomDelta > 0
	oomVal := float64(oomDelta)

	w, c := threshold("mem.psi", 5, 20)
	w2, c2 := threshold("mem.available.low", 85, 95)
	w3, c3 := threshold("mem.reclaim.direct", 10, 500)
	w4, c4 := threshold("mem.swap.activity", 2, 50)
	w5, c5 := threshold("mem.major.faults", 10, 200)
	w6, c6 := threshold("mem.oom.kills", 1, 1)
	r.EvidenceV2 = append(r.EvidenceV2,
		emitEvidence("mem.psi", model.DomainMemory,
			memSome*100, w, c, true, 0.9,
			fmt.Sprintf("MEM PSI some=%.1f%% full=%.1f%%", memSome*100, memFull*100), "avg10",
			nil, nil),
		emitEvidence("mem.available.low", model.DomainMemory,
			usedPct, w2, c2, true, 0.9,
			fmt.Sprintf("MemAvailable=%.1f%% (%s free)", availPct, formatB(mem.Available)), "1s",
			nil, nil),
		emitEvidence("mem.reclaim.direct", model.DomainMemory,
			directReclaimRate, w3, c3, false, 0.7,
			fmt.Sprintf("direct reclaim=%.0f pages/s", directReclaimRate), "1s",
			nil, nil),
		emitEvidence("mem.swap.activity", model.DomainMemory,
			swapIOMBs, w4, c4, true, 0.8,
			fmt.Sprintf("swap IO=%.1f MB/s", swapIOMBs), "1s",
			nil, nil),
		emitEvidence("mem.major.faults", model.DomainMemory,
			majFaultRate, w5, c5, false, 0.7,
			fmt.Sprintf("major faults=%.0f/s", majFaultRate), "1s",
			nil, nil),
		emitEvidence("mem.oom.kills", model.DomainMemory,
			oomVal, w6, c6, true, 1.0,
			fmt.Sprintf("OOM kills=%d in last 1s", oomDelta), "1s",
			nil, nil),
	)

	// Sentinel: BPF-measured OOM kills and direct reclaim stalls
	if sent := curr.Global.Sentinel; sent.Active {
		if len(sent.OOMKills) > 0 {
			r.EvidenceV2 = append(r.EvidenceV2, emitEvidence("mem.sentinel.oom", model.DomainMemory,
				float64(len(sent.OOMKills)), 1, 1, true, 1.0,
				fmt.Sprintf("BPF OOM kills=%d (PID %d %s)", len(sent.OOMKills), sent.OOMKills[0].VictimPID, sent.OOMKills[0].VictimComm), "1s",
				nil, nil))
		}
		if sent.ReclaimStallMs > 0 {
			r.EvidenceV2 = append(r.EvidenceV2, emitEvidence("mem.sentinel.reclaim", model.DomainMemory,
				sent.ReclaimStallMs, 1, 100, true, 0.95,
				fmt.Sprintf("BPF reclaim stall=%.0fms", sent.ReclaimStallMs), "1s",
				nil, nil))
		}
	}

	// v2 scoring
	v2Score := weightedDomainScore(r.EvidenceV2)
	if !v2TrustGate(r.EvidenceV2) {
		v2Score = 0
	}
	r.Score = int(v2Score)
	if oomDetected && v2TrustGate(r.EvidenceV2) && r.Score < 70 {
		r.Score = 70
	}
	if availPct > 25 && memSome < 0.1 && memFull < 0.02 {
		if r.Score > 20 {
			r.Score = 20
		}
	}
	if r.Score < 20 {
		r.Score = 0
	}
	cap100(&r.Score)
	r.EvidenceGroups = evidenceGroupsFired(r.EvidenceV2, 0.35)
	r.Checks = evidenceToChecks(r.EvidenceV2)

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
		r.Evidence = append(r.Evidence, fmt.Sprintf("OOM kills=%d in last 1s", oomDelta))
	}

	// Chain
	if r.Score > 0 && r.EvidenceGroups >= minEvidenceGroups {
		r.Chain = append(r.Chain, "Memory pressure detected")
		if swapIOMBs > 0.1 {
			r.Chain = append(r.Chain, "System actively swapping")
		}
		if directReclaimRate > 0 {
			r.Chain = append(r.Chain, "Kernel reclaiming pages synchronously")
		}
		r.Chain = append(r.Chain, "Allocation stall risk")
	}

	// --- Culprit identification (priority order) ---

	// 1st priority: BPF sentinel OOM victims — if the sentinel saw an OOM kill
	// this tick, use the victim's cgroup as culprit (most precise attribution).
	if sent := curr.Global.Sentinel; sent.Active && len(sent.OOMKills) > 0 {
		victim := sent.OOMKills[0]
		r.TopProcess = victim.VictimComm
		r.TopPID = int(victim.VictimPID)
		// Find the victim's cgroup path from process list
		for _, p := range curr.Processes {
			if p.PID == int(victim.VictimPID) && p.CgroupPath != "" {
				r.TopCgroup = p.CgroupPath
				break
			}
		}
	}

	// 2nd priority: cgroup with OOM delta > 0 (from cgroup memory.events)
	if r.TopCgroup == "" && rates != nil {
		for _, cr := range rates.CgroupRates {
			if cr.Path == "/" || cr.Path == "" {
				continue
			}
			if cr.OOMKillDelta > 0 {
				r.TopCgroup = cr.Path
				break
			}
		}
	}

	// 3rd priority: cgroup closest to memory limit (existing logic for non-OOM pressure)
	if r.TopCgroup == "" {
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
	}

	// 4th priority (process fallback): top process by RSS (skip kernel threads)
	if r.TopProcess == "" {
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

	csPerCore := ctxRate / float64(nCPUs)

	// --- v2 evidence ---
	w, c := threshold("cpu.psi", 5, 20)
	w2, c2 := threshold("cpu.runqueue", 1.0, 2.0)
	w3, c3 := threshold("cpu.ctxswitch", 2000, 10000)
	w4, c4 := threshold("cpu.steal", 5, 15)
	w5, c5 := threshold("cpu.cgroup.throttle", 5, 25)
	r.EvidenceV2 = append(r.EvidenceV2,
		emitEvidence("cpu.psi", model.DomainCPU,
			cpuSome*100, w, c, true, 0.9,
			fmt.Sprintf("CPU PSI some=%.1f%% full=%.1f%%", cpuSome*100, cpuFull*100), "avg10",
			nil, nil),
		emitEvidence("cpu.runqueue", model.DomainCPU,
			rqRatio, w2, c2, false, 0.7,
			fmt.Sprintf("runqueue ratio=%.1f (%d/%d cores)", rqRatio, int(running), nCPUs), "1s",
			nil, nil),
		emitEvidence("cpu.ctxswitch", model.DomainCPU,
			csPerCore, w3, c3, true, 0.6,
			fmt.Sprintf("ctx switches=%.0f/core", csPerCore), "1s",
			nil, nil),
		emitEvidence("cpu.steal", model.DomainCPU,
			stealPct, w4, c4, true, 0.9,
			fmt.Sprintf("CPU steal=%.1f%%", stealPct), "1s",
			nil, nil),
		emitEvidence("cpu.cgroup.throttle", model.DomainCPU,
			maxThrottlePct, w5, c5, true, 0.8,
			fmt.Sprintf("cgroup throttle=%.1f%% (%s)", maxThrottlePct, maxThrottleCg), "1s",
			nil, map[string]string{"cgroup": maxThrottleCg}),
	)

	// Sentinel: BPF-measured cgroup throttle events
	if sent := curr.Global.Sentinel; sent.Active {
		if sent.ThrottleRate > 0 {
			topCg := ""
			if len(sent.CgThrottles) > 0 {
				topCg = sent.CgThrottles[0].CgPath
			}
			r.EvidenceV2 = append(r.EvidenceV2, emitEvidence("cpu.sentinel.throttle", model.DomainCPU,
				sent.ThrottleRate, 1, 50, true, 0.95,
				fmt.Sprintf("BPF throttle=%.0f/s (%s)", sent.ThrottleRate, topCg), "1s",
				nil, nil))
		}
	}

	// v2 scoring
	v2Score := weightedDomainScore(r.EvidenceV2)
	if !v2TrustGate(r.EvidenceV2) {
		v2Score = 0
	}
	r.Score = int(v2Score)
	if busyPct < 50 && cpuSome < 0.10 && cpuFull < 0.02 {
		if r.Score > 30 {
			r.Score = 30
		}
	}
	if stealPct > 5 && v2TrustGate(r.EvidenceV2) {
		r.Score += 10
	}
	if r.Score < 20 {
		r.Score = 0
	}
	cap100(&r.Score)
	r.EvidenceGroups = evidenceGroupsFired(r.EvidenceV2, 0.35)
	r.Checks = evidenceToChecks(r.EvidenceV2)

	// Evidence strings
	if cpuSome > 0.05 {
		r.Evidence = append(r.Evidence, fmt.Sprintf("CPU PSI some=%.1f%%", cpuSome*100))
	}
	if cpuFull > 0.01 {
		r.Evidence = append(r.Evidence, fmt.Sprintf("CPU PSI full=%.1f%%", cpuFull*100))
	}
	if rqRatio > 1.5 {
		r.Evidence = append(r.Evidence, fmt.Sprintf("Run queue ratio=%.1f (%d runnable / %d cores)", rqRatio, int(running), nCPUs))
	}
	if csPerCore > 30000 {
		r.Evidence = append(r.Evidence, fmt.Sprintf("Context switches=%.0f/s (%.0f/core)", ctxRate, csPerCore))
	}
	if maxThrottlePct > 5 {
		r.Evidence = append(r.Evidence, fmt.Sprintf("Cgroup %s throttled %.1f%%", maxThrottleCg, maxThrottlePct))
		r.TopCgroup = maxThrottleCg
	}
	if stealPct > 5 {
		r.Evidence = append(r.Evidence, fmt.Sprintf("CPU steal=%.1f%% (hypervisor)", stealPct))
	}

	// Chain
	if r.Score > 0 && r.EvidenceGroups >= minEvidenceGroups {
		r.Chain = append(r.Chain, "CPU contention detected")
		if rqRatio > 1.5 {
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

	st := curr.Global.TCPStates

	// Ephemeral ports
	eph := curr.Global.EphemeralPorts
	ephRange := eph.RangeHi - eph.RangeLo + 1
	var ephPct float64
	if ephRange > 0 {
		ephPct = float64(eph.InUse) / float64(ephRange) * 100
	}

	// --- v2 evidence ---
	var retransRatio float64
	if rates.OutSegRate > 0 {
		retransRatio = retransRate / rates.OutSegRate * 100
	}
	// Composite TCP state: TIME_WAIT + SYN_SENT (CLOSE_WAIT split to net.closewait)
	tcpStateVal := float64(st.TimeWait)
	if synScaled := float64(st.SynSent) * 200; synScaled > tcpStateVal {
		tcpStateVal = synScaled
	}
	w, c := threshold("net.drops", 1, 100)
	w2, c2 := threshold("net.tcp.retrans", 1, 5)
	w3, c3 := threshold("net.conntrack", 70, 95)
	w4, c4 := threshold("net.softirq", 5, 25)
	w5, c5 := threshold("net.tcp.state", 3000, 15000)
	r.EvidenceV2 = append(r.EvidenceV2,
		emitEvidence("net.drops", model.DomainNetwork,
			totalDrops, w, c, true, 0.8,
			fmt.Sprintf("net drops=%.0f/s", totalDrops), "1s",
			nil, nil),
		emitEvidence("net.tcp.retrans", model.DomainNetwork,
			retransRatio, w2, c2, true, 0.8,
			fmt.Sprintf("retrans=%.0f/s (%.1f%% ratio)", retransRate, retransRatio), "1s",
			nil, nil),
		emitEvidence("net.conntrack", model.DomainNetwork,
			conntrackPct*100, w3, c3, true, 0.9,
			fmt.Sprintf("conntrack=%.0f%% (%d/%d)", conntrackPct*100, ct.Count, ct.Max), "1s",
			nil, nil),
		emitEvidence("net.softirq", model.DomainNetwork,
			rates.CPUSoftIRQPct, w4, c4, false, 0.6,
			fmt.Sprintf("softirq CPU=%.1f%%", rates.CPUSoftIRQPct), "1s",
			nil, nil),
		emitEvidence("net.tcp.state", model.DomainNetwork,
			tcpStateVal, w5, c5, false, 0.6,
			fmt.Sprintf("TW=%d SYN=%d", st.TimeWait, st.SynSent), "1s",
			nil, nil),
	)

	// Sentinel: BPF-measured packet drops and TCP resets
	if sent := curr.Global.Sentinel; sent.Active {
		if sent.PktDropRate > 0 {
			r.EvidenceV2 = append(r.EvidenceV2, emitEvidence("net.sentinel.drops", model.DomainNetwork,
				sent.PktDropRate, 1, 100, true, 0.95,
				fmt.Sprintf("BPF pkt drops=%.0f/s", sent.PktDropRate), "1s",
				nil, nil))
		}
		if sent.TCPResetRate > 0 {
			r.EvidenceV2 = append(r.EvidenceV2, emitEvidence("net.sentinel.resets", model.DomainNetwork,
				sent.TCPResetRate, 1, 50, true, 0.95,
				fmt.Sprintf("BPF TCP RSTs=%.0f/s", sent.TCPResetRate), "1s",
				nil, nil))
		}
	}

	// Dedicated CLOSE_WAIT evidence with per-PID attribution
	w6, c6 := threshold("net.closewait", 50, 500)
	cwMsg := fmt.Sprintf("CLOSE_WAIT=%d", st.CloseWait)
	if len(curr.Global.CloseWaitLeakers) > 0 {
		top := curr.Global.CloseWaitLeakers[0]
		cwMsg = fmt.Sprintf("CLOSE_WAIT=%d — %s(PID %d) holds %d, oldest %s",
			st.CloseWait, top.Comm, top.PID, top.Count, fmtAge(top.OldestAge))
	}
	r.EvidenceV2 = append(r.EvidenceV2,
		emitEvidence("net.closewait", model.DomainNetwork,
			float64(st.CloseWait), w6, c6, true, 0.8,
			cwMsg, "1s",
			nil, nil),
	)

	// v2 scoring
	v2Score := weightedDomainScore(r.EvidenceV2)
	if !v2TrustGate(r.EvidenceV2) {
		v2Score = 0
	}
	r.Score = int(v2Score)
	if totalDrops < 1 && retransRate < 5 {
		if r.Score > 25 {
			r.Score = 25
		}
	}
	if totalDrops > 1 && rates.CPUSoftIRQPct > 5 && v2TrustGate(r.EvidenceV2) {
		r.Score += 10
	}
	if r.Score < 20 {
		r.Score = 0
	}
	cap100(&r.Score)
	r.EvidenceGroups = evidenceGroupsFired(r.EvidenceV2, 0.35)
	r.Checks = evidenceToChecks(r.EvidenceV2)

	// Evidence strings
	if totalDrops > 1 {
		r.Evidence = append(r.Evidence, fmt.Sprintf("Network drops=%.0f/s", totalDrops))
	}
	if retransRate > 5 {
		r.Evidence = append(r.Evidence, fmt.Sprintf("TCP retransmits=%.0f/s", retransRate))
	}
	if conntrackPct > 0.7 {
		r.Evidence = append(r.Evidence, fmt.Sprintf("Conntrack=%.0f%% (%d/%d)", conntrackPct*100, ct.Count, ct.Max))
	}
	if rates.CPUSoftIRQPct > 5 {
		r.Evidence = append(r.Evidence, fmt.Sprintf("SoftIRQ CPU=%.1f%%", rates.CPUSoftIRQPct))
	}
	if st.TimeWait > 5000 {
		r.Evidence = append(r.Evidence, fmt.Sprintf("TIME_WAIT=%d (port exhaustion risk)", st.TimeWait))
	}
	if st.CloseWait > 20 {
		cwEvStr := fmt.Sprintf("CLOSE_WAIT=%d (app not closing)", st.CloseWait)
		if len(curr.Global.CloseWaitLeakers) > 0 {
			top := curr.Global.CloseWaitLeakers[0]
			cwEvStr = fmt.Sprintf("CLOSE_WAIT=%d — %s(PID %d) holds %d, oldest %s",
				st.CloseWait, top.Comm, top.PID, top.Count, fmtAge(top.OldestAge))
		}
		r.Evidence = append(r.Evidence, cwEvStr)
	}
	if totalErrors > 1 {
		r.Evidence = append(r.Evidence, fmt.Sprintf("Network errors=%.0f/s", totalErrors))
	}
	if ephPct > 50 {
		r.Evidence = append(r.Evidence, fmt.Sprintf("Ephemeral ports=%.0f%% (%d/%d)", ephPct, eph.InUse, ephRange))
	}

	// Chain
	if r.Score > 0 && r.EvidenceGroups >= minEvidenceGroups {
		if retransRate > 5 {
			r.Chain = append(r.Chain, fmt.Sprintf("retrans=%.0f/s", retransRate))
		}
		if totalDrops > 1 {
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

// detectHiddenLatency identifies when all traditional metrics look fine (CPU low,
// memory OK, IO calm) but processes show signs of hidden waiting — high voluntary
// context switches relative to CPU time, suggesting lock contention, futex waits,
// or scheduler delays. This is the "something is slow but metrics look fine" case.
func detectHiddenLatency(curr *model.Snapshot, rates *model.RateSnapshot, result *model.AnalysisResult) {
	if rates == nil {
		return
	}

	// Only trigger when system appears healthy or inconclusive
	if result.Health == model.HealthCritical || result.Health == model.HealthDegraded {
		return
	}

	// System must be idle enough that traditional metrics wouldn't explain slowness
	if rates.CPUBusyPct > 50 {
		return
	}

	// Find processes with high voluntary ctx switches but low CPU usage.
	// High vol_ctxsw + low CPU = thread is sleeping/waiting a lot (locks, IO, futexes).
	type waiter struct {
		comm      string
		pid       int
		volRate   float64
		cpuPct    float64
		waitRatio float64 // vol_ctxsw per % CPU — higher = more waiting
	}

	var waiters []waiter
	var totalVolRate float64

	for _, pr := range rates.ProcessRates {
		if isKernelThread(pr.Comm) {
			continue
		}
		if pr.CtxSwitchRate < 100 {
			continue // not interesting
		}
		totalVolRate += pr.CtxSwitchRate

		// High context switches with low CPU = suspicious
		cpuPct := pr.CPUPct
		if cpuPct < 0.1 {
			cpuPct = 0.1 // avoid division by zero
		}
		ratio := pr.CtxSwitchRate / cpuPct
		if ratio > 500 { // > 500 switches per % CPU = heavy waiting
			waiters = append(waiters, waiter{
				comm:      pr.Comm,
				pid:       pr.PID,
				volRate:   pr.CtxSwitchRate,
				cpuPct:    pr.CPUPct,
				waitRatio: ratio,
			})
		}
	}

	if len(waiters) == 0 {
		return
	}

	// Sort by wait ratio descending
	sort.Slice(waiters, func(i, j int) bool {
		return waiters[i].waitRatio > waiters[j].waitRatio
	})

	top := waiters[0]

	// Estimate off-CPU percentage: total vol switches / (vol + nonvol) as a proxy
	// This is a rough estimate — true off-CPU requires eBPF, but high voluntary
	// switches with low CPU is a strong signal.
	nCPU := curr.Global.CPU.NumCPUs
	if nCPU == 0 {
		nCPU = 1
	}
	// Rough estimate: each voluntary context switch means ~some microseconds of waiting.
	// At 10000 switches/s with ~100us avg wait, that's ~1s of waiting per second = ~100/nCPU% off-CPU.
	estimatedWaitPct := totalVolRate / float64(nCPU) / 100 // rough scaling
	if estimatedWaitPct > 100 {
		estimatedWaitPct = 100
	}

	// Only flag if the wait seems significant
	if estimatedWaitPct < 15 && top.waitRatio < 2000 {
		return
	}

	result.HiddenLatency = true
	result.HiddenLatencyPct = estimatedWaitPct
	result.HiddenLatencyComm = top.comm

	if top.waitRatio > 5000 {
		result.HiddenLatencyDesc = fmt.Sprintf(
			"CPU %.0f%% but %s is context-switching %.0f/s with only %.1f%% CPU — likely lock contention or blocking IO. Run: sudo xtop then press 'p' for eBPF probe.",
			rates.CPUBusyPct, top.comm, top.volRate, top.cpuPct)
	} else {
		result.HiddenLatencyDesc = fmt.Sprintf(
			"CPU %.0f%% but threads are waiting (%.0f voluntary switches/s across %d procs). Top waiter: %s. Run: sudo xtop then press 'p' for eBPF off-CPU analysis.",
			rates.CPUBusyPct, totalVolRate, len(waiters), top.comm)
	}

	// Upgrade health to INCONCLUSIVE if it was OK, to flag this isn't truly healthy
	if result.Health == model.HealthOK && estimatedWaitPct > 30 {
		result.Health = model.HealthInconclusive
		result.Confidence = 40
	}
}

func cap100(score *int) {
	if *score > 100 {
		*score = 100
	}
}

// fmtAge formats seconds as a human-readable duration (e.g. "23m", "1h12m", "45s").
func fmtAge(seconds int) string {
	if seconds < 60 {
		return fmt.Sprintf("%ds", seconds)
	}
	if seconds < 3600 {
		return fmt.Sprintf("%dm", seconds/60)
	}
	h := seconds / 3600
	m := (seconds % 3600) / 60
	if m == 0 {
		return fmt.Sprintf("%dh", h)
	}
	return fmt.Sprintf("%dh%dm", h, m)
}

