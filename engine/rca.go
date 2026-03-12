package engine

import (
	"fmt"
	"sort"
	"strings"
	"time"

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

	// Resolve application identity for all RCA entries
	if curr.Global.AppIdentities != nil {
		for i := range result.RCA {
			if result.RCA[i].TopPID > 0 {
				if id, ok := curr.Global.AppIdentities[result.RCA[i].TopPID]; ok {
					result.RCA[i].TopAppName = id.DisplayName
				}
			}
		}
	}

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
		result.PrimaryAppName = primary.TopAppName
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
		result.Health = hist.alert.Update(result.Health, result.PrimaryScore, hasCritEvidence)
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

	// Cross-signal correlation: detect cause-effect pairs across domains
	result.CrossCorrelations = BuildCrossCorrelation(result, hist)

	// Blame attribution: identify top offenders
	result.Blame = ComputeBlame(result, curr, rates)

	// Statistical intelligence
	runStatisticalAnalysis(result, curr, rates, hist)

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

	// Brendan Gregg USE method: find worst device by IOPS-weighted latency
	// Ignore idle devices (< 10 IOPS) — USB sticks, unused LUNs produce noise
	var worstAwait, worstUtil float64
	var worstDev string
	var worstQueueDepth uint64
	var worstQueueDev string
	if rates != nil {
		for _, d := range rates.DiskRates {
			totalIOPS := d.ReadIOPS + d.WriteIOPS
			// Only consider devices with meaningful IO activity
			if totalIOPS >= 10 && d.AvgAwaitMs > worstAwait {
				worstAwait = d.AvgAwaitMs
				worstDev = d.Name
			}
			if totalIOPS >= 10 && d.UtilPct > worstUtil {
				worstUtil = d.UtilPct
			}
			if d.QueueDepth > worstQueueDepth {
				worstQueueDepth = d.QueueDepth
				worstQueueDev = d.Name
			}
		}
	}

	// Dirty pages
	mem := curr.Global.Memory
	var dirtyPct float64
	if mem.Total > 0 {
		dirtyPct = float64(mem.Dirty) / float64(mem.Total) * 100
	}

	// Filesystem space + inode pressure
	var worstFreePct float64 = 100
	var worstMount string
	var worstGrowthBPS float64
	var worstInodePct float64
	var worstInodeMount string
	if rates != nil {
		for _, mr := range rates.MountRates {
			if mr.FreePct < worstFreePct {
				worstFreePct = mr.FreePct
				worstMount = mr.MountPoint
				worstGrowthBPS = mr.GrowthBytesPerSec
			}
		}
	}
	for _, m := range curr.Global.Mounts {
		if m.TotalInodes > 0 {
			inodePct := float64(m.UsedInodes) / float64(m.TotalInodes) * 100
			if inodePct > worstInodePct {
				worstInodePct = inodePct
				worstInodeMount = m.MountPoint
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
		worstAwait, w, c, true, 0.8, // measured=true: from /proc/diskstats
		fmt.Sprintf("%s await=%.0fms", worstDev, worstAwait), "1s",
		nil, map[string]string{"device": worstDev}))
	w, c = threshold("io.disk.util", 70, 95)
	r.EvidenceV2 = append(r.EvidenceV2, emitEvidence("io.disk.util", model.DomainIO,
		worstUtil, w, c, true, 0.8, // measured=true: from /proc/diskstats
		fmt.Sprintf("%s util=%.0f%%", worstDev, worstUtil), "1s",
		nil, map[string]string{"device": worstDev}))

	// Queue depth: saturation indicator (Gregg USE: Saturation for disk)
	w, c = threshold("io.disk.queuedepth", 4, 16)
	r.EvidenceV2 = append(r.EvidenceV2, emitEvidence("io.disk.queuedepth", model.DomainIO,
		float64(worstQueueDepth), w, c, true, 0.7,
		fmt.Sprintf("%s queue=%d", worstQueueDev, worstQueueDepth), "1s",
		nil, map[string]string{"device": worstQueueDev}))

	w, c = threshold("io.writeback", 5, 20)
	r.EvidenceV2 = append(r.EvidenceV2, emitEvidence("io.writeback", model.DomainIO,
		dirtyPct, w, c, false, 0.6,
		fmt.Sprintf("dirty pages=%.1f%% of RAM", dirtyPct), "1s",
		nil, nil))

	// Filesystem full: gate by growth rate — static full disk with no writes is not urgent
	fsUsedPct := 100 - worstFreePct
	fsConf := 0.9
	if fsUsedPct < 95 && worstGrowthBPS <= 0 {
		fsConf = 0.4 // dampen confidence when not actively growing
	}
	w, c = threshold("io.fsfull", 85, 95)
	r.EvidenceV2 = append(r.EvidenceV2, emitEvidence("io.fsfull", model.DomainIO,
		fsUsedPct, w, c, true, fsConf,
		fmt.Sprintf("%s %.0f%% used", worstMount, fsUsedPct), "1s",
		nil, map[string]string{"mount": worstMount}))

	// Inode exhaustion: can cause "no space left" even with free disk space
	if worstInodePct > 0 {
		w, c = threshold("io.inode.pressure", 80, 95)
		r.EvidenceV2 = append(r.EvidenceV2, emitEvidence("io.inode.pressure", model.DomainIO,
			worstInodePct, w, c, true, 0.8,
			fmt.Sprintf("%s inodes=%.0f%% used", worstInodeMount, worstInodePct), "1s",
			nil, map[string]string{"mount": worstInodeMount}))
	}

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

	var swapInRate, swapOutRate, directPct, majFaultRate, directReclaimRate, allocStallRate float64
	var slabUnreclaimDelta int64
	if rates != nil {
		swapInRate = rates.SwapInRate
		swapOutRate = rates.SwapOutRate
		totalScan := rates.DirectReclaimRate + rates.KswapdRate
		if totalScan > 0 {
			directPct = rates.DirectReclaimRate / totalScan
		}
		majFaultRate = rates.MajFaultRate
		directReclaimRate = rates.DirectReclaimRate
		allocStallRate = rates.AllocStallRate
		slabUnreclaimDelta = rates.SUnreclaimDelta
	}

	// Kernel slab metrics (Gregg: check slab for kernel memory leaks)
	slabUnreclaimMB := float64(mem.SUnreclaim) / (1024 * 1024)
	slabPctOfTotal := float64(mem.SUnreclaim) / float64(mem.Total) * 100

	// --- v2 evidence ---
	usedPct := 100 - availPct

	// Use delta-based OOM detection: only fire if OOM kills happened since last tick
	var oomDelta uint64
	if rates != nil {
		oomDelta = rates.OOMKillDelta
	}
	oomDetected := oomDelta > 0
	oomVal := float64(oomDelta)

	// PSI acceleration: sudden onset detection (Facebook TSA method)
	// If avg10 >> avg300, pressure is spiking rapidly
	memPSIAvg10 := curr.Global.PSI.Memory.Some.Avg10
	memPSIAvg300 := curr.Global.PSI.Memory.Some.Avg300
	psiAcceleration := false
	if memPSIAvg300 > 0.5 && memPSIAvg10 > 2*memPSIAvg300 {
		psiAcceleration = true
	}

	// Dynamic available threshold: scale for large-memory systems
	// On 256GB box, 15% free = 38GB (fine). Use min(85%, absoluteFloor)
	// Google SRE: "alert on symptoms not causes" — use absolute floor
	totalGB := float64(mem.Total) / (1024 * 1024 * 1024)
	availWarn := float64(85)
	availCrit := float64(95)
	if totalGB > 32 {
		// On large systems, 500MB free is the real danger zone
		absFloor := 500.0 / (totalGB * 1024) * 100 // 500MB as % of total
		if absFloor > 5 {
			absFloor = 5
		}
		dynCrit := 100 - absFloor
		if dynCrit < availCrit {
			availCrit = dynCrit
		}
		dynWarn := dynCrit - 5
		if dynWarn < availWarn {
			availWarn = dynWarn
		}
	}

	// Direct reclaim confidence: dampen when PSI shows no pressure
	// (Gregg: direct reclaim from cache pressure is normal, only meaningful with PSI)
	reclaimConf := 0.7
	if memSome < 0.01 {
		reclaimConf = 0.35 // much less confident without PSI confirmation
	}

	w, c := threshold("mem.psi", 5, 20)
	w2, c2 := threshold("mem.available.low", availWarn, availCrit)
	w3, c3 := threshold("mem.reclaim.direct", 10, 500)
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
			directReclaimRate, w3, c3, true, reclaimConf, // measured from vmstat, confidence gated by PSI
			fmt.Sprintf("direct reclaim=%.0f pages/s", directReclaimRate), "1s",
			nil, nil),
		// Split swap: swap-in is worse than swap-out (Gregg: swap-in = demand paging failure)
		emitEvidence("mem.swap.in", model.DomainMemory,
			swapInRate, 1, 30, true, 0.85,
			fmt.Sprintf("swap in=%.1f MB/s", swapInRate), "1s",
			nil, nil),
		emitEvidence("mem.swap.out", model.DomainMemory,
			swapOutRate, 2, 50, true, 0.7,
			fmt.Sprintf("swap out=%.1f MB/s", swapOutRate), "1s",
			nil, nil),
		emitEvidence("mem.major.faults", model.DomainMemory,
			majFaultRate, w5, c5, true, 0.7, // measured from vmstat
			fmt.Sprintf("major faults=%.0f/s", majFaultRate), "1s",
			nil, nil),
		emitEvidence("mem.oom.kills", model.DomainMemory,
			oomVal, w6, c6, true, 1.0,
			fmt.Sprintf("OOM kills=%d in last tick", oomDelta), "1s",
			nil, nil),
	)

	// PSI acceleration: rapid onset detection (Meta TSA: detect rate-of-change)
	if psiAcceleration {
		r.EvidenceV2 = append(r.EvidenceV2, emitEvidence("mem.psi.acceleration", model.DomainMemory,
			memPSIAvg10, memPSIAvg300, memPSIAvg300*3, true, 0.85,
			fmt.Sprintf("MEM PSI spike: avg10=%.1f%% vs avg300=%.1f%% (%.1fx)", memPSIAvg10, memPSIAvg300, memPSIAvg10/memPSIAvg300), "avg10",
			nil, nil))
	}

	// Kernel slab leak: unreclaimable slab growing (Gregg: check slabtop for kernel leaks)
	if slabPctOfTotal > 5 && slabUnreclaimDelta > 0 {
		r.EvidenceV2 = append(r.EvidenceV2, emitEvidence("mem.slab.leak", model.DomainMemory,
			slabPctOfTotal, 5, 15, false, 0.7,
			fmt.Sprintf("slab unreclaimable=%.0fMB (%.1f%% of RAM, growing)", slabUnreclaimMB, slabPctOfTotal), "1s",
			nil, nil))
	}

	// Allocation stalls: processes blocked in page allocator (Gregg: allocstall = direct evidence)
	if allocStallRate > 0 {
		r.EvidenceV2 = append(r.EvidenceV2, emitEvidence("mem.alloc.stall", model.DomainMemory,
			allocStallRate, 1, 100, true, 0.85,
			fmt.Sprintf("alloc stalls=%.0f/s", allocStallRate), "1s",
			nil, nil))
	}

	// .NET allocation storm evidence: high alloc rate + threadpool queuing
	for _, dn := range curr.Global.DotNet {
		if dn.AllocRateMBs > 100 {
			r.EvidenceV2 = append(r.EvidenceV2, emitEvidence("dotnet.alloc.storm", model.DomainMemory,
				dn.AllocRateMBs, 50, 200, true, 0.8,
				fmt.Sprintf(".NET alloc=%.0f MB/s (PID %d %s)", dn.AllocRateMBs, dn.PID, dn.Comm), "1s",
				nil, map[string]string{"pid": fmt.Sprintf("%d", dn.PID)}))
			break
		}
	}
	for _, dn := range curr.Global.DotNet {
		if dn.ThreadPoolQueue > 10 {
			r.EvidenceV2 = append(r.EvidenceV2, emitEvidence("dotnet.threadpool.queue", model.DomainMemory,
				float64(dn.ThreadPoolQueue), 5, 50, true, 0.7,
				fmt.Sprintf(".NET threadpool queue=%d (PID %d %s)", dn.ThreadPoolQueue, dn.PID, dn.Comm), "1s",
				nil, map[string]string{"pid": fmt.Sprintf("%d", dn.PID)}))
			break
		}
	}

	// JVM heap pressure evidence: heap used > 80% of capacity
	for _, entry := range curr.Global.Runtimes.Entries {
		if entry.Name != "jvm" || !entry.Active {
			continue
		}
		for _, jp := range entry.Processes {
			heapMaxStr := jp.Extra["heap_max_mb"]
			if heapMaxStr == "" {
				continue
			}
			heapMaxMB := parseFloat(heapMaxStr)
			if heapMaxMB <= 0 {
				continue
			}
			heapPct := jp.GCHeapMB / heapMaxMB * 100
			if heapPct > 80 {
				r.EvidenceV2 = append(r.EvidenceV2, emitEvidence("jvm.heap.pressure", model.DomainMemory,
					heapPct, 70, 90, true, 0.8,
					fmt.Sprintf("JVM heap=%.0f%% (%.0f/%.0f MB, PID %d %s)", heapPct, jp.GCHeapMB, heapMaxMB, jp.PID, jp.Comm), "1s",
					nil, map[string]string{"pid": fmt.Sprintf("%d", jp.PID)}))
				break // use worst JVM process
			}
		}
		break
	}

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
	if psiAcceleration {
		r.Evidence = append(r.Evidence, fmt.Sprintf("PSI spike: avg10=%.1f%% vs avg300=%.1f%%", memPSIAvg10, memPSIAvg300))
	}
	if availPct < 15 {
		r.Evidence = append(r.Evidence, fmt.Sprintf("MemAvailable=%.1f%% (%s)", availPct, formatB(mem.Available)))
	}
	swapIOMBs := swapInRate + swapOutRate
	if swapInRate > 0.1 {
		r.Evidence = append(r.Evidence, fmt.Sprintf("Swap in=%.1f MB/s (demand paging)", swapInRate))
	}
	if swapOutRate > 0.1 {
		r.Evidence = append(r.Evidence, fmt.Sprintf("Swap out=%.1f MB/s", swapOutRate))
	}
	if directReclaimRate > 0 {
		r.Evidence = append(r.Evidence, fmt.Sprintf("Direct reclaim=%.0f pages/s (ratio=%.0f%%)", directReclaimRate, directPct*100))
	}
	if allocStallRate > 0 {
		r.Evidence = append(r.Evidence, fmt.Sprintf("Alloc stalls=%.0f/s", allocStallRate))
	}
	if majFaultRate > 10 {
		r.Evidence = append(r.Evidence, fmt.Sprintf("Major faults=%.0f/s", majFaultRate))
	}
	if oomDetected {
		r.Evidence = append(r.Evidence, fmt.Sprintf("OOM kills=%d in last tick", oomDelta))
	}
	if slabPctOfTotal > 5 {
		r.Evidence = append(r.Evidence, fmt.Sprintf("Slab unreclaimable=%.0fMB (%.1f%%)", slabUnreclaimMB, slabPctOfTotal))
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
		if allocStallRate > 0 {
			r.Chain = append(r.Chain, "Allocation stalls blocking processes")
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

	// Proxmox VM-level memory evidence — only emit when actual degradation is measured
	if pve := curr.Global.Proxmox; pve != nil && pve.IsProxmoxHost {
		for _, vm := range pve.VMs {
			if vm.Status != "running" {
				continue
			}
			// OOM kills — always evidence of a real problem
			if vm.MemOOMKills > 0 {
				r.EvidenceV2 = append(r.EvidenceV2, emitEvidence("pve.vm.oom", model.DomainMemory,
					float64(vm.MemOOMKills), 1, 3, false, 0.95,
					fmt.Sprintf("VM %d (%s) OOM kills=%d", vm.VMID, vm.Name, vm.MemOOMKills), "cgroup",
					nil, map[string]string{"vmid": fmt.Sprintf("%d", vm.VMID)}))
			}
			// Swap only matters if PSI confirms degradation
			if vm.MemSwapMB > 100 && vm.PSIMemSome > 5 {
				r.EvidenceV2 = append(r.EvidenceV2, emitEvidence("pve.vm.swap", model.DomainMemory,
					float64(vm.MemSwapMB), 100, 1024, false, 0.8,
					fmt.Sprintf("VM %d (%s) swap=%dMB with pressure", vm.VMID, vm.Name, vm.MemSwapMB), "cgroup",
					nil, map[string]string{"vmid": fmt.Sprintf("%d", vm.VMID)}))
			}
			// Memory near limit only matters if OOM events are happening
			if vm.MemLimitMB > 0 && vm.MemUsedMB > 0 && vm.MemOOMEvents > 0 {
				pct := float64(vm.MemUsedMB) / float64(vm.MemLimitMB) * 100
				if pct > 80 {
					r.EvidenceV2 = append(r.EvidenceV2, emitEvidence("pve.vm.memlimit", model.DomainMemory,
						pct, 85, 95, true, 0.75,
						fmt.Sprintf("VM %d (%s) mem=%.0f%% of limit with OOM events", vm.VMID, vm.Name, pct), "cgroup",
						nil, map[string]string{"vmid": fmt.Sprintf("%d", vm.VMID)}))
				}
			}
			// Memory PSI — direct proof of degradation
			if vm.PSIMemSome > 10 {
				r.EvidenceV2 = append(r.EvidenceV2, emitEvidence("pve.vm.mempsi", model.DomainMemory,
					vm.PSIMemSome, 15, 40, true, 0.7,
					fmt.Sprintf("VM %d (%s) mem PSI=%.1f%%", vm.VMID, vm.Name, vm.PSIMemSome), "cgroup",
					nil, map[string]string{"vmid": fmt.Sprintf("%d", vm.VMID)}))
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
	// Use Load1 for run queue: kernel-smoothed average, not instantaneous procs_running
	// (Gregg: Load1 is already a 1-minute EWMA, less noise than point-in-time sample)
	rqRatio := curr.Global.CPU.LoadAvg.Load1 / float64(nCPUs)
	running := curr.Global.CPU.LoadAvg.Load1 // for display

	var ctxRate, busyPct, stealPct, iowaitPct float64
	var maxThrottlePct float64
	var maxThrottleCg string

	if rates != nil {
		ctxRate = rates.CtxSwitchRate
		busyPct = rates.CPUBusyPct
		stealPct = rates.CPUStealPct
		iowaitPct = rates.CPUIOWaitPct
		for _, cg := range rates.CgroupRates {
			if cg.ThrottlePct > maxThrottlePct {
				maxThrottlePct = cg.ThrottlePct
				maxThrottleCg = cg.Path
			}
		}
	}

	csPerCore := ctxRate / float64(nCPUs)

	// Per-CPU IRQ imbalance detection (Gregg: check /proc/softirqs per CPU)
	var irqImbalanceRatio float64
	if len(curr.Global.CPU.PerCPU) > 1 && rates != nil {
		var maxSoftIRQ, sumSoftIRQ float64
		// Approximate per-CPU softIRQ from per-CPU time breakdown
		for _, cpu := range curr.Global.CPU.PerCPU {
			cpuTotal := cpu.Total()
			if cpuTotal == 0 {
				continue
			}
			sirqPct := float64(cpu.SoftIRQ) / float64(cpuTotal) * 100
			sumSoftIRQ += sirqPct
			if sirqPct > maxSoftIRQ {
				maxSoftIRQ = sirqPct
			}
		}
		avgSoftIRQ := sumSoftIRQ / float64(len(curr.Global.CPU.PerCPU))
		if avgSoftIRQ > 0.1 {
			irqImbalanceRatio = maxSoftIRQ / avgSoftIRQ
		}
	}

	// --- v2 evidence ---
	w, c := threshold("cpu.psi", 5, 20)
	wb, cb := threshold("cpu.busy", 60, 90)
	w2, c2 := threshold("cpu.runqueue", 1.0, 2.0)
	w3, c3 := threshold("cpu.ctxswitch", 2000, 10000)
	w4, c4 := threshold("cpu.steal", 5, 15)
	w5, c5 := threshold("cpu.cgroup.throttle", 5, 25)
	r.EvidenceV2 = append(r.EvidenceV2,
		emitEvidence("cpu.psi", model.DomainCPU,
			cpuSome*100, w, c, true, 0.9,
			fmt.Sprintf("CPU PSI some=%.1f%% full=%.1f%%", cpuSome*100, cpuFull*100), "avg10",
			nil, nil),
		emitEvidence("cpu.busy", model.DomainCPU,
			busyPct, wb, cb, true, 0.85,
			fmt.Sprintf("CPU busy=%.1f%%", busyPct), "1s",
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

	// .NET GC pause evidence: high time-in-GC adds CPU contention
	for _, dn := range curr.Global.DotNet {
		if dn.TimeInGCPct > 5 {
			r.EvidenceV2 = append(r.EvidenceV2, emitEvidence("dotnet.gc.pause", model.DomainCPU,
				dn.TimeInGCPct, 10, 30, true, 0.8,
				fmt.Sprintf(".NET GC pause=%.1f%% (PID %d %s)", dn.TimeInGCPct, dn.PID, dn.Comm), "1s",
				nil, map[string]string{"pid": fmt.Sprintf("%d", dn.PID)}))
			break // use worst .NET process
		}
	}

	// JVM GC pause evidence: high GC time from hsperfdata
	for _, entry := range curr.Global.Runtimes.Entries {
		if entry.Name != "jvm" || !entry.Active {
			continue
		}
		for _, jp := range entry.Processes {
			if jp.GCPausePct > 5 {
				r.EvidenceV2 = append(r.EvidenceV2, emitEvidence("jvm.gc.pause", model.DomainCPU,
					jp.GCPausePct, 10, 30, true, 0.8,
					fmt.Sprintf("JVM GC pause=%.1f%% (PID %d %s)", jp.GCPausePct, jp.PID, jp.Comm), "1s",
					nil, map[string]string{"pid": fmt.Sprintf("%d", jp.PID)}))
				break // use worst JVM process
			}
		}
		break
	}

	// Proxmox VM-level CPU evidence
	if pve := curr.Global.Proxmox; pve != nil && pve.IsProxmoxHost {
		for _, vm := range pve.VMs {
			if vm.Status != "running" {
				continue
			}
			if vm.CPUThrottledPct > 1 {
				r.EvidenceV2 = append(r.EvidenceV2, emitEvidence("pve.vm.throttle", model.DomainCPU,
					vm.CPUThrottledPct, 5, 25, true, 0.85,
					fmt.Sprintf("VM %d (%s) throttled=%.1f%%", vm.VMID, vm.Name, vm.CPUThrottledPct), "cgroup",
					nil, map[string]string{"vmid": fmt.Sprintf("%d", vm.VMID)}))
			}
			if vm.PSICPUSome > 5 {
				r.EvidenceV2 = append(r.EvidenceV2, emitEvidence("pve.vm.cpupsi", model.DomainCPU,
					vm.PSICPUSome, 10, 40, true, 0.7,
					fmt.Sprintf("VM %d (%s) CPU PSI=%.1f%%", vm.VMID, vm.Name, vm.PSICPUSome), "cgroup",
					nil, map[string]string{"vmid": fmt.Sprintf("%d", vm.VMID)}))
			}
		}
	}

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

	// IOWait evidence: CPU time waiting on IO (cross-domain signal, Gregg USE: Errors for CPU)
	if iowaitPct > 5 {
		w6, c6 := threshold("cpu.iowait", 10, 30)
		r.EvidenceV2 = append(r.EvidenceV2, emitEvidence("cpu.iowait", model.DomainCPU,
			iowaitPct, w6, c6, true, 0.8,
			fmt.Sprintf("CPU iowait=%.1f%%", iowaitPct), "1s",
			nil, nil))
	}

	// IRQ imbalance: single CPU handling disproportionate softIRQ load (Gregg: check /proc/softirqs)
	if irqImbalanceRatio > 3 {
		w7, c7 := threshold("cpu.irq.imbalance", 5, 10)
		r.EvidenceV2 = append(r.EvidenceV2, emitEvidence("cpu.irq.imbalance", model.DomainCPU,
			irqImbalanceRatio, w7, c7, true, 0.65,
			fmt.Sprintf("softIRQ imbalance ratio=%.1fx (one CPU hot)", irqImbalanceRatio), "1s",
			nil, nil))
	}

	// Dampen GC pause confidence when run queue is healthy (no CPU contention = GC is not the bottleneck)
	rqStrength := normalize(rqRatio, 1.0, 2.0)
	if rqStrength < 0.1 {
		for i := range r.EvidenceV2 {
			if r.EvidenceV2[i].ID == "dotnet.gc.pause" || r.EvidenceV2[i].ID == "jvm.gc.pause" {
				r.EvidenceV2[i].Confidence *= 0.5
			}
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
	if busyPct > 70 {
		r.Evidence = append(r.Evidence, fmt.Sprintf("CPU busy=%.1f%%", busyPct))
	}
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

// isPrivateIPStr checks if a formatted IP is RFC1918, link-local, or loopback.
func isPrivateIPStr(ip string) bool {
	if strings.HasPrefix(ip, "10.") || strings.HasPrefix(ip, "127.") ||
		strings.HasPrefix(ip, "192.168.") || strings.HasPrefix(ip, "169.254.") {
		return true
	}
	if strings.HasPrefix(ip, "172.") {
		var second int
		fmt.Sscanf(ip, "172.%d.", &second)
		return second >= 16 && second <= 31
	}
	return false
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

	// Retrans confidence: dampen when absolute rate is very low (< 5/s is normal background)
	retransConf := 0.8
	if retransRate < 5 {
		retransConf = 0.4
	}

	// Split RX/TX drops for directional attribution
	var totalRxDrops, totalTxDrops float64
	for _, nr := range rates.NetRates {
		totalRxDrops += nr.RxDropsPS
		totalTxDrops += nr.TxDropsPS
	}

	w, c := threshold("net.drops", 1, 100)
	w2, c2 := threshold("net.tcp.retrans", 1, 5)
	w3, c3 := threshold("net.conntrack", 70, 95)
	w4, c4 := threshold("net.softirq", 5, 25)
	r.EvidenceV2 = append(r.EvidenceV2,
		emitEvidence("net.drops", model.DomainNetwork,
			totalDrops, w, c, true, 0.8,
			fmt.Sprintf("net drops=%.0f/s (rx=%.0f tx=%.0f)", totalDrops, totalRxDrops, totalTxDrops), "1s",
			nil, nil),
		emitEvidence("net.tcp.retrans", model.DomainNetwork,
			retransRatio, w2, c2, true, retransConf,
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
	)

	// Split RX/TX drop evidence for directional diagnosis
	if totalRxDrops > 0.5 {
		wRx, cRx := threshold("net.drops.rx", 1, 100)
		r.EvidenceV2 = append(r.EvidenceV2, emitEvidence("net.drops.rx", model.DomainNetwork,
			totalRxDrops, wRx, cRx, true, 0.85,
			fmt.Sprintf("RX drops=%.0f/s (inbound buffer overflow)", totalRxDrops), "1s",
			nil, nil))
	}
	if totalTxDrops > 0.5 {
		wTx, cTx := threshold("net.drops.tx", 1, 50)
		r.EvidenceV2 = append(r.EvidenceV2, emitEvidence("net.drops.tx", model.DomainNetwork,
			totalTxDrops, wTx, cTx, true, 0.7,
			fmt.Sprintf("TX drops=%.0f/s (outbound queue full)", totalTxDrops), "1s",
			nil, nil))
	}

	// Split TIME_WAIT and SYN_SENT into separate evidence (different root causes)
	if st.TimeWait > 500 {
		wTw, cTw := threshold("net.tcp.timewait", 3000, 15000)
		r.EvidenceV2 = append(r.EvidenceV2, emitEvidence("net.tcp.timewait", model.DomainNetwork,
			float64(st.TimeWait), wTw, cTw, true, 0.6,
			fmt.Sprintf("TIME_WAIT=%d (connection churn)", st.TimeWait), "1s",
			nil, nil))
	}
	if st.SynSent > 5 {
		wSs, cSs := threshold("net.tcp.synsent", 10, 100)
		r.EvidenceV2 = append(r.EvidenceV2, emitEvidence("net.tcp.synsent", model.DomainNetwork,
			float64(st.SynSent), wSs, cSs, true, 0.85,
			fmt.Sprintf("SYN_SENT=%d (upstream unreachable/slow)", st.SynSent), "1s",
			nil, nil))
	}

	// Ephemeral port exhaustion (Gregg USE: Saturation for network stack)
	if ephPct > 30 {
		wEph, cEph := threshold("net.ephemeral", 50, 85)
		r.EvidenceV2 = append(r.EvidenceV2, emitEvidence("net.ephemeral", model.DomainNetwork,
			ephPct, wEph, cEph, true, 0.9,
			fmt.Sprintf("ephemeral ports=%.0f%% (%d/%d)", ephPct, eph.InUse, ephRange), "1s",
			nil, nil))
	}

	// UDP errors (USE: Errors for UDP)
	if rates.UDPErrRate > 0.5 {
		wUdp, cUdp := threshold("net.udp.errors", 1, 50)
		r.EvidenceV2 = append(r.EvidenceV2, emitEvidence("net.udp.errors", model.DomainNetwork,
			rates.UDPErrRate, wUdp, cUdp, true, 0.7,
			fmt.Sprintf("UDP errors=%.1f/s (InErrors+RcvbufErrors)", rates.UDPErrRate), "1s",
			nil, nil))
	}

	// TCP resets (connection rejections / aborts — Google SRE: Error signal)
	if rates.TCPResetRate > 1 {
		wRst, cRst := threshold("net.tcp.resets", 5, 100)
		r.EvidenceV2 = append(r.EvidenceV2, emitEvidence("net.tcp.resets", model.DomainNetwork,
			rates.TCPResetRate, wRst, cRst, true, 0.75,
			fmt.Sprintf("TCP RSTs=%.0f/s", rates.TCPResetRate), "1s",
			nil, nil))
	}

	// TCP connection attempt failures (Google SRE: Error signal)
	if rates.TCPAttemptFailRate > 1 {
		wAf, cAf := threshold("net.tcp.attemptfails", 5, 100)
		r.EvidenceV2 = append(r.EvidenceV2, emitEvidence("net.tcp.attemptfails", model.DomainNetwork,
			rates.TCPAttemptFailRate, wAf, cAf, true, 0.8,
			fmt.Sprintf("TCP attempt fails=%.0f/s", rates.TCPAttemptFailRate), "1s",
			nil, nil))
	}

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

	// Conntrack kernel failure rates
	w6a, c6a := threshold("net.conntrack.drops", 1, 100)
	w6b, c6b := threshold("net.conntrack.insertfail", 0.1, 10)
	ctGrowth := rates.ConntrackGrowthRate
	if ctGrowth < 0 {
		ctGrowth = 0 // only fire evidence on positive growth
	}
	w6c, c6c := threshold("net.conntrack.growth", 100, 1000)
	w6d, c6d := threshold("net.conntrack.invalid", 10, 500)
	w6e, c6e := threshold("net.conntrack.hashcontention", 100, 5000)
	r.EvidenceV2 = append(r.EvidenceV2,
		emitEvidence("net.conntrack.drops", model.DomainNetwork,
			rates.ConntrackDropRate, w6a, c6a, true, 0.95,
			fmt.Sprintf("conntrack drops=%.0f/s", rates.ConntrackDropRate), "1s",
			nil, nil),
		emitEvidence("net.conntrack.insertfail", model.DomainNetwork,
			rates.ConntrackInsertFailRate, w6b, c6b, true, 0.95,
			fmt.Sprintf("conntrack insert_failed=%.1f/s", rates.ConntrackInsertFailRate), "1s",
			nil, nil),
		emitEvidence("net.conntrack.growth", model.DomainNetwork,
			ctGrowth, w6c, c6c, false, 0.7,
			fmt.Sprintf("conntrack growth=%.0f/s", rates.ConntrackGrowthRate), "1s",
			nil, nil),
		emitEvidence("net.conntrack.invalid", model.DomainNetwork,
			rates.ConntrackInvalidRate, w6d, c6d, false, 0.6,
			fmt.Sprintf("conntrack invalid=%.0f/s", rates.ConntrackInvalidRate), "1s",
			nil, nil),
		emitEvidence("net.conntrack.hashcontention", model.DomainNetwork,
			rates.ConntrackSearchRestartRate, w6e, c6e, false, 0.6,
			fmt.Sprintf("conntrack search_restart=%.0f/s", rates.ConntrackSearchRestartRate), "1s",
			nil, nil),
	)

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

	// --- Network security evidence (BPF sentinel) ---
	var maxSynRate float64
	var maxPortBuckets int
	if curr.Global.Sentinel.Active {
		// SYN flood detection
		for _, sf := range curr.Global.Sentinel.SynFlood {
			if sf.Rate > maxSynRate {
				maxSynRate = sf.Rate
			}
		}
		if maxSynRate > 0 {
			ws, cs := threshold("sec.synflood", 100, 1000)
			r.EvidenceV2 = append(r.EvidenceV2, emitEvidence("sec.synflood", model.DomainNetwork,
				maxSynRate, ws, cs, true, 0.9,
				fmt.Sprintf("SYN flood: %.0f SYN/s from single source", maxSynRate), "3s",
				nil, nil))
		}

		// Port scan detection
		for _, ps := range curr.Global.Sentinel.PortScans {
			if ps.UniquePortBuckets > maxPortBuckets {
				maxPortBuckets = ps.UniquePortBuckets
			}
		}
		if maxPortBuckets >= 10 {
			ws, cs := threshold("sec.portscan", 15, 40)
			r.EvidenceV2 = append(r.EvidenceV2, emitEvidence("sec.portscan", model.DomainNetwork,
				float64(maxPortBuckets), ws, cs, true, 0.85,
				fmt.Sprintf("Port scan: %d unique port groups from single source", maxPortBuckets), "3s",
				nil, nil))
		}

		// DNS anomaly detection
		maxDNSRate := float64(0)
		for _, dns := range curr.Global.Sentinel.DNSAnomaly {
			if dns.QueriesPerSec > maxDNSRate {
				maxDNSRate = dns.QueriesPerSec
			}
		}
		if maxDNSRate > 0 {
			ws, cs := threshold("sec.dns.anomaly", 50, 200)
			r.EvidenceV2 = append(r.EvidenceV2, emitEvidence("sec.dns.anomaly", model.DomainNetwork,
				maxDNSRate, ws, cs, true, 0.8,
				fmt.Sprintf("DNS anomaly: %.0f queries/s", maxDNSRate), "3s",
				nil, nil))
		}

		// Lateral movement detection
		maxDests := 0
		for _, fr := range curr.Global.Sentinel.FlowRates {
			if fr.UniqueDestCount > maxDests {
				maxDests = fr.UniqueDestCount
			}
		}
		if maxDests >= 200 {
			ws, cs := threshold("sec.lateral", 200, 500)
			r.EvidenceV2 = append(r.EvidenceV2, emitEvidence("sec.lateral", model.DomainNetwork,
				float64(maxDests), ws, cs, true, 0.75,
				fmt.Sprintf("Lateral movement: %d unique destinations from single PID", maxDests), "3s",
				nil, nil))
		}

		// Data exfiltration detection — only consider non-private destinations
		maxEgressMBHr := float64(0)
		for _, ob := range curr.Global.Sentinel.OutboundTop {
			if isPrivateIPStr(ob.DstIP) {
				continue
			}
			mbhr := ob.BytesPerSec * 3600 / (1024 * 1024)
			if mbhr > maxEgressMBHr {
				maxEgressMBHr = mbhr
			}
		}
		if maxEgressMBHr > 100 {
			ws, cs := threshold("sec.outbound.exfil", 500, 5000)
			r.EvidenceV2 = append(r.EvidenceV2, emitEvidence("sec.outbound.exfil", model.DomainNetwork,
				maxEgressMBHr, ws, cs, true, 0.8,
				fmt.Sprintf("Outbound data: %.0f MB/hr to single destination", maxEgressMBHr), "3s",
				nil, nil))
		}
	}

	// Watchdog-derived evidence (from SecurityMetrics)
	// DNS tunneling (from dnsdeep watchdog)
	maxTXTRatio := float64(0)
	for _, dt := range curr.Global.Security.DNSTunnelIndicators {
		if dt.TXTRatio > maxTXTRatio {
			maxTXTRatio = dt.TXTRatio
		}
	}
	if maxTXTRatio > 0 {
		ws, cs := threshold("sec.dns.tunnel", 0.3, 0.7)
		r.EvidenceV2 = append(r.EvidenceV2, emitEvidence("sec.dns.tunnel", model.DomainNetwork,
			maxTXTRatio, ws, cs, true, 0.85,
			fmt.Sprintf("DNS tunneling: %.0f%% TXT queries", maxTXTRatio*100), "60s",
			nil, nil))
	}

	// C2 beacon detection (from beacondetect watchdog)
	minJitter := float64(1.0)
	for _, bi := range curr.Global.Security.BeaconIndicators {
		if bi.Jitter < minJitter && bi.SampleCount >= 5 {
			minJitter = bi.Jitter
		}
	}
	if minJitter < 1.0 && len(curr.Global.Security.BeaconIndicators) > 0 {
		// Invert: lower jitter = more suspicious = higher value for normalize
		invertedJitter := 1.0 - minJitter
		ws, cs := threshold("sec.beacon", 0.80, 0.95)
		r.EvidenceV2 = append(r.EvidenceV2, emitEvidence("sec.beacon", model.DomainNetwork,
			invertedJitter, ws, cs, true, 0.85,
			fmt.Sprintf("C2 beacon: %.1f%% jitter (regular intervals)", minJitter*100), "120s",
			nil, nil))
	}

	// TCP flag anomalies (from tcpflags watchdog)
	totalFlagCount := uint64(0)
	for _, fa := range curr.Global.Security.TCPFlagAnomalies {
		totalFlagCount += fa.Count
	}
	if totalFlagCount > 0 {
		ws, cs := threshold("sec.tcp.flags", 1, 10)
		r.EvidenceV2 = append(r.EvidenceV2, emitEvidence("sec.tcp.flags", model.DomainNetwork,
			float64(totalFlagCount), ws, cs, true, 0.9,
			fmt.Sprintf("TCP flag anomalies: %d suspicious packets", totalFlagCount), "60s",
			nil, nil))
	}

	// v2 scoring
	v2Score := weightedDomainScore(r.EvidenceV2)
	if !v2TrustGate(r.EvidenceV2) {
		v2Score = 0
	}
	r.Score = int(v2Score)
	hasSecEvidence := false
	for _, e := range r.EvidenceV2 {
		if strings.HasPrefix(e.ID, "sec.") && e.Strength >= 0.35 {
			hasSecEvidence = true
			break
		}
	}
	if !hasSecEvidence && totalDrops < 1 && retransRate < 5 {
		if r.Score > 25 {
			r.Score = 25
		}
	}
	if totalDrops > 1 && rates.CPUSoftIRQPct > 5 && v2TrustGate(r.EvidenceV2) {
		r.Score += 10
	}
	if r.Score < 20 && !hasSecEvidence {
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
	if maxSynRate > 100 {
		r.Evidence = append(r.Evidence, fmt.Sprintf("SYN flood: %.0f/s", maxSynRate))
	}
	if maxPortBuckets > 10 {
		r.Evidence = append(r.Evidence, fmt.Sprintf("Port scan: %d port groups", maxPortBuckets))
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

// runStatisticalAnalysis feeds evidence into statistical trackers and populates results.
func runStatisticalAnalysis(result *model.AnalysisResult, curr *model.Snapshot, rates *model.RateSnapshot, hist *History) {
	if hist == nil {
		return
	}

	// 1. Collect all evidence values from this tick
	evidenceMap := make(map[string]float64)
	for _, rca := range result.RCA {
		for _, ev := range rca.EvidenceV2 {
			evidenceMap[ev.ID] = ev.Value
		}
	}

	// 2. Update baselines + z-scores + forecaster + seasonal
	hour := time.Now().Hour()
	for id, val := range evidenceMap {
		hist.Baselines.Update(id, val)
		hist.ZScores.Push(id, val)
		hist.Forecaster.Update(id, val)
		hist.Seasonal.Update(id, val, hour)
	}

	// 3. Update correlator with all pairs
	hist.Correlator.UpdateFromEvidence(evidenceMap)

	// 4. Detect baseline anomalies (>3 sigma from EWMA)
	for id, val := range evidenceMap {
		if hist.Baselines.IsAnomaly(id, val, 3.0) {
			mean, std, _ := hist.Baselines.Get(id)
			z := hist.Baselines.ZScore(id, val)
			result.BaselineAnomalies = append(result.BaselineAnomalies, model.BaselineAnomaly{
				EvidenceID: id,
				Value:      val,
				Baseline:   mean,
				StdDev:     std,
				ZScore:     z,
				Sigma:      z,
			})
		}
	}

	// 5. Detect z-score anomalies (>3 sigma from sliding window)
	for id, val := range evidenceMap {
		z := hist.ZScores.ZScore(id, val)
		if z > 3.0 || z < -3.0 {
			mean, std, _ := hist.ZScores.MeanStd(id)
			result.ZScoreAnomalies = append(result.ZScoreAnomalies, model.ZScoreAnomaly{
				EvidenceID: id,
				Value:      val,
				WindowMean: mean,
				WindowStd:  std,
				ZScore:     z,
			})
		}
	}

	// 6. Surface top correlations
	topCorr := hist.Correlator.TopCorrelations(0.7, 5)
	for _, tc := range topCorr {
		strength := "moderate"
		if tc.R > 0.85 || tc.R < -0.85 {
			strength = "strong"
		}
		result.Correlations = append(result.Correlations, model.MetricCorrelation{
			MetricA:     tc.A,
			MetricB:     tc.B,
			Coefficient: tc.R,
			Samples:     tc.N,
			Strength:    strength,
		})
	}

	// 7. Build Golden Signal summary
	result.GoldenSignals = buildGoldenSignals(curr, rates)

	// 8. Process behavior profiling — detect processes deviating from their learned profile
	if rates != nil && len(rates.ProcessRates) > 0 {
		tracked := 0
		for _, pr := range rates.ProcessRates {
			if tracked >= 20 {
				break
			}
			if pr.CPUPct < 0.5 && pr.ReadMBs+pr.WriteMBs < 0.1 {
				continue
			}
			tracked++
			// Key by Comm (not PID) to avoid unbounded map growth from short-lived processes
			cpuID := "proc." + pr.Comm + ".cpu"
			ioID := "proc." + pr.Comm + ".io"

			hist.Baselines.Update(cpuID, pr.CPUPct)
			hist.Baselines.Update(ioID, pr.ReadMBs+pr.WriteMBs)

			if hist.Baselines.IsAnomaly(cpuID, pr.CPUPct, 3.0) {
				mean, std, _ := hist.Baselines.Get(cpuID)
				result.ProcessAnomalies = append(result.ProcessAnomalies, model.ProcessAnomaly{
					PID: pr.PID, Comm: pr.Comm, Metric: "cpu_pct",
					Current: pr.CPUPct, Baseline: mean, StdDev: std,
					Sigma: hist.Baselines.ZScore(cpuID, pr.CPUPct),
				})
			}
			if hist.Baselines.IsAnomaly(ioID, pr.ReadMBs+pr.WriteMBs, 3.0) {
				mean, std, _ := hist.Baselines.Get(ioID)
				result.ProcessAnomalies = append(result.ProcessAnomalies, model.ProcessAnomaly{
					PID: pr.PID, Comm: pr.Comm, Metric: "io_mbs",
					Current: pr.ReadMBs + pr.WriteMBs, Baseline: mean, StdDev: std,
					Sigma: hist.Baselines.ZScore(ioID, pr.ReadMBs+pr.WriteMBs),
				})
			}
		}
		if len(result.ProcessAnomalies) > 5 {
			sort.Slice(result.ProcessAnomalies, func(i, j int) bool {
				return result.ProcessAnomalies[i].Sigma > result.ProcessAnomalies[j].Sigma
			})
			result.ProcessAnomalies = result.ProcessAnomalies[:5]
		}
	}

	// 9. Feed causal learning observations
	// Snapshot signalOnsets under hist.mu, then release before calling Observe
	// to avoid nested locking (hist.mu → CausalLearner.mu).
	hist.mu.RLock()
	onsetsCopy := make(map[string]time.Time, len(hist.signalOnsets))
	for k, v := range hist.signalOnsets {
		onsetsCopy[k] = v
	}
	hist.mu.RUnlock()

	for _, rule := range causalRules {
		_, causeFired := evidenceMap[rule.from]
		_, effectFired := evidenceMap[rule.to]
		if causeFired || effectFired {
			causeOnset, cOK := onsetsCopy[rule.from]
			effectOnset, eOK := onsetsCopy[rule.to]
			causeFirst := false
			if cOK && eOK {
				causeFirst = !causeOnset.After(effectOnset)
			} else if cOK && !eOK {
				causeFirst = true
			}
			hist.CausalLearner.Observe(rule.rule, causeFired, effectFired, causeFirst)
		}
	}
}

// buildGoldenSignals approximates Google SRE Golden Signals from /proc data.
func buildGoldenSignals(curr *model.Snapshot, rates *model.RateSnapshot) *model.GoldenSignalSummary {
	gs := &model.GoldenSignalSummary{}
	if curr == nil {
		return gs
	}

	// Latency: worst disk await + max PSI stall
	if rates != nil {
		for _, d := range rates.DiskRates {
			if d.AvgAwaitMs > gs.DiskLatencyMs {
				gs.DiskLatencyMs = d.AvgAwaitMs
			}
		}
	}
	psiMax := curr.Global.PSI.CPU.Some.Avg10
	if curr.Global.PSI.Memory.Some.Avg10 > psiMax {
		psiMax = curr.Global.PSI.Memory.Some.Avg10
	}
	if curr.Global.PSI.IO.Full.Avg10 > psiMax {
		psiMax = curr.Global.PSI.IO.Full.Avg10
	}
	gs.PSIStallPct = psiMax

	// Traffic: TCP segments + bytes
	if rates != nil {
		gs.TCPSegmentsPerSec = rates.InSegRate + rates.OutSegRate
		var totalMBs float64
		for _, nr := range rates.NetRates {
			totalMBs += nr.RxMBs + nr.TxMBs
		}
		gs.NetBytesPerSec = totalMBs * 1024 * 1024 // convert MB/s → B/s

		// Error: drops + retrans + resets + OOM
		var totalDrops float64
		for _, nr := range rates.NetRates {
			totalDrops += nr.RxDropsPS + nr.TxDropsPS
		}
		gs.ErrorRate = totalDrops + rates.RetransRate + rates.TCPResetRate + float64(rates.OOMKillDelta)

		// Saturation: max of conntrack%, ephemeral%, runqueue/cores, PSI
		sat := psiMax / 100 // normalize to 0-1
		if curr.Global.Conntrack.Max > 0 {
			ctPct := float64(curr.Global.Conntrack.Count) / float64(curr.Global.Conntrack.Max)
			if ctPct > sat {
				sat = ctPct
			}
		}
		nCPUs := curr.Global.CPU.NumCPUs
		if nCPUs == 0 {
			nCPUs = 1
		}
		rqRatio := curr.Global.CPU.LoadAvg.Load1 / float64(nCPUs)
		if rqRatio > 1 {
			rqRatio = 1
		}
		if rqRatio > sat {
			sat = rqRatio
		}
		gs.SaturationPct = sat * 100
	}

	return gs
}

