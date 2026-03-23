package engine

import (
	"fmt"

	"github.com/ftahirops/xtop/model"
)

// ---------- Memory Score ----------
// Evidence groups: PSI, Low available, Swap active, Direct reclaim, Major faults, OOM
func analyzeMemory(curr *model.Snapshot, rates *model.RateSnapshot, sp systemProfile) model.RCAEntry {
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
	if memPSIAvg300 > memPSIAccelMinAvg300 && memPSIAvg10 > 2*memPSIAvg300 {
		psiAcceleration = true
	}

	// Dynamic available threshold: scale for large-memory systems
	// On 256GB box, 15% free = 38GB (fine). Use min(85%, absoluteFloor)
	// Google SRE: "alert on symptoms not causes" — use absolute floor
	totalGB := float64(mem.Total) / (1024 * 1024 * 1024)
	availWarn := float64(85)
	availCrit := float64(95)
	if totalGB > memLargeSystemGB {
		// On large systems, 500MB free is the real danger zone
		absFloor := memLargeSystemFloorMB / (totalGB * 1024) * 100 // absFloor as % of total
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
	// System-profile-based scaling: very large systems have proportionally more headroom.
	// Order matters: check >128 first since it's a superset of >64.
	if sp.TotalMemGB > 128 {
		availWarn = 92.0 // 128GB+ system: ~10GB free is still OK
		availCrit = 98.0
	} else if sp.TotalMemGB > 64 {
		availWarn = 90.0 // 64GB+ system: 6.4GB free is still OK
		availCrit = 97.0
	}

	// Direct reclaim confidence: dampen when PSI shows no pressure
	// (Gregg: direct reclaim from cache pressure is normal, only meaningful with PSI)
	reclaimConf := memReclaimBaseConf
	if memSome < memPSISomeMinForReclaim {
		reclaimConf = memReclaimNoPSIConf // much less confident without PSI confirmation
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
	if slabPctOfTotal > slabLeakMinPct && slabUnreclaimDelta > 0 {
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
		if dn.AllocRateMBs > dotnetAllocStormMBs {
			r.EvidenceV2 = append(r.EvidenceV2, emitEvidence("dotnet.alloc.storm", model.DomainMemory,
				dn.AllocRateMBs, 50, 200, true, 0.8,
				fmt.Sprintf(".NET alloc=%.0f MB/s (PID %d %s)", dn.AllocRateMBs, dn.PID, dn.Comm), "1s",
				nil, map[string]string{"pid": fmt.Sprintf("%d", dn.PID)}))
			break
		}
	}
	for _, dn := range curr.Global.DotNet {
		if dn.ThreadPoolQueue > dotnetThreadPoolQueueN {
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
			if heapPct > jvmHeapPressurePct {
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
	if oomDetected && v2TrustGate(r.EvidenceV2) && r.Score < memOOMMinScore {
		r.Score = memOOMMinScore
	}
	if availPct > memSafeAvailPct && memSome < memSafePSISome && memFull < memSafePSIFull {
		if r.Score > memSafeMaxScore {
			r.Score = memSafeMaxScore
		}
	}
	if r.Score < rcaScoreFloor {
		r.Score = 0
	}
	cap100(&r.Score)
	r.EvidenceGroups = evidenceGroupsFired(r.EvidenceV2, evidenceStrengthMin)
	r.Checks = evidenceToChecks(r.EvidenceV2)

	// Evidence strings
	if memSome > memEvPSISomeMin {
		r.Evidence = append(r.Evidence, fmt.Sprintf("MEM PSI some=%.1f%%", memSome*100))
	}
	if memFull > memEvPSIFullMin {
		r.Evidence = append(r.Evidence, fmt.Sprintf("MEM PSI full=%.1f%%", memFull*100))
	}
	if psiAcceleration {
		r.Evidence = append(r.Evidence, fmt.Sprintf("PSI spike: avg10=%.1f%% vs avg300=%.1f%%", memPSIAvg10, memPSIAvg300))
	}
	if availPct < memEvAvailPctMin {
		r.Evidence = append(r.Evidence, fmt.Sprintf("MemAvailable=%.1f%% (%s)", availPct, formatB(mem.Available)))
	}
	swapIOMBs := swapInRate + swapOutRate
	if swapInRate > memEvSwapRateMin {
		r.Evidence = append(r.Evidence, fmt.Sprintf("Swap in=%.1f MB/s (demand paging)", swapInRate))
	}
	if swapOutRate > memEvSwapRateMin {
		r.Evidence = append(r.Evidence, fmt.Sprintf("Swap out=%.1f MB/s", swapOutRate))
	}
	if directReclaimRate > 0 {
		r.Evidence = append(r.Evidence, fmt.Sprintf("Direct reclaim=%.0f pages/s (ratio=%.0f%%)", directReclaimRate, directPct*100))
	}
	if allocStallRate > 0 {
		r.Evidence = append(r.Evidence, fmt.Sprintf("Alloc stalls=%.0f/s", allocStallRate))
	}
	if majFaultRate > memEvMajFaultMin {
		r.Evidence = append(r.Evidence, fmt.Sprintf("Major faults=%.0f/s", majFaultRate))
	}
	if oomDetected {
		r.Evidence = append(r.Evidence, fmt.Sprintf("OOM kills=%d in last tick", oomDelta))
	}
	if slabPctOfTotal > memEvSlabPctMin {
		r.Evidence = append(r.Evidence, fmt.Sprintf("Slab unreclaimable=%.0fMB (%.1f%%)", slabUnreclaimMB, slabPctOfTotal))
	}

	// Chain
	if r.Score > 0 && r.EvidenceGroups >= minEvidenceGroups {
		r.Chain = append(r.Chain, "Memory pressure detected")
		if swapIOMBs > memEvSwapRateMin {
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
			if vm.MemSwapMB > pveSwapMinMB && vm.PSIMemSome > pveSwapMinPSI {
				r.EvidenceV2 = append(r.EvidenceV2, emitEvidence("pve.vm.swap", model.DomainMemory,
					float64(vm.MemSwapMB), 100, 1024, false, 0.8,
					fmt.Sprintf("VM %d (%s) swap=%dMB with pressure", vm.VMID, vm.Name, vm.MemSwapMB), "cgroup",
					nil, map[string]string{"vmid": fmt.Sprintf("%d", vm.VMID)}))
			}
			// Memory near limit only matters if OOM events are happening
			if vm.MemLimitMB > 0 && vm.MemUsedMB > 0 && vm.MemOOMEvents > 0 {
				pct := float64(vm.MemUsedMB) / float64(vm.MemLimitMB) * 100
				if pct > pveMemLimitWarnPct {
					r.EvidenceV2 = append(r.EvidenceV2, emitEvidence("pve.vm.memlimit", model.DomainMemory,
						pct, 85, 95, true, 0.75,
						fmt.Sprintf("VM %d (%s) mem=%.0f%% of limit with OOM events", vm.VMID, vm.Name, pct), "cgroup",
						nil, map[string]string{"vmid": fmt.Sprintf("%d", vm.VMID)}))
				}
			}
			// Memory PSI — direct proof of degradation
			if vm.PSIMemSome > pvePSIMemMinSome {
				r.EvidenceV2 = append(r.EvidenceV2, emitEvidence("pve.vm.mempsi", model.DomainMemory,
					vm.PSIMemSome, 15, 40, true, 0.7,
					fmt.Sprintf("VM %d (%s) mem PSI=%.1f%%", vm.VMID, vm.Name, vm.PSIMemSome), "cgroup",
					nil, map[string]string{"vmid": fmt.Sprintf("%d", vm.VMID)}))
			}
		}
	}

	return r
}
