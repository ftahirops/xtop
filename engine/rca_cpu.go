package engine

import (
	"fmt"

	"github.com/ftahirops/xtop/model"
)

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
		if avgSoftIRQ > cpuSoftIRQAvgMinForImbal {
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
		if dn.TimeInGCPct > dotnetGCPauseMinPct {
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
			if jp.GCPausePct > jvmGCPauseMinPct {
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
			if vm.CPUThrottledPct > pveCPUThrottleMinPct {
				r.EvidenceV2 = append(r.EvidenceV2, emitEvidence("pve.vm.throttle", model.DomainCPU,
					vm.CPUThrottledPct, 5, 25, true, 0.85,
					fmt.Sprintf("VM %d (%s) throttled=%.1f%%", vm.VMID, vm.Name, vm.CPUThrottledPct), "cgroup",
					nil, map[string]string{"vmid": fmt.Sprintf("%d", vm.VMID)}))
			}
			if vm.PSICPUSome > pveCPUSomeMinPSI {
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
	if iowaitPct > cpuIOWaitMinPct {
		w6, c6 := threshold("cpu.iowait", 10, 30)
		r.EvidenceV2 = append(r.EvidenceV2, emitEvidence("cpu.iowait", model.DomainCPU,
			iowaitPct, w6, c6, true, 0.8,
			fmt.Sprintf("CPU iowait=%.1f%%", iowaitPct), "1s",
			nil, nil))
	}

	// IRQ imbalance: single CPU handling disproportionate softIRQ load (Gregg: check /proc/softirqs)
	if irqImbalanceRatio > cpuIRQImbalanceMinRatio {
		w7, c7 := threshold("cpu.irq.imbalance", 5, 10)
		r.EvidenceV2 = append(r.EvidenceV2, emitEvidence("cpu.irq.imbalance", model.DomainCPU,
			irqImbalanceRatio, w7, c7, true, 0.65,
			fmt.Sprintf("softIRQ imbalance ratio=%.1fx (one CPU hot)", irqImbalanceRatio), "1s",
			nil, nil))
	}

	// Dampen GC pause confidence when run queue is healthy (no CPU contention = GC is not the bottleneck)
	rqStrength := normalize(rqRatio, 1.0, 2.0)
	if rqStrength < cpuRunQueueDampenThreshold {
		for i := range r.EvidenceV2 {
			if r.EvidenceV2[i].ID == "dotnet.gc.pause" || r.EvidenceV2[i].ID == "jvm.gc.pause" {
				r.EvidenceV2[i].Confidence *= cpuGCPauseDampenFactor
			}
		}
	}

	// v2 scoring
	v2Score := weightedDomainScore(r.EvidenceV2)
	if !v2TrustGate(r.EvidenceV2) {
		v2Score = 0
	}
	r.Score = int(v2Score)
	if busyPct < cpuSafeBusyPct && cpuSome < cpuSafePSISome && cpuFull < cpuSafePSIFull {
		if r.Score > cpuSafeMaxScore {
			r.Score = cpuSafeMaxScore
		}
	}
	if stealPct > cpuStealBonusThreshold && v2TrustGate(r.EvidenceV2) {
		r.Score += cpuStealBonusScore
	}
	if r.Score < rcaScoreFloor {
		r.Score = 0
	}
	cap100(&r.Score)
	r.EvidenceGroups = evidenceGroupsFired(r.EvidenceV2, evidenceStrengthMin)
	r.Checks = evidenceToChecks(r.EvidenceV2)

	// Evidence strings
	if busyPct > cpuEvBusyMin {
		r.Evidence = append(r.Evidence, fmt.Sprintf("CPU busy=%.1f%%", busyPct))
	}
	if cpuSome > cpuEvPSISomeMin {
		r.Evidence = append(r.Evidence, fmt.Sprintf("CPU PSI some=%.1f%%", cpuSome*100))
	}
	if cpuFull > cpuEvPSIFullMin {
		r.Evidence = append(r.Evidence, fmt.Sprintf("CPU PSI full=%.1f%%", cpuFull*100))
	}
	if rqRatio > cpuEvRunQueueMin {
		r.Evidence = append(r.Evidence, fmt.Sprintf("Run queue ratio=%.1f (%d runnable / %d cores)", rqRatio, int(running), nCPUs))
	}
	if csPerCore > cpuEvCtxSwitchPerCore {
		r.Evidence = append(r.Evidence, fmt.Sprintf("Context switches=%.0f/s (%.0f/core)", ctxRate, csPerCore))
	}
	if maxThrottlePct > cpuEvThrottleMin {
		r.Evidence = append(r.Evidence, fmt.Sprintf("Cgroup %s throttled %.1f%%", maxThrottleCg, maxThrottlePct))
		r.TopCgroup = maxThrottleCg
	}
	if stealPct > cpuEvStealMin {
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
