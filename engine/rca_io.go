package engine

import (
	"fmt"
	"strings"

	"github.com/ftahirops/xtop/model"
)

// ---------- IO Score ----------
// Evidence groups: PSI, D-state, Disk latency, Dirty pages
func analyzeIO(curr *model.Snapshot, rates *model.RateSnapshot, sp systemProfile) model.RCAEntry {
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
			if totalIOPS >= minIOPSForLatency && d.AvgAwaitMs > worstAwait {
				worstAwait = d.AvgAwaitMs
				worstDev = d.Name
			}
			if totalIOPS >= minIOPSForLatency && d.UtilPct > worstUtil {
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
	fsFull := worstFreePct < ioFsFullFreePct

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
	if fsUsedPct < fsFullUsedPctNoGrowth && worstGrowthBPS <= 0 {
		fsConf = fsFullGrowthDampenConf // dampen confidence when not actively growing
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
	if dCount >= ioDstateMinCount && v2TrustGate(r.EvidenceV2) && r.Score < ioDstateBumpScore {
		r.Score = ioDstateBumpScore
	}
	if r.Score < rcaScoreFloor {
		r.Score = 0
	}
	cap100(&r.Score)
	r.EvidenceGroups = evidenceGroupsFired(r.EvidenceV2, evidenceStrengthMin)
	r.Checks = evidenceToChecks(r.EvidenceV2)

	// Evidence strings
	if ioSome > ioEvPSISomeMin {
		r.Evidence = append(r.Evidence, fmt.Sprintf("IO PSI some=%.1f%%", ioSome*100))
	}
	if ioFull > ioEvPSIFullMin {
		r.Evidence = append(r.Evidence, fmt.Sprintf("IO PSI full=%.1f%%", ioFull*100))
	}
	if dCount > 0 {
		r.Evidence = append(r.Evidence, fmt.Sprintf("D-state tasks=%d (%s)", dCount, strings.Join(dProcs, ", ")))
	}
	if worstAwait > ioEvAwaitMin {
		r.Evidence = append(r.Evidence, fmt.Sprintf("%s await=%.0fms", worstDev, worstAwait))
	}
	if worstUtil > ioEvUtilMin {
		r.Evidence = append(r.Evidence, fmt.Sprintf("%s util=%.0f%%", worstDev, worstUtil))
	}
	if dirtyPct > ioEvDirtyPctMin {
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
		if worstAwait > ioEvAwaitMin {
			r.Chain = append(r.Chain, fmt.Sprintf("%s latency=%.0fms", worstDev, worstAwait))
		}
		r.Chain = append(r.Chain, "Application latency risk")
	}

	// Culprit
	findIOCulprit(curr, rates, &r)
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
	// Culprit selection: find who CAUSED the IO, not who's stuck in it.
	// Priority: 1) top memory consumer (if memory-induced IO), 2) top IO writer,
	// 3) D-state process, 4) top IO reader.
	// Always exclude xtop itself and kernel threads.

	// If IO is caused by memory reclaim (swap storm), blame the memory hog, not IO victim
	if rates != nil && (rates.SwapInRate > 0 || rates.DirectReclaimRate > 0) {
		var maxRSS uint64
		for _, pr := range rates.ProcessRates {
			if isKernelThread(pr.Comm) || isSelfProcess(pr.Comm) {
				continue
			}
			if pr.RSS > maxRSS {
				maxRSS = pr.RSS
				r.TopProcess = pr.Comm
				r.TopPID = pr.PID
			}
		}
		if r.TopProcess != "" {
			return
		}
	}

	// Top IO writer by throughput (the actual IO generator)
	if rates != nil {
		var maxIO float64
		for _, pr := range rates.ProcessRates {
			if isKernelThread(pr.Comm) || isSelfProcess(pr.Comm) {
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

	// D-state user-space process (stuck waiting for IO)
	for _, p := range curr.Processes {
		if p.State == "D" && !isKernelThread(p.Comm) && !isSelfProcess(p.Comm) {
			r.TopProcess = p.Comm
			r.TopPID = p.PID
			return
		}
	}

	// Fallback: any user-space process with high IO bytes
	var maxIO uint64
	for _, p := range curr.Processes {
		if isKernelThread(p.Comm) || isSelfProcess(p.Comm) {
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
