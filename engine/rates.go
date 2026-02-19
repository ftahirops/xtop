package engine

import (
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/ftahirops/xtop/model"
	"github.com/ftahirops/xtop/util"
)

// ComputeRates computes all rates between two snapshots.
func ComputeRates(prev, curr *model.Snapshot) model.RateSnapshot {
	dt := curr.Timestamp.Sub(prev.Timestamp)
	if dt <= 0 {
		dt = time.Second
	}
	r := model.RateSnapshot{DeltaSec: dt.Seconds()}

	computeCPURates(prev, curr, &r)
	computeMemRates(prev, curr, dt, &r)
	computeDiskRates(prev, curr, dt, &r)
	computeMountRates(prev, curr, dt, &r)
	computeNetRates(prev, curr, dt, &r)
	computeSoftIRQRates(prev, curr, dt, &r)
	computeCgroupRates(prev, curr, dt, &r)
	computeProcessRates(prev, curr, dt, &r)
	return r
}

func computeCPURates(prev, curr *model.Snapshot, r *model.RateSnapshot) {
	pt := prev.Global.CPU.Total
	ct := curr.Global.CPU.Total
	dtotal := ct.Total() - pt.Total()
	if dtotal == 0 {
		return
	}
	pct := func(pv, cv uint64) float64 {
		return float64(cv-pv) / float64(dtotal) * 100
	}
	r.CPUUserPct = pct(pt.User+pt.Nice, ct.User+ct.Nice)
	r.CPUSystemPct = pct(pt.System, ct.System)
	r.CPUIOWaitPct = pct(pt.IOWait, ct.IOWait)
	r.CPUSoftIRQPct = pct(pt.SoftIRQ, ct.SoftIRQ)
	r.CPUIRQPct = pct(pt.IRQ, ct.IRQ)
	r.CPUStealPct = pct(pt.Steal, ct.Steal)
	r.CPUNicePct = pct(pt.Nice, ct.Nice)
	r.CPUBusyPct = float64(ct.Active()-pt.Active()) / float64(dtotal) * 100

	// Estimate ctx switch rate from processes
	var prevCtx, currCtx uint64
	for _, p := range prev.Processes {
		prevCtx += p.VoluntaryCtxSwitches + p.NonVoluntaryCtxSwitches
	}
	for _, p := range curr.Processes {
		currCtx += p.VoluntaryCtxSwitches + p.NonVoluntaryCtxSwitches
	}
	r.CtxSwitchRate = util.Rate(prevCtx, currCtx, curr.Timestamp.Sub(prev.Timestamp))
}

func computeMemRates(prev, curr *model.Snapshot, dt time.Duration, r *model.RateSnapshot) {
	pv := prev.Global.VMStat
	cv := curr.Global.VMStat
	// Swap rates in pages/s, convert to approx MB/s (4KB pages)
	r.SwapInRate = util.Rate(pv.PswpIn, cv.PswpIn, dt) * 4 / 1024
	r.SwapOutRate = util.Rate(pv.PswpOut, cv.PswpOut, dt) * 4 / 1024
	r.PgFaultRate = util.Rate(pv.PgFault, cv.PgFault, dt)
	r.MajFaultRate = util.Rate(pv.PgMajFault, cv.PgMajFault, dt)
	r.DirectReclaimRate = util.Rate(pv.PgScanDirect, cv.PgScanDirect, dt)
	r.KswapdRate = util.Rate(pv.PgScanKswapd, cv.PgScanKswapd, dt)
}

func computeDiskRates(prev, curr *model.Snapshot, dt time.Duration, r *model.RateSnapshot) {
	prevMap := make(map[string]model.DiskStats)
	for _, d := range prev.Global.Disks {
		prevMap[d.Name] = d
	}
	for _, d := range curr.Global.Disks {
		pd, ok := prevMap[d.Name]
		if !ok {
			continue
		}
		readOps := util.Delta(pd.ReadsCompleted, d.ReadsCompleted)
		writeOps := util.Delta(pd.WritesCompleted, d.WritesCompleted)
		totalOps := readOps + writeOps
		totalTimeMs := util.Delta(pd.ReadTimeMs+pd.WriteTimeMs, d.ReadTimeMs+d.WriteTimeMs)

		var awaitMs float64
		if totalOps > 0 {
			awaitMs = float64(totalTimeMs) / float64(totalOps)
		}

		ioTicksDelta := util.Delta(pd.IOTimeMs, d.IOTimeMs)
		utilPct := float64(ioTicksDelta) / (dt.Seconds() * 1000) * 100
		if utilPct > 100 {
			utilPct = 100
		}

		dr := model.DiskRate{
			Name:       d.Name,
			ReadMBs:    util.Rate(pd.SectorsRead, d.SectorsRead, dt) * 512 / (1024 * 1024),
			WriteMBs:   util.Rate(pd.SectorsWritten, d.SectorsWritten, dt) * 512 / (1024 * 1024),
			ReadIOPS:   util.Rate(pd.ReadsCompleted, d.ReadsCompleted, dt),
			WriteIOPS:  util.Rate(pd.WritesCompleted, d.WritesCompleted, dt),
			AvgAwaitMs: awaitMs,
			UtilPct:    utilPct,
			QueueDepth: d.IOsInProgress,
		}
		r.DiskRates = append(r.DiskRates, dr)
	}
}

func computeMountRates(prev, curr *model.Snapshot, dt time.Duration, r *model.RateSnapshot) {
	dtSec := dt.Seconds()
	if dtSec <= 0 {
		dtSec = 1
	}

	prevMap := make(map[string]model.MountStats)
	for _, m := range prev.Global.Mounts {
		prevMap[m.MountPoint] = m
	}

	for _, m := range curr.Global.Mounts {
		var usedPct, freePct, inodeUsedPct float64
		if m.TotalBytes > 0 {
			// Match df: usable = total - reserved; used% = used / usable
			// Reserved blocks = Bfree - Bavail (space only root can use)
			usable := m.TotalBytes - (m.FreeBytes - m.AvailBytes)
			if usable > 0 {
				usedPct = float64(m.UsedBytes) / float64(usable) * 100
			}
			freePct = float64(m.AvailBytes) / float64(usable) * 100
		}
		if m.TotalInodes > 0 {
			inodeUsedPct = float64(m.UsedInodes) / float64(m.TotalInodes) * 100
		}

		var growthBPS float64
		if pm, ok := prevMap[m.MountPoint]; ok && m.UsedBytes > pm.UsedBytes {
			growthBPS = float64(m.UsedBytes-pm.UsedBytes) / dtSec
		}

		var etaSec float64 = -1
		if growthBPS > 0 && m.FreeBytes > 0 {
			etaSec = float64(m.FreeBytes) / growthBPS
		}

		mr := model.MountRate{
			MountPoint:        m.MountPoint,
			Device:            m.Device,
			FSType:            m.FSType,
			TotalBytes:        m.TotalBytes,
			UsedPct:           usedPct,
			FreePct:           freePct,
			FreeBytes:         m.FreeBytes,
			InodeUsedPct:      inodeUsedPct,
			GrowthBytesPerSec: growthBPS,
			ETASeconds:        etaSec,
			State:             "OK",
		}
		r.MountRates = append(r.MountRates, mr)
	}
}

func computeNetRates(prev, curr *model.Snapshot, dt time.Duration, r *model.RateSnapshot) {
	prevMap := make(map[string]model.NetworkStats)
	for _, n := range prev.Global.Network {
		prevMap[n.Name] = n
	}
	for _, n := range curr.Global.Network {
		pn, ok := prevMap[n.Name]
		if !ok {
			continue
		}
		rxMBs := util.Rate(pn.RxBytes, n.RxBytes, dt) / (1024 * 1024)
		txMBs := util.Rate(pn.TxBytes, n.TxBytes, dt) / (1024 * 1024)
		nr := model.NetRate{
			Name:       n.Name,
			RxMBs:      rxMBs,
			TxMBs:      txMBs,
			RxPPS:      util.Rate(pn.RxPackets, n.RxPackets, dt),
			TxPPS:      util.Rate(pn.TxPackets, n.TxPackets, dt),
			RxDropsPS:  util.Rate(pn.RxDrops, n.RxDrops, dt),
			TxDropsPS:  util.Rate(pn.TxDrops, n.TxDrops, dt),
			RxErrorsPS: util.Rate(pn.RxErrors, n.RxErrors, dt),
			TxErrorsPS: util.Rate(pn.TxErrors, n.TxErrors, dt),
			OperState:  n.OperState,
			SpeedMbps:  n.SpeedMbps,
			Master:     n.Master,
			IfType:     n.IfType,
			UtilPct:    -1,
		}
		if n.SpeedMbps > 0 {
			nr.UtilPct = (rxMBs + txMBs) * 8 * 1024 / float64(n.SpeedMbps) * 100
			if nr.UtilPct > 100 {
				nr.UtilPct = 100
			}
		}
		r.NetRates = append(r.NetRates, nr)
	}

	r.RetransRate = util.Rate(prev.Global.TCP.RetransSegs, curr.Global.TCP.RetransSegs, dt)
	r.InSegRate = util.Rate(prev.Global.TCP.InSegs, curr.Global.TCP.InSegs, dt)
	r.OutSegRate = util.Rate(prev.Global.TCP.OutSegs, curr.Global.TCP.OutSegs, dt)
	r.TCPResetRate = util.Rate(prev.Global.TCP.EstabResets, curr.Global.TCP.EstabResets, dt)

	r.UDPInRate = util.Rate(prev.Global.UDP.InDatagrams, curr.Global.UDP.InDatagrams, dt)
	r.UDPOutRate = util.Rate(prev.Global.UDP.OutDatagrams, curr.Global.UDP.OutDatagrams, dt)
	r.UDPErrRate = util.Rate(prev.Global.UDP.InErrors+prev.Global.UDP.RcvbufErrors,
		curr.Global.UDP.InErrors+curr.Global.UDP.RcvbufErrors, dt)
}

func computeSoftIRQRates(prev, curr *model.Snapshot, dt time.Duration, r *model.RateSnapshot) {
	r.SoftIRQNetRxRate = util.Rate(prev.Global.SoftIRQ.NET_RX, curr.Global.SoftIRQ.NET_RX, dt)
	r.SoftIRQNetTxRate = util.Rate(prev.Global.SoftIRQ.NET_TX, curr.Global.SoftIRQ.NET_TX, dt)
	r.SoftIRQBlockRate = util.Rate(prev.Global.SoftIRQ.BLOCK, curr.Global.SoftIRQ.BLOCK, dt)
}

func computeCgroupRates(prev, curr *model.Snapshot, dt time.Duration, r *model.RateSnapshot) {
	prevMap := make(map[string]model.CgroupMetrics)
	for _, cg := range prev.Cgroups {
		prevMap[cg.Path] = cg
	}
	totalMem := curr.Global.Memory.Total
	if totalMem == 0 {
		totalMem = 1
	}

	for _, cg := range curr.Cgroups {
		pcg, ok := prevMap[cg.Path]
		if !ok {
			continue
		}
		cpuDelta := util.Delta(pcg.UsageUsec, cg.UsageUsec)
		cpuPct := float64(cpuDelta) / (dt.Seconds() * 1e6) * 100 // µs→s, then %

		var throttlePct float64
		periodDelta := util.Delta(pcg.NrPeriods, cg.NrPeriods)
		throttleDelta := util.Delta(pcg.NrThrottled, cg.NrThrottled)
		if periodDelta > 0 {
			throttlePct = float64(throttleDelta) / float64(periodDelta) * 100
		}

		cr := model.CgroupRate{
			Path:        cg.Path,
			Name:        cg.Name,
			CPUPct:      cpuPct,
			ThrottlePct: throttlePct,
			MemPct:      float64(cg.MemCurrent) / float64(totalMem) * 100,
			IORateMBs:   util.Rate(pcg.IORBytes, cg.IORBytes, dt) / (1024 * 1024),
			IOWRateMBs:  util.Rate(pcg.IOWBytes, cg.IOWBytes, dt) / (1024 * 1024),
		}
		r.CgroupRates = append(r.CgroupRates, cr)
	}
}

func computeProcessRates(prev, curr *model.Snapshot, dt time.Duration, r *model.RateSnapshot) {
	prevMap := make(map[int]model.ProcessMetrics)
	for _, p := range prev.Processes {
		prevMap[p.PID] = p
	}

	totalMem := curr.Global.Memory.Total
	if totalMem == 0 {
		totalMem = 1
	}
	// Total CPU ticks in this period
	cpuDtotal := curr.Global.CPU.Total.Total() - prev.Global.CPU.Total.Total()
	if cpuDtotal == 0 {
		cpuDtotal = 1
	}

	for _, p := range curr.Processes {
		pp, ok := prevMap[p.PID]
		if !ok {
			continue
		}
		cpuDelta := util.Delta(pp.UTime+pp.STime, p.UTime+p.STime)
		var fdPct float64
		if p.FDSoftLimit > 0 {
			fdPct = float64(p.FDCount) / float64(p.FDSoftLimit) * 100
		}
		pr := model.ProcessRate{
			PID:           p.PID,
			Comm:          p.Comm,
			State:         p.State,
			CgroupPath:    p.CgroupPath,
			ServiceName:   resolveServiceName(p.CgroupPath),
			CPUPct:        float64(cpuDelta) / float64(cpuDtotal) * 100 * float64(curr.Global.CPU.NumCPUs),
			MemPct:        float64(p.RSS) / float64(totalMem) * 100,
			ReadMBs:       util.Rate(pp.ReadBytes, p.ReadBytes, dt) / (1024 * 1024),
			WriteMBs:      util.Rate(pp.WriteBytes, p.WriteBytes, dt) / (1024 * 1024),
			FaultRate:     util.Rate(pp.MinFault, p.MinFault, dt),
			MajFaultRate:  util.Rate(pp.MajFault, p.MajFault, dt),
			CtxSwitchRate: util.Rate(pp.VoluntaryCtxSwitches+pp.NonVoluntaryCtxSwitches, p.VoluntaryCtxSwitches+p.NonVoluntaryCtxSwitches, dt),
			RSS:           p.RSS,
			VmSwap:        p.VmSwap,
			NumThreads:    p.NumThreads,
			FDCount:       p.FDCount,
			FDSoftLimit:   p.FDSoftLimit,
			FDPct:         fdPct,
		}
		r.ProcessRates = append(r.ProcessRates, pr)
	}

	// Resolve write paths for top writers (budget: top 20 by WriteMBs)
	resolveWritePaths(r.ProcessRates)
}

// resolveWritePaths populates WritePath for the top writer processes by
// reading /proc/<pid>/fd/ symlinks to find open regular files.
func resolveWritePaths(rates []model.ProcessRate) {
	// Sort indices by WriteMBs descending to find top writers
	type idx struct {
		i    int
		rate float64
	}
	var writers []idx
	for i, pr := range rates {
		if pr.WriteMBs > 0.001 {
			writers = append(writers, idx{i, pr.WriteMBs})
		}
	}
	sort.Slice(writers, func(a, b int) bool {
		return writers[a].rate > writers[b].rate
	})
	if len(writers) > 20 {
		writers = writers[:20]
	}

	for _, w := range writers {
		pid := rates[w.i].PID
		path := resolveProcessWritePath(pid)
		if path != "" {
			rates[w.i].WritePath = path
		}
	}
}

// resolveProcessWritePath reads /proc/<pid>/fd/ to find the primary file being written.
// It picks the largest open regular file, skipping deleted files, pipes, sockets, and internal tool paths.
func resolveProcessWritePath(pid int) string {
	fdDir := fmt.Sprintf("/proc/%d/fd", pid)
	entries, err := os.ReadDir(fdDir)
	if err != nil {
		return ""
	}

	type candidate struct {
		path string
		size int64
	}
	var candidates []candidate

	for _, e := range entries {
		fdPath := fmt.Sprintf("%s/%s", fdDir, e.Name())
		link, err := os.Readlink(fdPath)
		if err != nil {
			continue
		}
		// Skip non-file FDs
		if strings.HasPrefix(link, "pipe:") ||
			strings.HasPrefix(link, "socket:") ||
			strings.HasPrefix(link, "anon_inode:") ||
			strings.HasPrefix(link, "/dev/") ||
			strings.HasPrefix(link, "/proc/") ||
			strings.HasPrefix(link, "/sys/") {
			continue
		}
		if link == "" {
			continue
		}
		// Skip deleted files
		if strings.HasSuffix(link, " (deleted)") {
			continue
		}
		// Stat via the fd path (works even if filename has special chars)
		info, err := os.Stat(fdPath)
		if err != nil {
			// Can't stat — still include but with size 0
			candidates = append(candidates, candidate{path: link, size: 0})
			continue
		}
		candidates = append(candidates, candidate{path: link, size: info.Size()})
	}

	if len(candidates) == 0 {
		return ""
	}

	// Pick the largest file — most likely the write target
	best := candidates[0]
	for _, c := range candidates[1:] {
		if c.size > best.size {
			best = c
		}
	}
	return best.path
}

// resolveServiceName extracts a human-readable service/container name from a cgroup path.
// Examples:
//   /system.slice/mysql.service                    → mysql.service
//   /kubepods/pod.../cri-containerd-.../           → k8s:<container-id-prefix>
//   /docker/abc123...                              → docker:abc123
//   /user.slice/user-1000.slice/session-1.scope    → session-1.scope
func resolveServiceName(cgPath string) string {
	if cgPath == "" || cgPath == "/" {
		return ""
	}
	parts := strings.Split(strings.TrimRight(cgPath, "/"), "/")
	if len(parts) == 0 {
		return ""
	}
	leaf := parts[len(parts)-1]

	// Kubernetes: /kubepods[.slice]/.../<container-id>
	for i, p := range parts {
		if strings.HasPrefix(p, "kubepods") {
			// The last part is usually the container ID
			if len(parts) > i+2 {
				cid := parts[len(parts)-1]
				// Try to find pod name in middle segments
				for _, seg := range parts[i+1:] {
					if strings.HasPrefix(seg, "pod") {
						podID := strings.TrimPrefix(seg, "pod")
						if len(podID) > 8 {
							podID = podID[:8]
						}
						if len(cid) > 12 {
							cid = cid[:12]
						}
						return "k8s:" + cid
					}
				}
				if len(cid) > 12 {
					cid = cid[:12]
				}
				return "k8s:" + cid
			}
			return "k8s:" + leaf
		}
	}

	// Docker: /docker/<container-id> or /system.slice/docker-<id>.scope
	for _, p := range parts {
		if p == "docker" {
			if len(leaf) > 12 {
				return "docker:" + leaf[:12]
			}
			return "docker:" + leaf
		}
		if strings.HasPrefix(p, "docker-") && strings.HasSuffix(p, ".scope") {
			cid := strings.TrimPrefix(p, "docker-")
			cid = strings.TrimSuffix(cid, ".scope")
			if len(cid) > 12 {
				cid = cid[:12]
			}
			return "docker:" + cid
		}
	}

	// Systemd service: *.service
	if strings.HasSuffix(leaf, ".service") {
		return leaf
	}

	// Systemd scope (e.g., session-1.scope)
	if strings.HasSuffix(leaf, ".scope") {
		return leaf
	}

	return ""
}
