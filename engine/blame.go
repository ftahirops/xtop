package engine

import (
	"fmt"
	"sort"

	"github.com/ftahirops/xtop/model"
)

// ComputeBlame identifies top offending processes/cgroups for the primary bottleneck.
func ComputeBlame(result *model.AnalysisResult, curr *model.Snapshot, rates *model.RateSnapshot) []model.BlameEntry {
	if result == nil || rates == nil || result.Health == model.HealthOK {
		return nil
	}

	var entries []model.BlameEntry
	switch result.PrimaryBottleneck {
	case BottleneckCPU:
		entries = blameCPU(result, rates)
	case BottleneckMemory:
		entries = blameMemory(rates)
	case BottleneckIO:
		entries = blameIO(result, rates)
	case BottleneckNetwork:
		entries = blameNetwork(result, rates, curr)
	}

	// Resolve application identity for all blame entries
	if curr != nil && curr.Global.AppIdentities != nil {
		for i := range entries {
			if id, ok := curr.Global.AppIdentities[entries[i].PID]; ok {
				entries[i].AppName = id.DisplayName
			}
		}
	}

	return entries
}

// hasActiveEvidence checks whether any RCA entry for the given bottleneck has
// a firing evidence item (warn or critical) with the specified ID prefix.
func hasActiveEvidence(result *model.AnalysisResult, bottleneck, evidenceID string) bool {
	for _, rca := range result.RCA {
		if rca.Bottleneck != bottleneck {
			continue
		}
		for _, ev := range rca.EvidenceV2 {
			if ev.ID == evidenceID && ev.Severity != model.SeverityInfo {
				return true
			}
		}
	}
	return false
}

func blameCPU(result *model.AnalysisResult, rates *model.RateSnapshot) []model.BlameEntry {
	type agg struct {
		comm       string
		pid        int
		cgroup     string
		cpuPct     float64
		threads    int
		ctxsw      float64
	}

	// Detect whether cpu.steal evidence is active — if so, the hypervisor is
	// the real culprit and per-process blame should be dampened.
	stealActive := hasActiveEvidence(result, BottleneckCPU, "cpu.steal")

	// Use per-process data (top by CPU)
	procs := make([]agg, 0, len(rates.ProcessRates))
	for _, p := range rates.ProcessRates {
		if isKernelThread(p.Comm) {
			continue
		}
		if p.CPUPct < 1.0 {
			continue
		}
		procs = append(procs, agg{
			comm:   p.Comm,
			pid:    p.PID,
			cgroup: p.CgroupPath,
			cpuPct: p.CPUPct,
			threads: p.NumThreads,
			ctxsw:  p.CtxSwitchRate,
		})
	}
	sort.Slice(procs, func(i, j int) bool { return procs[i].cpuPct > procs[j].cpuPct })

	n := 5
	if len(procs) < n {
		n = len(procs)
	}

	entries := make([]model.BlameEntry, 0, n+1)
	for i := 0; i < n; i++ {
		p := procs[i]

		// When steal is active, dampen per-process blame since the real
		// cause is the hypervisor, not any local process.
		impact := p.cpuPct
		if stealActive {
			impact *= 0.5
		}

		metrics := map[string]string{
			"cpu": fmt.Sprintf("%.1f%%", p.cpuPct),
		}
		if stealActive {
			metrics["note"] = "dampened (steal)"
		}
		if p.threads > 1 {
			metrics["threads"] = fmt.Sprintf("%d", p.threads)
		}
		if p.ctxsw > 100 {
			metrics["ctxsw"] = fmt.Sprintf("%.0f/s", p.ctxsw)
		}
		entries = append(entries, model.BlameEntry{
			Comm:       p.comm,
			PID:        p.pid,
			CgroupPath: p.cgroup,
			Metrics:    metrics,
			ImpactPct:  impact,
		})
	}

	// If steal is the dominant issue, blame hypervisor
	if rates.CPUStealPct > rates.CPUBusyPct*0.3 && rates.CPUStealPct > 5 {
		entries = append([]model.BlameEntry{{
			Comm: "hypervisor-steal",
			Metrics: map[string]string{
				"steal": fmt.Sprintf("%.1f%%", rates.CPUStealPct),
			},
			ImpactPct: rates.CPUStealPct,
		}}, entries...)
	}

	return entries
}

func blameMemory(rates *model.RateSnapshot) []model.BlameEntry {
	type agg struct {
		comm   string
		pid    int
		cgroup string
		memPct float64
		rss    uint64
		swap   uint64
	}

	procs := make([]agg, 0, len(rates.ProcessRates))
	for _, p := range rates.ProcessRates {
		if isKernelThread(p.Comm) {
			continue
		}
		if p.MemPct < 0.5 {
			continue
		}
		procs = append(procs, agg{
			comm:   p.Comm,
			pid:    p.PID,
			cgroup: p.CgroupPath,
			memPct: p.MemPct,
			rss:    p.RSS,
			swap:   p.VmSwap,
		})
	}
	sort.Slice(procs, func(i, j int) bool { return procs[i].memPct > procs[j].memPct })

	n := 5
	if len(procs) < n {
		n = len(procs)
	}

	entries := make([]model.BlameEntry, 0, n)
	for i := 0; i < n; i++ {
		p := procs[i]
		metrics := map[string]string{
			"mem": fmt.Sprintf("%.1f%%", p.memPct),
			"rss": fmtBytes(p.rss),
		}
		if p.swap > 0 {
			metrics["swap"] = fmtBytes(p.swap)
		}
		entries = append(entries, model.BlameEntry{
			Comm:       p.comm,
			PID:        p.pid,
			CgroupPath: p.cgroup,
			Metrics:    metrics,
			ImpactPct:  p.memPct,
		})
	}
	return entries
}

func blameIO(result *model.AnalysisResult, rates *model.RateSnapshot) []model.BlameEntry {
	// Detect writeback or disk latency evidence — when active, write-heavy
	// processes deserve proportionally more blame than read-heavy ones.
	writebackActive := hasActiveEvidence(result, BottleneckIO, "io.writeback")
	diskLatActive := hasActiveEvidence(result, BottleneckIO, "io.disk.latency")
	writeWeighted := writebackActive || diskLatActive

	type agg struct {
		comm   string
		pid    int
		cgroup string
		ioMBs  float64
		readMB float64
		writMB float64
		write  string
	}

	procs := make([]agg, 0, len(rates.ProcessRates))
	for _, p := range rates.ProcessRates {
		if isKernelThread(p.Comm) {
			continue
		}

		// Base weight: writes already get 2x. When writeback/disk-latency
		// evidence fires, boost the write multiplier to 4x so write-heavy
		// processes float to the top of the blame list.
		writeMult := 2.0
		if writeWeighted {
			writeMult = 4.0
		}
		totalIO := p.ReadMBs + p.WriteMBs*writeMult
		if totalIO < 0.1 {
			continue
		}
		procs = append(procs, agg{
			comm:   p.Comm,
			pid:    p.PID,
			cgroup: p.CgroupPath,
			ioMBs:  totalIO,
			readMB: p.ReadMBs,
			writMB: p.WriteMBs,
			write:  p.WritePath,
		})
	}
	sort.Slice(procs, func(i, j int) bool { return procs[i].ioMBs > procs[j].ioMBs })

	n := 5
	if len(procs) < n {
		n = len(procs)
	}

	entries := make([]model.BlameEntry, 0, n)
	for i := 0; i < n; i++ {
		p := procs[i]
		metrics := map[string]string{
			"io": fmt.Sprintf("R:%.1f W:%.1f MB/s", p.readMB, p.writMB),
		}
		if writeWeighted && p.writMB > p.readMB {
			metrics["note"] = "write-heavy (writeback/latency)"
		}
		if p.write != "" {
			metrics["path"] = p.write
		}
		entries = append(entries, model.BlameEntry{
			Comm:       p.comm,
			PID:        p.pid,
			CgroupPath: p.cgroup,
			Metrics:    metrics,
			ImpactPct:  p.ioMBs,
		})
	}
	return entries
}

func blameNetwork(result *model.AnalysisResult, rates *model.RateSnapshot, curr *model.Snapshot) []model.BlameEntry {
	var entries []model.BlameEntry

	// 1. CLOSE_WAIT leakers — processes holding stale connections
	if curr != nil {
		for _, cw := range curr.Global.CloseWaitLeakers {
			if cw.Count < 1 {
				continue
			}
			entries = append(entries, model.BlameEntry{
				Comm: cw.Comm,
				PID:  cw.PID,
				Metrics: map[string]string{
					"CLOSE_WAIT": fmt.Sprintf("%d", cw.Count),
				},
				ImpactPct: float64(cw.Count),
			})
		}
	}

	// 2. Application-level connection hogs — processes holding many connections
	//    contribute to conntrack pressure, ephemeral port exhaustion, and retransmits.
	if curr != nil {
		for _, app := range curr.Global.Apps.Instances {
			if app.Connections < 20 {
				continue
			}
			// Avoid duplicating a CLOSE_WAIT leaker already listed
			dup := false
			for _, e := range entries {
				if e.PID == app.PID {
					dup = true
					break
				}
			}
			if dup {
				continue
			}
			metrics := map[string]string{
				"conns": fmt.Sprintf("%d", app.Connections),
			}
			if app.CPUPct > 1 {
				metrics["cpu"] = fmt.Sprintf("%.1f%%", app.CPUPct)
			}
			entries = append(entries, model.BlameEntry{
				Comm:    app.DisplayName,
				PID:     app.PID,
				Metrics: metrics,
				// Scale impact: each connection adds to network pressure.
				ImpactPct: float64(app.Connections),
			})
		}
	}

	// 3. High-FD processes as connection proxy — when no application-level data,
	//    processes with very high FD counts are likely holding many sockets.
	if len(entries) == 0 && rates != nil {
		type fdProc struct {
			comm   string
			pid    int
			cgroup string
			fds    int
			fdPct  float64
		}
		var procs []fdProc
		for _, p := range rates.ProcessRates {
			if isKernelThread(p.Comm) {
				continue
			}
			// Only consider processes with a meaningful number of FDs
			if p.FDCount < 100 {
				continue
			}
			procs = append(procs, fdProc{p.Comm, p.PID, p.CgroupPath, p.FDCount, p.FDPct})
		}
		sort.Slice(procs, func(i, j int) bool { return procs[i].fds > procs[j].fds })
		n := 3
		if len(procs) < n {
			n = len(procs)
		}
		for i := 0; i < n; i++ {
			p := procs[i]
			metrics := map[string]string{
				"fds": fmt.Sprintf("%d", p.fds),
			}
			if p.fdPct > 50 {
				metrics["fd_pressure"] = fmt.Sprintf("%.0f%%", p.fdPct)
			}
			entries = append(entries, model.BlameEntry{
				Comm:       p.comm,
				PID:        p.pid,
				CgroupPath: p.cgroup,
				Metrics:    metrics,
				ImpactPct:  float64(p.fds),
			})
		}
	}

	// 4. Fallback: top bandwidth consumers from process IO rates
	if len(entries) == 0 && rates != nil {
		type netProc struct {
			comm   string
			pid    int
			cgroup string
			bw     float64
		}
		var procs []netProc
		for _, p := range rates.ProcessRates {
			if isKernelThread(p.Comm) {
				continue
			}
			total := p.ReadMBs + p.WriteMBs
			if total < 0.1 {
				continue
			}
			procs = append(procs, netProc{p.Comm, p.PID, p.CgroupPath, total})
		}
		sort.Slice(procs, func(i, j int) bool { return procs[i].bw > procs[j].bw })
		n := 5
		if len(procs) < n {
			n = len(procs)
		}
		for i := 0; i < n; i++ {
			entries = append(entries, model.BlameEntry{
				Comm:       procs[i].comm,
				PID:        procs[i].pid,
				CgroupPath: procs[i].cgroup,
				Metrics:    map[string]string{"io": fmt.Sprintf("%.1f MB/s", procs[i].bw)},
				ImpactPct:  procs[i].bw,
			})
		}
	}

	// 5. When conntrack/retrans evidence fires at system level, add a synthetic
	//    entry so the user knows it is a system-wide issue, not just one process.
	if result != nil {
		conntrackDrop := hasActiveEvidence(result, BottleneckNetwork, "net.conntrack.drops")
		conntrackGrowth := hasActiveEvidence(result, BottleneckNetwork, "net.conntrack.growth")
		retransHigh := hasActiveEvidence(result, BottleneckNetwork, "net.tcp.retrans")
		if conntrackDrop || conntrackGrowth {
			metrics := map[string]string{}
			if rates != nil && rates.ConntrackDropRate > 0 {
				metrics["ct_drops"] = fmt.Sprintf("%.0f/s", rates.ConntrackDropRate)
			}
			if rates != nil && rates.ConntrackGrowthRate > 0 {
				metrics["ct_growth"] = fmt.Sprintf("%.0f/s", rates.ConntrackGrowthRate)
			}
			if len(metrics) > 0 {
				entries = append(entries, model.BlameEntry{
					Comm:      "conntrack-pressure",
					Metrics:   metrics,
					ImpactPct: rates.ConntrackDropRate + rates.ConntrackGrowthRate,
				})
			}
		}
		if retransHigh && rates != nil && rates.RetransRate > 0 {
			entries = append(entries, model.BlameEntry{
				Comm: "tcp-retransmits",
				Metrics: map[string]string{
					"retrans": fmt.Sprintf("%.0f/s", rates.RetransRate),
				},
				ImpactPct: rates.RetransRate,
			})
		}
	}

	// Limit to top 5
	sort.Slice(entries, func(i, j int) bool { return entries[i].ImpactPct > entries[j].ImpactPct })
	if len(entries) > 5 {
		entries = entries[:5]
	}
	return entries
}

// fmtBytes formats bytes to human-readable string.
func fmtBytes(b uint64) string {
	const (
		kb = 1024
		mb = 1024 * kb
		gb = 1024 * mb
	)
	switch {
	case b >= gb:
		return fmt.Sprintf("%.1f GB", float64(b)/float64(gb))
	case b >= mb:
		return fmt.Sprintf("%.1f MB", float64(b)/float64(mb))
	case b >= kb:
		return fmt.Sprintf("%.0f KB", float64(b)/float64(kb))
	default:
		return fmt.Sprintf("%d B", b)
	}
}
