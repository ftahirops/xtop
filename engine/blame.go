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

	switch result.PrimaryBottleneck {
	case BottleneckCPU:
		return blameCPU(rates)
	case BottleneckMemory:
		return blameMemory(rates)
	case BottleneckIO:
		return blameIO(rates)
	case BottleneckNetwork:
		return blameNetwork(rates, curr)
	default:
		return nil
	}
}

func blameCPU(rates *model.RateSnapshot) []model.BlameEntry {
	type agg struct {
		comm       string
		pid        int
		cgroup     string
		cpuPct     float64
		threads    int
		ctxsw      float64
	}

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

	entries := make([]model.BlameEntry, 0, n)
	for i := 0; i < n; i++ {
		p := procs[i]
		metrics := map[string]string{
			"cpu": fmt.Sprintf("%.1f%%", p.cpuPct),
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
			ImpactPct:  p.cpuPct,
		})
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

func blameIO(rates *model.RateSnapshot) []model.BlameEntry {
	type agg struct {
		comm   string
		pid    int
		cgroup string
		ioMBs  float64
		write  string
	}

	procs := make([]agg, 0, len(rates.ProcessRates))
	for _, p := range rates.ProcessRates {
		if isKernelThread(p.Comm) {
			continue
		}
		totalIO := p.ReadMBs + p.WriteMBs
		if totalIO < 0.1 {
			continue
		}
		procs = append(procs, agg{
			comm:   p.Comm,
			pid:    p.PID,
			cgroup: p.CgroupPath,
			ioMBs:  totalIO,
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
			"io": fmt.Sprintf("%.1f MB/s", p.ioMBs),
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

func blameNetwork(rates *model.RateSnapshot, curr *model.Snapshot) []model.BlameEntry {
	// For network, attribute by CLOSE_WAIT leakers + top processes
	var entries []model.BlameEntry

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
