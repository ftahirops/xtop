package engine

import (
	"fmt"

	"github.com/ftahirops/xtop/model"
)

// ComputeCapacity calculates headroom for key resources.
func ComputeCapacity(snap *model.Snapshot, rates *model.RateSnapshot) []model.Capacity {
	if rates == nil {
		return nil
	}
	var caps []model.Capacity

	// CPU headroom
	cpuFree := 100 - rates.CPUBusyPct
	if cpuFree < 0 {
		cpuFree = 0
	}
	caps = append(caps, model.Capacity{
		Label:   "CPU headroom",
		Pct:     cpuFree,
		Current: fmt.Sprintf("%.0f%% busy", rates.CPUBusyPct),
		Limit:   fmt.Sprintf("%d cores", snap.Global.CPU.NumCPUs),
	})

	// MemAvailable %
	mem := snap.Global.Memory
	memPct := float64(mem.Available) / float64(mem.Total) * 100
	caps = append(caps, model.Capacity{
		Label:   "MemAvailable",
		Pct:     memPct,
		Current: formatB(mem.Available),
		Limit:   formatB(mem.Total),
	})

	// Swap
	if mem.SwapTotal > 0 {
		swapFree := float64(mem.SwapFree) / float64(mem.SwapTotal) * 100
		caps = append(caps, model.Capacity{
			Label:   "Swap free",
			Pct:     swapFree,
			Current: formatB(mem.SwapUsed) + " used",
			Limit:   formatB(mem.SwapTotal),
		})
	}

	// Disk utilization (worst device)
	if len(rates.DiskRates) > 0 {
		var worstUtil float64
		var worstDisk string
		for _, d := range rates.DiskRates {
			if d.UtilPct > worstUtil {
				worstUtil = d.UtilPct
				worstDisk = d.Name
			}
		}
		// Find the worst disk's await time
		var worstAwait float64
		for _, d := range rates.DiskRates {
			if d.Name == worstDisk {
				worstAwait = d.AvgAwaitMs
				break
			}
		}
		caps = append(caps, model.Capacity{
			Label:   fmt.Sprintf("Disk %s", worstDisk),
			Pct:     100 - worstUtil,
			Current: fmt.Sprintf("%.0f%% util, %.1fms await", worstUtil, worstAwait),
			Limit:   "100%",
		})
	}

	// FD usage
	fd := snap.Global.FD
	if fd.Max > 0 {
		fdPct := 100 - float64(fd.Allocated)/float64(fd.Max)*100
		caps = append(caps, model.Capacity{
			Label:   "File descriptors",
			Pct:     fdPct,
			Current: fmt.Sprintf("%d alloc", fd.Allocated),
			Limit:   fmt.Sprintf("%d max", fd.Max),
		})
	}

	// Conntrack
	ct := snap.Global.Conntrack
	if ct.Max > 0 {
		ctPct := 100 - float64(ct.Count)/float64(ct.Max)*100
		caps = append(caps, model.Capacity{
			Label:   "Conntrack",
			Pct:     ctPct,
			Current: fmt.Sprintf("%d entries", ct.Count),
			Limit:   fmt.Sprintf("%d max", ct.Max),
		})
	}

	return caps
}

func formatB(b uint64) string {
	switch {
	case b >= 1<<30:
		return fmt.Sprintf("%.1fG", float64(b)/(1<<30))
	case b >= 1<<20:
		return fmt.Sprintf("%.1fM", float64(b)/(1<<20))
	case b >= 1<<10:
		return fmt.Sprintf("%.1fK", float64(b)/(1<<10))
	default:
		return fmt.Sprintf("%dB", b)
	}
}
