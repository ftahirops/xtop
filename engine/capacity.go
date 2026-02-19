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

	// Filesystem space per real mount
	if rates != nil {
		for _, mr := range rates.MountRates {
			etaStr := "not growing"
			if mr.ETASeconds > 0 {
				etaMin := mr.ETASeconds / 60
				if etaMin < 60 {
					etaStr = fmt.Sprintf("ETA %.0fm", etaMin)
				} else {
					etaStr = fmt.Sprintf("ETA %.0fh", etaMin/60)
				}
			}
			caps = append(caps, model.Capacity{
				Label:   fmt.Sprintf("FS %s", mr.MountPoint),
				Pct:     mr.FreePct,
				Current: fmt.Sprintf("%.0f%% used, %s", mr.UsedPct, etaStr),
				Limit:   formatB(mr.TotalBytes),
			})
		}
		// Inode capacity for worst mount if high
		var worstInodePct float64
		var worstInodeMount string
		for _, mr := range rates.MountRates {
			if mr.InodeUsedPct > worstInodePct {
				worstInodePct = mr.InodeUsedPct
				worstInodeMount = mr.MountPoint
			}
		}
		if worstInodePct > 50 {
			caps = append(caps, model.Capacity{
				Label:   fmt.Sprintf("Inodes %s", worstInodeMount),
				Pct:     100 - worstInodePct,
				Current: fmt.Sprintf("%.0f%% used", worstInodePct),
				Limit:   "inode table",
			})
		}
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

	// Ephemeral ports
	eph := snap.Global.EphemeralPorts
	ephRange := eph.RangeHi - eph.RangeLo + 1
	if ephRange > 0 {
		ephFree := 100 - float64(eph.InUse)/float64(ephRange)*100
		caps = append(caps, model.Capacity{
			Label:   "Ephemeral ports",
			Pct:     ephFree,
			Current: fmt.Sprintf("%d in use", eph.InUse),
			Limit:   fmt.Sprintf("%d–%d (%d)", eph.RangeLo, eph.RangeHi, ephRange),
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
