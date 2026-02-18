package engine

import (
	"fmt"

	"github.com/ftahirops/xtop/model"
)

// ComputeWarnings detects early warning signals.
func ComputeWarnings(snap *model.Snapshot, rates *model.RateSnapshot) []model.Warning {
	var warns []model.Warning

	// PSI rising
	if psi := snap.Global.PSI.CPU.Some.Avg10; psi > 5 {
		warns = append(warns, model.Warning{
			Severity: severity(psi, 10, 25),
			Signal:   "CPU PSI",
			Detail:   "CPU pressure stall",
			Value:    fmt.Sprintf("some avg10=%.1f%%", psi),
		})
	}
	if psi := snap.Global.PSI.Memory.Full.Avg10; psi > 2 {
		warns = append(warns, model.Warning{
			Severity: severity(psi, 5, 15),
			Signal:   "MEM PSI",
			Detail:   "Memory pressure stall",
			Value:    fmt.Sprintf("full avg10=%.1f%%", psi),
		})
	}
	if psi := snap.Global.PSI.IO.Full.Avg10; psi > 2 {
		warns = append(warns, model.Warning{
			Severity: severity(psi, 5, 15),
			Signal:   "IO PSI",
			Detail:   "IO pressure stall",
			Value:    fmt.Sprintf("full avg10=%.1f%%", psi),
		})
	}

	// Retransmits
	if rates.RetransRate > 1 {
		warns = append(warns, model.Warning{
			Severity: severity(rates.RetransRate, 10, 100),
			Signal:   "retrans/s",
			Detail:   "TCP retransmissions",
			Value:    fmt.Sprintf("%.0f/s", rates.RetransRate),
		})
	}

	// Disk latency
	for _, d := range rates.DiskRates {
		if d.AvgAwaitMs > 20 {
			warns = append(warns, model.Warning{
				Severity: severity(d.AvgAwaitMs, 50, 200),
				Signal:   fmt.Sprintf("%s await", d.Name),
				Detail:   "Disk latency high",
				Value:    fmt.Sprintf("%.0fms", d.AvgAwaitMs),
			})
		}
		if d.UtilPct > 80 {
			warns = append(warns, model.Warning{
				Severity: severity(d.UtilPct, 90, 98),
				Signal:   fmt.Sprintf("%s util", d.Name),
				Detail:   "Disk utilization high",
				Value:    fmt.Sprintf("%.0f%%", d.UtilPct),
			})
		}
	}

	// Context switches
	nCPU := snap.Global.CPU.NumCPUs
	if nCPU == 0 {
		nCPU = 1
	}
	csPerCore := rates.CtxSwitchRate / float64(nCPU)
	if csPerCore > 30000 {
		warns = append(warns, model.Warning{
			Severity: severity(csPerCore, 50000, 100000),
			Signal:   "ctxswitch/s",
			Detail:   "High context switching",
			Value:    fmt.Sprintf("%.0f/s/core", csPerCore),
		})
	}

	// D-state processes
	dCount := 0
	for _, p := range snap.Processes {
		if p.State == "D" {
			dCount++
		}
	}
	if dCount > 0 {
		warns = append(warns, model.Warning{
			Severity: severity(float64(dCount), 3, 10),
			Signal:   "D-state",
			Detail:   "Uninterruptible sleep tasks",
			Value:    fmt.Sprintf("%d tasks", dCount),
		})
	}

	// Swap activity
	if rates.SwapInRate > 0 || rates.SwapOutRate > 0 {
		warns = append(warns, model.Warning{
			Severity: severity(rates.SwapInRate+rates.SwapOutRate, 1, 10),
			Signal:   "swap rate",
			Detail:   "Active swapping",
			Value:    fmt.Sprintf("in=%.1f out=%.1f MB/s", rates.SwapInRate, rates.SwapOutRate),
		})
	}

	// Direct reclaim
	if rates.DirectReclaimRate > 0 {
		warns = append(warns, model.Warning{
			Severity: severity(rates.DirectReclaimRate, 100, 1000),
			Signal:   "direct reclaim",
			Detail:   "Synchronous page reclaim",
			Value:    fmt.Sprintf("%.0f pages/s", rates.DirectReclaimRate),
		})
	}

	// Network drops
	for _, nr := range rates.NetRates {
		totalDrops := nr.RxDropsPS + nr.TxDropsPS
		if totalDrops > 0 {
			warns = append(warns, model.Warning{
				Severity: severity(totalDrops, 10, 100),
				Signal:   fmt.Sprintf("%s drops", nr.Name),
				Detail:   "Network drops",
				Value:    fmt.Sprintf("%.0f/s", totalDrops),
			})
		}
	}

	// Conntrack pressure
	ct := snap.Global.Conntrack
	if ct.Max > 0 {
		pct := float64(ct.Count) / float64(ct.Max) * 100
		if pct > 70 {
			warns = append(warns, model.Warning{
				Severity: severity(pct, 85, 95),
				Signal:   "conntrack",
				Detail:   "Connection tracking table filling",
				Value:    fmt.Sprintf("%.0f%% (%d/%d)", pct, ct.Count, ct.Max),
			})
		}
	}

	// FD usage
	fd := snap.Global.FD
	if fd.Max > 0 {
		pct := float64(fd.Allocated) / float64(fd.Max) * 100
		if pct > 70 {
			warns = append(warns, model.Warning{
				Severity: severity(pct, 85, 95),
				Signal:   "FDs",
				Detail:   "File descriptor usage high",
				Value:    fmt.Sprintf("%.0f%% (%d/%d)", pct, fd.Allocated, fd.Max),
			})
		}
	}

	// CPU steal
	if rates.CPUStealPct > 1 {
		warns = append(warns, model.Warning{
			Severity: severity(rates.CPUStealPct, 5, 15),
			Signal:   "CPU steal",
			Detail:   "Hypervisor stealing CPU",
			Value:    fmt.Sprintf("%.1f%%", rates.CPUStealPct),
		})
	}

	// Cgroup throttling
	for _, cg := range rates.CgroupRates {
		if cg.ThrottlePct > 5 {
			warns = append(warns, model.Warning{
				Severity: severity(cg.ThrottlePct, 10, 30),
				Signal:   "throttle",
				Detail:   fmt.Sprintf("Cgroup %s throttled", cg.Name),
				Value:    fmt.Sprintf("%.0f%% periods", cg.ThrottlePct),
			})
			break // only report worst
		}
	}

	return warns
}

func severity(value, warnThresh, critThresh float64) string {
	if value >= critThresh {
		return "crit"
	}
	if value >= warnThresh {
		return "warn"
	}
	return "info"
}
