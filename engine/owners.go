package engine

import (
	"fmt"
	"sort"

	"github.com/ftahirops/xtop/model"
)

const topN = 3

// ComputeOwners computes top resource consumers per subsystem.
func ComputeOwners(snap *model.Snapshot, rates *model.RateSnapshot) (cpu, mem, io, net []model.Owner) {
	if rates == nil {
		return
	}
	cpu = topCPUOwners(rates)
	mem = topMemOwners(snap, rates)
	io = topIOOwners(rates)
	net = topNetOwners(rates)
	return
}

func topCPUOwners(rates *model.RateSnapshot) []model.Owner {
	cgs := make([]model.CgroupRate, len(rates.CgroupRates))
	copy(cgs, rates.CgroupRates)
	sort.Slice(cgs, func(i, j int) bool { return cgs[i].CPUPct > cgs[j].CPUPct })

	var owners []model.Owner
	for i, cg := range cgs {
		if i >= topN || cg.CPUPct < 0.1 {
			break
		}
		owners = append(owners, model.Owner{
			Name:   cg.Name,
			CgPath: cg.Path,
			Pct:    cg.CPUPct,
			Value:  fmt.Sprintf("%.1f%%", cg.CPUPct),
		})
	}
	return owners
}

func topMemOwners(snap *model.Snapshot, rates *model.RateSnapshot) []model.Owner {
	cgs := make([]model.CgroupRate, len(rates.CgroupRates))
	copy(cgs, rates.CgroupRates)
	sort.Slice(cgs, func(i, j int) bool { return cgs[i].MemPct > cgs[j].MemPct })

	var owners []model.Owner
	for i, cg := range cgs {
		if i >= topN || cg.MemPct < 0.1 {
			break
		}
		// Find the matching absolute value
		var memBytes uint64
		for _, c := range snap.Cgroups {
			if c.Path == cg.Path {
				memBytes = c.MemCurrent
				break
			}
		}
		owners = append(owners, model.Owner{
			Name:   cg.Name,
			CgPath: cg.Path,
			Pct:    cg.MemPct,
			Value:  fmt.Sprintf("%.1f%% (%s)", cg.MemPct, formatB(memBytes)),
		})
	}
	return owners
}

func topIOOwners(rates *model.RateSnapshot) []model.Owner {
	cgs := make([]model.CgroupRate, len(rates.CgroupRates))
	copy(cgs, rates.CgroupRates)

	// Compute total IO MB/s across ALL cgroups so each owner gets a real
	// share-of-total-IO percentage. (Pct field was previously left at 0,
	// which made it useless to the UI.)
	var totalIO float64
	for _, c := range cgs {
		totalIO += c.IORateMBs + c.IOWRateMBs
	}

	sort.Slice(cgs, func(i, j int) bool {
		return (cgs[i].IORateMBs + cgs[i].IOWRateMBs) > (cgs[j].IORateMBs + cgs[j].IOWRateMBs)
	})

	var owners []model.Owner
	for i, cg := range cgs {
		totalMBs := cg.IORateMBs + cg.IOWRateMBs
		if i >= topN || totalMBs < 0.001 {
			break
		}
		var pct float64
		if totalIO > 0 {
			pct = totalMBs / totalIO * 100
		}
		owners = append(owners, model.Owner{
			Name:   cg.Name,
			CgPath: cg.Path,
			Pct:    pct,
			Value:  fmt.Sprintf("%.1f MB/s (R:%.1f W:%.1f)", totalMBs, cg.IORateMBs, cg.IOWRateMBs),
		})
	}
	return owners
}

func topNetOwners(rates *model.RateSnapshot) []model.Owner {
	// "Network ownership" approximated from per-process disk read+write,
	// which is the closest signal in /proc — proper per-process net
	// counters need eBPF. Pct field is share-of-total-IO across processes.
	procs := make([]model.ProcessRate, len(rates.ProcessRates))
	copy(procs, rates.ProcessRates)

	var totalIO float64
	for _, p := range procs {
		totalIO += p.ReadMBs + p.WriteMBs
	}

	sort.Slice(procs, func(i, j int) bool {
		return (procs[i].ReadMBs + procs[i].WriteMBs) > (procs[j].ReadMBs + procs[j].WriteMBs)
	})

	var owners []model.Owner
	seen := make(map[string]bool)
	for _, p := range procs {
		if len(owners) >= topN {
			break
		}
		mbs := p.ReadMBs + p.WriteMBs
		if seen[p.Comm] || mbs < 0.001 {
			continue
		}
		seen[p.Comm] = true
		var pct float64
		if totalIO > 0 {
			pct = mbs / totalIO * 100
		}
		owners = append(owners, model.Owner{
			Name:   p.Comm,
			PID:    p.PID,
			CgPath: p.CgroupPath,
			Pct:    pct,
			Value:  fmt.Sprintf("%.1f MB/s IO", mbs),
		})
	}
	return owners
}
