package engine

import (
	"fmt"
	"sort"

	"github.com/ftahirops/xtop/model"
)

const topN = 3

// ComputeOwners computes top resource consumers per subsystem.
func ComputeOwners(snap *model.Snapshot, rates *model.RateSnapshot) (cpu, mem, io, net []model.Owner) {
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
	sort.Slice(cgs, func(i, j int) bool {
		return (cgs[i].IORateMBs + cgs[i].IOWRateMBs) > (cgs[j].IORateMBs + cgs[j].IOWRateMBs)
	})

	var owners []model.Owner
	for i, cg := range cgs {
		totalMBs := cg.IORateMBs + cg.IOWRateMBs
		if i >= topN || totalMBs < 0.001 {
			break
		}
		owners = append(owners, model.Owner{
			Name:   cg.Name,
			CgPath: cg.Path,
			Value:  fmt.Sprintf("%.1f MB/s (R:%.1f W:%.1f)", totalMBs, cg.IORateMBs, cg.IOWRateMBs),
		})
	}
	return owners
}

func topNetOwners(rates *model.RateSnapshot) []model.Owner {
	// Network ownership is best-effort: use top processes by name
	procs := make([]model.ProcessRate, len(rates.ProcessRates))
	copy(procs, rates.ProcessRates)
	sort.Slice(procs, func(i, j int) bool {
		return (procs[i].ReadMBs + procs[i].WriteMBs) > (procs[j].ReadMBs + procs[j].WriteMBs)
	})

	var owners []model.Owner
	seen := make(map[string]bool)
	for _, p := range procs {
		if len(owners) >= topN {
			break
		}
		if seen[p.Comm] || (p.ReadMBs+p.WriteMBs) < 0.001 {
			continue
		}
		seen[p.Comm] = true
		owners = append(owners, model.Owner{
			Name:   p.Comm,
			PID:    p.PID,
			CgPath: p.CgroupPath,
			Value:  fmt.Sprintf("%.1f MB/s IO", p.ReadMBs+p.WriteMBs),
		})
	}
	return owners
}
