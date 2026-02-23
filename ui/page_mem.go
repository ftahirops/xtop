package ui

import (
	"fmt"
	"sort"
	"strings"

	"github.com/ftahirops/xtop/model"
)

func renderMemPage(snap *model.Snapshot, rates *model.RateSnapshot, result *model.AnalysisResult, pm probeQuerier, width, height int) string {
	var sb strings.Builder
	iw := pageInnerW(width)

	sb.WriteString(titleStyle.Render("MEMORY SUBSYSTEM"))
	sb.WriteString("\n")
	sb.WriteString(renderRCAInline(result))
	sb.WriteString(renderProbeStatusLine(pm))
	sb.WriteString("\n")

	mem := snap.Global.Memory
	vm := snap.Global.VMStat
	psi := snap.Global.PSI.Memory

	// === Summary ===
	availPct := float64(0)
	if mem.Total > 0 {
		availPct = float64(mem.Available) / float64(mem.Total) * 100
	}
	usedPct := 100 - availPct

	bw := iw/2 - 15
	if bw < 5 {
		bw = 5
	}

	swapIn := float64(0)
	swapOut := float64(0)
	pgFault := float64(0)
	majFault := float64(0)
	directRecl := float64(0)
	kswapdR := float64(0)
	if rates != nil {
		swapIn = rates.SwapInRate
		swapOut = rates.SwapOutRate
		pgFault = rates.PgFaultRate
		majFault = rates.MajFaultRate
		directRecl = rates.DirectReclaimRate
		kswapdR = rates.KswapdRate
	}

	var sumLines []string
	sumLines = append(sumLines, fmt.Sprintf("Memory used: %s %s  (%s avail / %s total)",
		bar(usedPct, bw), fmtPct(usedPct), fmtBytes(mem.Available), fmtBytes(mem.Total)))
	sumLines = append(sumLines, fmt.Sprintf("PSI some/full: %s / %s", fmtPSI(psi.Some.Avg10), fmtPSI(psi.Full.Avg10)))
	sumLines = append(sumLines, fmt.Sprintf("Swap in/out: %.1f / %.1f MB/s", swapIn, swapOut))
	sumLines = append(sumLines, fmt.Sprintf("Page faults: %.0f/s  Major: %.0f/s", pgFault, majFault))
	sumLines = append(sumLines, fmt.Sprintf("Direct reclaim: %.0f pages/s  Kswapd: %.0f pages/s", directRecl, kswapdR))
	sb.WriteString(boxSection("SUMMARY", sumLines, iw))

	// === Full Breakdown ===
	totalF := float64(mem.Total)
	if totalF == 0 {
		totalF = 1 // avoid division by zero
	}
	breakdown := []struct {
		label string
		bytes uint64
	}{
		{"AnonPages (app data)", mem.AnonPages},
		{"Cached (page cache)", mem.Cached},
		{"Buffers", mem.Buffers},
		{"Slab total", mem.Slab},
		{"  SReclaimable", mem.SReclaimable},
		{"  SUnreclaim", mem.SUnreclaim},
		{"Shmem (tmpfs/shm)", mem.Shmem},
		{"Mapped (mmap'd files)", mem.Mapped},
		{"KernelStack", mem.KernelStack},
		{"PageTables", mem.PageTables},
		{"Bounce", mem.Bounce},
		{"Mlocked", mem.Mlocked},
		{"Free", mem.Free},
	}

	var bdLines []string
	for _, b := range breakdown {
		pct := float64(b.bytes) / totalF * 100
		bdLines = append(bdLines, fmt.Sprintf("%-24s %8s  %5.1f%%", b.label, fmtBytes(b.bytes), pct))
	}
	sb.WriteString(boxSection("MEMORY BREAKDOWN", bdLines, iw))

	// === Active/Inactive ===
	var aiLines []string
	aiLines = append(aiLines, fmt.Sprintf("Active (anon):   %8s    Inactive (anon):   %8s", fmtBytes(mem.ActiveAnon), fmtBytes(mem.InactiveAnon)))
	aiLines = append(aiLines, fmt.Sprintf("Active (file):   %8s    Inactive (file):   %8s", fmtBytes(mem.ActiveFile), fmtBytes(mem.InactiveFile)))
	aiLines = append(aiLines, fmt.Sprintf("Unevictable:     %8s", fmtBytes(mem.Unevictable)))
	sb.WriteString(boxSection("ACTIVE / INACTIVE", aiLines, iw))

	// === Swap ===
	var swapLines []string
	if mem.SwapTotal > 0 {
		swapPct := float64(mem.SwapUsed) / float64(mem.SwapTotal) * 100
		swapLines = append(swapLines, fmt.Sprintf("Swap used:   %s %s  (%s / %s)",
			bar(swapPct, bw), fmtPct(swapPct), fmtBytes(mem.SwapUsed), fmtBytes(mem.SwapTotal)))
		swapLines = append(swapLines, fmt.Sprintf("SwapCached:  %s", fmtBytes(mem.SwapCached)))
	} else {
		swapLines = append(swapLines, dimStyle.Render("No swap configured"))
	}
	sb.WriteString(boxSection("SWAP", swapLines, iw))

	// === VMStat counters ===
	var vmLines []string
	vmLines = append(vmLines, fmt.Sprintf("pgfault: %d   pgmajfault: %d", vm.PgFault, vm.PgMajFault))
	vmLines = append(vmLines, fmt.Sprintf("pgpgin: %d   pgpgout: %d", vm.PgPgIn, vm.PgPgOut))
	vmLines = append(vmLines, fmt.Sprintf("pswpin: %d   pswpout: %d", vm.PswpIn, vm.PswpOut))
	vmLines = append(vmLines, fmt.Sprintf("pgsteal_direct: %d   pgsteal_kswapd: %d", vm.PgStealDirect, vm.PgStealKswapd))
	vmLines = append(vmLines, fmt.Sprintf("pgscan_direct: %d   pgscan_kswapd: %d", vm.PgScanDirect, vm.PgScanKswapd))
	vmLines = append(vmLines, fmt.Sprintf("allocstall: %d   compact_stall: %d", vm.AllocStall, vm.CompactStall))
	vmLines = append(vmLines, fmt.Sprintf("oom_kill: %d", vm.OOMKill))
	vmLines = append(vmLines, fmt.Sprintf("thp_fault_alloc: %d   thp_collapse: %d", vm.ThpFaultAlloc, vm.ThpCollapseAlloc))

	directRatio := float64(0)
	if vm.PgScanDirect+vm.PgScanKswapd > 0 {
		directRatio = float64(vm.PgScanDirect) / float64(vm.PgScanDirect+vm.PgScanKswapd) * 100
	}
	vmLines = append(vmLines, fmt.Sprintf("Direct reclaim ratio: %5.1f%% (lower is better)", directRatio))
	sb.WriteString(boxSection("VMSTAT COUNTERS (cumulative)", vmLines, iw))

	// === Hugepages ===
	var hpLines []string
	if mem.HugePages_Total > 0 {
		hpLines = append(hpLines, fmt.Sprintf("Total: %d  Free: %d  Size: %s",
			mem.HugePages_Total, mem.HugePages_Free, fmtBytes(mem.HugepageSize)))
	} else {
		hpLines = append(hpLines, dimStyle.Render("not configured"))
	}
	sb.WriteString(boxSection("HUGEPAGES", hpLines, iw))

	// === Top cgroups by memory ===
	var cgLines []string
	cgLines = append(cgLines, dimStyle.Render(fmt.Sprintf("%-28s %10s %8s %6s %8s", "CGROUP", "CURRENT", "LIMIT", "OOM", "MAJFLT")))

	cgs := make([]model.CgroupMetrics, len(snap.Cgroups))
	copy(cgs, snap.Cgroups)
	sort.Slice(cgs, func(i, j int) bool { return cgs[i].MemCurrent > cgs[j].MemCurrent })
	for i, cg := range cgs {
		if i >= 10 || cg.MemCurrent == 0 {
			break
		}
		name := cg.Name
		if len(name) > 28 {
			name = name[:25] + "..."
		}
		limitStr := "-"
		if cg.MemLimit > 0 {
			limitStr = fmtBytes(cg.MemLimit)
		}
		cgLines = append(cgLines, fmt.Sprintf("%-28s %10s %8s %6d %8d",
			name, fmtBytes(cg.MemCurrent), limitStr, cg.OOMKills, cg.PgMajFault))
	}
	sb.WriteString(boxSection("TOP CGROUPS BY MEMORY", cgLines, iw))

	// === Top PIDs by RSS ===
	var procLines []string
	procLines = append(procLines, dimStyle.Render(fmt.Sprintf("%7s %-16s %10s %10s %8s %10s", "PID", "COMMAND", "RSS", "SWAP", "MEM%", "MAJFLT/s")))

	if rates != nil && len(rates.ProcessRates) > 0 {
		procs := make([]model.ProcessRate, len(rates.ProcessRates))
		copy(procs, rates.ProcessRates)
		sort.Slice(procs, func(i, j int) bool { return procs[i].RSS > procs[j].RSS })
		for i, p := range procs {
			if i >= 15 || p.RSS == 0 {
				break
			}
			comm := p.Comm
			if len(comm) > 16 {
				comm = comm[:13] + "..."
			}
			procLines = append(procLines, fmt.Sprintf("%7d %-16s %10s %10s %7.1f%% %10.0f",
				p.PID, comm, fmtBytes(p.RSS), fmtBytes(p.VmSwap), p.MemPct, p.MajFaultRate))
		}
	} else {
		procLines = append(procLines, dimStyle.Render("(collecting...)"))
	}
	sb.WriteString(boxSection("TOP PROCESSES BY MEMORY", procLines, iw))

	return sb.String()
}
