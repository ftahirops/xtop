package ui

import (
	"fmt"
	"sort"
	"strings"

	"github.com/ftahirops/xtop/model"
)

func renderMemPage(snap *model.Snapshot, rates *model.RateSnapshot, result *model.AnalysisResult, pm probeQuerier, width, height int, intermediate bool) string {
	var sb strings.Builder
	iw := pageInnerW(width)

	sb.WriteString(titleStyle.Render("MEMORY SUBSYSTEM"))
	if intermediate {
		sb.WriteString(dimStyle.Render("  [verdicts ON]"))
	}
	sb.WriteString("\n")
	sb.WriteString(renderRCAInline(result))
	sb.WriteString(renderProbeStatusLine(pm, snap, intermediate))
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
	memLine := fmt.Sprintf("Memory used: %s %s  (%s avail / %s total)",
		bar(usedPct, bw), fmtPct(usedPct), fmtBytes(mem.Available), fmtBytes(mem.Total))
	if intermediate {
		memLine += "  " + metricVerdict(usedPct, 80, 95)
	}
	sumLines = append(sumLines, memLine)

	psiLine := fmt.Sprintf("%s some/full: %s / %s",
		abbr("PSI", "Pressure Stall — % time tasks wait for memory", intermediate),
		fmtPSI(psi.Some.Avg10), fmtPSI(psi.Full.Avg10))
	if intermediate {
		psiLine += "  " + metricVerdict(psi.Some.Avg10, 5, 25)
	}
	sumLines = append(sumLines, psiLine)

	swapLine := fmt.Sprintf("Swap in/out: %.1f / %.1f MB/s", swapIn, swapOut)
	if intermediate && (swapIn > 0 || swapOut > 0) {
		swapLine += "  " + metricVerdict(swapIn+swapOut, 1, 10)
	}
	sumLines = append(sumLines, swapLine)

	faultLine := fmt.Sprintf("%s: %.0f/s  %s: %.0f/s",
		abbr("Page faults", "memory page misses", intermediate), pgFault,
		abbr("Major", "required disk read", intermediate), majFault)
	if intermediate && majFault > 0 {
		faultLine += "  " + metricVerdict(majFault, 100, 1000)
	}
	sumLines = append(sumLines, faultLine)

	reclaimLine := fmt.Sprintf("%s: %.0f pages/s  %s: %.0f pages/s",
		abbr("Direct reclaim", "urgent memory recovery — causes latency", intermediate), directRecl,
		abbr("Kswapd", "background memory recovery daemon", intermediate), kswapdR)
	if intermediate && directRecl > 0 {
		reclaimLine += "  " + metricVerdict(directRecl, 100, 1000)
	}
	sumLines = append(sumLines, reclaimLine)
	sb.WriteString(boxSection("SUMMARY", sumLines, iw))

	// === Key Memory Metrics (shown in intermediate mode instead of full breakdown) ===
	if intermediate {
		totalF := float64(mem.Total)
		if totalF == 0 {
			totalF = 1
		}
		var keyLines []string
		keyLines = append(keyLines, fmt.Sprintf("%-28s %8s  %5.1f%%  %s", "App memory (heap/stack)", fmtBytes(mem.AnonPages), float64(mem.AnonPages)/totalF*100, metricVerdict(float64(mem.AnonPages)/totalF*100, 60, 85)))
		keyLines = append(keyLines, fmt.Sprintf("%-28s %8s  %5.1f%%  %s", "File cache (reclaimable)", fmtBytes(mem.Cached), float64(mem.Cached)/totalF*100, dimStyle.Render("← can be freed")))
		keyLines = append(keyLines, fmt.Sprintf("%-28s %8s  %5.1f%%", "Kernel caches", fmtBytes(mem.Slab), float64(mem.Slab)/totalF*100))
		keyLines = append(keyLines, fmt.Sprintf("%-28s %8s  %5.1f%%", "Shared memory (tmpfs)", fmtBytes(mem.Shmem), float64(mem.Shmem)/totalF*100))
		keyLines = append(keyLines, fmt.Sprintf("%-28s %8s  %5.1f%%", "Free (unused)", fmtBytes(mem.Free), float64(mem.Free)/totalF*100))
		sb.WriteString(boxSection("MEMORY BREAKDOWN (key metrics)", keyLines, iw))
	} else {
		// === Full Breakdown (expert mode) ===
		totalF := float64(mem.Total)
		if totalF == 0 {
			totalF = 1
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

		// === Active/Inactive (expert only) ===
		var aiLines []string
		aiLines = append(aiLines, fmt.Sprintf("Active (anon):   %8s    Inactive (anon):   %8s", fmtBytes(mem.ActiveAnon), fmtBytes(mem.InactiveAnon)))
		aiLines = append(aiLines, fmt.Sprintf("Active (file):   %8s    Inactive (file):   %8s", fmtBytes(mem.ActiveFile), fmtBytes(mem.InactiveFile)))
		aiLines = append(aiLines, fmt.Sprintf("Unevictable:     %8s", fmtBytes(mem.Unevictable)))
		sb.WriteString(boxSection("ACTIVE / INACTIVE", aiLines, iw))
	}

	// === Swap ===
	var swapLines []string
	if mem.SwapTotal > 0 {
		swapPct := float64(mem.SwapUsed) / float64(mem.SwapTotal) * 100
		swLine := fmt.Sprintf("Swap used:   %s %s  (%s / %s)",
			bar(swapPct, bw), fmtPct(swapPct), fmtBytes(mem.SwapUsed), fmtBytes(mem.SwapTotal))
		if intermediate {
			swLine += "  " + metricVerdict(swapPct, 30, 80)
		}
		swapLines = append(swapLines, swLine)
		swapLines = append(swapLines, fmt.Sprintf("SwapCached:  %s", fmtBytes(mem.SwapCached)))
	} else {
		swapLines = append(swapLines, dimStyle.Render("No swap configured"))
	}
	sb.WriteString(boxSection("SWAP", swapLines, iw))

	// === VMStat counters (expert only) ===
	if !intermediate {
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

		// === Hugepages (expert only) ===
		var hpLines []string
		if mem.HugePages_Total > 0 {
			hpLines = append(hpLines, fmt.Sprintf("Total: %d  Free: %d  Size: %s",
				mem.HugePages_Total, mem.HugePages_Free, fmtBytes(mem.HugepageSize)))
		} else {
			hpLines = append(hpLines, dimStyle.Render("not configured"))
		}
		sb.WriteString(boxSection("HUGEPAGES", hpLines, iw))
	} else {
		// In intermediate mode, show OOM kills as a highlighted metric
		if vm.OOMKill > 0 {
			sb.WriteString(boxSection("CRITICAL", []string{
				critStyle.Render(fmt.Sprintf("OOM kills (out-of-memory): %d — kernel killed processes to free memory", vm.OOMKill)),
			}, iw))
		}
	}

	// === Top cgroups by memory ===
	var cgLines []string
	cgLines = append(cgLines, dimStyle.Render(fmt.Sprintf("%-28s %10s %8s %6s %8s",
		"CGROUP", "CURRENT", "LIMIT",
		abbr("OOM", "out-of-memory kills", intermediate),
		abbr("MAJFLT", "major page faults", intermediate))))

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
	procLines = append(procLines, dimStyle.Render(fmt.Sprintf("%7s %-16s %10s %10s %8s %10s",
		"PID", "COMMAND",
		abbr("RSS", "resident memory", intermediate),
		"SWAP", "MEM%",
		abbr("MAJFLT/s", "disk page faults/sec", intermediate))))

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

	// === Process Tree for top memory consumers (expert only) ===
	if !intermediate {
		if len(snap.Processes) > 0 && rates != nil && len(rates.ProcessRates) > 0 {
			var treeLines []string
			treeLines = append(treeLines, dimStyle.Render(fmt.Sprintf("%7s %-16s %10s %7s  %s", "PID", "COMMAND", "RSS", "MEM%", "TREE")))

			pidProc := make(map[int]*model.ProcessMetrics, len(snap.Processes))
			children := make(map[int][]int)
			for i := range snap.Processes {
				p := &snap.Processes[i]
				pidProc[p.PID] = p
				if p.PPID > 1 {
					children[p.PPID] = append(children[p.PPID], p.PID)
				}
			}

			memByPID := make(map[int]float64)
			rssByPID := make(map[int]uint64)
			for _, pr := range rates.ProcessRates {
				memByPID[pr.PID] = pr.MemPct
				rssByPID[pr.PID] = pr.RSS
			}

			procs := make([]model.ProcessRate, len(rates.ProcessRates))
			copy(procs, rates.ProcessRates)
			sort.Slice(procs, func(i, j int) bool { return procs[i].RSS > procs[j].RSS })

			shown := make(map[int]bool)
			for i, p := range procs {
				if i >= 6 || p.RSS == 0 {
					break
				}
				if shown[p.PID] {
					continue
				}

				var chain []int
				pid := p.PID
				for pid > 1 && len(chain) < 4 {
					chain = append(chain, pid)
					if proc, ok := pidProc[pid]; ok {
						pid = proc.PPID
					} else {
						break
					}
				}

				for j := len(chain) - 1; j >= 0; j-- {
					cpid := chain[j]
					if shown[cpid] {
						continue
					}
					shown[cpid] = true
					proc := pidProc[cpid]
					if proc == nil {
						continue
					}
					indent := len(chain) - 1 - j
					prefix := ""
					if indent > 0 {
						prefix = strings.Repeat("  ", indent-1) + "└─"
					}
					comm := proc.Comm
					if len(comm) > 14 {
						comm = comm[:11] + "..."
					}
					childCount := len(children[cpid])
					tree := ""
					if childCount > 0 {
						// Sum RSS of all direct children
						var childRSS uint64
						for _, cid := range children[cpid] {
							childRSS += rssByPID[cid]
						}
						if childRSS > 0 {
							tree = fmt.Sprintf("(%d children, %s total)", childCount, fmtBytes(childRSS))
						} else {
							tree = fmt.Sprintf("(%d children)", childCount)
						}
					}

					row := fmt.Sprintf("%7d %s%-*s %10s %6.1f%%  %s",
						cpid, prefix, 16-len(prefix), comm,
						fmtBytes(rssByPID[cpid]), memByPID[cpid], tree)
					treeLines = append(treeLines, row)
				}
			}
			if len(treeLines) > 1 {
				sb.WriteString(boxSection("PROCESS TREE (top memory)", treeLines, iw))
			}
		}
	}

	sb.WriteString(pageFooter(""))

	return sb.String()
}
