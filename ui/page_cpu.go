package ui

import (
	"fmt"
	"sort"
	"strings"

	"github.com/ftahirops/xtop/model"
)

func renderCPUPage(snap *model.Snapshot, rates *model.RateSnapshot, result *model.AnalysisResult, pm probeQuerier, width, height int, intermediate bool) string {
	var sb strings.Builder
	iw := pageInnerW(width)

	sb.WriteString(titleStyle.Render("CPU SUBSYSTEM"))
	if intermediate {
		sb.WriteString(dimStyle.Render("  [verdicts ON]"))
	}
	sb.WriteString("\n")
	sb.WriteString(renderRCAInline(result))
	sb.WriteString(renderProbeStatusLine(pm, snap, intermediate))
	sb.WriteString("\n")

	// === Summary ===
	nCPU := snap.Global.CPU.NumCPUs
	load := snap.Global.CPU.LoadAvg
	psi := snap.Global.PSI.CPU

	busyPct := float64(0)
	userPct := float64(0)
	sysPct := float64(0)
	iowPct := float64(0)
	softPct := float64(0)
	irqPct := float64(0)
	stealPct := float64(0)
	nicePct := float64(0)
	ctxRate := float64(0)
	if rates != nil {
		busyPct = rates.CPUBusyPct
		userPct = rates.CPUUserPct
		sysPct = rates.CPUSystemPct
		iowPct = rates.CPUIOWaitPct
		softPct = rates.CPUSoftIRQPct
		irqPct = rates.CPUIRQPct
		stealPct = rates.CPUStealPct
		nicePct = rates.CPUNicePct
		ctxRate = rates.CtxSwitchRate
	}
	bw := iw/2 - 15
	if bw < 5 {
		bw = 5
	}
	ctxPerCore := float64(0)
	if nCPU > 0 {
		ctxPerCore = ctxRate / float64(nCPU)
	}

	var sumLines []string
	cpuLine := fmt.Sprintf("CPU busy:    %s %s  (%d cores)", bar(busyPct, bw), fmtPct(busyPct), nCPU)
	if intermediate {
		cpuLine += "  " + metricVerdict(busyPct, 70, 90)
	}
	sumLines = append(sumLines, cpuLine)

	userLine := fmt.Sprintf("User:        %s  System: %s  %s: %s",
		fmtPct(userPct), fmtPct(sysPct),
		abbr("IOWait", "CPU idle waiting for disk", intermediate), fmtPct(iowPct))
	if intermediate && iowPct > 0 {
		userLine += "  " + metricVerdict(iowPct, 10, 30)
	}
	sumLines = append(sumLines, userLine)

	sumLines = append(sumLines, fmt.Sprintf("%s: %s  %s: %s  Steal: %s  Nice: %s",
		abbr("SoftIRQ", "network/timer interrupt overhead", intermediate), fmtPct(softPct),
		abbr("IRQ", "hardware interrupt time", intermediate), fmtPct(irqPct),
		fmtPct(stealPct), fmtPct(nicePct)))

	ctxLine := fmt.Sprintf("%s: %.0f/s (%.0f/core)",
		abbr("Ctx switches", "task context switches", intermediate), ctxRate, ctxPerCore)
	sumLines = append(sumLines, ctxLine)

	psiLine := fmt.Sprintf("%s some/full: %s / %s",
		abbr("PSI", "Pressure Stall Information — % time tasks wait", intermediate),
		fmtPSI(psi.Some.Avg10), fmtPSI(psi.Full.Avg10))
	if intermediate {
		psiLine += "  " + metricVerdict(psi.Some.Avg10, 5, 25)
	}
	sumLines = append(sumLines, psiLine)

	// Load average with capacity interpretation
	cpuLoadPct := float64(0)
	if nCPU > 0 {
		cpuLoadPct = load.Load1 / float64(nCPU) * 100
	}
	var cpuLoadInterp string
	switch {
	case cpuLoadPct < 25:
		cpuLoadInterp = "idle"
	case cpuLoadPct < 50:
		cpuLoadInterp = "light"
	case cpuLoadPct < 75:
		cpuLoadInterp = "moderate"
	case cpuLoadPct < 100:
		cpuLoadInterp = "heavy"
	case cpuLoadPct < 150:
		cpuLoadInterp = "overloaded"
	case cpuLoadPct < 200:
		cpuLoadInterp = "severely overloaded"
	default:
		cpuLoadInterp = "critically overloaded"
	}
	loadLine := fmt.Sprintf("Load avg:    1m=%.2f  5m=%.2f  15m=%.2f  → %.0f%% of %d CPUs (%s)",
		load.Load1, load.Load5, load.Load15, cpuLoadPct, nCPU, cpuLoadInterp)
	if intermediate {
		loadLine += "  " + metricVerdict(cpuLoadPct, 100, 200)
	}
	sumLines = append(sumLines, loadLine)

	cpuRQPct := float64(load.Running) / float64(nCPU) * 100
	var cpuRQLabel string
	switch {
	case cpuRQPct <= 100:
		cpuRQLabel = "OK"
	case cpuRQPct <= 200:
		cpuRQLabel = "BUSY"
	case cpuRQPct <= 400:
		cpuRQLabel = "SATURATED"
	default:
		cpuRQLabel = "CRITICAL"
	}
	sumLines = append(sumLines, fmt.Sprintf("Run queue:   %d runnable / %d cores (%.0f%%) — %s", load.Running, nCPU, cpuRQPct, cpuRQLabel))
	// VM steal explanation
	if stealPct > 0.1 {
		sumLines = append(sumLines, "")
		stealLine := fmt.Sprintf("Steal:       %.1f%% — ", stealPct)
		if stealPct > 10 {
			stealLine += "VM starved by hypervisor — cloud host severely oversubscribed"
		} else if stealPct > 3 {
			stealLine += "noisy neighbor — other VMs on same host stealing your CPU time"
		} else {
			stealLine += "minor hypervisor overhead (normal for cloud VMs)"
		}
		if result != nil && result.SysInfo != nil && result.SysInfo.Virtualization != "Bare Metal" {
			stealLine += fmt.Sprintf("  [%s]", result.SysInfo.Virtualization)
		}
		sumLines = append(sumLines, warnStyle.Render(stealLine))
	}

	sb.WriteString(boxSection("SUMMARY", sumLines, iw))

	// === Top cgroups by CPU% ===
	var cgLines []string
	cgLines = append(cgLines, dimStyle.Render(fmt.Sprintf("%-30s %8s %10s", "CGROUP", "CPU%", "THROTTLE%")))

	if rates != nil && len(rates.CgroupRates) > 0 {
		cgs := make([]model.CgroupRate, len(rates.CgroupRates))
		copy(cgs, rates.CgroupRates)
		sort.Slice(cgs, func(i, j int) bool { return cgs[i].CPUPct > cgs[j].CPUPct })
		for i, cg := range cgs {
			if i >= 10 || cg.CPUPct < 0.1 {
				break
			}
			name := cg.Name
			if len(name) > 30 {
				name = name[:27] + "..."
			}
			cgLines = append(cgLines, fmt.Sprintf("%-30s %7.1f%% %9.1f%%", name, cg.CPUPct, cg.ThrottlePct))
		}
	} else {
		cgLines = append(cgLines, dimStyle.Render("(collecting...)"))
	}
	sb.WriteString(boxSection("TOP CGROUPS BY CPU", cgLines, iw))

	// === Top cgroups by throttling ===
	var thrLines []string
	if rates != nil && len(rates.CgroupRates) > 0 {
		cgs := make([]model.CgroupRate, len(rates.CgroupRates))
		copy(cgs, rates.CgroupRates)
		sort.Slice(cgs, func(i, j int) bool { return cgs[i].ThrottlePct > cgs[j].ThrottlePct })
		shown := 0
		for i, cg := range cgs {
			if i >= 5 || cg.ThrottlePct < 0.1 {
				break
			}
			line := fmt.Sprintf("%-30s %s %5.1f%%", cg.Name, abbr("throttled", "cgroup hit its CPU limit", intermediate), cg.ThrottlePct)
			if intermediate {
				line += "  " + metricVerdict(cg.ThrottlePct, 10, 50)
			}
			thrLines = append(thrLines, line)
			shown++
		}
		if shown == 0 {
			thrLines = append(thrLines, dimStyle.Render("none"))
		}
	} else {
		thrLines = append(thrLines, dimStyle.Render("(collecting...)"))
	}
	sb.WriteString(boxSection("TOP CGROUPS BY THROTTLING", thrLines, iw))

	// === Top PIDs ===
	var procLines []string
	procHeader := fmt.Sprintf("%7s %-16s %8s %8s %12s",
		"PID", "COMMAND", "CPU%", "STATE",
		abbr("CTXSW/s", "context switches/sec", intermediate))
	procLines = append(procLines, dimStyle.Render(procHeader))

	if rates != nil && len(rates.ProcessRates) > 0 {
		procs := make([]model.ProcessRate, len(rates.ProcessRates))
		copy(procs, rates.ProcessRates)
		sort.Slice(procs, func(i, j int) bool { return procs[i].CPUPct > procs[j].CPUPct })
		for i, p := range procs {
			if i >= 15 || p.CPUPct < 0.1 {
				break
			}
			comm := p.Comm
			if len(comm) > 16 {
				comm = comm[:13] + "..."
			}
			row := fmt.Sprintf("%7d %-16s %7.1f%% %8s %11.0f", p.PID, comm, p.CPUPct, p.State, p.CtxSwitchRate)
			if p.State == "D" {
				if intermediate {
					row += "  " + warnStyle.Render("← stuck waiting for disk")
				}
				procLines = append(procLines, warnStyle.Render(row))
			} else {
				procLines = append(procLines, row)
			}
		}
	} else {
		procLines = append(procLines, dimStyle.Render("(collecting...)"))
	}
	sb.WriteString(boxSection("TOP PROCESSES BY CPU", procLines, iw))

	// === Process Tree for top CPU consumers ===
	if !intermediate { // Hide tree in intermediate mode to reduce complexity
		if len(snap.Processes) > 0 && rates != nil && len(rates.ProcessRates) > 0 {
			var treeLines []string
			treeLines = append(treeLines, dimStyle.Render(fmt.Sprintf("%7s %-16s %7s %8s  %s", "PID", "COMMAND", "CPU%", "STATE", "TREE")))

			// Build PID→Process lookup and PID→children map
			pidProc := make(map[int]*model.ProcessMetrics, len(snap.Processes))
			children := make(map[int][]int)
			for i := range snap.Processes {
				p := &snap.Processes[i]
				pidProc[p.PID] = p
				if p.PPID > 1 {
					children[p.PPID] = append(children[p.PPID], p.PID)
				}
			}

			// Build CPU% lookup from rates
			cpuByPID := make(map[int]float64, len(rates.ProcessRates))
			for _, pr := range rates.ProcessRates {
				cpuByPID[pr.PID] = pr.CPUPct
			}

			// Find top 8 CPU consumers and show their ancestry
			procs := make([]model.ProcessRate, len(rates.ProcessRates))
			copy(procs, rates.ProcessRates)
			sort.Slice(procs, func(i, j int) bool { return procs[i].CPUPct > procs[j].CPUPct })

			shown := make(map[int]bool)
			for i, p := range procs {
				if i >= 8 || p.CPUPct < 0.5 {
					break
				}
				if shown[p.PID] {
					continue
				}

				// Build ancestry chain: PID → parent → grandparent → ...
				var chain []int
				pid := p.PID
				for pid > 1 && len(chain) < 5 {
					chain = append(chain, pid)
					if proc, ok := pidProc[pid]; ok {
						pid = proc.PPID
					} else {
						break
					}
				}

				// Render chain from root → child (reverse)
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
					prefix := strings.Repeat("  ", indent)
					if indent > 0 {
						prefix = strings.Repeat("  ", indent-1) + "└─"
					}
					comm := proc.Comm
					if len(comm) > 14 {
						comm = comm[:11] + "..."
					}

					// Count child threads/processes
					childCount := len(children[cpid])
					tree := ""
					if childCount > 0 {
						tree = fmt.Sprintf("(%d children)", childCount)
					}

					cpuPct := cpuByPID[cpid]
					row := fmt.Sprintf("%7d %s%-*s %6.1f%% %8s  %s",
						cpid, prefix, 16-len(prefix), comm, cpuPct, proc.State, tree)
					if proc.State == "D" {
						treeLines = append(treeLines, warnStyle.Render(row))
					} else if cpuPct > 50 {
						treeLines = append(treeLines, critStyle.Render(row))
					} else {
						treeLines = append(treeLines, row)
					}
				}
			}
			if len(treeLines) > 1 {
				sb.WriteString(boxSection("PROCESS TREE (top CPU)", treeLines, iw))
			}
		}
	}

	// === Per-Process Network Activity (from eBPF) ===
	if snap.Global.Sentinel.Active {
		sent := snap.Global.Sentinel
		// Build PID→network map from retrans + connlat + outbound
		type procNetInfo struct {
			Comm       string
			CPUPct     float64
			Retrans    uint32
			ConnLatAvg float64
			OutBytes   uint64
			Dests      int
		}
		pnet := make(map[int]*procNetInfo)

		// Get CPU% for top procs
		if rates != nil {
			for _, pr := range rates.ProcessRates {
				if pr.CPUPct >= 1.0 {
					pnet[pr.PID] = &procNetInfo{Comm: pr.Comm, CPUPct: pr.CPUPct}
				}
			}
		}

		// Enrich with retransmit data
		for _, r := range sent.Retransmits {
			if pn, ok := pnet[int(r.PID)]; ok {
				pn.Retrans = r.Count
			}
		}
		// Enrich with connect latency
		for _, c := range sent.ConnLatency {
			if pn, ok := pnet[int(c.PID)]; ok {
				pn.ConnLatAvg = c.AvgMs
			}
		}
		// Enrich with outbound bytes
		for _, o := range sent.OutboundTop {
			if pn, ok := pnet[o.PID]; ok {
				pn.OutBytes += o.TotalBytes
				pn.Dests++
			}
		}

		// Only show procs that have network activity
		var netProcLines []string
		type netProc struct {
			PID  int
			Info *procNetInfo
		}
		var netProcs []netProc
		for pid, info := range pnet {
			if info.Retrans > 0 || info.ConnLatAvg > 0 || info.OutBytes > 0 {
				netProcs = append(netProcs, netProc{pid, info})
			}
		}
		sort.Slice(netProcs, func(i, j int) bool { return netProcs[i].Info.CPUPct > netProcs[j].Info.CPUPct })

		if len(netProcs) > 0 {
			netProcLines = append(netProcLines, dimStyle.Render(fmt.Sprintf("%7s %-14s %7s %8s %10s %10s",
				"PID", "COMMAND", "CPU%",
				abbr("RETRANS", "TCP resends", intermediate),
				abbr("CONN LAT", "connect latency", intermediate), "OUT")))
			for i, np := range netProcs {
				if i >= 10 {
					break
				}
				comm := np.Info.Comm
				if len(comm) > 14 {
					comm = comm[:11] + "..."
				}
				retStr := "—"
				if np.Info.Retrans > 0 {
					retStr = fmt.Sprintf("%d", np.Info.Retrans)
				}
				latStr := "—"
				if np.Info.ConnLatAvg > 0 {
					latStr = fmt.Sprintf("%.1fms", np.Info.ConnLatAvg)
				}
				outStr := "—"
				if np.Info.OutBytes > 0 {
					outStr = fmtBytes(np.Info.OutBytes)
				}

				row := fmt.Sprintf("%7d %-14s %6.1f%% %8s %10s %10s",
					np.PID, comm, np.Info.CPUPct, retStr, latStr, outStr)
				if np.Info.Retrans > 10 {
					netProcLines = append(netProcLines, warnStyle.Render(row))
				} else {
					netProcLines = append(netProcLines, row)
				}
			}
			sb.WriteString(boxSection("NETWORK ACTIVITY (top CPU procs)", netProcLines, iw))
		}
	}

	// === Log Errors Correlated to CPU Load ===
	if snap.Global.Logs.Services != nil && rates != nil && len(rates.ProcessRates) > 0 {
		// Build set of top CPU process names
		topComms := make(map[string]float64)
		for i, p := range rates.ProcessRates {
			if i >= 20 || p.CPUPct < 1.0 {
				break
			}
			topComms[p.Comm] = p.CPUPct
		}

		var logLines []string
		for _, svc := range snap.Global.Logs.Services {
			if svc.ErrorRate == 0 && svc.WarnRate == 0 {
				continue
			}
			// Match service name to process comm (fuzzy: nginx, mysql, redis, etc.)
			svcName := strings.ToLower(svc.Name)
			matched := false
			var matchedCPU float64
			for comm, cpu := range topComms {
				if strings.Contains(svcName, strings.ToLower(comm)) || strings.Contains(strings.ToLower(comm), svcName) {
					matched = true
					matchedCPU = cpu
					break
				}
			}
			if !matched && svc.ErrorRate < 0.1 {
				continue
			}

			errLabel := ""
			if svc.ErrorRate > 0 {
				errLabel = fmt.Sprintf("%.1f err/s", svc.ErrorRate)
			}
			warnLabel := ""
			if svc.WarnRate > 0 {
				warnLabel = fmt.Sprintf("%.1f warn/s", svc.WarnRate)
			}
			cpuLabel := ""
			if matched {
				cpuLabel = fmt.Sprintf("(%.1f%% CPU)", matchedCPU)
			}

			line := fmt.Sprintf("  %-16s %s %s %s",
				svc.Name, errLabel, warnLabel, cpuLabel)
			if svc.ErrorRate > 1 {
				logLines = append(logLines, warnStyle.Render(line))
			} else {
				logLines = append(logLines, line)
			}
			if svc.LastError != "" {
				lastErr := svc.LastError
				if len(lastErr) > iw-8 {
					lastErr = lastErr[:iw-11] + "..."
				}
				logLines = append(logLines, dimStyle.Render("    "+lastErr))
			}
		}
		if len(logLines) > 0 {
			sb.WriteString(boxSection("LOG ERRORS (correlated)", logLines, iw))
		}
	}

	sb.WriteString(pageFooter("F9:signal"))

	return sb.String()
}
