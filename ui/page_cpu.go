package ui

import (
	"fmt"
	"sort"
	"strings"

	"github.com/ftahirops/xtop/model"
)

func renderCPUPage(snap *model.Snapshot, rates *model.RateSnapshot, result *model.AnalysisResult, pm probeQuerier, width, height int) string {
	var sb strings.Builder
	iw := pageInnerW(width)

	sb.WriteString(titleStyle.Render("CPU SUBSYSTEM"))
	sb.WriteString("\n")
	sb.WriteString(renderRCAInline(result))
	sb.WriteString(renderProbeStatusLine(pm, snap))
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
	sumLines = append(sumLines, fmt.Sprintf("CPU busy:    %s %s  (%d cores)", bar(busyPct, bw), fmtPct(busyPct), nCPU))
	sumLines = append(sumLines, fmt.Sprintf("User:        %s  System: %s  IOWait: %s", fmtPct(userPct), fmtPct(sysPct), fmtPct(iowPct)))
	sumLines = append(sumLines, fmt.Sprintf("SoftIRQ:     %s  IRQ: %s  Steal: %s  Nice: %s", fmtPct(softPct), fmtPct(irqPct), fmtPct(stealPct), fmtPct(nicePct)))
	sumLines = append(sumLines, fmt.Sprintf("Ctx switches: %.0f/s (%.0f/core)", ctxRate, ctxPerCore))
	sumLines = append(sumLines, fmt.Sprintf("PSI some/full: %s / %s", fmtPSI(psi.Some.Avg10), fmtPSI(psi.Full.Avg10)))
	sumLines = append(sumLines, fmt.Sprintf("Load: %.2f %.2f %.2f  Runnable: %d", load.Load1, load.Load5, load.Load15, load.Running))
	// VM steal hint
	if result != nil && result.SysInfo != nil && result.SysInfo.Virtualization != "Bare Metal" && stealPct > 1 {
		sumLines = append(sumLines, "")
		sumLines = append(sumLines, warnStyle.Render("VM Steal detected: ")+
			dimStyle.Render("High steal suggests host/hypervisor contention — contact infrastructure team"))
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
			thrLines = append(thrLines, fmt.Sprintf("%-30s throttled %5.1f%%", cg.Name, cg.ThrottlePct))
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
	procLines = append(procLines, dimStyle.Render(fmt.Sprintf("%7s %-16s %8s %8s %12s", "PID", "COMMAND", "CPU%", "STATE", "CTXSW/s")))

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
				procLines = append(procLines, warnStyle.Render(row))
			} else {
				procLines = append(procLines, row)
			}
		}
	} else {
		procLines = append(procLines, dimStyle.Render("(collecting...)"))
	}
	sb.WriteString(boxSection("TOP PROCESSES BY CPU", procLines, iw))

	return sb.String()
}
