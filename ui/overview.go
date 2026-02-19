package ui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/ftahirops/xtop/engine"
	"github.com/ftahirops/xtop/model"
)

// LayoutMode selects which overview layout to render.
type LayoutMode int

const (
	LayoutTwoCol   LayoutMode = 0 // A: Two-Column Split
	LayoutCompact  LayoutMode = 1 // B: Compact Table
	LayoutAdaptive LayoutMode = 2 // C: Adaptive Expand
	LayoutGrid     LayoutMode = 3 // D: Dashboard Grid
	layoutCount    LayoutMode = 4
)

var layoutNames = []string{"Two-Column", "Compact", "Adaptive", "Grid"}

func (l LayoutMode) String() string {
	if int(l) < len(layoutNames) {
		return layoutNames[l]
	}
	return "Unknown"
}

// renderOverview dispatches to the selected layout.
func renderOverview(snap *model.Snapshot, rates *model.RateSnapshot, result *model.AnalysisResult,
	history *engine.History, smartDisks []model.SMARTDisk, pm probeQuerier,
	layout LayoutMode, width, height int) string {

	if snap == nil {
		return "Collecting first sample..."
	}

	ss := extractSubsystems(snap, rates, result)

	var content string
	switch layout {
	case LayoutTwoCol:
		content = renderLayoutA(snap, rates, result, history, pm, ss, width, height)
	case LayoutCompact:
		content = renderLayoutB(snap, rates, result, history, pm, ss, width, height)
	case LayoutAdaptive:
		content = renderLayoutC(snap, rates, result, history, pm, ss, width, height)
	case LayoutGrid:
		content = renderLayoutD(snap, rates, result, history, pm, ss, width, height)
	default:
		content = renderLayoutA(snap, rates, result, history, pm, ss, width, height)
	}

	// Inject layout indicator into the first line (top right)
	lines := strings.Split(content, "\n")
	if len(lines) > 0 {
		label := dimStyle.Render(fmt.Sprintf("[%s]", layout))
		labelW := lipgloss.Width(label)
		lineW := lipgloss.Width(lines[0])
		gap := width - lineW - labelW
		if gap < 1 {
			gap = 1
		}
		lines[0] = lines[0] + strings.Repeat(" ", gap) + label
	}
	return strings.Join(lines, "\n")
}

// ─── SHARED: HEADER ─────────────────────────────────────────────────────────

func renderHeader(snap *model.Snapshot, rates *model.RateSnapshot, result *model.AnalysisResult) string {
	var sb strings.Builder

	if result == nil {
		return dimStyle.Render(" collecting...")
	}

	sb.WriteString(" ")
	switch result.Health {
	case model.HealthOK:
		sb.WriteString(okStyle.Render("HEALTH: OK"))
	case model.HealthInconclusive:
		sb.WriteString(orangeStyle.Render("HEALTH: INCONCLUSIVE"))
	case model.HealthDegraded:
		sb.WriteString(warnStyle.Render(fmt.Sprintf("DEGRADED — %s (%d%% confidence)",
			result.PrimaryBottleneck, result.Confidence)))
	case model.HealthCritical:
		sb.WriteString(critStyle.Render(fmt.Sprintf("CRITICAL — %s (%d%% confidence)",
			result.PrimaryBottleneck, result.Confidence)))
	}

	if result.AnomalyStartedAgo > 0 {
		sb.WriteString(critStyle.Render(fmt.Sprintf(" — Incident %s", fmtDuration(result.AnomalyStartedAgo))))
	} else if result.StableSince > 60 {
		sb.WriteString(dimStyle.Render(fmt.Sprintf(" | Stable %s", fmtDuration(result.StableSince))))
	}

	sb.WriteString(dimStyle.Render(" | "))

	cpuPct := float64(0)
	if rates != nil {
		cpuPct = rates.CPUBusyPct
	}
	sb.WriteString(meterColor(cpuPct).Render(fmt.Sprintf("CPU %5.1f%%", cpuPct)))
	sb.WriteString(dimStyle.Render(" | "))

	memPct := float64(0)
	if snap.Global.Memory.Total > 0 {
		memPct = float64(snap.Global.Memory.Total-snap.Global.Memory.Available) / float64(snap.Global.Memory.Total) * 100
	}
	sb.WriteString(meterColor(memPct).Render(fmt.Sprintf("MEM %5.1f%%", memPct)))
	sb.WriteString(dimStyle.Render(" | "))

	ioPct := float64(0)
	if rates != nil {
		for _, d := range rates.DiskRates {
			if d.UtilPct > ioPct {
				ioPct = d.UtilPct
			}
		}
	}
	sb.WriteString(meterColor(ioPct).Render(fmt.Sprintf("IO %5.1f%%", ioPct)))
	sb.WriteString(dimStyle.Render(" | "))
	sb.WriteString(dimStyle.Render(fmt.Sprintf("Load %5.2f", snap.Global.CPU.LoadAvg.Load1)))

	// Disk free % (worst mount)
	if rates != nil && len(rates.MountRates) > 0 {
		var worstFreePct float64 = 100
		var worstETA float64 = -1
		for _, mr := range rates.MountRates {
			if mr.FreePct < worstFreePct {
				worstFreePct = mr.FreePct
				worstETA = mr.ETASeconds
			}
		}
		diskUsedPct := 100 - worstFreePct
		sb.WriteString(dimStyle.Render(" | "))
		diskStr := fmt.Sprintf("DISK %4.0f%%", diskUsedPct)
		if worstETA > 0 && worstETA < 7200 {
			diskStr += fmt.Sprintf(" ETA %.0fm", worstETA/60)
		}
		// Color: green >30% free, yellow >10% free, red <=10% free
		if worstFreePct <= 10 {
			sb.WriteString(critStyle.Render(diskStr))
		} else if worstFreePct <= 30 {
			sb.WriteString(warnStyle.Render(diskStr))
		} else {
			sb.WriteString(okStyle.Render(diskStr))
		}
	}

	return sb.String()
}

// ─── SHARED: SUBSYSTEM DATA ─────────────────────────────────────────────────

// subsysInfo holds pre-computed metrics for one subsystem.
type subsysInfo struct {
	Name        string
	Status      string // "GREEN", "YELLOW", "RED"
	StatusStyle lipgloss.Style
	PressurePct float64
	PressureStr string
	CapacityPct float64
	CapacityStr string
	Risk        string
	TopOwner    string
	TopOwnerVal string
	Details     []kv // key-value detail lines
}

type kv struct {
	Key string
	Val string
}

func extractSubsystems(snap *model.Snapshot, rates *model.RateSnapshot, result *model.AnalysisResult) []subsysInfo {
	var ss []subsysInfo

	// CPU
	cpu := subsysInfo{Name: "CPU"}
	cpu.PressurePct = snap.Global.PSI.CPU.Some.Avg10
	cpu.PressureStr = fmt.Sprintf("%.1f%%", cpu.PressurePct)
	cpu.Status, cpu.StatusStyle = statusFromPSI(cpu.PressurePct)

	busyPct := float64(0)
	stealPct := float64(0)
	if rates != nil {
		busyPct = rates.CPUBusyPct
		stealPct = rates.CPUStealPct
	}
	cpu.CapacityPct = 100 - busyPct
	cpu.CapacityStr = fmt.Sprintf("%.1f%%", cpu.CapacityPct)
	cpu.Risk = findRisk(result, "CPU")

	ctxRate := float64(0)
	sysPct := float64(0)
	if rates != nil {
		ctxRate = rates.CtxSwitchRate
		sysPct = rates.CPUSystemPct
	}

	cpu.Details = []kv{
		{"Usage", fmt.Sprintf("%.1f%% busy", busyPct)},
		{"Run queue", fmt.Sprintf("%d", snap.Global.CPU.LoadAvg.Running)},
		{"Ctx switch", fmt.Sprintf("%.0f/s", ctxRate)},
		{"System CPU", fmt.Sprintf("%.1f%%", sysPct)},
		{"Steal", fmt.Sprintf("%.1f%%", stealPct)},
	}
	// Throttling from cgroups
	throttled := "none"
	if rates != nil {
		for _, cg := range rates.CgroupRates {
			if cg.ThrottlePct > 1 {
				throttled = fmt.Sprintf("%s (%.0f%%)", cg.Name, cg.ThrottlePct)
				break
			}
		}
	}
	cpu.Details = append(cpu.Details, kv{"Throttling", throttled})

	if result != nil && len(result.CPUOwners) > 0 {
		cpu.TopOwner = result.CPUOwners[0].Name
		cpu.TopOwnerVal = result.CPUOwners[0].Value
	}
	topCPU := "\u2014" // em dash
	if cpu.TopOwner != "" {
		topCPU = fmt.Sprintf("%s (%s)", cpu.TopOwner, cpu.TopOwnerVal)
	}
	cpu.Details = append(cpu.Details, kv{"Top group", topCPU})
	ss = append(ss, cpu)

	// Memory
	mem := subsysInfo{Name: "Memory"}
	mem.PressurePct = snap.Global.PSI.Memory.Some.Avg10
	mem.PressureStr = fmt.Sprintf("%.1f%%", mem.PressurePct)
	mem.Status, mem.StatusStyle = statusFromPSI(mem.PressurePct)

	memUsedPct := float64(0)
	memAvail := snap.Global.Memory.Available
	if snap.Global.Memory.Total > 0 {
		memUsedPct = float64(snap.Global.Memory.Total-memAvail) / float64(snap.Global.Memory.Total) * 100
		mem.CapacityPct = 100 - memUsedPct
	}
	mem.CapacityStr = fmt.Sprintf("%.1f%%", mem.CapacityPct)
	mem.Risk = findRisk(result, "Memory")

	memTotal := snap.Global.Memory.Total
	dirtyPct := float64(0)
	if memTotal > 0 {
		dirtyPct = float64(snap.Global.Memory.Dirty) / float64(memTotal) * 100
	}

	mem.Details = []kv{
		{"Used", fmt.Sprintf("%.1f%% (%s free)", memUsedPct, fmtBytes(memAvail))},
		{"Cache", fmtBytes(snap.Global.Memory.Cached)},
	}
	swapStr := "unused"
	if snap.Global.Memory.SwapTotal > 0 && snap.Global.Memory.SwapUsed > 0 {
		swapStr = fmt.Sprintf("%s/%s", fmtBytes(snap.Global.Memory.SwapUsed), fmtBytes(snap.Global.Memory.SwapTotal))
	}
	mem.Details = append(mem.Details, kv{"Swap", swapStr})

	dirtyStr := "clean"
	if dirtyPct > 0.1 {
		dirtyStr = fmt.Sprintf("%s (%.1f%%)", fmtBytes(snap.Global.Memory.Dirty), dirtyPct)
	}
	mem.Details = append(mem.Details, kv{"Dirty pages", dirtyStr})

	reclaimStr := "none"
	if rates != nil && rates.DirectReclaimRate > 0 {
		reclaimStr = fmt.Sprintf("%.0f pages/s", rates.DirectReclaimRate)
	}
	mem.Details = append(mem.Details, kv{"Reclaim", reclaimStr})

	faultStr := "normal"
	if rates != nil && rates.MajFaultRate > 10 {
		faultStr = fmt.Sprintf("%.0f major/s", rates.MajFaultRate)
	}
	mem.Details = append(mem.Details, kv{"Page faults", faultStr})

	if result != nil && len(result.MemOwners) > 0 {
		mem.TopOwner = result.MemOwners[0].Name
		mem.TopOwnerVal = result.MemOwners[0].Value
	}
	topMem := "\u2014"
	if mem.TopOwner != "" {
		topMem = fmt.Sprintf("%s (%s)", mem.TopOwner, mem.TopOwnerVal)
	}
	mem.Details = append(mem.Details, kv{"Top group", topMem})
	ss = append(ss, mem)

	// Disk IO
	io := subsysInfo{Name: "Disk IO"}
	io.PressurePct = snap.Global.PSI.IO.Some.Avg10
	io.PressureStr = fmt.Sprintf("%5.1f%%", io.PressurePct)
	io.Status, io.StatusStyle = statusFromPSI(io.PressurePct)

	worstUtil := float64(0)
	worstAwait := float64(0)
	worstQ := uint64(0)
	worstName := ""
	if rates != nil {
		for _, d := range rates.DiskRates {
			if d.UtilPct > worstUtil {
				worstUtil = d.UtilPct
				worstAwait = d.AvgAwaitMs
				worstQ = d.QueueDepth
				worstName = d.Name
			}
		}
	}
	io.CapacityPct = 100 - worstUtil
	io.CapacityStr = fmt.Sprintf("%.1f%%", io.CapacityPct)
	io.Risk = findRisk(result, "IO")

	utilVal := fmt.Sprintf("%.1f%%", worstUtil)
	if worstName != "" {
		utilVal = fmt.Sprintf("%.1f%% (%s)", worstUtil, worstName)
	}
	io.Details = []kv{
		{"Utilization", utilVal},
		{"Latency", fmt.Sprintf("%.1f ms", worstAwait)},
		{"Queue depth", fmt.Sprintf("%d", worstQ)},
	}

	// Read/write throughput
	readMBs := float64(0)
	writeMBs := float64(0)
	if rates != nil {
		for _, d := range rates.DiskRates {
			readMBs += d.ReadMBs
			writeMBs += d.WriteMBs
		}
	}
	io.Details = append(io.Details, kv{"Throughput", fmt.Sprintf("R:%.1f W:%.1f MB/s", readMBs, writeMBs)})

	// IOPS
	readIOPS := float64(0)
	writeIOPS := float64(0)
	if rates != nil {
		for _, d := range rates.DiskRates {
			readIOPS += d.ReadIOPS
			writeIOPS += d.WriteIOPS
		}
	}
	io.Details = append(io.Details, kv{"IOPS", fmt.Sprintf("R:%.0f W:%.0f", readIOPS, writeIOPS)})

	if result != nil && len(result.IOOwners) > 0 {
		io.TopOwner = result.IOOwners[0].Name
		io.TopOwnerVal = result.IOOwners[0].Value
	}
	topIO := "\u2014"
	if io.TopOwner != "" {
		topIO = fmt.Sprintf("%s (%s)", io.TopOwner, io.TopOwnerVal)
	}
	io.Details = append(io.Details, kv{"Top writer", topIO})
	ss = append(ss, io)

	// Network
	net := subsysInfo{Name: "Network"}
	net.PressureStr = "OK"
	net.PressurePct = 0
	net.Status = "GREEN"
	net.StatusStyle = okStyle
	net.CapacityStr = "OK"
	net.CapacityPct = 100
	net.Risk = findRisk(result, "Network")

	totalDrops := float64(0)
	retransRate := float64(0)
	if rates != nil {
		for _, nr := range rates.NetRates {
			totalDrops += nr.RxDropsPS + nr.TxDropsPS
		}
		retransRate = rates.RetransRate
	}

	if totalDrops > 100 || retransRate > 50 {
		net.Status = "RED"
		net.StatusStyle = critStyle
		net.PressureStr = "HIGH"
	} else if totalDrops > 0 || retransRate > 10 {
		net.Status = "YELLOW"
		net.StatusStyle = warnStyle
		net.PressureStr = "ELEVATED"
	}

	ct := snap.Global.Conntrack
	ctStr := "OK"
	if ct.Max > 0 {
		ctPct := float64(ct.Count) / float64(ct.Max) * 100
		ctStr = fmt.Sprintf("%d entries", ct.Count)
		net.CapacityPct = 100 - ctPct
		net.CapacityStr = fmt.Sprintf("%.1f%%", net.CapacityPct)
		if ctPct > 80 {
			net.Status = "RED"
			net.StatusStyle = critStyle
		}
	}

	var totalRx, totalTx float64
	if rates != nil {
		for _, nr := range rates.NetRates {
			totalRx += nr.RxMBs
			totalTx += nr.TxMBs
		}
	}
	rxTx := fmt.Sprintf("%.1f/%.1f MB/s", totalRx, totalTx)

	softIRQ := float64(0)
	if rates != nil {
		softIRQ = rates.CPUSoftIRQPct
	}

	// Ephemeral port pressure
	eph := snap.Global.EphemeralPorts
	ephStr := "OK"
	if eph.RangeHi > 0 {
		ephRange := eph.RangeHi - eph.RangeLo + 1
		ephPct := float64(eph.InUse) / float64(ephRange) * 100
		ephStr = fmt.Sprintf("%d/%d (%.0f%%)", eph.InUse, ephRange, ephPct)
		if ephPct > 80 {
			net.Status = "RED"
			net.StatusStyle = critStyle
		} else if ephPct > 50 && net.Status != "RED" {
			net.Status = "YELLOW"
			net.StatusStyle = warnStyle
		}
		// Also factor ephemeral into capacity
		ephFree := 100 - ephPct
		if ephFree < net.CapacityPct {
			net.CapacityPct = ephFree
			net.CapacityStr = fmt.Sprintf("%.1f%%", ephFree)
		}
	}

	net.Details = []kv{
		{"RX/TX", rxTx},
		{"Drops", fmt.Sprintf("%.0f/s", totalDrops)},
		{"Retransmits", fmt.Sprintf("%.0f/s", retransRate)},
		{"Ephemeral", ephStr},
		{"Conntrack", ctStr},
		{"SoftIRQ load", fmt.Sprintf("%.1f%%", softIRQ)},
	}

	if result != nil && len(result.NetOwners) > 0 {
		net.TopOwner = result.NetOwners[0].Name
		net.TopOwnerVal = result.NetOwners[0].Value
	}
	topNet := "\u2014"
	if net.TopOwner != "" {
		topNet = fmt.Sprintf("%s (%s)", net.TopOwner, net.TopOwnerVal)
	}
	net.Details = append(net.Details, kv{"Top owner", topNet})
	ss = append(ss, net)

	// Disk Space
	disk := subsysInfo{Name: "Disk Space"}
	disk.Status = "GREEN"
	disk.StatusStyle = okStyle
	disk.PressurePct = 0
	disk.PressureStr = "OK"
	disk.CapacityPct = 100
	disk.CapacityStr = "100%"
	disk.Risk = "none"

	if rates != nil && len(rates.MountRates) > 0 {
		var worstFreePct float64 = 100
		var worstMount string
		var worstETA float64 = -1
		var worstInodePct float64
		for _, mr := range rates.MountRates {
			if mr.FreePct < worstFreePct {
				worstFreePct = mr.FreePct
				worstMount = mr.MountPoint
				worstETA = mr.ETASeconds
			}
			if mr.InodeUsedPct > worstInodePct {
				worstInodePct = mr.InodeUsedPct
			}
		}
		usedPct := 100 - worstFreePct
		disk.CapacityPct = worstFreePct
		disk.CapacityStr = fmt.Sprintf("%.0f%%", worstFreePct)

		if worstFreePct < 5 {
			disk.Status = "RED"
			disk.StatusStyle = critStyle
			disk.PressureStr = "CRITICAL"
		} else if worstFreePct < 15 {
			disk.Status = "YELLOW"
			disk.StatusStyle = warnStyle
			disk.PressureStr = "ELEVATED"
		}

		etaStr := "not growing"
		if worstETA > 0 {
			etaMin := worstETA / 60
			if etaMin < 60 {
				etaStr = fmt.Sprintf("ETA %.0fm", etaMin)
			} else {
				etaStr = fmt.Sprintf("ETA %.0fh", etaMin/60)
			}
		}

		disk.Details = []kv{
			{"Worst mount", fmt.Sprintf("%s (%.0f%% used)", worstMount, usedPct)},
			{"Free", fmt.Sprintf("%.0f%%", worstFreePct)},
			{"Fill rate", etaStr},
			{"Inode usage", fmt.Sprintf("%.0f%%", worstInodePct)},
		}

		if result != nil && result.DiskGuardWorst != "" {
			disk.Risk = result.DiskGuardWorst
		}
	} else {
		disk.Details = []kv{
			{"Status", "collecting..."},
		}
	}
	ss = append(ss, disk)

	return ss
}

func statusFromPSI(pct float64) (string, lipgloss.Style) {
	switch {
	case pct >= 25:
		return "RED", critStyle
	case pct >= 5:
		return "YELLOW", warnStyle
	default:
		return "GREEN", okStyle
	}
}

func findRisk(result *model.AnalysisResult, keyword string) string {
	if result == nil {
		return "none"
	}
	for _, rca := range result.RCA {
		if rca.Score > 20 && strings.Contains(rca.Bottleneck, keyword) {
			return fmt.Sprintf("%s (%d%%)", rca.Bottleneck, rca.Score)
		}
	}
	return "none"
}

// ─── SHARED: TREND SPARKLINE ────────────────────────────────────────────────

func renderTrendBlock(result *model.AnalysisResult, history *engine.History, width int, _ bool) string {
	var sb strings.Builder
	n := history.Len()
	if n < 3 {
		sb.WriteString(titleStyle.Render(" Trend"))
		sb.WriteString(dimStyle.Render("  collecting..."))
		return sb.String()
	}

	oldest := history.Get(0)
	latest := history.Latest()
	durLabel := ""
	if oldest != nil && latest != nil {
		durLabel = fmt.Sprintf(" (%s)", formatDuration(latest.Timestamp.Sub(oldest.Timestamp)))
	}
	sb.WriteString(titleStyle.Render(fmt.Sprintf(" Trend%s", durLabel)))
	sb.WriteString("\n")

	// Box inner width: total width - 5 for border chars (` │ ... │`)
	innerW := width - 7
	if innerW < 40 {
		innerW = 40
	}

	// Sparkline chart width: inner width - label(8) - padding(2) - " now=XXX.X"(~12)
	chartW := innerW - 22
	if chartW < 10 {
		chartW = 10
	}

	// Collect all 16 series from snapshot + rate history
	cpuBusy := make([]float64, n)
	cpuIOWait := make([]float64, n)
	cpuSteal := make([]float64, n)
	cpuPSI := make([]float64, n)

	memUsed := make([]float64, n)
	memPSI := make([]float64, n)
	swapIO := make([]float64, n)
	reclaim := make([]float64, n)

	ioPSI := make([]float64, n)
	ioUtil := make([]float64, n)
	ioAwait := make([]float64, n)
	ioThru := make([]float64, n)

	netThru := make([]float64, n)
	netRetx := make([]float64, n)
	netDrops := make([]float64, n)
	netSoftIRQ := make([]float64, n)

	for i := 0; i < n; i++ {
		s := history.Get(i)
		if s == nil {
			continue
		}

		// PSI (from snapshot directly)
		cpuPSI[i] = s.Global.PSI.CPU.Some.Avg10
		memPSI[i] = s.Global.PSI.Memory.Full.Avg10
		ioPSI[i] = s.Global.PSI.IO.Full.Avg10

		// Memory used %
		if s.Global.Memory.Total > 0 {
			memUsed[i] = float64(s.Global.Memory.Total-s.Global.Memory.Available) / float64(s.Global.Memory.Total) * 100
		}

		// Rate-based metrics
		r := history.GetRate(i)
		if r == nil {
			continue
		}

		cpuBusy[i] = r.CPUBusyPct
		cpuIOWait[i] = r.CPUIOWaitPct
		cpuSteal[i] = r.CPUStealPct

		swapIO[i] = r.SwapInRate + r.SwapOutRate
		reclaim[i] = r.DirectReclaimRate

		// Worst disk util/await/throughput
		for _, d := range r.DiskRates {
			if d.UtilPct > ioUtil[i] {
				ioUtil[i] = d.UtilPct
				ioAwait[i] = d.AvgAwaitMs
			}
			ioThru[i] += d.ReadMBs + d.WriteMBs
		}

		// Network aggregates
		for _, nr := range r.NetRates {
			netThru[i] += nr.RxMBs + nr.TxMBs
			netDrops[i] += nr.RxDropsPS + nr.TxDropsPS
		}
		netRetx[i] = r.RetransRate
		netSoftIRQ[i] = r.CPUSoftIRQPct
	}

	sb.WriteString(boxTop(innerW) + "\n")

	line := func(label string, data []float64, maxV float64) {
		content := fmt.Sprintf("  %s %s", styledPad(dimStyle.Render(label), 8), sparkline(data, chartW, 0, maxV))
		sb.WriteString(boxRow(content, innerW) + "\n")
	}

	section := func(title string) {
		sb.WriteString(boxRow(titleStyle.Render(title), innerW) + "\n")
	}

	section("CPU")
	line("busy", cpuBusy, 100)
	line("iowait", cpuIOWait, 100)
	line("steal", cpuSteal, 100)
	line("PSI", cpuPSI, 50)

	sb.WriteString(boxMid(innerW) + "\n")
	section("Memory")
	line("used", memUsed, 100)
	line("PSI", memPSI, 50)
	line("swap", swapIO, 10)
	line("reclm", reclaim, 1000)

	sb.WriteString(boxMid(innerW) + "\n")
	section("Disk IO")
	line("PSI", ioPSI, 50)
	line("util", ioUtil, 100)
	line("await", ioAwait, 100)
	line("thru", ioThru, 500)

	// Derive network throughput max from link speed
	netThruMax := float64(100) // default 100 MB/s
	if latest != nil {
		for _, iface := range latest.Global.Network {
			if iface.SpeedMbps > 0 {
				// Convert Mbps to MB/s (divide by 8)
				ifaceMaxMBs := float64(iface.SpeedMbps) / 8
				if ifaceMaxMBs > netThruMax {
					netThruMax = ifaceMaxMBs
				}
			}
		}
	}

	sb.WriteString(boxMid(innerW) + "\n")
	section("Network")
	line("thru", netThru, netThruMax)
	line("retx", netRetx, 100)
	line("drops", netDrops, 100)
	line("softirq", netSoftIRQ, 100)

	sb.WriteString(boxBot(innerW) + "\n")

	return sb.String()
}

// ─── SHARED: OWNERS BLOCK ───────────────────────────────────────────────────

func renderOwnersBlock(result *model.AnalysisResult) string {
	var sb strings.Builder
	sb.WriteString(titleStyle.Render(" Top Resource Owners"))
	sb.WriteString("\n")

	innerW := 78
	var lines []string

	renderLine := func(resource string, owners []model.Owner) {
		label := styledPad(headerStyle.Render(resource+":"), colOwLbl+1)
		if len(owners) == 0 {
			lines = append(lines, label+dimStyle.Render("\u2014"))
			return
		}
		parts := make([]string, 0, 3)
		for i, o := range owners {
			if i >= 3 {
				break
			}
			name := truncate(o.Name, 24)
			parts = append(parts, valueStyle.Render(name)+dimStyle.Render(":"+o.Value))
		}
		lines = append(lines, label+strings.Join(parts, dimStyle.Render(" | ")))
	}

	if result == nil {
		renderLine("IO", nil)
		renderLine("CPU", nil)
		renderLine("MEM", nil)
		renderLine("NET", nil)
	} else {
		renderLine("IO", result.IOOwners)
		renderLine("CPU", result.CPUOwners)
		renderLine("MEM", result.MemOwners)
		renderLine("NET", result.NetOwners)
	}

	sb.WriteString(boxTop(innerW) + "\n")
	for _, l := range lines {
		sb.WriteString(boxRow(l, innerW) + "\n")
	}
	sb.WriteString(boxBot(innerW) + "\n")
	return sb.String()
}

// ─── SHARED: RCA BOX ────────────────────────────────────────────────────────

func renderRCABox(result *model.AnalysisResult) string {
	var sb strings.Builder
	sb.WriteString(titleStyle.Render(" Root Cause Analysis"))
	sb.WriteString("\n")

	innerW := 72

	// Always 3 lines for stable layout
	lines := [3]string{" ", " ", " "}

	if result == nil {
		lines[0] = dimStyle.Render("collecting...")
	} else {
		switch result.Health {
		case model.HealthOK:
			lines[0] = okStyle.Render("RCA: No bottleneck detected")
			if result.StableSince > 60 {
				lines[1] = dimStyle.Render(fmt.Sprintf("Stable for %s", fmtDuration(result.StableSince)))
			}

		case model.HealthInconclusive:
			lines[0] = orangeStyle.Render("RCA: Inconclusive") +
				dimStyle.Render(" \u2014 evidence insufficient")
			lines[1] = dimStyle.Render("Press I to investigate (10s kernel probe)")

		case model.HealthDegraded, model.HealthCritical:
			style := warnStyle
			if result.Health == model.HealthCritical {
				style = critStyle
			}
			lines[0] = style.Render("RCA: " + result.PrimaryBottleneck)

			culprit := "\u2014"
			if result.PrimaryProcess != "" {
				culprit = result.PrimaryProcess
				if result.PrimaryPID > 0 {
					culprit = fmt.Sprintf("%s(%d)", result.PrimaryProcess, result.PrimaryPID)
				}
			} else if result.PrimaryCulprit != "" && result.PrimaryCulprit != "/" {
				culprit = result.PrimaryCulprit
			}
			culprit = truncate(culprit, 24)

			parts := []string{
				fmt.Sprintf("Culprit: %s", valueStyle.Render(culprit)),
				fmt.Sprintf("Confidence: %s", style.Render(fmt.Sprintf("%d%%", result.Confidence))),
			}
			if result.AnomalyStartedAgo > 0 {
				parts = append(parts,
					fmt.Sprintf("Active: %s", critStyle.Render(fmtDuration(result.AnomalyStartedAgo))))
			}
			lines[1] = strings.Join(parts, dimStyle.Render(" | "))

			if result.CausalChain != "" {
				chain := result.CausalChain
				if len(chain) > 70 {
					chain = chain[:67] + "..."
				}
				lines[2] = dimStyle.Render("Chain: ") + valueStyle.Render(chain)
			}
		}
	}

	sb.WriteString(boxTop(innerW) + "\n")
	for _, l := range lines {
		sb.WriteString(boxRow(l, innerW) + "\n")
	}
	sb.WriteString(boxBot(innerW) + "\n")
	return sb.String()
}

// ─── SHARED: CAPACITY BLOCK ─────────────────────────────────────────────────

func renderCapacityBlock(result *model.AnalysisResult, withBars bool, barW int) string {
	var sb strings.Builder
	sb.WriteString(titleStyle.Render(" Capacity Remaining"))
	sb.WriteString("\n")

	innerW := colKey + barW + 40
	if !withBars {
		innerW = colKey + 40
	}

	if result == nil {
		sb.WriteString(boxTop(innerW) + "\n")
		sb.WriteString(boxRow(dimStyle.Render("collecting..."), innerW) + "\n")
		sb.WriteString(boxBot(innerW) + "\n")
		return sb.String()
	}

	// Header
	if withBars {
		hdr := fmt.Sprintf("%s %s %s  %s",
			styledPad(dimStyle.Render("Resource"), colKey),
			styledPad("", barW),
			styledPad(dimStyle.Render("Free"), 6),
			dimStyle.Render("Current / Limit"))
		sb.WriteString(boxTop(innerW) + "\n")
		sb.WriteString(boxRow(hdr, innerW) + "\n")
	} else {
		sb.WriteString(boxTop(innerW) + "\n")
	}

	for _, cap := range result.Capacities {
		style := dimStyle
		if cap.Pct < 15 {
			style = critStyle
		} else if cap.Pct < 30 {
			style = warnStyle
		}

		lbl := styledPad(cap.Label, colKey)
		var content string
		if withBars {
			limitInfo := ""
			if cap.Current != "" && cap.Limit != "" {
				limitInfo = dimStyle.Render(fmt.Sprintf("  %s / %s", cap.Current, cap.Limit))
			} else if cap.Current != "" {
				limitInfo = dimStyle.Render(fmt.Sprintf("  %s", cap.Current))
			}
			content = fmt.Sprintf("%s %s %s%s",
				lbl,
				capacityBar(cap.Pct, barW),
				style.Render(fmtPct(cap.Pct)),
				limitInfo)
		} else {
			content = fmt.Sprintf("%s %s",
				lbl,
				style.Render(fmtPct(cap.Pct)))
			if cap.Current != "" && cap.Limit != "" {
				content += dimStyle.Render(fmt.Sprintf("  %s / %s", cap.Current, cap.Limit))
			} else if cap.Current != "" {
				content += dimStyle.Render(fmt.Sprintf("  %s", cap.Current))
			}
		}
		sb.WriteString(boxRow(content, innerW) + "\n")
	}
	sb.WriteString(boxBot(innerW) + "\n")
	return sb.String()
}

// capacityBar renders a green/yellow/red bar based on remaining capacity.
func capacityBar(pct float64, width int) string {
	if pct < 0 {
		pct = 0
	}
	if pct > 100 {
		pct = 100
	}
	filled := int(pct / 100 * float64(width))
	if filled > width {
		filled = width
	}
	filledStr := strings.Repeat("█", filled)
	emptyStr := strings.Repeat("░", width-filled)
	style := okStyle
	if pct < 15 {
		style = critStyle
	} else if pct < 30 {
		style = warnStyle
	}
	return style.Render(filledStr) + dimStyle.Render(emptyStr)
}

// ─── SHARED: EXHAUSTION WARNINGS ────────────────────────────────────────────

func renderExhaustionBlock(result *model.AnalysisResult) string {
	var sb strings.Builder
	sb.WriteString(titleStyle.Render(" Exhaustion Warnings"))
	sb.WriteString("\n")

	innerW := 50

	sb.WriteString(boxTop(innerW) + "\n")
	if result == nil || len(result.Exhaustions) == 0 {
		sb.WriteString(boxRow(dimStyle.Render("none"), innerW) + "\n")
	} else {
		for _, ex := range result.Exhaustions {
			content := critStyle.Render(fmt.Sprintf("!! %s exhaustion in ~%.0fm", ex.Resource, ex.EstMinutes)) +
				dimStyle.Render(fmt.Sprintf("  (%.0f%%, +%.2f%%/s)", ex.CurrentPct, ex.TrendPerS))
			sb.WriteString(boxRow(content, innerW) + "\n")
		}
	}
	sb.WriteString(boxBot(innerW) + "\n")
	return sb.String()
}

// ─── SHARED: WHAT CHANGED BLOCK ─────────────────────────────────────────────

func renderChangesBlock(result *model.AnalysisResult) string {
	var sb strings.Builder
	sb.WriteString(titleStyle.Render(" What Changed (30s)"))
	sb.WriteString("\n")

	innerW := 60

	sb.WriteString(boxTop(innerW) + "\n")
	if result == nil || len(result.TopChanges) == 0 {
		sb.WriteString(boxRow(dimStyle.Render("no significant changes"), innerW) + "\n")
	} else {
		for _, c := range result.TopChanges {
			arrow := okStyle.Render("\u2193") // ↓
			if c.Rising {
				arrow = critStyle.Render("\u2191") // ↑
			}
			sign := ""
			if c.Rising {
				sign = "+"
			}
			pctStr := fmt.Sprintf("%s%.0f%%", sign, c.DeltaPct)
			style := dimStyle
			absPct := c.DeltaPct
			if absPct < 0 {
				absPct = -absPct
			}
			if absPct > 50 {
				style = critStyle
			} else if absPct > 20 {
				style = warnStyle
			}
			content := fmt.Sprintf(" %s %s %s  now %s",
				arrow,
				styledPad(valueStyle.Render(c.Name), 18),
				styledPad(style.Render(pctStr), 8),
				dimStyle.Render(c.Current))
			sb.WriteString(boxRow(content, innerW) + "\n")
		}
	}
	sb.WriteString(boxBot(innerW) + "\n")
	return sb.String()
}

func renderChangesInline(result *model.AnalysisResult) string {
	var sb strings.Builder
	sb.WriteString(" ")
	sb.WriteString(titleStyle.Render("Changed:"))
	sb.WriteString(" ")

	if result == nil || len(result.TopChanges) == 0 {
		sb.WriteString(dimStyle.Render("no significant changes"))
		sb.WriteString("\n")
		return sb.String()
	}

	parts := []string{}
	for i, c := range result.TopChanges {
		if i >= 5 {
			break
		}
		arrow := "\u2193"
		if c.Rising {
			arrow = "\u2191"
		}
		sign := ""
		if c.Rising {
			sign = "+"
		}
		parts = append(parts, fmt.Sprintf("%s%s %s%.0f%%", arrow, c.Name, sign, c.DeltaPct))
	}
	sb.WriteString(dimStyle.Render(strings.Join(parts, " | ")))
	sb.WriteString("\n")
	return sb.String()
}

// ─── SHARED: SUGGESTED ACTIONS BLOCK ─────────────────────────────────────────

func renderActionsBlock(result *model.AnalysisResult) string {
	var sb strings.Builder
	sb.WriteString(titleStyle.Render(" Suggested Actions"))
	sb.WriteString("\n")

	innerW := 72

	sb.WriteString(boxTop(innerW) + "\n")
	if result == nil || len(result.Actions) == 0 {
		sb.WriteString(boxRow(dimStyle.Render("no actions — system healthy"), innerW) + "\n")
	} else {
		shown := result.Actions
		if len(shown) > 5 {
			shown = shown[:5]
		}
		for i, a := range shown {
			summary := a.Summary
			if len(summary) > 55 {
				summary = summary[:52] + "..."
			}
			content := fmt.Sprintf(" %s %s", orangeStyle.Render(fmt.Sprintf("%d.", i+1)), valueStyle.Render(summary))
			sb.WriteString(boxRow(content, innerW) + "\n")
			if a.Command != "" {
				cmd := a.Command
				if len(cmd) > 60 {
					cmd = cmd[:57] + "..."
				}
				sb.WriteString(boxRow(dimStyle.Render("    $ "+cmd), innerW) + "\n")
			}
		}
	}
	sb.WriteString(boxBot(innerW) + "\n")
	return sb.String()
}

// ─── SHARED: DEGRADATION BLOCK ──────────────────────────────────────────────

func renderDegradationBlock(result *model.AnalysisResult) string {
	if result == nil || len(result.Degradations) == 0 {
		return ""
	}

	var sb strings.Builder
	sb.WriteString(titleStyle.Render(" Slow Degradation"))
	sb.WriteString("\n")

	innerW := 60

	sb.WriteString(boxTop(innerW) + "\n")
	for _, d := range result.Degradations {
		dur := fmtDuration(d.Duration)
		content := warnStyle.Render(fmt.Sprintf(" %s %s", d.Metric, d.Direction)) +
			dimStyle.Render(fmt.Sprintf("  %.2f %s for %s", d.Rate, d.Unit, dur))
		sb.WriteString(boxRow(content, innerW) + "\n")
	}
	sb.WriteString(boxBot(innerW) + "\n")
	return sb.String()
}

// ─── SHARED: INLINE BLOCKS (fixed-size for layouts C/D) ─────────────────────

// renderRCAInline renders a single-line RCA status. Always produces exactly 1 line.
func renderRCAInline(result *model.AnalysisResult) string {
	var sb strings.Builder
	sb.WriteString(" ")
	sb.WriteString(titleStyle.Render("RCA:"))
	sb.WriteString(" ")

	if result == nil {
		sb.WriteString(dimStyle.Render("collecting..."))
		sb.WriteString("\n")
		return sb.String()
	}

	switch result.Health {
	case model.HealthOK:
		sb.WriteString(okStyle.Render("No bottleneck detected"))

	case model.HealthInconclusive:
		sb.WriteString(orangeStyle.Render("Inconclusive"))
		sb.WriteString(dimStyle.Render(" \u2014 evidence insufficient"))
		sb.WriteString(dimStyle.Render(" | Press I to investigate"))

	case model.HealthDegraded, model.HealthCritical:
		style := warnStyle
		if result.Health == model.HealthCritical {
			style = critStyle
		}
		sb.WriteString(style.Render(result.PrimaryBottleneck))

		culprit := "\u2014"
		if result.PrimaryProcess != "" {
			culprit = truncate(result.PrimaryProcess, 24)
		} else if result.PrimaryCulprit != "" && result.PrimaryCulprit != "/" {
			culprit = truncate(result.PrimaryCulprit, 24)
		}
		sb.WriteString(dimStyle.Render(" | Culprit: "))
		sb.WriteString(valueStyle.Render(culprit))
		sb.WriteString(dimStyle.Render(fmt.Sprintf(" | Confidence: %d%%", result.Confidence)))

		if result.AnomalyStartedAgo > 0 {
			sb.WriteString(dimStyle.Render(" | Active: "))
			sb.WriteString(critStyle.Render(fmtDuration(result.AnomalyStartedAgo)))
		}
	}

	sb.WriteString("\n")
	return sb.String()
}

// renderProbeStatusLine renders the probe status. Always produces exactly 1 line.
// Pass nil for idle state (no probe engine available yet).
func renderProbeStatusLine(pm probeQuerier) string {
	var sb strings.Builder
	sb.WriteString(" ")
	sb.WriteString(titleStyle.Render("Probe:"))
	sb.WriteString(" ")

	if pm == nil || pm.ProbeState() == 0 {
		sb.WriteString(dimStyle.Render("idle"))
		sb.WriteString(dimStyle.Render(
			" | Press I to run 10s probe (off-CPU / IO latency / lock waits / retrans)"))
		sb.WriteString("\n")
		return sb.String()
	}

	switch pm.ProbeState() {
	case 1: // running
		sb.WriteString(orangeStyle.Render("running"))
		sb.WriteString(dimStyle.Render(fmt.Sprintf(
			" (%s) \u2014 %ds left\u2026", pm.ProbePack(), pm.ProbeSecsLeft())))
	case 2: // done
		sb.WriteString(okStyle.Render("done"))
		summary := pm.ProbeSummary()
		if summary != "" {
			sb.WriteString(dimStyle.Render(" | Findings: "))
			sb.WriteString(valueStyle.Render(summary))
		}
	}

	sb.WriteString("\n")
	return sb.String()
}

// probeQuerier is an interface for querying probe state without importing engine.
type probeQuerier interface {
	ProbeState() int
	ProbePack() string
	ProbeSecsLeft() int
	ProbeSummary() string
}

// renderOwnersInline renders owners with top-3 per resource. 5 lines (title + 4 resource lines).
func renderOwnersInline(result *model.AnalysisResult) string {
	var sb strings.Builder
	sb.WriteString(" ")
	sb.WriteString(titleStyle.Render("Owners:"))
	sb.WriteString("\n")

	renderLine := func(label string, owners []model.Owner) {
		sb.WriteString("  ")
		sb.WriteString(headerStyle.Render(label + ":"))
		sb.WriteString(" ")
		if len(owners) == 0 {
			sb.WriteString(dimStyle.Render("\u2014"))
		} else {
			parts := make([]string, 0, 3)
			for i, o := range owners {
				if i >= 3 {
					break
				}
				name := truncate(o.Name, 24)
				parts = append(parts, valueStyle.Render(name)+dimStyle.Render(":"+o.Value))
			}
			sb.WriteString(strings.Join(parts, dimStyle.Render(" | ")))
		}
		sb.WriteString("\n")
	}

	if result != nil {
		renderLine("IO", result.IOOwners)
		renderLine("CPU", result.CPUOwners)
		renderLine("MEM", result.MemOwners)
		renderLine("NET", result.NetOwners)
	} else {
		renderLine("IO", nil)
		renderLine("CPU", nil)
		renderLine("MEM", nil)
		renderLine("NET", nil)
	}
	return sb.String()
}

// renderCapacityInline renders a single-line capacity summary. Always produces exactly 1 line.
func renderCapacityInline(result *model.AnalysisResult) string {
	var sb strings.Builder
	sb.WriteString(" ")
	sb.WriteString(titleStyle.Render("Capacity:"))
	sb.WriteString(" ")

	if result == nil || len(result.Capacities) == 0 {
		sb.WriteString(dimStyle.Render("collecting..."))
		sb.WriteString("\n")
		return sb.String()
	}

	parts := []string{}
	for _, cap := range result.Capacities {
		style := dimStyle
		if cap.Pct < 15 {
			style = critStyle
		} else if cap.Pct < 30 {
			style = warnStyle
		}
		parts = append(parts, fmt.Sprintf("%s %s", cap.Label, style.Render(fmtPct(cap.Pct))))
	}
	sb.WriteString(strings.Join(parts, dimStyle.Render(" | ")))
	sb.WriteString("\n")
	return sb.String()
}

// ─── SHARED: HELPERS ────────────────────────────────────────────────────────

func psiColor(pct float64) lipgloss.Style {
	switch {
	case pct >= 25:
		return critStyle
	case pct >= 5:
		return warnStyle
	case pct >= 0.5:
		return orangeStyle
	default:
		return okStyle
	}
}

func meterColor(pct float64) lipgloss.Style {
	switch {
	case pct >= 80:
		return critStyle
	case pct >= 50:
		return warnStyle
	default:
		return okStyle
	}
}

func fmtDuration(sec int) string {
	if sec >= 3600 {
		return fmt.Sprintf("%dh%dm", sec/3600, (sec%3600)/60)
	}
	if sec >= 60 {
		return fmt.Sprintf("%dm%ds", sec/60, sec%60)
	}
	return fmt.Sprintf("%ds", sec)
}

// separator renders a horizontal rule.
func separator(width int) string {
	if width < 1 {
		width = 40
	}
	return dimStyle.Render(strings.Repeat("─", width))
}
