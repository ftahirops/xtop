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
	LayoutHtop     LayoutMode = 4 // E: htop-style
	LayoutBtop     LayoutMode = 5 // F: btop-style
	layoutCount    LayoutMode = 6
)

var layoutNames = []string{"Two-Column", "Compact", "Adaptive", "Grid", "htop", "btop"}

func (l LayoutMode) String() string {
	if int(l) < len(layoutNames) {
		return layoutNames[l]
	}
	return "Unknown"
}

// renderOverview dispatches to the selected layout.
func renderOverview(snap *model.Snapshot, rates *model.RateSnapshot, result *model.AnalysisResult,
	history *engine.History, smartDisks []model.SMARTDisk, pm probeQuerier,
	layout LayoutMode, compact bool, width, height int, intermediate bool) string {

	if snap == nil {
		return "Collecting first sample..."
	}

	ss := extractSubsystems(snap, rates, result, intermediate)

	var content string
	switch layout {
	case LayoutTwoCol:
		content = renderLayoutA(snap, rates, result, history, pm, ss, compact, width, height, intermediate)
	case LayoutCompact:
		content = renderLayoutB(snap, rates, result, history, pm, ss, width, height, intermediate)
	case LayoutAdaptive:
		content = renderLayoutC(snap, rates, result, history, pm, ss, width, height, intermediate)
	case LayoutGrid:
		content = renderLayoutD(snap, rates, result, history, pm, ss, width, height, intermediate)
	case LayoutHtop:
		content = renderLayoutE(snap, rates, result, history, pm, ss, width, height, intermediate)
	case LayoutBtop:
		content = renderLayoutF(snap, rates, result, history, pm, ss, width, height, intermediate)
	default:
		content = renderLayoutA(snap, rates, result, history, pm, ss, compact, width, height, intermediate)
	}

	// Inject layout indicator into the first line (top right)
	lines := strings.Split(content, "\n")
	if len(lines) > 0 {
		viewLabel := "Summary"
		if !compact {
			viewLabel = "Detail"
		}
		label := dimStyle.Render(fmt.Sprintf("[%s | %s] d:toggle", layout, viewLabel))
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

func extractSubsystems(snap *model.Snapshot, rates *model.RateSnapshot, result *model.AnalysisResult, intermediate bool) []subsysInfo {
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

	// Load average with human-readable capacity interpretation
	la := snap.Global.CPU.LoadAvg
	nCPU := snap.Global.CPU.NumCPUs
	if nCPU == 0 {
		nCPU = 1
	}
	loadPct := la.Load1 / float64(nCPU) * 100
	var loadInterp string
	switch {
	case loadPct < 25:
		loadInterp = "idle"
	case loadPct < 50:
		loadInterp = "light"
	case loadPct < 75:
		loadInterp = "moderate"
	case loadPct < 100:
		loadInterp = "heavy"
	case loadPct < 150:
		loadInterp = "overloaded"
	case loadPct < 200:
		loadInterp = "severe"
	default:
		loadInterp = "critical"
	}
	loadStr := fmt.Sprintf("%.1f / %.1f / %.1f = %.0f%% of %d CPUs (%s)", la.Load1, la.Load5, la.Load15, loadPct, nCPU, loadInterp)

	// Run queue with percentage and color hint
	rqPct := float64(la.Running) / float64(nCPU) * 100
	var rqLabel string
	switch {
	case rqPct <= 100:
		rqLabel = "OK"
	case rqPct <= 200:
		rqLabel = "BUSY"
	case rqPct <= 400:
		rqLabel = "SATURATED"
	default:
		rqLabel = "CRITICAL"
	}
	rqStr := fmt.Sprintf("%d / %d CPUs (%.0f%%) %s", la.Running, nCPU, rqPct, rqLabel)

	// Steal explanation
	stealStr := fmt.Sprintf("%.1f%%", stealPct)
	if stealPct > 10 {
		stealStr += " — VM starved by hypervisor"
	} else if stealPct > 3 {
		stealStr += " — noisy neighbor"
	}

	usageVal := fmt.Sprintf("%.1f%% busy", busyPct)
	loadVal := loadStr
	ctxVal := fmt.Sprintf("%.0f/s", ctxRate)
	sysVal := fmt.Sprintf("%.1f%%", sysPct)
	if intermediate {
		usageVal += " " + metricVerdict(busyPct, 70, 90)
		loadVal += " " + metricVerdict(loadPct, 100, 200)
		sysVal += " " + metricVerdict(sysPct, 20, 40)
		stealStr += " " + metricVerdict(stealPct, 3, 10)
	}
	cpu.Details = []kv{
		{"Usage", usageVal},
		{"Load avg", loadVal},
		{"Run queue", rqStr},
		{"Ctx switch", ctxVal},
		{"System CPU", sysVal},
		{"Steal", stealStr},
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

	usedVal := fmt.Sprintf("%.1f%% (%s free)", memUsedPct, fmtBytes(memAvail))
	if intermediate {
		usedVal += " " + metricVerdict(memUsedPct, 80, 95)
	}
	mem.Details = []kv{
		{"Used", usedVal},
		{"Cache", fmtBytes(snap.Global.Memory.Cached)},
	}
	swapStr := "unused"
	swapPct := float64(0)
	if snap.Global.Memory.SwapTotal > 0 && snap.Global.Memory.SwapUsed > 0 {
		swapStr = fmt.Sprintf("%s/%s", fmtBytes(snap.Global.Memory.SwapUsed), fmtBytes(snap.Global.Memory.SwapTotal))
		swapPct = float64(snap.Global.Memory.SwapUsed) / float64(snap.Global.Memory.SwapTotal) * 100
		if intermediate {
			swapStr += " " + metricVerdict(swapPct, 30, 70)
		}
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
	utilValStr := utilVal
	if intermediate {
		utilValStr += " " + metricVerdict(worstUtil, 70, 90)
	}
	latencyVal := fmt.Sprintf("%.1f ms", worstAwait)
	if intermediate {
		latencyVal += " " + metricVerdict(worstAwait, 10, 50)
	}
	qdVal := fmt.Sprintf("%d", worstQ)
	if intermediate {
		qdVal += " " + metricVerdict(float64(worstQ), 32, 128)
	}
	io.Details = []kv{
		{"Utilization", utilValStr},
		{"Latency", latencyVal},
		{"Queue depth", qdVal},
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

	dropsVal := fmt.Sprintf("%.0f/s", totalDrops)
	if intermediate {
		dropsVal += " " + metricVerdict(totalDrops, 1, 100)
	}
	retransVal := fmt.Sprintf("%.0f/s", retransRate)
	if intermediate {
		retransVal += " " + metricVerdict(retransRate, 10, 50)
	}

	net.Details = []kv{
		{"RX/TX", rxTx},
		{"Drops", dropsVal},
		{"Retransmits", retransVal},
	}

	ephVal := ephStr
	if intermediate {
		ephPctVal := float64(0)
		if eph.RangeHi > 0 {
			ephRange := eph.RangeHi - eph.RangeLo + 1
			ephPctVal = float64(eph.InUse) / float64(ephRange) * 100
		}
		ephVal += " " + metricVerdict(ephPctVal, 50, 80)
	}
	net.Details = append(net.Details, kv{"Ephemeral", ephVal})

	ctVal := ctStr
	if intermediate && ct.Max > 0 {
		ctPctVal := float64(ct.Count) / float64(ct.Max) * 100
		ctVal += " " + metricVerdict(ctPctVal, 80, 95)
	}
	net.Details = append(net.Details, kv{"Conntrack", ctVal})

	softIRQVal := fmt.Sprintf("%.1f%%", softIRQ)
	if intermediate {
		softIRQVal += " " + metricVerdict(softIRQ, 5, 15)
	}
	net.Details = append(net.Details, kv{"SoftIRQ load", softIRQVal})

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

		worstMountVal := fmt.Sprintf("%s (%.0f%% used)", worstMount, usedPct)
		if intermediate {
			worstMountVal += " " + metricVerdict(usedPct, 80, 95)
		}
		inodeVal := fmt.Sprintf("%.0f%%", worstInodePct)
		if intermediate {
			inodeVal += " " + metricVerdict(worstInodePct, 80, 95)
		}
		disk.Details = []kv{
			{"Worst mount", worstMountVal},
			{"Free", fmt.Sprintf("%.0f%%", worstFreePct)},
			{"Fill rate", etaStr},
			{"Inode usage", inodeVal},
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
