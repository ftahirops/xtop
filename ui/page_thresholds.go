package ui

import (
	"fmt"
	"strings"

	"github.com/ftahirops/xtop/model"
)

// thresholdEntry describes one metric's thresholds and current value.
type thresholdEntry struct {
	Metric   string
	Current  string
	Normal   string // "normal" range
	Warn     string // warning threshold
	Crit     string // critical threshold
	Limit    string // theoretical/system max
	Source   string // where the limit comes from
	CurFloat float64
	WarnF    float64
	CritF    float64
	Status   string // "ok", "warn", "crit"
}

func renderThresholdsPage(snap *model.Snapshot, rates *model.RateSnapshot, result *model.AnalysisResult, width, height int) string {
	var sb strings.Builder
	iw := pageInnerW(width)

	sb.WriteString(titleStyle.Render("THRESHOLDS & LIMITS — How High Is High?"))
	sb.WriteString("\n")
	sb.WriteString(dimStyle.Render(" Current system values vs detection thresholds. Dynamic limits derived from hardware."))
	sb.WriteString("\n\n")

	// ── CPU Thresholds ──
	nCPU := snap.Global.CPU.NumCPUs
	if nCPU == 0 {
		nCPU = 1
	}
	busyPct := float64(0)
	stealPct := float64(0)
	softPct := float64(0)
	ctxRate := float64(0)
	if rates != nil {
		busyPct = rates.CPUBusyPct
		stealPct = rates.CPUStealPct
		softPct = rates.CPUSoftIRQPct
		ctxRate = rates.CtxSwitchRate
	}
	ctxPerCore := ctxRate / float64(nCPU)
	psiCPU := snap.Global.PSI.CPU.Some.Avg10
	rqRatio := float64(snap.Global.CPU.LoadAvg.Running) / float64(nCPU)

	var maxThrottle float64
	if rates != nil {
		for _, cg := range rates.CgroupRates {
			if cg.ThrottlePct > maxThrottle {
				maxThrottle = cg.ThrottlePct
			}
		}
	}

	cpuEntries := []thresholdEntry{
		makeEntry("CPU Busy", busyPct, "%", 0, 80, 100, fmt.Sprintf("%d cores", nCPU), "/proc/stat"),
		makeEntry("CPU PSI some", psiCPU, "%", 0, 5, 25, "100%", "/proc/pressure/cpu"),
		makeEntry("Run Queue Ratio", rqRatio, "x", 0, 1.5, 3.0, fmt.Sprintf("%.0fx", float64(nCPU)), "/proc/loadavg runnable/cores"),
		makeEntry("Ctx Switches/core", ctxPerCore, "/s", 0, 30000, 100000, "~200K/core", "/proc/pid/status aggregate"),
		makeEntry("CPU Steal", stealPct, "%", 0, 5, 15, "100%", "hypervisor (VM only)"),
		makeEntry("SoftIRQ CPU", softPct, "%", 0, 5, 15, "100%", "/proc/stat"),
		makeEntry("Cgroup Throttle", maxThrottle, "%", 0, 5, 30, "100%", "cpu.stat nr_throttled"),
	}
	sb.WriteString(renderThresholdSection("CPU", cpuEntries, iw))

	// ── Memory Thresholds ──
	mem := snap.Global.Memory
	memUsedPct := float64(0)
	availPct := float64(0)
	if mem.Total > 0 {
		memUsedPct = float64(mem.Total-mem.Available) / float64(mem.Total) * 100
		availPct = float64(mem.Available) / float64(mem.Total) * 100
	}
	psiMem := snap.Global.PSI.Memory.Full.Avg10
	dirtyPct := float64(0)
	if mem.Total > 0 {
		dirtyPct = float64(mem.Dirty) / float64(mem.Total) * 100
	}
	swapIn := float64(0)
	swapOut := float64(0)
	directR := float64(0)
	majFaultR := float64(0)
	if rates != nil {
		swapIn = rates.SwapInRate
		swapOut = rates.SwapOutRate
		directR = rates.DirectReclaimRate
		majFaultR = rates.MajFaultRate
	}

	memEntries := []thresholdEntry{
		makeEntry("Memory Used", memUsedPct, "%", 0, 80, 95, fmtBytes(mem.Total), "/proc/meminfo"),
		makeEntry("MemAvailable", availPct, "% free", 100, 20, 5, fmtBytes(mem.Total), "/proc/meminfo (avail<thresh=bad)"),
		makeEntry("MEM PSI full", psiMem, "%", 0, 2, 15, "100%", "/proc/pressure/memory"),
		makeEntry("Dirty Pages", dirtyPct, "% RAM", 0, 5, 20, fmtBytes(mem.Total), "/proc/meminfo Dirty"),
		makeEntry("Swap In Rate", swapIn, "MB/s", 0, 0.1, 10, "disk speed", "/proc/vmstat pswpin"),
		makeEntry("Swap Out Rate", swapOut, "MB/s", 0, 0.1, 10, "disk speed", "/proc/vmstat pswpout"),
		makeEntry("Direct Reclaim", directR, "pg/s", 0, 1, 1000, "unlimited", "/proc/vmstat pgscan_direct"),
		makeEntry("Major Faults", majFaultR, "/s", 0, 10, 500, "unlimited", "/proc/vmstat pgmajfault"),
	}
	sb.WriteString(renderThresholdSection("Memory", memEntries, iw))

	// ── Disk IO Thresholds ──
	psiIO := snap.Global.PSI.IO.Full.Avg10
	worstAwait := float64(0)
	worstUtil := float64(0)
	dCount := 0
	for _, p := range snap.Processes {
		if p.State == "D" {
			dCount++
		}
	}
	if rates != nil {
		for _, d := range rates.DiskRates {
			if d.AvgAwaitMs > worstAwait {
				worstAwait = d.AvgAwaitMs
			}
			if d.UtilPct > worstUtil {
				worstUtil = d.UtilPct
			}
		}
	}
	ioEntries := []thresholdEntry{
		makeEntry("IO PSI full", psiIO, "%", 0, 2, 15, "100%", "/proc/pressure/io"),
		makeEntry("Disk Utilization", worstUtil, "%", 0, 80, 98, "100%", "/proc/diskstats io_ticks"),
		makeEntry("Disk Await", worstAwait, "ms", 0, 20, 200, "unbounded", "/proc/diskstats (SSD<1ms, HDD~10ms)"),
		makeEntry("D-state Procs", float64(dCount), "", 0, 1, 10, "nr_procs", "/proc/pid/stat state=D"),
		makeEntry("Dirty % of RAM", dirtyPct, "%", 0, 5, 20, "vm.dirty_ratio", "/proc/meminfo"),
	}
	sb.WriteString(renderThresholdSection("Disk IO", ioEntries, iw))

	// ── Disk Space Thresholds ──
	worstFSUsed := float64(0)
	worstFSETA := float64(-1)
	worstFSInode := float64(0)
	if rates != nil {
		for _, mr := range rates.MountRates {
			if mr.UsedPct > worstFSUsed {
				worstFSUsed = mr.UsedPct
			}
			if mr.ETASeconds > 0 && (worstFSETA < 0 || mr.ETASeconds < worstFSETA) {
				worstFSETA = mr.ETASeconds
			}
			if mr.InodeUsedPct > worstFSInode {
				worstFSInode = mr.InodeUsedPct
			}
		}
	}
	etaMin := float64(-1)
	if worstFSETA > 0 {
		etaMin = worstFSETA / 60
	}
	fsEntries := []thresholdEntry{
		makeEntry("FS Used%", worstFSUsed, "%", 0, 85, 95, "100%", "statfs / worst mount"),
		makeEntry("FS ETA to full", etaMin, "min", 9999, 120, 30, "—", "EWMA growth rate (lower=worse)"),
		makeEntry("Inode Used%", worstFSInode, "%", 0, 85, 95, "100%", "statfs / worst mount"),
	}
	sb.WriteString(renderThresholdSection("Disk Space", fsEntries, iw))

	// ── Network Thresholds ──
	retransR := float64(0)
	totalDrops := float64(0)
	if rates != nil {
		retransR = rates.RetransRate
		for _, nr := range rates.NetRates {
			totalDrops += nr.RxDropsPS + nr.TxDropsPS
		}
	}
	ct := snap.Global.Conntrack
	ctPct := float64(0)
	if ct.Max > 0 {
		ctPct = float64(ct.Count) / float64(ct.Max) * 100
	}
	st := snap.Global.TCPStates
	eph := snap.Global.EphemeralPorts
	ephRange := eph.RangeHi - eph.RangeLo + 1
	ephPct := float64(0)
	if ephRange > 0 {
		ephPct = float64(eph.InUse) / float64(ephRange) * 100
	}
	fd := snap.Global.FD
	fdPct := float64(0)
	if fd.Max > 0 {
		fdPct = float64(fd.Allocated) / float64(fd.Max) * 100
	}

	// Find fastest link speed
	maxLinkMbps := 0
	worstUtilPct := float64(-1)
	for _, iface := range snap.Global.Network {
		if iface.SpeedMbps > maxLinkMbps {
			maxLinkMbps = iface.SpeedMbps
		}
	}
	if rates != nil {
		for _, nr := range rates.NetRates {
			if nr.UtilPct > worstUtilPct {
				worstUtilPct = nr.UtilPct
			}
		}
	}
	if worstUtilPct < 0 {
		worstUtilPct = 0
	}

	linkLimitStr := "unknown"
	if maxLinkMbps > 0 {
		linkLimitStr = fmt.Sprintf("%d Mbps (%d MB/s)", maxLinkMbps, maxLinkMbps/8)
	}

	netEntries := []thresholdEntry{
		makeEntry("Packet Drops", totalDrops, "/s", 0, 1, 100, "ring buffer size", "/proc/net/dev"),
		makeEntry("TCP Retransmits", retransR, "/s", 0, 5, 100, "unbounded", "/proc/net/snmp RetransSegs"),
		makeEntry("Link Utilization", worstUtilPct, "%", 0, 70, 95, linkLimitStr, "ethtool speed"),
		makeEntry("Conntrack", ctPct, "%", 0, 70, 95, fmt.Sprintf("%d max", ct.Max), "/proc/sys/net/nf_conntrack_max"),
		makeEntry("Ephemeral Ports", ephPct, "%", 0, 50, 90, fmt.Sprintf("%d–%d (%d)", eph.RangeLo, eph.RangeHi, ephRange), "/proc/sys/net/ipv4/ip_local_port_range"),
		makeEntry("File Descriptors", fdPct, "%", 0, 70, 95, fmt.Sprintf("%d max", fd.Max), "/proc/sys/fs/file-max"),
		makeEntry("TIME_WAIT", float64(st.TimeWait), "", 0, 5000, 20000, fmt.Sprintf("%d (eph range)", ephRange), "/proc/net/tcp (holds ports 60s)"),
		makeEntry("CLOSE_WAIT", float64(st.CloseWait), "", 0, 100, 1000, fmt.Sprintf("%d (fd limit)", fd.Max), "/proc/net/tcp (app must close)"),
		makeEntry("SYN_SENT", float64(st.SynSent), "", 0, 50, 500, fmt.Sprintf("%d (eph range)", ephRange), "/proc/net/tcp (connect() pending)"),
		makeEntry("TCP Orphans", float64(snap.Global.Sockets.TCPOrphan), "", 0, 200, 2000, "net.ipv4.tcp_max_orphans", "/proc/net/sockstat"),
		makeEntry("SoftIRQ CPU", softPct, "%", 0, 5, 15, "100% (per core)", "/proc/stat"),
	}
	sb.WriteString(renderThresholdSection("Network", netEntries, iw))

	// ── RCA Score Thresholds ──
	var rcaLines []string
	rcaLines = append(rcaLines, dimStyle.Render(fmt.Sprintf("%-25s %8s %10s %12s %8s", "SIGNAL", "WEIGHT", "CLAMP MAX", "FIRES WHEN", "STATUS")))
	rcaLines = append(rcaLines, "")

	rcaLines = append(rcaLines, titleStyle.Render("IO Score (4 evidence groups, need 2+):"))
	rcaLines = append(rcaLines, rcaLine("IO PSI some", 35, "50%", ">5%", psiIO > 5))
	rcaLines = append(rcaLines, rcaLine("IO PSI full", 25, "10%", ">1%", snap.Global.PSI.IO.Full.Avg10 > 1))
	rcaLines = append(rcaLines, rcaLine("D-state tasks", 15, "10", ">0", dCount > 0))
	rcaLines = append(rcaLines, rcaLine("Disk await", 15, "50ms", ">10ms", worstAwait > 10))
	rcaLines = append(rcaLines, rcaLine("Disk util", 10, "95%", ">80%", worstUtil > 80))

	rcaLines = append(rcaLines, "")
	rcaLines = append(rcaLines, titleStyle.Render("Memory Score (6 evidence groups, need 2+):"))
	rcaLines = append(rcaLines, rcaLine("MEM PSI some", 30, "50%", ">5%", snap.Global.PSI.Memory.Some.Avg10 > 5))
	rcaLines = append(rcaLines, rcaLine("MEM PSI full", 25, "10%", ">1%", psiMem > 1))
	rcaLines = append(rcaLines, rcaLine("Swap IO rate", 20, "50 MB/s", ">0.1 MB/s", swapIn+swapOut > 0.1))
	rcaLines = append(rcaLines, rcaLine("Direct reclaim ratio", 15, "60%", ">0", directR > 0))
	rcaLines = append(rcaLines, rcaLine("Major faults", 10, "500/s", ">10/s", majFaultR > 10))
	oomDelta := rates != nil && rates.OOMKillDelta > 0
	rcaLines = append(rcaLines, rcaLine("OOM kills", 0, "—", ">0/s", oomDelta))

	rcaLines = append(rcaLines, "")
	rcaLines = append(rcaLines, titleStyle.Render("CPU Score (5 evidence groups, need 2+):"))
	rcaLines = append(rcaLines, rcaLine("CPU PSI some", 35, "50%", ">5%", psiCPU > 5))
	rcaLines = append(rcaLines, rcaLine("CPU PSI full", 20, "10%", ">1%", snap.Global.PSI.CPU.Full.Avg10 > 1))
	rcaLines = append(rcaLines, rcaLine("Run queue ratio", 15, "3.0x", ">1.5x", rqRatio > 1.5))
	rcaLines = append(rcaLines, rcaLine("Ctx switch rate", 15, "150K/s", ">30K/core", ctxPerCore > 30000))
	rcaLines = append(rcaLines, rcaLine("Cgroup throttle", 15, "50%", ">5%", maxThrottle > 5))

	rcaLines = append(rcaLines, "")
	rcaLines = append(rcaLines, titleStyle.Render("Network Score (7 evidence groups, need 2+):"))
	rcaLines = append(rcaLines, rcaLine("Packet drops", 35, "100/s", ">1/s", totalDrops > 1))
	rcaLines = append(rcaLines, rcaLine("TCP retransmits", 25, "100/s", ">5/s", retransR > 5))
	rcaLines = append(rcaLines, rcaLine("Conntrack pct", 15, "100%", ">70%", ctPct > 70))
	rcaLines = append(rcaLines, rcaLine("SoftIRQ CPU", 15, "25%", ">5%", softPct > 5))
	rcaLines = append(rcaLines, rcaLine("TCP state anomaly", 10, "—", "TW>5K|CW>100", st.TimeWait > 5000 || st.CloseWait > 100))

	rcaLines = append(rcaLines, "")
	rcaLines = append(rcaLines, titleStyle.Render("Health Classification:"))
	rcaLines = append(rcaLines, fmt.Sprintf("  Score >= 60 + 2+ evidence groups = %s", critStyle.Render("CRITICAL")))
	rcaLines = append(rcaLines, fmt.Sprintf("  Score >= 25 + 2+ evidence groups = %s", warnStyle.Render("DEGRADED")))
	rcaLines = append(rcaLines, fmt.Sprintf("  Score >= 25 + <2 evidence groups = %s", orangeStyle.Render("INCONCLUSIVE")))
	rcaLines = append(rcaLines, fmt.Sprintf("  Score <  25                      = %s", okStyle.Render("OK")))

	sb.WriteString(boxSection("RCA SCORING", rcaLines, iw))

	// ── Sparkline Scaling ──
	var sparkLines []string
	sparkLines = append(sparkLines, dimStyle.Render(fmt.Sprintf("%-20s %10s %s", "METRIC", "MAX", "HOW DETERMINED")))

	type sparkInfo struct {
		name, max, source string
	}

	// Network throughput is dynamic
	netThruMax := "100 MB/s"
	netThruSource := "Default fallback"
	if maxLinkMbps > 0 {
		netThruMax = fmt.Sprintf("%d MB/s", maxLinkMbps/8)
		netThruSource = fmt.Sprintf("Dynamic — fastest link %d Mbps / 8", maxLinkMbps)
	}

	sparkInfos2 := []sparkInfo{
		{"CPU busy", "100%", "Fixed — percentage of total CPU time"},
		{"CPU iowait", "100%", "Fixed — percentage of total CPU time"},
		{"CPU steal", "100%", "Fixed — percentage of total CPU time"},
		{"CPU PSI", "50%", "Sensitivity — PSI rarely exceeds 50%, makes low values visible"},
		{"MEM used", "100%", "Fixed — percentage of total RAM"},
		{"MEM PSI", "50%", "Sensitivity — same as CPU PSI"},
		{"Swap IO", "10 MB/s", "Fixed — typical disk swap bandwidth ceiling"},
		{"Reclaim", "1000 pg/s", "Fixed — typical direct reclaim ceiling"},
		{"IO PSI", "50%", "Sensitivity — same as CPU PSI"},
		{"IO util", "100%", "Fixed — /proc/diskstats io_ticks percentage"},
		{"IO await", "100 ms", "Fixed — reasonable max for visualization (SSDs <1ms, HDDs ~10-20ms)"},
		{"IO throughput", "500 MB/s", "Fixed — reasonable max for visualization"},
		{"Net throughput", netThruMax, netThruSource},
		{"Net retransmits", "100/s", "Fixed — reasonable max for visualization"},
		{"Net drops", "100/s", "Fixed — reasonable max for visualization"},
		{"Net SoftIRQ", "100%", "Fixed — percentage of CPU time"},
	}
	for _, si := range sparkInfos2 {
		sparkLines = append(sparkLines, fmt.Sprintf("%-20s %10s %s", si.name, si.max, dimStyle.Render(si.source)))
	}
	sb.WriteString(boxSection("SPARKLINE SCALING", sparkLines, iw))

	sb.WriteString("\n")
	sb.WriteString(dimStyle.Render("  Limits marked 'Dynamic' adapt to your hardware. Fixed limits are detection thresholds."))
	sb.WriteString("\n")
	sb.WriteString(dimStyle.Render("  All system limits are read from /proc and /sys at runtime."))

	return sb.String()
}

func makeEntry(name string, cur float64, unit string, normVal, warnVal, critVal float64, limit, source string) thresholdEntry {
	status := "ok"
	// For "avail %" style metrics where lower = worse, the thresholds are inverted
	if strings.Contains(name, "Avail") {
		// Lower is worse: cur < crit → crit, cur < warn → warn
		if cur < critVal {
			status = "crit"
		} else if cur < warnVal {
			status = "warn"
		}
	} else {
		if cur >= critVal && critVal > 0 {
			status = "crit"
		} else if cur >= warnVal && warnVal > 0 {
			status = "warn"
		}
	}

	curStr := fmt.Sprintf("%.1f%s", cur, unit)
	if cur >= 10000 {
		curStr = fmt.Sprintf("%.0f%s", cur, unit)
	}

	normStr := "—"
	if normVal == 0 && !strings.Contains(name, "Avail") {
		normStr = fmt.Sprintf("<%.0f%s", warnVal, unit)
	} else if strings.Contains(name, "Avail") {
		normStr = fmt.Sprintf(">%.0f%s", warnVal, unit)
	}

	return thresholdEntry{
		Metric:   name,
		Current:  curStr,
		Normal:   normStr,
		Warn:     fmt.Sprintf("%.0f%s", warnVal, unit),
		Crit:     fmt.Sprintf("%.0f%s", critVal, unit),
		Limit:    limit,
		Source:   source,
		CurFloat: cur,
		WarnF:    warnVal,
		CritF:    critVal,
		Status:   status,
	}
}

func renderThresholdSection(title string, entries []thresholdEntry, iw int) string {
	var lines []string
	lines = append(lines, dimStyle.Render(fmt.Sprintf("%-22s %12s %10s %10s %10s  %-24s %s",
		"METRIC", "CURRENT", "NORMAL", "WARN @", "CRIT @", "SYSTEM LIMIT", "SOURCE")))

	for _, e := range entries {
		statusIcon := okStyle.Render("\u25cf") // ●
		curStyle := valueStyle
		if e.Status == "crit" {
			statusIcon = critStyle.Render("\u25cf")
			curStyle = critStyle
		} else if e.Status == "warn" {
			statusIcon = warnStyle.Render("\u25cf")
			curStyle = warnStyle
		}

		line := fmt.Sprintf("%s %-20s %s %10s %10s %10s  %-24s %s",
			statusIcon,
			e.Metric,
			styledPad(curStyle.Render(e.Current), 12),
			dimStyle.Render(e.Normal),
			warnStyle.Render(e.Warn),
			critStyle.Render(e.Crit),
			e.Limit,
			dimStyle.Render(e.Source))
		lines = append(lines, line)
	}
	return boxSection(title, lines, iw)
}

func rcaLine(signal string, weight int, clampMax, firesWhen string, fired bool) string {
	statusStr := dimStyle.Render("idle")
	if fired {
		statusStr = critStyle.Render("FIRED")
	}
	return fmt.Sprintf("  %-24s  w=%2d  clamp=%8s  fires: %-14s %s",
		signal, weight, clampMax, firesWhen, statusStr)
}
