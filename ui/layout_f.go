package ui

import (
	"fmt"
	"strings"

	"github.com/ftahirops/xtop/engine"
	"github.com/ftahirops/xtop/model"
)

// renderLayoutF renders the btop-style layout.
// Top: 2x2 grid (CPU | Memory / Disk IO | Network)
// Middle: RCA + Probe inline
// Bottom: process table filling remaining height
func renderLayoutF(snap *model.Snapshot, rates *model.RateSnapshot, result *model.AnalysisResult,
	history *engine.History, pm probeQuerier, ss []subsysInfo, width, height int) string {

	var sb strings.Builder

	// Header
	sb.WriteString(renderHeader(snap, rates, result))
	sb.WriteString("\n")
	sb.WriteString(separator(width))
	sb.WriteString("\n")

	usedLines := 4 // header(2) + separator + separator after grid

	cellW := width/2 - 2
	if cellW < 30 {
		cellW = 30
	}

	// ─── Top-left cell: CPU ─────────────────────────────────────────────
	cpuCell := renderBtopCPUCell(snap, rates, history, cellW)

	// ─── Top-right cell: Memory ─────────────────────────────────────────
	memCell := renderBtopMemCell(snap, cellW)

	// Row 1: CPU | Memory
	row1 := joinColumns(cpuCell, memCell, cellW, dimStyle.Render("│"))
	sb.WriteString(row1)
	usedLines += strings.Count(row1, "\n")

	sb.WriteString(separator(width))
	sb.WriteString("\n")
	usedLines++

	// ─── Bottom-left cell: Disk IO ──────────────────────────────────────
	ioCell := renderBtopIOCell(rates, cellW)

	// ─── Bottom-right cell: Network ─────────────────────────────────────
	netCell := renderBtopNetCell(snap, rates, cellW)

	// Row 2: Disk IO | Network
	row2 := joinColumns(ioCell, netCell, cellW, dimStyle.Render("│"))
	sb.WriteString(row2)
	usedLines += strings.Count(row2, "\n")

	sb.WriteString(separator(width))
	sb.WriteString("\n")
	usedLines++

	// ─── RCA + Probe inline ─────────────────────────────────────────────
	sb.WriteString(renderRCAInline(result))
	sb.WriteString(renderProbeStatusLine(pm))
	usedLines += 2

	sb.WriteString(separator(width))
	sb.WriteString("\n")
	usedLines++

	// ─── Process table fills remaining height ───────────────────────────
	maxRows := height - usedLines - 2
	if maxRows < 3 {
		maxRows = 3
	}
	sb.WriteString(renderProcessTable(rates, width, maxRows))

	return sb.String()
}

// renderBtopCPUCell renders the CPU cell for btop layout.
// Shows: sparkline history + aggregate busy% + compact per-core bars (3 per row).
func renderBtopCPUCell(snap *model.Snapshot, rates *model.RateSnapshot,
	history *engine.History, cellW int) string {

	var sb strings.Builder

	boxInnerW := cellW - 5
	if boxInnerW < 20 {
		boxInnerW = 20
	}

	cpuPct := float64(0)
	if rates != nil {
		cpuPct = rates.CPUBusyPct
	}

	title := fmt.Sprintf(" %s %s ",
		titleStyle.Render("CPU"),
		meterColor(cpuPct).Render(fmt.Sprintf("%.1f%%", cpuPct)))
	sb.WriteString(boxTopTitle(title, boxInnerW) + "\n")

	// Sparkline from history
	n := history.Len()
	chartW := boxInnerW - 4
	if chartW < 10 {
		chartW = 10
	}
	if n >= 3 {
		cpuData := make([]float64, n)
		for i := 0; i < n; i++ {
			r := history.GetRate(i)
			if r != nil {
				cpuData[i] = r.CPUBusyPct
			}
		}
		sb.WriteString(boxRow(sparkline(cpuData, chartW, 0, 100), boxInnerW) + "\n")
	} else {
		sb.WriteString(boxRow(dimStyle.Render("collecting..."), boxInnerW) + "\n")
	}

	// Per-core compact bars (3 per row)
	var corePcts []float64
	if n >= 2 {
		prev := history.Get(n - 2)
		curr := history.Get(n - 1)
		corePcts = perCoreBusy(prev, curr)
	}

	if len(corePcts) > 0 {
		perCoreBarW := (boxInnerW - 6) / 3
		coreBarW := perCoreBarW - 8
		if coreBarW < 4 {
			coreBarW = 4
		}

		for i := 0; i < len(corePcts); i += 3 {
			var parts []string
			for j := 0; j < 3 && i+j < len(corePcts); j++ {
				idx := i + j
				pct := corePcts[idx]
				parts = append(parts, fmt.Sprintf("%s %s",
					dimStyle.Render(fmt.Sprintf("%d", idx+1)),
					bar(pct, coreBarW)))
			}
			sb.WriteString(boxRow(strings.Join(parts, " "), boxInnerW) + "\n")
		}
	}

	sb.WriteString(boxBot(boxInnerW) + "\n")
	return sb.String()
}

// renderBtopMemCell renders the Memory cell for btop layout.
func renderBtopMemCell(snap *model.Snapshot, cellW int) string {
	var sb strings.Builder

	boxInnerW := cellW - 5
	if boxInnerW < 20 {
		boxInnerW = 20
	}

	memTotal := snap.Global.Memory.Total
	memUsed := uint64(0)
	memPct := float64(0)
	if memTotal > 0 {
		memUsed = memTotal - snap.Global.Memory.Available
		memPct = float64(memUsed) / float64(memTotal) * 100
	}

	title := fmt.Sprintf(" %s %s ",
		titleStyle.Render("Memory"),
		meterColor(memPct).Render(fmt.Sprintf("%.1f%%", memPct)))
	sb.WriteString(boxTopTitle(title, boxInnerW) + "\n")

	memBarW := boxInnerW - 22
	if memBarW < 10 {
		memBarW = 10
	}

	// Used memory
	usedLine := fmt.Sprintf("%s %s %s  %s/%s",
		styledPad(dimStyle.Render("Used"), 5),
		bar(memPct, memBarW),
		meterColor(memPct).Render(fmt.Sprintf("%5.1f%%", memPct)),
		fmtBytes(memUsed), fmtBytes(memTotal))
	sb.WriteString(boxRow(usedLine, boxInnerW) + "\n")

	// Swap
	swapTotal := snap.Global.Memory.SwapTotal
	swapUsed := snap.Global.Memory.SwapUsed
	swapPct := float64(0)
	if swapTotal > 0 {
		swapPct = float64(swapUsed) / float64(swapTotal) * 100
	}
	swapLine := fmt.Sprintf("%s %s %s  %s/%s",
		styledPad(dimStyle.Render("Swap"), 5),
		bar(swapPct, memBarW),
		meterColor(swapPct).Render(fmt.Sprintf("%5.1f%%", swapPct)),
		fmtBytes(swapUsed), fmtBytes(swapTotal))
	sb.WriteString(boxRow(swapLine, boxInnerW) + "\n")

	// Cache + Dirty
	cacheLine := fmt.Sprintf("%s %s  %s %s",
		dimStyle.Render("Cache"),
		valueStyle.Render(fmtBytes(snap.Global.Memory.Cached)),
		dimStyle.Render("Dirty"),
		valueStyle.Render(fmtBytes(snap.Global.Memory.Dirty)))
	sb.WriteString(boxRow(cacheLine, boxInnerW) + "\n")

	sb.WriteString(boxBot(boxInnerW) + "\n")
	return sb.String()
}

// renderBtopIOCell renders the Disk IO cell for btop layout.
func renderBtopIOCell(rates *model.RateSnapshot, cellW int) string {
	var sb strings.Builder

	boxInnerW := cellW - 5
	if boxInnerW < 20 {
		boxInnerW = 20
	}

	// Find worst disk
	var worstUtil float64
	var worstAwait float64
	var worstQ uint64
	var worstName string
	var totalRead, totalWrite float64

	if rates != nil {
		for _, d := range rates.DiskRates {
			totalRead += d.ReadMBs
			totalWrite += d.WriteMBs
			if d.UtilPct > worstUtil {
				worstUtil = d.UtilPct
				worstAwait = d.AvgAwaitMs
				worstQ = d.QueueDepth
				worstName = d.Name
			}
		}
	}

	diskLabel := "Disk IO"
	if worstName != "" {
		diskLabel = fmt.Sprintf("Disk IO (%s)", worstName)
	}
	title := fmt.Sprintf(" %s %s ",
		titleStyle.Render(diskLabel),
		meterColor(worstUtil).Render(fmt.Sprintf("%.1f%%", worstUtil)))
	sb.WriteString(boxTopTitle(title, boxInnerW) + "\n")

	ioBarW := boxInnerW - 18
	if ioBarW < 10 {
		ioBarW = 10
	}

	// Utilization bar
	utilLine := fmt.Sprintf("%s %s %s",
		styledPad(dimStyle.Render("Util"), 6),
		bar(worstUtil, ioBarW),
		meterColor(worstUtil).Render(fmt.Sprintf("%5.1f%%", worstUtil)))
	sb.WriteString(boxRow(utilLine, boxInnerW) + "\n")

	// Await + Queue
	aqLine := fmt.Sprintf("%s %s  %s %s",
		dimStyle.Render("Await"),
		valueStyle.Render(fmt.Sprintf("%.1fms", worstAwait)),
		dimStyle.Render("Queue"),
		valueStyle.Render(fmt.Sprintf("%d", worstQ)))
	sb.WriteString(boxRow(aqLine, boxInnerW) + "\n")

	// Read/Write throughput
	rwLine := fmt.Sprintf("%s %s  %s %s",
		dimStyle.Render("R:"),
		valueStyle.Render(fmt.Sprintf("%.1f MB/s", totalRead)),
		dimStyle.Render("W:"),
		valueStyle.Render(fmt.Sprintf("%.1f MB/s", totalWrite)))
	sb.WriteString(boxRow(rwLine, boxInnerW) + "\n")

	sb.WriteString(boxBot(boxInnerW) + "\n")
	return sb.String()
}

// renderBtopNetCell renders the Network cell for btop layout.
func renderBtopNetCell(snap *model.Snapshot, rates *model.RateSnapshot, cellW int) string {
	var sb strings.Builder

	boxInnerW := cellW - 5
	if boxInnerW < 20 {
		boxInnerW = 20
	}

	var totalRx, totalTx float64
	var totalDrops float64
	if rates != nil {
		for _, nr := range rates.NetRates {
			totalRx += nr.RxMBs
			totalTx += nr.TxMBs
			totalDrops += nr.RxDropsPS + nr.TxDropsPS
		}
	}

	title := fmt.Sprintf(" %s ", titleStyle.Render("Network"))
	sb.WriteString(boxTopTitle(title, boxInnerW) + "\n")

	// RX/TX
	rxTxLine := fmt.Sprintf("%s %s  %s %s",
		dimStyle.Render("RX"),
		valueStyle.Render(fmtRate(totalRx)),
		dimStyle.Render("TX"),
		valueStyle.Render(fmtRate(totalTx)))
	sb.WriteString(boxRow(rxTxLine, boxInnerW) + "\n")

	// Drops + Retrans
	retransRate := float64(0)
	if rates != nil {
		retransRate = rates.RetransRate
	}
	dropsStyle := dimStyle
	if totalDrops > 0 {
		dropsStyle = warnStyle
	}
	retransStyle := dimStyle
	if retransRate > 10 {
		retransStyle = warnStyle
	}
	drLine := fmt.Sprintf("%s %s  %s %s",
		dimStyle.Render("Drops"),
		dropsStyle.Render(fmt.Sprintf("%.0f/s", totalDrops)),
		dimStyle.Render("Retrans"),
		retransStyle.Render(fmt.Sprintf("%.0f/s", retransRate)))
	sb.WriteString(boxRow(drLine, boxInnerW) + "\n")

	// Conntrack + Ephemeral
	ct := snap.Global.Conntrack
	ctStr := dimStyle.Render(fmt.Sprintf("%d", ct.Count))

	eph := snap.Global.EphemeralPorts
	ephStr := dimStyle.Render("OK")
	if eph.RangeHi > 0 {
		ephRange := eph.RangeHi - eph.RangeLo + 1
		ephPct := float64(eph.InUse) / float64(ephRange) * 100
		ephStyle := dimStyle
		if ephPct > 80 {
			ephStyle = critStyle
		} else if ephPct > 50 {
			ephStyle = warnStyle
		}
		ephStr = ephStyle.Render(fmt.Sprintf("%.0f%%", ephPct))
	}
	ceLine := fmt.Sprintf("%s %s  %s %s",
		dimStyle.Render("Conntrack"),
		ctStr,
		dimStyle.Render("Ephemeral"),
		ephStr)
	sb.WriteString(boxRow(ceLine, boxInnerW) + "\n")

	sb.WriteString(boxBot(boxInnerW) + "\n")
	return sb.String()
}
