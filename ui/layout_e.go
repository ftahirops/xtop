package ui

import (
	"fmt"
	"strings"

	"github.com/ftahirops/xtop/engine"
	"github.com/ftahirops/xtop/model"
)

// renderLayoutE renders the htop-style layout.
// Top: per-CPU core bars (left) + Mem/Swap/Load info (right)
// Middle: RCA + Probe status
// Bottom: process table filling remaining height
func renderLayoutE(snap *model.Snapshot, rates *model.RateSnapshot, result *model.AnalysisResult,
	history *engine.History, pm probeQuerier, _ []subsysInfo, width, height int) string {

	var sb strings.Builder

	// Header
	sb.WriteString(renderHeader(snap, rates, result))
	sb.WriteString("\n")
	sb.WriteString(separator(width))
	sb.WriteString("\n")

	usedLines := 4 // header(2) + separator + separator after CPU section

	// ─── Per-core CPU bars (left) + Memory/Swap/Load (right) ────────────

	// Compute per-core busy %
	var corePcts []float64
	n := history.Len()
	if n >= 2 {
		prev := history.Get(n - 2)
		curr := history.Get(n - 1)
		corePcts = perCoreBusy(prev, curr)
	}

	leftW := width/2 - 1
	if leftW < 30 {
		leftW = 30
	}

	// Build left column: CPU bars
	var leftSB strings.Builder
	barW := leftW - 16 // "CPU XX [bar] XXX.X%"
	if barW < 10 {
		barW = 10
	}

	if len(corePcts) == 0 {
		// Fallback: show aggregate
		cpuPct := float64(0)
		if rates != nil {
			cpuPct = rates.CPUBusyPct
		}
		leftSB.WriteString(fmt.Sprintf(" %s %s %s\n",
			styledPad(dimStyle.Render("CPU"), 6),
			bar(cpuPct, barW),
			meterColor(cpuPct).Render(fmt.Sprintf("%5.1f%%", cpuPct))))
	} else {
		for i, pct := range corePcts {
			label := fmt.Sprintf("CPU %d", i+1)
			if i+1 >= 10 {
				label = fmt.Sprintf("CPU%d", i+1)
			}
			leftSB.WriteString(fmt.Sprintf(" %s %s %s\n",
				styledPad(dimStyle.Render(label), 6),
				bar(pct, barW),
				meterColor(pct).Render(fmt.Sprintf("%5.1f%%", pct))))
		}
	}
	leftStr := leftSB.String()

	// Build right column: Memory + Swap + Load + Tasks
	var rightSB strings.Builder
	rightBarW := width - leftW - 22
	if rightBarW < 10 {
		rightBarW = 10
	}

	// Memory bar
	memTotal := snap.Global.Memory.Total
	memUsed := uint64(0)
	memPct := float64(0)
	if memTotal > 0 {
		memUsed = memTotal - snap.Global.Memory.Available
		memPct = float64(memUsed) / float64(memTotal) * 100
	}
	rightSB.WriteString(fmt.Sprintf(" %s %s %s  %s/%s\n",
		styledPad(dimStyle.Render("Mem"), 5),
		bar(memPct, rightBarW),
		meterColor(memPct).Render(fmt.Sprintf("%5.1f%%", memPct)),
		fmtBytes(memUsed), fmtBytes(memTotal)))

	// Swap bar
	swapTotal := snap.Global.Memory.SwapTotal
	swapUsed := snap.Global.Memory.SwapUsed
	swapPct := float64(0)
	if swapTotal > 0 {
		swapPct = float64(swapUsed) / float64(swapTotal) * 100
	}
	rightSB.WriteString(fmt.Sprintf(" %s %s %s  %s/%s\n",
		styledPad(dimStyle.Render("Swp"), 5),
		bar(swapPct, rightBarW),
		meterColor(swapPct).Render(fmt.Sprintf("%5.1f%%", swapPct)),
		fmtBytes(swapUsed), fmtBytes(swapTotal)))

	// Blank line
	rightSB.WriteString("\n")

	// Load averages
	la := snap.Global.CPU.LoadAvg
	rightSB.WriteString(fmt.Sprintf(" %s %s\n",
		dimStyle.Render("Load:"),
		valueStyle.Render(fmt.Sprintf("%.2f %.2f %.2f", la.Load1, la.Load5, la.Load15))))

	// Tasks
	rightSB.WriteString(fmt.Sprintf(" %s %s\n",
		dimStyle.Render("Tasks:"),
		valueStyle.Render(fmt.Sprintf("%d run, %d total", la.Running, la.Total))))

	// Cache info
	rightSB.WriteString(fmt.Sprintf(" %s %s  %s %s\n",
		dimStyle.Render("Cache:"),
		valueStyle.Render(fmtBytes(snap.Global.Memory.Cached)),
		dimStyle.Render("Dirty:"),
		valueStyle.Render(fmtBytes(snap.Global.Memory.Dirty))))

	rightStr := rightSB.String()

	// Join columns
	cpuSection := joinColumns(leftStr, rightStr, leftW, dimStyle.Render("│"))
	sb.WriteString(cpuSection)
	cpuLines := strings.Count(cpuSection, "\n")
	usedLines += cpuLines

	sb.WriteString(separator(width))
	sb.WriteString("\n")
	usedLines++

	// ─── RCA + Probe inline ─────────────────────────────────────────────
	sb.WriteString(renderRCAInline(result))
	sb.WriteString(renderProbeStatusLine(pm, snap))
	usedLines += 2

	sb.WriteString(separator(width))
	sb.WriteString("\n")
	usedLines++

	// ─── Process table fills remaining height ───────────────────────────
	maxRows := height - usedLines - 2 // leave margin
	if maxRows < 3 {
		maxRows = 3
	}
	sb.WriteString(renderProcessTable(rates, width, maxRows))

	return sb.String()
}
