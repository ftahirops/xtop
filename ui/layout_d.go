package ui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/ftahirops/xtop/engine"
	"github.com/ftahirops/xtop/model"
)

// renderLayoutD renders the Dashboard Grid layout.
// 2x2 grid: CPU | Memory / Disk IO | Network, then bottom bar.
func renderLayoutD(snap *model.Snapshot, rates *model.RateSnapshot, result *model.AnalysisResult,
	history *engine.History, pm probeQuerier, ss []subsysInfo, width, height int) string {

	var sb strings.Builder

	// Header
	sb.WriteString(renderHeader(snap, rates, result))
	sb.WriteString("\n")
	sb.WriteString(separator(width))
	sb.WriteString("\n")

	cellW := width/2 - 2
	if cellW < 30 {
		cellW = 30
	}

	// Build 4 cells (CPU, Memory, Disk IO, Network)
	cells := [4]string{}
	for i := 0; i < 4 && i < len(ss); i++ {
		cells[i] = renderGridCell(ss[i], cellW)
	}

	// Row 1: CPU | Memory
	row1 := joinColumns(cells[0], cells[1], cellW, dimStyle.Render("\u2502"))
	sb.WriteString(row1)
	sb.WriteString(separator(width))
	sb.WriteString("\n")

	// Row 2: Disk IO | Network
	row2 := joinColumns(cells[2], cells[3], cellW, dimStyle.Render("\u2502"))
	sb.WriteString(row2)
	sb.WriteString(separator(width))
	sb.WriteString("\n")

	// Bottom: RCA + Changes + Owners + Capacity + Probe + Trend (all stable)
	sb.WriteString(renderRCAInline(result))
	sb.WriteString(renderChangesInline(result))
	sb.WriteString(renderOwnersInline(result))
	sb.WriteString(renderCapacityInline(result))
	sb.WriteString(renderProbeStatusLine(pm, snap))

	// Trend
	sb.WriteString(renderTrendBlock(result, history, width, true))

	return sb.String()
}

// renderGridCell renders one subsystem cell for the grid layout.
// Title is embedded in the box top border: ╭──CPU  GREEN  PSI 0.0%──╮
func renderGridCell(s subsysInfo, cellW int) string {
	var sb strings.Builder

	boxInnerW := cellW - 5
	if boxInnerW < 20 {
		boxInnerW = 20
	}
	if boxInnerW > maxBoxInner {
		boxInnerW = maxBoxInner
	}

	title := fmt.Sprintf(" %s %s  %s ",
		styledPad(titleStyle.Render(s.Name), colName),
		styledPad(s.StatusStyle.Render(s.Status), colStat),
		dimStyle.Render(fmt.Sprintf("PSI %s", s.PressureStr)))

	sb.WriteString(boxTopTitle(title, boxInnerW) + "\n")
	for _, d := range s.Details {
		key := d.Key
		if len(key) > 14 {
			key = key[:14]
		}
		content := fmt.Sprintf("%s %s",
			styledPad(dimStyle.Render(key+":"), colKey),
			valueStyle.Render(d.Val))
		sb.WriteString(boxRow(content, boxInnerW) + "\n")
	}
	sb.WriteString(boxBot(boxInnerW) + "\n")

	return sb.String()
}

// joinColumns joins two text blocks side-by-side with a separator.
func joinColumns(left, right string, leftW int, sep string) string {
	leftLines := strings.Split(strings.TrimRight(left, "\n"), "\n")
	rightLines := strings.Split(strings.TrimRight(right, "\n"), "\n")

	maxLines := len(leftLines)
	if len(rightLines) > maxLines {
		maxLines = len(rightLines)
	}

	var sb strings.Builder
	for i := 0; i < maxLines; i++ {
		l := ""
		r := ""
		if i < len(leftLines) {
			l = leftLines[i]
		}
		if i < len(rightLines) {
			r = rightLines[i]
		}
		lVis := lipgloss.Width(l)
		pad := leftW - lVis
		if pad < 0 {
			pad = 0
		}
		sb.WriteString(l)
		sb.WriteString(strings.Repeat(" ", pad))
		sb.WriteString(" ")
		sb.WriteString(sep)
		sb.WriteString(" ")
		sb.WriteString(r)
		sb.WriteString("\n")
	}
	return sb.String()
}
