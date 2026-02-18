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

	// Build 4 cells
	cells := make([]string, 4)
	for i, s := range ss {
		if i >= 4 {
			break
		}
		cells[i] = renderGridCell(s, cellW)
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

	// Bottom: RCA + Owners + Capacity + Probe + Trend (all stable)
	sb.WriteString(renderRCAInline(result))
	sb.WriteString(renderOwnersInline(result))
	sb.WriteString(renderCapacityInline(result))
	sb.WriteString(renderProbeStatusLine(pm))

	// Trend
	sb.WriteString(renderTrendBlock(result, history, width, true))
	sb.WriteString("\n")

	return sb.String()
}

// renderGridCell renders one subsystem cell for the grid layout.
// Always renders the same number of lines: 1 header + bordered detail box.
func renderGridCell(s subsysInfo, cellW int) string {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf(" %s %s  %s\n",
		styledPad(titleStyle.Render(s.Name), colName),
		styledPad(s.StatusStyle.Render(s.Status), colStat),
		dimStyle.Render(fmt.Sprintf("PSI %s", s.PressureStr))))

	boxInnerW := cellW - 5
	if boxInnerW < 20 {
		boxInnerW = 20
	}
	if boxInnerW > maxBoxInner {
		boxInnerW = maxBoxInner
	}
	sb.WriteString(renderKVBox(s.Details, boxInnerW))

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
