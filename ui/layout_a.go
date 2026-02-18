package ui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/ftahirops/xtop/engine"
	"github.com/ftahirops/xtop/model"
)

// renderLayoutA renders the Two-Column Split layout.
// Left: Subsystem health with details
// Right: Owners + Chain + Capacity + Trend
func renderLayoutA(snap *model.Snapshot, rates *model.RateSnapshot, result *model.AnalysisResult,
	history *engine.History, pm probeQuerier, ss []subsysInfo, width, height int) string {

	var sb strings.Builder

	// Header
	sb.WriteString(renderHeader(snap, rates, result))
	sb.WriteString("\n")
	sb.WriteString(separator(width))
	sb.WriteString("\n\n")

	leftW := width/2 - 2
	if leftW < 30 {
		leftW = 30
	}
	rightW := width - leftW - 3 // 3 for separator column
	if rightW < 20 {
		rightW = 20
	}

	// Build left column: Subsystem Health
	var left strings.Builder
	left.WriteString(titleStyle.Render(" Subsystem Health"))
	left.WriteString("\n")

	boxInnerW := leftW - 5
	if boxInnerW < 30 {
		boxInnerW = 30
	}
	if boxInnerW > maxBoxInner {
		boxInnerW = maxBoxInner
	}

	for _, s := range ss {
		left.WriteString(fmt.Sprintf(" %s %s  %s\n",
			styledPad(valueStyle.Render(s.Name), colName),
			styledPad(s.StatusStyle.Render(s.Status), colStat),
			dimStyle.Render(fmt.Sprintf("PSI %s", s.PressureStr))))

		left.WriteString(renderKVBox(s.Details, boxInnerW))
	}

	// Build right column: RCA + Owners + Capacity + Probe + Exhaustion + Trend
	var right strings.Builder
	right.WriteString(renderRCABox(result))
	right.WriteString("\n")
	right.WriteString(renderOwnersBlock(result))
	right.WriteString("\n")
	right.WriteString(renderCapacityBlock(result, true, 16))
	right.WriteString("\n")
	right.WriteString(renderProbeStatusLine(pm))
	right.WriteString("\n")
	right.WriteString(renderExhaustionBlock(result))
	right.WriteString("\n")
	right.WriteString(renderTrendBlock(result, history, rightW, true))

	// Join columns with vertical separator
	leftLines := strings.Split(left.String(), "\n")
	rightLines := strings.Split(right.String(), "\n")

	maxLines := len(leftLines)
	if len(rightLines) > maxLines {
		maxLines = len(rightLines)
	}

	sep := dimStyle.Render("\u2502")

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
