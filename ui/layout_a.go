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
	sb.WriteString("\n")

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
		title := fmt.Sprintf(" %s %s  %s ",
			styledPad(valueStyle.Render(s.Name), colName),
			styledPad(s.StatusStyle.Render(s.Status), colStat),
			dimStyle.Render(fmt.Sprintf("PSI %s", s.PressureStr)))

		left.WriteString(boxTopTitle(title, boxInnerW) + "\n")
		for _, d := range s.Details {
			key := d.Key
			if len(key) > 14 {
				key = key[:14]
			}
			content := fmt.Sprintf("%s %s",
				styledPad(dimStyle.Render(key+":"), colKey),
				valueStyle.Render(d.Val))
			left.WriteString(boxRow(content, boxInnerW) + "\n")
		}
		left.WriteString(boxBot(boxInnerW) + "\n")
	}

	// Build right column: RCA + Changes + Actions + Owners + Capacity + Probe + Exhaustion + Degradation + Trend
	var right strings.Builder
	right.WriteString(renderRCABox(result, rightW))
	right.WriteString(renderChangesBlock(result, rightW))
	right.WriteString(renderActionsBlock(result, rightW))
	right.WriteString(renderOwnersBlock(result, rightW))
	right.WriteString(renderCapacityBlock(result, true, 16, rightW))
	right.WriteString(renderProbeStatusLine(pm, snap))
	right.WriteString(renderExhaustionBlock(result, rightW))
	right.WriteString(renderDegradationBlock(result, rightW))
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
