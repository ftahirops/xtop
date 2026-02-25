package ui

import (
	"fmt"
	"strings"

	"github.com/ftahirops/xtop/engine"
	"github.com/ftahirops/xtop/model"
)

// renderLayoutC renders the Adaptive Expand layout.
// All subsystems always show full detail box for layout stability.
func renderLayoutC(snap *model.Snapshot, rates *model.RateSnapshot, result *model.AnalysisResult,
	history *engine.History, pm probeQuerier, ss []subsysInfo, width, height int) string {

	var sb strings.Builder

	// Header
	sb.WriteString(renderHeader(snap, rates, result))
	sb.WriteString("\n")
	sb.WriteString(separator(width))
	sb.WriteString("\n")

	boxInnerW := width - 7
	if boxInnerW < 40 {
		boxInnerW = 40
	}
	if boxInnerW > maxBoxInner {
		boxInnerW = maxBoxInner
	}

	// Render each subsystem with title in box border
	for _, s := range ss {
		title := fmt.Sprintf(" %s %s  %s ",
			styledPad(valueStyle.Render(s.Name), colName),
			styledPad(s.StatusStyle.Render(s.Status), colStat),
			dimStyle.Render(fmt.Sprintf("PSI %s", s.PressureStr)))

		sb.WriteString(boxTopTitle(title, boxInnerW) + "\n")
		for _, d := range s.Details {
			key := d.Key
			if len(key) > 14 {
				key = key[:14]
			}
			vs := valueStyle
			if s.Status == "RED" && d.Val != "none" && d.Val != "\u2014" && d.Val != "normal" {
				vs = critStyle
			} else if s.Status == "YELLOW" && d.Val != "none" && d.Val != "\u2014" && d.Val != "normal" {
				vs = warnStyle
			}
			content := fmt.Sprintf("%s %s",
				styledPad(dimStyle.Render(key+":"), colKey),
				vs.Render(d.Val))
			sb.WriteString(boxRow(content, boxInnerW) + "\n")
		}
		sb.WriteString(boxBot(boxInnerW) + "\n")
	}

	// RCA (always render with fixed format)
	sb.WriteString(renderRCAInline(result))
	// What Changed
	sb.WriteString(renderChangesInline(result))
	// Owners (top-3 per resource)
	sb.WriteString(renderOwnersInline(result))
	// Capacity (always render inline)
	sb.WriteString(renderCapacityInline(result))
	// Probe status
	sb.WriteString(renderProbeStatusLine(pm, snap))
	// Exhaustion + Degradation
	sb.WriteString(renderExhaustionBlock(result, width))
	sb.WriteString(renderDegradationBlock(result, width))
	// Trend (full 16 metrics)
	sb.WriteString(renderTrendBlock(result, history, width, true))

	return sb.String()
}
