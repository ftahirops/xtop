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
	sb.WriteString("\n\n")

	boxInnerW := width - 7
	if boxInnerW < 40 {
		boxInnerW = 40
	}
	if boxInnerW > maxBoxInner {
		boxInnerW = maxBoxInner
	}

	// Render each subsystem with consistent detail box
	for _, s := range ss {
		sb.WriteString(fmt.Sprintf(" %s %s  %s\n",
			styledPad(valueStyle.Render(s.Name), colName),
			styledPad(s.StatusStyle.Render(s.Status), colStat),
			dimStyle.Render(fmt.Sprintf("PSI %s", s.PressureStr))))

		sb.WriteString(renderKVBoxStyled(s.Details, boxInnerW, s.Status))
	}

	sb.WriteString("\n")

	// RCA (always render with fixed format)
	sb.WriteString(renderRCAInline(result))
	sb.WriteString("\n")

	// What Changed
	sb.WriteString(renderChangesInline(result))
	sb.WriteString("\n")

	// Owners (top-3 per resource)
	sb.WriteString(renderOwnersInline(result))
	sb.WriteString("\n")

	// Capacity (always render inline)
	sb.WriteString(renderCapacityInline(result))
	sb.WriteString("\n")

	// Probe status
	sb.WriteString(renderProbeStatusLine(pm))
	sb.WriteString("\n")

	// Exhaustion + Degradation
	sb.WriteString(renderExhaustionBlock(result))
	sb.WriteString(renderDegradationBlock(result))

	// Trend (full 16 metrics)
	sb.WriteString(renderTrendBlock(result, history, width, true))
	sb.WriteString("\n")

	return sb.String()
}
