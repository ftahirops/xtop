package ui

import (
	"fmt"
	"strings"

	"github.com/ftahirops/xtop/engine"
	"github.com/ftahirops/xtop/model"
)

// renderLayoutB renders the Compact Table layout.
// Everything in a single dense table + detail for worst subsystem + trend.
func renderLayoutB(snap *model.Snapshot, rates *model.RateSnapshot, result *model.AnalysisResult,
	history *engine.History, pm probeQuerier, ss []subsysInfo, width, height int) string {

	var sb strings.Builder

	// Header
	sb.WriteString(renderHeader(snap, rates, result))
	sb.WriteString("\n")
	sb.WriteString(separator(width))
	sb.WriteString("\n\n")

	tableInnerW := width - 7
	if tableInnerW < 60 {
		tableInnerW = 60
	}
	if tableInnerW > 105 {
		tableInnerW = 105
	}

	// System Health Summary table
	sb.WriteString(titleStyle.Render(" System Health Summary"))
	sb.WriteString("\n")

	// Table header inside box
	hdr := fmt.Sprintf("%-12s %-8s %10s %15s   %-20s  %s",
		"Subsystem", "Status", "Pressure", "Capacity Left", "Key Metric", "Top Owner")
	sb.WriteString(boxTop(tableInnerW) + "\n")
	sb.WriteString(boxRow(dimStyle.Render(hdr), tableInnerW) + "\n")
	sb.WriteString(boxMid(tableInnerW) + "\n")

	// Find worst subsystem (highest pressure)
	worstIdx := 0
	worstPressure := float64(-1)

	for i, s := range ss {
		statusStr := styledPad(s.StatusStyle.Render(s.Status), colStat)

		pStyle := dimStyle
		if s.PressurePct >= 5 {
			pStyle = psiColor(s.PressurePct)
		}
		pressureStr := styledPad(pStyle.Render(s.PressureStr), 10)

		capStyle := dimStyle
		if s.CapacityPct < 15 {
			capStyle = critStyle
		} else if s.CapacityPct < 30 {
			capStyle = warnStyle
		}
		capStr := styledPad(capStyle.Render(s.CapacityStr), 15)

		// Key metric: first detail value (always present now)
		keyMetric := "\u2014"
		if len(s.Details) > 0 {
			keyMetric = s.Details[0].Val
		}
		if len(keyMetric) > 20 {
			keyMetric = keyMetric[:17] + "..."
		}

		owner := dimStyle.Render("\u2014")
		if s.TopOwner != "" {
			owner = valueStyle.Render(s.TopOwner)
		}

		row := fmt.Sprintf("%s %s %s %s   %-20s  %s",
			styledPad(valueStyle.Render(s.Name), 12),
			statusStr, pressureStr, capStr,
			keyMetric, owner)
		sb.WriteString(boxRow(row, tableInnerW) + "\n")

		if s.PressurePct > worstPressure {
			worstPressure = s.PressurePct
			worstIdx = i
		}
	}
	sb.WriteString(boxBot(tableInnerW) + "\n")

	sb.WriteString("\n")

	// Detail for highest-pressure subsystem
	worst := ss[worstIdx]
	sb.WriteString(titleStyle.Render(fmt.Sprintf(" Detail: %s", worst.Name)))
	sb.WriteString("\n")

	detailInnerW := width - 7
	if detailInnerW < 40 {
		detailInnerW = 40
	}
	if detailInnerW > maxBoxInner {
		detailInnerW = maxBoxInner
	}
	sb.WriteString(renderKVBox(worst.Details, detailInnerW))

	// RCA + Owners + Probe
	sb.WriteString(renderRCAInline(result))
	sb.WriteString(renderOwnersInline(result))
	sb.WriteString(renderProbeStatusLine(pm))

	sb.WriteString("\n")

	// Trend (one line per resource)
	sb.WriteString(renderTrendBlock(result, history, width, true))
	sb.WriteString("\n")

	return sb.String()
}
