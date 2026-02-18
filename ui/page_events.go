package ui

import (
	"fmt"
	"strings"

	"github.com/ftahirops/xtop/model"
)

func renderEventsPage(active *model.Event, completed []model.Event, selected int, width, height int) string {
	var sb strings.Builder

	total := len(completed)
	if active != nil {
		total++
	}
	sb.WriteString(titleStyle.Render(fmt.Sprintf("EVENTS  (%d events)", total)))
	sb.WriteString("\n\n")

	// Active incident banner
	if active != nil {
		sb.WriteString(critStyle.Render("  ACTIVE INCIDENT"))
		sb.WriteString("\n")
		sb.WriteString(fmt.Sprintf("  Started: %s  Bottleneck: %s  Score: %s  ",
			valueStyle.Render(active.StartTime.Format("15:04:05")),
			warnStyle.Render(active.Bottleneck),
			scoreColor(active.PeakScore).Render(fmt.Sprintf("%d", active.PeakScore)),
		))
		if active.CulpritProcess != "" {
			sb.WriteString(fmt.Sprintf("Culprit: %s(%d)",
				valueStyle.Render(active.CulpritProcess), active.CulpritPID))
		}
		sb.WriteString("\n")
		if active.CausalChain != "" {
			sb.WriteString(fmt.Sprintf("  Chain: %s", orangeStyle.Render(active.CausalChain)))
			sb.WriteString("\n")
		}
		sb.WriteString("\n")
	}

	if len(completed) == 0 {
		if active == nil {
			sb.WriteString(okStyle.Render("  No events detected yet — system is healthy"))
			sb.WriteString("\n")
			sb.WriteString(dimStyle.Render("  Events appear when health degrades (3+ consecutive non-OK ticks)"))
		}
		return sb.String()
	}

	// Table header
	hdr := fmt.Sprintf("  %-10s %-19s %8s  %-10s %-20s %5s  %s",
		"STATUS", "TIME RANGE", "DURATION", "HEALTH", "BOTTLENECK", "SCORE", "CULPRIT")
	sb.WriteString(headerStyle.Render(hdr))
	sb.WriteString("\n")
	sb.WriteString(dimStyle.Render("  " + strings.Repeat("─", width-4)))
	sb.WriteString("\n")

	for i, evt := range completed {
		timeRange := evt.StartTime.Format("15:04:05")
		if !evt.EndTime.IsZero() {
			timeRange += "-" + evt.EndTime.Format("15:04:05")
		}

		dur := fmt.Sprintf("%ds", evt.Duration)
		if evt.Duration >= 60 {
			dur = fmt.Sprintf("%dm%ds", evt.Duration/60, evt.Duration%60)
		}

		health := healthStyled(evt.PeakHealth)
		bneck := padRight(evt.Bottleneck, 20)
		score := scoreColor(evt.PeakScore).Render(fmt.Sprintf("%3d%%", evt.PeakScore))

		culprit := ""
		if evt.CulpritProcess != "" {
			culprit = fmt.Sprintf("%s(%d)", evt.CulpritProcess, evt.CulpritPID)
		}

		line := fmt.Sprintf("  %-10s %-19s %8s  %-10s %-20s %s  %s",
			okStyle.Render("RESOLVED"), timeRange, dur, health, bneck, score, culprit)

		if i == selected {
			sb.WriteString(selectedStyle.Render(line))
		} else {
			sb.WriteString(line)
		}
		sb.WriteString("\n")

		// Show expanded detail for selected event
		if i == selected {
			if len(evt.Evidence) > 0 {
				for _, e := range evt.Evidence {
					sb.WriteString(fmt.Sprintf("    %s %s\n", dimStyle.Render("->"), e))
				}
			}
			if evt.CausalChain != "" {
				sb.WriteString(fmt.Sprintf("    Chain: %s\n", orangeStyle.Render(evt.CausalChain)))
			}
			if evt.PeakCPUBusy > 0 || evt.PeakMemUsedPct > 0 || evt.PeakIOPSI > 0 {
				sb.WriteString(fmt.Sprintf("    Peaks: CPU=%.1f%%  Mem=%.1f%%  IO PSI=%.1f%%\n",
					evt.PeakCPUBusy, evt.PeakMemUsedPct, evt.PeakIOPSI))
			}
		}
	}

	sb.WriteString("\n")
	sb.WriteString(dimStyle.Render("  j/k: navigate  Events auto-detect from health transitions"))

	return sb.String()
}

func healthStyled(h model.HealthLevel) string {
	switch h {
	case model.HealthOK:
		return okStyle.Render("OK")
	case model.HealthInconclusive:
		return orangeStyle.Render("INCONC")
	case model.HealthDegraded:
		return warnStyle.Render("DEGRADED")
	case model.HealthCritical:
		return critStyle.Render("CRITICAL")
	}
	return "UNKNOWN"
}
