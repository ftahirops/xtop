package ui

import (
	"fmt"
	"strings"

	"github.com/ftahirops/xtop/model"
)

func renderDiagPage(snap *model.Snapshot, rates *model.RateSnapshot, result *model.AnalysisResult, pm probeQuerier, width, height int) string {
	var sb strings.Builder
	iw := pageInnerW(width)

	sb.WriteString(titleStyle.Render("SERVICE DIAGNOSTICS"))
	sb.WriteString("\n")
	sb.WriteString(renderRCAInline(result))
	sb.WriteString(renderProbeStatusLine(pm, snap))
	sb.WriteString("\n")

	diag := snap.Global.Diagnostics
	if len(diag.Services) == 0 {
		sb.WriteString(boxTop(iw) + "\n")
		sb.WriteString(boxRow(dimStyle.Render("No services detected — waiting for first scan (30s interval)..."), iw) + "\n")
		sb.WriteString(boxBot(iw) + "\n")
		return sb.String()
	}

	// ── Service Overview Box ──
	sb.WriteString(boxTopTitle(headerStyle.Render(" SERVICE OVERVIEW "), iw) + "\n")
	for _, svc := range diag.Services {
		badge := diagSevBadge(svc.WorstSev)
		name := styledPad(valueStyle.Render(svc.Name), 14)
		metrics := diagMetricsSummary(svc)
		sb.WriteString(boxRow(name+badge+"  "+dimStyle.Render(metrics), iw) + "\n")
	}
	sb.WriteString(boxBot(iw) + "\n")
	sb.WriteString("\n")

	// ── Per-Service Detail Boxes ──
	for _, svc := range diag.Services {
		badge := diagSevBadge(svc.WorstSev)
		title := headerStyle.Render(fmt.Sprintf(" %s ", svc.Name))
		separator := dimStyle.Render(strings.Repeat("─", 3))
		sb.WriteString(boxTopTitle(title+separator+badge+dimStyle.Render(" "), iw) + "\n")

		if len(svc.Findings) == 0 {
			sb.WriteString(boxRow(dimStyle.Render("No findings"), iw) + "\n")
		} else {
			for _, f := range svc.Findings {
				icon := diagSevIcon(f.Severity)
				summary := f.Summary
				line := icon + " " + summary
				if f.Advice != "" {
					line += dimStyle.Render(" → "+f.Advice)
				}
				sb.WriteString(boxRow(line, iw) + "\n")
			}
		}

		sb.WriteString(boxBot(iw) + "\n")
		sb.WriteString("\n")
	}

	return sb.String()
}

// diagSevBadge returns a styled severity badge.
func diagSevBadge(sev model.DiagSeverity) string {
	switch sev {
	case model.DiagCrit:
		return critStyle.Render("CRIT")
	case model.DiagWarn:
		return warnStyle.Render("WARN")
	case model.DiagInfo:
		return orangeStyle.Render("INFO")
	default:
		return okStyle.Render(" OK ")
	}
}

// diagSevIcon returns an icon for the severity level.
func diagSevIcon(sev model.DiagSeverity) string {
	switch sev {
	case model.DiagCrit:
		return critStyle.Render("!!")
	case model.DiagWarn:
		return warnStyle.Render("!!")
	case model.DiagInfo:
		return orangeStyle.Render(" i")
	default:
		return okStyle.Render(" +")
	}
}

// diagMetricsSummary builds a compact metrics line for the overview table.
func diagMetricsSummary(svc model.ServiceDiag) string {
	m := svc.Metrics
	var parts []string

	switch svc.Name {
	case "nginx":
		if v, ok := m["workers"]; ok {
			parts = append(parts, "workers="+v)
		}
		if v, ok := m["active"]; ok {
			parts = append(parts, "conns="+v)
		}
		if v, ok := m["5xx"]; ok {
			parts = append(parts, "5xx="+v)
		}
	case "apache":
		if v, ok := m["mpm"]; ok {
			parts = append(parts, "mpm="+v)
		}
		if v, ok := m["max_workers"]; ok {
			parts = append(parts, "workers="+v)
		}
	case "mysql":
		if v, ok := m["conns"]; ok {
			parts = append(parts, "conns="+v)
		}
		if v, ok := m["slow"]; ok {
			parts = append(parts, "slow="+v)
		}
		if v, ok := m["hit"]; ok {
			parts = append(parts, "hit="+v)
		}
	case "postgresql":
		if v, ok := m["conn_pct"]; ok {
			parts = append(parts, "conns="+v)
		}
		if v, ok := m["hit"]; ok {
			parts = append(parts, "hit="+v)
		}
		if v, ok := m["active"]; ok {
			parts = append(parts, "active="+v)
		}
	case "haproxy":
		if v, ok := m["conns"]; ok {
			parts = append(parts, "conns="+v)
		}
		if v, ok := m["5xx"]; ok {
			parts = append(parts, "5xx="+v)
		}
		if v, ok := m["queue"]; ok {
			parts = append(parts, "queue="+v)
		}
	case "redis":
		if v, ok := m["mem"]; ok {
			parts = append(parts, "mem="+v)
		}
		if v, ok := m["frag"]; ok {
			parts = append(parts, "frag="+v)
		}
		if v, ok := m["blocked"]; ok {
			parts = append(parts, "blocked="+v)
		}
	case "docker":
		if v, ok := m["running"]; ok {
			parts = append(parts, v+" running")
		}
		if v, ok := m["unhealthy"]; ok {
			parts = append(parts, v+" unhealthy")
		}
	}

	return strings.Join(parts, "  ")
}
