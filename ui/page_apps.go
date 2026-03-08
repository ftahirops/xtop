//go:build linux

package ui

import (
	"fmt"
	"sort"
	"strings"

	"github.com/ftahirops/xtop/model"
)

func renderAppsPage(snap *model.Snapshot, selectedIdx int, detailMode bool, width, height int) string {
	var sb strings.Builder
	iw := pageInnerW(width)

	instances := snap.Global.Apps.Instances

	if detailMode && selectedIdx < len(instances) {
		return renderAppsDetail(instances[selectedIdx], iw)
	}

	// ── List View ──────────────────────────────────────────────────────────

	sb.WriteString(titleStyle.Render("APPS DIAGNOSTICS"))
	sb.WriteString("\n\n")

	if len(instances) == 0 {
		sb.WriteString("\n")
		pad := (iw - 26) / 2
		if pad < 0 {
			pad = 0
		}
		sb.WriteString(strings.Repeat(" ", pad) + dimStyle.Render("No applications detected."))
		sb.WriteString("\n")
		sb.WriteString(pageFooter("Y:Apps"))
		return sb.String()
	}

	// Summary
	issueCount := 0
	for _, a := range instances {
		if len(a.HealthIssues) > 0 {
			issueCount++
		}
	}
	sb.WriteString(fmt.Sprintf("  %s detected   %s with issues\n\n",
		valueStyle.Render(fmt.Sprintf("%d apps", len(instances))),
		warnStyle.Render(fmt.Sprintf("%d", issueCount))))

	// Table
	colNum := 3
	colApp := 14
	colPID := 8
	colPort := 7
	colRSS := 8
	colConn := 7
	colThr := 9
	colHlth := 8
	// version takes remainder

	header := fmt.Sprintf("  %s %s %s %s %s %s %s %s %s",
		styledPad(dimStyle.Render("#"), colNum),
		styledPad(dimStyle.Render("App"), colApp),
		styledPad(dimStyle.Render("PID"), colPID),
		styledPad(dimStyle.Render("Port"), colPort),
		styledPad(dimStyle.Render("RSS"), colRSS),
		styledPad(dimStyle.Render("Conns"), colConn),
		styledPad(dimStyle.Render("Threads"), colThr),
		styledPad(dimStyle.Render("Health"), colHlth),
		dimStyle.Render("Version"))

	sb.WriteString(boxTop(iw) + "\n")
	sb.WriteString(boxRow(header, iw) + "\n")
	sb.WriteString(boxMid(iw) + "\n")

	for i, app := range instances {
		name := app.DisplayName
		if len(name) > colApp-2 {
			name = name[:colApp-2]
		}

		portStr := "—"
		if app.Port > 0 {
			portStr = fmt.Sprintf("%d", app.Port)
		}

		rssStr := fmt.Sprintf("%.0fM", app.RSSMB)
		if app.RSSMB >= 1024 {
			rssStr = fmt.Sprintf("%.1fG", app.RSSMB/1024)
		}

		healthStr := healthScoreStr(app.HealthScore)

		verStr := app.Version
		if verStr == "" {
			verStr = "—"
		}

		row := fmt.Sprintf("  %s %s %s %s %s %s %s %s %s",
			styledPad(dimStyle.Render(fmt.Sprintf("%d", i+1)), colNum),
			styledPad(valueStyle.Render(name), colApp),
			styledPad(valueStyle.Render(fmt.Sprintf("%d", app.PID)), colPID),
			styledPad(valueStyle.Render(portStr), colPort),
			styledPad(valueStyle.Render(rssStr), colRSS),
			styledPad(valueStyle.Render(fmt.Sprintf("%d", app.Connections)), colConn),
			styledPad(valueStyle.Render(fmt.Sprintf("%d", app.Threads)), colThr),
			styledPad(healthStr, colHlth),
			dimStyle.Render(verStr))

		if i == selectedIdx {
			row = titleStyle.Render("> ") + row[2:]
		}

		sb.WriteString(boxRow(row, iw) + "\n")
	}

	sb.WriteString(boxBot(iw) + "\n")
	sb.WriteString(pageFooter("j/k:Navigate  Enter:Details  Y:Apps"))
	return sb.String()
}

// renderAppsDetail renders the detail view for a single application.
func renderAppsDetail(app model.AppInstance, iw int) string {
	var sb strings.Builder

	// Header
	status := "OK"
	if app.HealthScore < 50 {
		status = "CRIT"
	} else if app.HealthScore < 80 {
		status = "WARN"
	}
	sb.WriteString(titleStyle.Render(app.DisplayName) + "  " + renderHealthBadge(status) +
		"  " + dimStyle.Render(fmt.Sprintf("(score: %d)", app.HealthScore)))
	sb.WriteString("\n\n")

	// Section 1: Process Info
	sb.WriteString("  " + titleStyle.Render("PROCESS INFO") + "\n")
	sb.WriteString(boxTop(iw) + "\n")

	pidRow := fmt.Sprintf("  %s %s", styledPad(dimStyle.Render("PID:"), 16), valueStyle.Render(fmt.Sprintf("%d", app.PID)))
	sb.WriteString(boxRow(pidRow, iw) + "\n")

	portVal := "—"
	if app.Port > 0 {
		portVal = fmt.Sprintf("%d", app.Port)
	}
	portRow := fmt.Sprintf("  %s %s", styledPad(dimStyle.Render("Port:"), 16), valueStyle.Render(portVal))
	sb.WriteString(boxRow(portRow, iw) + "\n")

	uptimeRow := fmt.Sprintf("  %s %s", styledPad(dimStyle.Render("Uptime:"), 16), valueStyle.Render(fmtUptime(app.UptimeSec)))
	sb.WriteString(boxRow(uptimeRow, iw) + "\n")

	if app.ConfigPath != "" {
		cfgRow := fmt.Sprintf("  %s %s", styledPad(dimStyle.Render("Config:"), 16), valueStyle.Render(app.ConfigPath))
		sb.WriteString(boxRow(cfgRow, iw) + "\n")
	}

	verVal := app.Version
	if verVal == "" {
		verVal = "—"
	}
	verRow := fmt.Sprintf("  %s %s", styledPad(dimStyle.Render("Version:"), 16), valueStyle.Render(verVal))
	sb.WriteString(boxRow(verRow, iw) + "\n")
	sb.WriteString(boxBot(iw) + "\n\n")

	// Section 2: Resource Usage
	sb.WriteString("  " + titleStyle.Render("RESOURCE USAGE") + "\n")
	sb.WriteString(boxTop(iw) + "\n")

	rssStr := fmt.Sprintf("%.0fM", app.RSSMB)
	if app.RSSMB >= 1024 {
		rssStr = fmt.Sprintf("%.1fG", app.RSSMB/1024)
	}

	kvs := []struct{ k, v string }{
		{"RSS:", rssStr},
		{"CPU:", fmt.Sprintf("%.1f%%", app.CPUPct)},
		{"Threads:", fmt.Sprintf("%d", app.Threads)},
		{"FDs:", fmt.Sprintf("%d", app.FDs)},
		{"Connections:", fmt.Sprintf("%d", app.Connections)},
	}
	for _, kv := range kvs {
		row := fmt.Sprintf("  %s %s", styledPad(dimStyle.Render(kv.k), 16), valueStyle.Render(kv.v))
		sb.WriteString(boxRow(row, iw) + "\n")
	}
	sb.WriteString(boxBot(iw) + "\n\n")

	// Section 3: Deep Metrics
	if app.HasDeepMetrics && len(app.DeepMetrics) > 0 {
		sb.WriteString("  " + titleStyle.Render("DEEP METRICS") + "\n")
		sb.WriteString(boxTop(iw) + "\n")

		// Sort keys for stable output
		keys := make([]string, 0, len(app.DeepMetrics))
		for k := range app.DeepMetrics {
			keys = append(keys, k)
		}
		sort.Strings(keys)

		for _, k := range keys {
			label := k + ":"
			if len(label) > 14 {
				label = label[:14]
			}
			row := fmt.Sprintf("  %s %s", styledPad(dimStyle.Render(label), 16), valueStyle.Render(app.DeepMetrics[k]))
			sb.WriteString(boxRow(row, iw) + "\n")
		}
		sb.WriteString(boxBot(iw) + "\n\n")
	}

	// Section 4: Health Issues
	if len(app.HealthIssues) > 0 {
		sb.WriteString("  " + titleStyle.Render("HEALTH ISSUES") + "\n")
		sb.WriteString(boxTop(iw) + "\n")
		for _, issue := range app.HealthIssues {
			row := "  " + critStyle.Render("\u25cf") + " " + valueStyle.Render(issue)
			sb.WriteString(boxRow(row, iw) + "\n")
		}
		sb.WriteString(boxBot(iw) + "\n\n")
	}

	// Creds hint
	if app.NeedsCreds && !app.HasDeepMetrics {
		sb.WriteString("  " + dimStyle.Render("Configure credentials in ~/.config/xtop/secrets.json for deep metrics") + "\n\n")
	}

	sb.WriteString(pageFooter("k:Back  Y:Apps"))
	return sb.String()
}

// healthScoreStr returns a colored health score string.
func healthScoreStr(score int) string {
	s := fmt.Sprintf("%d", score)
	switch {
	case score >= 80:
		return okStyle.Render(s)
	case score >= 50:
		return warnStyle.Render(s)
	default:
		return critStyle.Render(s)
	}
}
