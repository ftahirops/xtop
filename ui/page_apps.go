//go:build linux

package ui

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/ftahirops/xtop/model"
)

func renderAppsPage(snap *model.Snapshot, result *model.AnalysisResult, selectedIdx int, detailMode bool,
	viewCompact bool,
	stackCursor int, stackExpanded []bool, containerIdx int,
	width, height int) string {
	var sb strings.Builder
	iw := pageInnerW(width)

	instances := snap.Global.Apps.Instances

	if detailMode && selectedIdx < len(instances) {
		app := instances[selectedIdx]
		if app.AppType == "docker" {
			return renderDockerDetail(app, stackCursor, stackExpanded, containerIdx, iw)
		}
		nCPU := snap.Global.CPU.NumCPUs
		if viewCompact {
			return renderAppsDetailCompact(app, nCPU, iw)
		}
		return renderAppsDetail(app, result, nCPU, iw)
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
		sb.WriteString(renderAppsServiceProbes(snap, iw))
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
	colApp := 18
	colPID := 8
	colPort := 7
	colRSS := 8
	colConn := 7
	colThr := 9
	colHlth := 8

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

		rssStr := appFmtMem(app.RSSMB)
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

	// ── Resource Share panel (SRE view) ───────────────────────────────────
	// Each dimension is reported independently (no composite score) with
	// rank + capacity share + headroom. When an incident is firing, the
	// bottleneck dimension's column shows each app's contribution share.
	sb.WriteString(renderAppsResourceShare(snap, iw))

	// Service probes section (merged from Services page)
	sb.WriteString(renderAppsServiceProbes(snap, iw))

	sb.WriteString(pageFooter("j/k:Navigate  Enter:Details  Y:Apps"))
	return sb.String()
}

// renderAppsResourceShare renders the per-app resource breakdown table plus
// the "top 5 consumers per dimension" block and, when an incident is active,
// the contribution-to-bottleneck highlight.
func renderAppsResourceShare(snap *model.Snapshot, iw int) string {
	apps := snap.Global.Apps.Instances
	if len(apps) == 0 {
		return ""
	}

	var sb strings.Builder
	sb.WriteString("\n")
	sb.WriteString(titleStyle.Render("RESOURCE SHARE"))
	sb.WriteString(dimStyle.Render("   per-dimension rank · capacity share · headroom  (no composite % — each dim is independent)"))
	sb.WriteString("\n\n")

	// Detect active bottleneck from the first app's Share.BottleneckDimension
	// (the enrichment pass sets the same dim on every app).
	activeDim := ""
	for i := range apps {
		if apps[i].Share.BottleneckDimension != "" {
			activeDim = apps[i].Share.BottleneckDimension
			break
		}
	}

	// Banner when an incident is firing.
	if activeDim != "" {
		banner := fmt.Sprintf("  %s %s is the active bottleneck — BOTTLENECK column shows each app's contribution",
			warnStyle.Render("⚠"), strings.ToUpper(activeDim))
		sb.WriteString(warnStyle.Render(banner))
		sb.WriteString("\n\n")
	}

	// ── Per-app table ────────────────────────────────────────────────────
	colApp := 18
	colImpact := 8
	colCPU := 18   // "2.80/4c  (70%)"
	colMem := 18   // "12.3/32G (38%)"
	colIO := 14    // "45 MB/s (37%)"
	colConn := 8
	colRank := 18  // "CPU#1 MEM#2 IO#3"
	colBottle := 0
	if activeDim != "" {
		colBottle = 10 // "72%"
	}

	sep := dimStyle.Render(" │ ")
	header := fmt.Sprintf("  %s%s%s%s%s%s%s%s%s%s%s%s%s",
		styledPad(dimStyle.Render("App"), colApp), sep,
		styledPad(dimStyle.Render("Impact"), colImpact), sep,
		styledPad(dimStyle.Render("CPU (cores/%)"), colCPU), sep,
		styledPad(dimStyle.Render("Mem (RSS/%)"), colMem), sep,
		styledPad(dimStyle.Render("IO MB/s"), colIO), sep,
		styledPad(dimStyle.Render("Conns"), colConn), sep,
		styledPad(dimStyle.Render("Ranks"), colRank))
	if activeDim != "" {
		header += sep + styledPad(warnStyle.Render("Bottleneck%"), colBottle)
	}

	sb.WriteString(boxTop(iw) + "\n")
	sb.WriteString(boxRow(header, iw) + "\n")
	sb.WriteString(boxMid(iw) + "\n")

	for i := range apps {
		a := &apps[i]
		sh := a.Share

		name := a.DisplayName
		if len(name) > colApp-2 {
			name = name[:colApp-2]
		}

		cpuCell := fmt.Sprintf("%.2fc (%s)",
			sh.CPUCoresUsed, colorPctOfCapacity(sh.CPUPctOfSystem))
		memCell := fmt.Sprintf("%s (%s)",
			appFmtMem(float64(sh.MemRSSBytes)/1024/1024),
			colorPctOfCapacity(sh.MemPctOfSystem))
		ioCell := fmt.Sprintf("%.1f", sh.ReadMBs+sh.WriteMBs)
		if sh.IOPctOfBusiest > 0.5 {
			ioCell += fmt.Sprintf(" (%s)", colorPctOfCapacity(sh.IOPctOfBusiest))
		}
		connCell := fmt.Sprintf("%d", sh.NetConns)
		impactCell := impactScoreCell(sh.Impact)
		rankCell := fmtRankQuad(sh.RankCPU, sh.RankMem, sh.RankIO, sh.RankNet)

		row := fmt.Sprintf("  %s%s%s%s%s%s%s%s%s%s%s%s%s",
			styledPad(valueStyle.Render(name), colApp), sep,
			styledPad(impactCell, colImpact), sep,
			styledPad(cpuCell, colCPU), sep,
			styledPad(memCell, colMem), sep,
			styledPad(ioCell, colIO), sep,
			styledPad(valueStyle.Render(connCell), colConn), sep,
			styledPad(rankCell, colRank))
		if activeDim != "" {
			var bottle string
			if sh.BottleneckSharePct >= 1 {
				bottle = colorBottleneckShare(sh.BottleneckSharePct)
			} else {
				bottle = dimStyle.Render("—")
			}
			row += sep + styledPad(bottle, colBottle)
		}
		sb.WriteString(boxRow(row, iw) + "\n")
	}
	sb.WriteString(boxBot(iw) + "\n")

	// ── Top-5-per-dimension panel ────────────────────────────────────────
	// "Who are the top consumers on each axis?" — the single most-asked
	// question in an incident room, answered at a glance.
	sb.WriteString(renderTopConsumersPanel(apps, iw))
	return sb.String()
}

// renderTopConsumersPanel renders a 4-column mini-table inside a proper box,
// with vertical separators between dimensions and a tight per-cell width so
// wide terminals don't produce huge whitespace gaps. Each cell shows
// "#N name  value" — rank first so the eye picks up the ordering.
func renderTopConsumersPanel(apps []model.AppInstance, iw int) string {
	var sb strings.Builder
	sb.WriteString("\n")
	sb.WriteString(titleStyle.Render("  TOP 5 CONSUMERS PER DIMENSION"))
	sb.WriteString("\n")

	// Build the four rank lists. Each value is a plain string — colors live
	// on the main resource-share table, not here, to keep this compact.
	cpuTop := topBy(apps, 5, func(a *model.AppInstance) float64 { return a.Share.CPUCoresUsed },
		func(a *model.AppInstance) (string, string) {
			return truncName(a.DisplayName, 14),
				fmt.Sprintf("%.2fc %.0f%%", a.Share.CPUCoresUsed, a.Share.CPUPctOfSystem)
		})
	memTop := topBy(apps, 5, func(a *model.AppInstance) float64 { return float64(a.Share.MemRSSBytes) },
		func(a *model.AppInstance) (string, string) {
			return truncName(a.DisplayName, 14),
				fmt.Sprintf("%s %.0f%%", appFmtMem(float64(a.Share.MemRSSBytes)/1024/1024), a.Share.MemPctOfSystem)
		})
	ioTop := topBy(apps, 5, func(a *model.AppInstance) float64 { return a.Share.ReadMBs + a.Share.WriteMBs },
		func(a *model.AppInstance) (string, string) {
			return truncName(a.DisplayName, 14),
				fmt.Sprintf("%.1f MB/s", a.Share.ReadMBs+a.Share.WriteMBs)
		})
	netTop := topBy(apps, 5, func(a *model.AppInstance) float64 { return float64(a.Share.NetConns) },
		func(a *model.AppInstance) (string, string) {
			return truncName(a.DisplayName, 14),
				fmt.Sprintf("%d conns", a.Share.NetConns)
		})

	// Each column shows: "#N  <14-char name>  <12-char value>" → 2+1+14+2+12 = 31 chars
	// Four columns + 3 " │ " separators + leading "  " → 31*4 + 9 + 2 = 135 chars total.
	// We stay well inside the standard iw (160+ common), and gracefully
	// truncate names for narrower terminals.
	const (
		rankW  = 3  // "#1 "
		nameW  = 14
		valueW = 12
		cellW  = rankW + nameW + 1 + valueW // 30
	)

	sep := dimStyle.Render(" │ ")
	sb.WriteString(boxTop(iw) + "\n")

	// Header row
	header := fmt.Sprintf("  %s%s%s%s%s%s%s",
		styledPad(titleStyle.Render("CPU"), cellW), sep,
		styledPad(titleStyle.Render("Memory"), cellW), sep,
		styledPad(titleStyle.Render("IO"), cellW), sep,
		styledPad(titleStyle.Render("Network"), cellW))
	sb.WriteString(boxRow(header, iw) + "\n")
	sb.WriteString(boxMid(iw) + "\n")

	maxRows := max4(len(cpuTop), len(memTop), len(ioTop), len(netTop))
	for i := 0; i < maxRows; i++ {
		cpu := fmtRankedCell(cpuTop, i, rankW, nameW, valueW)
		mem := fmtRankedCell(memTop, i, rankW, nameW, valueW)
		io := fmtRankedCell(ioTop, i, rankW, nameW, valueW)
		net := fmtRankedCell(netTop, i, rankW, nameW, valueW)
		row := fmt.Sprintf("  %s%s%s%s%s%s%s",
			styledPad(cpu, cellW), sep,
			styledPad(mem, cellW), sep,
			styledPad(io, cellW), sep,
			styledPad(net, cellW))
		sb.WriteString(boxRow(row, iw) + "\n")
	}
	sb.WriteString(boxBot(iw) + "\n")
	return sb.String()
}

// fmtRankedCell renders one "#N  name  value" cell, or a blank spacer when
// the rank row doesn't exist for this dimension (fewer consumers than max).
// `padRight` comes from ui/components.go — we reuse it for plain strings;
// rank number is pre-styled and padded with styledPad so its ANSI escapes
// don't distort the measured width.
func fmtRankedCell(rows []rankedRow, i, rankW, nameW, valueW int) string {
	if i >= len(rows) {
		return strings.Repeat(" ", rankW+nameW+1+valueW)
	}
	r := rows[i]
	rank := styledPad(dimStyle.Render(fmt.Sprintf("#%d", i+1)), rankW)
	name := valueStyle.Render(padRight(r.name, nameW))
	value := valueStyle.Render(padRight(r.value, valueW))
	return fmt.Sprintf("%s %s %s", rank, name, value)
}

// rankedRow is a (name, value) pair fed to the top-N consumer panel.
type rankedRow struct {
	name  string
	value string
}

// ── Small helpers local to the Resource Share view ──────────────────────────

// colorPctOfCapacity picks a color based on 0..100 share of total capacity.
// The ramp is deliberately conservative — we don't want "yellow" for a
// well-behaved app at 30% of system CPU.
func colorPctOfCapacity(pct float64) string {
	switch {
	case pct >= 80:
		return critStyle.Render(fmt.Sprintf("%.0f%%", pct))
	case pct >= 50:
		return warnStyle.Render(fmt.Sprintf("%.0f%%", pct))
	case pct >= 20:
		return valueStyle.Render(fmt.Sprintf("%.0f%%", pct))
	default:
		return dimStyle.Render(fmt.Sprintf("%.0f%%", pct))
	}
}

// colorBottleneckShare is more aggressive — during an active bottleneck, an
// app contributing 40%+ is a smoking-gun culprit.
func colorBottleneckShare(pct float64) string {
	switch {
	case pct >= 50:
		return critStyle.Render(fmt.Sprintf("%.0f%%", pct))
	case pct >= 25:
		return warnStyle.Render(fmt.Sprintf("%.0f%%", pct))
	default:
		return valueStyle.Render(fmt.Sprintf("%.0f%%", pct))
	}
}

func impactScoreCell(score float64) string {
	if score <= 0 {
		return dimStyle.Render("—")
	}
	switch {
	case score >= 70:
		return critStyle.Render(fmt.Sprintf("%.0f", score))
	case score >= 40:
		return warnStyle.Render(fmt.Sprintf("%.0f", score))
	default:
		return valueStyle.Render(fmt.Sprintf("%.0f", score))
	}
}

// fmtRankQuad renders compact per-dim ranks like "C#1 M#2 I#— N#3". Unranked
// dimensions render as "—" to avoid confusing them with "rank zero."
func fmtRankQuad(c, m, io, n int) string {
	fmtOne := func(r int) string {
		if r == 0 {
			return "—"
		}
		return fmt.Sprintf("#%d", r)
	}
	return fmt.Sprintf("C%s M%s I%s N%s",
		fmtOne(c), fmtOne(m), fmtOne(io), fmtOne(n))
}

// topBy returns the top-N apps by a picker function, rendered as (name,
// value) pairs. Apps with value <= 0 are excluded so the panel never shows
// padding rows masquerading as data.
func topBy(apps []model.AppInstance, n int,
	pick func(*model.AppInstance) float64,
	render func(*model.AppInstance) (string, string)) []rankedRow {
	type idxVal struct {
		a *model.AppInstance
		v float64
	}
	pairs := make([]idxVal, 0, len(apps))
	for i := range apps {
		v := pick(&apps[i])
		if v <= 0 {
			continue
		}
		pairs = append(pairs, idxVal{a: &apps[i], v: v})
	}
	sort.Slice(pairs, func(a, b int) bool { return pairs[a].v > pairs[b].v })
	if len(pairs) > n {
		pairs = pairs[:n]
	}
	out := make([]rankedRow, len(pairs))
	for i := range pairs {
		name, val := render(pairs[i].a)
		out[i] = rankedRow{name: name, value: val}
	}
	return out
}

func truncName(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}

func max4(a, b, c, d int) int {
	m := a
	if b > m {
		m = b
	}
	if c > m {
		m = c
	}
	if d > m {
		m = d
	}
	return m
}

// ── Generic App Detail ─────────────────────────────────────────────────

func renderAppsDetail(app model.AppInstance, result *model.AnalysisResult, nCPU int, iw int) string {
	var sb strings.Builder

	sb.WriteString(appDetailHeader(app))

	// Show credential requirement notice at the TOP (only when needed)
	if app.NeedsCreds && !app.HasDeepMetrics {
		sb.WriteString(renderCredsNotice(app, iw))
	}

	sb.WriteString(renderAppInfoResourceBox(app, nCPU, iw))

	// Per-app RCA findings — pluggable rule engine, no extra cost.
	// Renders a clear panel of "what's wrong with this app right now"
	// based on already-collected DeepMetrics. Empty = no panel rendered.
	if result != nil && len(result.AppRCA) > 0 {
		sb.WriteString(renderAppRCAFindings(app, result.AppRCA, iw))
	}

	if app.HasDeepMetrics && len(app.DeepMetrics) > 0 {
		sb.WriteString(renderAppDeepMetrics(app, iw))
	}

	// Per-website table
	if len(app.Websites) > 0 {
		sb.WriteString(renderWebsitesTable(app.Websites, iw))
	}

	// MySQL handles its own diagnostics; other apps use generic health issues
	if app.AppType != "mysql" && len(app.HealthIssues) > 0 {
		if app.AppType == "haproxy" && app.HasDeepMetrics {
			sb.WriteString(renderHAProxyHealthIssues(app, iw))
		} else {
			sb.WriteString("  " + titleStyle.Render("HEALTH ISSUES") + "\n")
			sb.WriteString(boxTop(iw) + "\n")
			for _, issue := range app.HealthIssues {
				row := "  " + critStyle.Render("\u25cf") + " " + valueStyle.Render(issue)
				sb.WriteString(boxRow(row, iw) + "\n")
			}
			sb.WriteString(boxBot(iw) + "\n\n")
		}
	}

	sb.WriteString(pageFooter("b:Back  d:Summary  Y:Apps"))
	return sb.String()
}

// renderAppsServiceProbes renders the merged service health probes section on the Apps list view.
func renderAppsServiceProbes(snap *model.Snapshot, iw int) string {
	if snap == nil {
		return ""
	}
	probes := snap.Global.HealthChecks.Probes
	if len(probes) == 0 {
		return ""
	}

	var sb strings.Builder
	sb.WriteString("\n")

	// Categorize
	var httpProbes, tcpProbes []model.HealthProbeResult
	healthy, degraded, down := 0, 0, 0
	for _, p := range probes {
		switch p.Status {
		case "OK":
			healthy++
		case "WARN":
			degraded++
		case "CRIT":
			down++
		}
		switch p.ProbeType {
		case "http":
			httpProbes = append(httpProbes, p)
		case "tcp":
			tcpProbes = append(tcpProbes, p)
		}
	}

	// Summary line
	summary := fmt.Sprintf("  %s healthy   %s degraded   %s down",
		okStyle.Render(fmt.Sprintf("%d", healthy)),
		warnStyle.Render(fmt.Sprintf("%d", degraded)),
		critStyle.Render(fmt.Sprintf("%d", down)))

	sb.WriteString(boxTopTitle(" "+titleStyle.Render("SERVICE PROBES")+" ", iw) + "\n")
	sb.WriteString(boxRow(summary, iw) + "\n")

	// HTTP probes
	if len(httpProbes) > 0 {
		sb.WriteString(boxRow("", iw) + "\n")
		sb.WriteString(boxRow("  "+dimStyle.Render("HTTP/HTTPS"), iw) + "\n")
		for _, p := range httpProbes {
			badge := renderHealthBadge(p.Status)
			latStr := valueStyle.Render(fmt.Sprintf("%.0fms", p.LatencyMs))
			certStr := ""
			if p.CertDaysLeft >= 0 {
				certStr = "  cert " + certDaysStr(p.CertDaysLeft)
			}
			row := fmt.Sprintf("  %s  %s  %s  %s%s",
				styledPad(badge, 6),
				styledPad(valueStyle.Render(p.Name), 12),
				styledPad(dimStyle.Render(truncate(p.Target, 35)), 37),
				latStr,
				certStr)
			sb.WriteString(boxRow(row, iw) + "\n")
		}
	}

	// TCP probes
	if len(tcpProbes) > 0 {
		sb.WriteString(boxRow("", iw) + "\n")
		sb.WriteString(boxRow("  "+dimStyle.Render("TCP"), iw) + "\n")
		for _, p := range tcpProbes {
			badge := renderHealthBadge(p.Status)
			latStr := valueStyle.Render(fmt.Sprintf("%.0fms", p.LatencyMs))
			row := fmt.Sprintf("  %s  %s  %s  %s",
				styledPad(badge, 6),
				styledPad(valueStyle.Render(p.Name), 16),
				styledPad(dimStyle.Render(p.Target), 24),
				latStr)
			sb.WriteString(boxRow(row, iw) + "\n")
		}
	}

	sb.WriteString(boxBot(iw) + "\n")
	return sb.String()
}

// renderCredsNotice shows a credential configuration template at the top of the detail page.
func renderCredsNotice(app model.AppInstance, iw int) string {
	template := appCredsTemplate(app.AppType, app.Port)
	if template == "" {
		return ""
	}

	var sb strings.Builder
	sb.WriteString("  " + warnStyle.Render("CREDENTIALS REQUIRED") + "  " +
		dimStyle.Render("Deep metrics unavailable without credentials") + "\n")
	sb.WriteString(boxTop(iw) + "\n")

	sb.WriteString(boxRow("  "+dimStyle.Render("Add to")+" "+valueStyle.Render("~/.xtop_secrets")+" "+dimStyle.Render("(JSON, combine multiple apps in one file):"), iw) + "\n")
	sb.WriteString(boxMid(iw) + "\n")

	for _, line := range strings.Split(template, "\n") {
		sb.WriteString(boxRow("  "+dimStyle.Render(line), iw) + "\n")
	}

	sb.WriteString(boxMid(iw) + "\n")
	sb.WriteString(boxRow("  "+dimStyle.Render("chmod 600 ~/.xtop_secrets  # secure the file"), iw) + "\n")
	sb.WriteString(boxBot(iw) + "\n\n")
	return sb.String()
}

func appCredsTemplate(appType string, port int) string {
	switch appType {
	case "mysql":
		return `{
  "mysql": {
    "host": "127.0.0.1",
    "port": 3306,
    "user": "root",
    "password": "YOUR_MYSQL_PASSWORD"
  }
}`
	case "postgresql":
		p := 5432
		if port > 0 {
			p = port
		}
		return fmt.Sprintf(`{
  "postgresql": {
    "host": "127.0.0.1",
    "port": %d,
    "user": "postgres",
    "password": "YOUR_PG_PASSWORD",
    "dbname": "postgres"
  }
}`, p)
	case "mongodb":
		return `{
  "mongodb": {
    "uri": "mongodb://user:password@127.0.0.1:27017/admin"
  }
}`
	case "redis":
		p := 6379
		if port > 0 {
			p = port
		}
		return fmt.Sprintf(`{
  "redis": {
    "host": "127.0.0.1",
    "port": %d,
    "password": "YOUR_REDIS_PASSWORD"
  }
}`, p)
	case "rabbitmq":
		return `{
  "rabbitmq": {
    "host": "127.0.0.1",
    "port": 15672,
    "user": "guest",
    "password": "guest"
  }
}`
	case "elasticsearch":
		return `{
  "elasticsearch": {
    "url": "http://127.0.0.1:9200",
    "user": "elastic",
    "password": "YOUR_ES_PASSWORD"
  }
}`
	default:
		return ""
	}
}

func renderAppDeepMetrics(app model.AppInstance, iw int) string {
	switch app.AppType {
	case "elasticsearch":
		return renderESDeepMetrics(app, iw)
	case "logstash":
		return renderLogstashDeepMetrics(app, iw)
	case "kibana":
		return renderKibanaDeepMetrics(app, iw)
	case "redis":
		return renderRedisDeepMetrics(app, iw)
	case "mysql":
		return renderMySQLDeepMetrics(app, iw)
	case "postgresql":
		return renderPostgreSQLDeepMetrics(app, iw)
	case "phpfpm":
		return renderPHPFPMDeepMetrics(app, iw)
	case "nginx":
		return renderNginxDeepMetrics(app, iw)
	case "haproxy":
		return renderHAProxyDeepMetrics(app, iw)
	case "apache":
		return renderApacheDeepMetrics(app, iw)
	case "mongodb":
		return renderMongoDBDeepMetrics(app, iw)
	case "memcached":
		return renderMemcachedDeepMetrics(app, iw)
	case "rabbitmq":
		return renderRabbitMQDeepMetrics(app, iw)
	case "kafka":
		return renderKafkaDeepMetrics(app, iw)
	case "caddy":
		return renderCaddyDeepMetrics(app, iw)
	case "traefik":
		return renderTraefikDeepMetrics(app, iw)
	case "plesk":
		return renderPleskDeepMetrics(app, iw)
	default:
		return renderGenericDeepMetrics(app.DeepMetrics, iw)
	}
}

// ── Elasticsearch Detail ───────────────────────────────────────────────

func renderESDeepMetrics(app model.AppInstance, iw int) string {
	var sb strings.Builder
	dm := app.DeepMetrics

	// --- Overall health banner on top ---
	sb.WriteString(esRenderHealthBanner(app, iw))

	// --- Performance suggestions & config issues (if any) ---
	sb.WriteString(esRenderSuggestions(app, iw))

	// --- Compact 2-column sections ---
	sb.WriteString(appSection2Col("CLUSTER", iw, []kv{
		{Key: "Name", Val: dm["cluster_name"]},
		{Key: "Status", Val: esColorStatus(dm["status"])},
		{Key: "Nodes", Val: esWithVerdictInt(dm["number_of_nodes"], 1, 1)},
		{Key: "Data Nodes", Val: esWithVerdictInt(dm["number_of_data_nodes"], 1, 1)},
		{Key: "Lucene", Val: dm["lucene_version"]},
	}))

	sb.WriteString(appSection2Col("SHARDS", iw, []kv{
		{Key: "Primary", Val: esOK(dm["active_primary_shards"])},
		{Key: "Total", Val: esOK(dm["active_shards"])},
		{Key: "Unassigned", Val: esVerdictCount(dm["unassigned_shards"], 0, 5)},
		{Key: "Relocating", Val: esVerdictCount(dm["relocating_shards"], 0, 5)},
		{Key: "Initializing", Val: esVerdictCount(dm["initializing_shards"], 0, 5)},
		{Key: "Pending Tasks", Val: esVerdictCount(dm["number_of_pending_tasks"], 5, 20)},
		{Key: "Active %", Val: esVerdictPctLow(dm["active_shards_percent_as_number"], 95, 99)},
	}))

	sb.WriteString(appSection2Col("INDICES", iw, []kv{
		{Key: "Total", Val: esVerdictCount(dm["total_indices"], 1000, 5000)},
		{Key: "Green", Val: esOK(dm["indices_green"])},
		{Key: "Yellow", Val: esVerdictCount(dm["indices_yellow"], 0, 5)},
		{Key: "Red", Val: esVerdictCount(dm["indices_red"], 0, 1)},
		{Key: "Documents", Val: dm["doc_count"]},
		{Key: "Deleted", Val: dm["deleted_docs"]},
		{Key: "Store Size", Val: dm["store_size"]},
		{Key: "Segments", Val: dm["segment_count"]},
	}))

	sb.WriteString(appSection2Col("JVM & MEMORY", iw, []kv{
		{Key: "Heap Used", Val: dm["jvm_heap_used"]},
		{Key: "Heap Max", Val: dm["jvm_heap_max"]},
		{Key: "Heap %", Val: esVerdictPct(dm["jvm_heap_used_pct"], 75, 85)},
		{Key: "Fielddata", Val: dm["fielddata_memory"]},
		{Key: "FD Evictions", Val: esVerdictCount(dm["fielddata_evictions"], 0, 10)},
		{Key: "QueryCache", Val: dm["query_cache_memory"]},
		{Key: "QC Hits", Val: dm["query_cache_hits"]},
		{Key: "QC Misses", Val: dm["query_cache_misses"]},
	}))

	// GC — collect all gc_*_count keys
	gcKVs := []kv{}
	for _, name := range []string{"young", "old"} {
		countKey := "gc_" + name + "_count"
		timeKey := "gc_" + name + "_time_ms"
		if dm[countKey] != "" {
			gcKVs = append(gcKVs, kv{Key: capitalize(name) + " Count", Val: dm[countKey]})
			gcKVs = append(gcKVs, kv{Key: capitalize(name) + " Time (ms)", Val: dm[timeKey]})
		}
	}
	if len(gcKVs) == 0 {
		for k, v := range dm {
			if strings.HasPrefix(k, "gc_") && strings.HasSuffix(k, "_count") {
				name := strings.TrimSuffix(strings.TrimPrefix(k, "gc_"), "_count")
				gcKVs = append(gcKVs, kv{Key: name + " Count", Val: v})
				if tv, ok := dm["gc_"+name+"_time_ms"]; ok {
					gcKVs = append(gcKVs, kv{Key: name + " Time (ms)", Val: tv})
				}
			}
		}
	}
	if len(gcKVs) > 0 {
		sb.WriteString(appSection("GARBAGE COLLECTION", iw, gcKVs))
	}

	sb.WriteString(appSection2Col("THROUGHPUT", iw, []kv{
		{Key: "Index Total", Val: dm["index_total"]},
		{Key: "Index Time", Val: esMS(dm["index_time_ms"])},
		{Key: "Search Q", Val: dm["search_query_total"]},
		{Key: "Search Time", Val: esMS(dm["search_query_time_ms"])},
		{Key: "Merges", Val: dm["merge_total"]},
		{Key: "OS CPU", Val: esVerdictPct(dm["os_cpu_pct"], 70, 90)},
		{Key: "HTTP Conns", Val: dm["http_current_open"]},
	}))

	// Thread pools — compact grid with verdicts
	if dm["tp_write_queue"] != "" || dm["tp_search_queue"] != "" || dm["tp_total_rejected"] != "" {
		tpKVs := []kv{
			{Key: "Write A/Q/R", Val: esThreePartVerdict(dm["tp_write_active"], dm["tp_write_queue"], dm["tp_write_rejected"])},
			{Key: "Search A/Q/R", Val: esThreePartVerdict(dm["tp_search_active"], dm["tp_search_queue"], dm["tp_search_rejected"])},
			{Key: "Bulk A/Q/R", Val: esThreePartVerdict(dm["tp_bulk_active"], dm["tp_bulk_queue"], dm["tp_bulk_rejected"])},
			{Key: "Get A/Q/R", Val: esThreePartVerdict(dm["tp_get_active"], dm["tp_get_queue"], dm["tp_get_rejected"])},
			{Key: "Total Rejected", Val: esVerdictCount(dm["tp_total_rejected"], 0, 1)},
		}
		sb.WriteString(appSection2Col("THREAD POOLS (Active/Queue/Rejected)", iw, tpKVs))
	}

	// Circuit breakers — compact
	if dm["cb_total_tripped"] != "" || dm["cb_parent_pct"] != "" {
		cbKVs := []kv{
			{Key: "Parent Pct", Val: esVerdictPct(dm["cb_parent_pct"], 80, 95)},
			{Key: "Parent Size/Limit", Val: esTwoPart(dm["cb_parent_size"], dm["cb_parent_limit"])},
			{Key: "Fielddata", Val: esTwoPart(dm["cb_fielddata_size"], dm["cb_fielddata_limit"])},
			{Key: "Request", Val: esTwoPart(dm["cb_request_size"], dm["cb_request_limit"])},
			{Key: "In-Flight", Val: esTwoPart(dm["cb_in_flight_requests_size"], dm["cb_in_flight_requests_limit"])},
			{Key: "Total Trips", Val: esVerdictCount(dm["cb_total_tripped"], 0, 1)},
		}
		sb.WriteString(appSection2Col("CIRCUIT BREAKERS", iw, cbKVs))
	}

	// Pending tasks + Shard analysis + Index lifecycle — merged into one compact section
	var sharKVs []kv
	if dm["pending_tasks_count"] != "" {
		sharKVs = append(sharKVs, kv{Key: "Pending Tasks", Val: esVerdictCount(dm["pending_tasks_count"], 5, 20)})
		if dm["pending_tasks_oldest_ms"] != "" {
			sharKVs = append(sharKVs, kv{Key: "Oldest (ms)", Val: esVerdictMs(dm["pending_tasks_oldest_ms"], 5000, 30000)})
		}
	}
	if dm["shards_unassigned_cat"] != "" {
		sharKVs = append(sharKVs, kv{Key: "Unassigned", Val: esVerdictCount(dm["shards_unassigned_cat"], 0, 1)})
	}
	if dm["shards_oversized"] != "" {
		sharKVs = append(sharKVs, kv{Key: "Oversized>50G", Val: esVerdictCount(dm["shards_oversized"], 0, 3)})
	}
	if dm["shards_undersized"] != "" {
		sharKVs = append(sharKVs, kv{Key: "Undersized<1G", Val: dm["shards_undersized"]})
	}
	if dm["largest_shard"] != "" {
		sharKVs = append(sharKVs, kv{Key: "Largest", Val: dm["largest_shard"] + " · " + dm["largest_shard_size"]})
	}
	if dm["indices_total_cat"] != "" {
		sharKVs = append(sharKVs, kv{Key: "Total Indices", Val: esVerdictCount(dm["indices_total_cat"], 1000, 5000)})
	}
	if dm["indices_aging_90d"] != "" {
		sharKVs = append(sharKVs, kv{Key: "Aging >90d", Val: dm["indices_aging_90d"]})
	}
	if dm["indices_empty"] != "" {
		sharKVs = append(sharKVs, kv{Key: "Empty", Val: dm["indices_empty"]})
	}
	if dm["indices_tiny"] != "" {
		sharKVs = append(sharKVs, kv{Key: "Tiny<100KB", Val: dm["indices_tiny"]})
	}
	if len(sharKVs) > 0 {
		sb.WriteString(appSection2Col("SHARDS & INDEX LIFECYCLE", iw, sharKVs))
	}

	// GC details (compact)
	if dm["gc_young_per_min"] != "" || dm["gc_young_avg_ms"] != "" {
		sb.WriteString(appSection2Col("GARBAGE COLLECTION", iw, []kv{
			{Key: "Young /min", Val: esVerdictGC(dm["gc_young_per_min"], 60, 120)},
			{Key: "Young Avg", Val: esMS(dm["gc_young_avg_ms"])},
			{Key: "Young p95", Val: esVerdictMs(dm["gc_young_p95_approx_ms"], 100, 500)},
			{Key: "Old /min", Val: esVerdictGC(dm["gc_old_per_min"], 1, 5)},
			{Key: "Old Avg", Val: esMS(dm["gc_old_avg_ms"])},
			{Key: "Old p95", Val: esVerdictMs(dm["gc_old_p95_approx_ms"], 500, 2000)},
			{Key: "Total Freq/min", Val: dm["gc_frequency"]},
		}))
	}

	// Slow indices
	if cntStr := dm["slow_index_count"]; cntStr != "" {
		cnt, _ := strconv.Atoi(cntStr)
		if cnt > 0 {
			slowKVs := []kv{}
			for i := 0; i < cnt; i++ {
				prefix := fmt.Sprintf("slow_index_%d_", i)
				name := dm[prefix+"name"]
				if name == "" {
					continue
				}
				label := fmt.Sprintf("#%d %s", i+1, name)
				val := fmt.Sprintf("search %sms · index %sms · %s queries",
					appFmtDash(dm[prefix+"search_avg_ms"]),
					appFmtDash(dm[prefix+"index_avg_ms"]),
					appFmtDash(dm[prefix+"search_count"]))
				slowKVs = append(slowKVs, kv{Key: label, Val: val})
			}
			if len(slowKVs) > 0 {
				sb.WriteString(appSection("SLOWEST INDICES", iw, slowKVs))
			}
		}
	}

	return sb.String()
}

// esThreePart renders "a / b / c" collapsing empty slots.
func esThreePart(a, b, c string) string {
	if a == "" && b == "" && c == "" {
		return ""
	}
	parts := []string{appFmtDash(a), appFmtDash(b), appFmtDash(c)}
	return strings.Join(parts, " / ")
}

func esTwoPart(a, b string) string {
	if a == "" && b == "" {
		return ""
	}
	return appFmtDash(a) + " / " + appFmtDash(b)
}

func esColorStatus(s string) string {
	switch s {
	case "green":
		return okStyle.Render("GREEN")
	case "yellow":
		return warnStyle.Render("YELLOW")
	case "red":
		return critStyle.Render("RED")
	}
	return s
}

func esColorVal(s, good string) string {
	if s == "" || s == good {
		return s
	}
	return warnStyle.Render(s)
}

func capitalize(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

// ── PostgreSQL Detail ──────────────────────────────────────────────────

func renderPostgreSQLDeepMetrics(app model.AppInstance, iw int) string {
	var sb strings.Builder
	dm := app.DeepMetrics

	// Health Status Table
	sb.WriteString("  " + titleStyle.Render("HEALTH STATUS") + "\n")
	sb.WriteString(boxTop(iw) + "\n")

	type healthRow struct {
		metric, value, status string
	}
	rows := []healthRow{}

	// Cache Hit Ratio
	if dm["cache_hit_ratio"] != "" {
		var ratio float64
		fmt.Sscanf(dm["cache_hit_ratio"], "%f", &ratio)
		status := "OK"
		if ratio < 90 {
			status = "CRIT"
		} else if ratio < 95 {
			status = "WARN"
		}
		rows = append(rows, healthRow{"Cache Hit Ratio", dm["cache_hit_ratio"] + "%", status})
	}

	// Deadlocks
	if dm["deadlocks"] != "" {
		status := "OK"
		if dm["deadlocks"] != "0" {
			status = "CRIT"
		}
		rows = append(rows, healthRow{"Deadlocks", dm["deadlocks"], status})
	}

	// Blocked Queries
	if dm["blocked_queries"] != "" {
		status := "OK"
		if dm["blocked_queries"] != "0" {
			v, _ := strconv.Atoi(dm["blocked_queries"])
			if v > 5 {
				status = "CRIT"
			} else if v > 0 {
				status = "WARN"
			}
		}
		rows = append(rows, healthRow{"Blocked Queries", dm["blocked_queries"], status})
	}

	// Connections
	if dm["backends"] != "" && dm["max_connections"] != "" {
		backends, _ := strconv.Atoi(dm["backends"])
		maxConn, _ := strconv.Atoi(dm["max_connections"])
		status := "OK"
		if maxConn > 0 {
			pct := float64(backends) / float64(maxConn) * 100
			if pct > 90 {
				status = "CRIT"
			} else if pct > 75 {
				status = "WARN"
			}
		}
		rows = append(rows, healthRow{"Connections", dm["backends"] + " / " + dm["max_connections"], status})
	}

	// Dead Tuples
	if dm["dead_tuple_ratio"] != "" {
		var ratio float64
		fmt.Sscanf(dm["dead_tuple_ratio"], "%f", &ratio)
		status := "OK"
		if ratio > 20 {
			status = "CRIT"
		} else if ratio > 10 {
			status = "WARN"
		}
		rows = append(rows, healthRow{"Dead Tuple Ratio", dm["dead_tuple_ratio"] + "%", status})
	}

	// Replication Lag
	if dm["replication_lag"] != "" {
		var lag float64
		fmt.Sscanf(dm["replication_lag"], "%f", &lag)
		status := "OK"
		if lag > 30 {
			status = "CRIT"
		} else if lag > 5 {
			status = "WARN"
		}
		rows = append(rows, healthRow{"Replication Lag", dm["replication_lag"] + "s", status})
	}

	cMetric := 24
	cValue := 40
	hdr := fmt.Sprintf("  %s %s %s",
		styledPad(dimStyle.Render("Metric"), cMetric),
		styledPad(dimStyle.Render("Value"), cValue),
		dimStyle.Render("Status"))
	sb.WriteString(boxRow(hdr, iw) + "\n")
	sb.WriteString(boxMid(iw) + "\n")

	for _, r := range rows {
		var badge string
		switch r.status {
		case "OK":
			badge = okStyle.Render("OK")
		case "WARN":
			badge = warnStyle.Render("WARN")
		case "CRIT":
			badge = critStyle.Render("CRIT")
		}
		row := fmt.Sprintf("  %s %s %s",
			styledPad(valueStyle.Render(r.metric), cMetric),
			styledPad(valueStyle.Render(r.value), cValue),
			badge)
		sb.WriteString(boxRow(row, iw) + "\n")
	}
	sb.WriteString(boxBot(iw) + "\n\n")

	// Connections
	sb.WriteString(appSection("CONNECTIONS", iw, []kv{
		{Key: "Max Connections", Val: dm["max_connections"]},
		{Key: "Backends", Val: dm["backends"]},
		{Key: "Active Queries", Val: dm["active_queries"]},
		{Key: "Idle Connections", Val: dm["idle_connections"]},
		{Key: "Idle In Transaction", Val: dm["idle_in_transaction"]},
		{Key: "Waiting", Val: dm["waiting_connections"]},
		{Key: "Long Running", Val: dm["long_running_queries"]},
	}))

	// Performance
	sb.WriteString(appSection("PERFORMANCE", iw, []kv{
		{Key: "Commits", Val: dm["xact_commit"]},
		{Key: "Rollbacks", Val: dm["xact_rollback"]},
		{Key: "Rollback Ratio", Val: dm["rollback_ratio"]},
		{Key: "Blocks Read", Val: dm["blks_read"]},
		{Key: "Blocks Hit", Val: dm["blks_hit"]},
		{Key: "Cache Hit Ratio", Val: dm["cache_hit_ratio"]},
		{Key: "Tuples Returned", Val: dm["tup_returned"]},
		{Key: "Tuples Fetched", Val: dm["tup_fetched"]},
		{Key: "Tuples Inserted", Val: dm["tup_inserted"]},
		{Key: "Tuples Updated", Val: dm["tup_updated"]},
		{Key: "Tuples Deleted", Val: dm["tup_deleted"]},
		{Key: "Conflicts", Val: dm["conflicts"]},
		{Key: "Deadlocks", Val: dm["deadlocks"]},
		{Key: "Temp Files", Val: dm["temp_files"]},
		{Key: "Temp Bytes", Val: dm["temp_bytes"]},
	}))

	// Bgwriter
	sb.WriteString(appSection("BGWRITER", iw, []kv{
		{Key: "Checkpoints Timed", Val: dm["checkpoints_timed"]},
		{Key: "Checkpoints Req", Val: dm["checkpoints_req"]},
		{Key: "Buffers Checkpoint", Val: dm["buffers_checkpoint"]},
		{Key: "Buffers Clean", Val: dm["buffers_clean"]},
		{Key: "Buffers Backend", Val: dm["buffers_backend"]},
		{Key: "Buffers Alloc", Val: dm["buffers_alloc"]},
	}))

	// Maintenance
	sb.WriteString(appSection("MAINTENANCE", iw, []kv{
		{Key: "Dead Tuple Ratio", Val: dm["dead_tuple_ratio"]},
		{Key: "Total Dead Tuples", Val: dm["total_dead_tuples"]},
		{Key: "Total Live Tuples", Val: dm["total_live_tuples"]},
		{Key: "Top Dead Tuples", Val: dm["top_dead_tuples"]},
		{Key: "Blocked Queries", Val: dm["blocked_queries"]},
	}))

	// Replication (if present)
	if dm["replica_count"] != "" || dm["replication_lag"] != "" {
		sb.WriteString(appSection("REPLICATION", iw, []kv{
			{Key: "Replica Count", Val: dm["replica_count"]},
			{Key: "Replication Lag", Val: dm["replication_lag"]},
		}))
	}

	// Database Sizes
	if dm["top_db_sizes"] != "" {
		sb.WriteString(appSection("DATABASE SIZES", iw, []kv{
			{Key: "Shared Buffers", Val: dm["shared_buffers"]},
			{Key: "Top Databases", Val: dm["top_db_sizes"]},
		}))
	}

	return sb.String()
}

// ── PHP-FPM Detail ─────────────────────────────────────────────────────

func renderPHPFPMDeepMetrics(app model.AppInstance, iw int) string {
	var sb strings.Builder
	dm := app.DeepMetrics

	// Health Status Table
	sb.WriteString("  " + titleStyle.Render("HEALTH STATUS") + "\n")
	sb.WriteString(boxTop(iw) + "\n")

	type healthRow struct {
		metric, value, status string
	}
	rows := []healthRow{}

	// Worker Utilization
	if dm["worker_utilization_pct"] != "" {
		var pct float64
		fmt.Sscanf(dm["worker_utilization_pct"], "%f", &pct)
		status := "OK"
		if pct > 90 {
			status = "CRIT"
		} else if pct > 75 {
			status = "WARN"
		}
		rows = append(rows, healthRow{"Worker Utilization", dm["active_workers"] + " / " + dm["max_children"] + " (" + dm["worker_utilization_pct"] + "%)", status})
	}

	// Max Children Reached
	if dm["max_children_reached"] != "" {
		status := "OK"
		if dm["max_children_reached"] != "0" {
			v, _ := strconv.Atoi(dm["max_children_reached"])
			if v > 10 {
				status = "CRIT"
			} else if v > 0 {
				status = "WARN"
			}
		}
		rows = append(rows, healthRow{"Max Children Reached", dm["max_children_reached"], status})
	}

	// Memory
	if dm["total_rss_mb"] != "" {
		var mb float64
		fmt.Sscanf(dm["total_rss_mb"], "%f", &mb)
		status := "OK"
		if mb > 4096 {
			status = "CRIT"
		} else if mb > 2048 {
			status = "WARN"
		}
		rows = append(rows, healthRow{"Total Memory", appFmtMem(mb), status})
	}

	cMetric := 24
	cValue := 40
	hdr := fmt.Sprintf("  %s %s %s",
		styledPad(dimStyle.Render("Metric"), cMetric),
		styledPad(dimStyle.Render("Value"), cValue),
		dimStyle.Render("Status"))
	sb.WriteString(boxRow(hdr, iw) + "\n")
	sb.WriteString(boxMid(iw) + "\n")

	for _, r := range rows {
		var badge string
		switch r.status {
		case "OK":
			badge = okStyle.Render("OK")
		case "WARN":
			badge = warnStyle.Render("WARN")
		case "CRIT":
			badge = critStyle.Render("CRIT")
		}
		row := fmt.Sprintf("  %s %s %s",
			styledPad(valueStyle.Render(r.metric), cMetric),
			styledPad(valueStyle.Render(r.value), cValue),
			badge)
		sb.WriteString(boxRow(row, iw) + "\n")
	}
	sb.WriteString(boxBot(iw) + "\n\n")

	// Pool Config
	sb.WriteString(appSection("POOL CONFIG", iw, []kv{
		{Key: "Pool Name", Val: dm["pool_name"]},
		{Key: "PM Type", Val: dm["pm_type"]},
		{Key: "Max Children", Val: dm["max_children"]},
		{Key: "Max Requests", Val: dm["max_requests"]},
		{Key: "Slow Log Timeout", Val: dm["slow_log_timeout"]},
		{Key: "Listen Mode", Val: dm["listen_mode"]},
		{Key: "Listen Address", Val: dm["listen_address"]},
	}))

	// Worker Status
	sb.WriteString(appSection("WORKER STATUS", iw, []kv{
		{Key: "Active Workers", Val: dm["active_workers"]},
		{Key: "Idle Workers", Val: dm["idle_workers"]},
		{Key: "Total Workers", Val: dm["total_workers"]},
		{Key: "Utilization", Val: dm["worker_utilization_pct"]},
		{Key: "Max Children Hit", Val: dm["max_children_reached"]},
	}))

	// Memory
	sb.WriteString(appSection("MEMORY", iw, []kv{
		{Key: "Avg Worker RSS", Val: dm["avg_worker_rss_mb"]},
		{Key: "Total RSS", Val: dm["total_rss_mb"]},
	}))

	return sb.String()
}

// ── Nginx Detail ───────────────────────────────────────────────────────

func renderNginxDeepMetrics(app model.AppInstance, iw int) string {
	var sb strings.Builder
	dm := app.DeepMetrics

	// Health Status Table
	sb.WriteString("  " + titleStyle.Render("HEALTH STATUS") + "\n")
	sb.WriteString(boxTop(iw) + "\n")

	type healthRow struct {
		metric, value, status string
	}
	rows := []healthRow{}

	// Dropped Connections
	if dm["dropped_connections"] != "" {
		status := "OK"
		if dm["dropped_connections"] != "0" {
			v, _ := strconv.Atoi(dm["dropped_connections"])
			if v > 100 {
				status = "CRIT"
			} else if v > 0 {
				status = "WARN"
			}
		}
		rows = append(rows, healthRow{"Dropped Connections", dm["dropped_connections"], status})
	}

	// Workers
	if dm["workers"] != "" && dm["worker_processes"] != "" {
		actual, _ := strconv.Atoi(dm["workers"])
		expected, _ := strconv.Atoi(dm["worker_processes"])
		status := "OK"
		if expected > 0 && actual < expected {
			status = "WARN"
		}
		rows = append(rows, healthRow{"Workers", dm["workers"] + " / " + dm["worker_processes"], status})
	}

	// Active Connections
	if dm["active_connections"] != "" {
		v, _ := strconv.Atoi(dm["active_connections"])
		maxConn, _ := strconv.Atoi(dm["worker_connections"])
		workers, _ := strconv.Atoi(dm["workers"])
		status := "OK"
		if maxConn > 0 && workers > 0 {
			totalCap := maxConn * workers
			pct := float64(v) / float64(totalCap) * 100
			if pct > 90 {
				status = "CRIT"
			} else if pct > 75 {
				status = "WARN"
			}
		}
		rows = append(rows, healthRow{"Active Connections", dm["active_connections"], status})
	}

	cMetric := 24
	cValue := 40
	hdr := fmt.Sprintf("  %s %s %s",
		styledPad(dimStyle.Render("Metric"), cMetric),
		styledPad(dimStyle.Render("Value"), cValue),
		dimStyle.Render("Status"))
	sb.WriteString(boxRow(hdr, iw) + "\n")
	sb.WriteString(boxMid(iw) + "\n")

	for _, r := range rows {
		var badge string
		switch r.status {
		case "OK":
			badge = okStyle.Render("OK")
		case "WARN":
			badge = warnStyle.Render("WARN")
		case "CRIT":
			badge = critStyle.Render("CRIT")
		}
		row := fmt.Sprintf("  %s %s %s",
			styledPad(valueStyle.Render(r.metric), cMetric),
			styledPad(valueStyle.Render(r.value), cValue),
			badge)
		sb.WriteString(boxRow(row, iw) + "\n")
	}
	sb.WriteString(boxBot(iw) + "\n\n")

	// Connections (stub_status)
	sb.WriteString(appSection("CONNECTIONS", iw, []kv{
		{Key: "Active", Val: dm["active_connections"]},
		{Key: "Accepts", Val: dm["accepts"]},
		{Key: "Handled", Val: dm["handled"]},
		{Key: "Requests", Val: dm["requests"]},
		{Key: "Reading", Val: dm["reading"]},
		{Key: "Writing", Val: dm["writing"]},
		{Key: "Waiting", Val: dm["waiting"]},
		{Key: "Req/Connection", Val: dm["requests_per_connection"]},
		{Key: "Dropped", Val: dm["dropped_connections"]},
	}))

	// Workers
	sb.WriteString(appSection("WORKERS", iw, []kv{
		{Key: "Worker Processes", Val: dm["worker_processes"]},
		{Key: "Worker Connections", Val: dm["worker_connections"]},
		{Key: "Workers Total", Val: dm["workers"]},
		{Key: "Workers Running", Val: dm["workers_running"]},
		{Key: "Workers Sleeping", Val: dm["workers_sleeping"]},
		{Key: "Workers Disk Wait", Val: dm["workers_disk_wait"]},
	}))

	// Config
	sb.WriteString(appSection("CONFIG", iw, []kv{
		{Key: "Keepalive Timeout", Val: dm["keepalive_timeout"]},
		{Key: "Client Max Body", Val: dm["client_max_body_size"]},
		{Key: "Gzip", Val: dm["gzip"]},
		{Key: "Upstream Blocks", Val: dm["upstream_blocks"]},
		{Key: "Server Blocks", Val: dm["server_blocks"]},
		{Key: "Stub Status", Val: dm["stub_status_location"]},
	}))

	return sb.String()
}

// ── Apache Detail ──────────────────────────────────────────────────────

func renderApacheDeepMetrics(app model.AppInstance, iw int) string {
	var sb strings.Builder
	dm := app.DeepMetrics

	// Health status table
	type healthRow struct{ metric, value, status string }
	rows := []healthRow{}

	if v := dm["worker_utilization_pct"]; v != "" {
		var pct float64
		fmt.Sscanf(v, "%f", &pct)
		status := "OK"
		if pct > 95 {
			status = "CRIT"
		} else if pct > 80 {
			status = "WARN"
		}
		rows = append(rows, healthRow{"Worker Utilization", v + "%", status})
	}
	if busy := dm["busy_workers"]; busy != "" {
		maxW := dm["max_request_workers"]
		val := busy + " busy"
		if maxW != "" {
			val += " / " + maxW + " max"
		}
		status := "OK"
		if maxW != "" {
			b, _ := strconv.Atoi(busy)
			m, _ := strconv.Atoi(maxW)
			if m > 0 && b >= m {
				status = "CRIT"
			}
		}
		rows = append(rows, healthRow{"Workers", val, status})
	}
	if v := dm["cpu_load"]; v != "" {
		var load float64
		fmt.Sscanf(v, "%f", &load)
		status := "OK"
		if load > 0.5 {
			status = "CRIT"
		} else if load > 0.2 {
			status = "WARN"
		}
		rows = append(rows, healthRow{"CPU Load", fmt.Sprintf("%.2f", load), status})
	}

	if len(rows) > 0 {
		sb.WriteString("  " + titleStyle.Render("HEALTH STATUS") + "\n")
		sb.WriteString(boxTop(iw) + "\n")
		cM, cV := 24, 30
		hdr := fmt.Sprintf("  %s %s %s", styledPad(dimStyle.Render("Metric"), cM), styledPad(dimStyle.Render("Value"), cV), dimStyle.Render("Status"))
		sb.WriteString(boxRow(hdr, iw) + "\n")
		sb.WriteString(boxMid(iw) + "\n")
		for _, r := range rows {
			badge := okStyle.Render("OK")
			if r.status == "WARN" {
				badge = warnStyle.Render("WARN")
			} else if r.status == "CRIT" {
				badge = critStyle.Render("CRIT")
			}
			row := fmt.Sprintf("  %s %s %s", styledPad(valueStyle.Render(r.metric), cM), styledPad(valueStyle.Render(r.value), cV), badge)
			sb.WriteString(boxRow(row, iw) + "\n")
		}
		sb.WriteString(boxBot(iw) + "\n\n")
	}

	sb.WriteString(appSection("TRAFFIC", iw, []kv{
		{Key: "Requests/sec", Val: dm["req_per_sec"]},
		{Key: "Bytes/sec", Val: dm["bytes_per_sec"]},
		{Key: "Bytes/req", Val: dm["bytes_per_req"]},
		{Key: "Total Accesses", Val: dm["total_accesses"]},
		{Key: "Total kBytes", Val: dm["total_kbytes"]},
	}))

	sb.WriteString(appSection("WORKERS", iw, []kv{
		{Key: "Busy", Val: dm["busy_workers"]},
		{Key: "Idle", Val: dm["idle_workers"]},
		{Key: "Running (R)", Val: dm["workers_running"]},
		{Key: "Sleeping (S)", Val: dm["workers_sleeping"]},
		{Key: "Disk Wait (D)", Val: dm["workers_disk_wait"]},
	}))

	sb.WriteString(appSection("SCOREBOARD", iw, []kv{
		{Key: "Writing (W)", Val: dm["scoreboard_writing"]},
		{Key: "Reading (R)", Val: dm["scoreboard_reading"]},
		{Key: "Keepalive (K)", Val: dm["scoreboard_keepalive"]},
		{Key: "DNS Lookup (D)", Val: dm["scoreboard_dns"]},
		{Key: "Closing (C)", Val: dm["scoreboard_closing"]},
		{Key: "Logging (L)", Val: dm["scoreboard_logging"]},
		{Key: "Graceful (G)", Val: dm["scoreboard_graceful"]},
		{Key: "Starting (S)", Val: dm["scoreboard_starting"]},
		{Key: "Idle Slots (.)", Val: dm["scoreboard_idle"]},
	}))

	sb.WriteString(appSection("CONFIG", iw, []kv{
		{Key: "MPM", Val: dm["mpm"]},
		{Key: "MaxRequestWorkers", Val: dm["max_request_workers"]},
		{Key: "ServerLimit", Val: dm["server_limit"]},
		{Key: "KeepAlive", Val: dm["keepalive"]},
		{Key: "KeepAliveTimeout", Val: dm["keepalive_timeout"]},
		{Key: "Timeout", Val: dm["timeout"]},
	}))

	return sb.String()
}

// ── Memcached Detail ───────────────────────────────────────────────────

func renderMemcachedDeepMetrics(app model.AppInstance, iw int) string {
	var sb strings.Builder
	dm := app.DeepMetrics

	type healthRow struct{ metric, value, status string }
	rows := []healthRow{}

	if v := dm["memory_usage_pct"]; v != "" {
		var pct float64
		fmt.Sscanf(v, "%f", &pct)
		status := "OK"
		if pct > 95 {
			status = "CRIT"
		} else if pct > 90 {
			status = "WARN"
		}
		rows = append(rows, healthRow{"Memory Usage", v + "%", status})
	}
	if v := dm["hit_ratio"]; v != "" {
		var pct float64
		fmt.Sscanf(v, "%f", &pct)
		status := "OK"
		if pct < 50 {
			status = "CRIT"
		} else if pct < 80 {
			status = "WARN"
		}
		rows = append(rows, healthRow{"Hit Ratio", v, status})
	}
	if v := dm["evictions"]; v != "" {
		status := "OK"
		if v != "0" {
			status = "CRIT"
		}
		rows = append(rows, healthRow{"Evictions", v, status})
	}
	if v := dm["accepting_conns"]; v == "0" {
		rows = append(rows, healthRow{"Accepting Conns", "NO", "CRIT"})
	}
	if v := dm["rejected_connections"]; v != "" && v != "0" {
		rows = append(rows, healthRow{"Rejected Conns", v, "CRIT"})
	}

	if len(rows) > 0 {
		sb.WriteString("  " + titleStyle.Render("HEALTH STATUS") + "\n")
		sb.WriteString(boxTop(iw) + "\n")
		cM, cV := 24, 30
		hdr := fmt.Sprintf("  %s %s %s", styledPad(dimStyle.Render("Metric"), cM), styledPad(dimStyle.Render("Value"), cV), dimStyle.Render("Status"))
		sb.WriteString(boxRow(hdr, iw) + "\n")
		sb.WriteString(boxMid(iw) + "\n")
		for _, r := range rows {
			badge := okStyle.Render("OK")
			if r.status == "WARN" {
				badge = warnStyle.Render("WARN")
			} else if r.status == "CRIT" {
				badge = critStyle.Render("CRIT")
			}
			row := fmt.Sprintf("  %s %s %s", styledPad(valueStyle.Render(r.metric), cM), styledPad(valueStyle.Render(r.value), cV), badge)
			sb.WriteString(boxRow(row, iw) + "\n")
		}
		sb.WriteString(boxBot(iw) + "\n\n")
	}

	sb.WriteString(appSection("CACHE", iw, []kv{
		{Key: "Current Items", Val: dm["curr_items"]},
		{Key: "Total Items", Val: dm["total_items"]},
		{Key: "Hit Ratio", Val: dm["hit_ratio"]},
		{Key: "Miss Ratio", Val: dm["miss_ratio"]},
		{Key: "Evictions", Val: dm["evictions"]},
		{Key: "Eviction Rate", Val: dm["eviction_rate"]},
		{Key: "Reclaimed", Val: dm["reclaimed"]},
	}))

	sb.WriteString(appSection("MEMORY", iw, []kv{
		{Key: "Used", Val: dm["bytes"]},
		{Key: "Limit", Val: dm["limit_maxbytes"]},
		{Key: "Usage", Val: dm["memory_usage_pct"]},
		{Key: "Config Memory MB", Val: dm["config_memory_mb"]},
		{Key: "Slab Count", Val: dm["slab_count"]},
		{Key: "Slab Waste", Val: dm["slab_wasted_pct"]},
	}))

	sb.WriteString(appSection("COMMANDS", iw, []kv{
		{Key: "GET", Val: dm["cmd_get"]},
		{Key: "SET", Val: dm["cmd_set"]},
		{Key: "Flush", Val: dm["cmd_flush"]},
		{Key: "Get/Set Ratio", Val: dm["cmd_ratio_get_set"]},
		{Key: "Delete Hits", Val: dm["delete_hits"]},
		{Key: "Delete Misses", Val: dm["delete_misses"]},
	}))

	sb.WriteString(appSection("CONNECTIONS", iw, []kv{
		{Key: "Current", Val: dm["curr_connections"]},
		{Key: "Total", Val: dm["total_connections"]},
		{Key: "Rejected", Val: dm["rejected_connections"]},
		{Key: "Listen Disabled", Val: dm["listen_disabled_num"]},
		{Key: "Max Connections", Val: dm["config_max_connections"]},
		{Key: "Threads", Val: dm["threads"]},
	}))

	sb.WriteString(appSection("NETWORK", iw, []kv{
		{Key: "Bytes Read", Val: dm["bytes_read_human"]},
		{Key: "Bytes Written", Val: dm["bytes_written_human"]},
	}))

	return sb.String()
}

// ── RabbitMQ Detail ────────────────────────────────────────────────────

func renderRabbitMQDeepMetrics(app model.AppInstance, iw int) string {
	var sb strings.Builder
	dm := app.DeepMetrics

	type healthRow struct{ metric, value, status string }
	rows := []healthRow{}

	if v := dm["messages_unacked"]; v != "" {
		status := "OK"
		n, _ := strconv.Atoi(v)
		if n > 10000 {
			status = "CRIT"
		} else if n > 1000 {
			status = "WARN"
		}
		rows = append(rows, healthRow{"Unacked Messages", v, status})
	}
	if v := dm["messages_ready"]; v != "" {
		status := "OK"
		n, _ := strconv.Atoi(v)
		if n > 100000 {
			status = "CRIT"
		} else if n > 10000 {
			status = "WARN"
		}
		rows = append(rows, healthRow{"Ready Messages", v, status})
	}
	if dm["mem_alarm"] == "true" {
		rows = append(rows, healthRow{"Memory Alarm", "TRIGGERED", "CRIT"})
	}
	if dm["disk_alarm"] == "true" {
		rows = append(rows, healthRow{"Disk Alarm", "TRIGGERED", "CRIT"})
	}
	if v := dm["mem_usage_pct"]; v != "" {
		var pct float64
		fmt.Sscanf(v, "%f", &pct)
		status := "OK"
		if pct > 80 {
			status = "WARN"
		}
		rows = append(rows, healthRow{"Memory Usage", v + "%", status})
	}
	if v := dm["fd_usage_pct"]; v != "" {
		var pct float64
		fmt.Sscanf(v, "%f", &pct)
		status := "OK"
		if pct > 80 {
			status = "WARN"
		}
		rows = append(rows, healthRow{"FD Usage", v + "%", status})
	}
	if v := dm["queues_idle"]; v != "" && v != "0" {
		n, _ := strconv.Atoi(v)
		status := "OK"
		if n > 5 {
			status = "WARN"
		}
		rows = append(rows, healthRow{"Idle Queues", v, status})
	}

	if len(rows) > 0 {
		sb.WriteString("  " + titleStyle.Render("HEALTH STATUS") + "\n")
		sb.WriteString(boxTop(iw) + "\n")
		cM, cV := 24, 30
		hdr := fmt.Sprintf("  %s %s %s", styledPad(dimStyle.Render("Metric"), cM), styledPad(dimStyle.Render("Value"), cV), dimStyle.Render("Status"))
		sb.WriteString(boxRow(hdr, iw) + "\n")
		sb.WriteString(boxMid(iw) + "\n")
		for _, r := range rows {
			badge := okStyle.Render("OK")
			if r.status == "WARN" {
				badge = warnStyle.Render("WARN")
			} else if r.status == "CRIT" {
				badge = critStyle.Render("CRIT")
			}
			row := fmt.Sprintf("  %s %s %s", styledPad(valueStyle.Render(r.metric), cM), styledPad(valueStyle.Render(r.value), cV), badge)
			sb.WriteString(boxRow(row, iw) + "\n")
		}
		sb.WriteString(boxBot(iw) + "\n\n")
	}

	sb.WriteString(appSection("MESSAGES", iw, []kv{
		{Key: "Ready", Val: dm["messages_ready"]},
		{Key: "Unacked", Val: dm["messages_unacked"]},
		{Key: "Total", Val: dm["messages_total"]},
		{Key: "Publish Rate", Val: dm["publish_rate"]},
		{Key: "Deliver Rate", Val: dm["deliver_rate"]},
		{Key: "Ack Rate", Val: dm["ack_rate"]},
		{Key: "Redeliver Rate", Val: dm["redeliver_rate"]},
		{Key: "Unroutable", Val: dm["return_unroutable"]},
	}))

	sb.WriteString(appSection("CLUSTER", iw, []kv{
		{Key: "Cluster Name", Val: dm["cluster_name"]},
		{Key: "Node", Val: dm["node"]},
		{Key: "Node Type", Val: dm["node_type"]},
		{Key: "Erlang Version", Val: dm["erlang_version"]},
		{Key: "Connections", Val: dm["connections"]},
		{Key: "Channels", Val: dm["channels"]},
		{Key: "Consumers", Val: dm["consumers"]},
	}))

	sb.WriteString(appSection("QUEUES", iw, []kv{
		{Key: "Total", Val: dm["queues"]},
		{Key: "Idle (no consumers)", Val: dm["queues_idle"]},
		{Key: "Backlogged (>1K)", Val: dm["queues_backlogged"]},
		{Key: "Top Queue", Val: dm["top_queue_name"]},
		{Key: "Top Queue Msgs", Val: dm["top_queue_messages"]},
	}))

	sb.WriteString(appSection("NODE RESOURCES", iw, []kv{
		{Key: "Memory", Val: dm["mem_used_mb"]},
		{Key: "Memory Limit", Val: dm["mem_limit_mb"]},
		{Key: "Memory Usage", Val: dm["mem_usage_pct"]},
		{Key: "Disk Free", Val: dm["disk_free_mb"]},
		{Key: "FD Used/Total", Val: dm["fd_used"] + " / " + dm["fd_total"]},
		{Key: "Sockets", Val: dm["sockets_used"] + " / " + dm["sockets_total"]},
		{Key: "Erlang Procs", Val: dm["proc_used"] + " / " + dm["proc_total"]},
	}))

	return sb.String()
}

// ── Kafka Detail ───────────────────────────────────────────────────────

func renderKafkaDeepMetrics(app model.AppInstance, iw int) string {
	var sb strings.Builder
	dm := app.DeepMetrics

	sb.WriteString(appSection("BROKER", iw, []kv{
		{Key: "Broker ID", Val: dm["broker_id"]},
		{Key: "Kafka Version", Val: dm["kafka_version"]},
		{Key: "Topics", Val: dm["topic_count"]},
		{Key: "Consumer Groups", Val: dm["consumer_group_count"]},
		{Key: "JMX Port", Val: dm["jmx_port"]},
		{Key: "JVM hsperfdata", Val: dm["jvm_hsperfdata"]},
	}))

	sb.WriteString(appSection("CONFIG", iw, []kv{
		{Key: "Partitions", Val: dm["num_partitions"]},
		{Key: "Log Dirs", Val: dm["log_dirs"]},
		{Key: "Retention Hours", Val: dm["log_retention_hours"]},
		{Key: "IO Threads", Val: dm["num_io_threads"]},
		{Key: "Network Threads", Val: dm["num_network_threads"]},
		{Key: "Replication Factor", Val: dm["default_replication_factor"]},
		{Key: "Auto-create Topics", Val: dm["auto_create_topics"]},
	}))

	if dm["log_dir_size_gb"] != "" {
		sb.WriteString(appSection("STORAGE", iw, []kv{
			{Key: "Log Dir Size", Val: dm["log_dir_size_gb"] + " GB"},
		}))
	}

	return sb.String()
}

// ── Caddy Detail ───────────────────────────────────────────────────────

func renderCaddyDeepMetrics(app model.AppInstance, iw int) string {
	var sb strings.Builder
	dm := app.DeepMetrics

	sb.WriteString(appSection("SERVER", iw, []kv{
		{Key: "Version", Val: dm["caddy_version"]},
		{Key: "Admin API", Val: dm["admin_api"]},
		{Key: "Sites", Val: dm["sites"]},
		{Key: "Reverse Proxies", Val: dm["reverse_proxy_count"]},
		{Key: "TLS Enabled", Val: dm["tls_enabled"]},
		{Key: "Gzip", Val: dm["encode_gzip"]},
	}))

	if dm["api_servers"] != "" || dm["api_routes"] != "" {
		sb.WriteString(appSection("LIVE CONFIG", iw, []kv{
			{Key: "Servers", Val: dm["api_servers"]},
			{Key: "Routes", Val: dm["api_routes"]},
			{Key: "Auto-HTTPS", Val: dm["api_auto_https"]},
		}))
	}

	if dm["upstreams_healthy"] != "" || dm["upstreams_unhealthy"] != "" {
		sb.WriteString(appSection("UPSTREAMS", iw, []kv{
			{Key: "Healthy", Val: dm["upstreams_healthy"]},
			{Key: "Unhealthy", Val: dm["upstreams_unhealthy"]},
		}))
	}

	if dm["http_requests_total"] != "" {
		sb.WriteString(appSection("METRICS", iw, []kv{
			{Key: "HTTP Requests", Val: dm["http_requests_total"]},
		}))
	}

	return sb.String()
}

// ── Traefik Detail ─────────────────────────────────────────────────────

func renderTraefikDeepMetrics(app model.AppInstance, iw int) string {
	var sb strings.Builder
	dm := app.DeepMetrics

	type healthRow struct{ metric, value, status string }
	rows := []healthRow{}

	if v := dm["health_status"]; v != "" {
		status := "OK"
		if v != "ok" {
			status = "CRIT"
		}
		rows = append(rows, healthRow{"Health Check", v, status})
	}
	if v := dm["http_router_errors"]; v != "" && v != "0" {
		rows = append(rows, healthRow{"Router Errors", v, "CRIT"})
	}
	if v := dm["http_service_errors"]; v != "" && v != "0" {
		rows = append(rows, healthRow{"Service Errors", v, "CRIT"})
	}

	if len(rows) > 0 {
		sb.WriteString("  " + titleStyle.Render("HEALTH STATUS") + "\n")
		sb.WriteString(boxTop(iw) + "\n")
		cM, cV := 24, 30
		hdr := fmt.Sprintf("  %s %s %s", styledPad(dimStyle.Render("Metric"), cM), styledPad(dimStyle.Render("Value"), cV), dimStyle.Render("Status"))
		sb.WriteString(boxRow(hdr, iw) + "\n")
		sb.WriteString(boxMid(iw) + "\n")
		for _, r := range rows {
			badge := okStyle.Render("OK")
			if r.status == "WARN" {
				badge = warnStyle.Render("WARN")
			} else if r.status == "CRIT" {
				badge = critStyle.Render("CRIT")
			}
			row := fmt.Sprintf("  %s %s %s", styledPad(valueStyle.Render(r.metric), cM), styledPad(valueStyle.Render(r.value), cV), badge)
			sb.WriteString(boxRow(row, iw) + "\n")
		}
		sb.WriteString(boxBot(iw) + "\n\n")
	}

	sb.WriteString(appSection("HTTP", iw, []kv{
		{Key: "Routers", Val: dm["http_routers"]},
		{Key: "Services", Val: dm["http_services"]},
		{Key: "Middlewares", Val: dm["http_middlewares"]},
		{Key: "Router Warnings", Val: dm["http_router_warnings"]},
	}))

	if dm["tcp_routers"] != "" && dm["tcp_routers"] != "0" {
		sb.WriteString(appSection("TCP", iw, []kv{
			{Key: "Routers", Val: dm["tcp_routers"]},
			{Key: "Services", Val: dm["tcp_services"]},
		}))
	}

	sb.WriteString(appSection("ENTRYPOINTS", iw, []kv{
		{Key: "Addresses", Val: dm["entrypoints"]},
		{Key: "API Port", Val: dm["api_port"]},
		{Key: "Dashboard", Val: dm["dashboard_enabled"]},
	}))

	return sb.String()
}
// ── Generic Deep Metrics ───────────────────────────────────────────────

func renderGenericDeepMetrics(dm map[string]string, iw int) string {
	keys := make([]string, 0, len(dm))
	for k := range dm {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	kvs := make([]kv, 0, len(keys))
	for _, k := range keys {
		kvs = append(kvs, kv{Key: k, Val: dm[k]})
	}
	return appSection("DEEP METRICS", iw, kvs)
}

// ── Shared Helpers ─────────────────────────────────────────────────────

func appDetailHeader(app model.AppInstance) string {
	status := "OK"
	if app.HealthScore < 50 {
		status = "CRIT"
	} else if app.HealthScore < 80 {
		status = "WARN"
	}
	return titleStyle.Render(app.DisplayName) + "  " + renderHealthBadge(status) +
		"  " + dimStyle.Render(fmt.Sprintf("(score: %d)", app.HealthScore)) + "\n\n"
}

// renderAppInfoResourceBox renders PROCESS INFO + RESOURCE USAGE as a compact 2-column box.
func renderAppInfoResourceBox(app model.AppInstance, nCPU int, iw int) string {
	var sb strings.Builder
	sb.WriteString("  " + titleStyle.Render("PROCESS & RESOURCES") + "\n")
	sb.WriteString(boxTop(iw) + "\n")

	halfW := (iw - 8) / 2
	lCol := []kv{
		{Key: "PID", Val: fmt.Sprintf("%d", app.PID)},
		{Key: "Port", Val: appFmtPort(app.Port)},
		{Key: "Uptime", Val: fmtUptime(app.UptimeSec)},
		{Key: "Version", Val: appFmtDash(app.Version)},
		{Key: "Config", Val: app.ConfigPath},
	}
	// CPU% in Linux convention: 100% = one full core. On a multi-core box
	// processes can exceed 100%. Translate to "X cores out of N" + "Y% of host"
	// so it's not just a giant number.
	if nCPU < 1 {
		nCPU = 1
	}
	cores := app.CPUPct / 100.0
	hostPct := app.CPUPct / float64(nCPU)
	cpuStr := fmt.Sprintf("%.1f%%  (%.1f / %d cores  =  %.0f%% of host)",
		app.CPUPct, cores, nCPU, hostPct)
	switch {
	case hostPct > 80:
		cpuStr = critStyle.Render(cpuStr)
	case hostPct > 50:
		cpuStr = warnStyle.Render(cpuStr)
	default:
		cpuStr = okStyle.Render(cpuStr)
	}
	rCol := []kv{
		{Key: "RSS", Val: appFmtMem(app.RSSMB)},
		{Key: "CPU", Val: cpuStr},
		{Key: "Threads", Val: fmt.Sprintf("%d", app.Threads)},
		{Key: "FDs", Val: fmt.Sprintf("%d", app.FDs)},
		{Key: "Conns", Val: fmt.Sprintf("%d", app.Connections)},
	}

	maxR := len(lCol)
	if len(rCol) > maxR { maxR = len(rCol) }
	for i := 0; i < maxR; i++ {
		var left, right string
		if i < len(lCol) && lCol[i].Val != "" {
			left = fmt.Sprintf("%s %s",
				styledPad(dimStyle.Render(lCol[i].Key+":"), 12),
				valueStyle.Render(lCol[i].Val))
		}
		if i < len(rCol) && rCol[i].Val != "" {
			// CPU val is pre-styled with color, use as-is
			val := rCol[i].Val
			if strings.Contains(val, "\x1b[") {
				// Already styled (contains ANSI escape)
			} else {
				val = valueStyle.Render(val)
			}
			right = fmt.Sprintf("%s %s",
				styledPad(dimStyle.Render(rCol[i].Key+":"), 10),
				val)
		}
		row := fmt.Sprintf("  %s%s", styledPad(left, halfW), right)
		sb.WriteString(boxRow(row, iw) + "\n")
	}
	sb.WriteString(boxBot(iw) + "\n")
	return sb.String()
}

// ── Plesk Detail ──────────────────────────────────────────────────────

func renderPleskDeepMetrics(app model.AppInstance, iw int) string {
	var sb strings.Builder
	dm := app.DeepMetrics

	// Panel Info
	var panelRows []string
	if v := dm["plesk_version"]; v != "" {
		panelRows = append(panelRows, pleskMetricRow("Version", v))
	}
	if v := dm["os_platform"]; v != "" {
		panelRows = append(panelRows, pleskMetricRow("Platform", v))
	}
	if v := dm["license_type"]; v != "" {
		panelRows = append(panelRows, pleskMetricRow("License", v))
	}
	if v := dm["updates_available"]; v != "" && v != "0" {
		panelRows = append(panelRows, pleskMetricRow("Updates", v+" available"))
	}
	if len(panelRows) > 0 {
		sb.WriteString(boxSection("PANEL INFO", panelRows, iw))
	}

	// Service Status
	svcDefs := []struct {
		key  string
		name string
	}{
		{"svc_panel", "Control Panel"},
		{"svc_engine", "SW Engine"},
		{"svc_nginx", "Nginx"},
		{"svc_apache", "Apache"},
		{"svc_mariadb", "MariaDB"},
		{"svc_postfix", "Postfix"},
		{"svc_dovecot", "Dovecot"},
		{"svc_named", "BIND DNS"},
		{"svc_php83", "PHP 8.3 FPM"},
		{"svc_php84", "PHP 8.4 FPM"},
		{"svc_fail2ban", "Fail2Ban"},
		{"svc_imunify", "Imunify360"},
	}
	var svcRows []string
	for _, s := range svcDefs {
		status := dm[s.key]
		if status == "" || status == "n/a" {
			continue
		}
		var badge string
		if status == "active" {
			badge = okStyle.Render("active")
		} else {
			badge = critStyle.Render("DOWN")
		}
		svcRows = append(svcRows, fmt.Sprintf("  %s %s",
			styledPad(dimStyle.Render(s.name+":"), 18), badge))
	}
	if len(svcRows) > 0 {
		sb.WriteString(boxSection("PLESK SERVICES", svcRows, iw))
	}

	// Hosting
	var hostRows []string
	if v := dm["domains"]; v != "" {
		hostRows = append(hostRows, pleskMetricRow("Domains", v))
	}
	if v := dm["suspended_domains"]; v != "" && v != "0" {
		hostRows = append(hostRows, fmt.Sprintf("  %s %s",
			styledPad(dimStyle.Render("Suspended:"), 18),
			warnStyle.Render(v)))
	}
	if v := dm["hosting_subscriptions"]; v != "" {
		hostRows = append(hostRows, pleskMetricRow("Subscriptions", v))
	}
	if v := dm["databases"]; v != "" {
		hostRows = append(hostRows, pleskMetricRow("Databases", v))
	}
	if v := dm["mail_accounts"]; v != "" {
		hostRows = append(hostRows, pleskMetricRow("Mail Accounts", v))
	}
	if len(hostRows) > 0 {
		sb.WriteString(boxSection("HOSTING", hostRows, iw))
	}

	// PHP-FPM Pools
	var phpRows []string
	for _, ver := range []string{"81", "82", "83", "84"} {
		if v := dm["php"+ver+"_pools"]; v != "" && v != "0" {
			phpRows = append(phpRows, pleskMetricRow("PHP "+ver[:1]+"."+ver[1:], v+" pools"))
		}
	}
	if t := dm["php_pools_total"]; t != "" && t != "0" {
		phpRows = append(phpRows, pleskMetricRow("Total Pools", t))
	}
	if len(phpRows) > 0 {
		sb.WriteString(boxSection("PHP-FPM", phpRows, iw))
	}

	// Mail
	var mailRows []string
	if v := dm["mail_queue"]; v != "" {
		mailRows = append(mailRows, pleskMetricRow("Queue Size", v))
	}
	if len(mailRows) > 0 {
		sb.WriteString(boxSection("MAIL", mailRows, iw))
	}

	// Certificates
	var certRows []string
	if v := dm["cert_total"]; v != "" && v != "0" {
		certRows = append(certRows, pleskMetricRow("Total Certs", v))
		if ok := dm["certs_ok"]; ok != "" {
			certRows = append(certRows, pleskMetricRow("Valid", ok))
		}
		if v := dm["certs_expiring"]; v != "" && v != "0" {
			certRows = append(certRows, fmt.Sprintf("  %s %s",
				styledPad(dimStyle.Render("Expiring:"), 18),
				warnStyle.Render(v)))
		}
		if v := dm["certs_expired"]; v != "" && v != "0" {
			certRows = append(certRows, fmt.Sprintf("  %s %s",
				styledPad(dimStyle.Render("Expired:"), 18),
				critStyle.Render(v)))
		}
	}
	if len(certRows) > 0 {
		sb.WriteString(boxSection("CERTIFICATES", certRows, iw))
	}

	// Security
	var secRows []string
	if v := dm["imunify_status"]; v == "active" {
		secRows = append(secRows, pleskMetricRow("Imunify360", "active"))
		if inf := dm["imunify_infected"]; inf != "" && inf != "0" {
			secRows = append(secRows, fmt.Sprintf("  %s %s",
				styledPad(dimStyle.Render("Infected:"), 18),
				critStyle.Render(inf+" files")))
		}
	}
	if len(secRows) > 0 {
		sb.WriteString(boxSection("SECURITY", secRows, iw))
	}

	// Disk Usage
	var diskRows []string
	for _, d := range []struct {
		key  string
		name string
	}{
		{"disk_vhosts_mb", "Web Data"},
		{"disk_mysql_mb", "MySQL Data"},
		{"disk_mail_mb", "Mail Data"},
	} {
		if v := dm[d.key]; v != "" {
			mb, _ := strconv.Atoi(v)
			var disp string
			if mb > 1024 {
				disp = fmt.Sprintf("%.1f GB", float64(mb)/1024)
			} else {
				disp = v + " MB"
			}
			diskRows = append(diskRows, pleskMetricRow(d.name, disp))
		}
	}
	if len(diskRows) > 0 {
		sb.WriteString(boxSection("DISK USAGE", diskRows, iw))
	}

	// Web Traffic
	var webRows []string
	if v := dm["http_connections"]; v != "" && v != "0" {
		webRows = append(webRows, pleskMetricRow("HTTP Conns", v))
	}
	if v := dm["https_connections"]; v != "" && v != "0" {
		webRows = append(webRows, pleskMetricRow("HTTPS Conns", v))
	}
	if len(webRows) > 0 {
		sb.WriteString(boxSection("WEB TRAFFIC", webRows, iw))
	}

	return sb.String()
}

func pleskMetricRow(key, val string) string {
	return fmt.Sprintf("  %s %s",
		styledPad(dimStyle.Render(key+":"), 18),
		valueStyle.Render(val))
}

func appSection(title string, iw int, kvs []kv) string {
	var sb strings.Builder
	sb.WriteString("  " + titleStyle.Render(title) + "\n")
	sb.WriteString(boxTop(iw) + "\n")
	for _, item := range kvs {
		if item.Val == "" {
			continue
		}
		label := item.Key + ":"
		row := fmt.Sprintf("  %s %s", styledPad(dimStyle.Render(label), 22), valueStyle.Render(item.Val))
		sb.WriteString(boxRow(row, iw) + "\n")
	}
	sb.WriteString(boxBot(iw) + "\n\n")
	return sb.String()
}

// appSection2Col renders a section in a 2-column compact layout to save vertical space.
// Each row shows two (key, value) pairs side by side. Scales to 3 columns on very wide terminals.
func appSection2Col(title string, iw int, kvs []kv) string {
	var sb strings.Builder
	// Filter out empty values
	filtered := make([]kv, 0, len(kvs))
	for _, item := range kvs {
		if item.Val != "" {
			filtered = append(filtered, item)
		}
	}
	if len(filtered) == 0 {
		return ""
	}

	sb.WriteString("  " + titleStyle.Render(title) + "\n")
	sb.WriteString(boxTop(iw) + "\n")

	// Decide columns: 3 cols if iw >= 120, else 2
	cols := 2
	if iw >= 120 {
		cols = 3
	}
	// Each cell gets ~ (iw - 4) / cols chars. Label is ~15, value ~rest.
	cellW := (iw - 4) / cols
	if cellW < 28 {
		cellW = 28
		cols = 2
	}
	labelW := 14 // fixed label column width inside each cell

	// Render in row-major order with `cols` items per row
	for i := 0; i < len(filtered); i += cols {
		parts := []string{}
		for j := 0; j < cols && i+j < len(filtered); j++ {
			item := filtered[i+j]
			label := styledPad(dimStyle.Render(item.Key+":"), labelW)
			// Value takes the rest of the cell
			valW := cellW - labelW - 1
			if valW < 10 {
				valW = 10
			}
			val := styledPad(valueStyle.Render(item.Val), valW)
			parts = append(parts, label+" "+val)
		}
		row := "  " + strings.Join(parts, " ")
		sb.WriteString(boxRow(row, iw) + "\n")
	}
	sb.WriteString(boxBot(iw) + "\n")
	return sb.String()
}

// --- Verdict helpers — color a value GREEN/YELLOW/RED based on thresholds ---

// esVerdictPct: higher is worse (heap %, os cpu %). Returns value with colored symbol + verdict.
func esVerdictPct(val string, warn, crit float64) string {
	if val == "" {
		return ""
	}
	v, err := strconv.ParseFloat(strings.TrimSuffix(strings.TrimSuffix(val, "%"), " %"), 64)
	if err != nil {
		return val
	}
	return esVerdictFloat(val+"%", v, warn, crit, true)
}

// esVerdictPctLow: lower is worse (shards active %).
func esVerdictPctLow(val string, warn, crit float64) string {
	if val == "" {
		return ""
	}
	v, err := strconv.ParseFloat(strings.TrimSuffix(val, "%"), 64)
	if err != nil {
		return val
	}
	if v < crit {
		return critStyle.Render("● " + val + "% CRIT")
	}
	if v < warn {
		return warnStyle.Render("● " + val + "% WARN")
	}
	return okStyle.Render("● " + val + "%")
}

// esVerdictCount: integer where 0 is good, > warn is warn, > crit is crit.
func esVerdictCount(val string, warn, crit int) string {
	if val == "" {
		return ""
	}
	v, err := strconv.Atoi(val)
	if err != nil {
		return val
	}
	if v >= crit && crit > 0 {
		return critStyle.Render("● " + val + " CRIT")
	}
	if v > warn {
		return warnStyle.Render("● " + val + " WARN")
	}
	return okStyle.Render("● " + val)
}

// esVerdictInt: validates a count has at least minVal (used for node count).
func esWithVerdictInt(val string, warn, crit int) string {
	if val == "" {
		return ""
	}
	v, err := strconv.Atoi(val)
	if err != nil {
		return val
	}
	if v < crit {
		return critStyle.Render("● " + val + " LOW")
	}
	if v < warn {
		return warnStyle.Render("● " + val)
	}
	return okStyle.Render("● " + val)
}

// esVerdictMs: milliseconds, higher is worse.
func esVerdictMs(val string, warn, crit float64) string {
	if val == "" {
		return ""
	}
	v, err := strconv.ParseFloat(strings.TrimSuffix(val, "ms"), 64)
	if err != nil {
		return val + "ms"
	}
	return esVerdictFloat(fmt.Sprintf("%.0fms", v), v, warn, crit, true)
}

// esVerdictGC: GC collections/min, higher is worse.
func esVerdictGC(val string, warn, crit float64) string {
	if val == "" {
		return ""
	}
	v, err := strconv.ParseFloat(val, 64)
	if err != nil {
		return val
	}
	return esVerdictFloat(val, v, warn, crit, true)
}

// esVerdictFloat: generic helper — colors value based on whether v exceeds warn/crit.
// higherIsWorse=true means v>=crit is RED, v>=warn is YELLOW, else GREEN.
func esVerdictFloat(display string, v, warn, crit float64, higherIsWorse bool) string {
	if higherIsWorse {
		if v >= crit {
			return critStyle.Render("● " + display + " CRIT")
		}
		if v >= warn {
			return warnStyle.Render("● " + display + " WARN")
		}
		return okStyle.Render("● " + display)
	}
	if v <= crit {
		return critStyle.Render("● " + display + " CRIT")
	}
	if v <= warn {
		return warnStyle.Render("● " + display + " WARN")
	}
	return okStyle.Render("● " + display)
}

// esOK marks a neutral/informational value in green (used for healthy counts).
func esOK(val string) string {
	if val == "" {
		return ""
	}
	return okStyle.Render("● " + val)
}

// esMS formats a raw number as milliseconds with no verdict.
func esMS(val string) string {
	if val == "" {
		return ""
	}
	return val + "ms"
}

// esThreePartVerdict shows "active / queue / rejected" with the rejected portion colored.
func esThreePartVerdict(active, queue, rejected string) string {
	if active == "" && queue == "" && rejected == "" {
		return ""
	}
	a := appFmtDash(active)
	q := appFmtDash(queue)
	r := appFmtDash(rejected)
	// Color queue (rising = warn) and rejected (any = crit)
	if rv, err := strconv.Atoi(rejected); err == nil && rv > 0 {
		r = critStyle.Render(r + " REJ")
	} else {
		r = okStyle.Render(r)
	}
	if qv, err := strconv.Atoi(queue); err == nil {
		if qv > 100 {
			q = critStyle.Render(q + " QUE")
		} else if qv > 10 {
			q = warnStyle.Render(q)
		} else {
			q = okStyle.Render(q)
		}
	}
	return fmt.Sprintf("%s / %s / %s", a, q, r)
}

// --- Health banner + suggestions ---

// esRenderHealthBanner shows overall ES health at the top: green/yellow/red badge + summary.
func esRenderHealthBanner(app model.AppInstance, iw int) string {
	var sb strings.Builder
	dm := app.DeepMetrics

	// Aggregate health from key signals
	score := app.HealthScore
	var status, badgeStyle string
	switch {
	case score >= 80:
		status = "HEALTHY"
		badgeStyle = "ok"
	case score >= 50:
		status = "DEGRADED"
		badgeStyle = "warn"
	default:
		status = "CRITICAL"
		badgeStyle = "crit"
	}

	// Build one-liner summary of key issues
	var issues []string
	if s := dm["status"]; s == "red" {
		issues = append(issues, "cluster RED")
	} else if s == "yellow" {
		issues = append(issues, "cluster YELLOW")
	}
	if n, _ := strconv.Atoi(dm["unassigned_shards"]); n > 0 {
		issues = append(issues, fmt.Sprintf("%d unassigned shards", n))
	}
	if n, _ := strconv.Atoi(dm["tp_total_rejected"]); n > 0 {
		issues = append(issues, fmt.Sprintf("%d thread pool rejections", n))
	}
	if n, _ := strconv.Atoi(dm["cb_total_tripped"]); n > 0 {
		issues = append(issues, fmt.Sprintf("%d circuit breaker trips", n))
	}
	if pct, _ := strconv.ParseFloat(strings.TrimSuffix(dm["jvm_heap_used_pct"], "%"), 64); pct > 85 {
		issues = append(issues, fmt.Sprintf("heap %.0f%%", pct))
	}

	// Render banner
	sb.WriteString(boxTop(iw) + "\n")
	var badge string
	summary := "all metrics normal"
	switch badgeStyle {
	case "ok":
		badge = okStyle.Render(fmt.Sprintf("● %s", status))
	case "warn":
		badge = warnStyle.Render(fmt.Sprintf("● %s", status))
	default:
		badge = critStyle.Render(fmt.Sprintf("● %s", status))
	}
	if len(issues) > 0 {
		summary = strings.Join(issues, " · ")
	}
	scoreStr := dimStyle.Render(fmt.Sprintf("score %d/100", score))
	line := fmt.Sprintf("  %s  %s  %s",
		styledPad(badge, 14),
		styledPad(scoreStr, 14),
		valueStyle.Render(summary))
	sb.WriteString(boxRow(line, iw) + "\n")
	if cn := dm["cluster_name"]; cn != "" {
		sub := fmt.Sprintf("  %s  %s",
			dimStyle.Render("Cluster:"),
			valueStyle.Render(cn))
		if v := dm["version"]; v != "" {
			sub += dimStyle.Render("  ·  ES "+v)
		}
		sb.WriteString(boxRow(sub, iw) + "\n")
	}
	sb.WriteString(boxBot(iw) + "\n\n")
	return sb.String()
}

// esRenderSuggestions analyses metrics and produces actionable performance/config suggestions.
func esRenderSuggestions(app model.AppInstance, iw int) string {
	dm := app.DeepMetrics
	var perf []string  // performance suggestions (metric-driven)
	var conf []string  // configuration issues (structural)

	// Performance — derived from live metrics
	if pct, _ := strconv.ParseFloat(strings.TrimSuffix(dm["jvm_heap_used_pct"], "%"), 64); pct > 85 {
		perf = append(perf, fmt.Sprintf("Heap at %.0f%% — raise -Xmx or reduce fielddata/query cache", pct))
	} else if pct > 75 {
		perf = append(perf, fmt.Sprintf("Heap at %.0f%% — monitor, near pressure threshold", pct))
	}
	if n, _ := strconv.Atoi(dm["fielddata_evictions"]); n > 10 {
		perf = append(perf, fmt.Sprintf("Fielddata evictions (%d) — raise indices.fielddata.cache.size or use doc_values", n))
	}
	if n, _ := strconv.Atoi(dm["tp_write_rejected"]); n > 0 {
		perf = append(perf, fmt.Sprintf("Write pool rejections (%d) — bulk clients overloading, increase thread_pool.write.queue_size or slow down ingest", n))
	}
	if n, _ := strconv.Atoi(dm["tp_search_rejected"]); n > 0 {
		perf = append(perf, fmt.Sprintf("Search rejections (%d) — queries exceed thread_pool.search.queue_size, add replicas or tune queries", n))
	}
	if n, _ := strconv.Atoi(dm["cb_total_tripped"]); n > 0 {
		perf = append(perf, fmt.Sprintf("Circuit breaker trips (%d) — queries too large, use search.max_buckets or reduce request size", n))
	}
	if n, _ := strconv.Atoi(dm["pending_tasks_count"]); n > 10 {
		perf = append(perf, fmt.Sprintf("Pending cluster tasks (%d) — master node overloaded, check logs on master", n))
	}
	if young, _ := strconv.ParseFloat(dm["gc_young_per_min"], 64); young > 120 {
		perf = append(perf, fmt.Sprintf("Young GC frequency high (%.0f/min) — allocation pressure, reduce query result sizes or scroll batches", young))
	}
	if old, _ := strconv.ParseFloat(dm["gc_old_per_min"], 64); old > 3 {
		perf = append(perf, fmt.Sprintf("Old GC frequency high (%.0f/min) — major heap pressure, likely needs more RAM", old))
	}
	if p95, _ := strconv.ParseFloat(dm["gc_old_p95_approx_ms"], 64); p95 > 1000 {
		perf = append(perf, fmt.Sprintf("Old GC p95 %.0fms — indexing/search stalling during major GC", p95))
	}

	// Configuration issues — structural
	if n, _ := strconv.Atoi(dm["shards_oversized"]); n > 0 {
		conf = append(conf, fmt.Sprintf("%d shard(s) >50GB — split large indices, target 20-40GB per shard", n))
	}
	if n, _ := strconv.Atoi(dm["shards_undersized"]); n >= 10 {
		conf = append(conf, fmt.Sprintf("%d shard(s) <1GB — too many small shards wastes resources, use ILM rollover with larger window", n))
	}
	if total, _ := strconv.Atoi(dm["indices_total_cat"]); total > 1000 {
		conf = append(conf, fmt.Sprintf("%d indices in cluster — setup Index Lifecycle Management (ILM) for retention/rollover", total))
	}
	if n, _ := strconv.Atoi(dm["indices_aging_90d"]); n > 50 {
		conf = append(conf, fmt.Sprintf("%d indices older than 90 days — use ILM to cold/delete them", n))
	}
	if n, _ := strconv.Atoi(dm["indices_empty"]); n > 0 {
		conf = append(conf, fmt.Sprintf("%d empty indices — delete if unused, they still consume cluster state", n))
	}
	if n, _ := strconv.Atoi(dm["shards_unassigned_cat"]); n > 0 {
		conf = append(conf, fmt.Sprintf("%d unassigned shards — check cluster.allocation.explain for reason (disk full? node missing?)", n))
	}
	if nodes, _ := strconv.Atoi(dm["number_of_nodes"]); nodes == 1 {
		conf = append(conf, "Single-node cluster — no redundancy, yellow shards are expected but no high availability")
	}
	if s := dm["status"]; s == "red" {
		conf = append(conf, "Cluster status RED — primary shards missing, DATA LOSS risk, investigate immediately")
	}

	if len(perf) == 0 && len(conf) == 0 {
		return ""
	}

	var sb strings.Builder
	if len(perf) > 0 {
		sb.WriteString("  " + titleStyle.Render("PERFORMANCE SUGGESTIONS") + "\n")
		sb.WriteString(boxTop(iw) + "\n")
		for i, s := range perf {
			if i >= 6 {
				break
			}
			row := fmt.Sprintf("  %s %s",
				warnStyle.Render(fmt.Sprintf("%d.", i+1)),
				valueStyle.Render(s))
			sb.WriteString(boxRow(row, iw) + "\n")
		}
		sb.WriteString(boxBot(iw) + "\n\n")
	}
	if len(conf) > 0 {
		sb.WriteString("  " + titleStyle.Render("CONFIGURATION ISSUES") + "\n")
		sb.WriteString(boxTop(iw) + "\n")
		for i, s := range conf {
			if i >= 6 {
				break
			}
			row := fmt.Sprintf("  %s %s",
				orangeStyle.Render(fmt.Sprintf("%d.", i+1)),
				valueStyle.Render(s))
			sb.WriteString(boxRow(row, iw) + "\n")
		}
		sb.WriteString(boxBot(iw) + "\n\n")
	}
	return sb.String()
}

func appFmtMem(mb float64) string {
	if mb >= 1024 {
		return fmt.Sprintf("%.1fG", mb/1024)
	}
	return fmt.Sprintf("%.0fM", mb)
}

func appFmtPort(port int) string {
	if port > 0 {
		return fmt.Sprintf("%d", port)
	}
	return "—"
}

func appFmtDash(s string) string {
	if s == "" {
		return "—"
	}
	return s
}

func appFmtBytesShort(b float64) string {
	switch {
	case b >= 1e12:
		return fmt.Sprintf("%.1fT", b/1e12)
	case b >= 1e9:
		return fmt.Sprintf("%.1fG", b/1e9)
	case b >= 1e6:
		return fmt.Sprintf("%.1fM", b/1e6)
	case b >= 1e3:
		return fmt.Sprintf("%.1fK", b/1e3)
	default:
		return fmt.Sprintf("%.0fB", b)
	}
}

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

// renderAppRCAFindings renders the per-app RCA panel for one app instance.
// Shows only findings whose .App matches this instance's ID. Sorted crit →
// warn → info by the engine; we render in the same order. Each finding
// gets a colored bullet, headline, detail line, and (when available) a
// recommended action.
//
// Cost: pure string assembly — never spawns subprocesses.
func renderAppRCAFindings(app model.AppInstance, all []model.AppRCAFinding, iw int) string {
	var mine []model.AppRCAFinding
	for _, f := range all {
		if f.App == app.ID {
			mine = append(mine, f)
		}
	}
	if len(mine) == 0 {
		return ""
	}

	var sb strings.Builder
	sb.WriteString("  " + titleStyle.Render(fmt.Sprintf("RCA FINDINGS — %s (%d)", app.DisplayName, len(mine))) + "\n")
	sb.WriteString(boxTop(iw) + "\n")
	for _, f := range mine {
		var bullet, sevStyle string
		switch f.Severity {
		case "crit":
			bullet = critStyle.Render("●")
			sevStyle = critStyle.Render("CRIT")
		case "warn":
			bullet = warnStyle.Render("●")
			sevStyle = warnStyle.Render("WARN")
		default:
			bullet = okStyle.Render("●")
			sevStyle = okStyle.Render("INFO")
		}
		head := fmt.Sprintf("  %s %s  %s", bullet, sevStyle, valueStyle.Render(f.Title))
		sb.WriteString(boxRow(head, iw) + "\n")
		if f.Detail != "" {
			sb.WriteString(boxRow("       "+dimStyle.Render(f.Detail), iw) + "\n")
		}
		if f.Action != "" {
			sb.WriteString(boxRow("       "+okStyle.Render("→ "+f.Action), iw) + "\n")
		}
		sb.WriteString(boxRow("", iw) + "\n")
	}
	sb.WriteString(boxBot(iw) + "\n")
	return sb.String()
}
