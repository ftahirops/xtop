package ui

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/ftahirops/xtop/collector/phpfpm"
	"github.com/ftahirops/xtop/model"
)

// renderPHPFPMPage shows two modes:
//
//   list   (default): compact site list, one row per site, navigate with j/k
//   detail (Enter):   full per-site breakdown — issues, resources, traffic,
//                     top IPs, hot URIs, currently-running scripts, slow log,
//                     filesystem-scan findings
//
// Keys handled in ui/app.go:
//   j/k or ↑/↓   move site cursor (list) or scroll (detail)
//   Enter        toggle detail / back to list
//   R            force-refresh PHP-FPM data
//   D            deep filesystem scan (focused site, or all)
func renderPHPFPMPage(snap *model.Snapshot, selectedIdx int, detailMode bool, scrollY int, width, height int) string {
	var sb strings.Builder
	iw := pageInnerW(width)

	sb.WriteString(titleStyle.Render("PHP-FPM — PER-SITE ANALYSIS"))
	sb.WriteString("\n")
	// Status banner: shows last refresh age + any queued refresh/deep-scan.
	sb.WriteString("  " + renderPHPFPMStatusLine())
	sb.WriteString("\n")
	sb.WriteString(dimStyle.Render("  R = force refresh now  ·  D = deep filesystem scan  ·  Enter = expand  ·  j/k = move"))
	sb.WriteString("\n\n")

	if snap == nil || (len(snap.Global.PHPFPM.Masters) == 0 && len(snap.Global.PHPFPM.Apps) == 0) {
		pad := (iw - 32) / 2
		if pad < 0 {
			pad = 0
		}
		sb.WriteString(strings.Repeat(" ", pad) + dimStyle.Render("No PHP-FPM processes detected.") + "\n")
		sb.WriteString(pageFooter("Press 0 for Overview"))
		return sb.String()
	}

	// Always show the MASTERS strip at top — useful context.
	renderPHPFPMMasters(&sb, snap.Global.PHPFPM.Masters)
	sb.WriteString("\n")

	apps := snap.Global.PHPFPM.Apps
	if len(apps) == 0 {
		sb.WriteString(dimStyle.Render("  no sites with activity yet"))
		sb.WriteString("\n")
		sb.WriteString(pageFooter("R:refresh"))
		return sb.String()
	}

	if !detailMode {
		renderPHPFPMList(&sb, apps, selectedIdx, iw)
		sb.WriteString("\n")
		sb.WriteString(pageFooter("Enter:detail  j/k:move  R:refresh  D:deep-scan-all"))
	} else {
		if selectedIdx >= len(apps) {
			selectedIdx = len(apps) - 1
		}
		a := apps[selectedIdx]
		renderPHPFPMDetail(&sb, &a, scrollY, iw, height)
		sb.WriteString("\n")
		sb.WriteString(pageFooter("Enter:back  j/k:scroll  R:refresh  D:deep-scan-this-site"))
	}
	return sb.String()
}

// renderPHPFPMStatusLine produces the single-line state banner shown
// under the title — answers "is my keystroke being processed?" and
// "how fresh is this data?".
func renderPHPFPMStatusLine() string {
	last, durMs := phpfpm.LastRefreshStats()
	var parts []string
	if last.IsZero() {
		parts = append(parts, dimStyle.Render("waiting for first refresh ..."))
	} else {
		age := time.Since(last)
		ageStr := fmt.Sprintf("%ds ago", int(age.Seconds()))
		if age > 60*time.Second {
			ageStr = fmt.Sprintf("%dm %ds ago", int(age.Minutes()), int(age.Seconds())%60)
		}
		parts = append(parts, dimStyle.Render(fmt.Sprintf("last refresh: %s (took %d ms)", ageStr, durMs)))
	}
	if phpfpm.RefreshPending() {
		parts = append(parts, warnStyle.Render("⟳ REFRESH QUEUED (will run on next tick)"))
	}
	if site := phpfpm.DeepScanPending(); site != "" {
		label := "this site"
		if site == "*" {
			label = "ALL sites"
		} else {
			label = site
		}
		parts = append(parts, warnStyle.Render("⟳ DEEP SCAN QUEUED for "+label))
	}
	return strings.Join(parts, "  ·  ")
}

func renderPHPFPMMasters(sb *strings.Builder, masters []model.PHPFPMMaster) {
	sb.WriteString(headerStyle.Render("  MASTERS"))
	sb.WriteString("\n")
	sort.Slice(masters, func(i, j int) bool {
		if masters[i].PHPVersion != masters[j].PHPVersion {
			return masters[i].PHPVersion < masters[j].PHPVersion
		}
		return masters[i].PoolName < masters[j].PoolName
	})
	fmt.Fprintf(sb, "  %-3s  %-32s  %7s  %-50s  %s\n",
		"PHP", "POOL", "WORKERS", "LISTEN", "STATE")
	sb.WriteString(dimStyle.Render("  "+strings.Repeat("─", 110)) + "\n")
	for _, m := range masters {
		fmt.Fprintf(sb, "  %-3s  %-32s  %7d  %-50s  %s\n",
			defaultPHP(m.PHPVersion),
			truncPHP(m.PoolName, 32),
			m.WorkerCount,
			truncPHP(m.ListenAddr, 50),
			renderMasterStateTUI(m))
	}
}

func renderMasterStateTUI(m model.PHPFPMMaster) string {
	switch m.State {
	case "ok":
		return okStyle.Render("ok")
	case "no-status":
		return dimStyle.Render("no-status")
	case "no-socket":
		return critStyle.Render("no-socket")
	case "connect-failed":
		return critStyle.Render("unreachable")
	default:
		if m.StatusOK {
			return okStyle.Render("ok")
		}
		return dimStyle.Render("unknown")
	}
}

func renderPHPFPMList(sb *strings.Builder, apps []model.PHPFPMApp, sel, iw int) {
	sb.WriteString(headerStyle.Render(fmt.Sprintf("  SITES  (%d total · cursor at row %d)", len(apps), sel+1)))
	sb.WriteString("\n")
	const (
		colSite    = 30
		colPHP     = 5
		colIssues  = 8
		colWorkers = 8
		colRun     = 4
		colCPU     = 6
		colRSS     = 8
		colReqs    = 8
		colErr     = 6
	)
	hdr := fmt.Sprintf("  %-*s %-*s %-*s %*s %*s %*s %*s %*s %*s   TOP URI",
		colSite, "SITE",
		colPHP, "PHP",
		colIssues, "ISSUES",
		colWorkers, "WORKERS",
		colRun, "RUN",
		colCPU, "CPU%",
		colRSS, "RSS MB",
		colReqs, "REQS",
		colErr, "4XX",
	)
	sb.WriteString(headerStyle.Render(hdr))
	sb.WriteString("\n")
	sb.WriteString(dimStyle.Render(strings.Repeat("─", minInt(iw, len(hdr)+20))))
	sb.WriteString("\n")

	for i, a := range apps {
		marker := "  "
		row := buildSiteRow(a)
		if i == sel {
			marker = warnStyle.Render("▶ ")
			row = boldRow(row)
		}
		sb.WriteString(marker + row + "\n")
	}
}

func buildSiteRow(a model.PHPFPMApp) string {
	issueTag := dimStyle.Render("-")
	critCount, warnCount := 0, 0
	for _, iss := range a.Issues {
		switch iss.Severity {
		case "crit":
			critCount++
		case "warn":
			warnCount++
		}
	}
	switch {
	case a.DocRootMissing:
		issueTag = dimStyle.Render("ghost")
	case critCount > 0:
		issueTag = critStyle.Render(fmt.Sprintf("%dC %dW", critCount, warnCount))
	case warnCount > 0:
		issueTag = warnStyle.Render(fmt.Sprintf("0C %dW", warnCount))
	}

	cpuStr := fmt.Sprintf("%.1f", a.CPUPct)
	if a.CPUPct >= 50 {
		cpuStr = warnStyle.Render(cpuStr)
	} else if a.CPUPct < 1 {
		cpuStr = dimStyle.Render(cpuStr)
	}

	err4 := fmt.Sprintf("%d", a.Status4xx)
	if a.Status4xx >= 100 {
		err4 = warnStyle.Render(err4)
	}

	const (
		colSite    = 30
		colPHP     = 5
		colIssues  = 8
		colWorkers = 8
		colRun     = 4
		colCPU     = 6
		colRSS     = 8
		colReqs    = 8
		colErr     = 6
	)
	row := fmt.Sprintf("%-*s %-*s %s %*d %*d %s %*d %*s %s   %s",
		colSite, truncPHP(a.App, colSite),
		colPHP, defaultPHP(a.PHPVersion),
		styledPad(issueTag, colIssues),
		colWorkers, a.WorkerCount,
		colRun, a.RunningCount,
		styledPad(cpuStr, colCPU),
		colRSS, a.RSSKB/1024,
		colReqs, fmtIntCommas(int64(a.AccessReqs)),
		styledPad(err4, colErr),
		truncPHP(a.TopURI, 40),
	)
	return row
}

// renderPHPFPMDetail mirrors the cmd/phpfpm.go per-site output, with
// scroll support so long sections work in the TUI.
func renderPHPFPMDetail(sb *strings.Builder, a *model.PHPFPMApp, scrollY, iw, height int) {
	if a.DocRootMissing {
		renderPHPFPMGhostDetail(sb, a, scrollY, iw, height)
		return
	}
	var raw strings.Builder
	// Compact site header — single line.
	raw.WriteString(fmt.Sprintf("  %s   %s   %s\n",
		headerStyle.Render(a.App),
		dimStyle.Render("PHP "+defaultPHP(a.PHPVersion)),
		dimStyle.Render(fmt.Sprintf("%d workers · %s reqs · %.0fms avg",
			a.WorkerCount, fmtIntCommas(int64(a.AccessReqs)), a.AvgDurationMs)),
	))
	if a.DocRoot != "" {
		raw.WriteString(dimStyle.Render("  "+a.DocRoot) + "\n")
	}
	if a.AccessLog != "" {
		raw.WriteString(dimStyle.Render("  log:     " + a.AccessLog))
		raw.WriteString("\n")
	}

	// Compact issues
	if len(a.Issues) > 0 {
		raw.WriteString("\n")
		for _, iss := range a.Issues {
			raw.WriteString(fmt.Sprintf("  %s  %s\n", issueTag(iss.Severity), iss.Message))
			if iss.Action != "" {
				raw.WriteString("        " + dimStyle.Render("→ "+iss.Action) + "\n")
			}
		}
	}

	// RESOURCES + TRAFFIC side by side.
	raw.WriteString("\n")
	leftRows := [][2]string{
		{"workers", fmt.Sprintf("%d total  (%d run · %d idle)", a.WorkerCount, a.RunningCount, a.IdleCount)},
		{"CPU", fmt.Sprintf("%.1f%% of one core", a.CPUPct)},
		{"RAM", fmt.Sprintf("%s MB", fmtIntCommas(a.RSSKB/1024))},
		{"disk I/O", fmt.Sprintf("read %s/s · write %s/s", humanBytesPHP(a.DiskReadBps), humanBytesPHP(a.DiskWriteBps))},
		{"avg req", fmt.Sprintf("%.1f ms", a.AvgDurationMs)},
		{"lifetime", fmt.Sprintf("%s reqs", fmtIntCommas(a.RequestsTotal))},
	}
	rightRows := [][2]string{
		{"requests", fmt.Sprintf("%s  (%s)", fmtIntCommas(int64(a.AccessReqs)), humanBytesUnitPHP(a.AccessBytes))},
		{"2xx", fmtPctPHP(a.Status2xx, a.AccessReqs, "")},
		{"3xx", fmtPctPHP(a.Status3xx, a.AccessReqs, "")},
		{"4xx", fmtPctPHP(a.Status4xx, a.AccessReqs, "yellow")},
		{"5xx", fmtPctPHP(a.Status5xx, a.AccessReqs, "red")},
	}
	renderTwoColPanelTUI(&raw, "RESOURCES", leftRows, "TRAFFIC", rightRows)

	// TOP IPs — single-line aligned table
	if len(a.TopIPs) > 0 {
		raw.WriteString("\n  " + headerStyle.Render("TOP CLIENT IPs") + "\n")
		raw.WriteString(fmt.Sprintf("    %-18s %7s  %4s  %-22s  %s\n",
			"IP", "HITS", "%", "PROVIDER", "REVERSE DNS"))
		raw.WriteString(dimStyle.Render("    "+strings.Repeat("─", minInt(iw-4, 120))) + "\n")
		for i, h := range a.TopIPs {
			if i >= 15 {
				raw.WriteString(fmt.Sprintf("    ... +%d more IPs\n", len(a.TopIPs)-i))
				break
			}
			share := 0
			if a.AccessReqs > 0 {
				share = h.Hits * 100 / a.AccessReqs
			}
			provider := h.Provider
			if provider != "" && h.Country != "" {
				provider = provider + " · " + h.Country
			}
			if provider == "" {
				provider = "-"
			}
			rdns := h.RDNS
			if rdns == "" {
				rdns = dimStyle.Render("(no rDNS)")
			}
			raw.WriteString(fmt.Sprintf("    %-18s %7s  %3d%%  %-22s  %s\n",
				h.IP, fmtIntCommas(int64(h.Hits)), share,
				truncPHP(provider, 22), rdns))
		}
	}

	// HOT URIs
	if len(a.TopAccessURIs) > 0 {
		raw.WriteString("\n  " + headerStyle.Render("HOT URIs") + "  " + dimStyle.Render("(? = scanner-probe pattern)") + "\n")
		raw.WriteString(fmt.Sprintf("    %s %7s  %s\n", " ", "HITS", "URI"))
		raw.WriteString(dimStyle.Render("    "+strings.Repeat("─", minInt(iw-4, 120))) + "\n")
		for i, h := range a.TopAccessURIs {
			if i >= 15 {
				raw.WriteString(fmt.Sprintf("    ... +%d more URIs\n", len(a.TopAccessURIs)-i))
				break
			}
			marker := " "
			if isProbePath(h.URI) {
				marker = warnStyle.Render("?")
			}
			raw.WriteString(fmt.Sprintf("    %s %7s  %s\n",
				marker, fmtIntCommas(int64(h.Hits)), h.URI))
		}
	}

	// TOP IP/URI PAIRS — "this IP hit that URL"
	if len(a.TopIPURIs) > 0 {
		raw.WriteString("\n  " + headerStyle.Render("WHO HIT WHAT  (top IP/URL combinations)") + "\n")
		raw.WriteString(fmt.Sprintf("    %7s  %-18s  %s\n", "HITS", "IP", "URI"))
		raw.WriteString(dimStyle.Render("    "+strings.Repeat("─", minInt(iw-4, 120))) + "\n")
		for i, p := range a.TopIPURIs {
			if i >= 15 {
				raw.WriteString(fmt.Sprintf("    ... +%d more combinations\n", len(a.TopIPURIs)-i))
				break
			}
			raw.WriteString(fmt.Sprintf("    %7d  %-18s  %s\n",
				p.Hits, p.IP, p.URI))
		}
	}

	// CURRENTLY RUNNING SCRIPTS
	if len(a.TopRunningScripts) > 0 {
		raw.WriteString("\n  " + headerStyle.Render("CURRENTLY RUNNING SCRIPTS") + "\n")
		raw.WriteString(fmt.Sprintf("    %7s  %s\n", "WORKERS", "SCRIPT"))
		raw.WriteString(dimStyle.Render("    "+strings.Repeat("─", minInt(iw-4, 120))) + "\n")
		for _, h := range a.TopRunningScripts {
			raw.WriteString(fmt.Sprintf("    %7d  %s\n", h.Hits, h.Script))
		}
	}

	// FILESYSTEM SCAN
	if len(a.FSWebShells) > 0 || len(a.FSBinaries) > 0 {
		raw.WriteString("\n  " + headerStyle.Render("FILESYSTEM SCAN  (docroot)") + "\n")
		raw.WriteString(fmt.Sprintf("    %-8s %8s  %-16s  %s\n", "KIND", "SIZE B", "MODIFIED", "PATH / SIGNAL"))
		raw.WriteString(dimStyle.Render("    "+strings.Repeat("─", minInt(iw-4, 120))) + "\n")
		for i, f := range a.FSWebShells {
			if i >= 8 {
				raw.WriteString(fmt.Sprintf("    ... +%d more shell hits\n", len(a.FSWebShells)-i))
				break
			}
			raw.WriteString(fmt.Sprintf("    %s %8d  %-16s  %s\n",
				critStyle.Render("[shell] "), f.Size, f.ModTime.Format("2006-01-02 15:04"), f.Path))
			raw.WriteString(fmt.Sprintf("                                                %s\n", dimStyle.Render("→ "+f.Signal)))
		}
		for i, f := range a.FSBinaries {
			if i >= 8 {
				raw.WriteString(fmt.Sprintf("    ... +%d more binary hits\n", len(a.FSBinaries)-i))
				break
			}
			raw.WriteString(fmt.Sprintf("    %s %8d  %-16s  %s\n",
				critStyle.Render("[binary]"), f.Size, f.ModTime.Format("2006-01-02 15:04"), f.Path))
			raw.WriteString(fmt.Sprintf("                                                %s\n", dimStyle.Render("→ "+f.Signal)))
		}
	}

	// SLOW SCRIPTS
	if a.SlowBlocksTotal > 0 {
		raw.WriteString("\n  " + headerStyle.Render(fmt.Sprintf("SLOW SCRIPTS  (%d events total)", a.SlowBlocksTotal)) + "\n")
		raw.WriteString(fmt.Sprintf("    %7s  %s\n", "EVENTS", "SCRIPT"))
		raw.WriteString(dimStyle.Render("    "+strings.Repeat("─", minInt(iw-4, 120))) + "\n")
		for i, h := range a.TopSlowScripts {
			if i >= 12 {
				raw.WriteString(fmt.Sprintf("    ... +%d more scripts\n", len(a.TopSlowScripts)-i))
				break
			}
			raw.WriteString(fmt.Sprintf("    %7s  %s\n",
				fmtIntCommas(int64(h.Hits)), h.Script))
		}
	}

	// BLOCKING PHP CALLS — analyzed with severity + optimization tip.
	if len(a.TopSlowFns) > 0 {
		raw.WriteString("\n  " + headerStyle.Render("BLOCKING PHP CALLS") + "  " +
			dimStyle.Render("(why each call shows up + how to optimize)") + "\n")
		raw.WriteString(fmt.Sprintf("    %-10s %-28s %s\n", "SEVERITY", "FUNCTION (hits)", "EXPLANATION / FIX"))
		raw.WriteString(dimStyle.Render("    "+strings.Repeat("─", minInt(iw-4, 120))) + "\n")
		for i, f := range a.TopSlowFns {
			if i >= 10 {
				break
			}
			tag := severityTagTUI(f.Severity)
			fnCell := fmt.Sprintf("%s (%dx)", f.Function, f.Hits)
			raw.WriteString(fmt.Sprintf("    %s  %-28s %s\n", tag, fnCell, f.Explanation))
			if f.Optimize != "" {
				raw.WriteString(fmt.Sprintf("    %-10s %-28s %s\n", "", "", dimStyle.Render("→ "+f.Optimize)))
			}
		}
	}

	// Apply scroll: drop first `scrollY` lines.
	lines := strings.Split(raw.String(), "\n")
	if scrollY > 0 && scrollY < len(lines) {
		lines = lines[scrollY:]
	}
	// Cap to fit in the available height.
	visible := height - 10
	if visible < 5 {
		visible = 5
	}
	if len(lines) > visible {
		lines = lines[:visible]
		lines = append(lines, dimStyle.Render(fmt.Sprintf("    (... %d more lines below — j/down to scroll ...)", len(strings.Split(raw.String(), "\n"))-scrollY-visible)))
	}
	sb.WriteString(strings.Join(lines, "\n"))
}

// renderPHPFPMGhostDetail is the TUI equivalent of cmd's renderGhostSite —
// when a vhost is configured but the docroot is gone, show only the
// cleanup hint + the 404 noise summary + top attacker IPs.
func renderPHPFPMGhostDetail(sb *strings.Builder, a *model.PHPFPMApp, scrollY, iw, height int) {
	var raw strings.Builder
	raw.WriteString(headerStyle.Render("  "+a.App) + "  " + warnStyle.Render("[GHOST SITE — docroot missing]") + "\n")
	if a.DocRoot != "" {
		raw.WriteString(dimStyle.Render("  docroot: "+a.DocRoot) + "  " + warnStyle.Render("(does not exist on disk)") + "\n")
	}
	if a.AccessLog != "" {
		raw.WriteString(dimStyle.Render("  log:     "+a.AccessLog) + "\n")
	}

	raw.WriteString("\n  " + headerStyle.Render("WHAT THIS MEANS") + "\n")
	raw.WriteString("    nginx still listens for this domain but every request returns 404.\n")
	raw.WriteString("    The traffic below is all 404 noise — no PHP runs, no real site exists.\n")
	raw.WriteString("    Slow-log entries may be historical from when the site was alive.\n")

	raw.WriteString("\n  " + headerStyle.Render("CLEANUP") + "\n")
	raw.WriteString(dimStyle.Render("    # remove the stale nginx vhost so the noise stops") + "\n")
	raw.WriteString(fmt.Sprintf("    rm /www/server/panel/vhost/nginx/%s.conf\n", a.App))
	raw.WriteString("    /www/server/nginx/sbin/nginx -s reload\n")
	if a.AccessLog != "" {
		raw.WriteString(dimStyle.Render("    # optional: archive the old access log") + "\n")
		raw.WriteString(fmt.Sprintf("    mv %s /root/%s.log.archive\n", a.AccessLog, a.App))
	}

	if a.AccessReqs > 0 {
		raw.WriteString("\n  " + headerStyle.Render("404 NOISE") + "\n")
		pct4 := 0
		if a.AccessReqs > 0 {
			pct4 = a.Status4xx * 100 / a.AccessReqs
		}
		raw.WriteString(fmt.Sprintf("    %s requests · %s bytes · %d%% are 4xx errors\n",
			fmtIntCommas(int64(a.AccessReqs)), fmtIntCommas(a.AccessBytes), pct4))
	}

	if len(a.TopIPs) > 0 {
		raw.WriteString("\n  " + headerStyle.Render("TOP IPs HITTING THIS GHOST") + "\n")
		raw.WriteString(fmt.Sprintf("    %-18s %7s  %4s  %-22s  %s\n",
			"IP", "HITS", "%", "PROVIDER", "REVERSE DNS"))
		raw.WriteString(dimStyle.Render("    "+strings.Repeat("─", minInt(iw-4, 120))) + "\n")
		for i, h := range a.TopIPs {
			if i >= 15 {
				raw.WriteString(fmt.Sprintf("    ... +%d more\n", len(a.TopIPs)-i))
				break
			}
			share := 0
			if a.AccessReqs > 0 {
				share = h.Hits * 100 / a.AccessReqs
			}
			provider := h.Provider
			if provider != "" && h.Country != "" {
				provider = provider + " · " + h.Country
			}
			if provider == "" {
				provider = "-"
			}
			rdns := h.RDNS
			if rdns == "" {
				rdns = dimStyle.Render("(no rDNS)")
			}
			raw.WriteString(fmt.Sprintf("    %-18s %7s  %3d%%  %-22s  %s\n",
				h.IP, fmtIntCommas(int64(h.Hits)), share, truncPHP(provider, 22), rdns))
		}
	}

	if len(a.WebShellHits) > 0 {
		raw.WriteString("\n  " + headerStyle.Render("HISTORICAL WEB-SHELL EVIDENCE") + "  " + dimStyle.Render("(from slow log)") + "\n")
		seen := map[string]bool{}
		for _, s := range a.WebShellHits {
			key := s.Script + "|" + s.Function
			if seen[key] {
				continue
			}
			seen[key] = true
			raw.WriteString(fmt.Sprintf("    %s in %s\n", warnStyle.Render(s.Function+"()"), s.Script))
		}
	}

	// Apply scroll.
	lines := strings.Split(raw.String(), "\n")
	if scrollY > 0 && scrollY < len(lines) {
		lines = lines[scrollY:]
	}
	visible := height - 10
	if visible < 5 {
		visible = 5
	}
	if len(lines) > visible {
		lines = lines[:visible]
		lines = append(lines, dimStyle.Render(fmt.Sprintf("    (... %d more lines below — j to scroll ...)",
			len(strings.Split(raw.String(), "\n"))-scrollY-visible)))
	}
	sb.WriteString(strings.Join(lines, "\n"))
}

// ── small helpers (named to avoid colliding with existing ui/ helpers) ──

func defaultPHP(s string) string {
	if s == "" {
		return "?"
	}
	return s
}

func truncPHP(s string, n int) string {
	if n <= 0 {
		return ""
	}
	if len(s) <= n {
		return s
	}
	if n < 3 {
		return s[:n]
	}
	return s[:n-2] + ".."
}

func shortPathPHP(p string) string {
	parts := strings.Split(p, "/")
	if len(parts) < 4 {
		return p
	}
	return ".../" + strings.Join(parts[len(parts)-3:], "/")
}

func fmtIntCommas(n int64) string {
	s := fmt.Sprintf("%d", n)
	if n < 1000 && n > -1000 {
		return s
	}
	neg := false
	if s[0] == '-' {
		neg = true
		s = s[1:]
	}
	var out []byte
	for i, c := range []byte(s) {
		if i > 0 && (len(s)-i)%3 == 0 {
			out = append(out, ',')
		}
		out = append(out, c)
	}
	if neg {
		return "-" + string(out)
	}
	return string(out)
}

func humanBytesPHP(bps float64) string {
	const k = 1024.0
	switch {
	case bps < k:
		return fmt.Sprintf("%.0f B", bps)
	case bps < k*k:
		return fmt.Sprintf("%.1f KB", bps/k)
	case bps < k*k*k:
		return fmt.Sprintf("%.1f MB", bps/(k*k))
	default:
		return fmt.Sprintf("%.1f GB", bps/(k*k*k))
	}
}

func issueTag(sev string) string {
	switch sev {
	case "crit":
		return critStyle.Render("[CRIT]")
	case "warn":
		return warnStyle.Render("[WARN]")
	case "info":
		return valueStyle.Render("[INFO]")
	default:
		return "[" + sev + "]"
	}
}

func colorIfErrPHP(n int, is5xx bool) string {
	s := fmtIntCommas(int64(n))
	if n == 0 {
		return s
	}
	if is5xx {
		return critStyle.Render(s)
	}
	if n > 50 {
		return warnStyle.Render(s)
	}
	return s
}

func bold(s string) string { return "\x1b[1m" + s + "\x1b[0m" }

func boldRow(s string) string { return "\x1b[1m" + s + "\x1b[0m" }

// renderTwoColPanelTUI renders two key/value panels side-by-side.
func renderTwoColPanelTUI(sb *strings.Builder, leftLabel string, left [][2]string, rightLabel string, right [][2]string) {
	const colWidth = 60
	keyW := 10
	for _, kv := range left {
		if len(kv[0]) > keyW {
			keyW = len(kv[0])
		}
	}
	keyR := 10
	for _, kv := range right {
		if len(kv[0]) > keyR {
			keyR = len(kv[0])
		}
	}
	sb.WriteString(fmt.Sprintf("  %s%s%s\n",
		headerStyle.Render(leftLabel),
		strings.Repeat(" ", maxIntPHP(0, colWidth-len(leftLabel))),
		headerStyle.Render(rightLabel)))
	sb.WriteString(fmt.Sprintf("  %s%s%s\n",
		dimStyle.Render(strings.Repeat("─", colWidth-2)),
		"  ",
		dimStyle.Render(strings.Repeat("─", 50))))
	rows := len(left)
	if len(right) > rows {
		rows = len(right)
	}
	for i := 0; i < rows; i++ {
		lk, lv := "", ""
		if i < len(left) {
			lk, lv = left[i][0], left[i][1]
		}
		rk, rv := "", ""
		if i < len(right) {
			rk, rv = right[i][0], right[i][1]
		}
		leftCol := ""
		if lk != "" {
			leftCol = fmt.Sprintf("%-*s  %s", keyW, lk, lv)
		}
		if visLenTUI(leftCol) < colWidth {
			leftCol += strings.Repeat(" ", colWidth-visLenTUI(leftCol))
		}
		rightCol := ""
		if rk != "" {
			rightCol = fmt.Sprintf("%-*s  %s", keyR, rk, rv)
		}
		sb.WriteString(fmt.Sprintf("  %s%s\n", leftCol, rightCol))
	}
}

func visLenTUI(s string) int {
	n := 0
	inEsc := false
	for _, c := range s {
		if inEsc {
			if c == 'm' {
				inEsc = false
			}
			continue
		}
		if c == 0x1b {
			inEsc = true
			continue
		}
		n++
	}
	return n
}

func maxIntPHP(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func fmtPctPHP(n, total int, color string) string {
	pct := 0
	if total > 0 {
		pct = n * 100 / total
	}
	s := fmt.Sprintf("%-7s (%2d%%)", fmtIntCommas(int64(n)), pct)
	if n == 0 {
		return s
	}
	switch color {
	case "yellow":
		return warnStyle.Render(s)
	case "red":
		return critStyle.Render(s)
	}
	return s
}

func humanBytesUnitPHP(n int64) string {
	const k = 1024.0
	f := float64(n)
	switch {
	case f < k:
		return fmt.Sprintf("%d B", n)
	case f < k*k:
		return fmt.Sprintf("%.1f KB", f/k)
	case f < k*k*k:
		return fmt.Sprintf("%.1f MB", f/(k*k))
	default:
		return fmt.Sprintf("%.1f GB", f/(k*k*k))
	}
}

func severityTagTUI(sev string) string {
	switch sev {
	case "critical":
		return critStyle.Render("[critical]")
	case "heavy":
		return warnStyle.Render("[heavy   ]")
	default:
		return dimStyle.Render("[normal  ]")
	}
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// isProbePath returns true if a URI looks like a known scanner / attacker
// probe (shell upload, env leak, common backdoor names).
func isProbePath(p string) bool {
	p = strings.ToLower(p)
	probes := []string{
		"/.env", "/wp-config", "/.git/", "/.aws/",
		"/legacy.php", "/short.php", "/bulk.php",
		"/shell.php", "/cmd.php", "/up.php", "/x.php", "/c.php",
		"/admin.php", "/login.php", "/test.php",
		"/phpinfo", "/phpunit/",
		"/xmlrpc.php",
		"/.well-known/security.txt",
		"/wp-login.php",
		"/server-status", "/server-info",
		"/manager/html", // tomcat
		"/wp-includes/wlwmanifest.xml",
	}
	for _, x := range probes {
		if strings.Contains(p, x) {
			return true
		}
	}
	// Random-looking *.php at root (e.g. /Sanskrit.php /CDX6.php /100.php)
	if strings.HasPrefix(p, "/") && strings.HasSuffix(p, ".php") &&
		strings.Count(p, "/") == 1 {
		name := strings.TrimSuffix(strings.TrimPrefix(p, "/"), ".php")
		// Unusual short or mixed-case names suggest a scanner.
		if len(name) <= 12 && !commonWPScript(name) {
			return true
		}
	}
	return false
}

func commonWPScript(name string) bool {
	switch name {
	case "index", "wp-login", "wp-cron", "xmlrpc", "wp-config",
		"wp-comments-post", "wp-trackback", "wp-mail", "wp-blog-header",
		"wp-load", "wp-settings", "wp-activate", "wp-signup":
		return true
	}
	return false
}
