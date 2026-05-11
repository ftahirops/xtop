package cmd

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/ftahirops/xtop/collector"
	"github.com/ftahirops/xtop/collector/phpfpm"
	"github.com/ftahirops/xtop/engine"
	"github.com/ftahirops/xtop/model"
)

// runPHPFPM implements `xtop phpfpm` — per-site PHP-FPM diagnostic.
//
// One section per site, ordered by criticality. Each section answers:
//   - what's serving this site (PHP version, pool, worker count)
//   - is it consuming resources? (CPU, RAM, disk I/O, requests/sec)
//   - who's hitting it? (top IPs from access log)
//   - what URIs are hot? (top access-log paths + currently-running scripts)
//   - what's slow? (top slow-log scripts + functions)
//   - what's wrong? (RCA issues: brute force, web shell, saturation, 5xx)
func runPHPFPM(args []string) error {
	fs := flag.NewFlagSet("phpfpm", flag.ExitOnError)
	jsonOut := fs.Bool("json", false, "emit JSON (full data)")
	siteFilter := fs.String("site", "", "show only the matching site (substring match)")
	showWorkers := fs.Bool("workers", false, "also show the per-worker table at the end")
	deepScan := fs.Bool("deep-scan", false, "force a fresh docroot filesystem scan (slower, finds new files)")
	maxIPs := fs.Int("max-ips", 15, "max IPs to show per site")
	maxURIs := fs.Int("max-uris", 15, "max URIs to show per site")
	maxSlow := fs.Int("max-slow-scripts", 12, "max slow scripts to show per site")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, `xtop phpfpm — per-site PHP-FPM diagnostic

  xtop phpfpm                         all sites, ordered by criticality
  xtop phpfpm --site=dula             only sites whose name contains "dula"
  xtop phpfpm --workers               include per-worker table
  xtop phpfpm --json                  full JSON dump
  xtop phpfpm --deep-scan             force fresh docroot scan (slower)
  xtop phpfpm --max-ips=30            show more IPs per site

For each site, shows:
  PHP version + pool, resource use, top IPs (with reverse DNS + provider),
  hot URIs, slow scripts + blocking calls, and any RCA issues (brute force,
  web shell, pool saturation, 5xx surge).`)
	}
	if err := fs.Parse(args); err != nil {
		return err
	}

	// Honor --deep-scan: invalidate fsscan cache before the engine ticks.
	if *deepScan {
		phpfpm.TriggerDeepScan("*")
		fmt.Fprintln(os.Stderr, "deep filesystem scan requested — first run on each docroot may take several seconds")
	}

	eng := engine.NewEngineMode(60, 3, collector.ModeRich)
	defer eng.Close()
	eng.Tick()
	snap, _, _ := eng.Tick()
	if snap == nil {
		return fmt.Errorf("failed to collect")
	}
	fp := snap.Global.PHPFPM

	if *jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(fp)
	}

	if len(fp.Masters) == 0 {
		fmt.Println("No PHP-FPM masters detected on this host.")
		return nil
	}

	renderMasters(fp.Masters)
	apps := filterApps(fp.Apps, *siteFilter)
	if len(apps) == 0 {
		fmt.Println("\n(no sites match filter — nothing to show)")
		return nil
	}
	fmt.Printf("\n%d site(s) reporting activity\n", len(apps))

	for _, a := range apps {
		renderSite(&a, *maxIPs, *maxURIs, *maxSlow)
	}

	if *showWorkers {
		renderWorkersTable(fp.Workers)
	}

	return nil
}

func filterApps(apps []model.PHPFPMApp, filter string) []model.PHPFPMApp {
	if filter == "" {
		return apps
	}
	filter = strings.ToLower(filter)
	out := apps[:0]
	for _, a := range apps {
		if strings.Contains(strings.ToLower(a.App), filter) {
			out = append(out, a)
		}
	}
	return out
}

func renderMasters(masters []model.PHPFPMMaster) {
	fmt.Println(bold("PHP-FPM MASTERS"))
	for _, m := range masters {
		status := green("ok")
		if !m.StatusOK {
			status = red("status-fail")
		}
		fmt.Printf("  PHP %-5s  pid=%-7d  pool=%s  workers=%d  listen=%s  %s\n",
			defaultS(m.PHPVersion, "?"), m.PID, m.PoolName, m.WorkerCount, m.ListenAddr, status)
		if !m.StatusOK && m.StatusError != "" {
			fmt.Printf("            err: %s\n", truncS(m.StatusError, 100))
		}
	}
}

func renderSite(a *model.PHPFPMApp, maxIPs, maxURIs, maxSlow int) {
	// Ghost site — docroot is gone. Don't pretend any of this is real.
	if a.DocRootMissing {
		renderGhostSite(a, maxIPs)
		return
	}
	fmt.Println()

	// Site header — single line: name + PHP version + key counters.
	header := fmt.Sprintf("%s   %s   %s",
		bold(a.App),
		dim("PHP "+defaultS(a.PHPVersion, "?")),
		dim(fmt.Sprintf("%d workers · %s reqs · %.0fms avg",
			a.WorkerCount, fmtInt(int64(a.AccessReqs)), a.AvgDurationMs)),
	)
	fmt.Println(header)
	if a.DocRoot != "" {
		fmt.Println(dim("  " + a.DocRoot))
	}

	// Issues — compact one-liners.
	if len(a.Issues) > 0 {
		fmt.Println()
		for _, iss := range a.Issues {
			fmt.Printf("  %s  %s\n", tagForSeverity(iss.Severity), iss.Message)
			if iss.Action != "" {
				fmt.Printf("        %s\n", dim("→ "+iss.Action))
			}
		}
	}

	// Resources + Traffic — side by side.
	fmt.Println()
	renderTwoColPanel(
		"RESOURCES",
		[][2]string{
			{"workers", fmt.Sprintf("%d total  (%d run · %d idle)", a.WorkerCount, a.RunningCount, a.IdleCount)},
			{"CPU", fmt.Sprintf("%.1f%% of one core", a.CPUPct)},
			{"RAM", fmt.Sprintf("%s MB", fmtInt(a.RSSKB/1024))},
			{"disk I/O", fmt.Sprintf("read %s/s · write %s/s", humanBytes(a.DiskReadBps), humanBytes(a.DiskWriteBps))},
			{"avg req", fmt.Sprintf("%.1f ms", a.AvgDurationMs)},
			{"lifetime", fmt.Sprintf("%s reqs", fmtInt(a.RequestsTotal))},
		},
		"TRAFFIC",
		[][2]string{
			{"requests", fmt.Sprintf("%s  (%s bytes)", fmtInt(int64(a.AccessReqs)), humanBytesUnit(a.AccessBytes))},
			{"2xx", fmtIntWithPct(a.Status2xx, a.AccessReqs, "")},
			{"3xx", fmtIntWithPct(a.Status3xx, a.AccessReqs, "")},
			{"4xx", fmtIntWithPct(a.Status4xx, a.AccessReqs, "yellow")},
			{"5xx", fmtIntWithPct(a.Status5xx, a.AccessReqs, "red")},
		},
	)
	// Top IPs — single-line aligned table
	if len(a.TopIPs) > 0 {
		fmt.Printf("\n  %s\n", bold("TOP CLIENT IPs"))
		fmt.Printf("    %-18s %7s  %4s  %-22s  %s\n",
			"IP", "HITS", "%", "PROVIDER", "REVERSE DNS")
		fmt.Println("    " + strings.Repeat("─", 120))
		for i, h := range a.TopIPs {
			if i >= maxIPs {
				fmt.Printf("    ... +%d more IPs (use --max-ips=N to see more)\n", len(a.TopIPs)-i)
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
				rdns = dim("(no rDNS)")
			}
			fmt.Printf("    %-18s %7s  %3d%%  %-22s  %s\n",
				h.IP, fmtInt(int64(h.Hits)), share,
				truncS(provider, 22), rdns)
		}
	}
	// Top access URIs
	if len(a.TopAccessURIs) > 0 {
		fmt.Printf("\n  %s  %s\n", bold("HOT URIs"), dim("(? = scanner-probe pattern)"))
		fmt.Printf("    %s %7s  %s\n", " ", "HITS", "URI")
		fmt.Println("    " + strings.Repeat("─", 120))
		for i, h := range a.TopAccessURIs {
			if i >= maxURIs {
				fmt.Printf("    ... +%d more URIs (use --max-uris=N to see more)\n", len(a.TopAccessURIs)-i)
				break
			}
			marker := " "
			if isAttackerProbe(h.URI) {
				marker = yellow("?")
			}
			fmt.Printf("    %s %7s  %s\n", marker, fmtInt(int64(h.Hits)), h.URI)
		}
	}
	// Who hit what — top IP/URL combinations
	if len(a.TopIPURIs) > 0 {
		fmt.Printf("\n  %s\n", bold("WHO HIT WHAT  (top IP/URL combinations)"))
		fmt.Printf("    %7s  %-18s  %s\n", "HITS", "IP", "URI")
		fmt.Println("    " + strings.Repeat("─", 120))
		shown := 0
		for _, p := range a.TopIPURIs {
			if shown >= 15 {
				fmt.Printf("    ... +%d more combinations\n", len(a.TopIPURIs)-shown)
				break
			}
			fmt.Printf("    %7d  %-18s  %s\n", p.Hits, p.IP, p.URI)
			shown++
		}
	}
	// What workers are currently serving
	if len(a.TopRunningScripts) > 0 {
		fmt.Printf("\n  %s\n", bold("CURRENTLY RUNNING SCRIPTS"))
		fmt.Printf("    %7s  %s\n", "WORKERS", "SCRIPT")
		fmt.Println("    " + strings.Repeat("─", 120))
		for _, h := range a.TopRunningScripts {
			fmt.Printf("    %7d  %s\n", h.Hits, h.Script)
		}
	}
	// Filesystem scan findings — one row per file with full path
	if len(a.FSWebShells) > 0 || len(a.FSBinaries) > 0 {
		fmt.Printf("\n  %s\n", bold("FILESYSTEM SCAN  (docroot)"))
		fmt.Printf("    %-8s %8s  %-16s  %s\n", "KIND", "SIZE B", "MODIFIED", "PATH / SIGNAL")
		fmt.Println("    " + strings.Repeat("─", 120))
		for i, f := range a.FSWebShells {
			if i >= 10 {
				fmt.Printf("    ... %d more web-shell hits\n", len(a.FSWebShells)-i)
				break
			}
			fmt.Printf("    %s %8d  %-16s  %s\n",
				red("[shell] "), f.Size, f.ModTime.Format("2006-01-02 15:04"), f.Path)
			fmt.Printf("                                                %s\n", dim("→ "+f.Signal))
		}
		for i, f := range a.FSBinaries {
			if i >= 10 {
				fmt.Printf("    ... %d more binary hits\n", len(a.FSBinaries)-i)
				break
			}
			fmt.Printf("    %s %8d  %-16s  %s\n",
				red("[binary]"), f.Size, f.ModTime.Format("2006-01-02 15:04"), f.Path)
			fmt.Printf("                                                %s\n", dim("→ "+f.Signal))
		}
	}
	// Slow log breakdown
	if a.SlowBlocksTotal > 0 {
		fmt.Printf("\n  %s  (%d events total)\n", bold("SLOW SCRIPTS"), a.SlowBlocksTotal)
		fmt.Printf("    %7s  %s\n", "EVENTS", "SCRIPT")
		fmt.Println("    " + strings.Repeat("─", 120))
		for i, h := range a.TopSlowScripts {
			if i >= maxSlow {
				fmt.Printf("    ... +%d more scripts\n", len(a.TopSlowScripts)-i)
				break
			}
			fmt.Printf("    %7s  %s\n", fmtInt(int64(h.Hits)), h.Script)
		}
		if len(a.TopSlowFns) > 0 {
			fmt.Println()
			fmt.Printf("  %s  %s\n", bold("BLOCKING PHP CALLS"),
				dim("(why each call shows up + how to optimize)"))
			fmt.Printf("    %-9s %-26s %s\n", "SEVERITY", "FUNCTION (hits)", "EXPLANATION / FIX")
			fmt.Println("    " + strings.Repeat("─", 120))
			for i, f := range a.TopSlowFns {
				if i >= 10 {
					break
				}
				sevTag := severityTag(f.Severity, f.Category)
				fnCell := fmt.Sprintf("%s (%dx)", f.Function, f.Hits)
				fmt.Printf("    %s  %-26s %s\n", sevTag, fnCell, f.Explanation)
				if f.Optimize != "" {
					fmt.Printf("    %-9s %-26s %s\n", "", "", dim("→ "+f.Optimize))
				}
			}
		}
	}
}

// renderGhostSite is the compact "stale vhost" view — nothing here is
// real site activity; nginx is serving 404s and attackers are still
// hammering the dead address. Show only what's actionable: cleanup
// hint, 404 volume, and the top attacker IPs (so the operator can
// block them).
func renderGhostSite(a *model.PHPFPMApp, maxIPs int) {
	fmt.Println()
	bar := strings.Repeat("─", 78)
	fmt.Println(dim(bar))
	fmt.Printf("  %s  %s\n", bold(a.App), yellow("[GHOST SITE — docroot missing]"))
	fmt.Printf("  docroot: %s %s\n", dim(a.DocRoot), yellow("(does not exist on disk)"))
	if a.AccessLog != "" {
		fmt.Printf("  log:     %s\n", dim(a.AccessLog))
	}

	fmt.Printf("\n  %s\n", bold("WHAT THIS MEANS"))
	fmt.Println("    nginx still listens for this domain but every request returns 404.")
	fmt.Println("    The traffic below is all 404 noise — no PHP runs, no real site exists.")
	fmt.Println("    Slow-log and worker stats may include historical data from when the site was alive.")

	fmt.Printf("\n  %s\n", bold("CLEANUP"))
	fmt.Printf("    %s\n", dim("# remove the stale nginx vhost so the 404 noise stops"))
	fmt.Printf("    rm /www/server/panel/vhost/nginx/%s.conf\n", a.App)
	fmt.Printf("    /www/server/nginx/sbin/nginx -s reload\n")
	fmt.Printf("    %s\n", dim("# optional: archive the old access log"))
	fmt.Printf("    mv %s /root/%s.log.archive\n", a.AccessLog, a.App)

	// 404 noise summary
	if a.AccessReqs > 0 {
		fmt.Printf("\n  %s\n", bold("404 NOISE  (since log was last rotated)"))
		fmt.Printf("    %s requests · %s bytes returned · %d%% are 4xx errors\n",
			fmtInt(int64(a.AccessReqs)), fmtInt(a.AccessBytes),
			pct(a.Status4xx, a.AccessReqs))
	}

	// Top attacker IPs — only thing actually useful (for blocking)
	if len(a.TopIPs) > 0 {
		fmt.Printf("\n  %s\n", bold("TOP IPs HITTING THIS GHOST"))
		fmt.Printf("    %-18s %7s  %4s  %-22s  %s\n",
			"IP", "HITS", "%", "PROVIDER", "REVERSE DNS")
		fmt.Println("    " + strings.Repeat("─", 120))
		for i, h := range a.TopIPs {
			if i >= maxIPs {
				fmt.Printf("    ... +%d more\n", len(a.TopIPs)-i)
				break
			}
			share := pct(h.Hits, a.AccessReqs)
			provider := h.Provider
			if provider != "" && h.Country != "" {
				provider = provider + " · " + h.Country
			}
			if provider == "" {
				provider = "-"
			}
			rdns := h.RDNS
			if rdns == "" {
				rdns = dim("(no rDNS)")
			}
			fmt.Printf("    %-18s %7s  %3d%%  %-22s  %s\n",
				h.IP, fmtInt(int64(h.Hits)), share,
				truncS(provider, 22), rdns)
		}
		fmt.Printf("\n    %s\n", dim("# block the top offenders if the cleanup will be delayed:"))
		count := 0
		for _, h := range a.TopIPs {
			if count >= 3 {
				break
			}
			if h.Provider == "private/local" {
				continue
			}
			fmt.Printf("    ufw deny from %s\n", h.IP)
			count++
		}
	}

	// Historical slow-log evidence — only if web-shell found, which is
	// genuinely interesting (the shell may still be deployed on a
	// twin server).
	if len(a.WebShellHits) > 0 {
		fmt.Printf("\n  %s  %s\n", bold("HISTORICAL WEB-SHELL EVIDENCE"),
			dim("(from slow log — site is gone but this happened)"))
		seen := map[string]bool{}
		for _, s := range a.WebShellHits {
			key := s.Script + "|" + s.Function
			if seen[key] {
				continue
			}
			seen[key] = true
			fmt.Printf("    %s in %s\n", yellow(s.Function+"()"), s.Script)
		}
	}
}

func pct(n, total int) int {
	if total <= 0 {
		return 0
	}
	return n * 100 / total
}

func renderWorkersTable(workers []model.PHPFPMWorker) {
	fmt.Println()
	fmt.Println(dim(strings.Repeat("─", 78)))
	fmt.Println(bold("PER-WORKER TABLE  (running first, then by CPU%)"))
	fmt.Printf("  %-7s %-4s %-8s %6s %7s %8s %-22s URI\n",
		"PID", "PHP", "STATE", "CPU%", "RSS MB", "DUR ms", "APP")
	for _, w := range workers {
		fmt.Printf("  %-7d %-4s %-8s %6.1f %7d %8d %-22s %s\n",
			w.PID, defaultS(w.PHPVersion, "?"), w.State,
			w.LiveCPUPct, w.LiveRSSKB/1024, w.DurationUs/1000,
			truncS(w.App, 22), truncS(w.RequestURI, 60))
	}
}

// severityTag produces a colored "[normal]", "[heavy]", "[critical]" tag
// with the category appended for non-normal cases.
func severityTag(sev, cat string) string {
	switch sev {
	case "critical":
		return red("[critical]")
	case "heavy":
		return yellow("[heavy   ]")
	default:
		return dim("[normal  ]")
	}
}

func tagForSeverity(sev string) string {
	switch sev {
	case "crit":
		return red("[CRIT]")
	case "warn":
		return yellow("[WARN]")
	case "info":
		return cyan("[INFO]")
	default:
		return "[" + sev + "]"
	}
}

// ── tiny helpers (ANSI + formatting) ───────────────────────────────────

func bold(s string) string   { return "\x1b[1m" + s + "\x1b[0m" }
func dim(s string) string    { return "\x1b[2m" + s + "\x1b[0m" }
func red(s string) string    { return "\x1b[31m" + s + "\x1b[0m" }
func green(s string) string  { return "\x1b[32m" + s + "\x1b[0m" }
func yellow(s string) string { return "\x1b[33m" + s + "\x1b[0m" }
func cyan(s string) string   { return "\x1b[36m" + s + "\x1b[0m" }

func colorIfNonZero(n int, color string) string {
	s := fmtInt(int64(n))
	if n == 0 {
		return s
	}
	switch color {
	case "yellow":
		return yellow(s)
	case "red":
		return red(s)
	}
	return s
}

func defaultS(s, d string) string {
	if s == "" {
		return d
	}
	return s
}

func truncS(s string, n int) string {
	if len(s) <= n {
		return s
	}
	if n < 3 {
		return s[:n]
	}
	return s[:n-2] + ".."
}

// renderTwoColPanel renders two key/value panels side-by-side with a
// clear visual separator. Each panel gets a header label, then aligned
// "key  value" pairs. Width-adaptive.
func renderTwoColPanel(leftLabel string, left [][2]string, rightLabel string, right [][2]string) {
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

	fmt.Printf("  %s%s%s\n", bold(leftLabel),
		strings.Repeat(" ", colWidth-len(leftLabel)),
		bold(rightLabel))
	fmt.Printf("  %s%s%s\n",
		dim(strings.Repeat("─", colWidth-2)),
		"  ",
		dim(strings.Repeat("─", 50)))

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
		if visibleLen(leftCol) < colWidth {
			leftCol += strings.Repeat(" ", colWidth-visibleLen(leftCol))
		}
		rightCol := ""
		if rk != "" {
			rightCol = fmt.Sprintf("%-*s  %s", keyR, rk, rv)
		}
		fmt.Printf("  %s%s\n", leftCol, rightCol)
	}
}

// fmtIntWithPct returns "957 (62%)" with optional color tag for non-zero.
func fmtIntWithPct(n, total int, color string) string {
	pct := 0
	if total > 0 {
		pct = n * 100 / total
	}
	s := fmt.Sprintf("%-7s (%2d%%)", fmtInt(int64(n)), pct)
	if n == 0 {
		return s
	}
	switch color {
	case "yellow":
		return yellow(s)
	case "red":
		return red(s)
	}
	return s
}

// humanBytesUnit converts bytes to human-readable size string.
func humanBytesUnit(n int64) string {
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

// visibleLen returns the visible (non-ANSI) length of a string.
func visibleLen(s string) int {
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

// isAttackerProbe is a small heuristic — same list used by the TUI page.
func isAttackerProbe(p string) bool {
	p = strings.ToLower(p)
	probes := []string{
		"/.env", "/wp-config", "/.git/", "/.aws/",
		"/legacy.php", "/short.php", "/bulk.php",
		"/shell.php", "/cmd.php", "/up.php", "/x.php", "/c.php",
		"/phpinfo", "/phpunit/",
		"/.well-known/security.txt",
		"/manager/html",
		"/wp-includes/wlwmanifest.xml",
		"/server-status", "/server-info",
	}
	for _, x := range probes {
		if strings.Contains(p, x) {
			return true
		}
	}
	if strings.HasPrefix(p, "/") && strings.HasSuffix(p, ".php") &&
		strings.Count(p, "/") == 1 {
		name := strings.TrimSuffix(strings.TrimPrefix(p, "/"), ".php")
		switch name {
		case "index", "wp-login", "wp-cron", "xmlrpc", "wp-config",
			"wp-comments-post", "wp-trackback", "wp-mail", "wp-blog-header",
			"wp-load", "wp-settings", "wp-activate", "wp-signup":
			return false
		}
		if len(name) <= 12 {
			return true
		}
	}
	return false
}

func shortPathCmd(p string) string {
	parts := strings.Split(p, "/")
	if len(parts) < 4 {
		return p
	}
	return ".../" + strings.Join(parts[len(parts)-3:], "/")
}

func fmtFloatPhp(f float64, dec int) string {
	return fmt.Sprintf("%.*f", dec, f)
}

func fmtInt(n int64) string {
	if n < 1000 {
		return fmt.Sprintf("%d", n)
	}
	// thousand-separator
	s := fmt.Sprintf("%d", n)
	var out []byte
	for i, c := range []byte(s) {
		if i > 0 && (len(s)-i)%3 == 0 {
			out = append(out, ',')
		}
		out = append(out, c)
	}
	return string(out)
}

func humanBytes(bps float64) string {
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
