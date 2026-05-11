//go:build linux

package phpfpm

import (
	"fmt"
	"strings"

	"github.com/ftahirops/xtop/model"
)

// evaluateRCA produces a slice of Issues for one app based on its
// aggregated stats. Deterministic, cheap, single-host scope. Order
// matters — critical first so they show at top of the panel.
func evaluateRCA(a *model.PHPFPMApp, masterCfg map[string]int) {
	// 0a. Stale vhost — nginx still configured but docroot missing.
	//     This is the "ghost site" case: attackers still hit it (the
	//     access log keeps growing) but no real content is served.
	if a.DocRootMissing {
		a.Issues = append(a.Issues, model.PHPFPMIssue{
			Severity: "warn",
			Code:     "phpfpm.vhost.stale",
			Message:  "vhost configured but docroot is gone — every request returns 404",
			Detail:   fmt.Sprintf("docroot %q does not exist on disk; access log still growing from stale attacker traffic", a.DocRoot),
			Action:   "either restore the docroot or remove the nginx vhost so the noise stops",
		})
	}

	// 0b. Filesystem-scan findings — strongest signal because they live
	//     on disk and the file content is the smoking gun.
	if len(a.FSWebShells) > 0 {
		first := a.FSWebShells[0]
		extra := ""
		if len(a.FSWebShells) > 1 {
			extra = fmt.Sprintf(" (+%d more)", len(a.FSWebShells)-1)
		}
		a.Issues = append(a.Issues, model.PHPFPMIssue{
			Severity: "crit",
			Code:     "phpfpm.fs.webshell",
			Message:  fmt.Sprintf("web-shell file found in docroot: %s%s", shortPath(first.Path), extra),
			Detail:   fmt.Sprintf("%s — kind=%s — size=%d B — modified=%s", first.Signal, first.Kind, first.Size, first.ModTime.Format("2006-01-02 15:04")),
			Action:   "quarantine the file, audit recent uploads/, rotate any credentials, and look for siblings",
		})
	}
	if len(a.FSBinaries) > 0 {
		first := a.FSBinaries[0]
		extra := ""
		if len(a.FSBinaries) > 1 {
			extra = fmt.Sprintf(" (+%d more)", len(a.FSBinaries)-1)
		}
		a.Issues = append(a.Issues, model.PHPFPMIssue{
			Severity: "crit",
			Code:     "phpfpm.fs.binary",
			Message:  fmt.Sprintf("unexpected binary in docroot: %s%s", shortPath(first.Path), extra),
			Detail:   fmt.Sprintf("%s — kind=%s — size=%d B — modified=%s", first.Signal, first.Kind, first.Size, first.ModTime.Format("2006-01-02 15:04")),
			Action:   "investigate why an ELF/script is inside a public webroot — most legitimate sites have none",
		})
	}

	// 1. Web-shell suspect — slow-log shows a high-risk fn at top of stack.
	if len(a.WebShellHits) > 0 {
		s := a.WebShellHits[0]
		a.Issues = append(a.Issues, model.PHPFPMIssue{
			Severity: "crit",
			Code:     "phpfpm.webshell.suspect",
			Message:  fmt.Sprintf("possible web shell — %s() called from %s", s.Function, shortPath(s.Script)),
			Detail:   fmt.Sprintf("%d slow-log events matched. Top frame: %s", len(a.WebShellHits), truncBlob(s.Frame, 120)),
			Action:   "inspect the script — uploaded shells often live in wp-includes/, /uploads/, or in obscurely-named files at site root",
		})
	}

	// 2. Brute-force / scrape — single IP > 100 hits on login or admin endpoints.
	if hit := detectBruteforce(a); hit != nil {
		a.Issues = append(a.Issues, *hit)
	}

	// 3. Single-IP dominance — one IP responsible for > 60% of all access-log requests.
	if a.AccessReqs > 50 && len(a.TopIPs) > 0 {
		topIP := a.TopIPs[0]
		// Skip localhost: server calling itself is not a takeover signal.
		isLocal := topIP.IP == "127.0.0.1" || topIP.IP == "::1" || topIP.IP == "localhost"
		share := float64(topIP.Hits) / float64(a.AccessReqs)
		if share >= 0.6 && !isLocal {
			a.Issues = append(a.Issues, model.PHPFPMIssue{
				Severity: "warn",
				Code:     "phpfpm.single_ip.dominant",
				Message:  fmt.Sprintf("one IP is %d%% of traffic: %s", int(share*100), topIP.IP),
				Detail:   fmt.Sprintf("%d of %d requests came from %s", topIP.Hits, a.AccessReqs, topIP.IP),
				Action:   "verify whether legitimate (CDN, monitor, partner) or a scraper/bot; rate-limit if needed",
			})
		}
	}

	// 4. Pool saturation — > 80% of pm.max_children busy. We don't track
	// max_children yet; use the master's WorkerCount as a proxy.
	if maxCh := masterCfg[a.PHPVersion]; maxCh > 0 && a.WorkerCount > 0 {
		if a.RunningCount*100/maxCh >= 80 {
			a.Issues = append(a.Issues, model.PHPFPMIssue{
				Severity: "warn",
				Code:     "phpfpm.pool.saturated",
				Message:  fmt.Sprintf("PHP %s pool at %d%% capacity (%d running / %d max)", a.PHPVersion, a.RunningCount*100/maxCh, a.RunningCount, maxCh),
				Detail:   "incoming requests will queue behind currently-running workers",
				Action:   "either increase pm.max_children, or find the slow script eating workers (see TopSlowScripts)",
			})
		}
	}

	// 5. Slow-log volume — many slow events for this site.
	if a.SlowBlocksTotal >= 100 {
		topScript := ""
		if len(a.TopSlowScripts) > 0 {
			topScript = shortPath(a.TopSlowScripts[0].Script)
		}
		a.Issues = append(a.Issues, model.PHPFPMIssue{
			Severity: "warn",
			Code:     "phpfpm.slow.high",
			Message:  fmt.Sprintf("%d slow-log events on this site", a.SlowBlocksTotal),
			Detail:   fmt.Sprintf("top offender: %s", topScript),
			Action:   "profile the top slow script — usually a missing index, blocking external call, or N+1 query",
		})
	}

	// 6. 5xx surge — > 5% of recent responses 5xx.
	if a.AccessReqs > 20 && a.Status5xx*100/a.AccessReqs >= 5 {
		a.Issues = append(a.Issues, model.PHPFPMIssue{
			Severity: "warn",
			Code:     "phpfpm.5xx.surge",
			Message:  fmt.Sprintf("%d 5xx responses (%d%% error rate)", a.Status5xx, a.Status5xx*100/a.AccessReqs),
			Detail:   "errors typically mean PHP fatal, upstream timeout, or pool exhaustion",
			Action:   "check PHP error log and slow log for the affected URIs",
		})
	}
}

// detectBruteforce returns an Issue if any single IP has > 100 hits on
// login / xmlrpc / admin-ajax endpoints.
func detectBruteforce(a *model.PHPFPMApp) *model.PHPFPMIssue {
	type key struct{ ip, kind string }
	tally := map[key]int{}
	classifiers := map[string]string{
		"/wp-login.php":          "login",
		"/wp-admin/index.php":    "admin",
		"/wp-admin/admin-ajax.php": "admin-ajax",
		"/xmlrpc.php":            "xmlrpc",
		"/administrator/":        "joomla-admin",
		"/user/login":            "drupal-login",
	}
	for _, p := range a.TopIPURIs {
		// Localhost is the server talking to itself (wp-cron, internal
		// health checks, etc.) — never a brute-force attacker.
		if p.IP == "127.0.0.1" || p.IP == "::1" || p.IP == "localhost" {
			continue
		}
		for prefix, label := range classifiers {
			if strings.HasPrefix(p.URI, prefix) {
				tally[key{ip: p.IP, kind: label}] += p.Hits
			}
		}
	}
	for k, n := range tally {
		if n >= 100 {
			return &model.PHPFPMIssue{
				Severity: "crit",
				Code:     "phpfpm.bruteforce.detected",
				Message:  fmt.Sprintf("brute-force on /%s from %s (%d hits)", k.kind, k.ip, n),
				Detail:   fmt.Sprintf("IP %s is hammering %s endpoints — likely credential stuffing", k.ip, k.kind),
				Action:   "block at firewall: ufw deny from " + k.ip + "  (or add to fail2ban/CrowdSec)",
			}
		}
	}
	return nil
}

func shortPath(p string) string {
	parts := strings.Split(p, "/")
	if len(parts) < 4 {
		return p
	}
	return ".../" + strings.Join(parts[len(parts)-3:], "/")
}

func truncBlob(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-2] + ".."
}
