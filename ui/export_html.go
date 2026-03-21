package ui

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ftahirops/xtop/model"
)

// exportHTMLReport generates a self-contained HTML incident report.
func exportHTMLReport(snap *model.Snapshot, rates *model.RateSnapshot, result *model.AnalysisResult) (string, error) {
	if snap == nil {
		return "", fmt.Errorf("no snapshot available")
	}

	ts := time.Now().Format("20060102-150405")
	hostname := "unknown"
	if snap.SysInfo != nil && snap.SysInfo.Hostname != "" {
		hostname = snap.SysInfo.Hostname
	}
	dir := filepath.Join(os.Getenv("HOME"), ".xtop", "reports")
	os.MkdirAll(dir, 0755)
	path := filepath.Join(dir, fmt.Sprintf("xtop-%s-%s.html", hostname, ts))

	var sb strings.Builder

	sysInfo := ""
	if snap.SysInfo != nil {
		parts := []string{}
		if snap.SysInfo.Hostname != "" {
			parts = append(parts, snap.SysInfo.Hostname)
		}
		if snap.SysInfo.OS != "" {
			parts = append(parts, snap.SysInfo.OS)
		}
		if snap.SysInfo.Kernel != "" {
			parts = append(parts, snap.SysInfo.Kernel)
		}
		if snap.SysInfo.Virtualization != "" {
			parts = append(parts, snap.SysInfo.Virtualization)
		}
		sysInfo = strings.Join(parts, " | ")
	}

	sb.WriteString(`<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>xtop Report — ` + htmlEsc(hostname) + `</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:'JetBrains Mono','Fira Code',Consolas,monospace;background:#282a36;color:#f8f8f2;padding:20px;line-height:1.6}
.container{max-width:1200px;margin:0 auto}
h1{color:#bd93f9;margin-bottom:5px}
h2{color:#8be9fd;margin:20px 0 10px;border-bottom:1px solid #44475a;padding-bottom:5px}
h3{color:#ff79c6;margin:15px 0 8px}
.sub{color:#6272a4;margin-bottom:20px}
.ok{color:#50fa7b;font-weight:bold} .warn{color:#ffb86c;font-weight:bold} .crit{color:#ff5555;font-weight:bold}
.dim{color:#6272a4}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:15px;margin:15px 0}
.card{background:#44475a;border-radius:8px;padding:15px;border-left:4px solid #6272a4}
.card.c-ok{border-left-color:#50fa7b} .card.c-warn{border-left-color:#ffb86c} .card.c-crit{border-left-color:#ff5555}
.card h3{margin-top:0}
.m{display:flex;justify-content:space-between;padding:3px 0}
.mk{color:#6272a4} .mv{color:#f8f8f2;font-weight:bold}
table{width:100%;border-collapse:collapse;margin:10px 0}
th{background:#44475a;color:#8be9fd;padding:8px;text-align:left}
td{padding:8px;border-bottom:1px solid #44475a}
.rca{background:#44475a;border-radius:8px;padding:20px;margin:15px 0;border:2px solid #6272a4}
.rca-w{border-color:#ffb86c} .rca-c{border-color:#ff5555}
.ev{padding:3px 0 3px 15px;color:#f1fa8c}
.badge{display:inline-block;padding:2px 8px;border-radius:4px;font-size:.85em;font-weight:bold}
.b-ok{background:#50fa7b20;color:#50fa7b} .b-w{background:#ffb86c20;color:#ffb86c} .b-c{background:#ff555520;color:#ff5555}
.footer{margin-top:30px;padding-top:15px;border-top:1px solid #44475a;color:#6272a4;font-size:.85em}
.bar{height:20px;border-radius:4px;margin:5px 0;overflow:hidden;display:flex}
.bar-bg{background:#282a36;flex:1;border-radius:4px;overflow:hidden}
.bar-fill{height:100%}
.bf-g{background:#50fa7b} .bf-y{background:#ffb86c} .bf-r{background:#ff5555}
</style></head><body><div class="container">
`)

	sb.WriteString(fmt.Sprintf("<h1>xtop Incident Report</h1>\n"))
	sb.WriteString(fmt.Sprintf("<p class=\"sub\">%s &mdash; %s</p>\n", htmlEsc(sysInfo), time.Now().Format("2006-01-02 15:04:05 MST")))

	// Health
	healthClass, healthText := "ok", "HEALTHY"
	if result != nil {
		switch result.Health {
		case model.HealthDegraded:
			healthClass = "warn"
			healthText = fmt.Sprintf("DEGRADED &mdash; %s (%d%% confidence)", htmlEsc(result.PrimaryBottleneck), result.Confidence)
		case model.HealthCritical:
			healthClass = "crit"
			healthText = fmt.Sprintf("CRITICAL &mdash; %s (%d%% confidence)", htmlEsc(result.PrimaryBottleneck), result.Confidence)
		case model.HealthInconclusive:
			healthClass = "warn"
			healthText = "INCONCLUSIVE"
		}
	}
	sb.WriteString(fmt.Sprintf("<h2>Health: <span class=\"%s\">%s</span></h2>\n", healthClass, healthText))

	// RCA Box
	if result != nil && result.Narrative != nil && (result.Health == model.HealthDegraded || result.Health == model.HealthCritical) {
		rcaClass := "rca rca-w"
		if result.Health == model.HealthCritical {
			rcaClass = "rca rca-c"
		}
		sb.WriteString(fmt.Sprintf("<div class=\"%s\">\n<h3>Root Cause Analysis</h3>\n", rcaClass))
		sb.WriteString(fmt.Sprintf("<p><strong>Root Cause:</strong> %s</p>\n", htmlEsc(result.Narrative.RootCause)))
		if len(result.Narrative.Evidence) > 0 {
			sb.WriteString("<p><strong>Evidence:</strong></p>\n")
			for _, ev := range result.Narrative.Evidence {
				sb.WriteString(fmt.Sprintf("<div class=\"ev\">&bull; %s</div>\n", htmlEsc(ev)))
			}
		}
		if result.Narrative.Impact != "" {
			sb.WriteString(fmt.Sprintf("<p><strong>Impact:</strong> %s</p>\n", htmlEsc(result.Narrative.Impact)))
		}
		culprit := result.PrimaryAppName
		if culprit == "" {
			culprit = result.PrimaryProcess
		}
		if culprit == "" {
			culprit = result.PrimaryCulprit
		}
		if culprit != "" {
			sb.WriteString(fmt.Sprintf("<p><strong>Culprit:</strong> %s</p>\n", htmlEsc(culprit)))
		}
		sb.WriteString("</div>\n")
	}

	// Subsystem cards
	sb.WriteString("<h2>Subsystem Health</h2>\n<div class=\"grid\">\n")

	cpuPct := float64(0)
	if rates != nil {
		cpuPct = rates.CPUBusyPct
	}
	sb.WriteString(htmlCard("CPU", cpuPct, 70, 90, []htmlKV{
		{"Usage", fmt.Sprintf("%.1f%%", cpuPct)},
		{"Load", fmt.Sprintf("%.1f / %.1f / %.1f", snap.Global.CPU.LoadAvg.Load1, snap.Global.CPU.LoadAvg.Load5, snap.Global.CPU.LoadAvg.Load15)},
		{"CPUs", fmt.Sprintf("%d", snap.Global.CPU.NumCPUs)},
		{"PSI", fmt.Sprintf("%.1f%%", snap.Global.PSI.CPU.Some.Avg10)},
	}))

	memPct := float64(0)
	if snap.Global.Memory.Total > 0 {
		memPct = float64(snap.Global.Memory.Total-snap.Global.Memory.Available) / float64(snap.Global.Memory.Total) * 100
	}
	sb.WriteString(htmlCard("Memory", memPct, 80, 95, []htmlKV{
		{"Used", fmt.Sprintf("%.1f%% (%s free)", memPct, fmtBytes(snap.Global.Memory.Available))},
		{"Total", fmtBytes(snap.Global.Memory.Total)},
		{"Swap", fmt.Sprintf("%s / %s", fmtBytes(snap.Global.Memory.SwapUsed), fmtBytes(snap.Global.Memory.SwapTotal))},
		{"PSI", fmt.Sprintf("%.1f%%", snap.Global.PSI.Memory.Some.Avg10)},
	}))

	ioUtil, ioAwait, ioName := float64(0), float64(0), ""
	if rates != nil {
		for _, d := range rates.DiskRates {
			if d.UtilPct > ioUtil {
				ioUtil = d.UtilPct
				ioAwait = d.AvgAwaitMs
				ioName = d.Name
			}
		}
	}
	sb.WriteString(htmlCard("Disk IO", ioUtil, 70, 90, []htmlKV{
		{"Utilization", fmt.Sprintf("%.1f%% (%s)", ioUtil, ioName)},
		{"Latency", fmt.Sprintf("%.1f ms", ioAwait)},
		{"PSI", fmt.Sprintf("%.1f%%", snap.Global.PSI.IO.Some.Avg10)},
	}))

	totalDrops, retrans := float64(0), float64(0)
	if rates != nil {
		for _, nr := range rates.NetRates {
			totalDrops += nr.RxDropsPS + nr.TxDropsPS
		}
		retrans = rates.RetransRate
	}
	sb.WriteString(htmlCard("Network", totalDrops, 1, 100, []htmlKV{
		{"Drops", fmt.Sprintf("%.0f/s", totalDrops)},
		{"Retransmits", fmt.Sprintf("%.0f/s", retrans)},
		{"Conntrack", fmt.Sprintf("%d / %d", snap.Global.Conntrack.Count, snap.Global.Conntrack.Max)},
	}))

	sb.WriteString("</div>\n")

	// Capacity table
	if result != nil && len(result.Capacities) > 0 {
		sb.WriteString("<h2>Capacity</h2>\n<table>\n")
		sb.WriteString("<tr><th>Resource</th><th>Free</th><th>Current / Limit</th><th>Status</th></tr>\n")
		for _, cap := range result.Capacities {
			badge := "<span class=\"badge b-ok\">OK</span>"
			if cap.Pct < 15 {
				badge = "<span class=\"badge b-c\">CRITICAL</span>"
			} else if cap.Pct < 30 {
				badge = "<span class=\"badge b-w\">LOW</span>"
			}
			sb.WriteString(fmt.Sprintf("<tr><td>%s</td><td>%.1f%%</td><td>%s / %s</td><td>%s</td></tr>\n",
				htmlEsc(cap.Label), cap.Pct, htmlEsc(cap.Current), htmlEsc(cap.Limit), badge))
		}
		sb.WriteString("</table>\n")
	}

	// Top owners
	if result != nil {
		sb.WriteString("<h2>Top Resource Owners</h2>\n<table>\n")
		sb.WriteString("<tr><th>Domain</th><th>Owner</th><th>Usage</th></tr>\n")
		writeOwners := func(domain string, owners []model.Owner) {
			for i, o := range owners {
				if i >= 3 {
					break
				}
				sb.WriteString(fmt.Sprintf("<tr><td>%s</td><td>%s</td><td>%s</td></tr>\n",
					domain, htmlEsc(o.Name), htmlEsc(o.Value)))
			}
		}
		writeOwners("CPU", result.CPUOwners)
		writeOwners("Memory", result.MemOwners)
		writeOwners("IO", result.IOOwners)
		writeOwners("Network", result.NetOwners)
		sb.WriteString("</table>\n")
	}

	// Apps
	if len(snap.Global.Apps.Instances) > 0 {
		sb.WriteString("<h2>Applications</h2>\n<table>\n")
		sb.WriteString("<tr><th>App</th><th>Health</th><th>PID</th><th>RSS</th><th>Connections</th></tr>\n")
		for _, app := range snap.Global.Apps.Instances {
			hClass := "ok"
			if app.HealthScore < 50 {
				hClass = "crit"
			} else if app.HealthScore < 80 {
				hClass = "warn"
			}
			sb.WriteString(fmt.Sprintf("<tr><td>%s</td><td><span class=\"%s\">%d/100</span></td><td>%d</td><td>%.0f MB</td><td>%d</td></tr>\n",
				htmlEsc(app.DisplayName), hClass, app.HealthScore, app.PID, app.RSSMB, app.Connections))
		}
		sb.WriteString("</table>\n")
	}

	// Footer
	sb.WriteString(fmt.Sprintf("<div class=\"footer\"><p>Generated by xtop &mdash; %s</p><p>%s</p></div>\n",
		time.Now().Format("2006-01-02 15:04:05 MST"), htmlEsc(sysInfo)))
	sb.WriteString("</div></body></html>")

	if err := os.WriteFile(path, []byte(sb.String()), 0644); err != nil {
		return "", err
	}
	return path, nil
}

type htmlKV struct {
	Key string
	Val string
}

func htmlCard(title string, val, warnAt, critAt float64, metrics []htmlKV) string {
	class := "c-ok"
	if val >= critAt {
		class = "c-crit"
	} else if val >= warnAt {
		class = "c-warn"
	}
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("<div class=\"card %s\"><h3>%s</h3>\n", class, title))
	for _, m := range metrics {
		sb.WriteString(fmt.Sprintf("<div class=\"m\"><span class=\"mk\">%s</span><span class=\"mv\">%s</span></div>\n", m.Key, htmlEsc(m.Val)))
	}
	sb.WriteString("</div>\n")
	return sb.String()
}

func htmlEsc(s string) string {
	s = strings.ReplaceAll(s, "&", "&amp;")
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, ">", "&gt;")
	s = strings.ReplaceAll(s, `"`, "&quot;")
	return s
}
