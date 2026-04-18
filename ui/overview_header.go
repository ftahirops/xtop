package ui

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/ftahirops/xtop/model"
)

// ─── SHARED: HEADER ─────────────────────────────────────────────────────────

func renderHeader(snap *model.Snapshot, rates *model.RateSnapshot, result *model.AnalysisResult) string {
	var sb strings.Builder

	if result == nil {
		return dimStyle.Render(" collecting...")
	}

	// System identity line
	if snap.SysInfo != nil {
		si := snap.SysInfo
		parts := []string{}
		if si.Hostname != "" {
			parts = append(parts, si.Hostname)
		}
		if len(si.IPs) > 0 {
			parts = append(parts, strings.Join(model.MaskIPs(si.IPs), ", "))
		}
		if si.Virtualization != "" {
			parts = append(parts, si.Virtualization)
		}
		if si.OS != "" {
			parts = append(parts, si.OS)
		}
		if si.Kernel != "" {
			parts = append(parts, si.Kernel)
		}
		if len(parts) > 0 {
			sb.WriteString(" ")
			sb.WriteString(dimStyle.Render(strings.Join(parts, " | ")))
			sb.WriteString("\n")
		}
	}

	sb.WriteString(" ")
	switch result.Health {
	case model.HealthOK:
		sb.WriteString(okStyle.Render("HEALTH: OK"))
	case model.HealthInconclusive:
		sb.WriteString(orangeStyle.Render("HEALTH: INCONCLUSIVE"))
	case model.HealthDegraded:
		sb.WriteString(warnStyle.Render(fmt.Sprintf("DEGRADED — %s (%d%% confidence)",
			result.PrimaryBottleneck, result.Confidence)))
	case model.HealthCritical:
		sb.WriteString(critStyle.Render(fmt.Sprintf("CRITICAL — %s (%d%% confidence)",
			result.PrimaryBottleneck, result.Confidence)))
	}

	if result.AnomalyStartedAgo > 0 {
		sb.WriteString(critStyle.Render(fmt.Sprintf(" — Incident %s", fmtDuration(result.AnomalyStartedAgo))))
	} else if result.StableSince > 60 {
		sb.WriteString(dimStyle.Render(fmt.Sprintf(" | Stable %s", fmtDuration(result.StableSince))))
	}

	sb.WriteString(dimStyle.Render(" | "))

	cpuPct := float64(0)
	if rates != nil {
		cpuPct = rates.CPUBusyPct
	}
	sb.WriteString(meterColor(cpuPct).Render(fmt.Sprintf("CPU %5.1f%%", cpuPct)))
	sb.WriteString(dimStyle.Render(" | "))

	memPct := float64(0)
	if snap.Global.Memory.Total > 0 {
		memPct = float64(snap.Global.Memory.Total-snap.Global.Memory.Available) / float64(snap.Global.Memory.Total) * 100
	}
	sb.WriteString(meterColor(memPct).Render(fmt.Sprintf("MEM %5.1f%%", memPct)))
	sb.WriteString(dimStyle.Render(" | "))

	ioPct := float64(0)
	if rates != nil {
		for _, d := range rates.DiskRates {
			if d.UtilPct > ioPct {
				ioPct = d.UtilPct
			}
		}
	}
	sb.WriteString(meterColor(ioPct).Render(fmt.Sprintf("IO %5.1f%%", ioPct)))
	sb.WriteString(dimStyle.Render(" | "))
	headerNCPU := snap.Global.CPU.NumCPUs
	if headerNCPU == 0 {
		headerNCPU = 1
	}
	headerLoadPct := snap.Global.CPU.LoadAvg.Load1 / float64(headerNCPU) * 100
	sb.WriteString(meterColor(headerLoadPct).Render(fmt.Sprintf("Load %.1f/%d=%.0f%%", snap.Global.CPU.LoadAvg.Load1, headerNCPU, headerLoadPct)))

	// Disk free % (worst mount)
	if rates != nil && len(rates.MountRates) > 0 {
		var worstFreePct float64 = 100
		var worstETA float64 = -1
		for _, mr := range rates.MountRates {
			if mr.FreePct < worstFreePct {
				worstFreePct = mr.FreePct
				worstETA = mr.ETASeconds
			}
		}
		diskUsedPct := 100 - worstFreePct
		sb.WriteString(dimStyle.Render(" | "))
		diskStr := fmt.Sprintf("DISK %4.0f%%", diskUsedPct)
		if worstETA > 0 && worstETA < 7200 {
			diskStr += fmt.Sprintf(" ETA %.0fm", worstETA/60)
		}
		// Color: green >30% free, yellow >10% free, red <=10% free
		if worstFreePct <= 10 {
			sb.WriteString(critStyle.Render(diskStr))
		} else if worstFreePct <= 30 {
			sb.WriteString(warnStyle.Render(diskStr))
		} else {
			sb.WriteString(okStyle.Render(diskStr))
		}
	}

	// Active sessions summary
	if len(snap.Global.Sessions) > 0 {
		uniqueIPs := make(map[string]bool)
		var users []string
		seen := make(map[string]bool)
		for _, s := range snap.Global.Sessions {
			if s.From != "" && s.From != "-" {
				uniqueIPs[s.From] = true
			}
			key := s.User + "@" + s.From
			if !seen[key] {
				seen[key] = true
				label := s.User
				if s.From != "" && s.From != "-" {
					label += "@" + s.From
				} else if s.TTY != "" {
					label += "@" + s.TTY
				}
				cmd := s.Command
				if len(cmd) > 20 {
					cmd = cmd[:17] + "..."
				}
				if cmd != "" {
					label += "(" + cmd + ")"
				}
				users = append(users, label)
			}
		}
		sb.WriteString("\n ")
		sb.WriteString(dimStyle.Render("USERS: "))
		sb.WriteString(valueStyle.Render(fmt.Sprintf("%d", len(snap.Global.Sessions))))
		sb.WriteString(dimStyle.Render(" sessions "))
		sb.WriteString(valueStyle.Render(fmt.Sprintf("%d", len(uniqueIPs))))
		sb.WriteString(dimStyle.Render(" IPs"))
		sb.WriteString(dimStyle.Render(" │ "))
		// Show up to 4 user entries
		show := users
		if len(show) > 4 {
			show = show[:4]
		}
		sb.WriteString(dimStyle.Render(strings.Join(show, "  ")))
		if len(users) > 4 {
			sb.WriteString(dimStyle.Render(fmt.Sprintf(" +%d more", len(users)-4)))
		}
	}

	if len(snap.Errors) > 0 {
		sb.WriteString("\n ")
		shown := snap.Errors
		if len(shown) > 2 {
			shown = shown[:2]
		}
		sb.WriteString(warnStyle.Render("Collector errors: "))
		sb.WriteString(dimStyle.Render(strings.Join(shown, " | ")))
		if len(snap.Errors) > 2 {
			sb.WriteString(dimStyle.Render(fmt.Sprintf(" (+%d more)", len(snap.Errors)-2)))
		}
	}

	return sb.String()
}

// ─── OVERVIEW: APPS SUMMARY BLOCK ───────────────────────────────────────────

func renderOverviewAppsSummary(snap *model.Snapshot, width int) string {
	var sb strings.Builder

	innerW := width - 7
	if innerW < 40 {
		innerW = 40
	}
	if innerW > 200 {
		innerW = 200
	}

	title := fmt.Sprintf(" %s ", titleStyle.Render("Apps"))
	sb.WriteString(boxTopTitle(title, innerW) + "\n")

	if snap == nil || len(snap.Global.Apps.Instances) == 0 {
		sb.WriteString(boxRow(dimStyle.Render("  no applications detected"), innerW) + "\n")
		sb.WriteString(boxBot(innerW) + "\n")
		return sb.String()
	}

	// Sort: unhealthy first, then by health score ascending
	apps := make([]model.AppInstance, len(snap.Global.Apps.Instances))
	copy(apps, snap.Global.Apps.Instances)
	sort.Slice(apps, func(i, j int) bool {
		return apps[i].HealthScore < apps[j].HealthScore
	})

	maxShow := 8
	if len(apps) < maxShow {
		maxShow = len(apps)
	}

	nameW := 14
	scoreW := 8
	for _, app := range apps[:maxShow] {
		name := app.DisplayName
		if len(name) > nameW {
			name = name[:nameW]
		}

		// Traffic light badge
		var badge string
		if app.HealthScore < 50 {
			badge = critStyle.Render("✗")
		} else if app.HealthScore < 80 {
			badge = warnStyle.Render("⚠")
		} else {
			badge = okStyle.Render("●")
		}

		scoreStr := fmt.Sprintf("%d/100", app.HealthScore)
		// Build compact one-line summary from deep metrics
		summary := overviewAppOneLiner(app)

		row := fmt.Sprintf("  %s %s %s  %s",
			badge,
			styledPad(valueStyle.Render(name), nameW),
			styledPad(dimStyle.Render(scoreStr), scoreW),
			dimStyle.Render(summary))
		sb.WriteString(boxRow(row, innerW) + "\n")
	}

	if len(apps) > maxShow {
		sb.WriteString(boxRow(dimStyle.Render(fmt.Sprintf("  ... +%d more", len(apps)-maxShow)), innerW) + "\n")
	}

	sb.WriteString(boxBot(innerW) + "\n")
	return sb.String()
}

// overviewAppOneLiner returns a compact metric summary for an app.
func overviewAppOneLiner(app model.AppInstance) string {
	dm := app.DeepMetrics
	if !app.HasDeepMetrics || len(dm) == 0 {
		return fmt.Sprintf("%dMB RSS  %d conns", int(app.RSSMB), app.Connections)
	}

	switch app.AppType {
	case "redis":
		parts := []string{}
		if ops := dm["instantaneous_ops_per_sec"]; ops != "" {
			parts = append(parts, ops+" ops/s")
		}
		if hr := dm["hit_ratio"]; hr != "" {
			parts = append(parts, hr+" hit")
		}
		if p99 := dm["latency_percentiles_usec_p99"]; p99 != "" {
			p99v, _ := strconv.ParseFloat(p99, 64)
			parts = append(parts, redisFmtUsec(p99v)+" p99")
		}
		return strings.Join(parts, "  ")
	case "elasticsearch":
		parts := []string{}
		if st := dm["status"]; st != "" {
			parts = append(parts, st)
		}
		if n := dm["number_of_nodes"]; n != "" {
			parts = append(parts, n+" nodes")
		}
		if h := dm["jvm_heap_used_pct"]; h != "" {
			parts = append(parts, h+" heap")
		}
		if rej := dm["tp_total_rejected"]; rej != "" && rej != "0" {
			parts = append(parts, rej+" rej")
		}
		return strings.Join(parts, "  ")
	case "logstash":
		parts := []string{}
		if s := dm["status"]; s != "" {
			parts = append(parts, s)
		}
		if in := dm["events_in_per_sec"]; in != "" {
			parts = append(parts, in+"→"+dm["events_out_per_sec"]+" ev/s")
		}
		if q := dm["queue_total_pct"]; q != "" {
			parts = append(parts, q+"% q")
		}
		if dlq := dm["dlq_total_events"]; dlq != "" && dlq != "0" {
			parts = append(parts, dlq+" DLQ")
		}
		return strings.Join(parts, "  ")
	case "kibana":
		parts := []string{}
		if s := dm["status_overall"]; s != "" {
			parts = append(parts, s)
		}
		if d := dm["event_loop_delay_ms"]; d != "" {
			parts = append(parts, d+"ms loop")
		}
		if h := dm["heap_used_pct"]; h != "" {
			parts = append(parts, h+"% heap")
		}
		return strings.Join(parts, "  ")
	case "mysql":
		parts := []string{}
		if qps := dm["queries_per_sec"]; qps != "" {
			parts = append(parts, qps+" qps")
		}
		if conn := dm["threads_connected"]; conn != "" {
			parts = append(parts, conn+" conns")
		}
		return strings.Join(parts, "  ")
	case "postgresql":
		parts := []string{}
		if ac := dm["active_connections"]; ac != "" {
			parts = append(parts, ac+" active")
		}
		if hr := dm["cache_hit_ratio"]; hr != "" {
			parts = append(parts, hr+" cache")
		}
		return strings.Join(parts, "  ")
	case "nginx":
		parts := []string{}
		if rps := dm["requests_per_sec"]; rps != "" {
			parts = append(parts, rps+" rps")
		}
		if ac := dm["active_connections"]; ac != "" {
			parts = append(parts, ac+" active")
		}
		return strings.Join(parts, "  ")
	case "haproxy":
		parts := []string{}
		if rps := dm["req_rate"]; rps != "" {
			parts = append(parts, rps+" rps")
		}
		if e5 := dm["hrsp_5xx"]; e5 != "" && e5 != "0" {
			parts = append(parts, e5+" 5xx")
		}
		return strings.Join(parts, "  ")
	case "mongodb":
		parts := []string{}
		if conn := dm["current_connections"]; conn != "" {
			parts = append(parts, conn+" conns")
		}
		return strings.Join(parts, "  ")
	case "rabbitmq":
		parts := []string{}
		if q := dm["queue_totals_messages"]; q != "" {
			parts = append(parts, q+" msgs")
		}
		if conn := dm["connections"]; conn != "" {
			parts = append(parts, conn+" conns")
		}
		return strings.Join(parts, "  ")
	case "memcached":
		parts := []string{}
		if hr := dm["hit_ratio"]; hr != "" {
			parts = append(parts, hr+" hit")
		}
		if mem := dm["bytes_human"]; mem != "" {
			parts = append(parts, mem)
		}
		return strings.Join(parts, "  ")
	default:
		return fmt.Sprintf("%dMB RSS  %d conns", int(app.RSSMB), app.Connections)
	}
}

// ─── OVERVIEW: SECURITY SUMMARY BLOCK ───────────────────────────────────────

func renderOverviewSecuritySummary(snap *model.Snapshot, width int) string {
	var sb strings.Builder

	innerW := width - 7
	if innerW < 40 {
		innerW = 40
	}
	if innerW > 200 {
		innerW = 200
	}

	title := fmt.Sprintf(" %s ", titleStyle.Render("Security"))
	sb.WriteString(boxTopTitle(title, innerW) + "\n")

	if snap == nil {
		sb.WriteString(boxRow(dimStyle.Render("  collecting..."), innerW) + "\n")
		sb.WriteString(boxBot(innerW) + "\n")
		return sb.String()
	}

	sec := snap.Global.Security
	var alerts []string

	// Check each detection mechanism
	if len(sec.ReverseShells) > 0 {
		alerts = append(alerts, critStyle.Render(fmt.Sprintf("%d reverse shell(s)", len(sec.ReverseShells))))
	}
	if sec.BruteForce {
		alerts = append(alerts, critStyle.Render(fmt.Sprintf("brute force (%.0f/s)", sec.FailedAuthRate)))
	}
	if len(sec.BeaconIndicators) > 0 {
		alerts = append(alerts, warnStyle.Render(fmt.Sprintf("%d beacon(s)", len(sec.BeaconIndicators))))
	}
	if len(sec.DNSTunnelIndicators) > 0 {
		alerts = append(alerts, warnStyle.Render(fmt.Sprintf("%d DNS tunnel(s)", len(sec.DNSTunnelIndicators))))
	}
	if len(snap.Global.FilelessProcs) > 0 {
		alerts = append(alerts, warnStyle.Render(fmt.Sprintf("%d fileless proc(s)", len(snap.Global.FilelessProcs))))
	}
	if len(sec.SUIDAnomalies) > 0 {
		alerts = append(alerts, warnStyle.Render(fmt.Sprintf("%d SUID anomaly", len(sec.SUIDAnomalies))))
	}

	// SYN flood from sentinel
	if len(snap.Global.Sentinel.SynFlood) > 0 {
		alerts = append(alerts, warnStyle.Render(fmt.Sprintf("%d SYN flood src(s)", len(snap.Global.Sentinel.SynFlood))))
	}

	if len(alerts) == 0 {
		row := fmt.Sprintf("  %s  %s", okStyle.Render("●"), dimStyle.Render("Clean — no threats detected"))
		sb.WriteString(boxRow(row, innerW) + "\n")
	} else {
		badge := warnStyle.Render("⚠")
		for _, r := range sec.ReverseShells {
			_ = r
			badge = critStyle.Render("✗")
			break
		}
		row := fmt.Sprintf("  %s  %s", badge, strings.Join(alerts, dimStyle.Render("  ")))
		sb.WriteString(boxRow(row, innerW) + "\n")
	}

	// Failed auth summary (always show if non-zero)
	if sec.FailedAuthTotal > 0 && !sec.BruteForce {
		authRow := fmt.Sprintf("  %s  %s",
			dimStyle.Render("·"),
			dimStyle.Render(fmt.Sprintf("Failed auth: %d total, %.1f/s from %d IPs",
				sec.FailedAuthTotal, sec.FailedAuthRate, len(sec.FailedAuthIPs))))
		sb.WriteString(boxRow(authRow, innerW) + "\n")
	}

	sb.WriteString(boxBot(innerW) + "\n")
	return sb.String()
}
