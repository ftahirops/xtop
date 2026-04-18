//go:build linux

package ui

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/ftahirops/xtop/model"
)

// ── Logstash Detail ────────────────────────────────────────────────────

func renderLogstashDeepMetrics(app model.AppInstance, iw int) string {
	var sb strings.Builder
	dm := app.DeepMetrics

	// ── HEALTH STATUS TABLE ───────────────────────────────────────────
	type hRow struct{ metric, value, status string }
	var rows []hRow

	if v := dm["status"]; v != "" {
		s := "OK"
		switch v {
		case "red":
			s = "CRIT"
		case "yellow":
			s = "WARN"
		}
		rows = append(rows, hRow{"Node Status", strings.ToUpper(v), s})
	}

	if pctStr := dm["jvm_heap_used_pct"]; pctStr != "" {
		pct, _ := strconv.ParseFloat(pctStr, 64)
		s := "OK"
		if pct > 90 {
			s = "CRIT"
		} else if pct > 80 {
			s = "WARN"
		}
		rows = append(rows, hRow{"JVM Heap", pctStr + "%", s})
	}

	if pctStr := dm["queue_total_pct"]; pctStr != "" {
		pct, _ := strconv.ParseFloat(pctStr, 64)
		s := "OK"
		if pct > 90 {
			s = "CRIT"
		} else if pct > 75 {
			s = "WARN"
		}
		rows = append(rows, hRow{"Persistent Queue", pctStr + "%", s})
	}

	if v := dm["dlq_total_events"]; v != "" && v != "0" {
		rows = append(rows, hRow{"DLQ Events", v, "WARN"})
	}

	// Pipeline throughput
	in, _ := strconv.ParseFloat(dm["events_in_per_sec"], 64)
	out, _ := strconv.ParseFloat(dm["events_out_per_sec"], 64)
	if in > 0 || out > 0 {
		s := "OK"
		label := fmt.Sprintf("%.1f in · %.1f out ev/s", in, out)
		if in > 10 && out < 0.1 {
			s = "CRIT"
			label += " (STALLED)"
		} else if in > 0 && out > 0 && out < in*0.5 {
			s = "WARN"
		}
		rows = append(rows, hRow{"Pipeline Throughput", label, s})
	}

	if msStr := dm["slowest_filter_ms"]; msStr != "" {
		ms, _ := strconv.ParseFloat(msStr, 64)
		s := "OK"
		if ms > 50 {
			s = "WARN"
		}
		if ms > 200 {
			s = "CRIT"
		}
		label := fmt.Sprintf("%s @ %.1fms", dm["slowest_filter_name"], ms)
		rows = append(rows, hRow{"Slowest Filter", label, s})
	}

	if v := dm["reload_failures"]; v != "" && v != "0" {
		rows = append(rows, hRow{"Reload Failures", v, "WARN"})
	}

	if len(rows) > 0 {
		sb.WriteString("  " + titleStyle.Render("HEALTH STATUS") + "\n")
		sb.WriteString(boxTop(iw) + "\n")
		cM, cV := 22, 32
		hdr := fmt.Sprintf("  %s %s %s",
			styledPad(dimStyle.Render("Metric"), cM),
			styledPad(dimStyle.Render("Value"), cV),
			dimStyle.Render("Status"))
		sb.WriteString(boxRow(hdr, iw) + "\n")
		sb.WriteString(boxMid(iw) + "\n")
		for _, r := range rows {
			badge := okStyle.Render("OK")
			if r.status == "WARN" {
				badge = warnStyle.Render("WARN")
			} else if r.status == "CRIT" {
				badge = critStyle.Render("CRIT")
			}
			row := fmt.Sprintf("  %s %s %s",
				styledPad(valueStyle.Render(r.metric), cM),
				styledPad(valueStyle.Render(r.value), cV),
				badge)
			sb.WriteString(boxRow(row, iw) + "\n")
		}
		sb.WriteString(boxBot(iw) + "\n\n")
	}

	// ── NODE ──
	sb.WriteString(appSection("NODE", iw, []kv{
		{Key: "Node Name", Val: dm["node_name"]},
		{Key: "Host", Val: dm["host"]},
		{Key: "Version", Val: dm["version"]},
		{Key: "Status", Val: logstashColorStatus(dm["status"])},
		{Key: "Uptime (s)", Val: formatUptimeMS(dm["jvm_uptime_ms"])},
	}))

	// ── JVM ──
	sb.WriteString(appSection("JVM", iw, []kv{
		{Key: "Heap Used", Val: dm["jvm_heap_used"]},
		{Key: "Heap Max", Val: dm["jvm_heap_max"]},
		{Key: "Heap Used %", Val: dm["jvm_heap_used_pct"]},
		{Key: "CPU %", Val: dm["process_cpu_pct"]},
		{Key: "Load 1m", Val: dm["load_avg_1m"]},
		{Key: "Open FDs", Val: dm["open_fds"]},
		{Key: "Max FDs", Val: dm["max_fds"]},
	}))

	// ── EVENTS (aggregated) ──
	sb.WriteString(appSection("EVENTS", iw, []kv{
		{Key: "In Total", Val: dm["events_in"]},
		{Key: "Filtered Total", Val: dm["events_filtered"]},
		{Key: "Out Total", Val: dm["events_out"]},
		{Key: "In/sec", Val: dm["events_in_per_sec"]},
		{Key: "Filtered/sec", Val: dm["events_filtered_per_sec"]},
		{Key: "Out/sec", Val: dm["events_out_per_sec"]},
		{Key: "Duration (ms)", Val: dm["events_duration_ms"]},
		{Key: "Queue Push (ms)", Val: dm["events_queue_push_ms"]},
	}))

	// ── PIPELINES ──
	if pCount := dm["pipeline_count"]; pCount != "" {
		names := strings.Split(dm["pipeline_names"], ",")
		sort.Strings(names)
		cnt, _ := strconv.Atoi(pCount)
		sb.WriteString("  " + titleStyle.Render(fmt.Sprintf("PIPELINES (%d)", cnt)) + "\n")
		sb.WriteString(boxTop(iw) + "\n")
		for _, name := range names {
			if name == "" {
				continue
			}
			prefix := "pipe_" + sanitizeUIKey(name) + "_"
			workers := dm[prefix+"workers"]
			batch := dm[prefix+"batch_size"]
			qType := dm[prefix+"queue_type"]
			qPct := dm[prefix+"queue_pct"]
			evIn := dm[prefix+"events_in"]
			evOut := dm[prefix+"events_out"]
			dlq := dm[prefix+"dlq_dropped"]
			line := fmt.Sprintf("  %s  workers=%s batch=%s queue=%s(%s%%) in=%s out=%s dlq=%s",
				titleStyle.Render(name),
				appFmtDash(workers),
				appFmtDash(batch),
				appFmtDash(qType),
				appFmtDash(qPct),
				appFmtDash(evIn),
				appFmtDash(evOut),
				appFmtDash(dlq))
			sb.WriteString(boxRow(line, iw) + "\n")

			// show slow filter for this pipeline
			if sf := dm[prefix+"slowfilter_0_name"]; sf != "" {
				sfMs := dm[prefix+"slowfilter_0_avg_ms"]
				inner := fmt.Sprintf("    %s slowest filter: %s @ %sms",
					dimStyle.Render("→"),
					valueStyle.Render(sf),
					valueStyle.Render(sfMs))
				sb.WriteString(boxRow(inner, iw) + "\n")
			}
		}
		sb.WriteString(boxBot(iw) + "\n\n")
	}

	// ── QUEUE ──
	if dm["queue_total_events"] != "" {
		sb.WriteString(appSection("PERSISTENT QUEUE", iw, []kv{
			{Key: "Total Events", Val: dm["queue_total_events"]},
			{Key: "Current Bytes", Val: dm["queue_total_cur"]},
			{Key: "Max Bytes", Val: dm["queue_total_max"]},
			{Key: "Usage %", Val: dm["queue_total_pct"]},
			{Key: "DLQ Dropped", Val: dm["dlq_total_events"]},
		}))
	}

	// ── RELOADS ──
	if dm["reload_successes"] != "" || dm["reload_failures"] != "" {
		sb.WriteString(appSection("CONFIG RELOADS", iw, []kv{
			{Key: "Successes", Val: dm["reload_successes"]},
			{Key: "Failures", Val: dm["reload_failures"]},
		}))
	}

	return sb.String()
}

// ── Kibana Detail ──────────────────────────────────────────────────────

func renderKibanaDeepMetrics(app model.AppInstance, iw int) string {
	var sb strings.Builder
	dm := app.DeepMetrics

	// ── HEALTH STATUS TABLE ──
	type hRow struct{ metric, value, status string }
	var rows []hRow

	if v := dm["status_overall"]; v != "" {
		s := "OK"
		switch strings.ToLower(v) {
		case "red", "critical", "unavailable":
			s = "CRIT"
		case "yellow", "degraded":
			s = "WARN"
		}
		rows = append(rows, hRow{"Overall Status", strings.ToUpper(v), s})
	}

	if n, _ := strconv.Atoi(dm["plugins_unavailable"]); n > 0 {
		rows = append(rows, hRow{"Plugins Unavailable", fmt.Sprintf("%d", n), "CRIT"})
	}
	if n, _ := strconv.Atoi(dm["plugins_degraded"]); n > 0 {
		rows = append(rows, hRow{"Plugins Degraded", fmt.Sprintf("%d", n), "WARN"})
	}

	if v, err := strconv.ParseFloat(dm["event_loop_delay_ms"], 64); err == nil {
		s := "OK"
		if v > 500 {
			s = "CRIT"
		} else if v > 100 {
			s = "WARN"
		}
		rows = append(rows, hRow{"Event Loop Delay", fmt.Sprintf("%.1fms", v), s})
	}

	if pctStr := dm["heap_used_pct"]; pctStr != "" {
		pct, _ := strconv.ParseFloat(pctStr, 64)
		s := "OK"
		if pct > 90 {
			s = "CRIT"
		} else if pct > 80 {
			s = "WARN"
		}
		rows = append(rows, hRow{"Node Heap", pctStr + "%", s})
	}

	if v, err := strconv.ParseFloat(dm["resp_avg_ms"], 64); err == nil {
		s := "OK"
		if v > 2000 {
			s = "CRIT"
		} else if v > 500 {
			s = "WARN"
		}
		rows = append(rows, hRow{"Avg Response", fmt.Sprintf("%.0fms", v), s})
	}

	if v, _ := strconv.ParseInt(dm["req_status_500"], 10, 64); v > 0 {
		rows = append(rows, hRow{"HTTP 500s", fmt.Sprintf("%d", v), "WARN"})
	}
	if v, _ := strconv.ParseInt(dm["req_status_503"], 10, 64); v > 0 {
		rows = append(rows, hRow{"HTTP 503s", fmt.Sprintf("%d", v), "WARN"})
	}

	if len(rows) > 0 {
		sb.WriteString("  " + titleStyle.Render("HEALTH STATUS") + "\n")
		sb.WriteString(boxTop(iw) + "\n")
		cM, cV := 22, 32
		hdr := fmt.Sprintf("  %s %s %s",
			styledPad(dimStyle.Render("Metric"), cM),
			styledPad(dimStyle.Render("Value"), cV),
			dimStyle.Render("Status"))
		sb.WriteString(boxRow(hdr, iw) + "\n")
		sb.WriteString(boxMid(iw) + "\n")
		for _, r := range rows {
			badge := okStyle.Render("OK")
			if r.status == "WARN" {
				badge = warnStyle.Render("WARN")
			} else if r.status == "CRIT" {
				badge = critStyle.Render("CRIT")
			}
			row := fmt.Sprintf("  %s %s %s",
				styledPad(valueStyle.Render(r.metric), cM),
				styledPad(valueStyle.Render(r.value), cV),
				badge)
			sb.WriteString(boxRow(row, iw) + "\n")
		}
		sb.WriteString(boxBot(iw) + "\n\n")
	}

	// ── NODE ──
	sb.WriteString(appSection("NODE", iw, []kv{
		{Key: "Name", Val: dm["node_name"]},
		{Key: "Version", Val: dm["version"]},
		{Key: "Build", Val: dm["build_number"]},
		{Key: "Status", Val: kibanaColorStatus(dm["status_overall"])},
		{Key: "Summary", Val: dm["status_summary"]},
		{Key: "Uptime (s)", Val: dm["process_uptime_sec"]},
	}))

	// ── MEMORY ──
	sb.WriteString(appSection("MEMORY", iw, []kv{
		{Key: "Heap Used", Val: dm["heap_used"]},
		{Key: "Heap Total", Val: dm["heap_total"]},
		{Key: "Heap Limit", Val: dm["heap_limit"]},
		{Key: "Heap Used %", Val: dm["heap_used_pct"]},
		{Key: "RSS", Val: dm["rss_bytes"]},
	}))

	// ── EVENT LOOP ──
	if dm["event_loop_delay_ms"] != "" {
		sb.WriteString(appSection("EVENT LOOP", iw, []kv{
			{Key: "Delay (ms)", Val: dm["event_loop_delay_ms"]},
			{Key: "OS Load 1m", Val: dm["os_load_1m"]},
		}))
	}

	// ── REQUESTS ──
	if dm["requests_total"] != "" {
		// collect status codes present
		codeKVs := []kv{
			{Key: "Total", Val: dm["requests_total"]},
			{Key: "Req/sec", Val: dm["requests_per_sec"]},
			{Key: "Concurrent", Val: dm["concurrent_connections"]},
			{Key: "Disconnects", Val: dm["requests_disconnects"]},
			{Key: "Avg Response (ms)", Val: dm["resp_avg_ms"]},
			{Key: "Max Response (ms)", Val: dm["resp_max_ms"]},
		}
		// appended status codes
		var codeKeys []string
		for k := range dm {
			if strings.HasPrefix(k, "req_status_") {
				codeKeys = append(codeKeys, k)
			}
		}
		sort.Strings(codeKeys)
		for _, k := range codeKeys {
			code := strings.TrimPrefix(k, "req_status_")
			codeKVs = append(codeKVs, kv{Key: "HTTP " + code, Val: dm[k]})
		}
		sb.WriteString(appSection("REQUESTS", iw, codeKVs))
	}

	// ── PLUGINS ──
	if dm["plugins_total"] != "" {
		plKVs := []kv{
			{Key: "Total", Val: dm["plugins_total"]},
			{Key: "Degraded", Val: dm["plugins_degraded"]},
			{Key: "Unavailable", Val: dm["plugins_unavailable"]},
			{Key: "Degraded Names", Val: dm["plugins_degraded_names"]},
			{Key: "Unavailable Names", Val: dm["plugins_unavailable_names"]},
		}
		sb.WriteString(appSection("PLUGINS", iw, plKVs))
	}

	return sb.String()
}

// ── helpers ──

func logstashColorStatus(s string) string {
	switch strings.ToLower(s) {
	case "green":
		return okStyle.Render("GREEN")
	case "yellow":
		return warnStyle.Render("YELLOW")
	case "red":
		return critStyle.Render("RED")
	}
	return s
}

func kibanaColorStatus(s string) string {
	switch strings.ToLower(s) {
	case "green", "available":
		return okStyle.Render(strings.ToUpper(s))
	case "yellow", "degraded":
		return warnStyle.Render(strings.ToUpper(s))
	case "red", "critical", "unavailable":
		return critStyle.Render(strings.ToUpper(s))
	}
	return s
}

func formatUptimeMS(ms string) string {
	if ms == "" {
		return ""
	}
	v, err := strconv.ParseInt(ms, 10, 64)
	if err != nil {
		return ms
	}
	sec := v / 1000
	if sec < 60 {
		return fmt.Sprintf("%ds", sec)
	}
	if sec < 3600 {
		return fmt.Sprintf("%dm", sec/60)
	}
	if sec < 86400 {
		return fmt.Sprintf("%dh", sec/3600)
	}
	return fmt.Sprintf("%dd", sec/86400)
}

// sanitizeUIKey mirrors sanitizeKey in collector/apps; duplicated here to avoid
// cross-package dependency on an internal helper.
func sanitizeUIKey(s string) string {
	s = strings.ToLower(s)
	s = strings.ReplaceAll(s, " ", "_")
	s = strings.ReplaceAll(s, "-", "_")
	s = strings.ReplaceAll(s, ".", "_")
	return s
}

// ── Compact verdicts ──

func logstashCompactVerdict(app model.AppInstance) string {
	dm := app.DeepMetrics
	badge := okStyle.Render("●")
	parts := []string{}
	if s := dm["status"]; s != "" {
		parts = append(parts, "status "+s)
		if s == "red" {
			badge = critStyle.Render("✗")
		} else if s == "yellow" {
			badge = warnStyle.Render("⚠")
		}
	}
	if pc := dm["pipeline_count"]; pc != "" {
		parts = append(parts, pc+" pipelines")
	}
	if in := dm["events_in_per_sec"]; in != "" {
		out := dm["events_out_per_sec"]
		parts = append(parts, fmt.Sprintf("%s→%s ev/s", in, out))
		if inV, _ := strconv.ParseFloat(in, 64); inV > 10 {
			if outV, _ := strconv.ParseFloat(out, 64); outV < 0.1 {
				badge = critStyle.Render("✗")
				parts = append(parts, critStyle.Render("STALLED"))
			}
		}
	}
	if h := dm["jvm_heap_used_pct"]; h != "" {
		parts = append(parts, h+"% heap")
	}
	if q := dm["queue_total_pct"]; q != "" && q != "0.0" {
		parts = append(parts, q+"% queue")
	}
	return badge + "  " + valueStyle.Render(strings.Join(parts, "  "))
}

func logstashCompactSections(app model.AppInstance, iw int) string {
	dm := app.DeepMetrics
	var sections []compactSection

	nodeStatus := "OK"
	if dm["status"] == "red" {
		nodeStatus = "CRIT"
	} else if dm["status"] == "yellow" {
		nodeStatus = "WARN"
	}
	sections = append(sections, compactSection{"Node", nodeStatus,
		fmt.Sprintf("status=%s version=%s", appFmtDash(dm["status"]), appFmtDash(dm["version"]))})

	jvmStatus := "OK"
	if h := dm["jvm_heap_used_pct"]; h != "" {
		var hv float64
		fmt.Sscanf(h, "%f", &hv)
		if hv > 90 {
			jvmStatus = "CRIT"
		} else if hv > 80 {
			jvmStatus = "WARN"
		}
	}
	sections = append(sections, compactSection{"JVM", jvmStatus,
		fmt.Sprintf("heap %s/%s (%s%%)", appFmtDash(dm["jvm_heap_used"]), appFmtDash(dm["jvm_heap_max"]), appFmtDash(dm["jvm_heap_used_pct"]))})

	inV, _ := strconv.ParseFloat(dm["events_in_per_sec"], 64)
	outV, _ := strconv.ParseFloat(dm["events_out_per_sec"], 64)
	evStatus := "OK"
	if inV > 10 && outV < 0.1 {
		evStatus = "CRIT"
	} else if inV > 0 && outV > 0 && outV < inV*0.5 {
		evStatus = "WARN"
	}
	sections = append(sections, compactSection{"Events", evStatus,
		fmt.Sprintf("in=%.1f/s out=%.1f/s filtered=%s/s", inV, outV, appFmtDash(dm["events_filtered_per_sec"]))})

	qStatus := "OK"
	if p, err := strconv.ParseFloat(dm["queue_total_pct"], 64); err == nil {
		if p > 90 {
			qStatus = "CRIT"
		} else if p > 75 {
			qStatus = "WARN"
		}
	}
	sections = append(sections, compactSection{"Queue", qStatus,
		fmt.Sprintf("%s/%s (%s%%) DLQ=%s", appFmtDash(dm["queue_total_cur"]), appFmtDash(dm["queue_total_max"]), appFmtDash(dm["queue_total_pct"]), appFmtDash(dm["dlq_total_events"]))})

	return "\n" + renderCompactSectionList(sections, iw)
}

func kibanaCompactVerdict(app model.AppInstance) string {
	dm := app.DeepMetrics
	badge := okStyle.Render("●")
	parts := []string{}
	if s := dm["status_overall"]; s != "" {
		parts = append(parts, "status "+strings.ToLower(s))
		switch strings.ToLower(s) {
		case "red", "critical", "unavailable":
			badge = critStyle.Render("✗")
		case "yellow", "degraded":
			badge = warnStyle.Render("⚠")
		}
	}
	if n := dm["plugins_unavailable"]; n != "" && n != "0" {
		parts = append(parts, n+" plugins down")
		badge = critStyle.Render("✗")
	}
	if n := dm["plugins_degraded"]; n != "" && n != "0" {
		parts = append(parts, n+" plugins degraded")
	}
	if d := dm["event_loop_delay_ms"]; d != "" {
		dv, _ := strconv.ParseFloat(d, 64)
		parts = append(parts, fmt.Sprintf("loop %.0fms", dv))
		if dv > 500 {
			badge = critStyle.Render("✗")
		} else if dv > 100 && badge == okStyle.Render("●") {
			badge = warnStyle.Render("⚠")
		}
	}
	if h := dm["heap_used_pct"]; h != "" {
		parts = append(parts, h+"% heap")
	}
	return badge + "  " + valueStyle.Render(strings.Join(parts, "  "))
}

func kibanaCompactSections(app model.AppInstance, iw int) string {
	dm := app.DeepMetrics
	var sections []compactSection

	overallStatus := "OK"
	switch strings.ToLower(dm["status_overall"]) {
	case "red", "critical", "unavailable":
		overallStatus = "CRIT"
	case "yellow", "degraded":
		overallStatus = "WARN"
	}
	sections = append(sections, compactSection{"Status", overallStatus,
		fmt.Sprintf("%s — %s", appFmtDash(dm["status_overall"]), appFmtDash(dm["status_summary"]))})

	plStatus := "OK"
	if n, _ := strconv.Atoi(dm["plugins_unavailable"]); n > 0 {
		plStatus = "CRIT"
	} else if n, _ := strconv.Atoi(dm["plugins_degraded"]); n > 0 {
		plStatus = "WARN"
	}
	sections = append(sections, compactSection{"Plugins", plStatus,
		fmt.Sprintf("total=%s degraded=%s unavailable=%s", appFmtDash(dm["plugins_total"]), appFmtDash(dm["plugins_degraded"]), appFmtDash(dm["plugins_unavailable"]))})

	loopStatus := "OK"
	if v, err := strconv.ParseFloat(dm["event_loop_delay_ms"], 64); err == nil {
		if v > 500 {
			loopStatus = "CRIT"
		} else if v > 100 {
			loopStatus = "WARN"
		}
	}
	sections = append(sections, compactSection{"EventLoop", loopStatus,
		fmt.Sprintf("delay=%sms load_1m=%s", appFmtDash(dm["event_loop_delay_ms"]), appFmtDash(dm["os_load_1m"]))})

	heapStatus := "OK"
	if h, err := strconv.ParseFloat(dm["heap_used_pct"], 64); err == nil {
		if h > 90 {
			heapStatus = "CRIT"
		} else if h > 80 {
			heapStatus = "WARN"
		}
	}
	sections = append(sections, compactSection{"Heap", heapStatus,
		fmt.Sprintf("%s/%s (%s%%)", appFmtDash(dm["heap_used"]), appFmtDash(dm["heap_limit"]), appFmtDash(dm["heap_used_pct"]))})

	reqStatus := "OK"
	if v, err := strconv.ParseFloat(dm["resp_avg_ms"], 64); err == nil {
		if v > 2000 {
			reqStatus = "CRIT"
		} else if v > 500 {
			reqStatus = "WARN"
		}
	}
	sections = append(sections, compactSection{"Requests", reqStatus,
		fmt.Sprintf("avg=%sms max=%sms rps=%s", appFmtDash(dm["resp_avg_ms"]), appFmtDash(dm["resp_max_ms"]), appFmtDash(dm["requests_per_sec"]))})

	return "\n" + renderCompactSectionList(sections, iw)
}
