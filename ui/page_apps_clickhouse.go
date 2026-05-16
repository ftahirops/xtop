package ui

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/ftahirops/xtop/model"
)

// renderClickHouseDeepMetrics is the operator-facing detail view for
// a detected ClickHouse instance.
//
// Goal: turn the raw `system.*` query results into something a human
// can read top-to-bottom and immediately know:
//
//   - Is this server healthy?
//   - What's it storing?
//   - What's currently running?
//   - Is ingest keeping up with compaction?
//   - Are caches doing their job?
//   - What's actually failing?
//   - What should I tune first?
//
// The earlier "generic" renderer dumped key=value pairs alphabetically
// which buried the answer to every one of those questions in noise.
//
// Sections are ordered by likely-action: errors and recommendations
// at the bottom so the eye doesn't fixate on them when everything's
// fine; storage and query patterns up top because they're the meat.
func renderClickHouseDeepMetrics(app model.AppInstance, iw int) string {
	dm := app.DeepMetrics
	var sb strings.Builder

	sb.WriteString("  " + titleStyle.Render("CLICKHOUSE — Deep Analysis") + "\n")

	// ─── HEALTH BANNER ───────────────────────────────────────────────
	// One-line summary so operators triaging an incident don't have
	// to read the whole page.
	sb.WriteString(chSection("Health", iw))
	healthScore := app.HealthScore
	healthColor := okStyle
	healthLabel := "HEALTHY"
	if healthScore < 80 {
		healthColor = warnStyle
		healthLabel = "DEGRADED"
	}
	if healthScore < 50 {
		healthColor = critStyle
		healthLabel = "CRITICAL"
	}
	sb.WriteString(chRow("Status", healthColor.Render(
		fmt.Sprintf("%s (score %d/100)", healthLabel, healthScore)), iw))
	if v := dm["version"]; v != "" {
		sb.WriteString(chRow("Version", valueStyle.Render(v), iw))
	}
	if v := dm["memory_resident_mb"]; v != "" {
		mb, _ := strconv.ParseFloat(v, 64)
		sb.WriteString(chRow("Server memory",
			valueStyle.Render(humanBytes(int64(mb*1024*1024))+
				dimStyle.Render(" (CH-tracked, includes caches)")), iw))
	}
	if len(app.HealthIssues) > 0 {
		for _, h := range app.HealthIssues {
			sb.WriteString(chRow("Issue", warnStyle.Render("• "+h), iw))
		}
	}
	sb.WriteString(chSpacer(iw))

	// ─── STORAGE ─────────────────────────────────────────────────────
	sb.WriteString(chSection("Storage", iw))
	if v := dm["databases"]; v != "" {
		sb.WriteString(chRow("Databases", valueStyle.Render(v), iw))
	}
	if v := dm["active_parts"]; v != "" {
		n, _ := strconv.ParseInt(v, 10, 64)
		warn := ""
		if n > 10000 {
			warn = warnStyle.Render(" (high — consider OPTIMIZE FINAL or part-size tuning)")
		}
		sb.WriteString(chRow("Active parts", valueStyle.Render(humanCount(n))+warn, iw))
	}
	if v := dm["total_rows"]; v != "" {
		n, _ := strconv.ParseInt(v, 10, 64)
		sb.WriteString(chRow("Total rows", valueStyle.Render(humanCount(n)), iw))
	}
	if v := dm["database_sizes"]; v != "" {
		for _, line := range splitListGuess(v) {
			sb.WriteString(chRow("DB", dimStyle.Render(line), iw))
		}
	}
	if v := dm["top_tables"]; v != "" {
		sb.WriteString(chRow("Top tables", "", iw))
		for _, line := range splitListGuess(v) {
			sb.WriteString(chRow("", dimStyle.Render("• "+line), iw))
		}
	}
	sb.WriteString(chSpacer(iw))

	// ─── QUERY ACTIVITY ──────────────────────────────────────────────
	sb.WriteString(chSection("Query activity", iw))
	if v := dm["active_queries"]; v != "" {
		sb.WriteString(chRow("Active right now", valueStyle.Render(v), iw))
	}
	if v := dm["long_running_queries"]; v != "" {
		n, _ := strconv.Atoi(v)
		style := okStyle
		note := ""
		if n > 0 {
			style = warnStyle
			note = dimStyle.Render(" (queries running > 30s — see system.processes)")
		}
		sb.WriteString(chRow("Long-running (>30s)", style.Render(v)+note, iw))
	}
	total, _ := strconv.ParseInt(dm["queries_total"], 10, 64)
	failed, _ := strconv.ParseInt(dm["queries_failed"], 10, 64)
	if total > 0 {
		failPct := float64(failed) / float64(total) * 100
		sb.WriteString(chRow("Total since boot",
			valueStyle.Render(humanCount(total)), iw))
		failStyle := okStyle
		if failPct > 1 {
			failStyle = warnStyle
		}
		if failPct > 5 {
			failStyle = critStyle
		}
		sb.WriteString(chRow("Failed", failStyle.Render(
			fmt.Sprintf("%s (%.2f%% of total)", humanCount(failed), failPct)), iw))
	}
	if v := dm["top_queries_1h"]; v != "" {
		sb.WriteString(chRow("Top queries (1h)", "", iw))
		for _, line := range splitListGuess(v) {
			sb.WriteString(chRow("", dimStyle.Render(line), iw))
		}
	}
	sb.WriteString(chSpacer(iw))

	// ─── INGEST & COMPACTION ─────────────────────────────────────────
	sb.WriteString(chSection("Ingest / compaction", iw))
	if v := dm["active_merges"]; v != "" {
		n, _ := strconv.Atoi(v)
		style := okStyle
		note := ""
		switch {
		case n > 50:
			style = critStyle
			note = dimStyle.Render(" (ingest outpacing compaction — see background_pool_size)")
		case n > 20:
			style = warnStyle
			note = dimStyle.Render(" (elevated — watch ingest rate)")
		}
		sb.WriteString(chRow("Active merges", style.Render(v)+note, iw))
	}
	if v := dm["pending_mutations"]; v != "" {
		sb.WriteString(chRow("Pending mutations", valueStyle.Render(v), iw))
	}
	if v := dm["async_insert_queue"]; v != "" {
		n, _ := strconv.Atoi(v)
		style := okStyle
		if n > 100 {
			style = warnStyle
		}
		sb.WriteString(chRow("Async-insert queue", style.Render(v), iw))
	}
	sb.WriteString(chSpacer(iw))

	// ─── CACHES ──────────────────────────────────────────────────────
	sb.WriteString(chSection("Caches", iw))
	if v := dm["mark_cache_hit_pct"]; v != "" {
		f, _ := strconv.ParseFloat(v, 64)
		style := okStyle
		note := ""
		switch {
		case f < 80:
			style = critStyle
			note = dimStyle.Render(" (very low — increase mark_cache_size in config)")
		case f < 95:
			style = warnStyle
			note = dimStyle.Render(" (below ideal — consider larger mark_cache_size)")
		}
		sb.WriteString(chRow("Mark cache hits", style.Render(v+"%")+note, iw))
	}
	if v := dm["uncompressed_cache_hit_pct"]; v != "" {
		f, _ := strconv.ParseFloat(v, 64)
		// Uncompressed cache is much smaller by default — sub-50% is
		// expected unless workload is highly cacheable.
		style := okStyle
		note := dimStyle.Render(" (low is normal — disabled by default on many workloads)")
		if f > 50 {
			style = okStyle
			note = ""
		}
		sb.WriteString(chRow("Uncompressed cache", style.Render(v+"%")+note, iw))
	}
	sb.WriteString(chSpacer(iw))

	// ─── REPLICATION ─────────────────────────────────────────────────
	// Only render this section when the cluster is actually replicated.
	repQueue, _ := strconv.Atoi(dm["replication_queue"])
	repDeg, _ := strconv.Atoi(dm["replicas_degraded"])
	zkConn, _ := strconv.Atoi(dm["zookeeper_connections"])
	if repQueue > 0 || repDeg > 0 || zkConn > 0 {
		sb.WriteString(chSection("Replication", iw))
		style := okStyle
		if repQueue > 100 {
			style = warnStyle
		}
		sb.WriteString(chRow("Replication queue", style.Render(dm["replication_queue"]), iw))
		degStyle := okStyle
		if repDeg > 0 {
			degStyle = critStyle
		}
		sb.WriteString(chRow("Degraded replicas", degStyle.Render(dm["replicas_degraded"]), iw))
		sb.WriteString(chRow("ZooKeeper conns", valueStyle.Render(dm["zookeeper_connections"]), iw))
		sb.WriteString(chSpacer(iw))
	}

	// ─── ERRORS ──────────────────────────────────────────────────────
	if e5 := dm["errors_5min"]; e5 != "" {
		sb.WriteString(chSection("Errors (recent)", iw))
		n, _ := strconv.Atoi(e5)
		style := okStyle
		if n > 0 {
			style = warnStyle
		}
		sb.WriteString(chRow("Last 5 min", style.Render(e5), iw))
		if te := dm["top_error"]; te != "" {
			// Special-case WRONG_PASSWORD with a contextual hint —
			// this one almost always traces to a misconfigured local
			// client (Grafana datasource, xtop pre-credentials, an
			// automation script). Tell the operator what to check.
			explain := ""
			if strings.Contains(te, "WRONG_PASSWORD") {
				explain = "\n" + chRow("",
					dimStyle.Render("    ↳ check local clients (grafana datasource, xtop pre-creds, automation scripts) — see /var/log/clickhouse-server/clickhouse-server.log"),
					iw)
			} else if strings.Contains(te, "TIMEOUT_EXCEEDED") {
				explain = "\n" + chRow("",
					dimStyle.Render("    ↳ queries hitting max_execution_time — review system.query_log"),
					iw)
			} else if strings.Contains(te, "MEMORY_LIMIT_EXCEEDED") {
				explain = "\n" + chRow("",
					dimStyle.Render("    ↳ raise max_memory_usage / max_server_memory_usage or trim heavy queries"),
					iw)
			}
			sb.WriteString(chRow("Top error", warnStyle.Render(te), iw))
			sb.WriteString(explain)
		}
		sb.WriteString(chSpacer(iw))
	}

	// ─── RECOMMENDATIONS ─────────────────────────────────────────────
	if v := dm["recommendations"]; v != "" {
		sb.WriteString(chSection("Recommendations", iw))
		for _, rec := range splitListGuess(v) {
			sb.WriteString(chRow("",
				lipglossOK("→ ")+valueStyle.Render(rec), iw))
		}
		sb.WriteString(chSpacer(iw))
	}

	return sb.String()
}

// chSection draws a single-line section header.
func chSection(name string, iw int) string {
	return "  " + headerStyle.Render("── "+name+" ────────") + "\n"
}

// chRow renders one "key: value" inside the deep-metrics block.
// If the key is empty the line is treated as a continuation (just
// the value, indented), which is how multi-row sections like
// "top queries" lay out.
func chRow(key, val string, iw int) string {
	if key == "" {
		return "    " + val + "\n"
	}
	return "  " + styledPad(dimStyle.Render(key+":"), 22) + " " + val + "\n"
}

// chSpacer is a blank line between sections.
func chSpacer(iw int) string { return "\n" }

// humanCount turns 3428369760 into "3.4B", 267488 into "267.5K", etc.
// Short, terminal-friendly, never longer than 7 characters.
func humanCount(n int64) string {
	if n < 1000 {
		return strconv.FormatInt(n, 10)
	}
	f := float64(n)
	switch {
	case f >= 1e12:
		return fmt.Sprintf("%.1fT", f/1e12)
	case f >= 1e9:
		return fmt.Sprintf("%.1fB", f/1e9)
	case f >= 1e6:
		return fmt.Sprintf("%.1fM", f/1e6)
	case f >= 1e3:
		return fmt.Sprintf("%.1fK", f/1e3)
	}
	return strconv.FormatInt(n, 10)
}

// humanBytes turns 6577 MB into "6.4 GiB" etc. Uses binary multiples
// to match ClickHouse's own formatReadableSize. Adapt to KiB/MiB/GiB.
func humanBytes(b int64) string {
	const (
		kib int64 = 1024
		mib       = kib * 1024
		gib       = mib * 1024
		tib       = gib * 1024
	)
	switch {
	case b >= tib:
		return fmt.Sprintf("%.2f TiB", float64(b)/float64(tib))
	case b >= gib:
		return fmt.Sprintf("%.2f GiB", float64(b)/float64(gib))
	case b >= mib:
		return fmt.Sprintf("%.1f MiB", float64(b)/float64(mib))
	case b >= kib:
		return fmt.Sprintf("%.1f KiB", float64(b)/float64(kib))
	}
	return fmt.Sprintf("%d B", b)
}

// splitListGuess splits a string by " ║ " (collector's separator),
// falling back to comma. Used for fields packed as comma- or
// pipe-separated lists in DeepMetrics.
func splitListGuess(s string) []string {
	if strings.Contains(s, " ║ ") {
		return strings.Split(s, " ║ ")
	}
	parts := strings.Split(s, ", ")
	// Sort for stable output — alphabetised lists make for predictable
	// diffs between ticks.
	sort.Strings(parts)
	return parts
}

// lipglossOK is a tiny shim so we don't pull more imports — returns
// a green-styled string.
func lipglossOK(s string) string { return okStyle.Render(s) }
