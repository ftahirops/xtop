//go:build linux

package ui

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/ftahirops/xtop/model"
)

func renderAppsPage(snap *model.Snapshot, selectedIdx int, detailMode bool,
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
		if viewCompact {
			return renderAppsDetailCompact(app, iw)
		}
		return renderAppsDetail(app, iw)
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

	// Service probes section (merged from Services page)
	sb.WriteString(renderAppsServiceProbes(snap, iw))

	sb.WriteString(pageFooter("j/k:Navigate  Enter:Details  Y:Apps"))
	return sb.String()
}

// ── Generic App Detail ─────────────────────────────────────────────────

func renderAppsDetail(app model.AppInstance, iw int) string {
	var sb strings.Builder

	sb.WriteString(appDetailHeader(app))

	// Show credential requirement notice at the TOP (only when needed)
	if app.NeedsCreds && !app.HasDeepMetrics {
		sb.WriteString(renderCredsNotice(app, iw))
	}

	sb.WriteString(renderAppInfoResourceBox(app, iw))

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

	sb.WriteString(appSection("CLUSTER", iw, []kv{
		{Key: "Cluster Name", Val: dm["cluster_name"]},
		{Key: "Status", Val: esColorStatus(dm["status"])},
		{Key: "Nodes", Val: dm["number_of_nodes"]},
		{Key: "Data Nodes", Val: dm["number_of_data_nodes"]},
		{Key: "Lucene", Val: dm["lucene_version"]},
	}))

	sb.WriteString(appSection("SHARDS", iw, []kv{
		{Key: "Active Primary", Val: dm["active_primary_shards"]},
		{Key: "Active Total", Val: dm["active_shards"]},
		{Key: "Unassigned", Val: esColorVal(dm["unassigned_shards"], "0")},
		{Key: "Relocating", Val: dm["relocating_shards"]},
		{Key: "Initializing", Val: dm["initializing_shards"]},
		{Key: "Pending Tasks", Val: dm["number_of_pending_tasks"]},
		{Key: "Active %", Val: dm["active_shards_percent_as_number"]},
	}))

	sb.WriteString(appSection("INDICES", iw, []kv{
		{Key: "Total Indices", Val: dm["total_indices"]},
		{Key: "Green", Val: dm["indices_green"]},
		{Key: "Yellow", Val: esColorVal(dm["indices_yellow"], "0")},
		{Key: "Red", Val: esColorVal(dm["indices_red"], "0")},
		{Key: "Documents", Val: dm["doc_count"]},
		{Key: "Deleted Docs", Val: dm["deleted_docs"]},
		{Key: "Store Size", Val: dm["store_size"]},
		{Key: "Segments", Val: dm["segment_count"]},
		{Key: "Segment Memory", Val: dm["segment_memory"]},
	}))

	sb.WriteString(appSection("JVM & MEMORY", iw, []kv{
		{Key: "Heap Used", Val: dm["jvm_heap_used"]},
		{Key: "Heap Max", Val: dm["jvm_heap_max"]},
		{Key: "Heap Used %", Val: dm["jvm_heap_used_pct"]},
		{Key: "Fielddata Mem", Val: dm["fielddata_memory"]},
		{Key: "Fielddata Evictions", Val: dm["fielddata_evictions"]},
		{Key: "Query Cache Mem", Val: dm["query_cache_memory"]},
		{Key: "Query Cache Hits", Val: dm["query_cache_hits"]},
		{Key: "Query Cache Misses", Val: dm["query_cache_misses"]},
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

	sb.WriteString(appSection("THROUGHPUT", iw, []kv{
		{Key: "Index Total", Val: dm["index_total"]},
		{Key: "Index Time (ms)", Val: dm["index_time_ms"]},
		{Key: "Search Queries", Val: dm["search_query_total"]},
		{Key: "Search Time (ms)", Val: dm["search_query_time_ms"]},
		{Key: "Merges", Val: dm["merge_total"]},
		{Key: "OS CPU", Val: dm["os_cpu_pct"]},
		{Key: "HTTP Connections", Val: dm["http_current_open"]},
	}))

	return sb.String()
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
func renderAppInfoResourceBox(app model.AppInstance, iw int) string {
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
	cpuStr := fmt.Sprintf("%.1f%%", app.CPUPct)
	if app.CPUPct > 80 {
		cpuStr = critStyle.Render(cpuStr)
	} else if app.CPUPct > 50 {
		cpuStr = warnStyle.Render(cpuStr)
	} else {
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
