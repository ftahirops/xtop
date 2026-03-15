//go:build linux

package ui

import (
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/charmbracelet/lipgloss"
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

// ── Redis Detail ───────────────────────────────────────────────────────

func renderRedisDeepMetrics(app model.AppInstance, iw int) string {
	var sb strings.Builder
	dm := app.DeepMetrics

	// Column widths: 33% health, 67% throughput
	healthW := iw / 3
	tpW := iw - healthW - 4 // gap between columns

	// ── SECTION 1: HEALTH STATUS (33%) | THROUGHPUT & CLIENTS (67%) ──
	sb.WriteString("  " + titleStyle.Render("HEALTH STATUS") + strings.Repeat(" ", healthW-15) + titleStyle.Render("THROUGHPUT & CLIENTS") + "\n")
	sb.WriteString(boxTop(iw) + "\n")

	type healthRow struct {
		metric, value, status string
	}
	var hRows []healthRow

	if dm["memory_usage_pct"] != "" {
		var pct float64
		fmt.Sscanf(dm["memory_usage_pct"], "%f", &pct)
		st := "OK"
		if pct > 90 {
			st = "CRIT"
		} else if pct > 75 {
			st = "WARN"
		}
		hRows = append(hRows, healthRow{"Memory", dm["used_memory_human"] + "/" + dm["maxmemory_human"] + " (" + dm["memory_usage_pct"] + ")", st})
	} else if dm["maxmemory"] == "0" || dm["maxmemory"] == "" {
		hRows = append(hRows, healthRow{"Memory", dm["used_memory_human"] + " (no limit)", "OK"})
	}
	if dm["hit_ratio"] != "" {
		var ratio float64
		fmt.Sscanf(dm["hit_ratio"], "%f", &ratio)
		st := "OK"
		if ratio < 80 {
			st = "CRIT"
		} else if ratio < 90 {
			st = "WARN"
		}
		hRows = append(hRows, healthRow{"Hit Ratio", dm["hit_ratio"], st})
	}
	if ev := dm["evicted_keys"]; ev != "" {
		st := "OK"
		if ev != "0" {
			st = "CRIT"
		}
		hRows = append(hRows, healthRow{"Evictions", ev, st})
	}
	if dm["mem_fragmentation_ratio"] != "" {
		frag, _ := strconv.ParseFloat(dm["mem_fragmentation_ratio"], 64)
		st := "OK"
		if frag > 1.5 || (frag < 1.0 && frag > 0) {
			st = "WARN"
		}
		hRows = append(hRows, healthRow{"Fragmentation", dm["mem_fragmentation_ratio"], st})
	}
	if dm["blocked_clients"] != "" {
		st := "OK"
		b, _ := strconv.Atoi(dm["blocked_clients"])
		if b > 10 {
			st = "CRIT"
		} else if b > 0 {
			st = "WARN"
		}
		hRows = append(hRows, healthRow{"Blocked", dm["blocked_clients"], st})
	}
	{
		st := "OK"
		if dm["rejected_connections"] != "" && dm["rejected_connections"] != "0" {
			st = "CRIT"
		}
		hRows = append(hRows, healthRow{"Rejected", dm["rejected_connections"], st})
	}
	if dm["rdb_last_bgsave_status"] != "" {
		st := "OK"
		if dm["rdb_last_bgsave_status"] != "ok" {
			st = "CRIT"
		}
		hRows = append(hRows, healthRow{"RDB Save", dm["rdb_last_bgsave_status"], st})
	}
	if dm["role"] == "slave" && dm["master_link_status"] != "" {
		st := "OK"
		if dm["master_link_status"] == "down" {
			st = "CRIT"
		}
		hRows = append(hRows, healthRow{"Repl Link", dm["master_link_status"], st})
	}
	// New health indicators
	if p99 := dm["latency_percentiles_usec_p99"]; p99 != "" {
		p99v, _ := strconv.ParseFloat(p99, 64)
		st := "OK"
		label := redisFmtUsec(p99v)
		if p99v > 10000 {
			st = "CRIT"
		} else if p99v > 1000 {
			st = "WARN"
		}
		hRows = append(hRows, healthRow{"P99 Latency", label, st})
	}
	if rssR := dm["rss_overhead_ratio"]; rssR != "" {
		rssv, _ := strconv.ParseFloat(rssR, 64)
		st := "OK"
		if rssv > 2.0 {
			st = "CRIT"
		} else if rssv > 1.5 {
			st = "WARN"
		}
		hRows = append(hRows, healthRow{"RSS Ratio", rssR + "x", st})
	}
	if capPct := dm["client_capacity_pct"]; capPct != "" {
		var cv float64
		fmt.Sscanf(capPct, "%f", &cv)
		st := "OK"
		if cv > 80 {
			st = "CRIT"
		} else if cv > 60 {
			st = "WARN"
		}
		hRows = append(hRows, healthRow{"Client Cap", capPct, st})
	}
	if forkUs := dm["latest_fork_usec"]; forkUs != "" {
		fv, _ := strconv.ParseInt(forkUs, 10, 64)
		st := "OK"
		label := redisFmtUsec(float64(fv))
		if fv > 500000 {
			st = "CRIT"
		} else if fv > 100000 {
			st = "WARN"
		}
		hRows = append(hRows, healthRow{"Fork Time", label, st})
	}
	if dm["slowlog_count"] != "" && dm["slowlog_count"] != "0" {
		st := "WARN"
		hRows = append(hRows, healthRow{"Slow Queries", dm["slowlog_count"] + " recent", st})
	}

	// Throughput items split into 2 sub-columns on right side
	type tpItem struct{ key, val string }
	tpCol1 := []tpItem{
		{"Ops/sec", dm["instantaneous_ops_per_sec"]},
		{"Input", redisFmtKbps(dm["instantaneous_input_kbps"])},
		{"Output", redisFmtKbps(dm["instantaneous_output_kbps"])},
		{"Total Cmds", redisFmtLargeNum(dm["total_commands_processed"])},
		{"Total Conns", redisFmtLargeNum(dm["total_connections_received"])},
		{"Net In", redisFmtNetBytes(dm["total_net_input_bytes"])},
		{"Net Out", redisFmtNetBytes(dm["total_net_output_bytes"])},
	}
	// Add latency to TP col1
	if p50 := dm["latency_percentiles_usec_p50"]; p50 != "" {
		p50v, _ := strconv.ParseFloat(p50, 64)
		tpCol1 = append(tpCol1, tpItem{"Latency p50", redisFmtUsec(p50v)})
	}
	if p99 := dm["latency_percentiles_usec_p99"]; p99 != "" {
		p99v, _ := strconv.ParseFloat(p99, 64)
		tpCol1 = append(tpCol1, tpItem{"Latency p99", redisFmtUsec(p99v)})
	}
	tpCol2 := []tpItem{
		{"Connected", dm["connected_clients"]},
		{"Blocked", dm["blocked_clients"]},
		{"Max Clients", dm["maxclients"]},
		{"Client Cap", dm["client_capacity_pct"]},
		{"Rejected", dm["rejected_connections"]},
		{"CPU Sys", redisFmtSec(dm["used_cpu_sys"])},
		{"CPU User", redisFmtSec(dm["used_cpu_user"])},
	}
	if ps := dm["pubsub_channels"]; ps != "" && ps != "0" {
		tpCol2 = append(tpCol2, tpItem{"PubSub Ch", ps})
	}
	if lf := dm["lazyfree_pending_objects"]; lf != "" && lf != "0" {
		tpCol2 = append(tpCol2, tpItem{"Lazyfree", lf})
	}

	cLabel := 14
	cVal := healthW - cLabel - 10
	if cVal < 10 {
		cVal = 10
	}
	tpHalf := (tpW - 2) / 2
	tpLabel := 13
	tpVal := tpHalf - tpLabel - 2
	if tpVal < 8 {
		tpVal = 8
	}

	maxRows := len(hRows)
	if len(tpCol1) > maxRows {
		maxRows = len(tpCol1)
	}
	if len(tpCol2) > maxRows {
		maxRows = len(tpCol2)
	}

	for i := 0; i < maxRows; i++ {
		// Health column (left 33%)
		var left string
		if i < len(hRows) {
			r := hRows[i]
			var badge string
			switch r.status {
			case "OK":
				badge = okStyle.Render("OK")
			case "WARN":
				badge = warnStyle.Render("WARN")
			case "CRIT":
				badge = critStyle.Render("CRIT")
			}
			left = fmt.Sprintf("%s %s %s",
				styledPad(dimStyle.Render(r.metric+":"), cLabel),
				styledPad(valueStyle.Render(r.value), cVal),
				badge)
		}

		// TP column 1 (middle)
		var mid string
		if i < len(tpCol1) && tpCol1[i].val != "" {
			mid = fmt.Sprintf("%s %s",
				styledPad(dimStyle.Render(tpCol1[i].key+":"), tpLabel),
				styledPad(valueStyle.Render(tpCol1[i].val), tpVal))
		}

		// TP column 2 (right)
		var right string
		if i < len(tpCol2) && tpCol2[i].val != "" {
			right = fmt.Sprintf("%s %s",
				styledPad(dimStyle.Render(tpCol2[i].key+":"), tpLabel),
				valueStyle.Render(tpCol2[i].val))
		}

		row := fmt.Sprintf("  %s %s %s %s %s",
			styledPad(left, healthW),
			dimStyle.Render("│"),
			styledPad(mid, tpHalf),
			dimStyle.Render("│"),
			right)
		sb.WriteString(boxRow(row, iw) + "\n")
	}
	sb.WriteString(boxBot(iw) + "\n")

	// ── SECTION 2: KEYSPACE & COMMANDS (full width, single box) ──
	sb.WriteString("  " + titleStyle.Render("KEYSPACE & COMMANDS") + "\n")
	sb.WriteString(boxTop(iw) + "\n")

	// Parse command stats
	type cmdEntry struct {
		name   string
		calls  int64
		usecPC float64
	}
	var cmds []cmdEntry
	for k, v := range dm {
		if !strings.HasPrefix(k, "cmdstat_") {
			continue
		}
		cmdName := strings.ToUpper(k[8:])
		var calls int64
		var usecPC float64
		for _, part := range strings.Split(v, ",") {
			pair := strings.SplitN(part, "=", 2)
			if len(pair) != 2 {
				continue
			}
			switch pair[0] {
			case "calls":
				calls, _ = strconv.ParseInt(pair[1], 10, 64)
			case "usec_per_call":
				usecPC, _ = strconv.ParseFloat(pair[1], 64)
			}
		}
		if calls > 0 {
			cmds = append(cmds, cmdEntry{name: cmdName, calls: calls, usecPC: usecPC})
		}
	}
	for i := 0; i < len(cmds); i++ {
		for j := i + 1; j < len(cmds); j++ {
			if cmds[j].calls > cmds[i].calls {
				cmds[i], cmds[j] = cmds[j], cmds[i]
			}
		}
	}
	var totalCmdCalls int64
	for _, c := range cmds {
		totalCmdCalls += c.calls
	}

	// DB table header
	dbHdr := fmt.Sprintf("  %s %s %s %s",
		styledPad(dimStyle.Render("DB"), 6),
		styledPad(dimStyle.Render("Keys"), 12),
		styledPad(dimStyle.Render("Expires"), 12),
		dimStyle.Render("Avg TTL"))
	sb.WriteString(boxRow(dbHdr, iw) + "\n")
	sb.WriteString(boxMid(iw) + "\n")

	// DB rows
	totalKeys := 0
	totalExpires := 0
	for i := 0; i <= 15; i++ {
		dbKey := fmt.Sprintf("db%d", i)
		v, ok := dm[dbKey]
		if !ok {
			continue
		}
		keys, expires, ttl := redisParseDBParts(v)
		totalKeys += keys
		totalExpires += expires
		dbRow := fmt.Sprintf("  %s %s %s %s",
			styledPad(valueStyle.Render(dbKey), 6),
			styledPad(valueStyle.Render(redisFmtLargeNum(fmt.Sprintf("%d", keys))), 12),
			styledPad(valueStyle.Render(redisFmtLargeNum(fmt.Sprintf("%d", expires))), 12),
			valueStyle.Render(redisFmtDuration(ttl)))
		sb.WriteString(boxRow(dbRow, iw) + "\n")
	}
	sb.WriteString(boxMid(iw) + "\n")
	totRow := fmt.Sprintf("  %s %s %s",
		styledPad(titleStyle.Render("Total"), 6),
		styledPad(valueStyle.Render(redisFmtLargeNum(fmt.Sprintf("%d", totalKeys))), 12),
		valueStyle.Render(redisFmtLargeNum(fmt.Sprintf("%d", totalExpires))))
	sb.WriteString(boxRow(totRow, iw) + "\n")

	// Key stats inline
	ksItems := []kv{
		{Key: "Hits", Val: redisFmtLargeNum(dm["keyspace_hits"])},
		{Key: "Misses", Val: redisFmtLargeNum(dm["keyspace_misses"])},
		{Key: "Hit Ratio", Val: dm["hit_ratio"]},
		{Key: "Expired", Val: redisFmtLargeNum(dm["expired_keys"])},
		{Key: "Evicted", Val: dm["evicted_keys"]},
	}
	var ksLine string
	for _, item := range ksItems {
		if item.Val == "" {
			continue
		}
		ksLine += fmt.Sprintf("  %s %s", dimStyle.Render(item.Key+":"), valueStyle.Render(item.Val))
	}
	sb.WriteString(boxRow(ksLine, iw) + "\n")

	// Command stats — wide table with each command as a column
	if len(cmds) > 0 {
		sb.WriteString(boxMid(iw) + "\n")

		// Determine how many commands fit per row (2 rows of commands)
		cmdColW := 18
		cmdsPerRow := (iw - 4) / cmdColW
		if cmdsPerRow < 4 {
			cmdsPerRow = 4
		}
		maxShow := cmdsPerRow * 2 // 2 rows
		if maxShow > len(cmds) {
			maxShow = len(cmds)
		}
		if maxShow > 28 {
			maxShow = 28
		}
		topCmds := cmds[:maxShow]

		// Row 1: command names
		for rowStart := 0; rowStart < len(topCmds); rowStart += cmdsPerRow {
			rowEnd := rowStart + cmdsPerRow
			if rowEnd > len(topCmds) {
				rowEnd = len(topCmds)
			}
			chunk := topCmds[rowStart:rowEnd]

			// Command name row
			var nameRow string
			for _, c := range chunk {
				nameRow += styledPad(titleStyle.Render(c.name), cmdColW)
			}
			sb.WriteString(boxRow("  "+nameRow, iw) + "\n")

			// Calls + % row
			var callRow string
			for _, c := range chunk {
				pct := float64(0)
				if totalCmdCalls > 0 {
					pct = float64(c.calls) / float64(totalCmdCalls) * 100
				}
				label := fmt.Sprintf("%s %.0f%%", redisFmtLargeNum(fmt.Sprintf("%d", c.calls)), pct)
				callRow += styledPad(valueStyle.Render(label), cmdColW)
			}
			sb.WriteString(boxRow("  "+callRow, iw) + "\n")

			// Latency row
			var latRow string
			for _, c := range chunk {
				latRow += styledPad(dimStyle.Render(redisFmtUsec(c.usecPC)+"/call"), cmdColW)
			}
			sb.WriteString(boxRow("  "+latRow, iw) + "\n")

			// Spacer between rows (not after last)
			if rowEnd < len(topCmds) {
				sb.WriteString(boxRow("", iw) + "\n")
			}
		}

		// Total commands summary
		sb.WriteString(boxMid(iw) + "\n")
		totalLine := fmt.Sprintf("  %s %s    %s %s    %s %d",
			dimStyle.Render("Total Calls:"), valueStyle.Render(redisFmtLargeNum(fmt.Sprintf("%d", totalCmdCalls))),
			dimStyle.Render("Unique Commands:"), valueStyle.Render(fmt.Sprintf("%d", len(cmds))),
			dimStyle.Render("Showing top:"), maxShow)
		sb.WriteString(boxRow(totalLine, iw) + "\n")
	}
	sb.WriteString(boxBot(iw) + "\n")

	// ── SECTION 3: MEMORY | PERSISTENCE | REPLICATION (full width, 3 cols) ──
	sb.WriteString("  " + titleStyle.Render("MEMORY") + strings.Repeat(" ", iw/3-8) +
		titleStyle.Render("PERSISTENCE") + strings.Repeat(" ", iw/3-13) +
		titleStyle.Render("REPLICATION") + "\n")
	sb.WriteString(boxTop(iw) + "\n")

	col3W := (iw - 8) / 3
	memKVs := []kv{
		{Key: "Used", Val: dm["used_memory_human"]},
		{Key: "RSS", Val: dm["used_memory_rss_human"]},
		{Key: "Peak", Val: dm["used_memory_peak_human"]},
		{Key: "Max", Val: dm["maxmemory_human"]},
		{Key: "Policy", Val: dm["maxmemory_policy"]},
		{Key: "Dataset%", Val: dm["used_memory_dataset_perc"]},
		{Key: "Fragment", Val: dm["mem_fragmentation_ratio"]},
		{Key: "Lua", Val: dm["used_memory_lua_human"]},
		{Key: "RSS Ratio", Val: dm["rss_overhead_ratio"]},
		{Key: "Allocator", Val: dm["mem_allocator"]},
	}
	persKVs := []kv{
		{Key: "RDB", Val: dm["rdb_last_bgsave_status"]},
		{Key: "Save Time", Val: redisFmtSec(dm["rdb_last_bgsave_time_sec"])},
		{Key: "Changes", Val: dm["rdb_changes_since_last_save"]},
		{Key: "AOF", Val: redisYesNo(dm["aof_enabled"])},
		{Key: "Rewrite", Val: dm["aof_last_bgrewrite_status"]},
		{Key: "Fork", Val: redisFmtUsecStr(dm["latest_fork_usec"])},
	}
	if dm["aof_current_size"] != "" {
		aofBytes, _ := strconv.ParseFloat(dm["aof_current_size"], 64)
		if aofBytes > 0 {
			persKVs = append(persKVs, kv{Key: "AOF Size", Val: redisFmtNetBytes(dm["aof_current_size"])})
		}
	}
	replKVs := []kv{
		{Key: "Role", Val: dm["role"]},
		{Key: "Slaves", Val: dm["connected_slaves"]},
	}
	if dm["master_host"] != "" {
		replKVs = append(replKVs,
			kv{Key: "Master", Val: dm["master_host"] + ":" + dm["master_port"]},
			kv{Key: "Link", Val: dm["master_link_status"]},
			kv{Key: "Last IO", Val: redisFmtSec(dm["master_last_io_seconds_ago"])})
	}
	if lagBytes := dm["repl_lag_bytes"]; lagBytes != "" {
		replKVs = append(replKVs, kv{Key: "Lag", Val: redisFmtNetBytes(lagBytes)})
	}
	if backlog := dm["repl_backlog_size"]; backlog != "" {
		replKVs = append(replKVs, kv{Key: "Backlog", Val: redisFmtNetBytes(backlog)})
	}

	maxR3 := len(memKVs)
	if len(persKVs) > maxR3 {
		maxR3 = len(persKVs)
	}
	if len(replKVs) > maxR3 {
		maxR3 = len(replKVs)
	}
	kvLabel := 10
	for i := 0; i < maxR3; i++ {
		var c1, c2, c3 string
		if i < len(memKVs) && memKVs[i].Val != "" {
			c1 = fmt.Sprintf("%s %s", styledPad(dimStyle.Render(memKVs[i].Key+":"), kvLabel), valueStyle.Render(memKVs[i].Val))
		}
		if i < len(persKVs) && persKVs[i].Val != "" {
			c2 = fmt.Sprintf("%s %s", styledPad(dimStyle.Render(persKVs[i].Key+":"), kvLabel), valueStyle.Render(persKVs[i].Val))
		}
		if i < len(replKVs) && replKVs[i].Val != "" {
			c3 = fmt.Sprintf("%s %s", styledPad(dimStyle.Render(replKVs[i].Key+":"), kvLabel), valueStyle.Render(replKVs[i].Val))
		}
		row := fmt.Sprintf("  %s %s %s %s %s",
			styledPad(c1, col3W),
			dimStyle.Render("│"),
			styledPad(c2, col3W),
			dimStyle.Render("│"),
			c3)
		sb.WriteString(boxRow(row, iw) + "\n")
	}
	sb.WriteString(boxBot(iw) + "\n")

	// ── SECTION 4: LATENCY & SLOW LOG (full width) ──
	hasLatency := dm["latency_percentiles_usec_p50"] != "" || dm["slowlog_entries"] != ""
	if hasLatency {
		sb.WriteString("  " + titleStyle.Render("LATENCY & SLOW LOG") + "\n")
		sb.WriteString(boxTop(iw) + "\n")

		// Latency summary row
		var latParts []string
		if p50 := dm["latency_percentiles_usec_p50"]; p50 != "" {
			p50v, _ := strconv.ParseFloat(p50, 64)
			latParts = append(latParts, fmt.Sprintf("%s %s", dimStyle.Render("p50:"), valueStyle.Render(redisFmtUsec(p50v))))
		}
		if p99 := dm["latency_percentiles_usec_p99"]; p99 != "" {
			p99v, _ := strconv.ParseFloat(p99, 64)
			latParts = append(latParts, fmt.Sprintf("%s %s", dimStyle.Render("p99:"), valueStyle.Render(redisFmtUsec(p99v))))
		}
		if p999 := dm["latency_percentiles_usec_p99.9"]; p999 != "" {
			p999v, _ := strconv.ParseFloat(p999, 64)
			latParts = append(latParts, fmt.Sprintf("%s %s", dimStyle.Render("p99.9:"), valueStyle.Render(redisFmtUsec(p999v))))
		}
		if forkUs := dm["latest_fork_usec"]; forkUs != "" {
			fv, _ := strconv.ParseFloat(forkUs, 64)
			latParts = append(latParts, fmt.Sprintf("%s %s", dimStyle.Render("Fork:"), valueStyle.Render(redisFmtUsec(fv))))
		}
		if len(latParts) > 0 {
			sb.WriteString(boxRow("  "+strings.Join(latParts, "    "), iw) + "\n")
		}

		// Slow log entries
		if entries := dm["slowlog_entries"]; entries != "" {
			sb.WriteString(boxMid(iw) + "\n")
			sb.WriteString(boxRow(fmt.Sprintf("  %s %s %s",
				styledPad(dimStyle.Render("TIME"), 10),
				styledPad(dimStyle.Render("DURATION"), 12),
				dimStyle.Render("COMMAND")), iw) + "\n")
			for _, entry := range strings.Split(entries, ";") {
				parts := strings.SplitN(entry, "|", 3)
				if len(parts) == 3 {
					row := fmt.Sprintf("  %s %s %s",
						styledPad(valueStyle.Render(parts[0]), 10),
						styledPad(warnStyle.Render(parts[1]), 12),
						valueStyle.Render(parts[2]))
					sb.WriteString(boxRow(row, iw) + "\n")
				}
			}
		}
		sb.WriteString(boxBot(iw) + "\n")
	}

	// ── SECTION 5: RECOMMENDATIONS (full width) ──
	recCount, _ := strconv.Atoi(dm["rec_count"])
	if recCount > 0 {
		sb.WriteString("  " + titleStyle.Render("RECOMMENDATIONS") + "\n")
		sb.WriteString(boxTop(iw) + "\n")
		for i := 0; i < recCount; i++ {
			rec := dm[fmt.Sprintf("rec_%d", i)]
			if rec == "" {
				continue
			}
			// Split recommendation into action + explanation at first " — "
			prefix := warnStyle.Render(fmt.Sprintf(" %d.", i+1))
			// Wrap long recommendations
			maxRecW := iw - 8
			if len(rec) > maxRecW {
				// First line
				sb.WriteString(boxRow(fmt.Sprintf("  %s %s", prefix, valueStyle.Render(rec[:maxRecW])), iw) + "\n")
				// Continuation lines
				remaining := rec[maxRecW:]
				for len(remaining) > 0 {
					chunk := remaining
					if len(chunk) > maxRecW {
						chunk = remaining[:maxRecW]
					}
					remaining = remaining[len(chunk):]
					sb.WriteString(boxRow(fmt.Sprintf("      %s", dimStyle.Render(chunk)), iw) + "\n")
				}
			} else {
				sb.WriteString(boxRow(fmt.Sprintf("  %s %s", prefix, valueStyle.Render(rec)), iw) + "\n")
			}
		}
		sb.WriteString(boxBot(iw) + "\n")
	}

	return sb.String()
}

// redisParseDBParts returns keys, expires, avg_ttl_ms from a Redis db info string.
func redisParseDBParts(v string) (keys, expires int, ttlMs int64) {
	for _, part := range strings.Split(v, ",") {
		kv := strings.SplitN(part, "=", 2)
		if len(kv) != 2 {
			continue
		}
		switch kv[0] {
		case "keys":
			keys, _ = strconv.Atoi(kv[1])
		case "expires":
			expires, _ = strconv.Atoi(kv[1])
		case "avg_ttl":
			ttlMs, _ = strconv.ParseInt(kv[1], 10, 64)
		}
	}
	return
}

// redisFmtDuration formats milliseconds into human-readable duration.
func redisFmtDuration(ms int64) string {
	if ms <= 0 {
		return "-"
	}
	sec := ms / 1000
	if sec >= 86400 {
		return fmt.Sprintf("%.1fd", float64(sec)/86400)
	}
	if sec >= 3600 {
		return fmt.Sprintf("%.1fh", float64(sec)/3600)
	}
	if sec >= 60 {
		return fmt.Sprintf("%.0fm", float64(sec)/60)
	}
	return fmt.Sprintf("%ds", sec)
}

// redisFmtUsec formats microseconds per call into readable latency.
func redisFmtUsec(usec float64) string {
	if usec >= 1000 {
		return fmt.Sprintf("%.2fms", usec/1000)
	}
	return fmt.Sprintf("%.1fus", usec)
}

func redisParseDB(v string) string {
	parts := strings.Split(v, ",")
	result := []string{}
	for _, p := range parts {
		kv := strings.SplitN(p, "=", 2)
		if len(kv) == 2 {
			switch kv[0] {
			case "keys":
				result = append(result, kv[1]+" keys")
			case "expires":
				result = append(result, kv[1]+" expires")
			case "avg_ttl":
				ttl, _ := strconv.ParseInt(kv[1], 10, 64)
				if ttl > 0 {
					result = append(result, fmt.Sprintf("avg_ttl=%ds", ttl/1000))
				}
			}
		}
	}
	return strings.Join(result, ", ")
}

func redisFmtKbps(s string) string {
	if s == "" {
		return ""
	}
	v, _ := strconv.ParseFloat(s, 64)
	if v >= 1024 {
		return fmt.Sprintf("%.1f MB/s", v/1024)
	}
	return fmt.Sprintf("%.1f KB/s", v)
}

func redisFmtNetBytes(s string) string {
	if s == "" {
		return ""
	}
	v, _ := strconv.ParseFloat(s, 64)
	return appFmtBytesShort(v)
}

func redisFmtLargeNum(s string) string {
	if s == "" {
		return ""
	}
	v, _ := strconv.ParseFloat(s, 64)
	switch {
	case v >= 1e9:
		return fmt.Sprintf("%.1fB", v/1e9)
	case v >= 1e6:
		return fmt.Sprintf("%.1fM", v/1e6)
	case v >= 1e3:
		return fmt.Sprintf("%.1fK", v/1e3)
	default:
		return s
	}
}

func redisYesNo(s string) string {
	if s == "1" {
		return "yes"
	}
	if s == "0" {
		return "no"
	}
	return s
}

func redisFmtUsecStr(s string) string {
	if s == "" {
		return ""
	}
	v, _ := strconv.ParseFloat(s, 64)
	return redisFmtUsec(v)
}

func redisFmtSec(s string) string {
	if s == "" {
		return ""
	}
	v, _ := strconv.ParseFloat(s, 64)
	if v >= 3600 {
		return fmt.Sprintf("%.1fh", v/3600)
	}
	if v >= 60 {
		return fmt.Sprintf("%.1fm", v/60)
	}
	return fmt.Sprintf("%.1fs", v)
}

// ── MySQL Detail ───────────────────────────────────────────────────────

func renderMySQLDeepMetrics(app model.AppInstance, iw int) string {
	var sb strings.Builder
	dm := app.DeepMetrics
	halfW := (iw - 8) / 2

	// ── ACTIVITY (real-time rates) ────────────────────────────────────
	hasActivity := dm["queries_per_sec"] != "" || dm["Bytes_received"] != "" || dm["selects_per_sec"] != ""
	if hasActivity {
		sb.WriteString("  " + titleStyle.Render("ACTIVITY") + "\n")
		sb.WriteString(boxTop(iw) + "\n")
		type actPair struct{ lKey, lVal, rKey, rVal string }
		actRows := []actPair{
			{"Queries/s", dm["queries_per_sec"], "Selects/s", dm["selects_per_sec"]},
			{"Inserts/s", dm["inserts_per_sec"], "Updates/s", dm["updates_per_sec"]},
			{"Deletes/s", dm["deletes_per_sec"], "Commits/s", dm["commits_per_sec"]},
			{"Bytes In", haFmtBytes(dm["bytes_in_per_sec"]) + "/s", "Bytes Out", haFmtBytes(dm["bytes_out_per_sec"]) + "/s"},
		}
		for _, r := range actRows {
			lv := r.lVal; if lv == "/s" { lv = "" }
			rv := r.rVal; if rv == "/s" { rv = "" }
			if lv == "" && rv == "" { continue }
			left := fmt.Sprintf("  %s %s", styledPad(dimStyle.Render(r.lKey+":"), 14), styledPad(valueStyle.Render(lv), halfW-16))
			right := ""
			if rv != "" {
				right = fmt.Sprintf("%s %s", styledPad(dimStyle.Render(r.rKey+":"), 14), valueStyle.Render(rv))
			}
			sb.WriteString(boxRow(left+right, iw) + "\n")
		}
		sb.WriteString(boxBot(iw) + "\n")
	}

	// ── TOP QUERIES ───────────────────────────────────────────────────
	if dm["top_query_count"] != "" {
		cnt, _ := strconv.Atoi(dm["top_query_count"])
		if cnt > 0 {
			sb.WriteString("  " + titleStyle.Render("TOP QUERIES") + "  " + dimStyle.Render(fmt.Sprintf("%d running", cnt)) + "\n")
			sb.WriteString(boxTop(iw) + "\n")
			cID, cUser, cHost, cDB, cTime, cState := 8, 10, 16, 10, 8, 16
			queryW := iw - cID - cUser - cHost - cDB - cTime - cState - 14
			if queryW < 20 { queryW = 20 }
			hdr := fmt.Sprintf("  %s%s%s%s%s%s%s",
				styledPad(dimStyle.Render("ID"), cID),
				styledPad(dimStyle.Render("User"), cUser),
				styledPad(dimStyle.Render("Host"), cHost),
				styledPad(dimStyle.Render("DB"), cDB),
				styledPad(dimStyle.Render("Time"), cTime),
				styledPad(dimStyle.Render("State"), cState),
				dimStyle.Render("Query"))
			sb.WriteString(boxRow(hdr, iw) + "\n")
			sb.WriteString(boxMid(iw) + "\n")
			maxQ := cnt; if maxQ > 5 { maxQ = 5 }
			for i := 0; i < maxQ; i++ {
				pfx := fmt.Sprintf("top_query_%d_", i)
				qID := dm[pfx+"id"]
				qUser := dm[pfx+"user"]
				qHost := dm[pfx+"host"]
				qDB := dm[pfx+"db"]
				qTime := dm[pfx+"time"]
				qState := dm[pfx+"state"]
				qInfo := dm[pfx+"info"]
				if qDB == "" || qDB == "NULL" { qDB = "-" }
				// color time
				timeStyled := valueStyle.Render(qTime + "s")
				if ts, _ := strconv.Atoi(qTime); ts > 30 {
					timeStyled = critStyle.Render(qTime + "s")
				} else if ts > 5 {
					timeStyled = warnStyle.Render(qTime + "s")
				}
				if len(qHost) > cHost-2 { qHost = qHost[:cHost-2] }
				if len(qState) > cState-2 { qState = qState[:cState-2] }
				if len(qInfo) > queryW { qInfo = qInfo[:queryW-3] + "..." }
				row := fmt.Sprintf("  %s%s%s%s%s%s%s",
					styledPad(dimStyle.Render(qID), cID),
					styledPad(valueStyle.Render(qUser), cUser),
					styledPad(valueStyle.Render(qHost), cHost),
					styledPad(dimStyle.Render(qDB), cDB),
					styledPad(timeStyled, cTime),
					styledPad(dimStyle.Render(qState), cState),
					dimStyle.Render(qInfo))
				sb.WriteString(boxRow(row, iw) + "\n")
			}
			sb.WriteString(boxBot(iw) + "\n")
		}
	}

	// ── CONNECTIONS BY HOST ───────────────────────────────────────────
	if dm["conn_host_count"] != "" {
		hostCnt, _ := strconv.Atoi(dm["conn_host_count"])
		if hostCnt > 0 {
			sb.WriteString("  " + titleStyle.Render("CONNECTIONS BY HOST") + "\n")
			sb.WriteString(boxTop(iw) + "\n")
			hdr := fmt.Sprintf("  %s %s %s",
				styledPad(dimStyle.Render("Host"), 22),
				styledPad(dimStyle.Render("Connections"), 14),
				dimStyle.Render("Active"))
			sb.WriteString(boxRow(hdr, iw) + "\n")
			sb.WriteString(boxMid(iw) + "\n")
			maxH := hostCnt; if maxH > 10 { maxH = 10 }
			for i := 0; i < maxH; i++ {
				pfx := fmt.Sprintf("conn_host_%d_", i)
				hHost := dm[pfx+"host"]
				hCount := dm[pfx+"count"]
				hActive := dm[pfx+"active"]
				if hHost == "" { continue }
				if len(hHost) > 21 { hHost = hHost[:21] }
				row := fmt.Sprintf("  %s %s %s",
					styledPad(valueStyle.Render(hHost), 22),
					styledPad(valueStyle.Render(hCount), 14),
					valueStyle.Render(hActive))
				sb.WriteString(boxRow(row, iw) + "\n")
			}
			sb.WriteString(boxBot(iw) + "\n")
		}
	}

	// ── DIAGNOSTICS ───────────────────────────────────────────────────
	type mysqlDiag struct {
		severity string
		title    string
		cause    string
		impact   string
		fix      string
	}
	var diags []mysqlDiag

	// Buffer Pool Hit Ratio
	if dm["buffer_pool_hit_ratio"] != "" {
		ratio, _ := strconv.ParseFloat(dm["buffer_pool_hit_ratio"], 64)
		if ratio < 95 {
			sev := "WARN"
			if ratio < 90 { sev = "CRIT" }
			poolSize := dm["innodb_buffer_pool_size"]
			dataPages := dm["Innodb_buffer_pool_pages_data"]
			totalPages := dm["Innodb_buffer_pool_pages_total"]
			diags = append(diags, mysqlDiag{
				severity: sev,
				title:    fmt.Sprintf("InnoDB buffer pool hit ratio %.1f%% — below optimal (>99%%)", ratio),
				cause:    fmt.Sprintf("Working set exceeds buffer pool. Pool: %s, data pages: %s/%s. Queries are reading from disk instead of memory.", poolSize, dataPages, totalPages),
				impact:   "Disk I/O increases, query latency rises. Every cache miss = random disk read (~5-10ms SSD, ~10-20ms HDD) vs ~0.1ms from memory.",
				fix:      "1) Increase innodb_buffer_pool_size (aim for 70-80%% of RAM). 2) Optimize queries to reduce working set. 3) Add indexes to avoid full table scans.",
			})
		}
	}

	// Slow Queries
	if v, _ := strconv.Atoi(dm["Slow_queries"]); v > 0 {
		sev := "WARN"
		if v > 100 { sev = "CRIT" }
		diags = append(diags, mysqlDiag{
			severity: sev,
			title:    fmt.Sprintf("%s slow queries detected", haFmtNum(dm["Slow_queries"])),
			cause:    "Queries exceeding long_query_time threshold. Common causes: missing indexes, full table scans, unoptimized joins, large result sets.",
			impact:   fmt.Sprintf("Slow queries hold locks longer, block other connections, increase CPU/IO load. Full scans: %s, full joins: %s.", haFmtNum(dm["Select_scan"]), haFmtNum(dm["Select_full_join"])),
			fix:      "1) Enable slow query log: SET GLOBAL slow_query_log=ON. 2) Run EXPLAIN on slow queries. 3) Add missing indexes. 4) Rewrite full joins to use indexed lookups.",
		})
	}

	// Row Lock Waits
	if v, _ := strconv.Atoi(dm["Innodb_row_lock_waits"]); v > 100 {
		sev := "WARN"
		if v > 1000 { sev = "CRIT" }
		avgMs := dm["Innodb_row_lock_time_avg"]
		diags = append(diags, mysqlDiag{
			severity: sev,
			title:    fmt.Sprintf("%s InnoDB row lock waits (avg %sms)", haFmtNum(dm["Innodb_row_lock_waits"]), avgMs),
			cause:    "Multiple transactions competing for the same rows. Long-running transactions hold locks, blocking others.",
			impact:   "Query queuing, increased response times, potential deadlocks. Active threads spike as connections wait for locks.",
			fix:      "1) Keep transactions short — commit early. 2) Access rows in consistent order to prevent deadlocks. 3) Use SELECT ... FOR UPDATE only when necessary. 4) Check for long-running transactions: SHOW ENGINE INNODB STATUS.",
		})
	}

	// Full Table Scans
	if v, _ := strconv.Atoi(dm["Select_scan"]); v > 100000 {
		sev := "WARN"
		if v > 1000000 { sev = "CRIT" }
		diags = append(diags, mysqlDiag{
			severity: sev,
			title:    fmt.Sprintf("%s full table scans — review query plans", haFmtNum(dm["Select_scan"])),
			cause:    "Queries scanning entire tables instead of using indexes. Missing indexes or queries that can't use existing indexes (e.g., functions on indexed columns, OR conditions).",
			impact:   "Each full scan reads every row — CPU and IO waste. Compounds with table size. Causes buffer pool churn, evicting useful cached pages.",
			fix:      "1) EXPLAIN suspect queries — look for 'type: ALL'. 2) Add composite indexes matching WHERE + ORDER BY. 3) Avoid SELECT * — select only needed columns. 4) Use covering indexes for frequent queries.",
		})
	}

	// Deadlocks
	if v, _ := strconv.Atoi(dm["Innodb_deadlocks"]); v > 0 {
		diags = append(diags, mysqlDiag{
			severity: "CRIT",
			title:    fmt.Sprintf("%s InnoDB deadlocks", dm["Innodb_deadlocks"]),
			cause:    "Two or more transactions waiting for each other's locks in a cycle. MySQL automatically kills one transaction (the victim).",
			impact:   "Victim transactions are rolled back — application must retry. If frequent, causes cascading failures and wasted work.",
			fix:      "1) Access tables/rows in the same order in all transactions. 2) Keep transactions short. 3) Use lower isolation level if possible (READ COMMITTED). 4) SHOW ENGINE INNODB STATUS — check LATEST DEADLOCK section.",
		})
	}

	// Connection Usage
	if dm["connection_usage_pct"] != "" {
		pct, _ := strconv.ParseFloat(dm["connection_usage_pct"], 64)
		if pct > 75 {
			sev := "WARN"
			if pct > 90 { sev = "CRIT" }
			diags = append(diags, mysqlDiag{
				severity: sev,
				title:    fmt.Sprintf("Connection usage at %.0f%% (%s/%s)", pct, dm["Threads_connected"], dm["max_connections"]),
				cause:    "Too many open connections. Applications not releasing connections, connection pool misconfigured, or max_connections set too low.",
				impact:   "New connections will be refused when limit is hit. Each connection uses ~1MB RAM (thread stack + buffers). High thread count increases context switching.",
				fix:      fmt.Sprintf("1) Tune application connection pool (max idle, max lifetime). 2) Increase max_connections (current: %s). 3) Kill idle connections: sleeping=%s. 4) Use connection pooling (ProxySQL/MaxScale).", dm["max_connections"], dm["sleeping_connections"]),
			})
		}
	}

	// Thread count high relative to connections
	threads, _ := strconv.Atoi(dm["Threads_connected"])
	running, _ := strconv.Atoi(dm["Threads_running"])
	if threads > 0 && running > 0 && threads > 30 && running < threads/4 {
		conns := app.Connections
		if conns > 0 && threads > conns*3 {
			diags = append(diags, mysqlDiag{
				severity: "WARN",
				title:    fmt.Sprintf("Thread count (%d) high relative to connections (%d)", threads, conns),
				cause:    "Many threads are idle or sleeping. Applications opening connections but not closing them, or connection pool holding too many idle connections.",
				impact:   "Wasted memory (~1MB per thread). Increases mutex contention on thread scheduler. Sleeping threads still hold resources.",
				fix:      "1) Reduce connection pool max-idle setting. 2) Set wait_timeout lower (current default: 28800s = 8h). 3) Use thread_pool plugin for better scaling.",
			})
		}
	}

	// Table Lock Contention
	if dm["table_lock_contention"] != "" {
		pct, _ := strconv.ParseFloat(dm["table_lock_contention"], 64)
		if pct > 1 {
			sev := "WARN"
			if pct > 5 { sev = "CRIT" }
			diags = append(diags, mysqlDiag{
				severity: sev,
				title:    fmt.Sprintf("Table lock contention %.1f%%", pct),
				cause:    fmt.Sprintf("Locks waited: %s vs immediate: %s. MyISAM tables or DDL operations cause table-level locks that block all other operations.", dm["Table_locks_waited"], dm["Table_locks_immediate"]),
				impact:   "All queries on the locked table queue up. Can cascade to connection exhaustion if lock is held long.",
				fix:      "1) Convert MyISAM tables to InnoDB (row-level locking). 2) Avoid long ALTER TABLE during peak hours — use pt-online-schema-change. 3) Keep DDL transactions short.",
			})
		}
	}

	// Replication lag
	if dm["replication_status"] != "" && dm["replication_status"] != "ok" {
		diags = append(diags, mysqlDiag{
			severity: "CRIT",
			title:    "Replication broken — " + dm["replication_status"],
			cause:    fmt.Sprintf("IO Running: %s, SQL Running: %s. Network issues, binary log corruption, or schema drift between master and replica.", dm["Slave_IO_Running"], dm["Slave_SQL_Running"]),
			impact:   "Replica serves stale data. Failover to replica will cause data loss. Read-scaling is compromised.",
			fix:      "1) Check SHOW SLAVE STATUS for Last_Error. 2) Verify network to master. 3) If SQL thread stopped: STOP SLAVE; SET GLOBAL SQL_SLAVE_SKIP_COUNTER=1; START SLAVE (skip one event). 4) If drift: re-provision from backup.",
		})
	} else if dm["Seconds_behind_master"] != "" && dm["Seconds_behind_master"] != "0" {
		lag, _ := strconv.Atoi(dm["Seconds_behind_master"])
		if lag > 5 {
			sev := "WARN"
			if lag > 30 { sev = "CRIT" }
			diags = append(diags, mysqlDiag{
				severity: sev,
				title:    fmt.Sprintf("Replication lag: %ds behind master", lag),
				cause:    "Replica SQL thread can't keep up with master write rate. Single-threaded replication, heavy writes, or slow disk on replica.",
				impact:   fmt.Sprintf("Reads from replica are %ds stale. Failover would lose %ds of data.", lag, lag),
				fix:      "1) Enable parallel replication: slave_parallel_workers > 1. 2) Optimize slow queries on replica. 3) Use faster disk on replica. 4) Reduce master write rate during catch-up.",
			})
		}
	}

	// Render diagnostics if any
	if len(diags) > 0 {
		sb.WriteString("  " + titleStyle.Render("DIAGNOSTICS") + "  " + dimStyle.Render(fmt.Sprintf("%d issues", len(diags))) + "\n")
		sb.WriteString(boxTop(iw) + "\n")
		for idx, d := range diags {
			if idx > 0 { sb.WriteString(boxMid(iw) + "\n") }
			var sevBadge string
			if d.severity == "CRIT" { sevBadge = critStyle.Render("CRIT") } else { sevBadge = warnStyle.Render("WARN") }
			sb.WriteString(boxRow(fmt.Sprintf("  %s %s  %s",
				warnStyle.Render(fmt.Sprintf("#%d", idx+1)), sevBadge, valueStyle.Render(d.title)), iw) + "\n")
			sb.WriteString(boxRow("  "+dimStyle.Render("Cause:")+"   "+dimStyle.Render(d.cause), iw) + "\n")
			sb.WriteString(boxRow("  "+dimStyle.Render("Impact:")+"  "+dimStyle.Render(d.impact), iw) + "\n")
			sb.WriteString(boxRow("  "+dimStyle.Render("Fix:")+"     "+dimStyle.Render(d.fix), iw) + "\n")
		}
		sb.WriteString(boxBot(iw) + "\n")
	}

	// ── HEALTH CHECKS + CONNECTIONS (side by side) ────────────────────
	type hRow struct{ metric, value, status string }
	var hRows []hRow
	mysqlAddH := func(name, val string, wT, cT float64, hi bool) {
		if val == "" { return }
		v, _ := strconv.ParseFloat(val, 64)
		st := "OK"
		if hi { if v >= cT { st = "CRIT" } else if v >= wT { st = "WARN" }
		} else { if v <= cT { st = "CRIT" } else if v <= wT { st = "WARN" } }
		hRows = append(hRows, hRow{name, val, st})
	}
	mysqlAddH("Buffer Pool Hit%", dm["buffer_pool_hit_ratio"]+"%", 95, 90, false)
	mysqlAddH("Conn Usage%", dm["connection_usage_pct"]+"%", 75, 90, true)
	mysqlAddH("Lock Contention%", dm["table_lock_contention"]+"%", 1, 5, true)
	if dm["Slow_queries"] != "" {
		sv, _ := strconv.Atoi(dm["Slow_queries"])
		st := "OK"; if sv > 100 { st = "CRIT" } else if sv > 0 { st = "WARN" }
		hRows = append(hRows, hRow{"Slow Queries", haFmtNum(dm["Slow_queries"]), st})
	}
	if dm["Innodb_deadlocks"] != "" && dm["Innodb_deadlocks"] != "0" {
		hRows = append(hRows, hRow{"Deadlocks", dm["Innodb_deadlocks"], "CRIT"})
	}
	if dm["Innodb_row_lock_waits"] != "" {
		rv, _ := strconv.Atoi(dm["Innodb_row_lock_waits"])
		st := "OK"; if rv > 1000 { st = "CRIT" } else if rv > 100 { st = "WARN" }
		hRows = append(hRows, hRow{"Row Lock Waits", haFmtNum(dm["Innodb_row_lock_waits"]), st})
	}
	if dm["replication_status"] != "" {
		st := "OK"; if dm["replication_status"] != "ok" { st = "CRIT" }
		val := dm["replication_status"]
		if dm["Seconds_behind_master"] != "" && dm["Seconds_behind_master"] != "0" {
			val += " (lag:" + dm["Seconds_behind_master"] + "s)"
			lag, _ := strconv.Atoi(dm["Seconds_behind_master"])
			if lag > 30 { st = "CRIT" } else if lag > 5 { st = "WARN" }
		}
		hRows = append(hRows, hRow{"Replication", val, st})
	}

	// Connection values with status coloring
	mysqlConnColor := func(key, val string) string {
		if val == "" { return "" }
		v, _ := strconv.Atoi(val)
		switch key {
		case "Connected":
			maxC, _ := strconv.Atoi(dm["max_connections"])
			if maxC > 0 {
				pct := float64(v) / float64(maxC) * 100
				if pct > 90 { return critStyle.Render(val) }
				if pct > 75 { return warnStyle.Render(val) }
			}
		case "Running":
			if v > 100 { return critStyle.Render(val) }
			if v > 50 { return warnStyle.Render(val) }
		case "Sleeping":
			if v > 100 { return warnStyle.Render(val) }
		case "Aborted In":
			if v > 100 { return warnStyle.Render(val) }
		case "Aborted Out":
			if v > 100 { return warnStyle.Render(val) }
		}
		return valueStyle.Render(val)
	}

	connKVs := []kv{
		{Key: "Max Conns", Val: dm["max_connections"]},
		{Key: "Connected", Val: dm["Threads_connected"]},
		{Key: "Running", Val: dm["Threads_running"]},
		{Key: "Max Used", Val: dm["Max_used_connections"]},
		{Key: "Active", Val: dm["active_queries"]},
		{Key: "Sleeping", Val: dm["sleeping_connections"]},
		{Key: "Aborted In", Val: dm["Aborted_connects"]},
		{Key: "Aborted Out", Val: dm["Aborted_clients"]},
	}

	sb.WriteString("  " + titleStyle.Render("HEALTH CHECKS") + strings.Repeat(" ", halfW-16) + titleStyle.Render("CONNECTIONS") + "\n")
	sb.WriteString(boxTop(iw) + "\n")
	cCheck, cVal := 18, 22
	leftHdr := fmt.Sprintf("  %s %s %s", styledPad(dimStyle.Render("Check"), cCheck), styledPad(dimStyle.Render("Value"), cVal), dimStyle.Render("St"))
	sb.WriteString(boxRow(fmt.Sprintf("%s  %s", styledPad(leftHdr, halfW), dimStyle.Render("Param          Value")), iw) + "\n")
	sb.WriteString(boxMid(iw) + "\n")
	maxR := len(hRows); if len(connKVs) > maxR { maxR = len(connKVs) }
	for i := 0; i < maxR; i++ {
		var left, right string
		if i < len(hRows) {
			r := hRows[i]
			badge := okStyle.Render(" OK "); if r.status == "WARN" { badge = warnStyle.Render("WARN") } else if r.status == "CRIT" { badge = critStyle.Render("CRIT") }
			left = fmt.Sprintf("  %s %s %s", styledPad(valueStyle.Render(r.metric), cCheck), styledPad(valueStyle.Render(r.value), cVal), badge)
		}
		if i < len(connKVs) && connKVs[i].Val != "" {
			right = fmt.Sprintf("  %s %s", styledPad(dimStyle.Render(connKVs[i].Key+":"), 14), mysqlConnColor(connKVs[i].Key, connKVs[i].Val))
		}
		sb.WriteString(boxRow(fmt.Sprintf("%s%s", styledPad(left, halfW), right), iw) + "\n")
	}
	sb.WriteString(boxBot(iw) + "\n")

	// ── INNODB + QUERY PERFORMANCE (side by side, with status colors) ─
	innoKVs := []kv{
		{Key: "Pool Size", Val: dm["innodb_buffer_pool_size"]},
		{Key: "Hit Ratio", Val: mysqlPctStr(dm["buffer_pool_hit_ratio"])},
		{Key: "Pool Usage", Val: mysqlPctStr(dm["buffer_pool_usage_pct"])},
		{Key: "Pages Data", Val: haFmtNum(dm["Innodb_buffer_pool_pages_data"])},
		{Key: "Pages Dirty", Val: haFmtNum(dm["Innodb_buffer_pool_pages_dirty"])},
		{Key: "Pages Free", Val: haFmtNum(dm["Innodb_buffer_pool_pages_free"])},
		{Key: "Lock Waits", Val: haFmtNum(dm["Innodb_row_lock_waits"])},
		{Key: "Lock Avg ms", Val: dm["Innodb_row_lock_time_avg"]},
		{Key: "Deadlocks", Val: dm["Innodb_deadlocks"]},
		{Key: "Data Reads", Val: haFmtNum(dm["Innodb_data_reads"])},
		{Key: "Data Writes", Val: haFmtNum(dm["Innodb_data_writes"])},
		{Key: "History Len", Val: dm["history_list_length"]},
	}
	queryKVs := []kv{
		{Key: "Questions", Val: haFmtNum(dm["Questions"])},
		{Key: "Slow Queries", Val: haFmtNum(dm["Slow_queries"])},
		{Key: "Full Joins", Val: haFmtNum(dm["Select_full_join"])},
		{Key: "Full Scans", Val: haFmtNum(dm["Select_scan"])},
		{Key: "Sort Merges", Val: haFmtNum(dm["Sort_merge_passes"])},
		{Key: "Tmp Disk %", Val: mysqlPctStr(dm["tmp_disk_table_pct"])},
		{Key: "Tmp Disk Tbl", Val: haFmtNum(dm["Created_tmp_disk_tables"])},
		{Key: "Tmp Tables", Val: haFmtNum(dm["Created_tmp_tables"])},
		{Key: "Rnd Reads", Val: haFmtNum(dm["Handler_read_rnd_next"])},
		{Key: "Open Tables", Val: dm["Open_tables"]},
		{Key: "Opened Tbls", Val: haFmtNum(dm["Opened_tables"])},
		{Key: "Locks Wait", Val: haFmtNum(dm["Table_locks_waited"])},
	}

	sb.WriteString("  " + titleStyle.Render("INNODB ENGINE") + strings.Repeat(" ", halfW-16) + titleStyle.Render("QUERY PERFORMANCE") + "\n")
	sb.WriteString(boxTop(iw) + "\n")
	maxR = len(innoKVs); if len(queryKVs) > maxR { maxR = len(queryKVs) }
	for i := 0; i < maxR; i++ {
		var left, right string
		if i < len(innoKVs) && innoKVs[i].Val != "" {
			left = fmt.Sprintf("  %s %s", styledPad(dimStyle.Render(innoKVs[i].Key+":"), 14), mysqlColorVal(innoKVs[i].Val, innoKVs[i].Key, dm))
		}
		if i < len(queryKVs) && queryKVs[i].Val != "" {
			right = fmt.Sprintf("  %s %s", styledPad(dimStyle.Render(queryKVs[i].Key+":"), 14), mysqlColorVal(queryKVs[i].Val, queryKVs[i].Key, dm))
		}
		if left != "" || right != "" {
			sb.WriteString(boxRow(fmt.Sprintf("%s%s", styledPad(left, halfW), right), iw) + "\n")
		}
	}
	sb.WriteString(boxBot(iw) + "\n")

	// ── REPLICATION + INNODB STATUS (side by side, if present) ────────
	if dm["Slave_IO_Running"] != "" || dm["replication_status"] != "" || dm["pending_reads"] != "" {
		replKVs := []kv{
			{Key: "Status", Val: dm["replication_status"]},
			{Key: "Lag (s)", Val: dm["Seconds_behind_master"]},
			{Key: "IO Thread", Val: dm["Slave_IO_Running"]},
			{Key: "SQL Thread", Val: dm["Slave_SQL_Running"]},
		}
		statusKVs := []kv{
			{Key: "Chkpt Age", Val: dm["checkpoint_age"]},
			{Key: "Pend Reads", Val: dm["pending_reads"]},
			{Key: "Pend Writes", Val: dm["pending_writes"]},
			{Key: "Tier 2", Val: dm["tier2_status"]},
		}

		hasRepl := false
		for _, k := range replKVs { if k.Val != "" { hasRepl = true; break } }
		hasStatus := false
		for _, k := range statusKVs { if k.Val != "" { hasStatus = true; break } }

		if hasRepl || hasStatus {
			lTitle := "REPLICATION"
			if !hasRepl { lTitle = "INNODB STATUS" }
			rTitle := "INNODB STATUS"
			if !hasRepl { rTitle = "" }
			sb.WriteString("  " + titleStyle.Render(lTitle))
			if rTitle != "" { sb.WriteString(strings.Repeat(" ", halfW-len(lTitle)-2) + titleStyle.Render(rTitle)) }
			sb.WriteString("\n")
			sb.WriteString(boxTop(iw) + "\n")
			lKVs := replKVs
			rKVs := statusKVs
			if !hasRepl { lKVs = statusKVs; rKVs = nil }
			maxR = len(lKVs); if rKVs != nil && len(rKVs) > maxR { maxR = len(rKVs) }
			for i := 0; i < maxR; i++ {
				var left, right string
				if i < len(lKVs) && lKVs[i].Val != "" {
					left = fmt.Sprintf("  %s %s", styledPad(dimStyle.Render(lKVs[i].Key+":"), 14), valueStyle.Render(lKVs[i].Val))
				}
				if rKVs != nil && i < len(rKVs) && rKVs[i].Val != "" {
					right = fmt.Sprintf("  %s %s", styledPad(dimStyle.Render(rKVs[i].Key+":"), 14), valueStyle.Render(rKVs[i].Val))
				}
				if left != "" || right != "" {
					sb.WriteString(boxRow(fmt.Sprintf("%s%s", styledPad(left, halfW), right), iw) + "\n")
				}
			}
			sb.WriteString(boxBot(iw) + "\n")
		}
	}

	return sb.String()
}

func mysqlPctStr(val string) string {
	if val == "" { return "" }
	return val + "%"
}

// mysqlColorVal returns a styled value string with threshold-based coloring
// for InnoDB and Query Performance metrics.
func mysqlColorVal(val, key string, dm map[string]string) string {
	if val == "" { return valueStyle.Render(val) }
	// strip % suffix for numeric comparison
	numStr := strings.TrimSuffix(val, "%")
	v, err := strconv.ParseFloat(numStr, 64)
	if err != nil { return valueStyle.Render(val) }
	switch key {
	// InnoDB thresholds
	case "Hit Ratio":
		if v < 90 { return critStyle.Render(val) }
		if v < 95 { return warnStyle.Render(val) }
		return okStyle.Render(val)
	case "Pages Dirty":
		if v > 1000 { return warnStyle.Render(val) }
	case "Lock Waits":
		if v > 1000 { return critStyle.Render(val) }
		if v > 100 { return warnStyle.Render(val) }
	case "Lock Avg ms":
		if v > 100 { return critStyle.Render(val) }
		if v > 50 { return warnStyle.Render(val) }
	case "Deadlocks":
		if v > 0 { return critStyle.Render(val) }
	// Query Performance thresholds
	case "Slow Queries":
		if v > 100 { return critStyle.Render(val) }
		if v > 0 { return warnStyle.Render(val) }
	case "Full Joins":
		if v > 1000 { return warnStyle.Render(val) }
	case "Full Scans":
		if v > 1000000 { return critStyle.Render(val) }
		if v > 100000 { return warnStyle.Render(val) }
	case "Sort Merges":
		if v > 1000 { return warnStyle.Render(val) }
	case "Tmp Disk %":
		if v > 25 { return critStyle.Render(val) }
		if v > 10 { return warnStyle.Render(val) }
	case "Locks Wait":
		if v > 100 { return warnStyle.Render(val) }
	}
	return valueStyle.Render(val)
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

// ── HAProxy Detail ─────────────────────────────────────────────────────

func renderHAProxyDeepMetrics(app model.AppInstance, iw int) string {
	var sb strings.Builder
	dm := app.DeepMetrics
	thirdW := (iw - 10) / 3
	halfW := (iw - 8) / 2

	// ── Health Checks + Proxy Info (side by side) ───────────────────────
	type hRow struct{ metric, value, status string }
	hRows := []hRow{}
	haAddH := func(name, val, ref string, wT, cT float64, hi bool) {
		if val == "" { return }
		v, _ := strconv.ParseFloat(val, 64)
		st := "OK"
		if hi { if v >= cT { st = "CRIT" } else if v >= wT { st = "WARN" }
		} else { if v <= cT { st = "CRIT" } else if v <= wT { st = "WARN" } }
		d := val; if ref != "" { d = val + "/" + ref }
		hRows = append(hRows, hRow{name, d, st})
	}
	haAddH("Servers Down", dm["servers_down"], dm["servers_total"], 1, 3, true)
	if dm["curr_conn"] != "" && dm["max_conn"] != "" {
		curr, _ := strconv.ParseFloat(dm["curr_conn"], 64)
		max, _ := strconv.ParseFloat(dm["max_conn"], 64)
		if max > 0 {
			pct := curr / max * 100
			st := "OK"; if pct > 90 { st = "CRIT" } else if pct > 75 { st = "WARN" }
			hRows = append(hRows, hRow{"Conn Usage", fmt.Sprintf("%s/%s (%.0f%%)", dm["curr_conn"], dm["max_conn"], pct), st})
		}
	}
	haAddH("Queue", dm["queue_current"], "", 10, 50, true)
	haAddH("5xx Rate%", dm["err_5xx_pct"], "", 1, 5, true)
	haAddH("4xx Rate%", dm["err_4xx_pct"], "", 5, 20, true)
	haAddH("CPU Idle%", dm["idle_pct"], "", 25, 10, false)
	haAddH("Conn Err%", dm["conn_err_pct"], "", 1, 5, true)
	haAddH("Retry%", dm["retry_pct"], "", 1, 5, true)

	infraKVs := []kv{
		{Key: "Role", Val: dm["proxy_role"]},
		{Key: "HTTP FE/BE", Val: haJoin(dm["http_frontends"], dm["http_backends"])},
		{Key: "TCP FE/BE", Val: haJoin(dm["tcp_frontends"], dm["tcp_backends"])},
		{Key: "Servers", Val: haServersLine(dm)},
		{Key: "MaxConn", Val: dm["max_conn"]},
		{Key: "Workers", Val: dm["workers"]},
		{Key: "Ports", Val: dm["listen_ports"]},
		{Key: "Stats", Val: dm["cfg_stats_uri"]},
	}

	sb.WriteString("  " + titleStyle.Render("HEALTH CHECKS") + strings.Repeat(" ", halfW-16) + titleStyle.Render("PROXY & INFRASTRUCTURE") + "\n")
	sb.WriteString(boxTop(iw) + "\n")
	cCheck, cVal := 14, 24
	leftHdr := fmt.Sprintf("  %s %s %s", styledPad(dimStyle.Render("Check"), cCheck), styledPad(dimStyle.Render("Value"), cVal), dimStyle.Render("St"))
	sb.WriteString(boxRow(fmt.Sprintf("%s  %s", styledPad(leftHdr, halfW), dimStyle.Render("Parameter        Value")), iw) + "\n")
	sb.WriteString(boxMid(iw) + "\n")

	maxRows := len(hRows); if len(infraKVs) > maxRows { maxRows = len(infraKVs) }
	for i := 0; i < maxRows; i++ {
		var left, right string
		if i < len(hRows) {
			r := hRows[i]
			badge := okStyle.Render(" OK ")
			if r.status == "WARN" { badge = warnStyle.Render("WARN") } else if r.status == "CRIT" { badge = critStyle.Render("CRIT") }
			left = fmt.Sprintf("  %s %s %s", styledPad(valueStyle.Render(r.metric), cCheck), styledPad(valueStyle.Render(r.value), cVal), badge)
		}
		if i < len(infraKVs) && infraKVs[i].Val != "" {
			right = fmt.Sprintf("  %s %s", styledPad(dimStyle.Render(infraKVs[i].Key+":"), 14), valueStyle.Render(infraKVs[i].Val))
		}
		sb.WriteString(boxRow(fmt.Sprintf("%s%s", styledPad(left, halfW), right), iw) + "\n")
	}
	sb.WriteString(boxBot(iw) + "\n\n")

	// ── Traffic & Throughput (3-column) ──────────────────────────────────
	sb.WriteString("  " + titleStyle.Render("TRAFFIC & THROUGHPUT") + "\n")
	sb.WriteString(boxTop(iw) + "\n")
	haRender3Col(&sb, iw, thirdW, []kv{
		{Key: "In Req/s", Val: haSuffix(dm["fe_req_rate"], "/s")},
		{Key: "Out Req/s", Val: haSuffix(dm["be_req_rate"], "/s")},
		{Key: "Sess Rate", Val: haSuffix(dm["session_rate"], "/s")},
		{Key: "Cur Sess", Val: dm["current_sessions"]},
	}, []kv{
		{Key: "Total In", Val: haFmtNum(dm["fe_req_total"])},
		{Key: "Total Out", Val: haFmtNum(dm["be_req_total"])},
		{Key: "Total Sess", Val: haFmtNum(dm["total_sessions"])},
		{Key: "Max Sess/s", Val: dm["max_sess_rate"]},
	}, []kv{
		{Key: "Bytes In", Val: haFmtBytes(dm["bytes_in"])},
		{Key: "Bytes Out", Val: haFmtBytes(dm["bytes_out"])},
		{Key: "Queue", Val: dm["queue_current"] + "/" + dm["queue_max"]},
		{Key: "Total Conns", Val: haFmtNum(dm["total_connections"])},
		{Key: "Denied Req", Val: haFmtNonZero(dm["total_dreq"])},
		{Key: "Denied Resp", Val: haFmtNonZero(dm["total_dresp"])},
	})
	sb.WriteString(boxBot(iw) + "\n\n")


	// ── BACKENDS ────────────────────────────────────────────────────────
	beCount, _ := strconv.Atoi(dm["be_detail_count"])
	if beCount > 0 {
		// Backend summary line
		beSumm := fmt.Sprintf("%s backends, %s servers (%s up, %s down), %s req/s out, %s 5xx, %s retries",
			dm["backends"], dm["servers_total"], dm["servers_up"], dm["servers_down"],
			dm["be_req_rate"], haFmtNum(dm["http_5xx"]), haFmtNum(dm["retries"]))
		sb.WriteString("  " + titleStyle.Render("BACKENDS") + "  " + dimStyle.Render(beSumm) + "\n")
		sb.WriteString(boxTop(iw) + "\n")

		cName, cAddr, cRate, cRt, cErr, c5, cAbrt, cHp, cChk := 20, 18, 7, 10, 7, 7, 9, 9, 16
		hdr := fmt.Sprintf("  %s%s%s%s%s%s%s%s%s%s",
			styledPad(dimStyle.Render("Backend"), cName),
			styledPad(dimStyle.Render("Endpoint"), cAddr),
			styledPad(dimStyle.Render("Req/s"), cRate),
			styledPad(dimStyle.Render("Response"), cRt),
			styledPad(dimStyle.Render("Err%"), cErr),
			styledPad(dimStyle.Render("5xx"), c5),
			styledPad(dimStyle.Render("Aborts"), cAbrt),
			styledPad(dimStyle.Render("Srv"), cHp),
			styledPad(dimStyle.Render("Health Check"), cChk),
			dimStyle.Render("Health"))
		sb.WriteString(boxRow(hdr, iw) + "\n")
		sb.WriteString(boxMid(iw) + "\n")

		for i := 0; i < beCount; i++ {
			pre := fmt.Sprintf("be_detail_%d_", i)
			name := dm[pre+"name"]
			addr := dm[pre+"addr"]
			rate := dm[pre+"sess_rate"]
			errPct := dm[pre+"err_pct"]
			h5xx := dm[pre+"5xx"]
			cliA := dm[pre+"cli_abrt"]
			srvA := dm[pre+"srv_abrt"]
			srvUp := dm[pre+"servers_up"]
			srvDown := dm[pre+"servers_down"]
			srvTotal := dm[pre+"servers_total"]
			rtime := dm[pre+"rtime"]
			beHealth := dm[pre+"health"]
			checkSt := dm[pre+"check_status"]

			if len(name) > 18 { name = name[:18] }
			if len(addr) > 16 { addr = addr[:16] }

			// Error %
			errStr := "0"
			if errPct != "" && errPct != "0.00" {
				ep, _ := strconv.ParseFloat(errPct, 64)
				if ep > 5 { errStr = critStyle.Render(errPct+"%") } else if ep > 1 { errStr = warnStyle.Render(errPct+"%") } else { errStr = errPct + "%" }
			}

			// Response time colored
			rtStr := rtime + "ms"
			if rt, _ := strconv.Atoi(rtime); rt > 5000 {
				rtStr = critStyle.Render(rtime + "ms")
			} else if rt > 2000 {
				rtStr = warnStyle.Render(rtime + "ms")
			}

			srvLine := srvUp + "/" + srvTotal
			if srvDown != "" && srvDown != "0" { srvLine += " " + critStyle.Render(srvDown+"d") }
			abortLine := haFmtNum(cliA) + "/" + haFmtNum(srvA)

			// Health badge
			var hBadge string
			switch beHealth {
			case "HEALTHY":  hBadge = okStyle.Render("HEALTHY")
			case "DEGRADED": hBadge = warnStyle.Render("DEGRADED")
			case "SLOW":     hBadge = warnStyle.Render("SLOW")
			case "CRITICAL": hBadge = critStyle.Render("CRITICAL")
			case "DOWN":     hBadge = critStyle.Render("DOWN")
			default:         hBadge = dimStyle.Render("?")
			}

			// Health check column
			var chkStr string
			if checkSt == "disabled" || checkSt == "" {
				chkStr = dimStyle.Render("no check")
			} else if strings.Contains(checkSt, "failing") {
				chkStr = critStyle.Render(checkSt)
				if len(checkSt) > 14 { chkStr = critStyle.Render(checkSt[:14]) }
			} else {
				chkStr = okStyle.Render(checkSt)
				if len(checkSt) > 14 { chkStr = okStyle.Render(checkSt[:14]) }
			}

			row := fmt.Sprintf("  %s%s%s%s%s%s%s%s%s%s",
				styledPad(valueStyle.Render(name), cName),
				styledPad(dimStyle.Render(addr), cAddr),
				styledPad(valueStyle.Render(rate+"/s"), cRate),
				styledPad(rtStr, cRt),
				styledPad(errStr, cErr),
				styledPad(haColorVal(haFmtNum(h5xx), "5xx"), c5),
				styledPad(valueStyle.Render(abortLine), cAbrt),
				styledPad(valueStyle.Render(srvLine), cHp),
				styledPad(chkStr, cChk),
				hBadge)
			sb.WriteString(boxRow(row, iw) + "\n")
		}
		sb.WriteString(boxBot(iw) + "\n\n")
	}

	// ── SLOW BACKENDS SPOTLIGHT ─────────────────────────────────────────
	slowBeCount, _ := strconv.Atoi(dm["slow_be_count"])
	if slowBeCount > 0 {
		sb.WriteString("  " + titleStyle.Render("SLOW BACKENDS") + "\n")
		sb.WriteString(boxTop(iw) + "\n")
		cSN, cSA, cSQ, cSC, cSR := 22, 20, 12, 12, 12
		sb.WriteString(boxRow(fmt.Sprintf("  %s%s%s%s%s%s",
			styledPad(dimStyle.Render("Backend"), cSN),
			styledPad(dimStyle.Render("Endpoint"), cSA),
			styledPad(dimStyle.Render("Queue"), cSQ),
			styledPad(dimStyle.Render("Connect"), cSC),
			styledPad(dimStyle.Render("Response"), cSR),
			dimStyle.Render("Total")), iw) + "\n")
		sb.WriteString(boxMid(iw) + "\n")
		for i := 0; i < slowBeCount; i++ {
			pre := fmt.Sprintf("slow_be_%d_", i)
			sName := dm[pre+"name"]
			sAddr := dm[pre+"addr"]
			sQ := dm[pre+"qtime"] + "ms"
			sC := dm[pre+"ctime"] + "ms"
			sR := dm[pre+"rtime"] + "ms"
			sT := dm[pre+"ttime"] + "ms"
			if len(sName) > 20 { sName = sName[:20] }
			if len(sAddr) > 18 { sAddr = sAddr[:18] }
			// Color response time
			rVal := valueStyle.Render(sR)
			if rt, _ := strconv.Atoi(dm[pre+"rtime"]); rt > 5000 {
				rVal = critStyle.Render(sR)
			} else if rt > 2000 {
				rVal = warnStyle.Render(sR)
			}
			row := fmt.Sprintf("  %s%s%s%s%s%s",
				styledPad(valueStyle.Render(sName), cSN),
				styledPad(dimStyle.Render(sAddr), cSA),
				styledPad(valueStyle.Render(sQ), cSQ),
				styledPad(valueStyle.Render(sC), cSC),
				styledPad(rVal, cSR),
				valueStyle.Render(sT))
			sb.WriteString(boxRow(row, iw) + "\n")
		}
		sb.WriteString(boxBot(iw) + "\n\n")
	}

	// ── RETRY & REDISPATCH ANALYSIS ─────────────────────────────────────
	{
		type retryRow struct{ name, retries, wredis, retryPct, reqs string }
		var retryRows []retryRow
		for i := 0; i < beCount; i++ {
			pre := fmt.Sprintf("be_detail_%d_", i)
			retries := dm[pre+"retries"]
			if retries == "" || retries == "0" { continue }
			retryRows = append(retryRows, retryRow{
				name:     dm[pre+"name"],
				retries:  retries,
				wredis:   dm[pre+"wredis"],
				retryPct: dm[pre+"retry_pct"],
				reqs:     dm[pre+"req_total"],
			})
		}
		if len(retryRows) > 0 {
			sb.WriteString("  " + titleStyle.Render("RETRY & REDISPATCH ANALYSIS") + "\n")
			sb.WriteString(boxTop(iw) + "\n")
			cRN, cRR, cRD, cRP := 22, 12, 12, 10
			sb.WriteString(boxRow(fmt.Sprintf("  %s%s%s%s%s",
				styledPad(dimStyle.Render("Backend"), cRN),
				styledPad(dimStyle.Render("Retries"), cRR),
				styledPad(dimStyle.Render("Redispatch"), cRD),
				styledPad(dimStyle.Render("Retry%"), cRP),
				dimStyle.Render("Sessions")), iw) + "\n")
			sb.WriteString(boxMid(iw) + "\n")
			for _, r := range retryRows {
				rName := r.name
				if len(rName) > 20 { rName = rName[:20] }
				row := fmt.Sprintf("  %s%s%s%s%s",
					styledPad(valueStyle.Render(rName), cRN),
					styledPad(valueStyle.Render(haFmtNum(r.retries)), cRR),
					styledPad(valueStyle.Render(haFmtNum(r.wredis)), cRD),
					styledPad(valueStyle.Render(haSuffix(r.retryPct, "%")), cRP),
					valueStyle.Render(haFmtNum(r.reqs)))
				sb.WriteString(boxRow(row, iw) + "\n")
			}
			sb.WriteString(boxBot(iw) + "\n\n")
		}
	}

	// ── PEAK vs CURRENT ─────────────────────────────────────────────────
	if beCount > 0 {
		type peakRow struct{ name, sessCur, sessMax, qCur, qMax string }
		var peakRows []peakRow
		for i := 0; i < beCount; i++ {
			pre := fmt.Sprintf("be_detail_%d_", i)
			scur := dm[pre+"scur"]
			smax := dm[pre+"smax"]
			if scur == "" && smax == "" { continue }
			peakRows = append(peakRows, peakRow{
				name:    dm[pre+"name"],
				sessCur: scur,
				sessMax: smax,
				qCur:    dm[pre+"qcur"],
				qMax:    dm[pre+"qmax"],
			})
		}
		if len(peakRows) > 0 {
			sb.WriteString("  " + titleStyle.Render("PEAK vs CURRENT") + "\n")
			sb.WriteString(boxTop(iw) + "\n")
			cPN, cPS := 22, 20
			sb.WriteString(boxRow(fmt.Sprintf("  %s%s%s",
				styledPad(dimStyle.Render("Backend"), cPN),
				styledPad(dimStyle.Render("Sess Cur/Max"), cPS),
				dimStyle.Render("Queue Cur/Max")), iw) + "\n")
			sb.WriteString(boxMid(iw) + "\n")
			for _, p := range peakRows {
				pName := p.name
				if len(pName) > 20 { pName = pName[:20] }
				sessStr := p.sessCur + "/" + p.sessMax
				qStr := p.qCur + "/" + p.qMax
				row := fmt.Sprintf("  %s%s%s",
					styledPad(valueStyle.Render(pName), cPN),
					styledPad(valueStyle.Render(sessStr), cPS),
					valueStyle.Render(qStr))
				sb.WriteString(boxRow(row, iw) + "\n")
			}
			sb.WriteString(boxBot(iw) + "\n\n")
		}
	}

	// ── CONFIG WARNINGS ─────────────────────────────────────────────────
	cfgWarnCount, _ := strconv.Atoi(dm["config_warning_count"])
	if cfgWarnCount > 0 {
		sb.WriteString("  " + titleStyle.Render("CONFIG WARNINGS") + "\n")
		sb.WriteString(boxTop(iw) + "\n")
		for i := 0; i < cfgWarnCount; i++ {
			w := dm[fmt.Sprintf("config_warning_%d", i)]
			if w == "" { continue }
			sb.WriteString(boxRow("  "+warnStyle.Render("!")+dimStyle.Render(" "+w), iw) + "\n")
		}
		sb.WriteString(boxBot(iw) + "\n\n")
	}

	// ── LAST STATE CHANGES ──────────────────────────────────────────────
	stateChgCount, _ := strconv.Atoi(dm["state_change_count"])
	if stateChgCount > 0 {
		sb.WriteString("  " + titleStyle.Render("LAST STATE CHANGES") + "\n")
		sb.WriteString(boxTop(iw) + "\n")
		cSS, cSB, cSSt := 20, 20, 12
		sb.WriteString(boxRow(fmt.Sprintf("  %s%s%s%s",
			styledPad(dimStyle.Render("Server"), cSS),
			styledPad(dimStyle.Render("Backend"), cSB),
			styledPad(dimStyle.Render("Status"), cSSt),
			dimStyle.Render("Changed Ago")), iw) + "\n")
		sb.WriteString(boxMid(iw) + "\n")
		for i := 0; i < stateChgCount; i++ {
			pre := fmt.Sprintf("state_change_%d_", i)
			srv := dm[pre+"server"]
			be := dm[pre+"backend"]
			status := dm[pre+"status"]
			lastchg := dm[pre+"lastchg"]
			if len(srv) > 18 { srv = srv[:18] }
			if len(be) > 18 { be = be[:18] }
			// Color status
			var stBadge string
			switch status {
			case "UP":   stBadge = okStyle.Render(status)
			case "DOWN": stBadge = critStyle.Render(status)
			default:     stBadge = warnStyle.Render(status)
			}
			row := fmt.Sprintf("  %s%s%s%s",
				styledPad(valueStyle.Render(srv), cSS),
				styledPad(valueStyle.Render(be), cSB),
				styledPad(stBadge, cSSt),
				dimStyle.Render(haFmtDuration(lastchg)))
			sb.WriteString(boxRow(row, iw) + "\n")
		}
		sb.WriteString(boxBot(iw) + "\n\n")
	}

	// ── FRONTENDS ───────────────────────────────────────────────────────
	feCount, _ := strconv.Atoi(dm["fe_detail_count"])
	if feCount > 0 {
		// Frontend summary line
		feTotalReq := dm["total_sessions"]
		fe2xxPctStr, fe5xxPctStr := "", ""
		if tot, _ := strconv.ParseFloat(feTotalReq, 64); tot > 0 {
			v2, _ := strconv.ParseFloat(dm["fe_2xx"], 64)
			v5, _ := strconv.ParseFloat(dm["fe_5xx"], 64)
			fe2xxPctStr = fmt.Sprintf(" (%.1f%%)", v2/tot*100)
			fe5xxPctStr = fmt.Sprintf(" (%.1f%%)", v5/tot*100)
		}
		feSumm := fmt.Sprintf("%s frontends, %s req/s in, %s 2xx%s, %s 5xx%s, %s ereq",
			dm["frontends"], dm["fe_req_rate"], haFmtNum(dm["fe_2xx"]), fe2xxPctStr, haFmtNum(dm["fe_5xx"]), fe5xxPctStr, haFmtNum(dm["fe_ereq"]))
		sb.WriteString("  " + titleStyle.Render("FRONTENDS") + "  " + dimStyle.Render(feSumm) + "\n")
		sb.WriteString(boxTop(iw) + "\n")

		cFN, cFM, cFR, cFRr, cFBi, cFBo, cF2, cF2p, cF5, cF5p := 20, 8, 8, 10, 12, 12, 10, 7, 10, 7
		feHdr := fmt.Sprintf("  %s%s%s%s%s%s%s%s%s%s%s",
			styledPad(dimStyle.Render("Frontend"), cFN),
			styledPad(dimStyle.Render("Mode"), cFM),
			styledPad(dimStyle.Render("Cur"), cFR),
			styledPad(dimStyle.Render("Req/s"), cFRr),
			styledPad(dimStyle.Render("In"), cFBi),
			styledPad(dimStyle.Render("Out"), cFBo),
			styledPad(dimStyle.Render("2xx"), cF2),
			styledPad(dimStyle.Render("2xx%"), cF2p),
			styledPad(dimStyle.Render("5xx"), cF5),
			styledPad(dimStyle.Render("5xx%"), cF5p),
			dimStyle.Render("Health"))
		sb.WriteString(boxRow(feHdr, iw) + "\n")
		sb.WriteString(boxMid(iw) + "\n")

		for i := 0; i < feCount; i++ {
			pre := fmt.Sprintf("fe_detail_%d_", i)
			feName := dm[pre+"name"]
			feMode := dm[pre+"mode"]
			feCur := dm[pre+"scur"]
			feRR := dm[pre+"req_rate"]
			feBin := dm[pre+"bin"]
			feBout := dm[pre+"bout"]
			fe2 := dm[pre+"2xx"]
			fe5 := dm[pre+"5xx"]
			feStot := dm[pre+"stot"]
			feH := dm[pre+"health"]

			if len(feName) > 18 { feName = feName[:18] }

			// Compute percentages
			fe2pct, fe5pct := "—", "—"
			if tot, _ := strconv.ParseFloat(feStot, 64); tot > 0 {
				v2, _ := strconv.ParseFloat(fe2, 64)
				v5, _ := strconv.ParseFloat(fe5, 64)
				fe2pct = fmt.Sprintf("%.1f%%", v2/tot*100)
				fe5pct = fmt.Sprintf("%.1f%%", v5/tot*100)
			}

			var hBadge string
			switch feH {
			case "HEALTHY":  hBadge = okStyle.Render("HEALTHY")
			case "DEGRADED": hBadge = warnStyle.Render("DEGRADED")
			case "CRITICAL": hBadge = critStyle.Render("CRITICAL")
			default:         hBadge = dimStyle.Render(feH)
			}

			// Color 5xx% — red if >1%, yellow if >0.1%
			fe5pctStyled := valueStyle.Render(fe5pct)
			if v5, _ := strconv.ParseFloat(fe5, 64); v5 > 0 {
				if tot, _ := strconv.ParseFloat(feStot, 64); tot > 0 {
					pct := v5 / tot * 100
					if pct > 1 {
						fe5pctStyled = critStyle.Render(fe5pct)
					} else if pct > 0.1 {
						fe5pctStyled = warnStyle.Render(fe5pct)
					}
				}
			}

			row := fmt.Sprintf("  %s%s%s%s%s%s%s%s%s%s%s",
				styledPad(valueStyle.Render(feName), cFN),
				styledPad(valueStyle.Render(feMode), cFM),
				styledPad(valueStyle.Render(feCur), cFR),
				styledPad(valueStyle.Render(feRR+"/s"), cFRr),
				styledPad(valueStyle.Render(haFmtBytes(feBin)), cFBi),
				styledPad(valueStyle.Render(haFmtBytes(feBout)), cFBo),
				styledPad(valueStyle.Render(haFmtNum(fe2)), cF2),
				styledPad(okStyle.Render(fe2pct), cF2p),
				styledPad(haColorVal(haFmtNum(fe5), "5xx"), cF5),
				styledPad(fe5pctStyled, cF5p),
				hBadge)
			sb.WriteString(boxRow(row, iw) + "\n")
		}
		// Source IPs inside frontend box
		inboundIPCount, _ := strconv.Atoi(dm["inbound_ip_count"])
		if inboundIPCount > 0 {
			sb.WriteString(boxMid(iw) + "\n")
			sb.WriteString(boxRow("  "+dimStyle.Render("SOURCE IPs"), iw) + "\n")
			sb.WriteString(boxMid(iw) + "\n")
			cIP, cConns, cFE := 20, 14, 20
			sb.WriteString(boxRow(fmt.Sprintf("  %s%s%s%s",
				styledPad(dimStyle.Render("Source IP"), cIP),
				styledPad(dimStyle.Render("Active Conns"), cConns),
				styledPad(dimStyle.Render("Frontend"), cFE),
				dimStyle.Render("% of Traffic")), iw) + "\n")
			for i := 0; i < inboundIPCount; i++ {
				pre := fmt.Sprintf("inbound_ip_%d_", i)
				ip := dm[pre+"addr"]
				conns := dm[pre+"conns"]
				pct := dm[pre+"pct"]
				fe := dm[pre+"frontend"]
				row := fmt.Sprintf("  %s%s%s%s",
					styledPad(valueStyle.Render(ip), cIP),
					styledPad(valueStyle.Render(conns), cConns),
					styledPad(dimStyle.Render(fe), cFE),
					valueStyle.Render(pct+"%"))
				sb.WriteString(boxRow(row, iw) + "\n")
			}
		}

		// TCP states — frontend (inbound) vs backend (outbound) side by side
		if dm["tcp_total"] != "" {
			sb.WriteString(boxMid(iw) + "\n")
			subHdr := fmt.Sprintf("%s%s",
				styledPad("  "+dimStyle.Render(fmt.Sprintf("INBOUND TCP (clients → HAProxy) [%s]", dm["fe_tcp_total"])), halfW),
				"  "+dimStyle.Render(fmt.Sprintf("OUTBOUND TCP (HAProxy → suppliers) [%s]", dm["be_tcp_total"])))
			sb.WriteString(boxRow(subHdr, iw) + "\n")

			feKVs := []kv{
				{Key: "ESTABLISHED", Val: dm["fe_tcp_established"]},
				{Key: "TIME_WAIT", Val: dm["fe_tcp_time_wait"]},
				{Key: "CLOSE_WAIT", Val: haColorTCPState(dm["fe_tcp_close_wait"], "CLOSE_WAIT")},
				{Key: "FIN_WAIT1", Val: haColorTCPState(dm["fe_tcp_fin_wait1"], "FIN_WAIT")},
				{Key: "FIN_WAIT2", Val: haColorTCPState(dm["fe_tcp_fin_wait2"], "FIN_WAIT")},
				{Key: "SYN_RECV", Val: haColorTCPState(dm["fe_tcp_syn_recv"], "SYN_RECV")},
				{Key: "LAST_ACK", Val: dm["fe_tcp_last_ack"]},
				{Key: "LISTEN", Val: dm["fe_tcp_listen"]},
			}
			beKVs := []kv{
				{Key: "ESTABLISHED", Val: dm["be_tcp_established"]},
				{Key: "TIME_WAIT", Val: dm["be_tcp_time_wait"]},
				{Key: "CLOSE_WAIT", Val: haColorTCPState(dm["be_tcp_close_wait"], "CLOSE_WAIT")},
				{Key: "FIN_WAIT1", Val: haColorTCPState(dm["be_tcp_fin_wait1"], "FIN_WAIT")},
				{Key: "FIN_WAIT2", Val: haColorTCPState(dm["be_tcp_fin_wait2"], "FIN_WAIT")},
				{Key: "SYN_SENT", Val: dm["be_tcp_syn_sent"]},
				{Key: "LAST_ACK", Val: dm["be_tcp_last_ack"]},
			}
			maxR := len(feKVs)
			if len(beKVs) > maxR { maxR = len(beKVs) }
			for i := 0; i < maxR; i++ {
				var left, right string
				if i < len(feKVs) && feKVs[i].Val != "" && feKVs[i].Val != "0" {
					left = fmt.Sprintf("  %s %s", styledPad(dimStyle.Render(feKVs[i].Key+":"), 14), feKVs[i].Val)
				}
				if i < len(beKVs) && beKVs[i].Val != "" && beKVs[i].Val != "0" {
					right = fmt.Sprintf("  %s %s", styledPad(dimStyle.Render(beKVs[i].Key+":"), 14), beKVs[i].Val)
				}
				if left != "" || right != "" {
					sb.WriteString(boxRow(fmt.Sprintf("%s%s", styledPad(left, halfW), right), iw) + "\n")
				}
			}

			// Top IPs per direction
			feIPCount, _ := strconv.Atoi(dm["fe_top_ip_count"])
			beIPCount, _ := strconv.Atoi(dm["be_top_ip_count"])
			if feIPCount > 0 || beIPCount > 0 {
				sb.WriteString(boxMid(iw) + "\n")
				subHdr2 := fmt.Sprintf("%s%s",
					styledPad("  "+dimStyle.Render("TOP INBOUND IPs"), halfW),
					"  "+dimStyle.Render("TOP OUTBOUND IPs"))
				sb.WriteString(boxRow(subHdr2, iw) + "\n")
				maxIP := feIPCount
				if beIPCount > maxIP { maxIP = beIPCount }
				for i := 0; i < maxIP; i++ {
					var left, right string
					if i < feIPCount {
						fePfx := fmt.Sprintf("fe_top_ip_%d_", i)
						left = fmt.Sprintf("  %s %s",
							styledPad(valueStyle.Render(dm[fePfx+"ip"]), 18),
							dimStyle.Render(dm[fePfx+"states"]))
					}
					if i < beIPCount {
						bePfx := fmt.Sprintf("be_top_ip_%d_", i)
						right = fmt.Sprintf("  %s %s",
							styledPad(valueStyle.Render(dm[bePfx+"ip"]), 18),
							dimStyle.Render(dm[bePfx+"states"]))
					}
					if left != "" || right != "" {
						sb.WriteString(boxRow(fmt.Sprintf("%s%s", styledPad(left, halfW), right), iw) + "\n")
					}
				}
			}

			// Connection summary below
			sb.WriteString(boxMid(iw) + "\n")
			summKVs := []kv{
				{Key: "Active Sess", Val: dm["inbound_active_sess"]},
				{Key: "Cli Aborts", Val: haFmtNum(dm["client_aborts"])},
				{Key: "Abort Rate", Val: haSuffix(dm["inbound_abort_pct"], "%")},
			}
			summKVs2 := []kv{
				{Key: "Unique IPs", Val: dm["inbound_total_unique"]},
				{Key: "Total TCP", Val: dm["tcp_total"]},
				{Key: "Ports", Val: dm["listen_ports"]},
			}
			for i := 0; i < len(summKVs); i++ {
				var left, right string
				if summKVs[i].Val != "" {
					left = fmt.Sprintf("  %s %s", styledPad(dimStyle.Render(summKVs[i].Key+":"), 14), valueStyle.Render(summKVs[i].Val))
				}
				if i < len(summKVs2) && summKVs2[i].Val != "" {
					right = fmt.Sprintf("  %s %s", styledPad(dimStyle.Render(summKVs2[i].Key+":"), 14), valueStyle.Render(summKVs2[i].Val))
				}
				sb.WriteString(boxRow(fmt.Sprintf("%s%s", styledPad(left, halfW), right), iw) + "\n")
			}
		}
		sb.WriteString(boxBot(iw) + "\n\n")
	}

	// ── DIAGNOSTICS (unified: all RCA in one place) ─────────────────────
	{
		// Collect all diagnostic items
		type diagItem struct {
			severity string
			title    string
			cause    string
			evidence string
			blame    string
			fix      string
		}
		var diags []diagItem

		// 1) RCA per-backend blame (from collector)
		if dm["rca_summary"] != "" && dm["rca_summary"] != "No significant issues detected" {
			rcaBeCount, _ := strconv.Atoi(dm["rca_backend_count"])
			if rcaBeCount > 0 {
				for i := 0; i < rcaBeCount; i++ {
					line := dm[fmt.Sprintf("rca_backend_%d", i)]
					if line != "" {
						diags = append(diags, diagItem{
							severity: "WARN",
							title:    "Backend: " + line,
						})
					}
				}
			}
			if dm["rca_abort_analysis"] != "" {
				diags = append(diags, diagItem{
					severity: "WARN",
					title:    "Aborts: " + dm["rca_abort_analysis"],
				})
			}
		}

		// 2) Inbound diagnostics (from collector)
		issueCount, _ := strconv.Atoi(dm["inbound_issue_count"])
		for i := 0; i < issueCount; i++ {
			pre := fmt.Sprintf("inbound_issue_%d_", i)
			title := dm[pre+"title"]
			if title == "" { continue }
			diags = append(diags, diagItem{
				severity: dm[pre+"severity"],
				title:    title,
				cause:    dm[pre+"cause"],
				evidence: dm[pre+"evidence"],
				blame:    dm[pre+"blame"],
				fix:      dm[pre+"fix"],
			})
		}

		if len(diags) > 0 {
			sb.WriteString("  " + titleStyle.Render("DIAGNOSTICS") + "  " + dimStyle.Render(fmt.Sprintf("%d issues", len(diags))) + "\n")
			sb.WriteString(boxTop(iw) + "\n")

			// Summary line
			if dm["rca_summary"] != "" && dm["rca_summary"] != "No significant issues detected" {
				sb.WriteString(boxRow("  "+critStyle.Render("SUMMARY: ")+valueStyle.Render(dm["rca_summary"]), iw) + "\n")
				sb.WriteString(boxMid(iw) + "\n")
			}

			for idx, d := range diags {
				if idx > 0 { sb.WriteString(boxMid(iw) + "\n") }

				var sevBadge string
				if d.severity == "CRIT" { sevBadge = critStyle.Render("CRIT") } else { sevBadge = warnStyle.Render("WARN") }
				sb.WriteString(boxRow(fmt.Sprintf("  %s %s  %s",
					warnStyle.Render(fmt.Sprintf("#%d", idx+1)), sevBadge, valueStyle.Render(d.title)), iw) + "\n")

				if d.cause != "" {
					sb.WriteString(boxRow("  "+dimStyle.Render("Cause:")+"    "+dimStyle.Render(d.cause), iw) + "\n")
				}
				if d.evidence != "" {
					sb.WriteString(boxRow("  "+dimStyle.Render("Evidence:")+" "+dimStyle.Render(d.evidence), iw) + "\n")
				}
				if d.blame != "" {
					blameStyled := dimStyle.Render(d.blame)
					if strings.HasPrefix(d.blame, "Our side") || strings.HasPrefix(d.blame, "Configuration") {
						blameStyled = warnStyle.Render(d.blame)
					} else if strings.HasPrefix(d.blame, "External") {
						blameStyled = critStyle.Render(d.blame)
					}
					sb.WriteString(boxRow("  "+dimStyle.Render("Blame:")+"    "+blameStyled, iw) + "\n")
				}
				if d.fix != "" {
					sb.WriteString(boxRow("  "+dimStyle.Render("Fix:")+"      "+dimStyle.Render(d.fix), iw) + "\n")
				}
			}
			sb.WriteString(boxBot(iw) + "\n\n")
		}
	}

	return sb.String()
}

// haRender3Col renders 3 columns of kv pairs in a box (no top/bot borders).
func haRender3Col(sb *strings.Builder, iw, thirdW int, c1, c2, c3 []kv) {
	maxR := len(c1)
	if len(c2) > maxR { maxR = len(c2) }
	if len(c3) > maxR { maxR = len(c3) }
	for i := 0; i < maxR; i++ {
		var s1, s2, s3 string
		if i < len(c1) && c1[i].Val != "" { s1 = fmt.Sprintf("  %s %s", styledPad(dimStyle.Render(c1[i].Key+":"), 12), valueStyle.Render(c1[i].Val)) }
		if i < len(c2) && c2[i].Val != "" { s2 = fmt.Sprintf("  %s %s", styledPad(dimStyle.Render(c2[i].Key+":"), 12), valueStyle.Render(c2[i].Val)) }
		if i < len(c3) && c3[i].Val != "" { s3 = fmt.Sprintf("  %s %s", styledPad(dimStyle.Render(c3[i].Key+":"), 12), valueStyle.Render(c3[i].Val)) }
		sb.WriteString(boxRow(fmt.Sprintf("%s%s%s", styledPad(s1, thirdW), styledPad(s2, thirdW), s3), iw) + "\n")
	}
}

// renderHAProxyHealthIssues shows health issues with per-backend error attribution.
func renderHAProxyHealthIssues(app model.AppInstance, iw int) string {
	dm := app.DeepMetrics
	var sb strings.Builder

	sb.WriteString("  " + titleStyle.Render("HEALTH ISSUES") + "\n")
	sb.WriteString(boxTop(iw) + "\n")

	// Show each issue
	for _, issue := range app.HealthIssues {
		row := "  " + critStyle.Render("\u25cf") + " " + valueStyle.Render(issue)
		sb.WriteString(boxRow(row, iw) + "\n")
	}

	// Per-backend error breakdown — find backends with errors
	type beErr struct {
		name     string
		addr     string
		e5xx     int64
		eresp    int64 // response errors = econ (connection errors on backend side)
		econ     int64
		retries  int64
		cliAbrt  int64
		rtime    int64
		reqTot   int64
		health   string
	}
	beCount, _ := strconv.Atoi(dm["be_detail_count"])
	var problemBEs []beErr
	for i := 0; i < beCount; i++ {
		pre := fmt.Sprintf("be_detail_%d_", i)
		e5, _ := strconv.ParseInt(dm[pre+"5xx"], 10, 64)
		ec, _ := strconv.ParseInt(dm[pre+"econ"], 10, 64)
		ret, _ := strconv.ParseInt(dm[pre+"retries"], 10, 64)
		ca, _ := strconv.ParseInt(dm[pre+"cli_abrt"], 10, 64)
		rt, _ := strconv.ParseInt(dm[pre+"rtime"], 10, 64)
		rq, _ := strconv.ParseInt(dm[pre+"req_total"], 10, 64)
		h := dm[pre+"health"]
		if e5 > 0 || ec > 0 || ret > 0 || ca > 100 || h == "DEGRADED" || h == "CRITICAL" || h == "DOWN" || h == "SLOW" {
			problemBEs = append(problemBEs, beErr{
				name: dm[pre+"name"], addr: dm[pre+"addr"],
				e5xx: e5, econ: ec, retries: ret, cliAbrt: ca,
				rtime: rt, reqTot: rq, health: h,
			})
		}
	}

	if len(problemBEs) > 0 {
		sb.WriteString(boxMid(iw) + "\n")
		sb.WriteString(boxRow("  "+titleStyle.Render("ERROR BREAKDOWN BY BACKEND"), iw) + "\n")
		sb.WriteString(boxMid(iw) + "\n")

		cN, cA, c5, cE, cR, cAb, cRt := 20, 18, 10, 10, 9, 12, 9
		hdr := fmt.Sprintf("  %s%s%s%s%s%s%s%s",
			styledPad(dimStyle.Render("Backend"), cN),
			styledPad(dimStyle.Render("Endpoint"), cA),
			styledPad(dimStyle.Render("5xx"), c5),
			styledPad(dimStyle.Render("ConnErr"), cE),
			styledPad(dimStyle.Render("Retries"), cR),
			styledPad(dimStyle.Render("Cli Aborts"), cAb),
			styledPad(dimStyle.Render("Resp ms"), cRt),
			dimStyle.Render("Status"))
		sb.WriteString(boxRow(hdr, iw) + "\n")

		for _, be := range problemBEs {
			name := be.name
			if len(name) > 18 { name = name[:18] }
			addr := be.addr
			if len(addr) > 16 { addr = addr[:16] }

			// 5xx with percentage
			e5str := haFmtNum(fmt.Sprintf("%d", be.e5xx))
			if be.reqTot > 0 && be.e5xx > 0 {
				pct := float64(be.e5xx) / float64(be.reqTot) * 100
				e5str += fmt.Sprintf(" %.1f%%", pct)
				if pct > 1 {
					e5str = critStyle.Render(e5str)
				} else {
					e5str = warnStyle.Render(e5str)
				}
			} else {
				e5str = dimStyle.Render("—")
			}

			ecStr := dimStyle.Render("—")
			if be.econ > 0 { ecStr = critStyle.Render(haFmtNum(fmt.Sprintf("%d", be.econ))) }

			retStr := dimStyle.Render("—")
			if be.retries > 0 { retStr = warnStyle.Render(haFmtNum(fmt.Sprintf("%d", be.retries))) }

			abStr := dimStyle.Render("—")
			if be.cliAbrt > 100 { abStr = warnStyle.Render(haFmtNum(fmt.Sprintf("%d", be.cliAbrt))) }

			rtStr := fmt.Sprintf("%dms", be.rtime)
			if be.rtime > 5000 {
				rtStr = critStyle.Render(rtStr)
			} else if be.rtime > 2000 {
				rtStr = warnStyle.Render(rtStr)
			} else {
				rtStr = valueStyle.Render(rtStr)
			}

			var hBadge string
			switch be.health {
			case "HEALTHY":  hBadge = okStyle.Render("OK")
			case "DEGRADED": hBadge = warnStyle.Render("DEGRADED")
			case "SLOW":     hBadge = warnStyle.Render("SLOW")
			case "CRITICAL": hBadge = critStyle.Render("CRITICAL")
			case "DOWN":     hBadge = critStyle.Render("DOWN")
			default:         hBadge = dimStyle.Render(be.health)
			}

			row := fmt.Sprintf("  %s%s%s%s%s%s%s%s",
				styledPad(valueStyle.Render(name), cN),
				styledPad(dimStyle.Render(addr), cA),
				styledPad(e5str, c5),
				styledPad(ecStr, cE),
				styledPad(retStr, cR),
				styledPad(abStr, cAb),
				styledPad(rtStr, cRt),
				hBadge)
			sb.WriteString(boxRow(row, iw) + "\n")
		}
	}

	// RCA summary — the root cause explanation
	if rca := dm["rca_summary"]; rca != "" && rca != "No significant issues detected" {
		sb.WriteString(boxMid(iw) + "\n")
		sb.WriteString(boxRow("  "+titleStyle.Render("ROOT CAUSE")+"  "+valueStyle.Render(rca), iw) + "\n")
	}

	sb.WriteString(boxBot(iw) + "\n\n")
	return sb.String()
}

// HAProxy UI helpers
func haJoin(a, b string) string {
	if a == "" && b == "" { return "" }
	if a == "" { a = "0" }
	if b == "" { b = "0" }
	return a + " / " + b
}

func haServersLine(dm map[string]string) string {
	up, down, total := dm["servers_up"], dm["servers_down"], dm["servers_total"]
	if total == "" { return "" }
	s := up + " up"
	if down != "" && down != "0" { s += ", " + warnStyle.Render(down+" down") }
	s += " / " + total
	return s
}

func haSuffix(val, suffix string) string {
	if val == "" { return "" }
	return val + suffix
}

func haFmtNum(val string) string {
	if val == "" { return "" }
	v, err := strconv.ParseInt(val, 10, 64)
	if err != nil { return val }
	switch {
	case v >= 1_000_000_000: return fmt.Sprintf("%.1fB", float64(v)/1e9)
	case v >= 1_000_000:     return fmt.Sprintf("%.1fM", float64(v)/1e6)
	case v >= 1_000:         return fmt.Sprintf("%.1fK", float64(v)/1e3)
	default:                 return val
	}
}

func haFmtNumPct(val, pct string) string {
	if val == "" { return "" }
	num := haFmtNum(val)
	if pct == "" || pct == "0.00" { return num }
	return num + " (" + pct + "%)"
}

func haFmtBytes(val string) string {
	if val == "" { return "" }
	v, err := strconv.ParseInt(val, 10, 64)
	if err != nil { return val }
	switch {
	case v >= 1<<40: return fmt.Sprintf("%.1f TB", float64(v)/float64(int64(1)<<40))
	case v >= 1<<30: return fmt.Sprintf("%.1f GB", float64(v)/float64(int64(1)<<30))
	case v >= 1<<20: return fmt.Sprintf("%.1f MB", float64(v)/float64(int64(1)<<20))
	case v >= 1<<10: return fmt.Sprintf("%.1f KB", float64(v)/float64(int64(1)<<10))
	default:         return fmt.Sprintf("%d B", v)
	}
}

func haColorVal(val, key string) string {
	if val == "" || val == "0" { return valueStyle.Render(val) }
	if strings.Contains(key, "5xx") || strings.Contains(key, "Err") { return critStyle.Render(val) }
	if strings.Contains(key, "4xx") || strings.Contains(key, "Abort") { return warnStyle.Render(val) }
	if strings.Contains(key, "2xx") { return okStyle.Render(val) }
	return valueStyle.Render(val)
}

func haFmtDuration(secStr string) string {
	s, err := strconv.ParseInt(secStr, 10, 64)
	if err != nil || secStr == "" { return secStr }
	switch {
	case s < 60:    return fmt.Sprintf("%ds ago", s)
	case s < 3600:  return fmt.Sprintf("%dm ago", s/60)
	case s < 86400: return fmt.Sprintf("%dh ago", s/3600)
	default:        return fmt.Sprintf("%dd ago", s/86400)
	}
}

func haFmtNonZero(val string) string {
	if val == "" || val == "0" { return "" }
	return haFmtNum(val)
}

func haColorTCPState(val, stateType string) string {
	if val == "" || val == "0" {
		return valueStyle.Render("0")
	}
	n, _ := strconv.Atoi(val)
	switch stateType {
	case "CLOSE_WAIT":
		if n > 50 {
			return critStyle.Render(val)
		} else if n > 10 {
			return warnStyle.Render(val)
		}
	case "FIN_WAIT":
		if n > 50 {
			return warnStyle.Render(val)
		}
	case "SYN_RECV":
		if n > 20 {
			return critStyle.Render(val)
		} else if n > 5 {
			return warnStyle.Render(val)
		}
	}
	return valueStyle.Render(val)
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

// ── MongoDB Detail ─────────────────────────────────────────────────────

// mongoRate returns "value (rate/s)" or just "value" if no rate.
func mongoRate(dm map[string]string, key string) string {
	v := dm[key]
	if v == "" {
		return ""
	}
	r := dm[key+"_rate"]
	if r == "" || r == "0.0" {
		return v
	}
	// Format rate nicely
	rf, _ := strconv.ParseFloat(r, 64)
	var rs string
	switch {
	case rf >= 1e9:
		rs = fmt.Sprintf("%.1fB", rf/1e9)
	case rf >= 1e6:
		rs = fmt.Sprintf("%.1fM", rf/1e6)
	case rf >= 1e3:
		rs = fmt.Sprintf("%.1fK", rf/1e3)
	case rf >= 1:
		rs = fmt.Sprintf("%.0f", rf)
	default:
		rs = fmt.Sprintf("%.1f", rf)
	}
	return v + " (" + rs + "/s)"
}

func renderMongoDBDeepMetrics(app model.AppInstance, iw int) string {
	var sb strings.Builder
	dm := app.DeepMetrics
	halfW := (iw - 4) / 2
	lw := 18 // label width for compact columns

	// ══════════════════════════════════════════════════════════════════
	// 1. DATABASES & COLLECTIONS — most actionable, shown first
	// ══════════════════════════════════════════════════════════════════
	if dbList := dm["db_list"]; dbList != "" {
		sb.WriteString(renderMongoDBCollections(dm, iw))
	}

	// ══════════════════════════════════════════════════════════════════
	// 2. HEALTH RCA
	// ══════════════════════════════════════════════════════════════════
	type healthRow struct{ metric, value, status, tip string }
	rows := []healthRow{}

	// Cache usage
	if v := dm["cache_usage_pct"]; v != "" {
		pct, _ := strconv.ParseFloat(v, 64)
		st, tip := "OK", ""
		if pct > 95 {
			st, tip = "CRIT", "eviction pressure — increase cacheSizeGB or reduce working set"
		} else if pct > 80 {
			st, tip = "WARN", "cache filling up — monitor eviction rate"
		}
		rows = append(rows, healthRow{"WT Cache", v + "%", st, tip})
	}

	// Cache dirty ratio
	dirtyMB, _ := strconv.ParseFloat(dm["cache_dirty_mb"], 64)
	cacheMB, _ := strconv.ParseFloat(dm["cache_max_mb"], 64)
	if cacheMB > 0 && dirtyMB > 0 {
		dirtyPct := dirtyMB / cacheMB * 100
		st, tip := "OK", ""
		if dirtyPct > 20 {
			st, tip = "CRIT", "write stalls likely — check I/O throughput"
		} else if dirtyPct > 5 {
			st, tip = "WARN", "dirty pages accumulating"
		}
		rows = append(rows, healthRow{"Cache Dirty", fmt.Sprintf("%.1f%%", dirtyPct), st, tip})
	}

	// Connection usage
	connCur, _ := strconv.Atoi(dm["conn_current"])
	connAvail, _ := strconv.Atoi(dm["conn_available"])
	if connAvail > 0 {
		pct := float64(connCur) / float64(connCur+connAvail) * 100
		st, tip := "OK", ""
		if pct > 90 {
			st, tip = "CRIT", "near connection limit — increase maxIncomingConnections or use connection pooling"
		} else if pct > 80 {
			st, tip = "WARN", "connection pool filling"
		}
		rows = append(rows, healthRow{"Connections", fmt.Sprintf("%d/%d (%.0f%%)", connCur, connCur+connAvail, pct), st, tip})
	}

	// Lock queue
	lockQ, _ := strconv.Atoi(dm["lock_queue_total"])
	{
		st, tip := "OK", ""
		if lockQ > 10 {
			st, tip = "CRIT", "severe contention — check slow queries and indexing"
		} else if lockQ > 0 {
			st, tip = "WARN", "lock contention detected"
		}
		rows = append(rows, healthRow{"Lock Queue", fmt.Sprintf("%d", lockQ), st, tip})
	}

	// WT tickets
	readAvail, _ := strconv.Atoi(dm["wt_read_avail"])
	writeAvail, _ := strconv.Atoi(dm["wt_write_avail"])
	readOut, _ := strconv.Atoi(dm["wt_read_out"])
	writeOut, _ := strconv.Atoi(dm["wt_write_out"])
	if readAvail+readOut > 0 {
		st, tip := "OK", ""
		if readAvail < 5 {
			st, tip = "CRIT", "read tickets exhausted — queries queuing"
		} else if readAvail < 20 {
			st, tip = "WARN", "read tickets low"
		}
		rows = append(rows, healthRow{"Read Tickets", fmt.Sprintf("%d avail / %d used", readAvail, readOut), st, tip})
	}
	if writeAvail+writeOut > 0 {
		st, tip := "OK", ""
		if writeAvail < 5 {
			st, tip = "CRIT", "write tickets exhausted — writes queuing"
		} else if writeAvail < 20 {
			st, tip = "WARN", "write tickets low"
		}
		rows = append(rows, healthRow{"Write Tickets", fmt.Sprintf("%d avail / %d used", writeAvail, writeOut), st, tip})
	}

	// Slow ops
	slowOps, _ := strconv.Atoi(dm["slow_ops"])
	if slowOps > 0 {
		st := "WARN"
		tip := "check db.currentOp() and add indexes"
		if slowOps > 10 {
			st, tip = "CRIT", "many slow queries — profile and optimize"
		}
		rows = append(rows, healthRow{"Slow Ops (>5s)", fmt.Sprintf("%d", slowOps), st, tip})
	}

	// Cursors timed out
	curTimeout, _ := strconv.Atoi(dm["cursor_timed_out"])
	if curTimeout > 100 {
		rows = append(rows, healthRow{"Cursor Timeouts", dm["cursor_timed_out"], "WARN", "increase batch size or process faster"})
	}

	// Replication lag
	if lagStr := dm["repl_lag_sec"]; lagStr != "" && lagStr != "0" {
		lag, _ := strconv.Atoi(lagStr)
		st, tip := "WARN", "secondary falling behind"
		if lag > 60 {
			st, tip = "CRIT", "severely behind primary — check oplog size and network"
		}
		rows = append(rows, healthRow{"Replication Lag", lagStr + "s", st, tip})
	}

	// Asserts
	assertReg, _ := strconv.Atoi(dm["assert_regular"])
	assertMsg, _ := strconv.Atoi(dm["assert_msg"])
	assertUser, _ := strconv.Atoi(dm["assert_user"])
	if assertReg > 0 || assertMsg > 0 {
		rows = append(rows, healthRow{"Asserts", fmt.Sprintf("reg:%d msg:%d user:%d", assertReg, assertMsg, assertUser), "WARN", "internal assertion failures detected"})
	} else if assertUser > 10000 {
		rows = append(rows, healthRow{"User Asserts", mongoFmtCount(int64(assertUser)), "WARN", "app-level errors (dupes, validation)"})
	}

	// Global avg latency
	avgReadUs, _ := strconv.Atoi(dm["avg_read_latency_us"])
	avgWriteUs, _ := strconv.Atoi(dm["avg_write_latency_us"])
	if avgReadUs > 0 || avgWriteUs > 0 {
		st, tip := "OK", ""
		if avgReadUs > 10000 || avgWriteUs > 50000 {
			st, tip = "CRIT", "high global latency — check indexes and working set"
		} else if avgReadUs > 1000 || avgWriteUs > 10000 {
			st, tip = "WARN", "latency elevated"
		}
		rows = append(rows, healthRow{"Avg Latency",
			fmt.Sprintf("R:%s W:%s", mongoFmtLatency(int64(avgReadUs)), mongoFmtLatency(int64(avgWriteUs))), st, tip})
	}

	// Collection scans
	collScans, _ := strconv.Atoi(dm["collection_scans"])
	if collScans > 100 {
		st := "WARN"
		tip := "add indexes to avoid full scans"
		if collScans > 10000 {
			st, tip = "CRIT", "excessive collection scans — missing indexes"
		}
		rows = append(rows, healthRow{"Collection Scans", mongoFmtCount(int64(collScans)), st, tip})
	}

	// Scan efficiency (scanned vs returned)
	scannedObj, _ := strconv.ParseFloat(dm["scanned_objects"], 64)
	docReturned, _ := strconv.ParseFloat(dm["doc_returned"], 64)
	if docReturned > 0 && scannedObj > 0 {
		ratio := scannedObj / docReturned
		if ratio > 10 {
			rows = append(rows, healthRow{"Scan Efficiency",
				fmt.Sprintf("%.0f:1 scan/return", ratio), "CRIT", "scanning far more docs than returning — missing indexes"})
		} else if ratio > 2 {
			rows = append(rows, healthRow{"Scan Efficiency",
				fmt.Sprintf("%.1f:1 scan/return", ratio), "WARN", "consider more targeted indexes"})
		}
	}

	// Rejected connections
	rejConns, _ := strconv.Atoi(dm["conn_rejected"])
	if rejConns > 0 {
		rows = append(rows, healthRow{"Rejected Conns", fmt.Sprintf("%d", rejConns), "CRIT", "clients being turned away — increase maxIncomingConnections"})
	}

	// Killed by disconnect
	killedDisc, _ := strconv.Atoi(dm["killed_disconnect"])
	if killedDisc > 1000 {
		rows = append(rows, healthRow{"Client Disconnects", mongoFmtCount(int64(killedDisc)), "WARN", "clients disconnecting mid-query — check timeouts"})
	}

	// Page faults
	pgFaults, _ := strconv.Atoi(dm["page_faults"])
	if pgFaults > 10000 {
		rows = append(rows, healthRow{"Page Faults", dm["page_faults"], "WARN", "working set exceeds RAM — increase cacheSizeGB"})
	}

	// Render health table
	sb.WriteString("  " + titleStyle.Render("HEALTH RCA") + "\n")
	sb.WriteString(boxTop(iw) + "\n")
	cM, cV, cS := 18, 28, 6
	cTip := iw - cM - cV - cS - 10
	if cTip < 10 {
		cTip = 10
	}
	hdr := fmt.Sprintf("  %s %s %s %s",
		styledPad(dimStyle.Render("Check"), cM),
		styledPad(dimStyle.Render("Value"), cV),
		styledPad(dimStyle.Render("Status"), cS),
		dimStyle.Render("Recommendation"))
	sb.WriteString(boxRow(hdr, iw) + "\n")
	sb.WriteString(boxMid(iw) + "\n")
	for _, r := range rows {
		badge := okStyle.Render(" OK ")
		if r.status == "WARN" {
			badge = warnStyle.Render("WARN")
		} else if r.status == "CRIT" {
			badge = critStyle.Render("CRIT")
		}
		tipStr := ""
		if r.tip != "" && r.status != "OK" {
			t := r.tip
			if len(t) > cTip {
				t = t[:cTip-1] + "…"
			}
			tipStr = dimStyle.Render(t)
		}
		row := fmt.Sprintf("  %s %s %s %s",
			styledPad(valueStyle.Render(r.metric), cM),
			styledPad(valueStyle.Render(r.value), cV),
			styledPad(badge, cS),
			tipStr)
		sb.WriteString(boxRow(row, iw) + "\n")
	}
	if len(rows) == 0 {
		sb.WriteString(boxRow("  "+dimStyle.Render("All checks passed"), iw) + "\n")
	}
	sb.WriteString(boxBot(iw) + "\n")

	// ── CONNECTIONS + OPERATIONS (side by side) ────────────────────────
	sb.WriteString("  " + titleStyle.Render("CONNECTIONS") + strings.Repeat(" ", halfW-12) + titleStyle.Render("OPERATIONS (/s)") + "\n")
	sb.WriteString(boxTop(iw) + "\n")
	lCol := []kv{
		{Key: "Current", Val: dm["conn_current"]},
		{Key: "Available", Val: dm["conn_available"]},
		{Key: "Total Created", Val: mongoRate(dm, "conn_total_created")},
		{Key: "Active", Val: dm["conn_active"]},
		{Key: "Rejected", Val: dm["conn_rejected"]},
		{Key: "Active Read", Val: dm["active_readers"]},
		{Key: "Active Write", Val: dm["active_writers"]},
	}
	rCol := []kv{
		{Key: "Queries", Val: mongoRate(dm, "op_query")},
		{Key: "Inserts", Val: mongoRate(dm, "op_insert")},
		{Key: "Updates", Val: mongoRate(dm, "op_update")},
		{Key: "Deletes", Val: mongoRate(dm, "op_delete")},
		{Key: "GetMore", Val: mongoRate(dm, "op_getmore")},
		{Key: "Commands", Val: mongoRate(dm, "op_command")},
		{Key: "Slow (>5s)", Val: dm["slow_ops"]},
	}
	mongoRenderDualCol(&sb, lCol, rCol, iw, halfW, lw)
	sb.WriteString(boxBot(iw) + "\n")

	// ── MEMORY/CACHE + WT ENGINE (side by side) ────────────────────────
	sb.WriteString("  " + titleStyle.Render("MEMORY & CACHE") + strings.Repeat(" ", halfW-15) + titleStyle.Render("WIREDTIGER") + "\n")
	sb.WriteString(boxTop(iw) + "\n")
	lCol = []kv{
		{Key: "Resident MB", Val: dm["mem_resident_mb"]},
		{Key: "Virtual MB", Val: dm["mem_virtual_mb"]},
		{Key: "Cache Used MB", Val: dm["cache_used_mb"]},
		{Key: "Cache Max MB", Val: dm["cache_max_mb"]},
		{Key: "Cache Usage%", Val: dm["cache_usage_pct"]},
		{Key: "Cache Dirty MB", Val: dm["cache_dirty_mb"]},
	}
	rCol = []kv{
		{Key: "Read Tickets", Val: mongoFmtTicket(dm["wt_read_avail"], dm["wt_read_out"])},
		{Key: "Write Tickets", Val: mongoFmtTicket(dm["wt_write_avail"], dm["wt_write_out"])},
		{Key: "Cache Reads", Val: mongoRate(dm, "cache_reads")},
		{Key: "Cache Writes", Val: mongoRate(dm, "cache_writes")},
		{Key: "Page Faults", Val: dm["page_faults"]},
		{Key: "Engine", Val: dm["storage_engine"]},
	}
	mongoRenderDualCol(&sb, lCol, rCol, iw, halfW, lw)
	sb.WriteString(boxBot(iw) + "\n")

	// ── DOCUMENTS + QUERY PERFORMANCE (side by side) ──────────────────
	sb.WriteString("  " + titleStyle.Render("DOCUMENTS & NETWORK (/s)") + strings.Repeat(" ", halfW-24) + titleStyle.Render("QUERY PERFORMANCE") + "\n")
	sb.WriteString(boxTop(iw) + "\n")
	lCol = []kv{
		{Key: "Inserted", Val: mongoRate(dm, "doc_inserted")},
		{Key: "Returned", Val: mongoRate(dm, "doc_returned")},
		{Key: "Updated", Val: mongoRate(dm, "doc_updated")},
		{Key: "Deleted", Val: mongoRate(dm, "doc_deleted")},
		{Key: "Net In", Val: mongoFmtBytes(dm["net_bytes_in"])},
		{Key: "Net Out", Val: mongoFmtBytes(dm["net_bytes_out"])},
		{Key: "Net Requests", Val: mongoRate(dm, "net_num_requests")},
	}
	// Compute avg latencies for display
	avgRdLat := mongoFmtLatency(mongoParseI64(dm["avg_read_latency_us"]))
	avgWrLat := mongoFmtLatency(mongoParseI64(dm["avg_write_latency_us"]))
	rCol = []kv{
		{Key: "Avg Read Lat", Val: avgRdLat},
		{Key: "Avg Write Lat", Val: avgWrLat},
		{Key: "Scanned Keys", Val: mongoRate(dm, "scanned_keys")},
		{Key: "Scanned Objs", Val: mongoRate(dm, "scanned_objects")},
		{Key: "Coll Scans", Val: mongoRate(dm, "collection_scans")},
		{Key: "Open Cursors", Val: dm["cursor_open"]},
		{Key: "Killed(disc)", Val: mongoRate(dm, "killed_disconnect")},
	}
	mongoRenderDualCol(&sb, lCol, rCol, iw, halfW, lw)
	sb.WriteString(boxBot(iw) + "\n")

	// ── LOCKS + REPLICATION (side by side) ─────────────────────────────
	sb.WriteString("  " + titleStyle.Render("LOCKS") + strings.Repeat(" ", halfW-6) + titleStyle.Render("REPLICATION") + "\n")
	sb.WriteString(boxTop(iw) + "\n")
	lCol = []kv{
		{Key: "Queue Total", Val: dm["lock_queue_total"]},
		{Key: "Queue Readers", Val: dm["lock_queue_readers"]},
		{Key: "Queue Writers", Val: dm["lock_queue_writers"]},
		{Key: "Active Ops", Val: dm["current_ops_active"]},
		{Key: "Total Ops", Val: dm["current_ops_total"]},
	}
	rCol = []kv{
		{Key: "Set Name", Val: dm["repl_set"]},
		{Key: "State", Val: dm["repl_state"]},
		{Key: "Members", Val: dm["repl_members"]},
		{Key: "Lag (sec)", Val: dm["repl_lag_sec"]},
	}
	mongoRenderDualCol(&sb, lCol, rCol, iw, halfW, lw)
	sb.WriteString(boxBot(iw) + "\n")

	// ── SLOW QUERIES ──────────────────────────────────────────────────
	if sqJSON := dm["slow_queries"]; sqJSON != "" {
		type slowQ struct {
			Op     string `json:"op"`
			NS     string `json:"ns"`
			Secs   int    `json:"secs"`
			Client string `json:"client"`
			Plan   string `json:"plan"`
			Cmd    string `json:"cmd"`
		}
		var queries []slowQ
		if err := json.Unmarshal([]byte(sqJSON), &queries); err == nil && len(queries) > 0 {
			sb.WriteString("  " + titleStyle.Render(fmt.Sprintf("SLOW QUERIES (%d active >5s)", len(queries))) + "\n")
			sb.WriteString(boxTop(iw) + "\n")
			for i, q := range queries {
				// Header line: duration, operation, namespace, client
				durStyle := warnStyle
				if q.Secs > 30 {
					durStyle = critStyle
				}
				header := fmt.Sprintf("  %s %s %s %s %s",
					durStyle.Render(fmt.Sprintf("[%ds]", q.Secs)),
					dimStyle.Render("op=")+valueStyle.Render(q.Op),
					dimStyle.Render("ns=")+valueStyle.Render(q.NS),
					dimStyle.Render("client=")+valueStyle.Render(q.Client),
					"")
				sb.WriteString(boxRow(header, iw) + "\n")

				// Plan summary — this tells WHY it's slow
				if q.Plan != "" {
					planLine := fmt.Sprintf("    %s %s", dimStyle.Render("plan:"), "")
					if q.Plan == "COLLSCAN" {
						planLine = fmt.Sprintf("    %s %s",
							dimStyle.Render("plan:"),
							critStyle.Render("COLLSCAN")+" "+dimStyle.Render("← MISSING INDEX, full collection scan"))
					} else if strings.HasPrefix(q.Plan, "IXSCAN") {
						planLine = fmt.Sprintf("    %s %s",
							dimStyle.Render("plan:"),
							okStyle.Render(q.Plan))
					} else {
						planLine = fmt.Sprintf("    %s %s",
							dimStyle.Render("plan:"),
							valueStyle.Render(q.Plan))
					}
					sb.WriteString(boxRow(planLine, iw) + "\n")
				}

				// Command snippet
				if q.Cmd != "" {
					cmd := q.Cmd
					maxCmdW := iw - 12
					if len(cmd) > maxCmdW {
						cmd = cmd[:maxCmdW-3] + "..."
					}
					cmdLine := fmt.Sprintf("    %s %s", dimStyle.Render("cmd:"), dimStyle.Render(cmd))
					sb.WriteString(boxRow(cmdLine, iw) + "\n")
				}

				if i < len(queries)-1 {
					sb.WriteString(boxMid(iw) + "\n")
				}
			}
			sb.WriteString(boxBot(iw) + "\n")
		}
	}

	// ── SECURITY & CONFIG AUDIT ────────────────────────────────────────
	sb.WriteString("  " + titleStyle.Render("SECURITY & CONFIGURATION AUDIT") + "\n")
	sb.WriteString(boxTop(iw) + "\n")
	auditLW := 28
	type auditRow struct{ check, value, status, note string }
	audits := []auditRow{}

	// Auth
	authVal := dm["auth_enabled"]
	if authVal == "" {
		authVal = "unknown"
	}
	{
		st, note := "OK", "authentication enforced"
		if authVal == "disabled" || authVal == "unknown" {
			st, note = "CRIT", "ENABLE authorization in mongod.conf"
		}
		audits = append(audits, auditRow{"Authorization", authVal, st, note})
	}

	// Bind IP
	bindIP := dm["bind_ip"]
	if bindIP == "" {
		bindIP = "default"
	}
	{
		st, note := "OK", ""
		if bindIP == "0.0.0.0" || bindIP == "default" {
			st, note = "WARN", "restrict to specific IPs"
		}
		audits = append(audits, auditRow{"Bind IP", bindIP, st, note})
	}

	// TLS
	tlsMode := dm["tls_mode"]
	if tlsMode == "" {
		tlsMode = "disabled"
	}
	{
		st, note := "OK", "encrypted connections"
		if tlsMode == "disabled" || tlsMode == "" {
			st, note = "WARN", "enable TLS for production"
		}
		audits = append(audits, auditRow{"TLS/SSL", tlsMode, st, note})
	}

	// Max connections config
	if maxC := dm["max_connections"]; maxC != "" {
		mc, _ := strconv.Atoi(maxC)
		st, note := "OK", ""
		if mc > 50000 {
			st, note = "WARN", "very high limit — may cause resource exhaustion"
		} else if mc == 0 {
			st, note = "WARN", "no limit set"
		}
		audits = append(audits, auditRow{"Max Connections", maxC, st, note})
	}

	// Cache size config
	if cs := dm["wt_cache_size_gb"]; cs != "" {
		audits = append(audits, auditRow{"Cache Size", cs + " GB", "OK", "explicitly configured"})
	} else {
		audits = append(audits, auditRow{"Cache Size", "auto", "OK", "default: 50% RAM - 1GB"})
	}

	// Journal
	if j := dm["journal_enabled"]; j != "" {
		st := "OK"
		note := "crash recovery enabled"
		if j != "true" && j != "enabled" {
			st, note = "CRIT", "ENABLE journaling for durability"
		}
		audits = append(audits, auditRow{"Journaling", j, st, note})
	}

	for _, a := range audits {
		badge := okStyle.Render(" OK ")
		if a.status == "WARN" {
			badge = warnStyle.Render("WARN")
		} else if a.status == "CRIT" {
			badge = critStyle.Render("CRIT")
		}
		noteStr := ""
		if a.note != "" {
			noteStr = dimStyle.Render(a.note)
		}
		row := fmt.Sprintf("  %s %s %s %s",
			styledPad(dimStyle.Render(a.check+":"), auditLW),
			styledPad(valueStyle.Render(a.value), 16),
			styledPad(badge, 6),
			noteStr)
		sb.WriteString(boxRow(row, iw) + "\n")
	}
	sb.WriteString(boxBot(iw) + "\n")

	// ── INDEX ANALYSIS (per-collection) ───────────────────────────────
	indexRecs := mongoIndexAnalysis(dm)
	if len(indexRecs) > 0 {
		sb.WriteString("  " + titleStyle.Render(fmt.Sprintf("INDEX ANALYSIS (%d issues found)", len(indexRecs))) + "\n")
		sb.WriteString(boxTop(iw) + "\n")
		for i, rec := range indexRecs {
			if i > 0 {
				sb.WriteString(boxMid(iw) + "\n")
			}
			badge := warnStyle.Render("WARN")
			if rec.severity == "CRIT" {
				badge = critStyle.Render("CRIT")
			}
			// Collection name + badge
			sb.WriteString(boxRow(fmt.Sprintf("  %s  %s", badge, critStyle.Render(rec.collection)), iw) + "\n")
			// Problem — plain English
			sb.WriteString(boxRow(fmt.Sprintf("  %s %s", dimStyle.Render("Problem:"), rec.problem), iw) + "\n")
			// Impact — quantified
			if rec.impact != "" {
				sb.WriteString(boxRow(fmt.Sprintf("  %s  %s", dimStyle.Render("Impact:"), warnStyle.Render(rec.impact)), iw) + "\n")
			}
			// Sibling reference
			if rec.sibling != "" {
				sb.WriteString(boxRow(fmt.Sprintf("  %s     %s", dimStyle.Render("Note:"), dimStyle.Render(rec.sibling)), iw) + "\n")
			}
			// Fix command
			if rec.fix != "" {
				sb.WriteString(boxRow(fmt.Sprintf("  %s     %s", dimStyle.Render("Fix:"), valueStyle.Render(rec.fix)), iw) + "\n")
			}
			// Safety note
			if rec.fixNote != "" {
				sb.WriteString(boxRow(fmt.Sprintf("           %s", okStyle.Render(rec.fixNote)), iw) + "\n")
			}
		}
		sb.WriteString(boxBot(iw) + "\n")
	}

	// ── CLIENT CONNECTIONS ────────────────────────────────────────────
	if clientJSON := dm["client_connections"]; clientJSON != "" {
		type clientEntry struct {
			IP    string `json:"ip"`
			Count int    `json:"count"`
		}
		var clients []clientEntry
		if err := json.Unmarshal([]byte(clientJSON), &clients); err == nil && len(clients) > 0 {
			totalConns := 0
			for _, c := range clients {
				totalConns += c.Count
			}
			sb.WriteString("  " + titleStyle.Render(fmt.Sprintf("CLIENT CONNECTIONS (%d total, %d sources)", totalConns, len(clients))) + "\n")
			sb.WriteString(boxTop(iw) + "\n")
			cIP, cCnt, cPct := 20, 8, 8
			hdr := fmt.Sprintf("  %s%s%s%s",
				styledPad(dimStyle.Render("Client IP"), cIP),
				styledPad(dimStyle.Render("Conns"), cCnt),
				styledPad(dimStyle.Render("Share"), cPct),
				dimStyle.Render("Status"))
			sb.WriteString(boxRow(hdr, iw) + "\n")
			sb.WriteString(boxMid(iw) + "\n")
			for _, c := range clients {
				pct := float64(c.Count) / float64(totalConns) * 100
				status := okStyle.Render(" OK ")
				note := ""
				if c.Count > 200 {
					status = critStyle.Render("CRIT")
					note = dimStyle.Render("excessive — reduce maxPoolSize")
				} else if c.Count > 100 {
					status = warnStyle.Render("WARN")
					note = dimStyle.Render("high — review pool settings")
				}
				row := fmt.Sprintf("  %s%s%s%s %s",
					styledPad(valueStyle.Render(c.IP), cIP),
					styledPad(valueStyle.Render(fmt.Sprintf("%d", c.Count)), cCnt),
					styledPad(valueStyle.Render(fmt.Sprintf("%.0f%%", pct)), cPct),
					status, note)
				sb.WriteString(boxRow(row, iw) + "\n")
			}
			sb.WriteString(boxBot(iw) + "\n")
		}
	}

	// ── OPERATION TYPE BREAKDOWN ──────────────────────────────────────
	if opJSON := dm["op_type_breakdown"]; opJSON != "" {
		type opEntry struct {
			Op    string `json:"op"`
			Count int    `json:"count"`
		}
		var ops []opEntry
		if err := json.Unmarshal([]byte(opJSON), &ops); err == nil && len(ops) > 0 {
			// Sort by count desc
			sort.Slice(ops, func(i, j int) bool { return ops[i].Count > ops[j].Count })
			totalOps := 0
			for _, o := range ops {
				totalOps += o.Count
			}
			sb.WriteString("  " + titleStyle.Render("OPERATION BREAKDOWN (currentOp)") + "\n")
			sb.WriteString(boxTop(iw) + "\n")
			for _, o := range ops {
				pct := float64(o.Count) / float64(totalOps) * 100
				label := o.Op
				note := ""
				if o.Op == "hello" {
					note = dimStyle.Render(" ← driver heartbeats (normal, but high count = too many connections)")
				} else if o.Op == "none" {
					note = dimStyle.Render(" ← idle connections waiting for work")
				}
				bar := strings.Repeat("█", int(pct/3))
				row := fmt.Sprintf("  %s %s %s%s",
					styledPad(valueStyle.Render(label), 12),
					styledPad(valueStyle.Render(fmt.Sprintf("%d (%.0f%%)", o.Count, pct)), 16),
					dimStyle.Render(bar), note)
				sb.WriteString(boxRow(row, iw) + "\n")
			}
			sb.WriteString(boxBot(iw) + "\n")
		}
	}

	// ── OPTIMIZATION RECOMMENDATIONS ───────────────────────────────────
	recs := mongoOptimizationRecs(dm)
	if len(recs) > 0 {
		sb.WriteString("  " + titleStyle.Render("OPTIMIZATION RECOMMENDATIONS") + "\n")
		sb.WriteString(boxTop(iw) + "\n")
		for _, rec := range recs {
			badge := warnStyle.Render("▸")
			if rec.severity == "CRIT" {
				badge = critStyle.Render("▸")
			}
			line := fmt.Sprintf("  %s %s", badge, valueStyle.Render(rec.text))
			sb.WriteString(boxRow(line, iw) + "\n")
		}
		sb.WriteString(boxBot(iw) + "\n")
	}

	return sb.String()
}

// renderMongoDBCollections renders the DATABASES & COLLECTIONS section.
func renderMongoDBCollections(dm map[string]string, iw int) string {
	var sb strings.Builder
	dbList := dm["db_list"]
	if dbList == "" {
		return ""
	}
	sb.WriteString("  " + titleStyle.Render("DATABASES & COLLECTIONS") + "\n")

	type collInfo struct {
		Name     string   `json:"name"`
		SizeMB   float64  `json:"size_mb"`
		Docs     int64    `json:"docs"`
		Indexes  int      `json:"indexes"`
		IdxNames []string `json:"idx_names"`
		AvgObj   int      `json:"avg_obj"`
		ROps     int64    `json:"r_ops"`
		RAvgUs   int64    `json:"r_avg_us"`
		WOps     int64    `json:"w_ops"`
		WAvgUs   int64    `json:"w_avg_us"`
		COps     int64    `json:"c_ops"`
		CAvgUs   int64    `json:"c_avg_us"`
		ROpsRate float64  `json:"r_ops_rate"`
		WOpsRate float64  `json:"w_ops_rate"`
	}
	type dbInfo struct {
		Name        string     `json:"name"`
		SizeMB      float64    `json:"size_mb"`
		Collections int        `json:"collections"`
		Indexes     int        `json:"indexes"`
		Colls       []collInfo `json:"colls"`
	}
	var dbs []dbInfo
	if err := json.Unmarshal([]byte(dbList), &dbs); err == nil {
		for _, d := range dbs {
			if (d.Name == "admin" || d.Name == "config" || d.Name == "local") && d.SizeMB < 1 {
				continue
			}
			dbSize := fmt.Sprintf("%.1fMB", d.SizeMB)
			if d.SizeMB >= 1024 {
				dbSize = fmt.Sprintf("%.1fGB", d.SizeMB/1024)
			}
			// Sum DB-level ops and rates
			var dbReads, dbWrites int64
			var dbReadRate, dbWriteRate float64
			for _, c := range d.Colls {
				dbReads += c.ROps
				dbWrites += c.WOps
				dbReadRate += c.ROpsRate
				dbWriteRate += c.WOpsRate
			}
			sb.WriteString(boxTop(iw) + "\n")
			readsVal := mongoFmtRateShort(dbReadRate)
			writesVal := mongoFmtRateShort(dbWriteRate)
			dbTitle := fmt.Sprintf("  %s  %s  %s  %s  %s  %s",
				titleStyle.Render(d.Name),
				dimStyle.Render("Size:")+valueStyle.Render(dbSize),
				dimStyle.Render("Colls:")+valueStyle.Render(fmt.Sprintf("%d", d.Collections)),
				dimStyle.Render("Idx:")+valueStyle.Render(fmt.Sprintf("%d", d.Indexes)),
				dimStyle.Render("Rd/s:")+valueStyle.Render(readsVal),
				dimStyle.Render("Wr/s:")+valueStyle.Render(writesVal))
			sb.WriteString(boxRow(dbTitle, iw) + "\n")

			if len(d.Colls) > 0 {
				sb.WriteString(boxMid(iw) + "\n")
				cN, cSz, cDoc, cRd, cWr, cRL, cWL, cSt := 34, 8, 10, 10, 10, 8, 8, 6
				cReason := iw - cN - cSz - cDoc - cRd - cWr - cRL - cWL - cSt - 8
				if cReason < 10 {
					cReason = 10
				}
				collHdr := fmt.Sprintf("  %s%s%s%s%s%s%s%s%s",
					styledPad(dimStyle.Render("Collection"), cN),
					styledPad(dimStyle.Render("Size"), cSz),
					styledPad(dimStyle.Render("Docs"), cDoc),
					styledPad(dimStyle.Render("Rd/s"), cRd),
					styledPad(dimStyle.Render("Wr/s"), cWr),
					styledPad(dimStyle.Render("R.Avg"), cRL),
					styledPad(dimStyle.Render("W.Avg"), cWL),
					styledPad(dimStyle.Render("Status"), cSt),
					dimStyle.Render("Reason"))
				sb.WriteString(boxRow(collHdr, iw) + "\n")

				for _, c := range d.Colls {
					collSize := mongoFmtSizeMB(c.SizeMB)
					docStr := mongoFmtCount(c.Docs)
					rdStr := mongoFmtRateShort(c.ROpsRate)
					wrStr := mongoFmtRateShort(c.WOpsRate)
					rLatStr := mongoFmtLatency(c.RAvgUs)
					wLatStr := mongoFmtLatency(c.WAvgUs)

					// Determine health + reason + color problem values
					status := "OK"
					reason := ""
					rLatStyled := valueStyle.Render(rLatStr)
					wLatStyled := valueStyle.Render(wLatStr)
					rdStyled := valueStyle.Render(rdStr)
					wrStyled := valueStyle.Render(wrStr)

					// Thresholds: R.Avg normal <1ms, warn >10ms, crit >50ms
					//             W.Avg normal <5ms, warn >10ms, crit >50ms
					if c.WAvgUs > 50000 {
						status = "CRIT"
						reason = fmt.Sprintf("W.Avg %s (>50ms)", wLatStr)
						wLatStyled = critStyle.Render(wLatStr)
					} else if c.RAvgUs > 50000 {
						status = "CRIT"
						reason = fmt.Sprintf("R.Avg %s (>50ms)", rLatStr)
						rLatStyled = critStyle.Render(rLatStr)
					} else if c.WAvgUs > 10000 {
						status = "WARN"
						reason = fmt.Sprintf("W.Avg %s (>10ms)", wLatStr)
						wLatStyled = warnStyle.Render(wLatStr)
					} else if c.RAvgUs > 10000 {
						status = "WARN"
						reason = fmt.Sprintf("R.Avg %s (>10ms)", rLatStr)
						rLatStyled = warnStyle.Render(rLatStr)
					}
					if c.Indexes < 2 && c.Docs > 100000 && c.ROps > 1000 {
						if status == "OK" {
							status = "WARN"
						}
						reason = fmt.Sprintf("only _id index, %s docs", mongoFmtCount(c.Docs))
					}
					// High read rate on large collection
					if c.ROpsRate > 10000 && c.Docs > 1000000 {
						if status == "OK" {
							status = "WARN"
						}
						if reason == "" {
							reason = fmt.Sprintf("%s rd/s on %s docs", rdStr, mongoFmtCount(c.Docs))
						}
						rdStyled = warnStyle.Render(rdStr)
					}

					badge := okStyle.Render(" OK ")
					reasonStyled := ""
					if status == "WARN" {
						badge = warnStyle.Render("WARN")
						reasonStyled = warnStyle.Render(reason)
					} else if status == "CRIT" {
						badge = critStyle.Render("CRIT")
						reasonStyled = critStyle.Render(reason)
					}

					name := c.Name
					if len(name) > cN-2 {
						name = name[:cN-5] + "..."
					}
					row := fmt.Sprintf("  %s%s%s%s%s%s%s%s%s",
						styledPad(valueStyle.Render(name), cN),
						styledPad(valueStyle.Render(collSize), cSz),
						styledPad(valueStyle.Render(docStr), cDoc),
						styledPad(rdStyled, cRd),
						styledPad(wrStyled, cWr),
						styledPad(rLatStyled, cRL),
						styledPad(wLatStyled, cWL),
						styledPad(badge, cSt),
						reasonStyled)
					sb.WriteString(boxRow(row, iw) + "\n")
				}
			}
			sb.WriteString(boxBot(iw) + "\n")
		}
	}
	if totalMB := dm["total_size_mb"]; totalMB != "" {
		t, _ := strconv.ParseFloat(totalMB, 64)
		totalStr := mongoFmtSizeMB(t)
		sb.WriteString(fmt.Sprintf("  %s %s (%s databases)\n",
			dimStyle.Render("Total Storage:"),
			valueStyle.Render(totalStr),
			dm["db_count"]))
	}
	return sb.String()
}

// mongoRenderDualCol renders two kv columns side by side in a box (no top/bot).
func mongoRenderDualCol(sb *strings.Builder, lCol, rCol []kv, iw, halfW, lw int) {
	maxR := len(lCol)
	if len(rCol) > maxR {
		maxR = len(rCol)
	}
	for i := 0; i < maxR; i++ {
		var left, right string
		if i < len(lCol) && lCol[i].Val != "" {
			left = fmt.Sprintf("%s %s",
				styledPad(dimStyle.Render(lCol[i].Key+":"), lw),
				valueStyle.Render(lCol[i].Val))
		}
		if i < len(rCol) && rCol[i].Val != "" {
			right = fmt.Sprintf("%s %s",
				styledPad(dimStyle.Render(rCol[i].Key+":"), lw),
				valueStyle.Render(rCol[i].Val))
		}
		row := fmt.Sprintf("  %s%s", styledPad(left, halfW), right)
		sb.WriteString(boxRow(row, iw) + "\n")
	}
}

// mongoFmtTicket formats available/used ticket pair.
func mongoFmtTicket(avail, used string) string {
	if avail == "" && used == "" {
		return ""
	}
	if avail == "" {
		avail = "—"
	}
	if used == "" {
		used = "—"
	}
	return avail + " / " + used
}

// mongoFmtBytes formats byte count to human readable.
func mongoFmtBytes(s string) string {
	if s == "" {
		return ""
	}
	b, _ := strconv.ParseFloat(s, 64)
	switch {
	case b >= 1e12:
		return fmt.Sprintf("%.1fTB", b/1e12)
	case b >= 1e9:
		return fmt.Sprintf("%.1fGB", b/1e9)
	case b >= 1e6:
		return fmt.Sprintf("%.1fMB", b/1e6)
	case b >= 1e3:
		return fmt.Sprintf("%.1fKB", b/1e3)
	default:
		return fmt.Sprintf("%.0fB", b)
	}
}

// mongoFmtSizeMB formats MB to human readable.
func mongoFmtSizeMB(mb float64) string {
	if mb >= 1024 {
		return fmt.Sprintf("%.1fGB", mb/1024)
	}
	return fmt.Sprintf("%.1fMB", mb)
}

// mongoFmtCount formats large numbers with K/M suffix.
func mongoFmtCount(n int64) string {
	if n >= 1000000000 {
		return fmt.Sprintf("%.1fB", float64(n)/1e9)
	}
	if n >= 1000000 {
		return fmt.Sprintf("%.1fM", float64(n)/1e6)
	}
	if n >= 1000 {
		return fmt.Sprintf("%.1fK", float64(n)/1e3)
	}
	return fmt.Sprintf("%d", n)
}

// mongoFmtOps formats operation count with K/M suffix.
func mongoFmtOps(n int64) string {
	if n == 0 {
		return "0"
	}
	return mongoFmtCount(n)
}

// mongoFmtRateShort formats a rate value compactly for inline display.
func mongoFmtRateShort(r float64) string {
	switch {
	case r >= 1e9:
		return fmt.Sprintf("%.0fB/s", r/1e9)
	case r >= 1e6:
		return fmt.Sprintf("%.0fM/s", r/1e6)
	case r >= 1e3:
		return fmt.Sprintf("%.1fK/s", r/1e3)
	case r >= 1:
		return fmt.Sprintf("%.0f/s", r)
	case r > 0:
		return fmt.Sprintf("%.1f/s", r)
	default:
		return "0"
	}
}

// mongoFmtLatency formats microseconds to human readable.
func mongoFmtLatency(us int64) string {
	if us == 0 {
		return "—"
	}
	if us >= 1000000 {
		return fmt.Sprintf("%.1fs", float64(us)/1e6)
	}
	if us >= 1000 {
		return fmt.Sprintf("%.1fms", float64(us)/1e3)
	}
	return fmt.Sprintf("%dµs", us)
}

// mongoParseI64 parses a string to int64, returns 0 on error.
func mongoParseI64(s string) int64 {
	if s == "" {
		return 0
	}
	v, _ := strconv.ParseInt(s, 10, 64)
	return v
}

type mongoRec struct {
	severity string
	text     string
}

type mongoIndexRec struct {
	severity   string
	collection string // "DB.Collection"
	problem    string // plain English explanation
	impact     string // quantified impact
	fix        string // createIndex() command
	fixNote    string // safety note
	sibling    string // sibling that has the index (if applicable)
}

// mongoIndexAnalysis examines per-collection index data and generates
// specific recommendations with clear problem/impact/fix explanations.
func mongoIndexAnalysis(dm map[string]string) []mongoIndexRec {
	dbList := dm["db_list"]
	if dbList == "" {
		return nil
	}

	type collInfo struct {
		Name     string   `json:"name"`
		SizeMB   float64  `json:"size_mb"`
		Docs     int64    `json:"docs"`
		Indexes  int      `json:"indexes"`
		IdxNames []string `json:"idx_names"`
		ROps     int64    `json:"r_ops"`
		RAvgUs   int64    `json:"r_avg_us"`
		WOps     int64    `json:"w_ops"`
		WAvgUs   int64    `json:"w_avg_us"`
		ROpsRate float64  `json:"r_ops_rate"`
	}
	type dbInfo struct {
		Name  string     `json:"name"`
		Colls []collInfo `json:"colls"`
	}

	var dbs []dbInfo
	if err := json.Unmarshal([]byte(dbList), &dbs); err != nil {
		return nil
	}

	var recs []mongoIndexRec

	for _, d := range dbs {
		if d.Name == "admin" || d.Name == "config" || d.Name == "local" {
			continue
		}

		// Build index map across sibling collections
		siblingIndexes := make(map[string]map[string]bool)
		for _, c := range d.Colls {
			idxSet := make(map[string]bool)
			for _, idx := range c.IdxNames {
				if idx != "_id_" {
					idxSet[idx] = true
				}
			}
			siblingIndexes[c.Name] = idxSet
		}

		for _, c := range d.Colls {
			ns := d.Name + "." + c.Name

			// 1. Large collection with only _id index and significant reads
			if c.Indexes < 2 && c.Docs > 50000 && c.ROps > 100 {
				sev := "WARN"
				if c.ROpsRate > 1000 || c.Docs > 1000000 {
					sev = "CRIT"
				}

				// Find missing indexes from siblings
				var missingIdxs []string
				var siblingName string
				for sibName, sibIdx := range siblingIndexes {
					if sibName == c.Name || !mongoAreSiblings(c.Name, sibName) {
						continue
					}
					for idx := range sibIdx {
						if !siblingIndexes[c.Name][idx] {
							missingIdxs = append(missingIdxs, strings.TrimSuffix(idx, "_1"))
							siblingName = sibName
						}
					}
				}

				docStr := mongoFmtCount(c.Docs)
				if len(missingIdxs) > 0 {
					// Missing sibling index — most actionable finding
					for _, idx := range missingIdxs {
						recs = append(recs, mongoIndexRec{
							severity:   sev,
							collection: ns,
							problem: fmt.Sprintf("No %s index — every query on %s scans all %s documents (full table scan)",
								idx, idx, docStr),
							impact: fmt.Sprintf("Each %s lookup takes ~%.0fms instead of <1ms, wasting CPU on %s reads",
								idx, float64(c.Docs)/500000.0*100, mongoFmtCount(c.ROps)),
							sibling: fmt.Sprintf("Sibling \"%s\" has this index — this collection was likely created without it",
								siblingName),
							fix: fmt.Sprintf("db.getSiblingDB(\"%s\").%s.createIndex({%s: 1})",
								d.Name, c.Name, idx),
							fixNote: "Safe to run in production — builds in background, no downtime",
						})
					}
				} else {
					// No sibling reference, generic "only _id" warning
					recs = append(recs, mongoIndexRec{
						severity:   sev,
						collection: ns,
						problem: fmt.Sprintf("Only _id index on %s docs — any query not using _id scans the entire collection",
							docStr),
						impact: fmt.Sprintf("Full collection scans cause high CPU and slow responses (%s total reads)",
							mongoFmtCount(c.ROps)),
						fix: "Enable profiling to find which fields need indexes: db.setProfilingLevel(1, {slowms: 50})",
						fixNote: "Then check db.system.profile for COLLSCAN queries to identify needed indexes",
					})
				}
			}

			// 2. High read latency with few indexes
			if c.RAvgUs > 5000 && c.Indexes < 3 && c.ROps > 1000 {
				recs = append(recs, mongoIndexRec{
					severity:   "WARN",
					collection: ns,
					problem: fmt.Sprintf("Average read takes %s with only %d index — queries may be scanning too many documents",
						mongoFmtLatency(c.RAvgUs), c.Indexes),
					impact: fmt.Sprintf("Slow reads affect application response time across %s operations",
						mongoFmtCount(c.ROps)),
					fix: fmt.Sprintf("db.getSiblingDB(\"%s\").setProfilingLevel(1, {slowms: 50})",
						d.Name),
					fixNote: "Check db.system.profile to find slow query patterns, then create targeted indexes",
				})
			}

			// 3. Write latency high (only when writes are actually happening)
			if c.WAvgUs > 50000 && c.WOps > 100 {
				recs = append(recs, mongoIndexRec{
					severity:   "CRIT",
					collection: ns,
					problem: fmt.Sprintf("Write operations averaging %s — significantly slower than normal (<10ms)",
						mongoFmtLatency(c.WAvgUs)),
					impact: fmt.Sprintf("Slow writes cause application timeouts and connection pile-ups (%d indexes to update per write)",
						c.Indexes),
					fix: "Check disk I/O with xtop IO page. If indexes > 5, review if all are needed",
					fixNote: "Too many indexes slow every write — each insert/update must update all indexes",
				})
			}
		}
	}

	return recs
}

// mongoAreSiblings checks if two collection names are variants of each other
// (e.g., "Foo" and "Foo_New", "Foo_DAG2" and "Foo_DAG2_New").
func mongoAreSiblings(a, b string) bool {
	if strings.HasSuffix(a, "_New") && strings.TrimSuffix(a, "_New") == b {
		return true
	}
	if strings.HasSuffix(b, "_New") && strings.TrimSuffix(b, "_New") == a {
		return true
	}
	// Also check base name match (strip _New, _DAG2, etc.)
	baseA := a
	baseB := b
	for _, suf := range []string{"_New", "_DAG2_New", "_DAG2"} {
		baseA = strings.TrimSuffix(baseA, suf)
		baseB = strings.TrimSuffix(baseB, suf)
	}
	return baseA == baseB && a != b
}

// mongoOptimizationRecs generates optimization recommendations from metrics.
func mongoOptimizationRecs(dm map[string]string) []mongoRec {
	var recs []mongoRec

	// Cache pressure
	if v := dm["cache_usage_pct"]; v != "" {
		pct, _ := strconv.ParseFloat(v, 64)
		if pct > 95 {
			recs = append(recs, mongoRec{"CRIT", "WT cache critically full — increase storage.wiredTiger.engineConfig.cacheSizeGB"})
		} else if pct > 85 {
			recs = append(recs, mongoRec{"WARN", "WT cache > 85% — consider increasing cacheSizeGB or reducing working set"})
		}
	}

	// Connection pool
	connCur, _ := strconv.Atoi(dm["conn_current"])
	if connCur > 5000 {
		recs = append(recs, mongoRec{"CRIT", fmt.Sprintf("%d connections — implement connection pooling (maxPoolSize in driver)", connCur)})
	} else if connCur > 1000 {
		recs = append(recs, mongoRec{"WARN", fmt.Sprintf("%d connections — consider connection pooling", connCur)})
	}

	// Lock contention
	lockQ, _ := strconv.Atoi(dm["lock_queue_total"])
	if lockQ > 10 {
		recs = append(recs, mongoRec{"CRIT", "Heavy lock contention — review slow queries with db.currentOp(), add missing indexes"})
	}

	// Slow ops
	slowOps, _ := strconv.Atoi(dm["slow_ops"])
	if slowOps > 5 {
		recs = append(recs, mongoRec{"CRIT", fmt.Sprintf("%d slow operations (>5s) — run db.setProfilingLevel(1) and check system.profile", slowOps)})
	} else if slowOps > 0 {
		recs = append(recs, mongoRec{"WARN", "Slow operations detected — check query plans with .explain()"})
	}

	// WT tickets
	readAvail, _ := strconv.Atoi(dm["wt_read_avail"])
	writeAvail, _ := strconv.Atoi(dm["wt_write_avail"])
	if readAvail > 0 && readAvail < 20 {
		recs = append(recs, mongoRec{"WARN", "Read tickets low — increase wiredTigerConcurrentReadTransactions or reduce load"})
	}
	if writeAvail > 0 && writeAvail < 20 {
		recs = append(recs, mongoRec{"WARN", "Write tickets low — increase wiredTigerConcurrentWriteTransactions or reduce write load"})
	}

	// Security
	if dm["auth_enabled"] == "disabled" {
		recs = append(recs, mongoRec{"CRIT", "Authentication DISABLED — set security.authorization: enabled in mongod.conf"})
	}
	if dm["tls_mode"] == "disabled" || dm["tls_mode"] == "" {
		recs = append(recs, mongoRec{"WARN", "TLS disabled — enable net.tls.mode: requireTLS for encrypted connections"})
	}
	if dm["bind_ip"] == "0.0.0.0" {
		recs = append(recs, mongoRec{"WARN", "Bound to all interfaces — restrict net.bindIp to specific addresses"})
	}

	// Replication
	if lagStr := dm["repl_lag_sec"]; lagStr != "" && lagStr != "0" {
		lag, _ := strconv.Atoi(lagStr)
		if lag > 60 {
			recs = append(recs, mongoRec{"CRIT", fmt.Sprintf("Replication lag %ds — increase oplog size (replSetResizeOplog) or check network", lag)})
		}
	}

	// Cursor timeouts
	curTimeout, _ := strconv.Atoi(dm["cursor_timed_out"])
	if curTimeout > 100 {
		recs = append(recs, mongoRec{"WARN", "High cursor timeouts — use noCursorTimeout cautiously or process batches faster"})
	}

	// Collection scans
	collScans, _ := strconv.Atoi(dm["collection_scans"])
	if collScans > 1000 {
		recs = append(recs, mongoRec{"CRIT", fmt.Sprintf("%d collection scans — create indexes for frequent query patterns", collScans)})
	} else if collScans > 100 {
		recs = append(recs, mongoRec{"WARN", fmt.Sprintf("%d collection scans — review queries without index support", collScans)})
	}

	// Scan efficiency
	scannedObj, _ := strconv.ParseFloat(dm["scanned_objects"], 64)
	docReturned, _ := strconv.ParseFloat(dm["doc_returned"], 64)
	if docReturned > 0 && scannedObj/docReturned > 5 {
		recs = append(recs, mongoRec{"WARN", fmt.Sprintf("Scanning %.0fx more docs than returning — create compound indexes matching query filters", scannedObj/docReturned)})
	}

	// High write latency
	avgWrUs, _ := strconv.Atoi(dm["avg_write_latency_us"])
	if avgWrUs > 50000 {
		recs = append(recs, mongoRec{"CRIT", fmt.Sprintf("Avg write latency %s — check disk I/O, journal, and write concern", mongoFmtLatency(int64(avgWrUs)))})
	} else if avgWrUs > 10000 {
		recs = append(recs, mongoRec{"WARN", fmt.Sprintf("Avg write latency %s — consider write concern w:1 or faster storage", mongoFmtLatency(int64(avgWrUs)))})
	}

	// Client disconnects killing ops
	killedDisc, _ := strconv.Atoi(dm["killed_disconnect"])
	if killedDisc > 10000 {
		recs = append(recs, mongoRec{"WARN", fmt.Sprintf("%s operations killed by client disconnect — increase client timeouts", mongoFmtCount(int64(killedDisc)))})
	}

	// No replication on production
	if dm["repl_set"] == "" && connCur > 100 {
		recs = append(recs, mongoRec{"WARN", "Standalone instance with significant traffic — consider replica set for HA"})
	}

	return recs
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

// ── Docker Detail ──────────────────────────────────────────────────────

func renderDockerDetail(app model.AppInstance, stackCursor int, stackExpanded []bool, containerIdx int, iw int) string {
	var sb strings.Builder
	dm := app.DeepMetrics

	sb.WriteString(appDetailHeader(app))

	// ── Daemon overview (compact 2-column) ───────────────────────────
	leftW := iw/2 - 1
	var left strings.Builder
	left.WriteString(dimStyle.Render("DOCKER DAEMON") + "\n")
	for _, item := range []kv{
		{"Version", appFmtDash(app.Version)},
		{"PID", fmt.Sprintf("%d", app.PID)},
		{"Uptime", fmtUptime(app.UptimeSec)},
		{"Storage", dm["Storage Driver"]},
		{"Cgroup", dm["Cgroup Driver"]},
		{"OS", dm["OS"]},
		{"Kernel", dm["Kernel"]},
	} {
		if item.Val == "" {
			continue
		}
		left.WriteString(fmt.Sprintf(" %-10s %s\n", item.Key+":", valueStyle.Render(item.Val)))
	}
	var right strings.Builder
	running := dm["Running"]
	stopped := dm["Stopped"]
	paused := dm["Paused"]
	right.WriteString(dimStyle.Render("SUMMARY") + "\n")
	right.WriteString(fmt.Sprintf(" Containers: %s  Run: %s  Stop: %s  Pause: %s\n",
		valueStyle.Render(dm["Total Containers"]), okStyle.Render(running),
		dockerColorNonZero(stopped), dockerColorNonZero(paused)))
	right.WriteString(fmt.Sprintf(" Images: %s  Orch: %s\n",
		valueStyle.Render(dm["Images"]),
		dockerOrchBadge(app.OrchestrationType)))
	right.WriteString("\n")
	right.WriteString(dimStyle.Render("DISK") + "\n")
	if dm["images_total_size"] != "" {
		right.WriteString(fmt.Sprintf(" Images: %s", valueStyle.Render(dm["images_total_size"])))
		if dm["images_reclaimable"] != "" {
			right.WriteString(dimStyle.Render(" (rec: " + dm["images_reclaimable"] + ")"))
		}
		right.WriteString("\n")
	}
	if dm["volumes_count"] != "" {
		right.WriteString(fmt.Sprintf(" Volumes: %s (%s)\n",
			valueStyle.Render(dm["volumes_size"]), valueStyle.Render(dm["volumes_count"])))
	}
	if dm["containers_rw_size"] != "" {
		right.WriteString(fmt.Sprintf(" Writable: %s\n", valueStyle.Render(dm["containers_rw_size"])))
	}

	sb.WriteString(boxTop(iw) + "\n")
	combined := joinColumns(left.String(), right.String(), leftW, " \u2502 ")
	for _, line := range strings.Split(combined, "\n") {
		if line != "" {
			sb.WriteString(boxRow(line, iw) + "\n")
		}
	}
	sb.WriteString(boxBot(iw) + "\n")

	// ── Stack sections (collapsible) ─────────────────────────────────
	if len(app.Stacks) > 0 {
		sb.WriteString("\n  " + titleStyle.Render("STACKS") +
			"  " + dimStyle.Render(fmt.Sprintf("(%d stacks, %d containers)",
				len(app.Stacks), len(app.Containers))) + "\n\n")

		for i, stack := range app.Stacks {
			selected := i == stackCursor
			expanded := i < len(stackExpanded) && stackExpanded[i]

			// Stack header: ▶/▼ [badge] name — health — container count
			badge := dockerStackBadge(stack.Type)
			healthBadge := dockerStackHealthBadge(stack.HealthScore)
			summary := fmt.Sprintf("%s %s  %s  %s",
				badge, valueStyle.Render(stack.Name),
				healthBadge,
				dimStyle.Render(fmt.Sprintf("%d containers", len(stack.Containers))))
			if len(stack.Issues) > 0 {
				summary += "  " + warnStyle.Render(fmt.Sprintf("%d issues", len(stack.Issues)))
			}
			sb.WriteString(renderNetSectionHeader("", summary, selected, expanded, iw))

			if !expanded {
				continue
			}

			// Working dir / compose file
			if stack.WorkingDir != "" {
				sb.WriteString(boxTop(iw) + "\n")
				sb.WriteString(boxRow("  "+dimStyle.Render("Dir: ")+valueStyle.Render(stack.WorkingDir), iw) + "\n")
				if stack.ComposeFile != "" {
					sb.WriteString(boxRow("  "+dimStyle.Render("File: ")+valueStyle.Render(stack.ComposeFile), iw) + "\n")
				}
				sb.WriteString(boxMid(iw) + "\n")
			} else {
				sb.WriteString(boxTop(iw) + "\n")
			}

			// Container table
			cName := 20
			cState := 10
			cCPU := 7
			cMem := 9
			cMemPct := 5
			cNetRx := 9
			cNetTx := 9
			cBlkR := 9
			cBlkW := 9
			cRst := 4
			cImage := 24

			hdr := fmt.Sprintf(" %s%s%s%s%s%s%s%s%s%s%s",
				styledPad(dimStyle.Render("Name"), cName),
				styledPad(dimStyle.Render("State"), cState),
				styledPad(dimStyle.Render("CPU%"), cCPU),
				styledPad(dimStyle.Render("Mem"), cMem),
				styledPad(dimStyle.Render("Mem%"), cMemPct),
				styledPad(dimStyle.Render("Net RX"), cNetRx),
				styledPad(dimStyle.Render("Net TX"), cNetTx),
				styledPad(dimStyle.Render("Blk R"), cBlkR),
				styledPad(dimStyle.Render("Blk W"), cBlkW),
				styledPad(dimStyle.Render("Rst"), cRst),
				styledPad(dimStyle.Render("Image"), cImage))
			sb.WriteString(boxRow(hdr, iw) + "\n")
			sb.WriteString(boxMid(iw) + "\n")

			for _, c := range stack.Containers {
				name := c.Name
				if len(name) > cName-1 {
					name = name[:cName-4] + "..."
				}

				stateStr := dockerContainerStateStr(c)
				cpuStr := "—"
				memStr := "—"
				memPctStr := "—"
				netRx := "—"
				netTx := "—"
				blkR := "—"
				blkW := "—"
				rstStr := "—"

				if c.State == "running" {
					cpuStr = fmt.Sprintf("%.1f%%", c.CPUPct)
					if c.CPUPct > 80 {
						cpuStr = critStyle.Render(cpuStr)
					} else if c.CPUPct > 50 {
						cpuStr = warnStyle.Render(cpuStr)
					}
					memStr = appFmtBytesShort(c.MemUsedBytes)
					if c.MemLimitBytes > 0 && c.MemLimitBytes < 1e18 {
						memPctStr = fmt.Sprintf("%.0f%%", c.MemPct)
						if c.MemPct > 90 {
							memPctStr = critStyle.Render(memPctStr)
						} else if c.MemPct > 75 {
							memPctStr = warnStyle.Render(memPctStr)
						}
					}
					netRx = appFmtBytesShort(c.NetRxBytes)
					netTx = appFmtBytesShort(c.NetTxBytes)
					blkR = appFmtBytesShort(c.BlockRead)
					blkW = appFmtBytesShort(c.BlockWrite)
				}
				if c.RestartCount > 0 {
					rstStr = warnStyle.Render(fmt.Sprintf("%d", c.RestartCount))
				} else {
					rstStr = dimStyle.Render("0")
				}

				imageStr := c.Image
				if len(imageStr) > cImage-1 {
					imageStr = imageStr[:cImage-4] + "..."
				}

				row := fmt.Sprintf(" %s%s%s%s%s%s%s%s%s%s%s",
					styledPad(valueStyle.Render(name), cName),
					styledPad(stateStr, cState),
					styledPad(cpuStr, cCPU),
					styledPad(valueStyle.Render(memStr), cMem),
					styledPad(memPctStr, cMemPct),
					styledPad(valueStyle.Render(netRx), cNetRx),
					styledPad(valueStyle.Render(netTx), cNetTx),
					styledPad(valueStyle.Render(blkR), cBlkR),
					styledPad(valueStyle.Render(blkW), cBlkW),
					styledPad(rstStr, cRst),
					styledPad(dimStyle.Render(imageStr), cImage))
				sb.WriteString(boxRow(row, iw) + "\n")
			}

			// Published ports (compact, deduplicated, show public vs local)
			type portInfo struct {
				host, container int
				isPublic        bool
			}
			portKey := map[string]*portInfo{}
			var portOrder []string
			for _, c := range stack.Containers {
				for _, p := range c.Ports {
					if p.HostPort > 0 {
						key := fmt.Sprintf("%d:%d", p.HostPort, p.ContainerPort)
						if pi, ok := portKey[key]; ok {
							if dockerPortIsPublic(p.HostIP) {
								pi.isPublic = true
							}
						} else {
							portKey[key] = &portInfo{
								host: p.HostPort, container: p.ContainerPort,
								isPublic: dockerPortIsPublic(p.HostIP),
							}
							portOrder = append(portOrder, key)
						}
					}
				}
			}
			if len(portOrder) > 0 {
				sb.WriteString(boxMid(iw) + "\n")
				var portStrs []string
				for _, k := range portOrder {
					pi := portKey[k]
					label := fmt.Sprintf("%d→%d", pi.host, pi.container)
					if pi.isPublic {
						portStrs = append(portStrs, warnStyle.Render(label+" public"))
					} else {
						portStrs = append(portStrs, okStyle.Render(label+" local"))
					}
				}
				sb.WriteString(boxRow("  "+dimStyle.Render("Ports: ")+strings.Join(portStrs, "  "), iw) + "\n")
			}

			// Stack issues (diagnostics only)
			if len(stack.Issues) > 0 {
				sb.WriteString(boxMid(iw) + "\n")
				for _, issue := range stack.Issues {
					sb.WriteString(boxRow("  "+critStyle.Render("\u25cf")+" "+valueStyle.Render(issue), iw) + "\n")
				}
			}

			sb.WriteString(boxBot(iw) + "\n")
		}
	} else if len(app.Containers) > 0 {
		// Fallback: no stacks, just flat container list (shouldn't happen with new collector)
		sb.WriteString(renderDockerFlatContainers(app, iw))
	}

	sb.WriteString(pageFooter("j/k:Scroll  Tab:Section  Enter:Expand  A:All  C:Collapse  b:Back"))
	return sb.String()
}

// dockerContainerStateStr renders the state with health/restart indicators.
func dockerContainerStateStr(c model.AppDockerContainer) string {
	switch c.State {
	case "running":
		if c.Health == "unhealthy" {
			return critStyle.Render("unhealthy")
		} else if c.Health == "healthy" {
			return okStyle.Render("healthy")
		}
		return okStyle.Render("running")
	case "exited":
		if c.ExitCode != 0 {
			return critStyle.Render(fmt.Sprintf("exit:%d", c.ExitCode))
		}
		return dimStyle.Render("exited")
	case "paused":
		return warnStyle.Render("paused")
	default:
		return dimStyle.Render(c.State)
	}
}


// dockerStackBadge returns a colored badge for stack type.
func dockerStackBadge(stype string) string {
	switch stype {
	case "compose":
		return lipgloss.NewStyle().Foreground(lipgloss.Color("14")).Render("[compose]")
	case "swarm":
		return lipgloss.NewStyle().Foreground(lipgloss.Color("13")).Render("[swarm]")
	case "k8s":
		return lipgloss.NewStyle().Foreground(lipgloss.Color("11")).Render("[k8s]")
	default:
		return dimStyle.Render("[standalone]")
	}
}

// dockerStackHealthBadge returns a colored health badge for a stack.
func dockerStackHealthBadge(score int) string {
	if score >= 80 {
		return okStyle.Render(fmt.Sprintf("H:%d", score))
	} else if score >= 50 {
		return warnStyle.Render(fmt.Sprintf("H:%d", score))
	}
	return critStyle.Render(fmt.Sprintf("H:%d", score))
}

// dockerOrchBadge renders the orchestration type.
func dockerOrchBadge(orch string) string {
	switch orch {
	case "compose":
		return lipgloss.NewStyle().Foreground(lipgloss.Color("14")).Render("compose")
	case "swarm":
		return lipgloss.NewStyle().Foreground(lipgloss.Color("13")).Render("swarm")
	case "k8s":
		return lipgloss.NewStyle().Foreground(lipgloss.Color("11")).Render("k8s")
	case "mixed":
		return warnStyle.Render("mixed")
	default:
		return dimStyle.Render("standalone")
	}
}

// dockerColorNonZero colors non-zero values as warnings.
// dockerPortIsPublic returns true if the host IP binding is publicly accessible.
func dockerPortIsPublic(hostIP string) bool {
	return hostIP == "" || hostIP == "0.0.0.0" || hostIP == "::"
}

func dockerColorNonZero(s string) string {
	if s != "" && s != "0" {
		return warnStyle.Render(s)
	}
	return dimStyle.Render(s)
}

// truncStr truncates a string to maxLen with ellipsis.
func truncStr(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	if maxLen < 4 {
		return s[:maxLen]
	}
	return s[:maxLen-3] + "..."
}

// renderDockerFlatContainers is a fallback for when stacks aren't available.
func renderDockerFlatContainers(app model.AppInstance, iw int) string {
	var sb strings.Builder
	sb.WriteString("  " + titleStyle.Render("CONTAINERS") + "\n")
	sb.WriteString(boxTop(iw) + "\n")
	for _, c := range app.Containers {
		name := c.Name
		if len(name) > 30 {
			name = name[:27] + "..."
		}
		stateStr := dockerContainerStateStr(c)
		row := fmt.Sprintf(" %s  %s  CPU:%s  Mem:%s",
			styledPad(valueStyle.Render(name), 30),
			styledPad(stateStr, 10),
			valueStyle.Render(fmt.Sprintf("%.1f%%", c.CPUPct)),
			valueStyle.Render(appFmtBytesShort(c.MemUsedBytes)))
		sb.WriteString(boxRow(row, iw) + "\n")
	}
	sb.WriteString(boxBot(iw) + "\n")
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
