//go:build linux

package ui

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/ftahirops/xtop/model"
)

func renderAppsPage(snap *model.Snapshot, selectedIdx int, detailMode bool,
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

	// MySQL handles its own diagnostics; other apps use generic health issues
	if app.AppType != "mysql" && len(app.HealthIssues) > 0 {
		sb.WriteString("  " + titleStyle.Render("HEALTH ISSUES") + "\n")
		sb.WriteString(boxTop(iw) + "\n")
		for _, issue := range app.HealthIssues {
			row := "  " + critStyle.Render("\u25cf") + " " + valueStyle.Render(issue)
			sb.WriteString(boxRow(row, iw) + "\n")
		}
		sb.WriteString(boxBot(iw) + "\n\n")
	}

	sb.WriteString(pageFooter("k:Back  Y:Apps"))
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

	// Health Status Table
	sb.WriteString("  " + titleStyle.Render("HEALTH STATUS") + "\n")
	sb.WriteString(boxTop(iw) + "\n")

	type healthRow struct {
		metric, value, status string
	}
	rows := []healthRow{}

	// Memory usage
	if dm["memory_usage_pct"] != "" {
		var pct float64
		fmt.Sscanf(dm["memory_usage_pct"], "%f", &pct)
		status := "OK"
		if pct > 90 {
			status = "CRIT"
		} else if pct > 75 {
			status = "WARN"
		}
		rows = append(rows, healthRow{"Memory Usage", dm["used_memory_human"] + " / " + dm["maxmemory_human"] + " (" + dm["memory_usage_pct"] + ")", status})
	} else if dm["maxmemory"] == "0" || dm["maxmemory"] == "" {
		rows = append(rows, healthRow{"Memory Usage", dm["used_memory_human"] + " (no limit)", "OK"})
	}

	// Hit ratio
	if dm["hit_ratio"] != "" {
		var ratio float64
		fmt.Sscanf(dm["hit_ratio"], "%f", &ratio)
		status := "OK"
		if ratio < 80 {
			status = "CRIT"
		} else if ratio < 90 {
			status = "WARN"
		}
		rows = append(rows, healthRow{"Hit Ratio", dm["hit_ratio"], status})
	}

	// Evictions
	evicted := dm["evicted_keys"]
	if evicted != "" {
		status := "OK"
		if evicted != "0" {
			status = "CRIT"
		}
		rows = append(rows, healthRow{"Evicted Keys", evicted, status})
	}

	// Fragmentation
	if dm["mem_fragmentation_ratio"] != "" {
		frag, _ := strconv.ParseFloat(dm["mem_fragmentation_ratio"], 64)
		status := "OK"
		if frag > 1.5 {
			status = "WARN"
		} else if frag < 1.0 && frag > 0 {
			status = "WARN"
		}
		rows = append(rows, healthRow{"Fragmentation Ratio", dm["mem_fragmentation_ratio"], status})
	}

	// Blocked clients
	if dm["blocked_clients"] != "" {
		status := "OK"
		if dm["blocked_clients"] != "0" {
			b, _ := strconv.Atoi(dm["blocked_clients"])
			if b > 10 {
				status = "CRIT"
			} else if b > 0 {
				status = "WARN"
			}
		}
		rows = append(rows, healthRow{"Blocked Clients", dm["blocked_clients"], status})
	}

	// Rejected connections
	if dm["rejected_connections"] != "" && dm["rejected_connections"] != "0" {
		rows = append(rows, healthRow{"Rejected Connections", dm["rejected_connections"], "CRIT"})
	} else {
		rows = append(rows, healthRow{"Rejected Connections", "0", "OK"})
	}

	// RDB save
	if dm["rdb_last_bgsave_status"] != "" {
		status := "OK"
		if dm["rdb_last_bgsave_status"] != "ok" {
			status = "CRIT"
		}
		rows = append(rows, healthRow{"Last RDB Save", dm["rdb_last_bgsave_status"], status})
	}

	// Replication
	if dm["role"] == "slave" {
		status := "OK"
		if dm["master_link_status"] == "down" {
			status = "CRIT"
		}
		rows = append(rows, healthRow{"Replication Link", dm["master_link_status"], status})
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

	// Throughput
	sb.WriteString(appSection("THROUGHPUT", iw, []kv{
		{Key: "Ops/sec", Val: dm["instantaneous_ops_per_sec"]},
		{Key: "Input", Val: redisFmtKbps(dm["instantaneous_input_kbps"])},
		{Key: "Output", Val: redisFmtKbps(dm["instantaneous_output_kbps"])},
		{Key: "Total Commands", Val: redisFmtLargeNum(dm["total_commands_processed"])},
		{Key: "Total Connections", Val: redisFmtLargeNum(dm["total_connections_received"])},
		{Key: "Total Net In", Val: redisFmtNetBytes(dm["total_net_input_bytes"])},
		{Key: "Total Net Out", Val: redisFmtNetBytes(dm["total_net_output_bytes"])},
	}))

	// Clients
	sb.WriteString(appSection("CLIENTS", iw, []kv{
		{Key: "Connected", Val: dm["connected_clients"]},
		{Key: "Blocked", Val: dm["blocked_clients"]},
		{Key: "Max Clients", Val: dm["maxclients"]},
		{Key: "Rejected", Val: dm["rejected_connections"]},
	}))

	// Memory
	sb.WriteString(appSection("MEMORY", iw, []kv{
		{Key: "Used", Val: dm["used_memory_human"]},
		{Key: "Used RSS", Val: dm["used_memory_rss_human"]},
		{Key: "Peak", Val: dm["used_memory_peak_human"]},
		{Key: "Lua", Val: dm["used_memory_lua_human"]},
		{Key: "Dataset %", Val: dm["used_memory_dataset_perc"]},
		{Key: "Max Memory", Val: dm["maxmemory_human"]},
		{Key: "Policy", Val: dm["maxmemory_policy"]},
		{Key: "Fragmentation", Val: dm["mem_fragmentation_ratio"]},
	}))

	// Persistence
	sb.WriteString(appSection("PERSISTENCE", iw, []kv{
		{Key: "RDB Last Save", Val: dm["rdb_last_bgsave_status"]},
		{Key: "RDB Save Time", Val: redisFmtSec(dm["rdb_last_bgsave_time_sec"])},
		{Key: "Changes Since Save", Val: dm["rdb_changes_since_last_save"]},
		{Key: "AOF Enabled", Val: dm["aof_enabled"]},
		{Key: "AOF Rewrite", Val: dm["aof_last_bgrewrite_status"]},
	}))

	// Replication
	sb.WriteString(appSection("REPLICATION", iw, []kv{
		{Key: "Role", Val: dm["role"]},
		{Key: "Connected Slaves", Val: dm["connected_slaves"]},
		{Key: "Master Host", Val: dm["master_host"]},
		{Key: "Master Port", Val: dm["master_port"]},
		{Key: "Master Link", Val: dm["master_link_status"]},
		{Key: "Master Last IO", Val: redisFmtSec(dm["master_last_io_seconds_ago"])},
	}))

	// Keyspace (databases)
	dbKVs := []kv{}
	for i := 0; i <= 15; i++ {
		dbKey := fmt.Sprintf("db%d", i)
		if v, ok := dm[dbKey]; ok {
			// Parse keys=N,expires=N,avg_ttl=N
			parsed := redisParseDB(v)
			dbKVs = append(dbKVs, kv{Key: dbKey, Val: parsed})
		}
	}
	if dm["total_keys"] != "" {
		dbKVs = append(dbKVs, kv{Key: "Total Keys", Val: dm["total_keys"]})
	}
	if dm["total_expires"] != "" {
		dbKVs = append(dbKVs, kv{Key: "Expiring Keys", Val: dm["total_expires"]})
	}
	if len(dbKVs) > 0 {
		sb.WriteString(appSection("KEYSPACE", iw, dbKVs))
	}

	// Stats
	sb.WriteString(appSection("KEYS", iw, []kv{
		{Key: "Keyspace Hits", Val: redisFmtLargeNum(dm["keyspace_hits"])},
		{Key: "Keyspace Misses", Val: redisFmtLargeNum(dm["keyspace_misses"])},
		{Key: "Expired Keys", Val: redisFmtLargeNum(dm["expired_keys"])},
		{Key: "Evicted Keys", Val: dm["evicted_keys"]},
	}))

	// CPU
	sb.WriteString(appSection("CPU", iw, []kv{
		{Key: "System CPU", Val: redisFmtSec(dm["used_cpu_sys"])},
		{Key: "User CPU", Val: redisFmtSec(dm["used_cpu_user"])},
	}))

	return sb.String()
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

		cName, cAddr, cRate, cReqs, cRt, cQt, cCt, cErr, c5, cAbrt, cHp := 20, 18, 7, 9, 8, 6, 6, 7, 7, 9, 9
		hdr := fmt.Sprintf("  %s%s%s%s%s%s%s%s%s%s%s%s",
			styledPad(dimStyle.Render("Backend"), cName),
			styledPad(dimStyle.Render("Endpoint"), cAddr),
			styledPad(dimStyle.Render("Req/s"), cRate),
			styledPad(dimStyle.Render("Reqs"), cReqs),
			styledPad(dimStyle.Render("Resp ms"), cRt),
			styledPad(dimStyle.Render("Qt ms"), cQt),
			styledPad(dimStyle.Render("Ct ms"), cCt),
			styledPad(dimStyle.Render("Err%"), cErr),
			styledPad(dimStyle.Render("5xx"), c5),
			styledPad(dimStyle.Render("Abort c/s"), cAbrt),
			styledPad(dimStyle.Render("Srv"), cHp),
			dimStyle.Render("Health"))
		sb.WriteString(boxRow(hdr, iw) + "\n")
		sb.WriteString(boxMid(iw) + "\n")

		for i := 0; i < beCount; i++ {
			pre := fmt.Sprintf("be_detail_%d_", i)
			name := dm[pre+"name"]
			addr := dm[pre+"addr"]
			rate := dm[pre+"sess_rate"]
			reqTot := dm[pre+"req_total"]
			errPct := dm[pre+"err_pct"]
			h5xx := dm[pre+"5xx"]
			cliA := dm[pre+"cli_abrt"]
			srvA := dm[pre+"srv_abrt"]
			srvUp := dm[pre+"servers_up"]
			srvDown := dm[pre+"servers_down"]
			srvTotal := dm[pre+"servers_total"]
			rtime := dm[pre+"rtime"]
			qtime := dm[pre+"qtime"]
			ctime := dm[pre+"ctime"]
			beHealth := dm[pre+"health"]

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

			// Queue time colored
			qtStr := qtime
			if qt, _ := strconv.Atoi(qtime); qt > 100 {
				qtStr = critStyle.Render(qtime)
			} else if qt > 50 {
				qtStr = warnStyle.Render(qtime)
			}

			// Connect time colored
			ctStr := ctime
			if ct, _ := strconv.Atoi(ctime); ct > 500 {
				ctStr = critStyle.Render(ctime)
			} else if ct > 100 {
				ctStr = warnStyle.Render(ctime)
			}

			row := fmt.Sprintf("  %s%s%s%s%s%s%s%s%s%s%s%s",
				styledPad(valueStyle.Render(name), cName),
				styledPad(dimStyle.Render(addr), cAddr),
				styledPad(valueStyle.Render(rate+"/s"), cRate),
				styledPad(valueStyle.Render(haFmtNum(reqTot)), cReqs),
				styledPad(rtStr, cRt),
				styledPad(qtStr, cQt),
				styledPad(ctStr, cCt),
				styledPad(errStr, cErr),
				styledPad(haColorVal(haFmtNum(h5xx), "5xx"), c5),
				styledPad(valueStyle.Render(abortLine), cAbrt),
				styledPad(valueStyle.Render(srvLine), cHp),
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
		cSN, cSA, cSQ, cSC, cSR := 22, 20, 8, 8, 8
		sb.WriteString(boxRow(fmt.Sprintf("  %s%s%s%s%s%s",
			styledPad(dimStyle.Render("Backend"), cSN),
			styledPad(dimStyle.Render("Endpoint"), cSA),
			styledPad(dimStyle.Render("Q ms"), cSQ),
			styledPad(dimStyle.Render("C ms"), cSC),
			styledPad(dimStyle.Render("R ms"), cSR),
			dimStyle.Render("T ms")), iw) + "\n")
		sb.WriteString(boxMid(iw) + "\n")
		for i := 0; i < slowBeCount; i++ {
			pre := fmt.Sprintf("slow_be_%d_", i)
			sName := dm[pre+"name"]
			sAddr := dm[pre+"addr"]
			sQ := dm[pre+"qtime"]
			sC := dm[pre+"ctime"]
			sR := dm[pre+"rtime"]
			sT := dm[pre+"ttime"]
			if len(sName) > 20 { sName = sName[:20] }
			if len(sAddr) > 18 { sAddr = sAddr[:18] }
			// Color response time
			rVal := valueStyle.Render(sR)
			if rt, _ := strconv.Atoi(sR); rt > 5000 {
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
		feSumm := fmt.Sprintf("%s frontends, %s req/s in, %s 2xx, %s 5xx, %s ereq",
			dm["frontends"], dm["fe_req_rate"], haFmtNum(dm["fe_2xx"]), haFmtNum(dm["fe_5xx"]), haFmtNum(dm["fe_ereq"]))
		sb.WriteString("  " + titleStyle.Render("FRONTENDS") + "  " + dimStyle.Render(feSumm) + "\n")
		sb.WriteString(boxTop(iw) + "\n")

		cFN, cFM, cFR, cFRr, cFBi, cFBo, cF2, cF5 := 20, 8, 8, 10, 12, 12, 10, 10
		feHdr := fmt.Sprintf("  %s%s%s%s%s%s%s%s%s",
			styledPad(dimStyle.Render("Frontend"), cFN),
			styledPad(dimStyle.Render("Mode"), cFM),
			styledPad(dimStyle.Render("Cur"), cFR),
			styledPad(dimStyle.Render("Req/s"), cFRr),
			styledPad(dimStyle.Render("In"), cFBi),
			styledPad(dimStyle.Render("Out"), cFBo),
			styledPad(dimStyle.Render("2xx"), cF2),
			styledPad(dimStyle.Render("5xx"), cF5),
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
			feH := dm[pre+"health"]

			if len(feName) > 18 { feName = feName[:18] }

			var hBadge string
			switch feH {
			case "HEALTHY":  hBadge = okStyle.Render("HEALTHY")
			case "DEGRADED": hBadge = warnStyle.Render("DEGRADED")
			case "CRITICAL": hBadge = critStyle.Render("CRITICAL")
			default:         hBadge = dimStyle.Render(feH)
			}

			row := fmt.Sprintf("  %s%s%s%s%s%s%s%s%s",
				styledPad(valueStyle.Render(feName), cFN),
				styledPad(valueStyle.Render(feMode), cFM),
				styledPad(valueStyle.Render(feCur), cFR),
				styledPad(valueStyle.Render(feRR+"/s"), cFRr),
				styledPad(valueStyle.Render(haFmtBytes(feBin)), cFBi),
				styledPad(valueStyle.Render(haFmtBytes(feBout)), cFBo),
				styledPad(valueStyle.Render(haFmtNum(fe2)), cF2),
				styledPad(haColorVal(haFmtNum(fe5), "5xx"), cF5),
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

func renderMongoDBDeepMetrics(app model.AppInstance, iw int) string {
	var sb strings.Builder
	dm := app.DeepMetrics

	type healthRow struct{ metric, value, status string }
	rows := []healthRow{}

	if v := dm["cache_usage_pct"]; v != "" {
		var pct float64
		fmt.Sscanf(v, "%f", &pct)
		status := "OK"
		if pct > 95 {
			status = "CRIT"
		} else if pct > 80 {
			status = "WARN"
		}
		rows = append(rows, healthRow{"Cache Usage", v + "%", status})
	}
	if cur := dm["conn_current"]; cur != "" {
		avail := dm["conn_available"]
		val := cur + " / " + avail
		status := "OK"
		c, _ := strconv.Atoi(cur)
		a, _ := strconv.Atoi(avail)
		if a > 0 {
			pct := float64(c) / float64(c+a) * 100
			if pct > 90 {
				status = "CRIT"
			} else if pct > 80 {
				status = "WARN"
			}
		}
		rows = append(rows, healthRow{"Connections", val, status})
	}
	if v := dm["lock_queue_total"]; v != "" && v != "0" {
		status := "WARN"
		q, _ := strconv.Atoi(v)
		if q > 10 {
			status = "CRIT"
		}
		rows = append(rows, healthRow{"Lock Queue", v, status})
	} else {
		rows = append(rows, healthRow{"Lock Queue", "0", "OK"})
	}
	if v := dm["slow_ops"]; v != "" && v != "0" {
		rows = append(rows, healthRow{"Slow Operations", v, "WARN"})
	}
	if v := dm["repl_lag_sec"]; v != "" && v != "0" {
		status := "WARN"
		lag, _ := strconv.Atoi(v)
		if lag > 60 {
			status = "CRIT"
		}
		rows = append(rows, healthRow{"Replication Lag", v + "s", status})
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

	sb.WriteString(appSection("CONNECTIONS", iw, []kv{
		{Key: "Current", Val: dm["conn_current"]},
		{Key: "Available", Val: dm["conn_available"]},
		{Key: "Total Created", Val: dm["conn_total_created"]},
		{Key: "Active Clients", Val: dm["active_clients"]},
		{Key: "Active Readers", Val: dm["active_readers"]},
		{Key: "Active Writers", Val: dm["active_writers"]},
	}))

	sb.WriteString(appSection("OPERATIONS", iw, []kv{
		{Key: "Queries", Val: dm["op_query"]},
		{Key: "Inserts", Val: dm["op_insert"]},
		{Key: "Updates", Val: dm["op_update"]},
		{Key: "Deletes", Val: dm["op_delete"]},
		{Key: "Commands", Val: dm["op_command"]},
		{Key: "Slow Ops (>5s)", Val: dm["slow_ops"]},
	}))

	sb.WriteString(appSection("MEMORY & CACHE", iw, []kv{
		{Key: "Resident", Val: dm["mem_resident_mb"]},
		{Key: "Virtual", Val: dm["mem_virtual_mb"]},
		{Key: "Cache Used", Val: dm["cache_used_mb"]},
		{Key: "Cache Max", Val: dm["cache_max_mb"]},
		{Key: "Cache Usage", Val: dm["cache_usage_pct"]},
		{Key: "Cache Dirty", Val: dm["cache_dirty_mb"]},
		{Key: "Storage Engine", Val: dm["storage_engine"]},
	}))

	sb.WriteString(appSection("LOCKS", iw, []kv{
		{Key: "Queue Total", Val: dm["lock_queue_total"]},
		{Key: "Queue Readers", Val: dm["lock_queue_readers"]},
		{Key: "Queue Writers", Val: dm["lock_queue_writers"]},
	}))

	if dm["repl_set"] != "" {
		sb.WriteString(appSection("REPLICATION", iw, []kv{
			{Key: "Set Name", Val: dm["repl_set"]},
			{Key: "State", Val: dm["repl_state"]},
			{Key: "Members", Val: dm["repl_members"]},
			{Key: "Lag", Val: dm["repl_lag_sec"]},
		}))
	}

	sb.WriteString(appSection("STORAGE", iw, []kv{
		{Key: "Databases", Val: dm["db_count"]},
		{Key: "Total Size", Val: dm["total_size_mb"]},
		{Key: "Config Cache", Val: dm["wt_cache_size_gb"]},
		{Key: "Max Connections", Val: dm["max_connections"]},
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
			cName := 22
			cState := 10
			cCPU := 7
			cMem := 10
			cMemPct := 6
			cNet := 16
			cRestart := 5
			cImage := 28

			hdr := fmt.Sprintf(" %s%s%s%s%s%s%s%s",
				styledPad(dimStyle.Render("Name"), cName),
				styledPad(dimStyle.Render("State"), cState),
				styledPad(dimStyle.Render("CPU%"), cCPU),
				styledPad(dimStyle.Render("Mem"), cMem),
				styledPad(dimStyle.Render("Mem%"), cMemPct),
				styledPad(dimStyle.Render("Net I/O"), cNet),
				styledPad(dimStyle.Render("Rst"), cRestart),
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
				netStr := "—"
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
					netStr = fmt.Sprintf("%s/%s",
						appFmtBytesShort(c.NetRxBytes), appFmtBytesShort(c.NetTxBytes))
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

				row := fmt.Sprintf(" %s%s%s%s%s%s%s%s",
					styledPad(valueStyle.Render(name), cName),
					styledPad(stateStr, cState),
					styledPad(cpuStr, cCPU),
					styledPad(valueStyle.Render(memStr), cMem),
					styledPad(memPctStr, cMemPct),
					styledPad(dimStyle.Render(netStr), cNet),
					styledPad(rstStr, cRestart),
					styledPad(dimStyle.Render(imageStr), cImage))
				sb.WriteString(boxRow(row, iw) + "\n")
			}

			// Container details: ports, mounts, networks, limits, issues
			for _, c := range stack.Containers {
				details := dockerContainerDetails(c)
				if len(details) > 0 {
					sb.WriteString(boxMid(iw) + "\n")
					sb.WriteString(boxRow("  "+valueStyle.Render(c.Name)+
						"  "+dimStyle.Render(c.Status), iw) + "\n")
					for _, d := range details {
						sb.WriteString(boxRow(d, iw) + "\n")
					}
				}
			}

			// Stack issues
			if len(stack.Issues) > 0 {
				sb.WriteString(boxMid(iw) + "\n")
				sb.WriteString(boxRow("  "+warnStyle.Render("ISSUES"), iw) + "\n")
				for _, issue := range stack.Issues {
					sb.WriteString(boxRow("  "+critStyle.Render("\u25cf")+" "+valueStyle.Render(issue), iw) + "\n")
				}
			}

			// Stack networks
			if len(stack.Networks) > 0 {
				sb.WriteString(boxMid(iw) + "\n")
				sb.WriteString(boxRow("  "+dimStyle.Render("Networks:"), iw) + "\n")
				for _, n := range stack.Networks {
					net := fmt.Sprintf("    %s  drv=%s", valueStyle.Render(n.Name), dimStyle.Render(n.Driver))
					if n.Subnet != "" {
						net += "  " + dimStyle.Render(n.Subnet)
					}
					sb.WriteString(boxRow(net, iw) + "\n")
				}
			}

			sb.WriteString(boxBot(iw) + "\n")
		}
	} else if len(app.Containers) > 0 {
		// Fallback: no stacks, just flat container list (shouldn't happen with new collector)
		sb.WriteString(renderDockerFlatContainers(app, iw))
	}

	sb.WriteString(pageFooter("j/k:Navigate  Enter:Expand  A:All  C:Collapse  b:Back  Y:Apps"))
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

// dockerContainerDetails returns detail lines for a container's inspect data.
func dockerContainerDetails(c model.AppDockerContainer) []string {
	var lines []string

	// Ports
	if len(c.Ports) > 0 {
		var ports []string
		for _, p := range c.Ports {
			if p.HostPort > 0 {
				ports = append(ports, fmt.Sprintf("%s:%d→%d/%s",
					p.HostIP, p.HostPort, p.ContainerPort, p.Protocol))
			} else {
				ports = append(ports, fmt.Sprintf("%d/%s", p.ContainerPort, p.Protocol))
			}
		}
		lines = append(lines, "    "+dimStyle.Render("Ports: ")+valueStyle.Render(strings.Join(ports, ", ")))
	}

	// Mounts (show first 3)
	if len(c.Mounts) > 0 {
		for i, m := range c.Mounts {
			if i >= 3 {
				lines = append(lines, fmt.Sprintf("    "+dimStyle.Render("  ... +%d more mounts"), len(c.Mounts)-3))
				break
			}
			ro := ""
			if m.ReadOnly {
				ro = dimStyle.Render(" (ro)")
			}
			lines = append(lines, fmt.Sprintf("    "+dimStyle.Render("Mount: ")+"%s → %s%s",
				dimStyle.Render(truncStr(m.Source, 30)),
				valueStyle.Render(truncStr(m.Target, 25)), ro))
		}
	}

	// Networks
	if len(c.Networks) > 0 {
		var nets []string
		for _, n := range c.Networks {
			nets = append(nets, fmt.Sprintf("%s(%s)", n.Name, n.IP))
		}
		lines = append(lines, "    "+dimStyle.Render("Nets: ")+dimStyle.Render(strings.Join(nets, ", ")))
	}

	// Resource limits
	var limits []string
	if c.MemLimit > 0 {
		limits = append(limits, fmt.Sprintf("mem=%s", appFmtBytesShort(float64(c.MemLimit))))
	}
	if c.CPUQuota > 0 {
		limits = append(limits, fmt.Sprintf("cpu=%.1f cores", c.CPUQuota))
	}
	if len(limits) > 0 {
		lines = append(lines, "    "+dimStyle.Render("Limits: ")+valueStyle.Render(strings.Join(limits, "  ")))
	}

	// Flags: restart policy, privileged, no healthcheck
	var flags []string
	if c.RestartPolicy != "" && c.RestartPolicy != "no" {
		flags = append(flags, "restart="+c.RestartPolicy)
	} else if c.RestartPolicy == "" || c.RestartPolicy == "no" {
		flags = append(flags, warnStyle.Render("no-restart"))
	}
	if c.Privileged {
		flags = append(flags, critStyle.Render("PRIVILEGED"))
	}
	if !c.HasHealthChk {
		flags = append(flags, dimStyle.Render("no-healthcheck"))
	}
	if c.User != "" {
		flags = append(flags, "user="+c.User)
	}
	if len(flags) > 0 {
		lines = append(lines, "    "+dimStyle.Render("Flags: ")+strings.Join(flags, "  "))
	}

	return lines
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
