//go:build linux

package ui

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/ftahirops/xtop/model"
)

// renderAppsDetailCompact renders the summary/compact view of an app detail page.
// Shows a one-line verdict at top, then collapsible sections with one-line summaries.
func renderAppsDetailCompact(app model.AppInstance, iw int) string {
	var sb strings.Builder

	// Header with health badge
	sb.WriteString(appDetailHeader(app))

	// Credential notice (if needed)
	if app.NeedsCreds && !app.HasDeepMetrics {
		sb.WriteString(renderCredsNotice(app, iw))
	}

	// ── One-line verdict ──
	verdict := appCompactVerdict(app)
	sb.WriteString(boxTop(iw) + "\n")
	sb.WriteString(boxRow("  "+verdict, iw) + "\n")
	sb.WriteString(boxBot(iw) + "\n\n")

	// ── Process & Resources (always shown, compact) ──
	sb.WriteString(renderAppInfoResourceBox(app, iw))

	// ── Deep metrics summary sections ──
	if app.HasDeepMetrics && len(app.DeepMetrics) > 0 {
		sb.WriteString(renderAppCompactSections(app, iw))
	}

	// Per-website table (for hosting panels, nginx, apache, php-fpm)
	if len(app.Websites) > 0 {
		sb.WriteString(renderWebsitesTable(app.Websites, iw))
	}

	// Health issues (if any)
	if app.AppType != "mysql" && len(app.HealthIssues) > 0 {
		sb.WriteString("\n  " + titleStyle.Render("HEALTH ISSUES") + "\n")
		sb.WriteString(boxTop(iw) + "\n")
		for _, issue := range app.HealthIssues {
			row := "  " + critStyle.Render("\u25cf") + " " + valueStyle.Render(issue)
			sb.WriteString(boxRow(row, iw) + "\n")
		}
		sb.WriteString(boxBot(iw) + "\n")
	}

	sb.WriteString(pageFooter("b:Back  d:Full Detail  Y:Apps"))
	return sb.String()
}

// appCompactVerdict returns a single-line colored verdict for the app.
func appCompactVerdict(app model.AppInstance) string {
	if !app.HasDeepMetrics || len(app.DeepMetrics) == 0 {
		base := fmt.Sprintf("%s  PID %d  RSS %s  %d conns  %d threads",
			app.DisplayName, app.PID, appFmtMem(app.RSSMB), app.Connections, app.Threads)
		if len(app.HealthIssues) > 0 {
			return warnStyle.Render("⚠") + "  " + valueStyle.Render(base) + "  " +
				warnStyle.Render(fmt.Sprintf("%d issues", len(app.HealthIssues)))
		}
		return okStyle.Render("●") + "  " + valueStyle.Render(base)
	}

	// Build verdict from deep metrics based on app type
	switch app.AppType {
	case "redis":
		return redisCompactVerdict(app)
	case "elasticsearch":
		return esCompactVerdict(app)
	case "mysql":
		return mysqlCompactVerdict(app)
	case "postgresql":
		return pgCompactVerdict(app)
	case "nginx":
		return nginxCompactVerdict(app)
	case "haproxy":
		return haproxyCompactVerdict(app)
	case "mongodb":
		return mongoCompactVerdict(app)
	case "memcached":
		return memcachedCompactVerdict(app)
	case "rabbitmq":
		return rabbitmqCompactVerdict(app)
	case "kafka":
		return kafkaCompactVerdict(app)
	case "plesk":
		return pleskCompactVerdict(app)
	default:
		return genericCompactVerdict(app)
	}
}

// renderAppCompactSections renders collapsible one-line summaries per metric section.
func renderAppCompactSections(app model.AppInstance, iw int) string {
	switch app.AppType {
	case "redis":
		return redisCompactSections(app, iw)
	case "elasticsearch":
		return esCompactSections(app, iw)
	case "mysql":
		return mysqlCompactSections(app, iw)
	case "postgresql":
		return pgCompactSections(app, iw)
	case "nginx":
		return nginxCompactSections(app, iw)
	case "haproxy":
		return haproxyCompactSections(app, iw)
	case "mongodb":
		return mongoCompactSections(app, iw)
	case "memcached":
		return memcachedCompactSections(app, iw)
	case "rabbitmq":
		return rabbitmqCompactSections(app, iw)
	case "kafka":
		return kafkaCompactSections(app, iw)
	case "plesk":
		return pleskCompactSections(app, iw)
	default:
		return genericCompactSections(app, iw)
	}
}

// ── Section rendering helpers ──

type compactSection struct {
	name    string
	status  string // "OK", "WARN", "CRIT"
	summary string
}

func renderCompactSectionList(sections []compactSection, iw int) string {
	var sb strings.Builder
	sb.WriteString(boxTop(iw) + "\n")
	for _, sec := range sections {
		var badge string
		switch sec.status {
		case "CRIT":
			badge = critStyle.Render("✗")
		case "WARN":
			badge = warnStyle.Render("⚠")
		default:
			badge = okStyle.Render("●")
		}
		row := fmt.Sprintf("  %s  %s  %s",
			badge,
			styledPad(titleStyle.Render(sec.name), 16),
			dimStyle.Render(sec.summary))
		sb.WriteString(boxRow(row, iw) + "\n")
	}
	sb.WriteString(boxBot(iw) + "\n")
	return sb.String()
}

// ── Redis compact ──

func redisCompactVerdict(app model.AppInstance) string {
	dm := app.DeepMetrics
	parts := []string{}
	badge := okStyle.Render("●")

	if ops := dm["instantaneous_ops_per_sec"]; ops != "" {
		parts = append(parts, ops+" ops/s")
	}
	if hr := dm["hit_ratio"]; hr != "" {
		parts = append(parts, hr+" hit")
	}
	if p99 := dm["latency_percentiles_usec_p99"]; p99 != "" {
		p99v, _ := strconv.ParseFloat(p99, 64)
		parts = append(parts, redisFmtUsec(p99v)+" p99")
		if p99v > 10000 {
			badge = critStyle.Render("✗")
		} else if p99v > 1000 {
			badge = warnStyle.Render("⚠")
		}
	}
	if mem := dm["used_memory_human"]; mem != "" {
		if mx := dm["maxmemory_human"]; mx != "" && mx != "0B" {
			parts = append(parts, mem+"/"+mx)
		} else {
			parts = append(parts, mem)
		}
	}
	if ev := dm["evicted_keys"]; ev != "" && ev != "0" {
		parts = append(parts, ev+" evictions")
		badge = critStyle.Render("✗")
	}

	return badge + "  " + valueStyle.Render(strings.Join(parts, "  "))
}

func redisCompactSections(app model.AppInstance, iw int) string {
	dm := app.DeepMetrics
	var sections []compactSection

	// Health
	healthStatus := "OK"
	if app.HealthScore < 50 {
		healthStatus = "CRIT"
	} else if app.HealthScore < 80 {
		healthStatus = "WARN"
	}
	healthSum := fmt.Sprintf("Score %d/100", app.HealthScore)
	if len(app.HealthIssues) > 0 {
		healthSum += fmt.Sprintf(", %d issues", len(app.HealthIssues))
	}
	sections = append(sections, compactSection{"Health", healthStatus, healthSum})

	// Throughput
	tpSum := dm["instantaneous_ops_per_sec"] + " ops/s"
	if hr := dm["hit_ratio"]; hr != "" {
		tpSum += ", " + hr + " hit rate"
	}
	if cc := dm["connected_clients"]; cc != "" {
		tpSum += ", " + cc + " clients"
	}
	sections = append(sections, compactSection{"Throughput", "OK", tpSum})

	// Memory
	memStatus := "OK"
	memSum := dm["used_memory_human"]
	if frag := dm["mem_fragmentation_ratio"]; frag != "" {
		fragV, _ := strconv.ParseFloat(frag, 64)
		memSum += ", frag " + frag
		if fragV > 1.5 || (fragV < 1.0 && fragV > 0) {
			memStatus = "WARN"
		}
	}
	if pct := dm["memory_usage_pct"]; pct != "" {
		memSum += " (" + pct + " used)"
		var pctV float64
		fmt.Sscanf(pct, "%f", &pctV)
		if pctV > 90 {
			memStatus = "CRIT"
		} else if pctV > 75 {
			memStatus = "WARN"
		}
	}
	sections = append(sections, compactSection{"Memory", memStatus, memSum})

	// Persistence
	persStatus := "OK"
	persSum := ""
	if rdb := dm["rdb_last_bgsave_status"]; rdb != "" {
		persSum = "RDB " + rdb
		if rdb != "ok" {
			persStatus = "CRIT"
		}
	}
	if aof := dm["aof_enabled"]; aof == "1" {
		if persSum != "" {
			persSum += ", "
		}
		persSum += "AOF on"
		if rew := dm["aof_last_bgrewrite_status"]; rew != "" && rew != "ok" {
			persStatus = "WARN"
		}
	}
	if forkUs := dm["latest_fork_usec"]; forkUs != "" {
		fv, _ := strconv.ParseFloat(forkUs, 64)
		if persSum != "" {
			persSum += ", "
		}
		persSum += "fork " + redisFmtUsec(fv)
		if fv > 500000 {
			persStatus = "CRIT"
		}
	}
	if persSum == "" {
		persSum = "no persistence configured"
	}
	sections = append(sections, compactSection{"Persistence", persStatus, persSum})

	// Replication
	replSum := dm["role"]
	replStatus := "OK"
	if dm["role"] == "slave" || dm["role"] == "replica" {
		if link := dm["master_link_status"]; link == "down" {
			replStatus = "CRIT"
			replSum += ", link DOWN"
		} else {
			replSum += ", link up"
		}
		if lag := dm["repl_lag_bytes"]; lag != "" {
			lagV, _ := strconv.ParseFloat(lag, 64)
			if lagV > 10*1024*1024 {
				replStatus = "WARN"
			}
			replSum += ", lag " + redisFmtNetBytes(lag)
		}
	} else if slaves := dm["connected_slaves"]; slaves != "" && slaves != "0" {
		replSum += ", " + slaves + " replicas"
	}
	sections = append(sections, compactSection{"Replication", replStatus, replSum})

	// Latency
	latStatus := "OK"
	latSum := ""
	if p99 := dm["latency_percentiles_usec_p99"]; p99 != "" {
		p99v, _ := strconv.ParseFloat(p99, 64)
		latSum = "p99 " + redisFmtUsec(p99v)
		if p99v > 10000 {
			latStatus = "CRIT"
		} else if p99v > 1000 {
			latStatus = "WARN"
		}
	}
	if sc := dm["slowlog_count"]; sc != "" && sc != "0" {
		if latSum != "" {
			latSum += ", "
		}
		latSum += sc + " slow queries"
		if latStatus == "OK" {
			latStatus = "WARN"
		}
	}
	if latSum != "" {
		sections = append(sections, compactSection{"Latency", latStatus, latSum})
	}

	// Keyspace
	totalKeys := 0
	dbCount := 0
	for i := 0; i <= 15; i++ {
		if v, ok := dm[fmt.Sprintf("db%d", i)]; ok {
			keys, _, _ := redisParseDBParts(v)
			totalKeys += keys
			dbCount++
		}
	}
	if totalKeys > 0 {
		ksSum := fmt.Sprintf("%s keys across %d DBs", redisFmtLargeNum(fmt.Sprintf("%d", totalKeys)), dbCount)
		if ec := dm["expire_coverage_pct"]; ec != "" {
			ksSum += ", " + ec + " TTL coverage"
		}
		sections = append(sections, compactSection{"Keyspace", "OK", ksSum})
	}

	// Recommendations
	recCount, _ := strconv.Atoi(dm["rec_count"])
	if recCount > 0 {
		sections = append(sections, compactSection{"Recommendations", "WARN", fmt.Sprintf("%d actionable recommendations", recCount)})
	}

	return "\n" + renderCompactSectionList(sections, iw)
}

// ── Elasticsearch compact ──

func esCompactVerdict(app model.AppInstance) string {
	dm := app.DeepMetrics
	badge := okStyle.Render("●")
	parts := []string{}

	if st := dm["status"]; st != "" {
		parts = append(parts, "cluster "+st)
		if st == "red" {
			badge = critStyle.Render("✗")
		} else if st == "yellow" {
			badge = warnStyle.Render("⚠")
		}
	}
	if n := dm["number_of_nodes"]; n != "" {
		parts = append(parts, n+" nodes")
	}
	if u := dm["unassigned_shards"]; u != "" && u != "0" {
		parts = append(parts, u+" unassigned shards")
		badge = warnStyle.Render("⚠")
	}
	if h := dm["jvm_heap_used_pct"]; h != "" {
		parts = append(parts, h+" heap")
	}
	return badge + "  " + valueStyle.Render(strings.Join(parts, "  "))
}

func esCompactSections(app model.AppInstance, iw int) string {
	dm := app.DeepMetrics
	var sections []compactSection

	// Cluster
	clStatus := "OK"
	if dm["status"] == "red" {
		clStatus = "CRIT"
	} else if dm["status"] == "yellow" {
		clStatus = "WARN"
	}
	sections = append(sections, compactSection{"Cluster", clStatus,
		fmt.Sprintf("%s, %s nodes, %s data nodes", dm["status"], dm["number_of_nodes"], dm["number_of_data_nodes"])})

	// Shards
	shStatus := "OK"
	if u := dm["unassigned_shards"]; u != "" && u != "0" {
		shStatus = "WARN"
	}
	sections = append(sections, compactSection{"Shards", shStatus,
		fmt.Sprintf("%s active, %s unassigned", dm["active_shards"], dm["unassigned_shards"])})

	// Indices
	sections = append(sections, compactSection{"Indices", "OK",
		fmt.Sprintf("%s indices, %s docs, %s store", dm["total_indices"], dm["doc_count"], dm["store_size"])})

	// JVM
	jvmStatus := "OK"
	if h := dm["jvm_heap_used_pct"]; h != "" {
		var hv float64
		fmt.Sscanf(h, "%f", &hv)
		if hv > 90 {
			jvmStatus = "CRIT"
		} else if hv > 75 {
			jvmStatus = "WARN"
		}
	}
	sections = append(sections, compactSection{"JVM", jvmStatus,
		fmt.Sprintf("heap %s/%s (%s)", dm["jvm_heap_used"], dm["jvm_heap_max"], dm["jvm_heap_used_pct"])})

	return "\n" + renderCompactSectionList(sections, iw)
}

// ── MySQL compact ──

func mysqlCompactVerdict(app model.AppInstance) string {
	dm := app.DeepMetrics
	badge := okStyle.Render("●")
	parts := []string{}

	if qps := dm["queries_per_sec"]; qps != "" {
		parts = append(parts, qps+" qps")
	}
	if conn := dm["threads_connected"]; conn != "" {
		if max := dm["max_connections"]; max != "" {
			parts = append(parts, conn+"/"+max+" conns")
		}
	}
	if sl := dm["slow_queries"]; sl != "" && sl != "0" {
		parts = append(parts, sl+" slow queries")
		badge = warnStyle.Render("⚠")
	}
	if rep := dm["slave_io_running"]; rep != "" {
		if rep != "Yes" || dm["slave_sql_running"] != "Yes" {
			badge = critStyle.Render("✗")
			parts = append(parts, "replication BROKEN")
		}
	}
	return badge + "  " + valueStyle.Render(strings.Join(parts, "  "))
}

func mysqlCompactSections(app model.AppInstance, iw int) string {
	dm := app.DeepMetrics
	var sections []compactSection

	// Performance
	perfSum := ""
	if qps := dm["queries_per_sec"]; qps != "" {
		perfSum = qps + " qps"
	}
	if sl := dm["slow_queries"]; sl != "" {
		perfSum += ", " + sl + " slow"
	}
	sections = append(sections, compactSection{"Performance", "OK", perfSum})

	// Connections
	connStatus := "OK"
	connSum := dm["threads_connected"] + " connected"
	if max := dm["max_connections"]; max != "" {
		connSum += "/" + max
		if tc, _ := strconv.Atoi(dm["threads_connected"]); tc > 0 {
			if mx, _ := strconv.Atoi(max); mx > 0 && float64(tc)/float64(mx) > 0.8 {
				connStatus = "WARN"
			}
		}
	}
	sections = append(sections, compactSection{"Connections", connStatus, connSum})

	// InnoDB
	if bp := dm["innodb_buffer_pool_size"]; bp != "" {
		sections = append(sections, compactSection{"InnoDB", "OK",
			"buffer pool " + bp + ", hit rate " + dm["innodb_buffer_pool_hit_rate"]})
	}

	// Replication
	if dm["slave_io_running"] != "" {
		replStatus := "OK"
		replSum := "IO=" + dm["slave_io_running"] + " SQL=" + dm["slave_sql_running"]
		if dm["slave_io_running"] != "Yes" || dm["slave_sql_running"] != "Yes" {
			replStatus = "CRIT"
		}
		if lag := dm["seconds_behind_master"]; lag != "" && lag != "0" {
			replSum += ", " + lag + "s behind"
			if replStatus == "OK" {
				replStatus = "WARN"
			}
		}
		sections = append(sections, compactSection{"Replication", replStatus, replSum})
	}

	return "\n" + renderCompactSectionList(sections, iw)
}

// ── PostgreSQL compact ──

func pgCompactVerdict(app model.AppInstance) string {
	dm := app.DeepMetrics
	badge := okStyle.Render("●")
	parts := []string{}

	if ac := dm["active_connections"]; ac != "" {
		parts = append(parts, ac+" active conns")
	}
	if hr := dm["cache_hit_ratio"]; hr != "" {
		parts = append(parts, hr+" cache hit")
	}
	if db := dm["deadlocks"]; db != "" && db != "0" {
		parts = append(parts, db+" deadlocks")
		badge = warnStyle.Render("⚠")
	}
	if rep := dm["replication_lag"]; rep != "" && rep != "0" {
		parts = append(parts, rep+"s repl lag")
	}
	return badge + "  " + valueStyle.Render(strings.Join(parts, "  "))
}

func pgCompactSections(app model.AppInstance, iw int) string {
	dm := app.DeepMetrics
	var sections []compactSection

	connSum := dm["active_connections"] + " active"
	if idle := dm["idle_connections"]; idle != "" {
		connSum += ", " + idle + " idle"
	}
	if max := dm["max_connections"]; max != "" {
		connSum += " / " + max + " max"
	}
	sections = append(sections, compactSection{"Connections", "OK", connSum})

	if hr := dm["cache_hit_ratio"]; hr != "" {
		sections = append(sections, compactSection{"Cache", "OK", hr + " hit ratio"})
	}

	if db := dm["database_size"]; db != "" {
		sections = append(sections, compactSection{"Storage", "OK", db + " total"})
	}

	if dm["replication_lag"] != "" {
		replStatus := "OK"
		if lag := dm["replication_lag"]; lag != "0" {
			replStatus = "WARN"
		}
		sections = append(sections, compactSection{"Replication", replStatus, dm["replication_lag"] + "s lag"})
	}

	return "\n" + renderCompactSectionList(sections, iw)
}

// ── Nginx compact ──

func nginxCompactVerdict(app model.AppInstance) string {
	dm := app.DeepMetrics
	badge := okStyle.Render("●")
	parts := []string{}
	if rps := dm["requests_per_sec"]; rps != "" {
		parts = append(parts, rps+" rps")
	}
	if ac := dm["active_connections"]; ac != "" {
		parts = append(parts, ac+" active")
	}
	return badge + "  " + valueStyle.Render(strings.Join(parts, "  "))
}

func nginxCompactSections(app model.AppInstance, iw int) string {
	dm := app.DeepMetrics
	var sections []compactSection
	connSum := dm["active_connections"] + " active"
	if w := dm["waiting"]; w != "" {
		connSum += ", " + w + " waiting"
	}
	sections = append(sections, compactSection{"Connections", "OK", connSum})
	if rps := dm["requests_per_sec"]; rps != "" {
		sections = append(sections, compactSection{"Traffic", "OK", rps + " rps, " + dm["total_requests"] + " total"})
	}
	return "\n" + renderCompactSectionList(sections, iw)
}

// ── HAProxy compact ──

func haproxyCompactVerdict(app model.AppInstance) string {
	dm := app.DeepMetrics
	severity := 0 // 0=ok, 1=warn, 2=crit
	parts := []string{}
	if fe := dm["frontends"]; fe != "" {
		parts = append(parts, fe+" frontends")
	}
	if be := dm["backends"]; be != "" {
		parts = append(parts, be+" backends")
	}
	if rps := dm["request_rate"]; rps != "" && rps != "0" {
		parts = append(parts, rps+" rps")
	}
	if sess := dm["current_sessions"]; sess != "" && sess != "0" {
		parts = append(parts, sess+" sessions")
	}
	if e5 := dm["http_5xx"]; e5 != "" && e5 != "0" {
		parts = append(parts, e5+" 5xx")
		if severity < 1 { severity = 1 }
	}
	if down := dm["servers_down"]; down != "" && down != "0" {
		parts = append(parts, down+" servers down")
		severity = 2
	}
	if re := dm["response_errors"]; re != "" && re != "0" {
		rev, _ := strconv.Atoi(re)
		if rev > 1000 {
			parts = append(parts, haFmtNum(re)+" resp errors")
			if severity < 1 { severity = 1 }
		}
	}
	badge := okStyle.Render("●")
	if severity == 2 {
		badge = critStyle.Render("✗")
	} else if severity == 1 {
		badge = warnStyle.Render("⚠")
	}
	return badge + "  " + valueStyle.Render(strings.Join(parts, "  "))
}

func haproxyCompactSections(app model.AppInstance, iw int) string {
	dm := app.DeepMetrics
	var sections []compactSection

	// Frontends
	feSum := dm["frontends"] + " frontends"
	if rps := dm["request_rate"]; rps != "" && rps != "0" {
		feSum += ", " + rps + " req/s"
	}
	if sess := dm["session_rate"]; sess != "" && sess != "0" {
		feSum += ", " + sess + " sess/s"
	}
	sections = append(sections, compactSection{"Frontends", "OK", feSum})

	// Backends
	bkStatus := "OK"
	bkSum := dm["backends"] + " backends, " + dm["servers_up"] + " up"
	if d := dm["servers_down"]; d != "" && d != "0" {
		bkStatus = "CRIT"
		bkSum += ", " + d + " down"
	}
	sections = append(sections, compactSection{"Backends", bkStatus, bkSum})

	// Sessions
	sessSum := dm["current_sessions"] + " current"
	if q := dm["queue_current"]; q != "" && q != "0" {
		sessSum += ", " + q + " queued"
	}
	if tot := dm["total_sessions"]; tot != "" {
		sessSum += ", " + haFmtNum(tot) + " total"
	}
	sections = append(sections, compactSection{"Sessions", "OK", sessSum})

	// Traffic
	trafficSum := ""
	if bi := dm["bytes_in"]; bi != "" {
		trafficSum = "in " + haFmtBytes(bi)
	}
	if bo := dm["bytes_out"]; bo != "" {
		if trafficSum != "" {
			trafficSum += ", "
		}
		trafficSum += "out " + haFmtBytes(bo)
	}
	if trafficSum != "" {
		sections = append(sections, compactSection{"Traffic", "OK", trafficSum})
	}

	// Errors
	errStatus := "OK"
	errParts := []string{}
	if e5 := dm["http_5xx"]; e5 != "" && e5 != "0" {
		errParts = append(errParts, haFmtNum(e5)+" 5xx")
		errStatus = "WARN"
	}
	if ce := dm["connection_errors"]; ce != "" && ce != "0" {
		errParts = append(errParts, haFmtNum(ce)+" conn err")
	}
	if re := dm["response_errors"]; re != "" && re != "0" {
		errParts = append(errParts, haFmtNum(re)+" resp err")
		errStatus = "WARN"
	}
	if ret := dm["retries"]; ret != "" && ret != "0" {
		errParts = append(errParts, haFmtNum(ret)+" retries")
	}
	if ca := dm["client_aborts"]; ca != "" && ca != "0" {
		errParts = append(errParts, haFmtNum(ca)+" client aborts")
	}
	if len(errParts) > 0 {
		sections = append(sections, compactSection{"Errors", errStatus, strings.Join(errParts, ", ")})
	} else {
		sections = append(sections, compactSection{"Errors", "OK", "none"})
	}

	// Config
	cfgParts := []string{}
	if mc := dm["cfg_maxconn"]; mc != "" {
		cfgParts = append(cfgParts, "maxconn "+mc)
	}
	if nt := dm["cfg_nbthread"]; nt != "" {
		cfgParts = append(cfgParts, nt+" threads")
	}
	if len(cfgParts) > 0 {
		sections = append(sections, compactSection{"Config", "OK", strings.Join(cfgParts, ", ")})
	}

	return "\n" + renderCompactSectionList(sections, iw)
}

// ── MongoDB compact ──

func mongoCompactVerdict(app model.AppInstance) string {
	dm := app.DeepMetrics
	badge := okStyle.Render("●")
	parts := []string{}
	if conn := dm["current_connections"]; conn != "" {
		parts = append(parts, conn+" conns")
	}
	if ops := dm["opcounters_total"]; ops != "" {
		parts = append(parts, ops+" ops")
	}
	if rs := dm["repl_set_status"]; rs != "" && rs != "ok" {
		badge = warnStyle.Render("⚠")
		parts = append(parts, "replset "+rs)
	}
	return badge + "  " + valueStyle.Render(strings.Join(parts, "  "))
}

func mongoCompactSections(app model.AppInstance, iw int) string {
	dm := app.DeepMetrics
	var sections []compactSection
	sections = append(sections, compactSection{"Connections", "OK", dm["current_connections"] + " current, " + dm["available_connections"] + " available"})
	sections = append(sections, compactSection{"Operations", "OK", "query " + dm["opcounters_query"] + ", insert " + dm["opcounters_insert"] + ", update " + dm["opcounters_update"]})
	if dm["repl_set_name"] != "" {
		sections = append(sections, compactSection{"Replication", "OK", dm["repl_set_name"] + " (" + dm["repl_my_state"] + ")"})
	}
	return "\n" + renderCompactSectionList(sections, iw)
}

// ── Memcached compact ──

func memcachedCompactVerdict(app model.AppInstance) string {
	dm := app.DeepMetrics
	badge := okStyle.Render("●")
	parts := []string{}
	if hr := dm["hit_ratio"]; hr != "" {
		parts = append(parts, hr+" hit")
	}
	if mem := dm["bytes_human"]; mem != "" {
		parts = append(parts, mem+" used")
	}
	if ev := dm["evictions"]; ev != "" && ev != "0" {
		parts = append(parts, ev+" evictions")
		badge = warnStyle.Render("⚠")
	}
	return badge + "  " + valueStyle.Render(strings.Join(parts, "  "))
}

func memcachedCompactSections(app model.AppInstance, iw int) string {
	dm := app.DeepMetrics
	var sections []compactSection
	sections = append(sections, compactSection{"Cache", "OK", dm["hit_ratio"] + " hit rate, " + dm["curr_items"] + " items"})
	memStatus := "OK"
	if ev := dm["evictions"]; ev != "" && ev != "0" {
		memStatus = "WARN"
	}
	sections = append(sections, compactSection{"Memory", memStatus, dm["bytes_human"] + " / " + dm["limit_maxbytes_human"] + ", " + dm["evictions"] + " evictions"})
	return "\n" + renderCompactSectionList(sections, iw)
}

// ── RabbitMQ compact ──

func rabbitmqCompactVerdict(app model.AppInstance) string {
	dm := app.DeepMetrics
	badge := okStyle.Render("●")
	parts := []string{}
	if q := dm["queue_totals_messages"]; q != "" {
		parts = append(parts, q+" msgs queued")
		if qv, _ := strconv.Atoi(q); qv > 10000 {
			badge = warnStyle.Render("⚠")
		}
	}
	if pub := dm["message_stats_publish"]; pub != "" {
		parts = append(parts, pub+" published")
	}
	if conn := dm["connections"]; conn != "" {
		parts = append(parts, conn+" conns")
	}
	return badge + "  " + valueStyle.Render(strings.Join(parts, "  "))
}

func rabbitmqCompactSections(app model.AppInstance, iw int) string {
	dm := app.DeepMetrics
	var sections []compactSection
	sections = append(sections, compactSection{"Queues", "OK", dm["queue_totals_messages"] + " messages, " + dm["queues"] + " queues"})
	sections = append(sections, compactSection{"Connections", "OK", dm["connections"] + " connections, " + dm["channels"] + " channels"})
	if n := dm["cluster_nodes"]; n != "" {
		sections = append(sections, compactSection{"Cluster", "OK", n + " nodes"})
	}
	return "\n" + renderCompactSectionList(sections, iw)
}

// ── Kafka compact ──

func kafkaCompactVerdict(app model.AppInstance) string {
	dm := app.DeepMetrics
	badge := okStyle.Render("●")
	parts := []string{}
	if t := dm["topics"]; t != "" {
		parts = append(parts, t+" topics")
	}
	if p := dm["partitions"]; p != "" {
		parts = append(parts, p+" partitions")
	}
	if uisr := dm["under_replicated"]; uisr != "" && uisr != "0" {
		parts = append(parts, uisr+" under-replicated")
		badge = warnStyle.Render("⚠")
	}
	return badge + "  " + valueStyle.Render(strings.Join(parts, "  "))
}

func kafkaCompactSections(app model.AppInstance, iw int) string {
	dm := app.DeepMetrics
	var sections []compactSection
	sections = append(sections, compactSection{"Topics", "OK", dm["topics"] + " topics, " + dm["partitions"] + " partitions"})
	replStatus := "OK"
	if u := dm["under_replicated"]; u != "" && u != "0" {
		replStatus = "WARN"
	}
	sections = append(sections, compactSection{"Replication", replStatus, dm["in_sync_replicas"] + " ISR, " + dm["under_replicated"] + " under-replicated"})
	return "\n" + renderCompactSectionList(sections, iw)
}

// ── Generic compact (for apps without specific handler) ──

func genericCompactVerdict(app model.AppInstance) string {
	badge := okStyle.Render("●")
	if app.HealthScore < 50 {
		badge = critStyle.Render("✗")
	} else if app.HealthScore < 80 {
		badge = warnStyle.Render("⚠")
	}
	return badge + "  " + valueStyle.Render(fmt.Sprintf("Score %d/100  %s  %d threads  %d conns",
		app.HealthScore, appFmtMem(app.RSSMB), app.Threads, app.Connections))
}

func genericCompactSections(app model.AppInstance, iw int) string {
	dm := app.DeepMetrics
	if len(dm) == 0 {
		return ""
	}
	// Show up to 8 key metrics as a simple list
	var sections []compactSection
	count := 0
	for k, v := range dm {
		if count >= 8 {
			break
		}
		if v == "" {
			continue
		}
		sections = append(sections, compactSection{k, "OK", v})
		count++
	}
	if len(sections) == 0 {
		return ""
	}
	return "\n" + renderCompactSectionList(sections, iw)
}

// ── Plesk compact ──

func pleskCompactVerdict(app model.AppInstance) string {
	dm := app.DeepMetrics
	severity := 0 // 0=ok, 1=warn, 2=crit
	parts := []string{}

	if v := dm["plesk_version"]; v != "" {
		parts = append(parts, "v"+v)
	}
	if d := dm["domains"]; d != "" {
		parts = append(parts, d+" domains")
	}
	if r := dm["services_running"]; r != "" {
		parts = append(parts, r+" services up")
	}
	if f := dm["services_failed"]; f != "" && f != "0" {
		names := dm["services_down_names"]
		if names != "" {
			parts = append(parts, "DOWN: "+names)
		} else {
			parts = append(parts, f+" services DOWN")
		}
		severity = 2
	}
	if inf, _ := strconv.Atoi(dm["imunify_infected"]); inf > 0 {
		parts = append(parts, dm["imunify_infected"]+" infected")
		if severity < 1 { severity = 1 }
	}

	badge := okStyle.Render("●")
	if severity == 2 {
		badge = critStyle.Render("✗")
	} else if severity == 1 {
		badge = warnStyle.Render("⚠")
	}
	return badge + "  " + valueStyle.Render(strings.Join(parts, "  "))
}

func pleskCompactSections(app model.AppInstance, iw int) string {
	dm := app.DeepMetrics
	var sections []compactSection

	// Services
	svcStatus := "OK"
	if f, _ := strconv.Atoi(dm["services_failed"]); f > 0 {
		svcStatus = "CRIT"
	}
	svcSum := dm["services_running"] + " running"
	if f := dm["services_failed"]; f != "" && f != "0" {
		names := dm["services_down_names"]
		if names != "" {
			svcSum += ", DOWN: " + names
		} else {
			svcSum += ", " + f + " failed"
		}
	}
	sections = append(sections, compactSection{"Services", svcStatus, svcSum})

	// Domains & Hosting
	domSum := dm["domains"] + " domains"
	if s := dm["suspended_domains"]; s != "" && s != "0" {
		domSum += ", " + s + " suspended"
	}
	if h := dm["hosting_subscriptions"]; h != "" {
		domSum += ", " + h + " hosting"
	}
	sections = append(sections, compactSection{"Domains", "OK", domSum})

	// PHP-FPM
	if p := dm["php_pools_total"]; p != "" && p != "0" {
		phpSum := p + " pools"
		for _, ver := range []string{"81", "82", "83", "84"} {
			if v := dm["php"+ver+"_pools"]; v != "" && v != "0" {
				phpSum += ", PHP " + ver[:1] + "." + ver[1:] + "=" + v
			}
		}
		sections = append(sections, compactSection{"PHP-FPM", "OK", phpSum})
	}

	// Mail
	mailSum := ""
	if ma := dm["mail_accounts"]; ma != "" {
		mailSum = ma + " accounts"
	}
	mailStatus := "OK"
	if mq := dm["mail_queue"]; mq != "" && mq != "0" {
		if mailSum != "" {
			mailSum += ", "
		}
		mailSum += "queue " + mq
		if q, _ := strconv.Atoi(mq); q > 100 {
			mailStatus = "WARN"
		}
	}
	if mailSum != "" {
		sections = append(sections, compactSection{"Mail", mailStatus, mailSum})
	}

	// Databases
	if d := dm["databases"]; d != "" {
		sections = append(sections, compactSection{"Databases", "OK", d + " databases"})
	}

	// Certificates (informational — expired certs are normal for unused domains)
	certSum := dm["cert_total"] + " certs"
	if ok := dm["certs_ok"]; ok != "" && ok != "0" {
		certSum += ", " + ok + " valid"
	}
	if exp := dm["certs_expired"]; exp != "" && exp != "0" {
		certSum += ", " + exp + " expired"
	}
	if expiring := dm["certs_expiring"]; expiring != "" && expiring != "0" {
		certSum += ", " + expiring + " expiring"
	}
	if dm["cert_total"] != "" && dm["cert_total"] != "0" {
		sections = append(sections, compactSection{"Certificates", "OK", certSum})
	}

	// Security (Imunify)
	if dm["imunify_status"] == "active" {
		imStatus := "OK"
		imSum := "Imunify360 active"
		if inf, _ := strconv.Atoi(dm["imunify_infected"]); inf > 0 {
			imStatus = "CRIT"
			imSum += ", " + dm["imunify_infected"] + " infected"
		}
		sections = append(sections, compactSection{"Security", imStatus, imSum})
	}

	// Disk
	diskParts := []string{}
	if v := dm["disk_vhosts_mb"]; v != "" {
		mb, _ := strconv.Atoi(v)
		if mb > 1024 {
			diskParts = append(diskParts, fmt.Sprintf("vhosts %.1fG", float64(mb)/1024))
		} else {
			diskParts = append(diskParts, "vhosts "+v+"M")
		}
	}
	if v := dm["disk_mysql_mb"]; v != "" {
		mb, _ := strconv.Atoi(v)
		if mb > 1024 {
			diskParts = append(diskParts, fmt.Sprintf("mysql %.1fG", float64(mb)/1024))
		} else {
			diskParts = append(diskParts, "mysql "+v+"M")
		}
	}
	if v := dm["disk_mail_mb"]; v != "" {
		mb, _ := strconv.Atoi(v)
		if mb > 1024 {
			diskParts = append(diskParts, fmt.Sprintf("mail %.1fG", float64(mb)/1024))
		} else {
			diskParts = append(diskParts, "mail "+v+"M")
		}
	}
	if len(diskParts) > 0 {
		sections = append(sections, compactSection{"Disk Usage", "OK", strings.Join(diskParts, ", ")})
	}

	// Web Traffic
	webParts := []string{}
	if v := dm["http_connections"]; v != "" && v != "0" {
		webParts = append(webParts, v+" HTTP")
	}
	if v := dm["https_connections"]; v != "" && v != "0" {
		webParts = append(webParts, v+" HTTPS")
	}
	if len(webParts) > 0 {
		sections = append(sections, compactSection{"Web Traffic", "OK", strings.Join(webParts, ", ") + " active conns"})
	}

	return "\n" + renderCompactSectionList(sections, iw)
}
