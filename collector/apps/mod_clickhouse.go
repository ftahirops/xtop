//go:build linux

package apps

import (
	"context"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/ftahirops/xtop/model"
)

// ClickHouse — column-store OLAP database. Process is named
// "clickhouse-serv" (truncated to 15 chars in /proc/<pid>/comm), with
// the watchdog appearing as "clickhouse-watc". The native client
// protocol listens on port 9000 by default; the MySQL-compatibility
// port is 9004, PostgreSQL-compat is 9005, HTTP is 8123, secure HTTP
// 8443.
//
// Tier 1 metrics come from /proc.
// Tier 2 metrics come from clickhouse-client running queries against
// system.* tables — credentials configurable via secrets.ClickHouse,
// otherwise we try the unauthenticated default user (which works on
// many out-of-the-box installs).
type clickhouseModule struct{}

func NewClickHouseModule() AppModule { return &clickhouseModule{} }

func (m *clickhouseModule) Type() string        { return "clickhouse" }
func (m *clickhouseModule) DisplayName() string { return "ClickHouse" }

func (m *clickhouseModule) Detect(processes []model.ProcessMetrics) []DetectedApp {
	// Candidates: every process whose truncated comm is "clickhouse-serv".
	// We pick ONE per listening port — typically the watchdog spawns the
	// real server which spawns helper processes that all share argv[0].
	// Picking by lowest PID gives us the parent (most-stable, longest-lived).
	type cand struct {
		pid     int
		port    int
		cmdline string
		comm    string
	}
	byPort := map[int]cand{}
	for _, p := range processes {
		if p.Comm != "clickhouse-serv" {
			continue
		}
		cmdline := readProcCmdline(p.PID)
		if !strings.Contains(cmdline, "config.xml") &&
			!strings.Contains(cmdline, "--config") {
			continue
		}
		if strings.Contains(cmdline, "watchdog") {
			continue
		}
		port := 9000
		for _, f := range strings.Fields(cmdline) {
			if strings.HasPrefix(f, "--tcp_port=") {
				if v, err := strconv.Atoi(strings.TrimPrefix(f, "--tcp_port=")); err == nil {
					port = v
				}
			}
		}
		existing, ok := byPort[port]
		if !ok || p.PID < existing.pid {
			byPort[port] = cand{pid: p.PID, port: port, cmdline: cmdline, comm: p.Comm}
		}
	}
	var detected []DetectedApp
	for _, c := range byPort {
		detected = append(detected, DetectedApp{
			PID:     c.pid,
			Port:    c.port,
			Comm:    c.comm,
			Cmdline: c.cmdline,
			Index:   len(detected),
		})
	}
	return detected
}

func (m *clickhouseModule) Collect(app *DetectedApp, secrets *AppSecrets) model.AppInstance {
	inst := model.AppInstance{
		AppType:     "clickhouse",
		DisplayName: "ClickHouse",
		PID:         app.PID,
		Port:        app.Port,
		Status:      "active",
		UptimeSec:   readProcUptime(app.PID),
		DeepMetrics: make(map[string]string),
	}

	// Tier 1: /proc-derived process metrics.
	inst.RSSMB = readProcRSS(app.PID)
	inst.Threads = readProcThreads(app.PID)
	inst.FDs = readProcFDs(app.PID)
	inst.Connections = countTCPConnections(app.Port)
	inst.CPUPct = readProcCPUPct(app.PID, inst.UptimeSec)

	// Config + version: try /etc/clickhouse-server/config.xml first.
	confPath := findConfigFile([]string{
		"/etc/clickhouse-server/config.xml",
		"/etc/clickhouse/config.xml",
	})
	inst.ConfigPath = confPath

	// Tier 2: deep metrics via clickhouse-client. Falls back gracefully
	// if the binary isn't on PATH or auth fails — we set NeedsCreds
	// so the UI shows the operator how to add credentials.
	collectClickhouseDeepMetrics(&inst, secrets)
	return inst
}

// chQuery runs `clickhouse-client --query` with a short timeout. Uses
// configured credentials when present; otherwise tries the default
// (unauthenticated) user against 127.0.0.1.
func chQuery(secrets *AppSecrets, query string) (string, error) {
	bin, err := exec.LookPath("clickhouse-client")
	if err != nil {
		// Some installs ship `clickhouse` with a `client` subcommand.
		if bin2, err2 := exec.LookPath("clickhouse"); err2 == nil {
			bin = bin2
		} else {
			return "", err
		}
	}
	args := []string{}
	host := "127.0.0.1"
	port := 9000
	user := ""
	pass := ""
	db := ""
	if secrets != nil && secrets.ClickHouse != nil {
		ch := secrets.ClickHouse
		if ch.Host != "" {
			host = ch.Host
		}
		if ch.Port > 0 {
			port = ch.Port
		}
		user = ch.User
		pass = ch.Password
		db = ch.DBName
	}
	args = append(args, "--host", host, "--port", strconv.Itoa(port))
	if user != "" {
		args = append(args, "--user", user)
	}
	if pass != "" {
		args = append(args, "--password", pass)
	}
	if db != "" {
		args = append(args, "--database", db)
	}
	args = append(args, "--query", query, "--format", "TabSeparated")

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, args...)
	if strings.HasSuffix(bin, "/clickhouse") {
		// `clickhouse client --host ...` rather than `clickhouse-client ...`
		cmd = exec.CommandContext(ctx, bin, append([]string{"client"}, args...)...)
	}
	out, err := cmd.Output()
	return strings.TrimSpace(string(out)), err
}

// collectClickhouseDeepMetrics fills inst.DeepMetrics with the
// signals operators care about: version, query counts, memory,
// replication, slow queries, merges.
func collectClickhouseDeepMetrics(inst *model.AppInstance, secrets *AppSecrets) {
	dm := inst.DeepMetrics
	any := false

	// 1. Version.
	if out, err := chQuery(secrets, "SELECT version()"); err == nil && out != "" {
		any = true
		inst.Version = strings.TrimSpace(out)
		dm["version"] = inst.Version
	}

	// 2. Currently-running queries + active mutations.
	if out, err := chQuery(secrets, "SELECT count() FROM system.processes"); err == nil && out != "" {
		any = true
		dm["active_queries"] = strings.TrimSpace(out)
	}
	if out, err := chQuery(secrets, "SELECT count() FROM system.mutations WHERE NOT is_done"); err == nil && out != "" {
		any = true
		dm["pending_mutations"] = strings.TrimSpace(out)
	}

	// 3. Background merges in flight — high counts mean ingest is
	// outpacing compaction, eventually causing query slowdown.
	if out, err := chQuery(secrets, "SELECT count() FROM system.merges"); err == nil && out != "" {
		any = true
		dm["active_merges"] = strings.TrimSpace(out)
	}

	// 4. Replication queue depth (per-table). If non-zero across many
	// tables, the replica is falling behind.
	if out, err := chQuery(secrets,
		"SELECT count() FROM system.replication_queue"); err == nil && out != "" {
		any = true
		dm["replication_queue"] = strings.TrimSpace(out)
	}
	if out, err := chQuery(secrets,
		"SELECT count() FROM system.replicas WHERE is_readonly OR future_parts > 100"); err == nil && out != "" {
		any = true
		dm["replicas_degraded"] = strings.TrimSpace(out)
	}

	// 5. Server-side memory tracker (much more accurate than RSS for
	// CH — it counts query caches, mark cache, primary-key cache).
	if out, err := chQuery(secrets,
		"SELECT value FROM system.asynchronous_metrics WHERE metric='MemoryResident'"); err == nil && out != "" {
		any = true
		if v, err := strconv.ParseFloat(strings.TrimSpace(out), 64); err == nil {
			dm["memory_resident_mb"] = fmt.Sprintf("%.0f", v/1024.0/1024.0)
		}
	}

	// 6. Query throughput (system.events delta over server uptime).
	// We just report the total; rate can be derived by the engine.
	if out, err := chQuery(secrets,
		"SELECT value FROM system.events WHERE event='Query'"); err == nil && out != "" {
		any = true
		dm["queries_total"] = strings.TrimSpace(out)
	}
	if out, err := chQuery(secrets,
		"SELECT value FROM system.events WHERE event='FailedQuery'"); err == nil && out != "" {
		any = true
		dm["queries_failed"] = strings.TrimSpace(out)
	}

	// 7. Slow query indicator — queries currently running > 30s.
	if out, err := chQuery(secrets,
		"SELECT count() FROM system.processes WHERE elapsed > 30"); err == nil && out != "" {
		any = true
		dm["long_running_queries"] = strings.TrimSpace(out)
	}

	// 8. Database / part counts (top databases by size).
	if out, err := chQuery(secrets,
		"SELECT database, formatReadableSize(sum(bytes_on_disk)) FROM system.parts WHERE active GROUP BY database ORDER BY sum(bytes_on_disk) DESC LIMIT 3"); err == nil && out != "" {
		any = true
		var sizes []string
		for _, line := range strings.Split(out, "\n") {
			parts := strings.SplitN(line, "\t", 2)
			if len(parts) == 2 {
				sizes = append(sizes, parts[0]+"="+parts[1])
			}
		}
		if len(sizes) > 0 {
			dm["database_sizes"] = strings.Join(sizes, ", ")
		}
	}

	// 9. Detached parts — typically a sign of past corruption.
	if out, err := chQuery(secrets,
		"SELECT count() FROM system.detached_parts"); err == nil && out != "" {
		any = true
		dm["detached_parts"] = strings.TrimSpace(out)
	}

	// 10. ZooKeeper sessions (replicated installs only).
	if out, err := chQuery(secrets,
		"SELECT count() FROM system.zookeeper_connection"); err == nil && out != "" {
		any = true
		dm["zookeeper_connections"] = strings.TrimSpace(out)
	}

	// 11. Database count + total parts + total rows.
	if out, err := chQuery(secrets,
		"SELECT count(DISTINCT database), count(), sum(rows) FROM system.parts WHERE active"); err == nil && out != "" {
		any = true
		parts := strings.Split(out, "\t")
		if len(parts) == 3 {
			dm["databases"] = strings.TrimSpace(parts[0])
			dm["active_parts"] = strings.TrimSpace(parts[1])
			dm["total_rows"] = strings.TrimSpace(parts[2])
		}
	}

	// 12. Top 3 tables by size — actionable for capacity planning.
	if out, err := chQuery(secrets,
		"SELECT database||'.'||table, formatReadableSize(sum(bytes_on_disk)), sum(rows) "+
			"FROM system.parts WHERE active GROUP BY database,table "+
			"ORDER BY sum(bytes_on_disk) DESC LIMIT 3"); err == nil && out != "" {
		any = true
		var lines []string
		for _, line := range strings.Split(out, "\n") {
			f := strings.Split(line, "\t")
			if len(f) == 3 {
				lines = append(lines, fmt.Sprintf("%s=%s/%s rows",
					f[0], strings.TrimSpace(f[1]), strings.TrimSpace(f[2])))
			}
		}
		if len(lines) > 0 {
			dm["top_tables"] = strings.Join(lines, ", ")
		}
	}

	// 13. Top 3 query patterns by total elapsed time — what the cluster
	// is actually spending time on. Uses query_log (must be enabled,
	// which it is by default in modern CH).
	if out, err := chQuery(secrets,
		"SELECT normalized_query_hash, any(substring(query,1,80)), count(), "+
			"round(sum(query_duration_ms)/1000,1) as total_s, "+
			"round(avg(query_duration_ms),0) as avg_ms "+
			"FROM system.query_log "+
			"WHERE type='QueryFinish' AND event_time > now() - INTERVAL 1 HOUR "+
			"GROUP BY normalized_query_hash ORDER BY total_s DESC LIMIT 3"); err == nil && out != "" {
		any = true
		var lines []string
		for _, line := range strings.Split(out, "\n") {
			f := strings.Split(line, "\t")
			if len(f) >= 5 {
				q := strings.TrimSpace(f[1])
				q = strings.ReplaceAll(q, "\n", " ")
				lines = append(lines, fmt.Sprintf("[%s× avg %sms] %s",
					strings.TrimSpace(f[2]), strings.TrimSpace(f[4]), q))
			}
		}
		if len(lines) > 0 {
			dm["top_queries_1h"] = strings.Join(lines, "  ║  ")
		}
	}

	// 14. Recent error count (last 5 minutes) — quick health pulse.
	if out, err := chQuery(secrets,
		"SELECT count() FROM system.errors WHERE last_error_time > now() - INTERVAL 5 MINUTE"); err == nil && out != "" {
		any = true
		dm["errors_5min"] = strings.TrimSpace(out)
	}

	// 15. Top recent error name — what's actually failing.
	if out, err := chQuery(secrets,
		"SELECT name, value FROM system.errors "+
			"WHERE last_error_time > now() - INTERVAL 1 HOUR "+
			"ORDER BY value DESC LIMIT 1"); err == nil && out != "" {
		any = true
		f := strings.Split(out, "\t")
		if len(f) == 2 {
			dm["top_error"] = fmt.Sprintf("%s (×%s)",
				strings.TrimSpace(f[0]), strings.TrimSpace(f[1]))
		}
	}

	// 16. Cache hit ratios — mark cache + uncompressed cache. Both
	// are critical for query performance.
	if out, err := chQuery(secrets,
		"SELECT "+
			"sum(if(event='MarkCacheHits', value, 0)) as mh, "+
			"sum(if(event='MarkCacheMisses', value, 0)) as mm, "+
			"sum(if(event='UncompressedCacheHits', value, 0)) as uh, "+
			"sum(if(event='UncompressedCacheMisses', value, 0)) as um "+
			"FROM system.events"); err == nil && out != "" {
		any = true
		f := strings.Split(out, "\t")
		if len(f) == 4 {
			mh, _ := strconv.ParseFloat(strings.TrimSpace(f[0]), 64)
			mm, _ := strconv.ParseFloat(strings.TrimSpace(f[1]), 64)
			uh, _ := strconv.ParseFloat(strings.TrimSpace(f[2]), 64)
			um, _ := strconv.ParseFloat(strings.TrimSpace(f[3]), 64)
			if mh+mm > 0 {
				dm["mark_cache_hit_pct"] = fmt.Sprintf("%.1f", mh/(mh+mm)*100)
			}
			if uh+um > 0 {
				dm["uncompressed_cache_hit_pct"] = fmt.Sprintf("%.1f", uh/(uh+um)*100)
			}
		}
	}

	// 17. Async insert queue depth — when ingest backs up this rises.
	if out, err := chQuery(secrets,
		"SELECT count() FROM system.asynchronous_inserts"); err == nil && out != "" {
		any = true
		dm["async_insert_queue"] = strings.TrimSpace(out)
	}

	// 18. Optimization recommendations — derived inline rather than
	// shipping a separate analyzer. Each rule is one-liner heuristics
	// drawn from ClickHouse field experience.
	var recs []string
	if v, ok := dm["mark_cache_hit_pct"]; ok {
		f, _ := strconv.ParseFloat(v, 64)
		if f < 90 {
			recs = append(recs, fmt.Sprintf(
				"increase mark_cache_size (current hit ratio %.1f%% — should be >95%%)", f))
		}
	}
	if v, ok := dm["active_merges"]; ok {
		n, _ := strconv.Atoi(v)
		if n > 30 {
			recs = append(recs,
				"consider raising background_pool_size (active merges high — ingest outpacing compaction)")
		}
	}
	if v, ok := dm["long_running_queries"]; ok {
		n, _ := strconv.Atoi(v)
		if n > 0 {
			recs = append(recs, fmt.Sprintf(
				"%d queries running >30s — inspect system.processes and consider max_execution_time", n))
		}
	}
	if v, ok := dm["async_insert_queue"]; ok {
		n, _ := strconv.Atoi(v)
		if n > 100 {
			recs = append(recs,
				"async-insert queue backed up — increase async_insert_threads or reduce ingest")
		}
	}
	if v, ok := dm["detached_parts"]; ok {
		n, _ := strconv.Atoi(v)
		if n > 0 {
			recs = append(recs, fmt.Sprintf(
				"%d detached parts (past corruption) — review /var/lib/clickhouse/.../detached/", n))
		}
	}
	if len(recs) > 0 {
		dm["recommendations"] = strings.Join(recs, " ║ ")
	}

	if any {
		inst.HasDeepMetrics = true
		inst.NeedsCreds = false
	} else {
		inst.NeedsCreds = true
		// Probe once to capture WHY no deep metrics — typical reasons:
		// auth failure (password required), clickhouse-client missing,
		// host:port wrong. The page-apps rendering reads tier2_skipped
		// and shows it inline, so the operator sees a specific cause
		// instead of the generic "deep metrics paused".
		if _, err := chQuery(secrets, "SELECT 1"); err != nil {
			msg := err.Error()
			switch {
			case strings.Contains(msg, "Authentication failed"),
				strings.Contains(msg, "password is incorrect"):
				inst.DeepMetrics["tier2_skipped"] =
					"auth-required — add ClickHouse creds to /root/.xtop_secrets"
			case strings.Contains(msg, "executable file not found"),
				strings.Contains(msg, "no such file"):
				inst.DeepMetrics["tier2_skipped"] = "clickhouse-client not on PATH"
			case strings.Contains(msg, "Connection refused"):
				inst.DeepMetrics["tier2_skipped"] = "connection refused on configured host:port"
			default:
				inst.DeepMetrics["tier2_skipped"] = "probe failed: " + truncErr(msg, 80)
			}
		}
	}

	// Health scoring — start at 100, dock per issue, similar pattern
	// to mod_postgresql so the UI's HealthScore column is comparable.
	inst.HealthScore = 100
	if !inst.HasDeepMetrics {
		return
	}

	if v, ok := dm["long_running_queries"]; ok {
		n, _ := strconv.Atoi(v)
		if n > 0 {
			inst.HealthScore -= 10
			inst.HealthIssues = append(inst.HealthIssues,
				fmt.Sprintf("Long-running queries (>30s): %d", n))
		}
	}
	if v, ok := dm["active_merges"]; ok {
		n, _ := strconv.Atoi(v)
		if n > 50 {
			inst.HealthScore -= 15
			inst.HealthIssues = append(inst.HealthIssues,
				fmt.Sprintf("Excessive background merges: %d (ingest outpacing compaction)", n))
		} else if n > 20 {
			inst.HealthScore -= 5
		}
	}
	if v, ok := dm["replication_queue"]; ok {
		n, _ := strconv.Atoi(v)
		if n > 100 {
			inst.HealthScore -= 20
			inst.HealthIssues = append(inst.HealthIssues,
				fmt.Sprintf("Replication queue backlog: %d entries", n))
		}
	}
	if v, ok := dm["replicas_degraded"]; ok {
		n, _ := strconv.Atoi(v)
		if n > 0 {
			inst.HealthScore -= 25
			inst.HealthIssues = append(inst.HealthIssues,
				fmt.Sprintf("Replicas in degraded state: %d", n))
		}
	}
	if v, ok := dm["detached_parts"]; ok {
		n, _ := strconv.Atoi(v)
		if n > 0 {
			inst.HealthScore -= 10
			inst.HealthIssues = append(inst.HealthIssues,
				fmt.Sprintf("Detached parts present: %d", n))
		}
	}
	if inst.HealthScore < 0 {
		inst.HealthScore = 0
	}
}

// truncErr trims an error message to width chars, single line.
func truncErr(s string, width int) string {
	s = strings.ReplaceAll(s, "\n", " ")
	if len(s) > width {
		s = s[:width-1] + "…"
	}
	return s
}
