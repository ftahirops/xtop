package collector

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ftahirops/xtop/model"
)

// DiagCollector runs per-service diagnostic analyzers.
type DiagCollector struct {
	interval time.Duration
	mu       sync.Mutex
	lastRun  time.Time
	cached   model.DiagMetrics
}

func (d *DiagCollector) Name() string { return "diag" }

func (d *DiagCollector) Collect(snap *model.Snapshot) error {
	if d.interval == 0 {
		d.interval = 30 * time.Second
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	if time.Since(d.lastRun) < d.interval && len(d.cached.Services) > 0 {
		snap.Global.Diagnostics = d.cached
		return nil
	}

	var services []model.ServiceDiag

	// Run all analyzers concurrently
	type result struct {
		svc model.ServiceDiag
	}
	ch := make(chan result, 7)

	analyzers := []func() model.ServiceDiag{
		DiagNginx, DiagApache, DiagMySQL, DiagPostgreSQL,
		DiagHAProxy, DiagRedis, DiagDocker,
	}
	for _, fn := range analyzers {
		fn := fn
		go func() { ch <- result{fn()} }()
	}
	for range analyzers {
		r := <-ch
		if r.svc.Available {
			services = append(services, r.svc)
		}
	}

	d.cached = model.DiagMetrics{Services: services}
	d.lastRun = time.Now()
	snap.Global.Diagnostics = d.cached
	return nil
}

// ─── Helpers ────────────────────────────────────────────────────────────────

// runCmd executes a command with a 3-second timeout and returns stdout.
func runCmd(name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// tailFile reads the last N lines of a file.
func tailFile(path string, n int) []string {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	var lines []string
	scanner := bufio.NewScanner(f)
	// Use a ring buffer approach
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
		if len(lines) > n*2 {
			lines = lines[len(lines)-n:]
		}
	}
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return lines
}

// addFinding appends a finding to a service diag and updates worst severity.
func addFinding(sd *model.ServiceDiag, sev model.DiagSeverity, cat, summary, detail, advice string) {
	sd.Findings = append(sd.Findings, model.DiagFinding{
		Severity: sev,
		Category: cat,
		Summary:  summary,
		Detail:   detail,
		Advice:   advice,
	})
	if sevRank(sev) > sevRank(sd.WorstSev) {
		sd.WorstSev = sev
	}
}

func sevRank(s model.DiagSeverity) int {
	switch s {
	case model.DiagCrit:
		return 3
	case model.DiagWarn:
		return 2
	case model.DiagInfo:
		return 1
	default:
		return 0
	}
}

// processRunning checks if a process is running via pgrep.
func processRunning(name string) bool {
	err := exec.Command("pgrep", "-x", name).Run()
	return err == nil
}

// parseKV parses "key\tvalue" or "key value" lines into a map.
func parseKV(text, sep string) map[string]string {
	m := make(map[string]string)
	for _, line := range strings.Split(text, "\n") {
		parts := strings.SplitN(line, sep, 2)
		if len(parts) == 2 {
			m[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
		}
	}
	return m
}

// atoiSafe converts string to int64 with fallback.
func atoiSafe(s string) int64 {
	n, _ := strconv.ParseInt(strings.TrimSpace(s), 10, 64)
	return n
}

// atofSafe converts string to float64 with fallback.
func atofSafe(s string) float64 {
	f, _ := strconv.ParseFloat(strings.TrimSpace(s), 64)
	return f
}

// ─── Nginx ──────────────────────────────────────────────────────────────────

// DiagNginx analyzes Nginx configuration and runtime status.
func DiagNginx() model.ServiceDiag {
	sd := model.ServiceDiag{
		Name:      "nginx",
		LastCheck: time.Now(),
		Metrics:   make(map[string]string),
		WorstSev:  model.DiagOK,
	}

	if !processRunning("nginx") {
		return sd
	}
	if _, err := exec.LookPath("nginx"); err != nil {
		return sd
	}
	sd.Available = true

	// Config syntax check
	out, err := runCmd("nginx", "-t")
	if err != nil {
		addFinding(&sd, model.DiagCrit, "config", "Config syntax error", out, "Fix nginx configuration and reload")
	} else {
		addFinding(&sd, model.DiagOK, "config", "Config syntax valid", "", "")
	}

	// Parse full config
	fullCfg, err := runCmd("nginx", "-T")
	if err == nil {
		// worker_processes
		if m := regexp.MustCompile(`worker_processes\s+(\S+)`).FindStringSubmatch(fullCfg); len(m) > 1 {
			sd.Metrics["workers"] = m[1]
			if m[1] == "1" && runtime.NumCPU() > 1 {
				addFinding(&sd, model.DiagWarn, "config",
					fmt.Sprintf("worker_processes=1 on %d-CPU host", runtime.NumCPU()),
					"Single worker cannot utilize multiple CPUs",
					"Set worker_processes auto or match CPU count")
			}
		}
		// worker_connections
		if m := regexp.MustCompile(`worker_connections\s+(\d+)`).FindStringSubmatch(fullCfg); len(m) > 1 {
			sd.Metrics["worker_conns"] = m[1]
		}
		// keepalive_timeout
		if m := regexp.MustCompile(`keepalive_timeout\s+(\S+)`).FindStringSubmatch(fullCfg); len(m) > 1 {
			sd.Metrics["keepalive"] = m[1]
		}
		// gzip
		if strings.Contains(fullCfg, "gzip on") {
			sd.Metrics["gzip"] = "on"
		} else {
			sd.Metrics["gzip"] = "off"
		}
		// client_max_body_size
		if m := regexp.MustCompile(`client_max_body_size\s+(\S+)`).FindStringSubmatch(fullCfg); len(m) > 1 {
			sd.Metrics["max_body"] = m[1]
		}
	}

	// Stub status
	statusOut, err := runCmd("curl", "-s", "--connect-timeout", "2", "http://localhost/nginx_status")
	if err == nil && strings.Contains(statusOut, "Active connections") {
		lines := strings.Split(statusOut, "\n")
		for _, l := range lines {
			l = strings.TrimSpace(l)
			if strings.HasPrefix(l, "Active connections:") {
				val := strings.TrimPrefix(l, "Active connections:")
				val = strings.TrimSpace(val)
				sd.Metrics["active"] = val
				n := atoiSafe(val)
				if n > 500 {
					addFinding(&sd, model.DiagWarn, "performance",
						fmt.Sprintf("High active connections: %d", n),
						"", "Check for connection leak or increase capacity")
				}
			}
			if fields := strings.Fields(l); len(fields) == 3 {
				// Reading: X Writing: Y Waiting: Z — but it's actually "Reading: X Writing: Y Waiting: Z"
				if strings.HasPrefix(l, "Reading:") {
					parts := strings.Fields(l)
					if len(parts) >= 6 {
						sd.Metrics["reading"] = parts[1]
						sd.Metrics["writing"] = parts[3]
						sd.Metrics["waiting"] = parts[5]
					}
				}
			}
		}
	}

	// Error log
	errLines := tailFile("/var/log/nginx/error.log", 50)
	if len(errLines) > 0 {
		errCount := 0
		critCount := 0
		for _, l := range errLines {
			if strings.Contains(l, "[error]") {
				errCount++
			}
			if strings.Contains(l, "[crit]") || strings.Contains(l, "[emerg]") {
				critCount++
			}
		}
		if critCount > 0 {
			addFinding(&sd, model.DiagCrit, "logs",
				fmt.Sprintf("%d critical/emergency errors in error.log", critCount),
				"", "Check /var/log/nginx/error.log immediately")
		} else if errCount > 5 {
			addFinding(&sd, model.DiagWarn, "logs",
				fmt.Sprintf("%d errors in last 50 lines of error.log", errCount),
				"", "Check /var/log/nginx/error.log")
		}
	}

	// Access log 5xx analysis
	accLines := tailFile("/var/log/nginx/access.log", 200)
	if len(accLines) > 0 {
		total := 0
		count5xx := 0
		count4xx := 0
		re := regexp.MustCompile(`" (\d{3}) `)
		for _, l := range accLines {
			if m := re.FindStringSubmatch(l); len(m) > 1 {
				total++
				code, _ := strconv.Atoi(m[1])
				if code >= 500 {
					count5xx++
				} else if code >= 400 {
					count4xx++
				}
			}
		}
		if total > 0 {
			pct5xx := float64(count5xx) / float64(total) * 100
			sd.Metrics["5xx"] = fmt.Sprintf("%.1f%%", pct5xx)
			sd.Metrics["4xx"] = fmt.Sprintf("%.1f%%", float64(count4xx)/float64(total)*100)
			if pct5xx > 10 {
				addFinding(&sd, model.DiagCrit, "performance",
					fmt.Sprintf("5xx rate: %.1f%% (%d/%d)", pct5xx, count5xx, total),
					"", "Check upstream servers and error.log")
			} else if pct5xx > 2 {
				addFinding(&sd, model.DiagWarn, "performance",
					fmt.Sprintf("5xx rate: %.1f%% (%d/%d)", pct5xx, count5xx, total),
					"", "Monitor upstream health")
			}
		}
	}

	return sd
}

// ─── Apache ─────────────────────────────────────────────────────────────────

// DiagApache analyzes Apache configuration and runtime status.
func DiagApache() model.ServiceDiag {
	sd := model.ServiceDiag{
		Name:      "apache",
		LastCheck: time.Now(),
		Metrics:   make(map[string]string),
		WorstSev:  model.DiagOK,
	}

	if !processRunning("apache2") && !processRunning("httpd") {
		return sd
	}
	apachectl := "apachectl"
	if _, err := exec.LookPath("apachectl"); err != nil {
		if _, err := exec.LookPath("apache2ctl"); err != nil {
			return sd
		}
		apachectl = "apache2ctl"
	}
	sd.Available = true

	// Config syntax
	out, err := runCmd(apachectl, "-t")
	if err != nil {
		addFinding(&sd, model.DiagCrit, "config", "Config syntax error", out, "Fix Apache configuration")
	} else {
		addFinding(&sd, model.DiagOK, "config", "Config syntax valid", "", "")
	}

	// MPM type
	vOut, err := runCmd(apachectl, "-V")
	if err == nil {
		if m := regexp.MustCompile(`(?i)Server MPM:\s+(\S+)`).FindStringSubmatch(vOut); len(m) > 1 {
			mpm := strings.ToLower(m[1])
			sd.Metrics["mpm"] = mpm
			if mpm == "prefork" {
				addFinding(&sd, model.DiagWarn, "config",
					"Using prefork MPM",
					"prefork uses one process per connection, limiting scalability",
					"Consider switching to event or worker MPM")
			}
		}
	}

	// Error log
	errPaths := []string{
		"/var/log/apache2/error.log",
		"/var/log/httpd/error_log",
	}
	for _, p := range errPaths {
		errLines := tailFile(p, 50)
		if len(errLines) > 0 {
			errCount := 0
			for _, l := range errLines {
				if strings.Contains(l, "[error]") || strings.Contains(l, "[:error]") {
					errCount++
				}
			}
			if errCount > 5 {
				addFinding(&sd, model.DiagWarn, "logs",
					fmt.Sprintf("%d errors in last 50 lines", errCount),
					"", fmt.Sprintf("Check %s", p))
			}
			break
		}
	}

	// MaxRequestWorkers from config
	cfgOut, err := runCmd(apachectl, "-t", "-D", "DUMP_RUN_CFG")
	if err == nil {
		if m := regexp.MustCompile(`MaxRequestWorkers:\s+(\d+)`).FindStringSubmatch(cfgOut); len(m) > 1 {
			sd.Metrics["max_workers"] = m[1]
			n := atoiSafe(m[1])
			if n > 0 && n < 150 {
				addFinding(&sd, model.DiagWarn, "config",
					fmt.Sprintf("MaxRequestWorkers=%d (low)", n),
					"", "Consider increasing MaxRequestWorkers for production")
			}
		}
	}

	return sd
}

// ─── MySQL / MariaDB ────────────────────────────────────────────────────────

// DiagMySQL analyzes MySQL/MariaDB configuration, performance and replication.
func DiagMySQL() model.ServiceDiag {
	sd := model.ServiceDiag{
		Name:      "mysql",
		LastCheck: time.Now(),
		Metrics:   make(map[string]string),
		WorstSev:  model.DiagOK,
	}

	if !processRunning("mysqld") && !processRunning("mariadbd") {
		return sd
	}
	if _, err := exec.LookPath("mysql"); err != nil {
		return sd
	}
	sd.Available = true

	// SHOW GLOBAL STATUS
	statusOut, err := runCmd("mysql", "-N", "-e", "SHOW GLOBAL STATUS")
	if err != nil {
		addFinding(&sd, model.DiagWarn, "connections", "Cannot connect to MySQL", err.Error(),
			"Check MySQL socket/permissions: mysql -N -e 'SELECT 1'")
		return sd
	}

	status := parseKV(statusOut, "\t")

	// SHOW GLOBAL VARIABLES
	varOut, _ := runCmd("mysql", "-N", "-e", "SHOW GLOBAL VARIABLES")
	vars := parseKV(varOut, "\t")

	// Connection analysis
	maxConn := atoiSafe(vars["max_connections"])
	threadsConn := atoiSafe(status["Threads_connected"])
	if maxConn > 0 {
		connPct := float64(threadsConn) / float64(maxConn) * 100
		sd.Metrics["conns"] = fmt.Sprintf("%d/%d(%.0f%%)", threadsConn, maxConn, connPct)
		if connPct > 95 {
			addFinding(&sd, model.DiagCrit, "connections",
				fmt.Sprintf("Connections near limit: %d/%d (%.0f%%)", threadsConn, maxConn, connPct),
				"", "Increase max_connections or investigate connection leaks")
		} else if connPct > 80 {
			addFinding(&sd, model.DiagWarn, "connections",
				fmt.Sprintf("Connections high: %d/%d (%.0f%%)", threadsConn, maxConn, connPct),
				"", "Monitor connection count; consider connection pooling")
		} else {
			addFinding(&sd, model.DiagOK, "connections",
				fmt.Sprintf("Connections: %.1f%%", connPct), "", "")
		}
	}

	// Buffer pool hit ratio
	poolReads := atoiSafe(status["Innodb_buffer_pool_reads"])
	poolReqs := atoiSafe(status["Innodb_buffer_pool_read_requests"])
	if poolReqs > 0 {
		hitRatio := (1.0 - float64(poolReads)/float64(poolReqs)) * 100
		sd.Metrics["hit"] = fmt.Sprintf("%.1f%%", hitRatio)
		if hitRatio < 95 {
			addFinding(&sd, model.DiagCrit, "performance",
				fmt.Sprintf("Buffer pool hit ratio: %.1f%%", hitRatio),
				"", "Increase innodb_buffer_pool_size")
		} else if hitRatio < 99 {
			addFinding(&sd, model.DiagWarn, "performance",
				fmt.Sprintf("Buffer pool hit ratio: %.1f%%", hitRatio),
				"", "Consider increasing innodb_buffer_pool_size")
		} else {
			addFinding(&sd, model.DiagOK, "performance",
				fmt.Sprintf("Buffer pool hit: %.1f%%", hitRatio), "", "")
		}
	}

	// Buffer pool size
	poolSize := atoiSafe(vars["innodb_buffer_pool_size"])
	if poolSize > 0 {
		poolMB := poolSize / (1024 * 1024)
		sd.Metrics["pool_mb"] = fmt.Sprintf("%dM", poolMB)
		if poolMB < 128 {
			addFinding(&sd, model.DiagWarn, "memory",
				fmt.Sprintf("InnoDB buffer pool only %dMB", poolMB),
				"", "Increase innodb_buffer_pool_size (typically 50-80% of RAM)")
		}
	}

	// Slow queries
	slowQ := atoiSafe(status["Slow_queries"])
	uptime := atoiSafe(status["Uptime"])
	if uptime > 0 {
		slowPerMin := float64(slowQ) / (float64(uptime) / 60.0)
		sd.Metrics["slow"] = fmt.Sprintf("%d", slowQ)
		if slowPerMin > 1 {
			addFinding(&sd, model.DiagWarn, "performance",
				fmt.Sprintf("Slow queries: %d total (%.1f/min)", slowQ, slowPerMin),
				"", "Enable slow_query_log and optimize queries")
		}
	}

	// SHOW PROCESSLIST — long running queries
	plOut, err := runCmd("mysql", "-N", "-e", "SHOW PROCESSLIST")
	if err == nil {
		longCount := 0
		for _, line := range strings.Split(plOut, "\n") {
			fields := strings.Split(line, "\t")
			if len(fields) >= 6 {
				timeSec := atoiSafe(fields[5])
				if timeSec > 30 && fields[4] != "Sleep" {
					longCount++
					if timeSec > 60 {
						addFinding(&sd, model.DiagCrit, "performance",
							fmt.Sprintf("Query running for %ds: %s", timeSec, truncStr(fields[len(fields)-1], 60)),
							"", "Check SHOW PROCESSLIST and consider killing the query")
					}
				}
			}
		}
		if longCount > 0 {
			addFinding(&sd, model.DiagWarn, "performance",
				fmt.Sprintf("%d queries running >30s", longCount),
				"", "Check SHOW PROCESSLIST")
		}
	}

	// Replication status
	replOut, err := runCmd("mysql", "-N", "-e", "SHOW SLAVE STATUS\\G")
	if err == nil && strings.Contains(replOut, "Slave_IO_Running") {
		replKV := make(map[string]string)
		for _, line := range strings.Split(replOut, "\n") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				replKV[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
			}
		}
		ioRunning := replKV["Slave_IO_Running"]
		sqlRunning := replKV["Slave_SQL_Running"]
		if ioRunning != "Yes" || sqlRunning != "Yes" {
			addFinding(&sd, model.DiagCrit, "replication",
				fmt.Sprintf("Replication broken: IO=%s SQL=%s", ioRunning, sqlRunning),
				"", "Check SHOW SLAVE STATUS\\G for errors")
		}
		lag := atoiSafe(replKV["Seconds_Behind_Master"])
		if lag > 300 {
			addFinding(&sd, model.DiagCrit, "replication",
				fmt.Sprintf("Replication lag: %ds", lag),
				"", "Investigate IO/SQL thread performance")
		} else if lag > 30 {
			addFinding(&sd, model.DiagWarn, "replication",
				fmt.Sprintf("Replication lag: %ds", lag),
				"", "Monitor replication lag trend")
		}
	}

	return sd
}

// ─── PostgreSQL ─────────────────────────────────────────────────────────────

// DiagPostgreSQL analyzes PostgreSQL connections, cache, and table health.
func DiagPostgreSQL() model.ServiceDiag {
	sd := model.ServiceDiag{
		Name:      "postgresql",
		LastCheck: time.Now(),
		Metrics:   make(map[string]string),
		WorstSev:  model.DiagOK,
	}

	if !processRunning("postgres") {
		return sd
	}
	if _, err := exec.LookPath("psql"); err != nil {
		return sd
	}
	sd.Available = true

	// Check connection — try sudo -u postgres first (peer auth), fall back to -U postgres
	psqlCmd := "psql"

	// Test connectivity: prefer sudo -u postgres for peer auth
	_, err := runCmd("sudo", "-u", "postgres", "psql", "-t", "-A", "-c", "SELECT 1")
	if err == nil {
		psqlCmd = "sudo"
	} else {
		// Fall back to direct psql -U postgres
		_, err = runCmd("psql", "-U", "postgres", "-t", "-A", "-c", "SELECT 1")
		if err != nil {
			addFinding(&sd, model.DiagWarn, "connections", "Cannot connect to PostgreSQL", err.Error(),
				"Check PostgreSQL authentication: sudo -u postgres psql -c 'SELECT 1'")
			return sd
		}
	}

	psqlArgs := func(query string) (string, []string) {
		if psqlCmd == "sudo" {
			return "sudo", []string{"-u", "postgres", "psql", "-t", "-A", "-c", query}
		}
		return "psql", []string{"-U", "postgres", "-t", "-A", "-c", query}
	}

	// max_connections
	cmd, args := psqlArgs("SHOW max_connections")
	maxOut, err := runCmd(cmd, args...)
	if err != nil {
		addFinding(&sd, model.DiagWarn, "connections", "Cannot query PostgreSQL", err.Error(), "")
		return sd
	}
	maxConn := atoiSafe(maxOut)
	sd.Metrics["max_conns"] = strings.TrimSpace(maxOut)

	// Connection states
	cmd, args = psqlArgs("SELECT state, count(*) FROM pg_stat_activity GROUP BY state")
	connOut, _ := runCmd(cmd, args...)
	connMap := make(map[string]int64)
	var totalConns int64
	for _, line := range strings.Split(connOut, "\n") {
		parts := strings.SplitN(line, "|", 2)
		if len(parts) == 2 {
			state := strings.TrimSpace(parts[0])
			cnt := atoiSafe(parts[1])
			connMap[state] = cnt
			totalConns += cnt
		}
	}
	activeConns := connMap["active"]
	idleConns := connMap["idle"]
	sd.Metrics["active"] = fmt.Sprintf("%d", activeConns)
	sd.Metrics["idle"] = fmt.Sprintf("%d", idleConns)

	if maxConn > 0 {
		activePct := float64(activeConns) / float64(maxConn) * 100
		idlePct := float64(idleConns) / float64(maxConn) * 100
		if activePct > 90 {
			addFinding(&sd, model.DiagCrit, "connections",
				fmt.Sprintf("Active connections at %.0f%% of max", activePct),
				"", "Increase max_connections or investigate query bottlenecks")
		}
		if idlePct > 50 {
			addFinding(&sd, model.DiagWarn, "connections",
				fmt.Sprintf("Idle connections: %d (%.0f%% of max)", idleConns, idlePct),
				"", "Consider using a connection pooler (pgbouncer)")
		}
		sd.Metrics["conn_pct"] = fmt.Sprintf("%.0f%%", float64(totalConns)/float64(maxConn)*100)
	}

	// Cache hit ratio
	cmd, args = psqlArgs("SELECT sum(blks_hit)::float/(sum(blks_hit)+sum(blks_read)+1) FROM pg_stat_database")
	hitOut, _ := runCmd(cmd, args...)
	hitRatio := atofSafe(hitOut) * 100
	if hitRatio > 0 {
		sd.Metrics["hit"] = fmt.Sprintf("%.1f%%", hitRatio)
		if hitRatio < 95 {
			addFinding(&sd, model.DiagCrit, "performance",
				fmt.Sprintf("Cache hit ratio: %.1f%%", hitRatio),
				"", "Increase shared_buffers")
		} else if hitRatio < 99 {
			addFinding(&sd, model.DiagWarn, "performance",
				fmt.Sprintf("Cache hit ratio: %.1f%%", hitRatio),
				"", "Consider increasing shared_buffers")
		} else {
			addFinding(&sd, model.DiagOK, "performance",
				fmt.Sprintf("Cache hit ratio: %.1f%%", hitRatio), "", "")
		}
	}

	// Deadlocks and temp files
	cmd, args = psqlArgs("SELECT sum(deadlocks), sum(temp_bytes) FROM pg_stat_database")
	dbStatsOut, _ := runCmd(cmd, args...)
	parts := strings.SplitN(strings.TrimSpace(dbStatsOut), "|", 2)
	if len(parts) == 2 {
		deadlocks := atoiSafe(parts[0])
		tempBytes := atoiSafe(parts[1])
		if deadlocks > 0 {
			addFinding(&sd, model.DiagWarn, "performance",
				fmt.Sprintf("Deadlocks detected: %d", deadlocks),
				"", "Investigate transaction ordering")
		}
		if tempBytes > 1024*1024*1024 {
			addFinding(&sd, model.DiagWarn, "performance",
				fmt.Sprintf("Temp file usage: %dMB", tempBytes/(1024*1024)),
				"", "Increase work_mem to reduce temp file usage")
		}
	}

	// Dead tuples (top 5 tables)
	cmd, args = psqlArgs("SELECT schemaname||'.'||relname, n_dead_tup FROM pg_stat_user_tables WHERE n_dead_tup > 100000 ORDER BY n_dead_tup DESC LIMIT 5")
	deadOut, _ := runCmd(cmd, args...)
	for _, line := range strings.Split(deadOut, "\n") {
		parts := strings.SplitN(line, "|", 2)
		if len(parts) == 2 {
			table := strings.TrimSpace(parts[0])
			dead := atoiSafe(parts[1])
			if dead > 100000 {
				addFinding(&sd, model.DiagWarn, "performance",
					fmt.Sprintf("Table %s has %dk dead tuples", table, dead/1000),
					"", fmt.Sprintf("Run VACUUM ANALYZE %s", table))
			}
		}
	}

	// Config values
	for _, param := range []string{"shared_buffers", "work_mem"} {
		cmd, args = psqlArgs(fmt.Sprintf("SHOW %s", param))
		out, err := runCmd(cmd, args...)
		if err == nil {
			sd.Metrics[param] = strings.TrimSpace(out)
		}
	}

	return sd
}

// ─── HAProxy ────────────────────────────────────────────────────────────────

// DiagHAProxy analyzes HAProxy stats and configuration.
func DiagHAProxy() model.ServiceDiag {
	sd := model.ServiceDiag{
		Name:      "haproxy",
		LastCheck: time.Now(),
		Metrics:   make(map[string]string),
		WorstSev:  model.DiagOK,
	}

	if !processRunning("haproxy") {
		return sd
	}
	sd.Available = true

	// Find stats socket
	socketPaths := []string{
		"/run/haproxy/admin.sock",
		"/var/run/haproxy/admin.sock",
		"/var/lib/haproxy/stats",
	}
	var socketPath string
	for _, p := range socketPaths {
		if _, err := os.Stat(p); err == nil {
			socketPath = p
			break
		}
	}

	hasSocat := false
	if _, err := exec.LookPath("socat"); err == nil {
		hasSocat = true
	}

	if socketPath != "" && hasSocat {
		// show stat
		statOut, err := runCmd("bash", "-c",
			fmt.Sprintf(`echo "show stat" | socat unix-connect:%s stdio`, socketPath))
		if err == nil {
			downBackends := 0
			var total5xx, totalReq int64
			var queueDepth int64

			for _, line := range strings.Split(statOut, "\n") {
				if strings.HasPrefix(line, "#") || line == "" {
					continue
				}
				fields := strings.Split(line, ",")
				if len(fields) < 40 {
					continue
				}
				// fields: pxname,svname,qcur,qmax,...,status(17),...,hrsp_5xx(39),...,req_tot(48)
				svname := fields[1]
				status := ""
				if len(fields) > 17 {
					status = fields[17]
				}

				if svname != "FRONTEND" && svname != "BACKEND" && status == "DOWN" {
					downBackends++
				}
				if len(fields) > 39 {
					total5xx += atoiSafe(fields[39])
				}
				if len(fields) > 48 {
					totalReq += atoiSafe(fields[48])
				}
				queueDepth += atoiSafe(fields[2])
			}

			if downBackends > 0 {
				addFinding(&sd, model.DiagCrit, "performance",
					fmt.Sprintf("%d backend server(s) DOWN", downBackends),
					"", "Check backend server health")
			}
			if totalReq > 0 {
				pct5xx := float64(total5xx) / float64(totalReq) * 100
				sd.Metrics["5xx"] = fmt.Sprintf("%.1f%%", pct5xx)
				if pct5xx > 1 {
					addFinding(&sd, model.DiagWarn, "performance",
						fmt.Sprintf("5xx rate: %.1f%%", pct5xx),
						"", "Investigate backend errors")
				}
			}
			if queueDepth > 0 {
				sd.Metrics["queue"] = fmt.Sprintf("%d", queueDepth)
				addFinding(&sd, model.DiagWarn, "performance",
					fmt.Sprintf("Queue depth: %d", queueDepth),
					"", "Backends may be overloaded")
			}
		}

		// show info
		infoOut, err := runCmd("bash", "-c",
			fmt.Sprintf(`echo "show info" | socat unix-connect:%s stdio`, socketPath))
		if err == nil {
			info := parseKV(infoOut, ":")
			currConns := atoiSafe(info["CurrConns"])
			maxConns := atoiSafe(info["Maxconn"])
			sd.Metrics["conns"] = fmt.Sprintf("%d/%d", currConns, maxConns)
			if maxConns > 0 {
				connPct := float64(currConns) / float64(maxConns) * 100
				if connPct > 80 {
					addFinding(&sd, model.DiagWarn, "connections",
						fmt.Sprintf("Connections at %.0f%% of max", connPct),
						"", "Increase maxconn or scale out")
				}
			}
		}
	} else {
		addFinding(&sd, model.DiagInfo, "config",
			"Stats socket not available",
			"Install socat and configure HAProxy stats socket for full diagnostics",
			"")
	}

	// Parse config file for basic info
	cfgPaths := []string{"/etc/haproxy/haproxy.cfg"}
	for _, p := range cfgPaths {
		data, err := os.ReadFile(p)
		if err == nil {
			cfg := string(data)
			if m := regexp.MustCompile(`maxconn\s+(\d+)`).FindStringSubmatch(cfg); len(m) > 1 {
				sd.Metrics["cfg_maxconn"] = m[1]
			}
			break
		}
	}

	return sd
}

// ─── Redis ──────────────────────────────────────────────────────────────────

// DiagRedis analyzes Redis memory, performance, and persistence.
func DiagRedis() model.ServiceDiag {
	sd := model.ServiceDiag{
		Name:      "redis",
		LastCheck: time.Now(),
		Metrics:   make(map[string]string),
		WorstSev:  model.DiagOK,
	}

	if !processRunning("redis-server") {
		return sd
	}
	if _, err := exec.LookPath("redis-cli"); err != nil {
		return sd
	}
	sd.Available = true

	// redis-cli info all
	infoOut, err := runCmd("redis-cli", "info", "all")
	if err != nil {
		addFinding(&sd, model.DiagWarn, "connections", "Cannot connect to Redis", err.Error(),
			"Check Redis is listening: redis-cli ping")
		return sd
	}

	info := parseKV(infoOut, ":")

	// Memory analysis
	usedMem := atoiSafe(info["used_memory"])
	maxMem := atoiSafe(info["maxmemory"])
	if maxMem > 0 {
		memPct := float64(usedMem) / float64(maxMem) * 100
		sd.Metrics["mem"] = fmt.Sprintf("%.0f%%", memPct)
		if memPct > 95 {
			addFinding(&sd, model.DiagCrit, "memory",
				fmt.Sprintf("Memory usage: %.0f%%", memPct),
				"", "Increase maxmemory or review eviction policy")
		} else if memPct > 80 {
			addFinding(&sd, model.DiagWarn, "memory",
				fmt.Sprintf("Memory usage: %.0f%%", memPct),
				"", "Monitor memory growth")
		}
	} else {
		sd.Metrics["mem"] = fmt.Sprintf("%dMB", usedMem/(1024*1024))
		addFinding(&sd, model.DiagWarn, "memory",
			"maxmemory not set (unbounded)",
			"Redis can grow until OOM killer hits",
			"Set maxmemory in redis.conf")
	}

	// Fragmentation
	fragStr := info["mem_fragmentation_ratio"]
	if fragStr != "" {
		frag := atofSafe(fragStr)
		sd.Metrics["frag"] = fmt.Sprintf("%.1f", frag)
		if frag > 1.5 {
			addFinding(&sd, model.DiagWarn, "memory",
				fmt.Sprintf("Memory fragmentation ratio: %.1f", frag),
				"", "Consider restarting Redis or enabling active defrag")
		}
	}

	// Clients
	connClients := atoiSafe(info["connected_clients"])
	blockedClients := atoiSafe(info["blocked_clients"])
	sd.Metrics["clients"] = fmt.Sprintf("%d", connClients)
	sd.Metrics["blocked"] = fmt.Sprintf("%d", blockedClients)
	if blockedClients > 0 {
		addFinding(&sd, model.DiagWarn, "connections",
			fmt.Sprintf("Blocked clients: %d", blockedClients),
			"", "Check BLPOP/BRPOP/WAIT blocking commands")
	}

	// Hit ratio
	hits := atoiSafe(info["keyspace_hits"])
	misses := atoiSafe(info["keyspace_misses"])
	if hits+misses > 0 {
		hitRatio := float64(hits) / float64(hits+misses) * 100
		sd.Metrics["hit"] = fmt.Sprintf("%.1f%%", hitRatio)
	}

	// Evictions
	evictions := atoiSafe(info["evicted_keys"])
	if evictions > 0 {
		addFinding(&sd, model.DiagWarn, "memory",
			fmt.Sprintf("Evictions: %d keys evicted", evictions),
			"", "Increase maxmemory or review data expiry")
	}

	// Persistence — last save status
	if lastSaveStatus := info["rdb_last_bgsave_status"]; lastSaveStatus != "" && lastSaveStatus != "ok" {
		addFinding(&sd, model.DiagWarn, "config",
			fmt.Sprintf("Last RDB save failed: %s", lastSaveStatus),
			"", "Check disk space and Redis logs")
	}

	// Replication
	role := info["role"]
	sd.Metrics["role"] = role
	if role == "slave" {
		linkStatus := info["master_link_status"]
		if linkStatus != "up" {
			addFinding(&sd, model.DiagCrit, "replication",
				fmt.Sprintf("Replication link: %s", linkStatus),
				"", "Check master connectivity")
		}
	}

	// Slowlog
	slowLenOut, err := runCmd("redis-cli", "slowlog", "len")
	if err == nil {
		slowLen := atoiSafe(slowLenOut)
		if slowLen > 50 {
			addFinding(&sd, model.DiagWarn, "performance",
				fmt.Sprintf("Slowlog entries: %d", slowLen),
				"", "Review slow commands: redis-cli slowlog get 10")
		}
	}

	return sd
}

// ─── Docker ─────────────────────────────────────────────────────────────────

// DiagDocker analyzes Docker container health, resource usage, and disk.
func DiagDocker() model.ServiceDiag {
	sd := model.ServiceDiag{
		Name:      "docker",
		LastCheck: time.Now(),
		Metrics:   make(map[string]string),
		WorstSev:  model.DiagOK,
	}

	if !processRunning("dockerd") {
		return sd
	}
	if _, err := exec.LookPath("docker"); err != nil {
		return sd
	}
	sd.Available = true

	// Container states
	psOut, err := runCmd("docker", "ps", "-a", "--format", "{{.ID}}\t{{.Names}}\t{{.Status}}\t{{.State}}")
	if err != nil {
		addFinding(&sd, model.DiagWarn, "config", "Cannot query Docker", err.Error(),
			"Check Docker socket permissions")
		return sd
	}

	var running, stopped, restarting, unhealthyNames int
	var unhealthyIDs []string
	for _, line := range strings.Split(psOut, "\n") {
		fields := strings.Split(line, "\t")
		if len(fields) < 4 {
			continue
		}
		state := strings.ToLower(fields[3])
		switch {
		case state == "running":
			running++
			if strings.Contains(strings.ToLower(fields[2]), "unhealthy") {
				unhealthyNames++
				unhealthyIDs = append(unhealthyIDs, fields[0])
			}
		case state == "restarting":
			restarting++
			addFinding(&sd, model.DiagCrit, "performance",
				fmt.Sprintf("Container %s is restarting", fields[1]),
				"", fmt.Sprintf("Check logs: docker logs %s", fields[1]))
		case state == "exited" || state == "dead":
			stopped++
		}
	}

	sd.Metrics["running"] = fmt.Sprintf("%d", running)
	sd.Metrics["stopped"] = fmt.Sprintf("%d", stopped)
	if unhealthyNames > 0 {
		sd.Metrics["unhealthy"] = fmt.Sprintf("%d", unhealthyNames)
	}

	if stopped > 2 {
		addFinding(&sd, model.DiagWarn, "performance",
			fmt.Sprintf("%d stopped containers", stopped),
			"", "Review stopped containers: docker ps -a --filter status=exited")
	}

	// Unhealthy container details
	for _, id := range unhealthyIDs {
		inspOut, err := runCmd("docker", "inspect", "--format",
			"{{.Name}} {{range .State.Health.Log}}{{.Output}}{{end}}", id)
		if err == nil {
			addFinding(&sd, model.DiagCrit, "performance",
				fmt.Sprintf("Unhealthy container: %s", strings.TrimSpace(inspOut)),
				"", fmt.Sprintf("Check: docker inspect %s", id))
		}
	}

	// Container resource usage
	statsOut, err := runCmd("docker", "stats", "--no-stream", "--format",
		"{{.Name}}\t{{.CPUPerc}}\t{{.MemPerc}}")
	if err == nil {
		for _, line := range strings.Split(statsOut, "\n") {
			fields := strings.Split(line, "\t")
			if len(fields) < 3 {
				continue
			}
			name := fields[0]
			memStr := strings.TrimSuffix(fields[2], "%")
			memPct := atofSafe(memStr)
			if memPct > 95 {
				addFinding(&sd, model.DiagCrit, "memory",
					fmt.Sprintf("Container %s at %.0f%% memory", name, memPct),
					"", "Increase memory limit or investigate leak")
			} else if memPct > 80 {
				addFinding(&sd, model.DiagWarn, "memory",
					fmt.Sprintf("Container %s at %.0f%% memory", name, memPct),
					"", "Monitor memory usage")
			}
		}
	}

	// Disk usage
	dfOut, err := runCmd("docker", "system", "df", "--format",
		"{{.Type}}\t{{.Size}}\t{{.Reclaimable}}")
	if err == nil {
		for _, line := range strings.Split(dfOut, "\n") {
			fields := strings.Split(line, "\t")
			if len(fields) < 3 {
				continue
			}
			reclaimStr := fields[2]
			// Parse reclaimable size — look for GB value
			if strings.Contains(reclaimStr, "GB") {
				sizeStr := strings.Fields(reclaimStr)[0]
				sizeStr = strings.TrimSuffix(sizeStr, "GB")
				gb := atofSafe(sizeStr)
				if gb > 10 {
					addFinding(&sd, model.DiagWarn, "config",
						fmt.Sprintf("Docker %s: %s reclaimable", fields[0], reclaimStr),
						"", "Run: docker system prune")
				}
			}
		}
	}

	return sd
}

// ─── Utility ────────────────────────────────────────────────────────────────

// truncStr truncates a string to maxLen characters.
func truncStr(s string, maxLen int) string {
	s = strings.TrimSpace(s)
	if len(s) > maxLen {
		return s[:maxLen-3] + "..."
	}
	return s
}

// DiagAll runs all analyzers and returns results (for CLI mode).
func DiagAll(target string) []model.ServiceDiag {
	type analyzerEntry struct {
		name string
		fn   func() model.ServiceDiag
	}
	all := []analyzerEntry{
		{"nginx", DiagNginx},
		{"apache", DiagApache},
		{"mysql", DiagMySQL},
		{"postgresql", DiagPostgreSQL},
		{"haproxy", DiagHAProxy},
		{"redis", DiagRedis},
		{"docker", DiagDocker},
	}

	if target != "" {
		target = strings.ToLower(target)
		for _, a := range all {
			if a.name == target || strings.HasPrefix(a.name, target) {
				result := a.fn()
				if !result.Available {
					// Force available for targeted analysis so user sees "not running" message
					result.Available = true
					result.Findings = append(result.Findings, model.DiagFinding{
						Severity: model.DiagInfo,
						Category: "status",
						Summary:  fmt.Sprintf("%s is not running or not detected", a.name),
					})
				}
				return []model.ServiceDiag{result}
			}
		}
		// No match — return empty with message
		names := make([]string, len(all))
		for i, a := range all {
			names[i] = a.name
		}
		return []model.ServiceDiag{{
			Name:      target,
			Available: true,
			WorstSev:  model.DiagInfo,
			LastCheck: time.Now(),
			Metrics:   make(map[string]string),
			Findings: []model.DiagFinding{{
				Severity: model.DiagInfo,
				Category: "status",
				Summary:  fmt.Sprintf("Unknown service: %s", target),
				Detail:   fmt.Sprintf("Available services: %s", strings.Join(names, ", ")),
			}},
		}}
	}

	// Run all in parallel
	ch := make(chan model.ServiceDiag, len(all))
	for _, a := range all {
		a := a
		go func() { ch <- a.fn() }()
	}

	var results []model.ServiceDiag
	for range all {
		r := <-ch
		if r.Available {
			results = append(results, r)
		}
	}
	return results
}

