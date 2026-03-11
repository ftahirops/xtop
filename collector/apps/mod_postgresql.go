//go:build linux

package apps

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/ftahirops/xtop/model"
)

type postgresqlModule struct{}

func NewPostgreSQLModule() AppModule { return &postgresqlModule{} }

func (m *postgresqlModule) Type() string        { return "postgresql" }
func (m *postgresqlModule) DisplayName() string { return "PostgreSQL" }

func (m *postgresqlModule) Detect(processes []model.ProcessMetrics) []DetectedApp {
	var apps []DetectedApp
	for _, p := range processes {
		if p.Comm != "postgres" {
			continue
		}
		// Only detect the postmaster (PPID <= 2 means launched by init/systemd)
		if p.PPID > 2 {
			continue
		}
		port := 5432
		cmdline := readProcCmdline(p.PID)
		// Parse port from cmdline: postgres -p 5433
		fields := strings.Fields(cmdline)
		for i, arg := range fields {
			if arg == "-p" && i+1 < len(fields) {
				if p, err := strconv.Atoi(fields[i+1]); err == nil && p > 0 {
					port = p
				}
			}
		}
		apps = append(apps, DetectedApp{
			PID:     p.PID,
			Port:    port,
			Comm:    p.Comm,
			Cmdline: cmdline,
			Index:   len(apps),
		})
	}
	return apps
}

func (m *postgresqlModule) Collect(app *DetectedApp, secrets *AppSecrets) model.AppInstance {
	inst := model.AppInstance{
		AppType:     "postgresql",
		DisplayName: "PostgreSQL",
		PID:         app.PID,
		Port:        app.Port,
		Status:      "active",
		UptimeSec:   readProcUptime(app.PID),
		DeepMetrics: make(map[string]string),
	}

	// Tier 1: process metrics (postmaster)
	inst.RSSMB = readProcRSS(app.PID)
	inst.Threads = readProcThreads(app.PID)
	inst.FDs = readProcFDs(app.PID)
	inst.Connections = countTCPConnections(app.Port)
	inst.CPUPct = readProcCPUPct(app.PID, inst.UptimeSec)

	// Sum RSS from backend processes (children of the postmaster)
	backendCount := 0
	backendRSS := 0.0
	entries, _ := os.ReadDir("/proc")
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil || pid == app.PID {
			continue
		}
		data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
		if err != nil {
			continue
		}
		s := string(data)
		if !strings.Contains(s, "(postgres)") {
			continue
		}
		ci := strings.LastIndex(s, ")")
		if ci > 0 && ci+2 < len(s) {
			fields := strings.Fields(s[ci+2:])
			if len(fields) > 1 {
				ppid, _ := strconv.Atoi(fields[1])
				if ppid == app.PID {
					backendCount++
					backendRSS += readProcRSS(pid)
				}
			}
		}
	}
	inst.RSSMB += backendRSS
	inst.DeepMetrics["backends"] = fmt.Sprintf("%d", backendCount)

	// Config file detection
	confPath := findConfigFile([]string{
		"/etc/postgresql/17/main/postgresql.conf",
		"/etc/postgresql/16/main/postgresql.conf",
		"/etc/postgresql/15/main/postgresql.conf",
		"/etc/postgresql/14/main/postgresql.conf",
		"/etc/postgresql/13/main/postgresql.conf",
		"/etc/postgresql/12/main/postgresql.conf",
		"/var/lib/pgsql/data/postgresql.conf",
		"/var/lib/pgsql/17/data/postgresql.conf",
		"/var/lib/pgsql/16/data/postgresql.conf",
		"/var/lib/pgsql/15/data/postgresql.conf",
		"/var/lib/pgsql/14/data/postgresql.conf",
		"/var/lib/pgsql/13/data/postgresql.conf",
	})
	inst.ConfigPath = confPath

	maxConn := 0
	if confPath != "" {
		var sharedBuf string
		maxConn, sharedBuf = parsePostgresqlConf(confPath)
		if maxConn > 0 {
			inst.DeepMetrics["max_connections"] = fmt.Sprintf("%d", maxConn)
		}
		if sharedBuf != "" {
			inst.DeepMetrics["shared_buffers"] = sharedBuf
		}
	}

	// Tier 2: deep metrics via psql CLI
	collectPostgresDeepMetrics(&inst, secrets, maxConn)

	return inst
}

// psqlQuery executes a SQL query via the psql CLI tool.
// If secrets are provided, it uses those credentials; otherwise it tries sudo -u postgres.
func psqlQuery(secrets *AppSecrets, query string) (string, error) {
	var args []string
	cmdName := "psql"
	env := os.Environ()

	if secrets != nil && secrets.PostgreSQL != nil {
		pg := secrets.PostgreSQL
		if pg.Host != "" {
			args = append(args, "-h", pg.Host)
		}
		if pg.Port > 0 {
			args = append(args, "-p", fmt.Sprintf("%d", pg.Port))
		}
		if pg.User != "" {
			args = append(args, "-U", pg.User)
		}
		if pg.DBName != "" {
			args = append(args, "-d", pg.DBName)
		}
		if pg.Password != "" {
			env = append(env, "PGPASSWORD="+pg.Password)
		}
	} else {
		// Try as postgres user
		cmdName = "sudo"
		args = []string{"-u", "postgres", "psql"}
	}
	args = append(args, "-t", "-A", "-F", "\t", "-c", query)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, cmdName, args...)
	cmd.Env = env
	out, err := cmd.CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

func collectPostgresDeepMetrics(inst *model.AppInstance, secrets *AppSecrets, maxConn int) {
	dm := inst.DeepMetrics
	anySuccess := false

	// 10. Version
	if out, err := psqlQuery(secrets, "SELECT version()"); err == nil && out != "" {
		anySuccess = true
		inst.Version = parsePostgresVersion(out)
		dm["version"] = inst.Version
	}

	// 1. pg_stat_activity — connection breakdown
	activeQueries := 0
	idleConns := 0
	idleInTx := 0
	waitingConns := 0
	totalConns := 0
	if out, err := psqlQuery(secrets, "SELECT state, count(*) FROM pg_stat_activity GROUP BY state"); err == nil && out != "" {
		anySuccess = true
		for _, line := range strings.Split(out, "\n") {
			parts := strings.SplitN(line, "\t", 2)
			if len(parts) != 2 {
				continue
			}
			state := strings.TrimSpace(parts[0])
			cnt, _ := strconv.Atoi(strings.TrimSpace(parts[1]))
			totalConns += cnt
			switch state {
			case "active":
				activeQueries = cnt
			case "idle":
				idleConns = cnt
			case "idle in transaction", "idle in transaction (aborted)":
				idleInTx += cnt
			case "disabled", "fastpath function call":
				// count toward total only
			}
		}
		// Waiting is tracked separately via wait_event_type
		dm["active_queries"] = fmt.Sprintf("%d", activeQueries)
		dm["idle_connections"] = fmt.Sprintf("%d", idleConns)
		dm["idle_in_transaction"] = fmt.Sprintf("%d", idleInTx)
		dm["total_connections"] = fmt.Sprintf("%d", totalConns)
	}

	// Check waiting connections separately
	if out, err := psqlQuery(secrets, "SELECT count(*) FROM pg_stat_activity WHERE wait_event_type IS NOT NULL AND state='active'"); err == nil && out != "" {
		anySuccess = true
		waitingConns, _ = strconv.Atoi(strings.TrimSpace(out))
		dm["waiting_connections"] = fmt.Sprintf("%d", waitingConns)
	}

	// 2. pg_stat_database
	var xactCommit, xactRollback, blksRead, blksHit int64
	var tupReturned, tupFetched, tupInserted, tupUpdated, tupDeleted int64
	var conflicts, deadlocks, tempFiles, tempBytes int64
	if out, err := psqlQuery(secrets, "SELECT sum(xact_commit), sum(xact_rollback), sum(blks_read), sum(blks_hit), sum(tup_returned), sum(tup_fetched), sum(tup_inserted), sum(tup_updated), sum(tup_deleted), sum(conflicts), sum(deadlocks), sum(temp_files), sum(temp_bytes) FROM pg_stat_database"); err == nil && out != "" {
		anySuccess = true
		parts := strings.Split(out, "\t")
		if len(parts) == 13 {
			xactCommit, _ = strconv.ParseInt(strings.TrimSpace(parts[0]), 10, 64)
			xactRollback, _ = strconv.ParseInt(strings.TrimSpace(parts[1]), 10, 64)
			blksRead, _ = strconv.ParseInt(strings.TrimSpace(parts[2]), 10, 64)
			blksHit, _ = strconv.ParseInt(strings.TrimSpace(parts[3]), 10, 64)
			tupReturned, _ = strconv.ParseInt(strings.TrimSpace(parts[4]), 10, 64)
			tupFetched, _ = strconv.ParseInt(strings.TrimSpace(parts[5]), 10, 64)
			tupInserted, _ = strconv.ParseInt(strings.TrimSpace(parts[6]), 10, 64)
			tupUpdated, _ = strconv.ParseInt(strings.TrimSpace(parts[7]), 10, 64)
			tupDeleted, _ = strconv.ParseInt(strings.TrimSpace(parts[8]), 10, 64)
			conflicts, _ = strconv.ParseInt(strings.TrimSpace(parts[9]), 10, 64)
			deadlocks, _ = strconv.ParseInt(strings.TrimSpace(parts[10]), 10, 64)
			tempFiles, _ = strconv.ParseInt(strings.TrimSpace(parts[11]), 10, 64)
			tempBytes, _ = strconv.ParseInt(strings.TrimSpace(parts[12]), 10, 64)

			dm["xact_commit"] = fmt.Sprintf("%d", xactCommit)
			dm["xact_rollback"] = fmt.Sprintf("%d", xactRollback)
			dm["blks_read"] = fmt.Sprintf("%d", blksRead)
			dm["blks_hit"] = fmt.Sprintf("%d", blksHit)
			dm["tup_returned"] = fmt.Sprintf("%d", tupReturned)
			dm["tup_fetched"] = fmt.Sprintf("%d", tupFetched)
			dm["tup_inserted"] = fmt.Sprintf("%d", tupInserted)
			dm["tup_updated"] = fmt.Sprintf("%d", tupUpdated)
			dm["tup_deleted"] = fmt.Sprintf("%d", tupDeleted)
			dm["conflicts"] = fmt.Sprintf("%d", conflicts)
			dm["deadlocks"] = fmt.Sprintf("%d", deadlocks)
			dm["temp_files"] = fmt.Sprintf("%d", tempFiles)
			dm["temp_bytes"] = fmt.Sprintf("%d", tempBytes)

			// Cache hit ratio
			totalBlks := blksHit + blksRead
			if totalBlks > 0 {
				cacheHitRatio := float64(blksHit) / float64(totalBlks) * 100.0
				dm["cache_hit_ratio"] = fmt.Sprintf("%.2f", cacheHitRatio)
			}
		}
	}

	// 3. pg_stat_bgwriter
	var buffersCheckpoint, buffersBackend int64
	if out, err := psqlQuery(secrets, "SELECT checkpoints_timed, checkpoints_req, buffers_checkpoint, buffers_clean, buffers_backend, buffers_alloc FROM pg_stat_bgwriter"); err == nil && out != "" {
		anySuccess = true
		parts := strings.Split(out, "\t")
		if len(parts) == 6 {
			checkpointsTimed, _ := strconv.ParseInt(strings.TrimSpace(parts[0]), 10, 64)
			checkpointsReq, _ := strconv.ParseInt(strings.TrimSpace(parts[1]), 10, 64)
			buffersCheckpoint, _ = strconv.ParseInt(strings.TrimSpace(parts[2]), 10, 64)
			buffersClean, _ := strconv.ParseInt(strings.TrimSpace(parts[3]), 10, 64)
			buffersBackend, _ = strconv.ParseInt(strings.TrimSpace(parts[4]), 10, 64)
			buffersAlloc, _ := strconv.ParseInt(strings.TrimSpace(parts[5]), 10, 64)

			dm["checkpoints_timed"] = fmt.Sprintf("%d", checkpointsTimed)
			dm["checkpoints_req"] = fmt.Sprintf("%d", checkpointsReq)
			dm["buffers_checkpoint"] = fmt.Sprintf("%d", buffersCheckpoint)
			dm["buffers_clean"] = fmt.Sprintf("%d", buffersClean)
			dm["buffers_backend"] = fmt.Sprintf("%d", buffersBackend)
			dm["buffers_alloc"] = fmt.Sprintf("%d", buffersAlloc)
		}
	}

	// 4. Dead tuples + vacuum lag (top 5 tables)
	if out, err := psqlQuery(secrets, "SELECT schemaname||'.'||relname, n_dead_tup, last_autovacuum FROM pg_stat_user_tables WHERE n_dead_tup > 1000 ORDER BY n_dead_tup DESC LIMIT 5"); err == nil && out != "" {
		anySuccess = true
		dm["top_dead_tuples"] = out
	}

	// 5. Lock contention — blocked queries
	blockedQueries := 0
	if out, err := psqlQuery(secrets, "SELECT count(*) FROM pg_locks WHERE NOT granted"); err == nil && out != "" {
		anySuccess = true
		blockedQueries, _ = strconv.Atoi(strings.TrimSpace(out))
		dm["blocked_queries"] = fmt.Sprintf("%d", blockedQueries)
	}

	// 6. Replication status
	replicaCount := 0
	replicationLag := false
	if out, err := psqlQuery(secrets, "SELECT client_addr, state, sent_lsn, write_lsn, flush_lsn, replay_lsn FROM pg_stat_replication"); err == nil && out != "" {
		anySuccess = true
		for _, line := range strings.Split(out, "\n") {
			parts := strings.SplitN(line, "\t", 6)
			if len(parts) < 6 {
				continue
			}
			replicaCount++
			sentLSN := strings.TrimSpace(parts[2])
			replayLSN := strings.TrimSpace(parts[5])
			if sentLSN != "" && replayLSN != "" && sentLSN != replayLSN {
				replicationLag = true
			}
		}
		dm["replica_count"] = fmt.Sprintf("%d", replicaCount)
		if replicationLag {
			dm["replication_lag"] = "true"
		} else {
			dm["replication_lag"] = "false"
		}
	}

	// 7. Long-running queries (>30s)
	longRunning := 0
	if out, err := psqlQuery(secrets, "SELECT count(*) FROM pg_stat_activity WHERE state='active' AND now()-query_start > interval '30 seconds'"); err == nil && out != "" {
		anySuccess = true
		longRunning, _ = strconv.Atoi(strings.TrimSpace(out))
		dm["long_running_queries"] = fmt.Sprintf("%d", longRunning)
	}

	// 8. Database sizes (top 3)
	if out, err := psqlQuery(secrets, "SELECT pg_database_size(datname), datname FROM pg_database WHERE datistemplate=false ORDER BY 1 DESC LIMIT 3"); err == nil && out != "" {
		anySuccess = true
		var dbSizes []string
		for _, line := range strings.Split(out, "\n") {
			parts := strings.SplitN(line, "\t", 2)
			if len(parts) != 2 {
				continue
			}
			sizeBytes, _ := strconv.ParseInt(strings.TrimSpace(parts[0]), 10, 64)
			dbName := strings.TrimSpace(parts[1])
			dbSizes = append(dbSizes, fmt.Sprintf("%s=%s", dbName, formatBytes(sizeBytes)))
		}
		dm["database_sizes"] = strings.Join(dbSizes, ", ")
	}

	// 9. Table bloat indicator (dead vs live tuple ratio)
	deadTupleRatio := 0.0
	if out, err := psqlQuery(secrets, "SELECT sum(n_dead_tup)::bigint, sum(n_live_tup)::bigint FROM pg_stat_user_tables"); err == nil && out != "" {
		anySuccess = true
		parts := strings.SplitN(out, "\t", 2)
		if len(parts) == 2 {
			deadTup, _ := strconv.ParseInt(strings.TrimSpace(parts[0]), 10, 64)
			liveTup, _ := strconv.ParseInt(strings.TrimSpace(parts[1]), 10, 64)
			total := deadTup + liveTup
			if total > 0 {
				deadTupleRatio = float64(deadTup) / float64(total) * 100.0
			}
			dm["dead_tuples_total"] = fmt.Sprintf("%d", deadTup)
			dm["live_tuples_total"] = fmt.Sprintf("%d", liveTup)
			dm["dead_tuple_ratio"] = fmt.Sprintf("%.2f", deadTupleRatio)
		}
	}

	if anySuccess {
		inst.HasDeepMetrics = true
		inst.NeedsCreds = false
	} else {
		inst.NeedsCreds = true
	}

	// Health scoring
	inst.HealthScore = 100

	if inst.HasDeepMetrics {
		// Cache hit ratio
		if v, ok := dm["cache_hit_ratio"]; ok {
			ratio, _ := strconv.ParseFloat(v, 64)
			if ratio > 0 && ratio < 90 {
				inst.HealthScore -= 20
				inst.HealthIssues = append(inst.HealthIssues, fmt.Sprintf("Low cache hit ratio: %.1f%%", ratio))
			} else if ratio > 0 && ratio < 99 {
				inst.HealthScore -= 10
				inst.HealthIssues = append(inst.HealthIssues, fmt.Sprintf("Cache hit ratio below optimal: %.1f%%", ratio))
			}
		}

		// Deadlocks
		if deadlocks > 0 {
			inst.HealthScore -= 10
			inst.HealthIssues = append(inst.HealthIssues, fmt.Sprintf("Deadlocks detected: %d", deadlocks))
		}

		// Blocked queries
		if blockedQueries > 5 {
			inst.HealthScore -= 15
			inst.HealthIssues = append(inst.HealthIssues, fmt.Sprintf("High lock contention: %d blocked queries", blockedQueries))
		} else if blockedQueries > 0 {
			inst.HealthScore -= 5
			inst.HealthIssues = append(inst.HealthIssues, fmt.Sprintf("Lock contention: %d blocked queries", blockedQueries))
		}

		// Connection usage vs max_connections
		if maxConn > 0 && totalConns > 0 {
			usagePct := float64(totalConns) / float64(maxConn) * 100.0
			dm["connection_usage_pct"] = fmt.Sprintf("%.1f", usagePct)
			if usagePct > 90 {
				inst.HealthScore -= 25
				inst.HealthIssues = append(inst.HealthIssues, fmt.Sprintf("Critical connection usage: %.0f%% of max", usagePct))
			} else if usagePct > 80 {
				inst.HealthScore -= 15
				inst.HealthIssues = append(inst.HealthIssues, fmt.Sprintf("High connection usage: %.0f%% of max", usagePct))
			}
		}

		// Idle in transaction
		if idleInTx > 10 {
			inst.HealthScore -= 10
			inst.HealthIssues = append(inst.HealthIssues, fmt.Sprintf("Excessive idle-in-transaction: %d sessions", idleInTx))
		}

		// Long-running queries
		if longRunning > 0 {
			inst.HealthScore -= 10
			inst.HealthIssues = append(inst.HealthIssues, fmt.Sprintf("Long-running queries (>30s): %d", longRunning))
		}

		// Dead tuple ratio (bloat)
		if deadTupleRatio > 10 {
			inst.HealthScore -= 10
			inst.HealthIssues = append(inst.HealthIssues, fmt.Sprintf("High table bloat: %.1f%% dead tuples", deadTupleRatio))
		}

		// Bgwriter not keeping up: buffers_backend > buffers_checkpoint
		if buffersBackend > 0 && buffersCheckpoint > 0 && buffersBackend > buffersCheckpoint {
			inst.HealthScore -= 10
			inst.HealthIssues = append(inst.HealthIssues, "Bgwriter behind: backends writing more buffers than checkpoints")
		}

		// Replication lag
		if replicaCount > 0 && replicationLag {
			inst.HealthScore -= 15
			inst.HealthIssues = append(inst.HealthIssues, "Replication lag detected")
		}

		// Temp files
		if tempFiles > 100 {
			inst.HealthScore -= 5
			inst.HealthIssues = append(inst.HealthIssues, fmt.Sprintf("High temp file usage: %d files", tempFiles))
		}

		// Rollback ratio
		totalXact := xactCommit + xactRollback
		if totalXact > 0 {
			rollbackRatio := float64(xactRollback) / float64(totalXact) * 100.0
			dm["rollback_ratio"] = fmt.Sprintf("%.2f", rollbackRatio)
			if rollbackRatio > 5 {
				inst.HealthScore -= 10
				inst.HealthIssues = append(inst.HealthIssues, fmt.Sprintf("High rollback ratio: %.1f%%", rollbackRatio))
			}
		}
	}

	// Clamp health score to [0, 100]
	if inst.HealthScore < 0 {
		inst.HealthScore = 0
	}
	if inst.HealthScore > 100 {
		inst.HealthScore = 100
	}
}

// parsePostgresVersion extracts version number from the full version string.
// e.g., "PostgreSQL 16.2 on x86_64..." -> "16.2"
func parsePostgresVersion(raw string) string {
	raw = strings.TrimSpace(raw)
	if strings.HasPrefix(raw, "PostgreSQL ") {
		rest := raw[len("PostgreSQL "):]
		if idx := strings.IndexByte(rest, ' '); idx > 0 {
			return rest[:idx]
		}
		return rest
	}
	return raw
}

// formatBytes converts bytes to a human-readable string.
func formatBytes(b int64) string {
	const (
		kb = 1024
		mb = 1024 * kb
		gb = 1024 * mb
		tb = 1024 * gb
	)
	switch {
	case b >= tb:
		return fmt.Sprintf("%.1fTB", float64(b)/float64(tb))
	case b >= gb:
		return fmt.Sprintf("%.1fGB", float64(b)/float64(gb))
	case b >= mb:
		return fmt.Sprintf("%.1fMB", float64(b)/float64(mb))
	case b >= kb:
		return fmt.Sprintf("%.1fKB", float64(b)/float64(kb))
	default:
		return fmt.Sprintf("%dB", b)
	}
}

// parsePostgresqlConf extracts key settings from postgresql.conf.
func parsePostgresqlConf(path string) (maxConnections int, sharedBuffers string) {
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// Strip inline comments
		if idx := strings.Index(line, "#"); idx > 0 {
			line = strings.TrimSpace(line[:idx])
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		val := strings.TrimSpace(parts[1])
		val = strings.Trim(val, "'\"")
		switch key {
		case "max_connections":
			maxConnections, _ = strconv.Atoi(val)
		case "shared_buffers":
			sharedBuffers = val
		}
	}
	return
}
