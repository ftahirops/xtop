//go:build linux

package apps

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/ftahirops/xtop/model"
)

type mysqlModule struct{}

func NewMySQLModule() AppModule { return &mysqlModule{} }

func (m *mysqlModule) Type() string        { return "mysql" }
func (m *mysqlModule) DisplayName() string { return "MySQL" }

func (m *mysqlModule) Detect(processes []model.ProcessMetrics) []DetectedApp {
	var apps []DetectedApp
	for _, p := range processes {
		if p.Comm != "mysqld" && p.Comm != "mariadbd" {
			continue
		}
		port := 3306
		cmdline := readProcCmdline(p.PID)
		for _, part := range strings.Fields(cmdline) {
			if strings.HasPrefix(part, "--port=") {
				if v, err := strconv.Atoi(strings.TrimPrefix(part, "--port=")); err == nil && v > 0 {
					port = v
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

func (m *mysqlModule) Collect(app *DetectedApp, secrets *AppSecrets) model.AppInstance {
	displayName := "MySQL"
	if app.Comm == "mariadbd" {
		displayName = "MariaDB"
	}

	inst := model.AppInstance{
		AppType:     "mysql",
		DisplayName: displayName,
		PID:         app.PID,
		Port:        app.Port,
		Status:      "active",
		UptimeSec:   readProcUptime(app.PID),
		DeepMetrics: make(map[string]string),
	}

	// Tier 1: process-level metrics (always available)
	inst.RSSMB = readProcRSS(app.PID)
	inst.Threads = readProcThreads(app.PID)
	inst.FDs = readProcFDs(app.PID)
	inst.Connections = countTCPConnections(app.Port)

	// Config parsing
	confPath := findConfigFile([]string{
		"/etc/mysql/my.cnf",
		"/etc/my.cnf",
		"/etc/mysql/mysql.conf.d/mysqld.cnf",
		"/etc/mysql/mariadb.conf.d/50-server.cnf",
	})
	inst.ConfigPath = confPath

	maxConns, bufferPool := parseMySQLConf(confPath)
	if maxConns > 0 {
		inst.DeepMetrics["max_connections"] = fmt.Sprintf("%d", maxConns)
	}
	if bufferPool != "" {
		inst.DeepMetrics["innodb_buffer_pool_size"] = bufferPool
	}

	// Version detection
	if ver := mysqlVersion(secrets); ver != "" {
		inst.Version = ver
	}

	// Tier 2: CLI-based deep metrics
	tier2OK := collectMySQLTier2(&inst, secrets, maxConns)
	if !tier2OK {
		// If secrets not configured and CLI without creds failed, flag NeedsCreds
		if secrets == nil || secrets.MySQL == nil || (secrets.MySQL.User == "" && secrets.MySQL.Password == "") {
			inst.NeedsCreds = true
		}
	}

	// Health scoring
	inst.HealthScore = 100
	mysqlHealthScore(&inst, maxConns)

	if inst.HealthScore < 0 {
		inst.HealthScore = 0
	}
	if inst.HealthScore > 100 {
		inst.HealthScore = 100
	}

	return inst
}

// mysqlCLIArgs builds the common mysql/mysqladmin CLI args from secrets.
func mysqlCLIArgs(secrets *AppSecrets) []string {
	var args []string
	if secrets != nil && secrets.MySQL != nil {
		if secrets.MySQL.User != "" {
			args = append(args, "-u", secrets.MySQL.User)
		}
		if secrets.MySQL.Password != "" {
			args = append(args, fmt.Sprintf("-p%s", secrets.MySQL.Password))
		}
		if secrets.MySQL.Host != "" {
			args = append(args, "-h", secrets.MySQL.Host)
		}
		if secrets.MySQL.Port > 0 {
			args = append(args, "-P", fmt.Sprintf("%d", secrets.MySQL.Port))
		}
	}
	return args
}

// mysqlQuery runs a query via the mysql CLI and returns the output.
func mysqlQuery(secrets *AppSecrets, query string) (string, error) {
	args := []string{"-N", "-B", "-e", query}
	args = append(args, mysqlCLIArgs(secrets)...)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "mysql", args...)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// mysqlAdmin runs a mysqladmin command and returns the output.
func mysqlAdmin(secrets *AppSecrets, subcmd string) (string, error) {
	args := []string{subcmd}
	args = append(args, mysqlCLIArgs(secrets)...)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "mysqladmin", args...)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// mysqlVersion tries to detect the MySQL version.
func mysqlVersion(secrets *AppSecrets) string {
	// Try SHOW GLOBAL STATUS version variable first via CLI
	out, err := mysqlQuery(secrets, "SHOW GLOBAL VARIABLES LIKE 'version'")
	if err == nil {
		for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
			parts := strings.SplitN(line, "\t", 2)
			if len(parts) == 2 && parts[0] == "version" {
				return parts[1]
			}
		}
	}
	// Fallback: mysqladmin version
	out, err = mysqlAdmin(secrets, "version")
	if err == nil {
		for _, line := range strings.Split(out, "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "Server version") {
				parts := strings.SplitN(line, "\t", 2)
				if len(parts) == 2 {
					return strings.TrimSpace(parts[1])
				}
				parts = strings.SplitN(line, "  ", 2)
				if len(parts) == 2 {
					return strings.TrimSpace(parts[1])
				}
			}
		}
	}
	return ""
}

// parseGlobalStatus parses tab-separated key\tvalue output from SHOW GLOBAL STATUS.
func parseGlobalStatus(raw string) map[string]string {
	m := make(map[string]string)
	for _, line := range strings.Split(strings.TrimSpace(raw), "\n") {
		parts := strings.SplitN(line, "\t", 2)
		if len(parts) == 2 {
			m[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
		}
	}
	return m
}

// collectMySQLTier2 fetches deep metrics via CLI commands. Returns true if at least
// SHOW GLOBAL STATUS succeeded.
func collectMySQLTier2(inst *model.AppInstance, secrets *AppSecrets, maxConns int) bool {
	dm := inst.DeepMetrics

	// 1. SHOW GLOBAL STATUS
	statusOut, err := mysqlQuery(secrets, "SHOW GLOBAL STATUS")
	if err != nil {
		// Try without creds as fallback (socket auth)
		statusOut, err = mysqlQuery(nil, "SHOW GLOBAL STATUS")
		if err != nil {
			return false
		}
	}

	inst.HasDeepMetrics = true
	status := parseGlobalStatus(statusOut)

	// Collect key variables
	statusKeys := []string{
		// Connections
		"Threads_connected", "Threads_running", "Max_used_connections",
		"Aborted_connects", "Aborted_clients", "Connection_errors_max_connections",
		// InnoDB
		"Innodb_buffer_pool_reads", "Innodb_buffer_pool_read_requests",
		"Innodb_buffer_pool_pages_data", "Innodb_buffer_pool_pages_total",
		"Innodb_buffer_pool_pages_dirty", "Innodb_buffer_pool_pages_free",
		"Innodb_row_lock_waits", "Innodb_row_lock_time_avg", "Innodb_deadlocks",
		"Innodb_data_reads", "Innodb_data_writes",
		// Queries
		"Questions", "Slow_queries", "Select_full_join", "Select_scan",
		"Sort_merge_passes", "Created_tmp_disk_tables", "Created_tmp_tables",
		// Tables
		"Open_tables", "Opened_tables", "Table_locks_waited", "Table_locks_immediate",
		// Handler
		"Handler_read_rnd_next",
	}
	for _, key := range statusKeys {
		if v, ok := status[key]; ok {
			dm[key] = v
		}
	}

	// Computed metrics from SHOW GLOBAL STATUS
	computeMySQLDerivedMetrics(dm)

	// 2. SHOW PROCESSLIST — count active queries and sleeping connections
	collectProcessList(inst, secrets)

	// 3. SHOW ENGINE INNODB STATUS — parse key metrics
	collectInnoDBStatus(inst, secrets)

	// 4. SHOW SLAVE STATUS / SHOW REPLICA STATUS
	collectReplicationStatus(inst, secrets)

	// Try to get max_connections from GLOBAL VARIABLES if not from config
	if maxConns == 0 {
		out, err := mysqlQuery(secrets, "SHOW GLOBAL VARIABLES LIKE 'max_connections'")
		if err == nil {
			for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
				parts := strings.SplitN(line, "\t", 2)
				if len(parts) == 2 && parts[0] == "max_connections" {
					if v, e := strconv.Atoi(parts[1]); e == nil && v > 0 {
						dm["max_connections"] = fmt.Sprintf("%d", v)
					}
				}
			}
		}
	}

	return true
}

// computeMySQLDerivedMetrics computes ratios from raw status values.
func computeMySQLDerivedMetrics(dm map[string]string) {
	// Buffer pool hit ratio: (1 - reads/read_requests) * 100
	reads, _ := strconv.ParseFloat(dm["Innodb_buffer_pool_reads"], 64)
	readReqs, _ := strconv.ParseFloat(dm["Innodb_buffer_pool_read_requests"], 64)
	if readReqs > 0 {
		ratio := (1 - reads/readReqs) * 100
		dm["buffer_pool_hit_ratio"] = fmt.Sprintf("%.2f", ratio)
	}

	// Buffer pool usage %: pages_data / pages_total * 100
	pagesData, _ := strconv.ParseFloat(dm["Innodb_buffer_pool_pages_data"], 64)
	pagesTotal, _ := strconv.ParseFloat(dm["Innodb_buffer_pool_pages_total"], 64)
	if pagesTotal > 0 {
		pct := pagesData / pagesTotal * 100
		dm["buffer_pool_usage_pct"] = fmt.Sprintf("%.1f", pct)
	}

	// Tmp disk table %: disk_tables / (disk_tables + tables) * 100
	diskTables, _ := strconv.ParseFloat(dm["Created_tmp_disk_tables"], 64)
	tmpTables, _ := strconv.ParseFloat(dm["Created_tmp_tables"], 64)
	if diskTables+tmpTables > 0 {
		pct := diskTables / (diskTables + tmpTables) * 100
		dm["tmp_disk_table_pct"] = fmt.Sprintf("%.1f", pct)
	}

	// Table lock contention: waited / (waited + immediate) * 100
	locksWaited, _ := strconv.ParseFloat(dm["Table_locks_waited"], 64)
	locksImmediate, _ := strconv.ParseFloat(dm["Table_locks_immediate"], 64)
	if locksWaited+locksImmediate > 0 {
		pct := locksWaited / (locksWaited + locksImmediate) * 100
		dm["table_lock_contention"] = fmt.Sprintf("%.2f", pct)
	}
}

// collectProcessList runs SHOW PROCESSLIST and counts active/sleeping connections.
func collectProcessList(inst *model.AppInstance, secrets *AppSecrets) {
	out, err := mysqlQuery(secrets, "SHOW PROCESSLIST")
	if err != nil {
		return
	}

	active := 0
	sleeping := 0
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		if line == "" {
			continue
		}
		fields := strings.Split(line, "\t")
		if len(fields) < 5 {
			continue
		}
		command := fields[4]
		switch strings.ToLower(command) {
		case "sleep":
			sleeping++
		case "query", "execute", "prepare":
			active++
		default:
			// Daemon, Binlog Dump, etc. — count as active
			if strings.ToLower(command) != "sleep" {
				active++
			}
		}
	}
	inst.DeepMetrics["active_queries"] = fmt.Sprintf("%d", active)
	inst.DeepMetrics["sleeping_connections"] = fmt.Sprintf("%d", sleeping)
}

// collectInnoDBStatus parses SHOW ENGINE INNODB STATUS for key metrics.
func collectInnoDBStatus(inst *model.AppInstance, secrets *AppSecrets) {
	out, err := mysqlQuery(secrets, "SHOW ENGINE INNODB STATUS")
	if err != nil {
		return
	}

	dm := inst.DeepMetrics
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)

		// History list length
		if strings.HasPrefix(line, "History list length") {
			parts := strings.Fields(line)
			if len(parts) >= 4 {
				dm["history_list_length"] = parts[3]
			}
		}

		// Log sequence number vs last checkpoint
		if strings.HasPrefix(line, "Log sequence number") {
			parts := strings.Fields(line)
			if len(parts) >= 4 {
				dm["log_sequence_number"] = parts[3]
			}
		}
		if strings.HasPrefix(line, "Last checkpoint at") {
			parts := strings.Fields(line)
			if len(parts) >= 4 {
				dm["last_checkpoint_at"] = parts[3]
			}
		}

		// Checkpoint age (computed)
		if dm["log_sequence_number"] != "" && dm["last_checkpoint_at"] != "" {
			lsn, e1 := strconv.ParseUint(dm["log_sequence_number"], 10, 64)
			cp, e2 := strconv.ParseUint(dm["last_checkpoint_at"], 10, 64)
			if e1 == nil && e2 == nil && lsn >= cp {
				dm["checkpoint_age"] = fmt.Sprintf("%d", lsn-cp)
			}
		}

		// Pending reads/writes
		if strings.Contains(line, "Pending normal aio reads:") {
			// e.g. "Pending normal aio reads: [0, 0, ...]"
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				dm["pending_aio_reads"] = strings.TrimSpace(parts[1])
			}
		}
		if strings.Contains(line, "Pending flushes (fsync)") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				dm["pending_flushes"] = strings.TrimSpace(parts[1])
			}
		}
	}
}

// collectReplicationStatus runs SHOW SLAVE STATUS or SHOW REPLICA STATUS.
func collectReplicationStatus(inst *model.AppInstance, secrets *AppSecrets) {
	dm := inst.DeepMetrics

	// Try SHOW REPLICA STATUS first (MySQL 8.0.22+), fall back to SHOW SLAVE STATUS
	out, err := mysqlQuery(secrets, "SHOW REPLICA STATUS")
	if err != nil {
		out, err = mysqlQuery(secrets, "SHOW SLAVE STATUS")
		if err != nil {
			return
		}
	}

	// Output is tab-separated single row with many columns.
	// We need a header row to map columns. Use vertical format instead.
	// Re-query with \G for easier parsing.
	out, err = mysqlQuery(secrets, "SHOW REPLICA STATUS\\G")
	if err != nil {
		out, err = mysqlQuery(secrets, "SHOW SLAVE STATUS\\G")
		if err != nil {
			return
		}
	}

	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if !strings.Contains(line, ":") {
			continue
		}
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		val := strings.TrimSpace(parts[1])

		switch key {
		case "Seconds_Behind_Master", "Seconds_Behind_Source":
			dm["Seconds_Behind_Master"] = val
		case "Slave_IO_Running", "Replica_IO_Running":
			dm["Slave_IO_Running"] = val
		case "Slave_SQL_Running", "Replica_SQL_Running":
			dm["Slave_SQL_Running"] = val
		case "Master_Host", "Source_Host":
			dm["Master_Host"] = val
		case "Master_Port", "Source_Port":
			dm["Master_Port"] = val
		}
	}
}

// mysqlHealthScore applies comprehensive health penalties.
func mysqlHealthScore(inst *model.AppInstance, maxConns int) {
	dm := inst.DeepMetrics

	// Get max_connections from deep metrics if not from config
	if maxConns == 0 {
		if v, ok := dm["max_connections"]; ok {
			maxConns, _ = strconv.Atoi(v)
		}
	}

	// Connection usage
	if maxConns > 0 && inst.Connections > 0 {
		connPct := float64(inst.Connections) / float64(maxConns) * 100
		dm["connection_usage_pct"] = fmt.Sprintf("%.1f%%", connPct)
		if connPct > 90 {
			inst.HealthScore -= 25
			inst.HealthIssues = append(inst.HealthIssues,
				fmt.Sprintf("connections at %.0f%% of max_connections (%d/%d) — critical", connPct, inst.Connections, maxConns))
		} else if connPct > 80 {
			inst.HealthScore -= 15
			inst.HealthIssues = append(inst.HealthIssues,
				fmt.Sprintf("connections at %.0f%% of max_connections (%d/%d)", connPct, inst.Connections, maxConns))
		}
	}

	// High thread count relative to connections (possible thread leak)
	if inst.Threads > 0 && inst.Connections > 0 && inst.Threads > inst.Connections*4 {
		inst.HealthScore -= 5
		inst.HealthIssues = append(inst.HealthIssues,
			fmt.Sprintf("thread count (%d) is high relative to connections (%d)", inst.Threads, inst.Connections))
	}

	// FD pressure
	if inst.FDs > 50000 {
		inst.HealthScore -= 10
		inst.HealthIssues = append(inst.HealthIssues,
			fmt.Sprintf("high FD usage (%d) — may be approaching system limits", inst.FDs))
	}

	if !inst.HasDeepMetrics {
		return
	}

	// Buffer pool hit ratio
	if v, ok := dm["buffer_pool_hit_ratio"]; ok {
		ratio, _ := strconv.ParseFloat(v, 64)
		if ratio > 0 {
			if ratio < 95 {
				inst.HealthScore -= 15
				inst.HealthIssues = append(inst.HealthIssues,
					fmt.Sprintf("InnoDB buffer pool hit ratio %.1f%% — severely low", ratio))
			} else if ratio < 99 {
				inst.HealthScore -= 5
				inst.HealthIssues = append(inst.HealthIssues,
					fmt.Sprintf("InnoDB buffer pool hit ratio %.1f%% — below optimal", ratio))
			}
		}
	}

	// Slow queries
	if v, ok := dm["Slow_queries"]; ok {
		slow, _ := strconv.ParseInt(v, 10, 64)
		if slow > 0 {
			inst.HealthScore -= 5
			inst.HealthIssues = append(inst.HealthIssues,
				fmt.Sprintf("%d slow queries detected", slow))
		}
	}

	// InnoDB deadlocks
	if v, ok := dm["Innodb_deadlocks"]; ok {
		deadlocks, _ := strconv.ParseInt(v, 10, 64)
		if deadlocks > 0 {
			inst.HealthScore -= 10
			inst.HealthIssues = append(inst.HealthIssues,
				fmt.Sprintf("%d InnoDB deadlocks — review transaction isolation", deadlocks))
		}
	}

	// Row lock waits
	if v, ok := dm["Innodb_row_lock_waits"]; ok {
		waits, _ := strconv.ParseInt(v, 10, 64)
		if waits > 100 {
			inst.HealthScore -= 10
			inst.HealthIssues = append(inst.HealthIssues,
				fmt.Sprintf("%d InnoDB row lock waits — high contention", waits))
		}
	}

	// Table lock contention
	if v, ok := dm["table_lock_contention"]; ok {
		pct, _ := strconv.ParseFloat(v, 64)
		if pct > 5 {
			inst.HealthScore -= 10
			inst.HealthIssues = append(inst.HealthIssues,
				fmt.Sprintf("table lock contention %.1f%% — consider switching to InnoDB", pct))
		}
	}

	// Replication lag
	if v, ok := dm["Seconds_Behind_Master"]; ok && v != "NULL" && v != "" {
		lag, err := strconv.ParseInt(v, 10, 64)
		if err == nil {
			if lag > 300 {
				inst.HealthScore -= 25
				inst.HealthIssues = append(inst.HealthIssues,
					fmt.Sprintf("replication lag %ds — critically behind", lag))
			} else if lag > 30 {
				inst.HealthScore -= 15
				inst.HealthIssues = append(inst.HealthIssues,
					fmt.Sprintf("replication lag %ds", lag))
			}
		}
	}

	// Replication broken
	ioRunning := dm["Slave_IO_Running"]
	sqlRunning := dm["Slave_SQL_Running"]
	if (ioRunning != "" && ioRunning != "Yes") || (sqlRunning != "" && sqlRunning != "Yes") {
		if ioRunning != "" || sqlRunning != "" {
			inst.HealthScore -= 25
			inst.HealthIssues = append(inst.HealthIssues,
				fmt.Sprintf("replication broken — IO=%s SQL=%s", ioRunning, sqlRunning))
		}
	}

	// Aborted connects
	if v, ok := dm["Aborted_connects"]; ok {
		aborted, _ := strconv.ParseInt(v, 10, 64)
		if aborted > 100 {
			inst.HealthScore -= 5
			inst.HealthIssues = append(inst.HealthIssues,
				fmt.Sprintf("%d aborted connects — check auth or networking", aborted))
		}
	}

	// Tmp disk tables percentage
	if v, ok := dm["tmp_disk_table_pct"]; ok {
		pct, _ := strconv.ParseFloat(v, 64)
		if pct > 25 {
			inst.HealthScore -= 10
			inst.HealthIssues = append(inst.HealthIssues,
				fmt.Sprintf("%.0f%% of tmp tables created on disk — increase tmp_table_size", pct))
		}
	}

	// Full table scans
	if v, ok := dm["Select_scan"]; ok {
		scans, _ := strconv.ParseInt(v, 10, 64)
		if scans > 10000 {
			inst.HealthScore -= 5
			inst.HealthIssues = append(inst.HealthIssues,
				fmt.Sprintf("%d full table scans — review query plans", scans))
		}
	}

	// History list length (undo log growth)
	if v, ok := dm["history_list_length"]; ok {
		hll, _ := strconv.ParseInt(v, 10, 64)
		if hll > 10000 {
			inst.HealthScore -= 10
			inst.HealthIssues = append(inst.HealthIssues,
				fmt.Sprintf("history list length %d — long-running transactions preventing purge", hll))
		}
	}

	// Max used connections near limit
	if maxConns > 0 {
		if v, ok := dm["Max_used_connections"]; ok {
			maxUsed, _ := strconv.Atoi(v)
			if maxUsed > 0 {
				pct := float64(maxUsed) / float64(maxConns) * 100
				if pct > 90 {
					inst.HealthScore -= 10
					inst.HealthIssues = append(inst.HealthIssues,
						fmt.Sprintf("max used connections %d (%.0f%% of max) — increase max_connections", maxUsed, pct))
				}
			}
		}
	}

	// Connection_errors_max_connections
	if v, ok := dm["Connection_errors_max_connections"]; ok {
		errs, _ := strconv.ParseInt(v, 10, 64)
		if errs > 0 {
			inst.HealthScore -= 10
			inst.HealthIssues = append(inst.HealthIssues,
				fmt.Sprintf("%d connections refused due to max_connections limit", errs))
		}
	}
}

// parseMySQLConf extracts max_connections and innodb_buffer_pool_size from a MySQL config file.
func parseMySQLConf(path string) (maxConnections int, bufferPoolSize string) {
	if path == "" {
		return
	}
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}

		// Handle key = value or key=value
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		val := strings.TrimSpace(parts[1])

		switch key {
		case "max_connections":
			maxConnections, _ = strconv.Atoi(val)
		case "innodb_buffer_pool_size":
			bufferPoolSize = val
		}
	}
	return
}
