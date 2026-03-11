//go:build linux

package apps

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"sort"
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
	inst.CPUPct = readProcCPUPct(app.PID, inst.UptimeSec)

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
		// Per-command counters
		"Com_select", "Com_insert", "Com_update", "Com_delete", "Com_commit", "Com_rollback",
		// Traffic
		"Bytes_received", "Bytes_sent",
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

	// QPS and per-command rates
	uptime := inst.UptimeSec
	if uptime > 0 {
		if questions, ok := dm["Questions"]; ok {
			q, _ := strconv.ParseInt(questions, 10, 64)
			if q > 0 {
				qps := float64(q) / float64(uptime)
				dm["queries_per_sec"] = fmt.Sprintf("%.1f", qps)
			}
		}
		perCmdKeys := []struct {
			statusKey string
			metricKey string
		}{
			{"Com_select", "selects_per_sec"},
			{"Com_insert", "inserts_per_sec"},
			{"Com_update", "updates_per_sec"},
			{"Com_delete", "deletes_per_sec"},
			{"Com_commit", "commits_per_sec"},
		}
		for _, ck := range perCmdKeys {
			if v, ok := dm[ck.statusKey]; ok {
				cnt, _ := strconv.ParseInt(v, 10, 64)
				if cnt > 0 {
					rate := float64(cnt) / float64(uptime)
					dm[ck.metricKey] = fmt.Sprintf("%.1f", rate)
				}
			}
		}
		// Bytes per second
		if v, ok := dm["Bytes_received"]; ok {
			b, _ := strconv.ParseInt(v, 10, 64)
			if b > 0 {
				dm["bytes_in_per_sec"] = fmt.Sprintf("%d", b/int64(uptime))
			}
		}
		if v, ok := dm["Bytes_sent"]; ok {
			b, _ := strconv.ParseInt(v, 10, 64)
			if b > 0 {
				dm["bytes_out_per_sec"] = fmt.Sprintf("%d", b/int64(uptime))
			}
		}
	}

	// 2. SHOW FULL PROCESSLIST — count active queries, sleeping connections, top queries, per-host breakdown
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

// processListEntry holds a parsed row from SHOW FULL PROCESSLIST.
type processListEntry struct {
	id      string
	user    string
	host    string
	db      string
	command string
	timeSec int64
	state   string
	info    string
}

// collectProcessList runs SHOW FULL PROCESSLIST and extracts active/sleeping counts,
// top 5 longest-running queries, and per-host connection breakdown.
func collectProcessList(inst *model.AppInstance, secrets *AppSecrets) {
	out, err := mysqlQuery(secrets, "SHOW FULL PROCESSLIST")
	if err != nil {
		return
	}

	dm := inst.DeepMetrics
	active := 0
	sleeping := 0

	var entries []processListEntry
	// Per-host tracking
	type hostStats struct {
		total  int
		active int
	}
	hostMap := make(map[string]*hostStats)

	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		if line == "" {
			continue
		}
		fields := strings.Split(line, "\t")
		if len(fields) < 5 {
			continue
		}

		e := processListEntry{
			id:      fields[0],
			command: fields[4],
		}
		if len(fields) > 1 {
			e.user = fields[1]
		}
		if len(fields) > 2 {
			e.host = fields[2]
		}
		if len(fields) > 3 {
			e.db = fields[3]
		}
		if len(fields) > 5 {
			e.timeSec, _ = strconv.ParseInt(fields[5], 10, 64)
		}
		if len(fields) > 6 {
			e.state = fields[6]
		}
		if len(fields) > 7 {
			e.info = fields[7]
		}

		// Strip port from host (host:port -> host)
		hostOnly := e.host
		if idx := strings.LastIndex(hostOnly, ":"); idx > 0 {
			hostOnly = hostOnly[:idx]
		}

		isActive := false
		cmd := strings.ToLower(e.command)
		switch cmd {
		case "sleep":
			sleeping++
		case "query", "execute", "prepare":
			active++
			isActive = true
		default:
			active++
			isActive = true
		}

		// Track per-host stats
		if hostOnly != "" {
			hs, ok := hostMap[hostOnly]
			if !ok {
				hs = &hostStats{}
				hostMap[hostOnly] = hs
			}
			hs.total++
			if isActive {
				hs.active++
			}
		}

		entries = append(entries, e)
	}

	dm["active_queries"] = fmt.Sprintf("%d", active)
	dm["sleeping_connections"] = fmt.Sprintf("%d", sleeping)

	// Top 5 longest-running non-Sleep queries (filter out system threads and self)
	var activeEntries []processListEntry
	for _, e := range entries {
		cmd := strings.ToLower(e.command)
		if cmd == "sleep" || cmd == "daemon" || cmd == "binlog dump" {
			continue
		}
		// Skip event_scheduler and our own SHOW FULL PROCESSLIST
		if e.user == "event_scheduler" {
			continue
		}
		infoLower := strings.ToLower(e.info)
		if infoLower == "show full processlist" || infoLower == "null" || e.info == "NULL" {
			continue
		}
		activeEntries = append(activeEntries, e)
	}
	sort.Slice(activeEntries, func(i, j int) bool {
		return activeEntries[i].timeSec > activeEntries[j].timeSec
	})
	topN := len(activeEntries)
	if topN > 5 {
		topN = 5
	}
	dm["top_query_count"] = fmt.Sprintf("%d", topN)
	for i := 0; i < topN; i++ {
		e := activeEntries[i]
		prefix := fmt.Sprintf("top_query_%d", i)
		dm[prefix+"_id"] = e.id
		dm[prefix+"_user"] = e.user
		// Store host without port
		h := e.host
		if idx := strings.LastIndex(h, ":"); idx > 0 {
			h = h[:idx]
		}
		dm[prefix+"_host"] = h
		dm[prefix+"_db"] = e.db
		dm[prefix+"_time"] = fmt.Sprintf("%d", e.timeSec)
		dm[prefix+"_state"] = e.state
		info := e.info
		if len(info) > 120 {
			info = info[:120]
		}
		dm[prefix+"_info"] = info
	}

	// Per-host connection breakdown (top 5 by total connections)
	type hostEntry struct {
		host   string
		total  int
		active int
	}
	var hostList []hostEntry
	for h, hs := range hostMap {
		hostList = append(hostList, hostEntry{host: h, total: hs.total, active: hs.active})
	}
	sort.Slice(hostList, func(i, j int) bool {
		return hostList[i].total > hostList[j].total
	})
	hostN := len(hostList)
	if hostN > 5 {
		hostN = 5
	}
	dm["conn_host_count"] = fmt.Sprintf("%d", hostN)
	for i := 0; i < hostN; i++ {
		prefix := fmt.Sprintf("conn_host_%d", i)
		dm[prefix+"_host"] = hostList[i].host
		dm[prefix+"_count"] = fmt.Sprintf("%d", hostList[i].total)
		dm[prefix+"_active"] = fmt.Sprintf("%d", hostList[i].active)
	}
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
