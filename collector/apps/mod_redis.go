//go:build linux

package apps

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/ftahirops/xtop/model"
)

type redisModule struct{}

func NewRedisModule() AppModule { return &redisModule{} }

func (m *redisModule) Type() string        { return "redis" }
func (m *redisModule) DisplayName() string { return "Redis" }

func (m *redisModule) Detect(processes []model.ProcessMetrics) []DetectedApp {
	var apps []DetectedApp
	for _, p := range processes {
		if p.Comm == "redis-server" || p.Comm == "redis-serve" {
			port := 6379
			cmdline := readProcCmdline(p.PID)
			// Parse port from cmdline: redis-server *:6380 or --port 6380
			if strings.Contains(cmdline, ":") {
				parts := strings.Fields(cmdline)
				for _, part := range parts {
					if strings.Contains(part, ":") && !strings.HasPrefix(part, "-") {
						colonIdx := strings.LastIndex(part, ":")
						if p, err := strconv.Atoi(part[colonIdx+1:]); err == nil && p > 0 {
							port = p
						}
					}
				}
			}
			fields := strings.Fields(cmdline)
			for i, part := range fields {
				if part == "--port" && i+1 < len(fields) {
					// --port 6380 (space-separated)
					if p, err := strconv.Atoi(fields[i+1]); err == nil {
						port = p
					}
				} else if strings.HasPrefix(part, "--port=") {
					// --port=6380
					if p, err := strconv.Atoi(strings.SplitN(part, "=", 2)[1]); err == nil {
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
	}
	return apps
}

func (m *redisModule) Collect(app *DetectedApp, secrets *AppSecrets) model.AppInstance {
	inst := model.AppInstance{
		AppType:     "redis",
		DisplayName: "Redis",
		PID:         app.PID,
		Port:        app.Port,
		Status:      "active",
		UptimeSec:   readProcUptime(app.PID),
		DeepMetrics: make(map[string]string),
	}

	// Tier 1: process metrics
	inst.RSSMB = readProcRSS(app.PID)
	inst.Threads = readProcThreads(app.PID)
	inst.FDs = readProcFDs(app.PID)
	inst.Connections = countTCPConnections(app.Port)
	inst.CPUPct = readProcCPUPct(app.PID, inst.UptimeSec)

	// Tier 2: Redis INFO command (raw RESP protocol)
	host := "127.0.0.1"
	port := app.Port
	password := ""

	if secrets != nil && secrets.Redis != nil {
		if secrets.Redis.Host != "" {
			host = secrets.Redis.Host
		}
		if secrets.Redis.Port > 0 {
			port = secrets.Redis.Port
		}
		password = secrets.Redis.Password
	}

	info := redisINFO(host, port, password)
	// Try without password if initial attempt fails
	if info == nil && password != "" {
		info = redisINFO(host, port, "")
	}
	if info == nil {
		if password == "" {
			inst.NeedsCreds = true
		}
		// else: creds provided but connection failed (wrong password or server issue)
	}

	if info != nil {
		inst.HasDeepMetrics = true

		// All keys we want to collect
		for _, key := range []string{
			// Server
			"redis_version", "redis_mode", "os", "uptime_in_seconds",
			"tcp_port", "config_file", "hz", "configured_hz",
			"executable", "arch_bits",
			// Clients
			"connected_clients", "blocked_clients", "tracking_clients",
			"maxclients", "client_recent_max_input_buffer",
			"client_recent_max_output_buffer",
			// Memory
			"used_memory", "used_memory_human", "used_memory_rss",
			"used_memory_rss_human",
			"used_memory_peak", "used_memory_peak_human",
			"used_memory_lua_human",
			"used_memory_dataset_perc", "used_memory_overhead",
			"maxmemory", "maxmemory_human", "maxmemory_policy",
			"mem_fragmentation_ratio", "mem_fragmentation_bytes",
			"mem_allocator", "lazyfree_pending_objects",
			"allocator_frag_ratio", "allocator_rss_ratio",
			// Persistence
			"rdb_last_save_time", "rdb_last_bgsave_status",
			"rdb_last_bgsave_time_sec", "rdb_changes_since_last_save",
			"rdb_current_bgsave_time_sec",
			"aof_enabled", "aof_last_bgrewrite_status",
			"aof_rewrite_in_progress", "aof_current_size",
			"aof_base_size", "aof_buffer_length",
			"latest_fork_usec",
			// Stats
			"total_connections_received", "total_commands_processed",
			"instantaneous_ops_per_sec", "instantaneous_input_kbps",
			"instantaneous_output_kbps",
			"rejected_connections", "expired_keys", "evicted_keys",
			"keyspace_hits", "keyspace_misses",
			"total_net_input_bytes", "total_net_output_bytes",
			"pubsub_channels", "pubsub_patterns",
			"migrate_cached_sockets", "expired_stale_perc",
			// Replication
			"role", "connected_slaves", "master_link_status",
			"master_last_io_seconds_ago", "master_host", "master_port",
			"master_sync_in_progress", "slave_repl_offset",
			"master_repl_offset", "repl_backlog_size",
			"repl_backlog_active", "second_repl_offset",
			// CPU
			"used_cpu_sys", "used_cpu_user",
			"used_cpu_sys_children", "used_cpu_user_children",
			// Keyspace
			"db0", "db1", "db2", "db3", "db4", "db5",
			"db6", "db7", "db8", "db9", "db10", "db11",
			"db12", "db13", "db14", "db15",
			// Latency
			"latency_percentiles_usec_p50", "latency_percentiles_usec_p99",
			"latency_percentiles_usec_p99.9",
			// Cluster
			"cluster_enabled",
		} {
			if v, ok := info[key]; ok {
				inst.DeepMetrics[key] = v
			}
		}

		if v, ok := info["redis_version"]; ok {
			inst.Version = v
		}

		// Collect commandstats (cmdstat_get, cmdstat_set, etc.)
		for k, v := range info {
			if strings.HasPrefix(k, "cmdstat_") {
				inst.DeepMetrics[k] = v
			}
		}

		// Compute hit ratio
		hits, _ := strconv.ParseFloat(info["keyspace_hits"], 64)
		misses, _ := strconv.ParseFloat(info["keyspace_misses"], 64)
		if hits+misses > 100 {
			ratio := hits / (hits + misses) * 100
			inst.DeepMetrics["hit_ratio"] = fmt.Sprintf("%.1f%%", ratio)
		}

		// Compute memory usage %
		usedMem, _ := strconv.ParseFloat(info["used_memory"], 64)
		maxMem, _ := strconv.ParseFloat(info["maxmemory"], 64)
		if maxMem > 0 {
			pct := usedMem / maxMem * 100
			inst.DeepMetrics["memory_usage_pct"] = fmt.Sprintf("%.1f%%", pct)
		}

		// Total keys across all databases
		totalKeys := 0
		totalExpires := 0
		for i := 0; i <= 15; i++ {
			dbKey := fmt.Sprintf("db%d", i)
			if v, ok := info[dbKey]; ok {
				// format: keys=123,expires=45,avg_ttl=67890
				for _, part := range strings.Split(v, ",") {
					kv := strings.SplitN(part, "=", 2)
					if len(kv) == 2 {
						if kv[0] == "keys" {
							n, _ := strconv.Atoi(kv[1])
							totalKeys += n
						}
						if kv[0] == "expires" {
							n, _ := strconv.Atoi(kv[1])
							totalExpires += n
						}
					}
				}
			}
		}
		inst.DeepMetrics["total_keys"] = fmt.Sprintf("%d", totalKeys)
		inst.DeepMetrics["total_expires"] = fmt.Sprintf("%d", totalExpires)

		// Compute RSS vs used memory ratio (overhead from OS allocator)
		usedMemRSS, _ := strconv.ParseFloat(info["used_memory_rss"], 64)
		if usedMem > 0 && usedMemRSS > 0 {
			rssRatio := usedMemRSS / usedMem
			inst.DeepMetrics["rss_overhead_ratio"] = fmt.Sprintf("%.2f", rssRatio)
		}

		// Client capacity %
		connClients, _ := strconv.Atoi(info["connected_clients"])
		maxClients, _ := strconv.Atoi(info["maxclients"])
		if maxClients > 0 && connClients > 0 {
			clientPct := float64(connClients) / float64(maxClients) * 100
			inst.DeepMetrics["client_capacity_pct"] = fmt.Sprintf("%.1f%%", clientPct)
		}

		// Replication lag (for slaves)
		if info["role"] == "slave" {
			slaveOff, _ := strconv.ParseInt(info["slave_repl_offset"], 10, 64)
			masterOff, _ := strconv.ParseInt(info["master_repl_offset"], 10, 64)
			if masterOff > 0 && slaveOff > 0 {
				lag := masterOff - slaveOff
				inst.DeepMetrics["repl_lag_bytes"] = fmt.Sprintf("%d", lag)
			}
		}

		// Expired keys ratio (keys with TTL that have expired)
		if totalKeys > 0 && totalExpires > 0 {
			expPct := float64(totalExpires) / float64(totalKeys) * 100
			inst.DeepMetrics["expire_coverage_pct"] = fmt.Sprintf("%.1f%%", expPct)
		}

		// Fork duration (latest_fork_usec) — for RDB/AOF operations
		if forkUsec := info["latest_fork_usec"]; forkUsec != "" {
			inst.DeepMetrics["latest_fork_usec"] = forkUsec
		}
	}

	// Tier 3: SLOWLOG GET (separate command, same connection reuse not possible — new conn)
	if info != nil {
		slowEntries := redisSLOWLOG(host, port, password, 10)
		if len(slowEntries) > 0 {
			inst.DeepMetrics["slowlog_count"] = fmt.Sprintf("%d", len(slowEntries))
			// Encode top entries as JSON-like format for display
			var slowLines []string
			for i, entry := range slowEntries {
				if i >= 5 {
					break
				}
				slowLines = append(slowLines, fmt.Sprintf("%s|%.2fms|%s",
					entry.timestamp.Format("15:04:05"),
					float64(entry.duration)/1000.0,
					entry.command))
			}
			inst.DeepMetrics["slowlog_entries"] = strings.Join(slowLines, ";")
			// Max slow query duration
			maxDur := int64(0)
			for _, e := range slowEntries {
				if e.duration > maxDur {
					maxDur = e.duration
				}
			}
			inst.DeepMetrics["slowlog_max_usec"] = fmt.Sprintf("%d", maxDur)
		}
	}

	// Generate recommendations based on actual workload
	if info != nil {
		recs := redisRecommendations(inst.DeepMetrics)
		for i, r := range recs {
			inst.DeepMetrics[fmt.Sprintf("rec_%d", i)] = r
		}
		inst.DeepMetrics["rec_count"] = fmt.Sprintf("%d", len(recs))
	}

	// Health scoring
	inst.HealthScore = 100

	if inst.HasDeepMetrics {
		// Evictions
		if evicted, _ := strconv.ParseInt(inst.DeepMetrics["evicted_keys"], 10, 64); evicted > 0 {
			inst.HealthScore -= 15
			inst.HealthIssues = append(inst.HealthIssues,
				fmt.Sprintf("evicting keys (%d) — maxmemory too low", evicted))
		}

		// Memory pressure
		usedMem, _ := strconv.ParseFloat(inst.DeepMetrics["used_memory"], 64)
		maxMem, _ := strconv.ParseFloat(inst.DeepMetrics["maxmemory"], 64)
		if maxMem > 0 && usedMem > 0 {
			pct := usedMem / maxMem * 100
			if pct > 90 {
				inst.HealthScore -= 10
				inst.HealthIssues = append(inst.HealthIssues,
					fmt.Sprintf("memory at %.0f%% of maxmemory", pct))
			}
		}

		// Hit ratio
		if inst.DeepMetrics["hit_ratio"] != "" {
			var ratio float64
			fmt.Sscanf(inst.DeepMetrics["hit_ratio"], "%f", &ratio)
			if ratio < 80 && ratio > 0 {
				inst.HealthScore -= 10
				inst.HealthIssues = append(inst.HealthIssues,
					fmt.Sprintf("hit ratio %.1f%% — ineffective caching", ratio))
			}
		}

		// Blocked clients
		if blocked, _ := strconv.Atoi(inst.DeepMetrics["blocked_clients"]); blocked > 10 {
			inst.HealthScore -= 5
			inst.HealthIssues = append(inst.HealthIssues,
				fmt.Sprintf("%d blocked clients", blocked))
		}

		// Memory fragmentation
		if fragStr := inst.DeepMetrics["mem_fragmentation_ratio"]; fragStr != "" {
			frag, _ := strconv.ParseFloat(fragStr, 64)
			if frag > 1.5 {
				inst.HealthScore -= 5
				inst.HealthIssues = append(inst.HealthIssues,
					fmt.Sprintf("memory fragmentation %.2f — consider restart", frag))
			}
		}

		// RDB save failure
		if inst.DeepMetrics["rdb_last_bgsave_status"] == "err" {
			inst.HealthScore -= 10
			inst.HealthIssues = append(inst.HealthIssues, "last RDB save failed")
		}

		// Rejected connections
		if rejected, _ := strconv.ParseInt(inst.DeepMetrics["rejected_connections"], 10, 64); rejected > 0 {
			inst.HealthScore -= 5
			inst.HealthIssues = append(inst.HealthIssues,
				fmt.Sprintf("%d rejected connections — increase maxclients", rejected))
		}

		// Replication broken
		if inst.DeepMetrics["role"] == "slave" && inst.DeepMetrics["master_link_status"] == "down" {
			inst.HealthScore -= 20
			inst.HealthIssues = append(inst.HealthIssues, "replication link DOWN")
		}

		// Latency p99
		if p99Str := inst.DeepMetrics["latency_percentiles_usec_p99"]; p99Str != "" {
			p99, _ := strconv.ParseFloat(p99Str, 64)
			if p99 > 10000 { // >10ms
				inst.HealthScore -= 10
				inst.HealthIssues = append(inst.HealthIssues,
					fmt.Sprintf("p99 latency %.1fms — slow responses", p99/1000))
			} else if p99 > 1000 { // >1ms
				inst.HealthScore -= 5
				inst.HealthIssues = append(inst.HealthIssues,
					fmt.Sprintf("p99 latency %.1fms — elevated", p99/1000))
			}
		}

		// RSS overhead ratio (RSS much larger than used_memory = fragmentation/allocator waste)
		if rssStr := inst.DeepMetrics["rss_overhead_ratio"]; rssStr != "" {
			rssRatio, _ := strconv.ParseFloat(rssStr, 64)
			if rssRatio > 2.0 {
				inst.HealthScore -= 5
				inst.HealthIssues = append(inst.HealthIssues,
					fmt.Sprintf("RSS %.1fx used memory — allocator overhead/fragmentation", rssRatio))
			}
		}

		// Client capacity (approaching maxclients)
		if capStr := inst.DeepMetrics["client_capacity_pct"]; capStr != "" {
			var capPct float64
			fmt.Sscanf(capStr, "%f", &capPct)
			if capPct > 80 {
				inst.HealthScore -= 5
				inst.HealthIssues = append(inst.HealthIssues,
					fmt.Sprintf("clients at %.0f%% of maxclients — risk of rejection", capPct))
			}
		}

		// Replication lag (for slaves with offset data)
		if lagStr := inst.DeepMetrics["repl_lag_bytes"]; lagStr != "" {
			lag, _ := strconv.ParseInt(lagStr, 10, 64)
			if lag > 10*1024*1024 { // >10MB lag
				inst.HealthScore -= 10
				inst.HealthIssues = append(inst.HealthIssues,
					fmt.Sprintf("replication lag %s — slave falling behind", redisFmtBytes(lag)))
			}
		}

		// Slow queries
		if slowMax := inst.DeepMetrics["slowlog_max_usec"]; slowMax != "" {
			maxUs, _ := strconv.ParseInt(slowMax, 10, 64)
			if maxUs > 500000 { // >500ms
				inst.HealthScore -= 5
				inst.HealthIssues = append(inst.HealthIssues,
					fmt.Sprintf("slow queries detected (max %.1fms)", float64(maxUs)/1000))
			}
		}

		// Fork duration (>500ms indicates large dataset causing fork delays)
		if forkStr := inst.DeepMetrics["latest_fork_usec"]; forkStr != "" {
			forkUs, _ := strconv.ParseInt(forkStr, 10, 64)
			if forkUs > 500000 { // >500ms
				inst.HealthScore -= 5
				inst.HealthIssues = append(inst.HealthIssues,
					fmt.Sprintf("fork took %.1fms — large dataset slowing persistence", float64(forkUs)/1000))
			}
		}

		// AOF rewrite in progress
		if inst.DeepMetrics["aof_rewrite_in_progress"] == "1" {
			inst.HealthIssues = append(inst.HealthIssues, "AOF rewrite in progress")
		}

		// Lazyfree pending
		if lfStr := inst.DeepMetrics["lazyfree_pending_objects"]; lfStr != "" && lfStr != "0" {
			lf, _ := strconv.ParseInt(lfStr, 10, 64)
			if lf > 1000 {
				inst.HealthScore -= 3
				inst.HealthIssues = append(inst.HealthIssues,
					fmt.Sprintf("%d lazyfree pending objects", lf))
			}
		}

		// Master IO too old (slave hasn't heard from master recently)
		if inst.DeepMetrics["role"] == "slave" {
			if ioAgo := inst.DeepMetrics["master_last_io_seconds_ago"]; ioAgo != "" {
				secs, _ := strconv.Atoi(ioAgo)
				if secs > 10 {
					inst.HealthScore -= 5
					inst.HealthIssues = append(inst.HealthIssues,
						fmt.Sprintf("last master IO %ds ago — possible link issue", secs))
				}
			}
		}
	}

	if inst.HealthScore < 0 {
		inst.HealthScore = 0
	}

	return inst
}

// redisINFO connects to Redis and runs the INFO command using raw RESP protocol.
func redisINFO(host string, port int, password string) map[string]string {
	addr := fmt.Sprintf("%s:%d", host, port)
	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		return nil
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(3 * time.Second))

	reader := bufio.NewReader(conn)

	// AUTH if password provided
	if password != "" {
		fmt.Fprintf(conn, "*2\r\n$4\r\nAUTH\r\n$%d\r\n%s\r\n", len(password), password)
		line, err := reader.ReadString('\n')
		if err != nil || (!strings.HasPrefix(line, "+OK") && !strings.HasPrefix(line, "+")) {
			return nil
		}
	}

	// Send INFO ALL command (includes commandstats)
	fmt.Fprintf(conn, "*2\r\n$4\r\nINFO\r\n$3\r\nALL\r\n")

	// Read bulk string header: $<length>\r\n
	header, err := reader.ReadString('\n')
	if err != nil || !strings.HasPrefix(header, "$") {
		return nil
	}

	length, err := strconv.Atoi(strings.TrimSpace(header[1:]))
	if err != nil || length <= 0 || length > 4*1024*1024 {
		return nil
	}

	// Read the bulk data
	data := make([]byte, length+2) // +2 for trailing \r\n
	n, err := io.ReadFull(reader, data)
	if err != nil && n == 0 {
		return nil
	}

	// Parse INFO response (key:value pairs, # Section headers)
	result := make(map[string]string)
	for _, line := range strings.Split(string(data[:n]), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, ":", 2)
		if len(parts) == 2 {
			result[parts[0]] = strings.TrimSpace(parts[1])
		}
	}

	return result
}

type slowlogEntry struct {
	timestamp time.Time
	duration  int64 // microseconds
	command   string
}

// redisSLOWLOG fetches recent slow queries via SLOWLOG GET N.
func redisSLOWLOG(host string, port int, password string, count int) []slowlogEntry {
	addr := fmt.Sprintf("%s:%d", host, port)
	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		return nil
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(3 * time.Second))

	reader := bufio.NewReader(conn)

	// AUTH if needed
	if password != "" {
		fmt.Fprintf(conn, "*2\r\n$4\r\nAUTH\r\n$%d\r\n%s\r\n", len(password), password)
		line, err := reader.ReadString('\n')
		if err != nil || !strings.HasPrefix(line, "+") {
			return nil
		}
	}

	// SLOWLOG GET <count>
	countStr := fmt.Sprintf("%d", count)
	fmt.Fprintf(conn, "*3\r\n$7\r\nSLOWLOG\r\n$3\r\nGET\r\n$%d\r\n%s\r\n",
		len(countStr), countStr)

	// Parse multibulk response — SLOWLOG returns array of arrays
	entries := parseSlowlogResp(reader)
	return entries
}

// parseSlowlogResp parses the RESP multi-bulk SLOWLOG response.
func parseSlowlogResp(reader *bufio.Reader) []slowlogEntry {
	line, err := reader.ReadString('\n')
	if err != nil || len(line) < 2 {
		return nil
	}
	line = strings.TrimSpace(line)
	if line[0] != '*' {
		return nil
	}
	outerCount, _ := strconv.Atoi(line[1:])
	if outerCount <= 0 {
		return nil
	}

	var entries []slowlogEntry
	for i := 0; i < outerCount; i++ {
		entry := parseSlowlogEntry(reader)
		if entry != nil {
			entries = append(entries, *entry)
		}
	}
	return entries
}

func parseSlowlogEntry(reader *bufio.Reader) *slowlogEntry {
	// Each entry is: *4+ (id, timestamp, duration, [command args...], ...)
	line, err := reader.ReadString('\n')
	if err != nil {
		return nil
	}
	line = strings.TrimSpace(line)
	if line[0] != '*' {
		return nil
	}
	fields, _ := strconv.Atoi(line[1:])
	if fields < 4 {
		return nil
	}

	// Field 0: entry ID (integer)
	readRespInt(reader) // skip ID

	// Field 1: timestamp (unix seconds)
	ts := readRespInt(reader)

	// Field 2: duration (microseconds)
	dur := readRespInt(reader)

	// Field 3: command args (array of bulk strings)
	cmdLine, err := reader.ReadString('\n')
	if err != nil {
		return nil
	}
	cmdLine = strings.TrimSpace(cmdLine)
	var cmdParts []string
	if cmdLine[0] == '*' {
		argCount, _ := strconv.Atoi(cmdLine[1:])
		for j := 0; j < argCount; j++ {
			s := readRespBulk(reader)
			if j < 4 { // Only keep first 4 args to keep it readable
				cmdParts = append(cmdParts, s)
			}
		}
	}

	// Skip remaining fields (client addr, client name in newer Redis)
	for f := 4; f < fields; f++ {
		skipRespValue(reader)
	}

	cmd := strings.Join(cmdParts, " ")
	if len(cmd) > 60 {
		cmd = cmd[:57] + "..."
	}

	return &slowlogEntry{
		timestamp: time.Unix(ts, 0),
		duration:  dur,
		command:   cmd,
	}
}

func readRespInt(reader *bufio.Reader) int64 {
	line, err := reader.ReadString('\n')
	if err != nil {
		return 0
	}
	line = strings.TrimSpace(line)
	if line[0] == ':' {
		v, _ := strconv.ParseInt(line[1:], 10, 64)
		return v
	}
	return 0
}

func readRespBulk(reader *bufio.Reader) string {
	line, err := reader.ReadString('\n')
	if err != nil {
		return ""
	}
	line = strings.TrimSpace(line)
	if line[0] != '$' {
		return ""
	}
	size, _ := strconv.Atoi(line[1:])
	if size < 0 {
		return ""
	}
	data := make([]byte, size+2)
	io.ReadFull(reader, data)
	return string(data[:size])
}

func skipRespValue(reader *bufio.Reader) {
	line, err := reader.ReadString('\n')
	if err != nil {
		return
	}
	line = strings.TrimSpace(line)
	if len(line) == 0 {
		return
	}
	switch line[0] {
	case '+', '-', ':':
		return
	case '$':
		size, _ := strconv.Atoi(line[1:])
		if size > 0 {
			data := make([]byte, size+2)
			io.ReadFull(reader, data)
		}
	case '*':
		count, _ := strconv.Atoi(line[1:])
		for i := 0; i < count; i++ {
			skipRespValue(reader)
		}
	}
}

func redisFmtBytes(b int64) string {
	switch {
	case b >= 1<<30:
		return fmt.Sprintf("%.1fGB", float64(b)/(1<<30))
	case b >= 1<<20:
		return fmt.Sprintf("%.1fMB", float64(b)/(1<<20))
	case b >= 1<<10:
		return fmt.Sprintf("%.1fKB", float64(b)/(1<<10))
	default:
		return fmt.Sprintf("%dB", b)
	}
}

// redisRecommendations analyzes actual workload and generates specific setup advice.
func redisRecommendations(dm map[string]string) []string {
	var recs []string

	opsPerSec, _ := strconv.ParseFloat(dm["instantaneous_ops_per_sec"], 64)
	usedMem, _ := strconv.ParseFloat(dm["used_memory"], 64)
	maxMem, _ := strconv.ParseFloat(dm["maxmemory"], 64)
	connClients, _ := strconv.Atoi(dm["connected_clients"])
	maxClients, _ := strconv.Atoi(dm["maxclients"])
	totalKeys, _ := strconv.Atoi(dm["total_keys"])
	totalExpires, _ := strconv.Atoi(dm["total_expires"])
	evicted, _ := strconv.ParseInt(dm["evicted_keys"], 10, 64)
	policy := dm["maxmemory_policy"]
	frag, _ := strconv.ParseFloat(dm["mem_fragmentation_ratio"], 64)
	aofEnabled := dm["aof_enabled"]
	rdbStatus := dm["rdb_last_bgsave_status"]
	role := dm["role"]
	connSlaves, _ := strconv.Atoi(dm["connected_slaves"])
	inputKbps, _ := strconv.ParseFloat(dm["instantaneous_input_kbps"], 64)
	outputKbps, _ := strconv.ParseFloat(dm["instantaneous_output_kbps"], 64)
	p99, _ := strconv.ParseFloat(dm["latency_percentiles_usec_p99"], 64)
	forkUsec, _ := strconv.ParseInt(dm["latest_fork_usec"], 10, 64)
	rejected, _ := strconv.ParseInt(dm["rejected_connections"], 10, 64)

	// --- Memory recommendations ---
	if maxMem == 0 && usedMem > 0 {
		// No maxmemory set — dangerous in production
		suggestMB := int(usedMem / (1024 * 1024) * 1.5)
		if suggestMB < 256 {
			suggestMB = 256
		}
		recs = append(recs, fmt.Sprintf("SET maxmemory %dMB — no limit set, Redis will consume all RAM until OOM killer strikes. Based on current usage (%.0fMB), set to ~%dMB",
			suggestMB, usedMem/(1024*1024), suggestMB))
	} else if maxMem > 0 && usedMem > 0 {
		pct := usedMem / maxMem * 100
		if pct > 85 {
			newMB := int(maxMem / (1024 * 1024) * 1.3)
			recs = append(recs, fmt.Sprintf("INCREASE maxmemory to ~%dMB — currently at %.0f%%, approaching limit. Risk of evictions/OOM",
				newMB, pct))
		}
	}

	// Eviction policy
	if evicted > 0 && policy == "noeviction" {
		recs = append(recs, "SET maxmemory-policy allkeys-lru — evictions happening with noeviction policy (writes rejected). Use allkeys-lru for cache workloads")
	} else if evicted > 0 && (policy == "volatile-lru" || policy == "volatile-random") {
		if totalKeys > 0 && totalExpires == 0 {
			recs = append(recs, fmt.Sprintf("CHANGE policy to allkeys-lru — using %s but 0 keys have TTL, so volatile-* policies can't evict anything", policy))
		}
	} else if totalKeys > 0 && totalExpires == totalKeys && policy == "noeviction" {
		recs = append(recs, "SET maxmemory-policy volatile-ttl — all keys have TTL, volatile-ttl will evict keys closest to expiry first")
	} else if totalKeys > 0 && float64(totalExpires)/float64(totalKeys) < 0.1 && policy != "noeviction" && policy != "allkeys-lru" && policy != "allkeys-lfu" {
		recs = append(recs, "CONSIDER allkeys-lru or allkeys-lfu — less than 10% of keys have TTL, volatile-* policies won't help")
	}

	// Fragmentation
	if frag > 1.5 && usedMem > 100*1024*1024 {
		recs = append(recs, fmt.Sprintf("HIGH memory fragmentation (%.2f) — Redis using %.0fMB more RSS than needed. Run MEMORY PURGE or schedule restart during low traffic",
			frag, (frag-1)*usedMem/(1024*1024)))
	} else if frag < 1.0 && frag > 0 {
		recs = append(recs, fmt.Sprintf("LOW fragmentation ratio (%.2f) — Redis using swap or has memory pressure, check system memory availability", frag))
	}

	// --- Connection recommendations ---
	if maxClients > 0 && connClients > 0 {
		clientPct := float64(connClients) / float64(maxClients) * 100
		if clientPct > 60 {
			newMax := connClients * 3
			if newMax < 1000 {
				newMax = 1000
			}
			recs = append(recs, fmt.Sprintf("INCREASE maxclients to %d — at %.0f%% capacity (%d/%d). Connection pool exhaustion risk",
				newMax, clientPct, connClients, maxClients))
		}
	}
	if rejected > 0 {
		recs = append(recs, fmt.Sprintf("FIX rejected connections (%d total) — increase maxclients and check connection pooling in application", rejected))
	}

	// --- Persistence recommendations ---
	if aofEnabled == "0" && rdbStatus != "ok" && rdbStatus != "" {
		recs = append(recs, "ENABLE AOF (appendonly yes) — RDB saves failing and AOF disabled, data loss risk on crash")
	}
	if forkUsec > 500000 && usedMem > 1024*1024*1024 { // >500ms fork, >1GB dataset
		recs = append(recs, fmt.Sprintf("LARGE fork delay (%.0fms for %.1fGB) — consider disabling RDB if AOF is enabled, or use BGSAVE during off-peak hours",
			float64(forkUsec)/1000, usedMem/(1024*1024*1024)))
	}
	if aofEnabled == "1" {
		if aofSize := dm["aof_current_size"]; aofSize != "" {
			aofBytes, _ := strconv.ParseFloat(aofSize, 64)
			if aofBytes > usedMem*2 && usedMem > 0 {
				recs = append(recs, "AOF file is >2x data size — run BGREWRITEAOF to compact, or set auto-aof-rewrite-percentage")
			}
		}
	}

	// --- Performance recommendations ---
	if opsPerSec > 50000 && p99 > 5000 {
		recs = append(recs, fmt.Sprintf("HIGH throughput (%.0f ops/s) with elevated p99 (%.1fms) — consider io-threads for multi-threaded I/O (Redis 6+)",
			opsPerSec, p99/1000))
	}
	if inputKbps+outputKbps > 100*1024 { // >100MB/s
		recs = append(recs, fmt.Sprintf("HEAVY network I/O (%.0fMB/s in + %.0fMB/s out) — ensure 10GbE NIC, consider client-side caching or pipeline batching",
			inputKbps/1024, outputKbps/1024))
	}

	// TTL recommendations
	if totalKeys > 10000 && totalExpires == 0 {
		recs = append(recs, fmt.Sprintf("NO TTL on any of %d keys — if this is cache data, set TTL to prevent unbounded growth", totalKeys))
	} else if totalKeys > 10000 && float64(totalExpires)/float64(totalKeys) < 0.2 {
		recs = append(recs, fmt.Sprintf("Only %.0f%% of %d keys have TTL — consider adding TTL to prevent memory growth",
			float64(totalExpires)/float64(totalKeys)*100, totalKeys))
	}

	// Replication
	if role == "master" && connSlaves == 0 && totalKeys > 100000 {
		recs = append(recs, "NO replicas configured with large dataset — add a replica for HA and read scaling")
	}

	// Slow queries
	if slowMax := dm["slowlog_max_usec"]; slowMax != "" {
		maxUs, _ := strconv.ParseInt(slowMax, 10, 64)
		if maxUs > 100000 { // >100ms
			recs = append(recs, fmt.Sprintf("SLOW queries detected (max %.0fms) — review SLOWLOG, avoid O(N) commands like KEYS, SMEMBERS on large sets",
				float64(maxUs)/1000))
		}
	}

	return recs
}
