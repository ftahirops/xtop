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
	if info == nil && password == "" {
		inst.NeedsCreds = true
	}

	if info != nil {
		inst.HasDeepMetrics = true

		// All keys we want to collect
		for _, key := range []string{
			// Server
			"redis_version", "redis_mode", "os", "uptime_in_seconds",
			"tcp_port", "config_file",
			// Clients
			"connected_clients", "blocked_clients", "tracking_clients",
			"maxclients",
			// Memory
			"used_memory", "used_memory_human", "used_memory_rss_human",
			"used_memory_peak_human", "used_memory_lua_human",
			"used_memory_dataset_perc",
			"maxmemory", "maxmemory_human", "maxmemory_policy",
			"mem_fragmentation_ratio",
			// Persistence
			"rdb_last_save_time", "rdb_last_bgsave_status",
			"rdb_last_bgsave_time_sec", "rdb_changes_since_last_save",
			"aof_enabled", "aof_last_bgrewrite_status",
			// Stats
			"total_connections_received", "total_commands_processed",
			"instantaneous_ops_per_sec", "instantaneous_input_kbps",
			"instantaneous_output_kbps",
			"rejected_connections", "expired_keys", "evicted_keys",
			"keyspace_hits", "keyspace_misses",
			"total_net_input_bytes", "total_net_output_bytes",
			// Replication
			"role", "connected_slaves", "master_link_status",
			"master_last_io_seconds_ago", "master_host", "master_port",
			// CPU
			"used_cpu_sys", "used_cpu_user",
			// Keyspace
			"db0", "db1", "db2", "db3", "db4", "db5",
			"db6", "db7", "db8", "db9", "db10", "db11",
			"db12", "db13", "db14", "db15",
			// Latency
			"latency_percentiles_usec_p50", "latency_percentiles_usec_p99",
		} {
			if v, ok := info[key]; ok {
				inst.DeepMetrics[key] = v
			}
		}

		if v, ok := info["redis_version"]; ok {
			inst.Version = v
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

	// Send INFO command
	fmt.Fprintf(conn, "*1\r\n$4\r\nINFO\r\n")

	// Read bulk string header: $<length>\r\n
	header, err := reader.ReadString('\n')
	if err != nil || !strings.HasPrefix(header, "$") {
		return nil
	}

	length, err := strconv.Atoi(strings.TrimSpace(header[1:]))
	if err != nil || length <= 0 || length > 1024*1024 {
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
