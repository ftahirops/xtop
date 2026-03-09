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
	if info != nil {
		inst.HasDeepMetrics = true

		for _, key := range []string{
			"redis_version", "used_memory_human", "used_memory_peak_human",
			"maxmemory_human", "connected_clients", "blocked_clients",
			"instantaneous_ops_per_sec", "total_commands_processed",
			"keyspace_hits", "keyspace_misses", "evicted_keys",
			"expired_keys", "role", "connected_slaves",
			"master_link_status", "master_last_io_seconds_ago",
			"used_memory", "maxmemory",
		} {
			if v, ok := info[key]; ok {
				inst.DeepMetrics[key] = v
			}
		}

		if v, ok := info["redis_version"]; ok {
			inst.Version = v
		}
	} else {
		// No connection — try without password (Redis default has no auth)
		if password != "" {
			inst.NeedsCreds = false // already tried with creds
		} else {
			info = redisINFO(host, port, "")
			if info != nil {
				inst.HasDeepMetrics = true
				for _, key := range []string{
					"redis_version", "used_memory_human", "maxmemory_human",
					"connected_clients", "instantaneous_ops_per_sec",
					"keyspace_hits", "keyspace_misses", "evicted_keys",
					"role", "connected_slaves", "used_memory", "maxmemory",
				} {
					if v, ok := info[key]; ok {
						inst.DeepMetrics[key] = v
					}
				}
				if v, ok := info["redis_version"]; ok {
					inst.Version = v
				}
			} else {
				inst.NeedsCreds = true
			}
		}
	}

	// Health scoring — only flag actual degradation
	inst.HealthScore = 100

	if inst.HasDeepMetrics {
		// Evictions = data loss
		if evicted, _ := strconv.ParseInt(inst.DeepMetrics["evicted_keys"], 10, 64); evicted > 0 {
			inst.HealthScore -= 15
			inst.HealthIssues = append(inst.HealthIssues,
				fmt.Sprintf("evicting keys (%d) — maxmemory too low or data growing", evicted))
		}

		// Memory near max
		usedMem, _ := strconv.ParseFloat(inst.DeepMetrics["used_memory"], 64)
		maxMem, _ := strconv.ParseFloat(inst.DeepMetrics["maxmemory"], 64)
		if maxMem > 0 && usedMem > 0 {
			pct := usedMem / maxMem * 100
			if pct > 90 {
				inst.HealthScore -= 10
				inst.HealthIssues = append(inst.HealthIssues,
					fmt.Sprintf("memory at %.0f%% of maxmemory — evictions imminent", pct))
			}
		}

		// Hit ratio
		hits, _ := strconv.ParseFloat(inst.DeepMetrics["keyspace_hits"], 64)
		misses, _ := strconv.ParseFloat(inst.DeepMetrics["keyspace_misses"], 64)
		if hits+misses > 100 {
			hitRatio := hits / (hits + misses) * 100
			inst.DeepMetrics["hit_ratio"] = fmt.Sprintf("%.1f%%", hitRatio)
			if hitRatio < 80 {
				inst.HealthScore -= 10
				inst.HealthIssues = append(inst.HealthIssues,
					fmt.Sprintf("cache hit ratio %.1f%% — keys expiring too fast or wrong eviction policy", hitRatio))
			}
		}

		// Blocked clients
		if blocked, _ := strconv.Atoi(inst.DeepMetrics["blocked_clients"]); blocked > 10 {
			inst.HealthScore -= 5
			inst.HealthIssues = append(inst.HealthIssues,
				fmt.Sprintf("%d blocked clients — slow commands or BLPOP waits", blocked))
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
