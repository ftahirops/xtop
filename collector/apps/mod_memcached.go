//go:build linux

package apps

import (
	"bufio"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/ftahirops/xtop/model"
)

type memcachedModule struct{}

func NewMemcachedModule() AppModule { return &memcachedModule{} }

func (m *memcachedModule) Type() string        { return "memcached" }
func (m *memcachedModule) DisplayName() string { return "Memcached" }

func (m *memcachedModule) Detect(processes []model.ProcessMetrics) []DetectedApp {
	var apps []DetectedApp
	for _, p := range processes {
		if p.Comm == "memcached" {
			port := 11211
			cmdline := readProcCmdline(p.PID)
			for i, arg := range strings.Fields(cmdline) {
				if arg == "-p" {
					parts := strings.Fields(cmdline)
					if i+1 < len(parts) {
						if p, err := strconv.Atoi(parts[i+1]); err == nil {
							port = p
						}
					}
				}
			}
			apps = append(apps, DetectedApp{
				PID: p.PID, Port: port, Comm: p.Comm,
				Cmdline: cmdline, Index: len(apps),
			})
		}
	}
	return apps
}

func (m *memcachedModule) Collect(app *DetectedApp, secrets *AppSecrets) model.AppInstance {
	inst := model.AppInstance{
		AppType: "memcached", DisplayName: "Memcached",
		PID: app.PID, Port: app.Port, Status: "active",
		UptimeSec: readProcUptime(app.PID), DeepMetrics: make(map[string]string),
	}

	inst.RSSMB = readProcRSS(app.PID)
	inst.Threads = readProcThreads(app.PID)
	inst.FDs = readProcFDs(app.PID)
	inst.Connections = countTCPConnections(app.Port)

	// Tier 2: stats command (no auth needed)
	stats := memcachedStats(app.Port)
	if stats != nil {
		inst.HasDeepMetrics = true
		for _, key := range []string{
			"version", "curr_connections", "total_connections",
			"get_hits", "get_misses", "evictions", "bytes", "limit_maxbytes",
			"curr_items", "total_items", "cmd_get", "cmd_set",
		} {
			if v, ok := stats[key]; ok {
				inst.DeepMetrics[key] = v
			}
		}
		if v, ok := stats["version"]; ok {
			inst.Version = v
		}

		// Hit ratio
		hits, _ := strconv.ParseFloat(stats["get_hits"], 64)
		misses, _ := strconv.ParseFloat(stats["get_misses"], 64)
		if hits+misses > 100 {
			hitRatio := hits / (hits + misses) * 100
			inst.DeepMetrics["hit_ratio"] = fmt.Sprintf("%.1f%%", hitRatio)
		}
	}

	inst.HealthScore = 100
	if inst.HasDeepMetrics {
		if evicted, _ := strconv.ParseInt(inst.DeepMetrics["evictions"], 10, 64); evicted > 0 {
			inst.HealthScore -= 15
			inst.HealthIssues = append(inst.HealthIssues,
				fmt.Sprintf("evicting keys (%d) — increase memory limit", evicted))
		}
		usedBytes, _ := strconv.ParseFloat(inst.DeepMetrics["bytes"], 64)
		maxBytes, _ := strconv.ParseFloat(inst.DeepMetrics["limit_maxbytes"], 64)
		if maxBytes > 0 && usedBytes/maxBytes > 0.9 {
			inst.HealthScore -= 10
			inst.HealthIssues = append(inst.HealthIssues, "memory near limit")
		}
	}
	if inst.HealthScore < 0 {
		inst.HealthScore = 0
	}

	return inst
}

func memcachedStats(port int) map[string]string {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 2*time.Second)
	if err != nil {
		return nil
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(3 * time.Second))

	fmt.Fprintf(conn, "stats\r\n")

	result := make(map[string]string)
	scanner := bufio.NewScanner(conn)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "END" {
			break
		}
		// Format: STAT <key> <value>
		parts := strings.Fields(line)
		if len(parts) == 3 && parts[0] == "STAT" {
			result[parts[1]] = parts[2]
		}
	}
	if len(result) == 0 {
		return nil
	}
	return result
}
