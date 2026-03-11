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
			fields := strings.Fields(cmdline)
			for i, arg := range fields {
				if arg == "-p" && i+1 < len(fields) {
					if p, err := strconv.Atoi(fields[i+1]); err == nil {
						port = p
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
	inst.CPUPct = readProcCPUPct(app.PID, inst.UptimeSec)

	// Parse cmdline for config values
	memcachedParseCmdline(app.Cmdline, inst.DeepMetrics)

	// Tier 2: stats + stats slabs (no auth needed)
	stats, slabs := memcachedAllStats(app.Port)
	if stats != nil {
		inst.HasDeepMetrics = true

		// Store all interesting stats keys
		for _, key := range []string{
			"version", "uptime",
			"curr_connections", "total_connections", "connection_structures",
			"accepting_conns", "listen_disabled_num", "rejected_connections",
			"threads",
			"cmd_get", "cmd_set", "cmd_flush",
			"get_hits", "get_misses",
			"delete_hits", "delete_misses",
			"incr_hits", "incr_misses", "decr_hits", "decr_misses",
			"cas_hits", "cas_misses", "cas_badval",
			"touch_hits", "touch_misses",
			"evictions", "reclaimed",
			"expired_unfetched", "evicted_unfetched",
			"bytes", "limit_maxbytes",
			"bytes_read", "bytes_written",
			"curr_items", "total_items",
			"slabs_moved",
			"rusage_user", "rusage_system",
		} {
			if v, ok := stats[key]; ok {
				inst.DeepMetrics[key] = v
			}
		}

		if v, ok := stats["version"]; ok {
			inst.Version = v
		}

		// Computed metrics
		hits, _ := strconv.ParseFloat(stats["get_hits"], 64)
		misses, _ := strconv.ParseFloat(stats["get_misses"], 64)
		uptime, _ := strconv.ParseFloat(stats["uptime"], 64)
		evictions, _ := strconv.ParseFloat(stats["evictions"], 64)
		usedBytes, _ := strconv.ParseFloat(stats["bytes"], 64)
		maxBytes, _ := strconv.ParseFloat(stats["limit_maxbytes"], 64)
		cmdGet, _ := strconv.ParseFloat(stats["cmd_get"], 64)
		cmdSet, _ := strconv.ParseFloat(stats["cmd_set"], 64)
		totalItems, _ := strconv.ParseFloat(stats["total_items"], 64)
		bytesRead, _ := strconv.ParseInt(stats["bytes_read"], 10, 64)
		bytesWritten, _ := strconv.ParseInt(stats["bytes_written"], 10, 64)

		// Hit ratio
		var hitRatio float64 = -1
		if hits+misses > 100 {
			hitRatio = hits / (hits + misses) * 100
			inst.DeepMetrics["hit_ratio"] = fmt.Sprintf("%.1f%%", hitRatio)
		}

		// Miss ratio
		if hits+misses > 100 {
			missRatio := misses / (hits + misses) * 100
			inst.DeepMetrics["miss_ratio"] = fmt.Sprintf("%.1f%%", missRatio)
		}

		// Memory usage percentage
		var memUsagePct float64
		if maxBytes > 0 {
			memUsagePct = usedBytes / maxBytes * 100
			inst.DeepMetrics["memory_usage_pct"] = fmt.Sprintf("%.1f%%", memUsagePct)
		}

		// Fill rate (items/sec average)
		if uptime > 0 {
			fillRate := totalItems / uptime
			inst.DeepMetrics["fill_rate"] = fmt.Sprintf("%.2f", fillRate)
		}

		// Eviction rate (evictions/sec)
		var evictionRate float64
		if uptime > 0 {
			evictionRate = evictions / uptime
			inst.DeepMetrics["eviction_rate"] = fmt.Sprintf("%.4f", evictionRate)
		}

		// Read/write ratio (cmd_get / cmd_set)
		if cmdSet > 0 {
			inst.DeepMetrics["cmd_ratio_get_set"] = fmt.Sprintf("%.2f", cmdGet/cmdSet)
		}

		// Human-readable byte counters
		if bytesRead > 0 {
			inst.DeepMetrics["bytes_read_human"] = formatBytes(bytesRead)
		}
		if bytesWritten > 0 {
			inst.DeepMetrics["bytes_written_human"] = formatBytes(bytesWritten)
		}

		// Slab analysis
		var slabWastePct float64 = -1
		if slabs != nil {
			slabCount, totalPages, totalChunks, usedChunks := memcachedAggregateSlabs(slabs)
			inst.DeepMetrics["slab_count"] = strconv.Itoa(slabCount)
			inst.DeepMetrics["total_pages"] = strconv.Itoa(totalPages)
			if totalChunks > 0 {
				slabWastePct = float64(totalChunks-usedChunks) / float64(totalChunks) * 100
				inst.DeepMetrics["slab_wasted_pct"] = fmt.Sprintf("%.1f%%", slabWastePct)
			}
		}

		// --- Health scoring ---
		inst.HealthScore = 100

		// Evictions penalty
		if evictions > 0 {
			inst.HealthScore -= 15
			inst.HealthIssues = append(inst.HealthIssues,
				fmt.Sprintf("evicting keys (%d) — increase memory limit", int64(evictions)))
		}

		// Eviction rate > 1/sec: additional penalty
		if evictionRate > 1.0 {
			inst.HealthScore -= 5
			inst.HealthIssues = append(inst.HealthIssues,
				fmt.Sprintf("high eviction rate (%.2f/sec)", evictionRate))
		}

		// Memory usage
		if maxBytes > 0 {
			if memUsagePct > 95 {
				inst.HealthScore -= 15
				inst.HealthIssues = append(inst.HealthIssues,
					fmt.Sprintf("memory critical (%.1f%% used)", memUsagePct))
			} else if memUsagePct > 90 {
				inst.HealthScore -= 10
				inst.HealthIssues = append(inst.HealthIssues, "memory near limit")
			}
		}

		// Hit ratio
		if hitRatio >= 0 {
			if hitRatio < 50 {
				inst.HealthScore -= 20
				inst.HealthIssues = append(inst.HealthIssues,
					fmt.Sprintf("very poor hit ratio (%.1f%%)", hitRatio))
			} else if hitRatio < 80 {
				inst.HealthScore -= 10
				inst.HealthIssues = append(inst.HealthIssues,
					fmt.Sprintf("poor hit ratio (%.1f%%)", hitRatio))
			}
		}

		// Connection issues
		rejectedConns, _ := strconv.ParseInt(stats["rejected_connections"], 10, 64)
		if rejectedConns > 0 {
			inst.HealthScore -= 10
			inst.HealthIssues = append(inst.HealthIssues,
				fmt.Sprintf("connections rejected (%d) — increase maxconns", rejectedConns))
		}

		listenDisabled, _ := strconv.ParseInt(stats["listen_disabled_num"], 10, 64)
		if listenDisabled > 0 {
			inst.HealthScore -= 5
			inst.HealthIssues = append(inst.HealthIssues,
				fmt.Sprintf("connection limit reached %d times", listenDisabled))
		}

		acceptingConns, _ := strconv.ParseInt(stats["accepting_conns"], 10, 64)
		if stats["accepting_conns"] != "" && acceptingConns == 0 {
			inst.HealthScore -= 20
			inst.HealthIssues = append(inst.HealthIssues,
				"NOT accepting connections — at maxconns")
		}

		// Slab waste
		if slabWastePct > 50 {
			inst.HealthScore -= 5
			inst.HealthIssues = append(inst.HealthIssues,
				fmt.Sprintf("high slab memory waste (%.1f%%)", slabWastePct))
		}

		// Expired unfetched
		expiredUnfetched, _ := strconv.ParseFloat(stats["expired_unfetched"], 64)
		if totalItems > 0 && expiredUnfetched > totalItems*0.10 {
			inst.HealthScore -= 5
			inst.HealthIssues = append(inst.HealthIssues,
				"items expiring before being read")
		}

		// Clamp
		if inst.HealthScore < 0 {
			inst.HealthScore = 0
		}
		if inst.HealthScore > 100 {
			inst.HealthScore = 100
		}
	} else {
		// No stats available — basic health only
		inst.HealthScore = 100
	}

	return inst
}

// memcachedParseCmdline extracts config flags from the memcached command line.
func memcachedParseCmdline(cmdline string, dm map[string]string) {
	fields := strings.Fields(cmdline)
	for i, arg := range fields {
		if i+1 >= len(fields) {
			break
		}
		switch arg {
		case "-m":
			dm["config_memory_mb"] = fields[i+1]
		case "-c":
			dm["config_max_connections"] = fields[i+1]
		case "-t":
			dm["config_threads"] = fields[i+1]
		}
	}
}

// memcachedAllStats connects to memcached and runs both "stats" and "stats slabs".
// Returns the general stats map and a per-slab-class map.
func memcachedAllStats(port int) (stats map[string]string, slabs map[int]map[string]string) {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 2*time.Second)
	if err != nil {
		return nil, nil
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))

	scanner := bufio.NewScanner(conn)

	// --- stats ---
	fmt.Fprintf(conn, "stats\r\n")
	stats = make(map[string]string)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "END" {
			break
		}
		parts := strings.Fields(line)
		if len(parts) == 3 && parts[0] == "STAT" {
			stats[parts[1]] = parts[2]
		}
	}
	if len(stats) == 0 {
		return nil, nil
	}

	// --- stats slabs ---
	fmt.Fprintf(conn, "stats slabs\r\n")
	slabs = make(map[int]map[string]string)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "END" {
			break
		}
		// Format: STAT <class>:<key> <value>   OR   STAT active_slabs <value>
		parts := strings.Fields(line)
		if len(parts) != 3 || parts[0] != "STAT" {
			continue
		}
		colonIdx := strings.IndexByte(parts[1], ':')
		if colonIdx < 0 {
			// Global slab stats like active_slabs, total_malloced — store in stats
			stats["slabs_"+parts[1]] = parts[2]
			continue
		}
		classStr := parts[1][:colonIdx]
		key := parts[1][colonIdx+1:]
		classID, err := strconv.Atoi(classStr)
		if err != nil {
			continue
		}
		if slabs[classID] == nil {
			slabs[classID] = make(map[string]string)
		}
		slabs[classID][key] = parts[2]
	}

	if len(slabs) == 0 {
		slabs = nil
	}
	return stats, slabs
}

// memcachedAggregateSlabs computes aggregate slab metrics.
// Returns: slabCount, totalPages, totalChunks, usedChunks.
func memcachedAggregateSlabs(slabs map[int]map[string]string) (int, int, int, int) {
	var slabCount, totalPages, totalChunks, usedChunks int
	for _, s := range slabs {
		slabCount++
		p, _ := strconv.Atoi(s["total_pages"])
		totalPages += p
		tc, _ := strconv.Atoi(s["total_chunks"])
		totalChunks += tc
		uc, _ := strconv.Atoi(s["used_chunks"])
		usedChunks += uc
	}
	return slabCount, totalPages, totalChunks, usedChunks
}
