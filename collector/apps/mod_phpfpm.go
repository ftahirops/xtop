//go:build linux

package apps

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/ftahirops/xtop/model"
)

type phpfpmModule struct{}

func NewPHPFPMModule() AppModule { return &phpfpmModule{} }

func (m *phpfpmModule) Type() string        { return "php-fpm" }
func (m *phpfpmModule) DisplayName() string { return "PHP-FPM" }

func (m *phpfpmModule) Detect(processes []model.ProcessMetrics) []DetectedApp {
	var apps []DetectedApp
	for _, p := range processes {
		if !strings.HasPrefix(p.Comm, "php-fpm") {
			continue
		}
		if p.PPID > 2 {
			continue
		}
		port := findListeningPort(p.PID)
		apps = append(apps, DetectedApp{
			PID:     p.PID,
			Port:    port,
			Comm:    p.Comm,
			Cmdline: readProcCmdline(p.PID),
			Index:   len(apps),
		})
	}
	return apps
}

func (m *phpfpmModule) Collect(app *DetectedApp, secrets *AppSecrets) model.AppInstance {
	inst := model.AppInstance{
		AppType:     "php-fpm",
		DisplayName: "PHP-FPM",
		PID:         app.PID,
		Port:        app.Port,
		Status:      "active",
		UptimeSec:   readProcUptime(app.PID),
	}

	// Tier 1: process-level metrics
	inst.RSSMB = readProcRSS(app.PID)
	inst.Threads = readProcThreads(app.PID)
	inst.FDs = readProcFDs(app.PID)
	if app.Port > 0 {
		inst.Connections = countTCPConnections(app.Port)
	}
	inst.CPUPct = readProcCPUPct(app.PID, inst.UptimeSec)

	// Enumerate worker processes (children of master with php-fpm comm prefix)
	type workerInfo struct {
		pid   int
		rss   float64
		state byte // 'S'=sleeping, 'R'=running, 'D'=disk wait
	}
	var workers []workerInfo

	pids, _ := procEntries()
	for _, pid := range pids {
		if pid == app.PID {
			continue
		}
		ppid, pcomm := readPPIDComm(pid)
		if ppid != app.PID || !strings.HasPrefix(pcomm, "php-fpm") {
			continue
		}
		wi := workerInfo{pid: pid, rss: readProcRSS(pid)}
		wi.state = readProcState(pid)
		workers = append(workers, wi)
	}

	totalWorkers := len(workers)
	activeWorkers := 0
	idleWorkers := 0
	var totalWorkerRSS float64
	for _, w := range workers {
		totalWorkerRSS += w.rss
		if w.state == 'R' || w.state == 'D' {
			activeWorkers++
		} else {
			idleWorkers++
		}
	}

	// Total RSS includes master + all workers
	inst.RSSMB += totalWorkerRSS

	// Tier 2: config parsing
	pool := parsePHPFPMPools()
	inst.DeepMetrics = make(map[string]string)
	inst.HasDeepMetrics = true

	inst.DeepMetrics["total_workers"] = fmt.Sprintf("%d", totalWorkers)
	inst.DeepMetrics["active_workers"] = fmt.Sprintf("%d", activeWorkers)
	inst.DeepMetrics["idle_workers"] = fmt.Sprintf("%d", idleWorkers)

	utilPct := 0.0
	if totalWorkers > 0 {
		utilPct = float64(activeWorkers) / float64(totalWorkers) * 100
	}
	inst.DeepMetrics["worker_utilization_pct"] = fmt.Sprintf("%.1f", utilPct)

	avgWorkerRSS := 0.0
	if totalWorkers > 0 {
		avgWorkerRSS = totalWorkerRSS / float64(totalWorkers)
	}
	inst.DeepMetrics["avg_worker_rss_mb"] = fmt.Sprintf("%.1f", avgWorkerRSS)
	inst.DeepMetrics["total_rss_mb"] = fmt.Sprintf("%.1f", inst.RSSMB)

	listenMode := "unix"
	listenAddr := ""
	if app.Port > 0 {
		listenMode = "tcp"
		listenAddr = fmt.Sprintf(":%d", app.Port)
	}

	if pool != nil {
		inst.DeepMetrics["pool_name"] = pool.Name
		inst.DeepMetrics["pm_type"] = pool.PM
		inst.DeepMetrics["max_children"] = fmt.Sprintf("%d", pool.MaxChildren)
		inst.DeepMetrics["max_requests"] = fmt.Sprintf("%d", pool.MaxRequests)
		inst.DeepMetrics["slow_log_timeout"] = fmt.Sprintf("%d", pool.SlowlogTimeout)
		if pool.Listen != "" {
			listenAddr = pool.Listen
			if strings.HasPrefix(pool.Listen, "/") {
				listenMode = "unix"
			} else {
				listenMode = "tcp"
			}
		}

		inst.DeepMetrics["max_children_reached"] = "false"
		if pool.MaxChildren > 0 && totalWorkers >= pool.MaxChildren {
			inst.DeepMetrics["max_children_reached"] = "true"
		}

		inst.ConfigPath = pool.ConfigPath
	}

	inst.DeepMetrics["listen_mode"] = listenMode
	inst.DeepMetrics["listen_address"] = listenAddr

	// Version detection from cmdline
	inst.Version = detectPHPFPMVersion(app.Cmdline, app.Comm)

	// Health scoring
	inst.HealthScore = 100
	maxChildren := 0
	if pool != nil {
		maxChildren = pool.MaxChildren
	}

	// Workers at max_children
	if maxChildren > 0 && totalWorkers >= maxChildren {
		inst.HealthScore -= 20
		inst.HealthIssues = append(inst.HealthIssues,
			"all worker slots used \u2014 requests may queue")
	}

	// Worker utilization checks
	if utilPct > 90 && (maxChildren == 0 || totalWorkers < maxChildren) {
		inst.HealthScore -= 15
		inst.HealthIssues = append(inst.HealthIssues,
			fmt.Sprintf("%.0f%% worker utilization", utilPct))
	} else if utilPct > 80 {
		inst.HealthScore -= 10
		inst.HealthIssues = append(inst.HealthIssues,
			"high worker utilization")
	}

	// No idle workers
	if totalWorkers > 5 && idleWorkers == 0 {
		inst.HealthScore -= 10
		inst.HealthIssues = append(inst.HealthIssues,
			"no idle workers available")
	}

	// High per-worker memory
	if avgWorkerRSS > 512 {
		inst.HealthScore -= 15
		inst.HealthIssues = append(inst.HealthIssues,
			fmt.Sprintf("very high per-worker memory (%.0f MB) \u2014 check for leaks", avgWorkerRSS))
	} else if avgWorkerRSS > 256 {
		inst.HealthScore -= 10
		inst.HealthIssues = append(inst.HealthIssues,
			fmt.Sprintf("high per-worker memory (%.0f MB) \u2014 check for leaks", avgWorkerRSS))
	}

	// Max requests not set with dynamic PM
	if pool != nil && pool.PM == "dynamic" && pool.MaxRequests == 0 {
		inst.HealthScore -= 5
		inst.HealthIssues = append(inst.HealthIssues,
			"pm.max_requests not set \u2014 worker memory may leak")
	}

	// Total RSS > 10% of system memory
	totalMemMB := readTotalMemoryMB()
	if totalMemMB > 0 && inst.RSSMB > float64(totalMemMB)*0.10 {
		inst.HealthScore -= 5
		inst.HealthIssues = append(inst.HealthIssues,
			fmt.Sprintf("PHP-FPM using %.0f MB (>10%% of system RAM)", inst.RSSMB))
	}

	// Static PM with low utilization
	if pool != nil && pool.PM == "static" && utilPct < 50 && totalWorkers > 0 {
		inst.HealthScore -= 5
		inst.HealthIssues = append(inst.HealthIssues,
			"static PM with low utilization \u2014 consider dynamic")
	}

	// Clamp health score
	if inst.HealthScore < 0 {
		inst.HealthScore = 0
	}
	if inst.HealthScore > 100 {
		inst.HealthScore = 100
	}

	// Per-website metrics (shared with Plesk/Nginx/Apache)
	inst.Websites = CollectWebsites()

	return inst
}

// phpfpmPool holds parsed PHP-FPM pool configuration.
type phpfpmPool struct {
	Name           string
	PM             string // dynamic, static, ondemand
	MaxChildren    int
	StartServers   int
	MinSpare       int
	MaxSpare       int
	MaxRequests    int
	Listen         string
	StatusPath     string
	SlowlogTimeout int
	ConfigPath     string
}

// parsePHPFPMPools scans known config directories for PHP-FPM pool configs
// and returns the first pool found (typically "www").
func parsePHPFPMPools() *phpfpmPool {
	configDirs := []string{
		"/etc/php/8.3/fpm/pool.d",
		"/etc/php/8.2/fpm/pool.d",
		"/etc/php/8.1/fpm/pool.d",
		"/etc/php/8.0/fpm/pool.d",
		"/etc/php/7.4/fpm/pool.d",
		"/etc/php-fpm.d",
	}

	for _, dir := range configDirs {
		matches, err := filepath.Glob(filepath.Join(dir, "*.conf"))
		if err != nil || len(matches) == 0 {
			continue
		}
		for _, confPath := range matches {
			pool := parsePHPFPMPoolConf(confPath)
			if pool != nil {
				pool.ConfigPath = confPath
				return pool
			}
		}
	}

	// Try main config files directly
	mainConfigs := []string{
		"/etc/php/8.3/fpm/php-fpm.conf",
		"/etc/php/8.2/fpm/php-fpm.conf",
		"/etc/php/8.1/fpm/php-fpm.conf",
		"/etc/php/8.0/fpm/php-fpm.conf",
		"/etc/php/7.4/fpm/php-fpm.conf",
	}
	for _, confPath := range mainConfigs {
		pool := parsePHPFPMPoolConf(confPath)
		if pool != nil {
			pool.ConfigPath = confPath
			return pool
		}
	}

	return nil
}

// parsePHPFPMPoolConf parses a single PHP-FPM pool config file.
func parsePHPFPMPoolConf(path string) *phpfpmPool {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	pool := &phpfpmPool{}
	foundPool := false

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, ";") {
			continue
		}

		// Pool name: [www]
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			pool.Name = line[1 : len(line)-1]
			foundPool = true
			continue
		}

		// key = value
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		val := strings.TrimSpace(parts[1])

		switch key {
		case "pm":
			pool.PM = val
		case "pm.max_children":
			pool.MaxChildren, _ = strconv.Atoi(val)
		case "pm.start_servers":
			pool.StartServers, _ = strconv.Atoi(val)
		case "pm.min_spare_servers":
			pool.MinSpare, _ = strconv.Atoi(val)
		case "pm.max_spare_servers":
			pool.MaxSpare, _ = strconv.Atoi(val)
		case "pm.max_requests":
			pool.MaxRequests, _ = strconv.Atoi(val)
		case "listen":
			pool.Listen = val
		case "pm.status_path":
			pool.StatusPath = val
		case "request_slowlog_timeout":
			pool.SlowlogTimeout = parsePHPDuration(val)
		}
	}

	if !foundPool {
		return nil
	}
	return pool
}

// parsePHPDuration parses PHP-FPM duration values like "30s", "5m", or plain seconds.
func parsePHPDuration(val string) int {
	val = strings.TrimSpace(val)
	if val == "" || val == "0" {
		return 0
	}
	if strings.HasSuffix(val, "s") {
		v, _ := strconv.Atoi(strings.TrimSuffix(val, "s"))
		return v
	}
	if strings.HasSuffix(val, "m") {
		v, _ := strconv.Atoi(strings.TrimSuffix(val, "m"))
		return v * 60
	}
	v, _ := strconv.Atoi(val)
	return v
}

// readProcState reads the process state character from /proc/PID/stat.
// Returns 'S' (sleeping), 'R' (running), 'D' (disk wait), etc.
func readProcState(pid int) byte {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return 'S'
	}
	s := string(data)
	j := strings.LastIndex(s, ")")
	if j < 0 || j+2 >= len(s) {
		return 'S'
	}
	fields := strings.Fields(s[j+2:])
	if len(fields) < 1 || len(fields[0]) < 1 {
		return 'S'
	}
	return fields[0][0]
}

// detectPHPFPMVersion tries to extract the PHP version from the process comm or cmdline.
func detectPHPFPMVersion(cmdline, comm string) string {
	// Check comm for version suffix: "php-fpm8.2" -> "8.2"
	if strings.HasPrefix(comm, "php-fpm") {
		ver := strings.TrimPrefix(comm, "php-fpm")
		if ver != "" {
			return ver
		}
	}

	// Parse version from cmdline, e.g. "php-fpm: master process (/etc/php/8.2/fpm/php-fpm.conf)"
	for _, prefix := range []string{"/php/", "/php-fpm/"} {
		idx := strings.Index(cmdline, prefix)
		if idx >= 0 {
			rest := cmdline[idx+len(prefix):]
			// Extract version segment before next /
			if slashIdx := strings.Index(rest, "/"); slashIdx > 0 {
				ver := rest[:slashIdx]
				if len(ver) > 0 && ver[0] >= '0' && ver[0] <= '9' {
					return ver
				}
			}
		}
	}

	return ""
}

// readTotalMemoryMB reads total system memory from /proc/meminfo in MB.
func readTotalMemoryMB() int {
	data, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "MemTotal:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				kb, _ := strconv.Atoi(fields[1])
				return kb / 1024
			}
		}
	}
	return 0
}
