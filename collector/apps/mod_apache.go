//go:build linux

package apps

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/ftahirops/xtop/model"
)

type apacheModule struct{}

func NewApacheModule() AppModule { return &apacheModule{} }

func (m *apacheModule) Type() string        { return "apache" }
func (m *apacheModule) DisplayName() string { return "Apache" }

func (m *apacheModule) Detect(processes []model.ProcessMetrics) []DetectedApp {
	var apps []DetectedApp
	for _, p := range processes {
		if (p.Comm == "httpd" || p.Comm == "apache2") && p.PPID <= 2 {
			port := findListeningPort(p.PID)
			if port == 0 {
				port = 80
			}
			apps = append(apps, DetectedApp{
				PID:     p.PID,
				Port:    port,
				Comm:    p.Comm,
				Cmdline: readProcCmdline(p.PID),
				Index:   len(apps),
			})
		}
	}
	return apps
}

// apacheConfData holds parsed Apache config results.
type apacheConfData struct {
	maxRequestWorkers    int
	serverLimit          int
	startServers         int
	minSpareServers      int
	maxSpareServers      int
	minSpareThreads      int
	maxSpareThreads      int
	threadsPerChild      int
	mpm                  string // prefork, worker, event
	timeout              int
	keepAlive            string // On/Off
	keepAliveTimeout     int
	maxKeepAliveRequests int
}

func (m *apacheModule) Collect(app *DetectedApp, secrets *AppSecrets) model.AppInstance {
	inst := model.AppInstance{
		AppType:     "apache",
		DisplayName: "Apache",
		PID:         app.PID,
		Port:        app.Port,
		Status:      "active",
		UptimeSec:   readProcUptime(app.PID),
		DeepMetrics: make(map[string]string),
	}

	inst.RSSMB = readProcRSS(app.PID)
	inst.Threads = readProcThreads(app.PID)
	inst.FDs = readProcFDs(app.PID)
	inst.Connections = countTCPConnections(app.Port)

	inst.ConfigPath = findConfigFile([]string{
		"/etc/httpd/conf/httpd.conf",
		"/etc/apache2/apache2.conf",
		"/usr/local/apache2/conf/httpd.conf",
	})

	// Enumerate workers: count, sum RSS, per-worker state analysis
	type workerInfo struct {
		pid   int
		rss   float64
		state string // R, S, D, etc.
	}
	var workers []workerInfo
	workerRSS := 0.0
	entries, _ := procEntries()
	for _, pid := range entries {
		if pid == app.PID {
			continue
		}
		ppid, pcomm := readPPIDComm(pid)
		if ppid == app.PID && pcomm == app.Comm {
			rss := readProcRSS(pid)
			workerRSS += rss
			state := string(readProcState(pid))
			workers = append(workers, workerInfo{
				pid:   pid,
				rss:   rss,
				state: state,
			})
		}
	}
	inst.RSSMB += workerRSS
	workerCount := len(workers)
	inst.DeepMetrics["workers"] = fmt.Sprintf("%d", workerCount)

	// Per-worker state counts
	stateR, stateS, stateD := 0, 0, 0
	for _, w := range workers {
		switch w.state {
		case "R":
			stateR++
		case "S":
			stateS++
		case "D":
			stateD++
		}
	}
	inst.DeepMetrics["workers_running"] = fmt.Sprintf("%d", stateR)
	inst.DeepMetrics["workers_sleeping"] = fmt.Sprintf("%d", stateS)
	inst.DeepMetrics["workers_disk_wait"] = fmt.Sprintf("%d", stateD)

	// Config parsing
	var confData apacheConfData
	if inst.ConfigPath != "" {
		confData = parseApacheConf(inst.ConfigPath)
	}
	// Also try to detect MPM from mods-enabled / conf.modules.d
	if confData.mpm == "" {
		confData.mpm = detectApacheMPM()
	}

	if confData.maxRequestWorkers > 0 {
		inst.DeepMetrics["max_request_workers"] = fmt.Sprintf("%d", confData.maxRequestWorkers)
	}
	if confData.serverLimit > 0 {
		inst.DeepMetrics["server_limit"] = fmt.Sprintf("%d", confData.serverLimit)
	}
	if confData.mpm != "" {
		inst.DeepMetrics["mpm"] = confData.mpm
	}
	if confData.keepAlive != "" {
		inst.DeepMetrics["keepalive"] = confData.keepAlive
	}
	if confData.keepAliveTimeout > 0 {
		inst.DeepMetrics["keepalive_timeout"] = fmt.Sprintf("%d", confData.keepAliveTimeout)
	}
	if confData.maxKeepAliveRequests > 0 {
		inst.DeepMetrics["max_keepalive_requests"] = fmt.Sprintf("%d", confData.maxKeepAliveRequests)
	}
	if confData.timeout > 0 {
		inst.DeepMetrics["timeout"] = fmt.Sprintf("%d", confData.timeout)
	}
	if confData.startServers > 0 {
		inst.DeepMetrics["start_servers"] = fmt.Sprintf("%d", confData.startServers)
	}
	if confData.minSpareServers > 0 {
		inst.DeepMetrics["min_spare_servers"] = fmt.Sprintf("%d", confData.minSpareServers)
	}
	if confData.maxSpareServers > 0 {
		inst.DeepMetrics["max_spare_servers"] = fmt.Sprintf("%d", confData.maxSpareServers)
	}
	if confData.minSpareThreads > 0 {
		inst.DeepMetrics["min_spare_threads"] = fmt.Sprintf("%d", confData.minSpareThreads)
	}
	if confData.maxSpareThreads > 0 {
		inst.DeepMetrics["max_spare_threads"] = fmt.Sprintf("%d", confData.maxSpareThreads)
	}
	if confData.threadsPerChild > 0 {
		inst.DeepMetrics["threads_per_child"] = fmt.Sprintf("%d", confData.threadsPerChild)
	}

	// server-status collection
	statusData := fetchApacheServerStatus(app.Port)
	if statusData != nil {
		inst.HasDeepMetrics = true
		for k, v := range statusData {
			inst.DeepMetrics[k] = v
		}
	} else {
		inst.DeepMetrics["server_status"] = "unavailable"
	}

	// Version detection
	inst.Version = detectApacheVersion(app.Comm)

	// ---- Health scoring ----
	inst.HealthScore = 100

	// Worker utilization from server-status
	busyWorkers, _ := strconv.Atoi(inst.DeepMetrics["busy_workers"])
	idleWorkers, _ := strconv.Atoi(inst.DeepMetrics["idle_workers"])
	totalActive := busyWorkers + idleWorkers
	if totalActive > 0 {
		utilPct := float64(busyWorkers) / float64(totalActive) * 100
		inst.DeepMetrics["worker_utilization_pct"] = fmt.Sprintf("%.1f", utilPct)
		if utilPct > 95 {
			inst.HealthScore -= 25
			inst.HealthIssues = append(inst.HealthIssues,
				fmt.Sprintf("critical worker utilization (%.0f%%)", utilPct))
		} else if utilPct > 80 {
			inst.HealthScore -= 15
			inst.HealthIssues = append(inst.HealthIssues,
				fmt.Sprintf("high worker utilization (%.0f%%)", utilPct))
		}
	}

	// BusyWorkers >= MaxRequestWorkers
	if confData.maxRequestWorkers > 0 && busyWorkers >= confData.maxRequestWorkers {
		inst.HealthScore -= 20
		inst.HealthIssues = append(inst.HealthIssues,
			fmt.Sprintf("all workers busy (%d/%d) — requests queuing", busyWorkers, confData.maxRequestWorkers))
	}

	// CPU load from server-status
	if cpuStr, ok := inst.DeepMetrics["cpu_load"]; ok {
		cpuLoad, _ := strconv.ParseFloat(cpuStr, 64)
		cpuLoadPct := cpuLoad * 100
		if cpuLoadPct > 50 {
			inst.HealthScore -= 10
			inst.HealthIssues = append(inst.HealthIssues,
				fmt.Sprintf("high CPU load (%.1f%%)", cpuLoadPct))
		}
	}

	// No idle workers
	if idleWorkers == 0 && busyWorkers > 10 {
		inst.HealthScore -= 10
		inst.HealthIssues = append(inst.HealthIssues, "no idle workers")
	}

	// Scoreboard DNS lookups > 10%
	sbDNS, _ := strconv.Atoi(inst.DeepMetrics["scoreboard_dns"])
	sbTotal := scoreboardTotal(inst.DeepMetrics)
	if sbTotal > 0 && sbDNS > 0 {
		dnsPct := float64(sbDNS) / float64(sbTotal) * 100
		if dnsPct > 10 {
			inst.HealthScore -= 5
			inst.HealthIssues = append(inst.HealthIssues,
				fmt.Sprintf("workers stuck in DNS lookups (%.0f%%)", dnsPct))
		}
	}

	// Scoreboard closing > 20%
	sbClosing, _ := strconv.Atoi(inst.DeepMetrics["scoreboard_closing"])
	if sbTotal > 0 && sbClosing > 0 {
		closePct := float64(sbClosing) / float64(sbTotal) * 100
		if closePct > 20 {
			inst.HealthScore -= 5
			inst.HealthIssues = append(inst.HealthIssues,
				fmt.Sprintf("workers stuck closing connections (%.0f%%)", closePct))
		}
	}

	// FD pressure
	if inst.FDs > 50000 {
		inst.HealthScore -= 10
		inst.HealthIssues = append(inst.HealthIssues,
			fmt.Sprintf("high FD count (%d) — may be approaching ulimit", inst.FDs))
	}

	// Workers in D state
	if stateD > 0 {
		inst.HealthScore -= 10
		inst.HealthIssues = append(inst.HealthIssues,
			fmt.Sprintf("%d worker(s) in disk-wait (D) state", stateD))
	}

	// Clamp
	if inst.HealthScore < 0 {
		inst.HealthScore = 0
	}
	if inst.HealthScore > 100 {
		inst.HealthScore = 100
	}

	return inst
}

// fetchApacheServerStatus tries to fetch Apache mod_status metrics.
func fetchApacheServerStatus(port int) map[string]string {
	client := &http.Client{Timeout: 2 * time.Second}

	var urls []string
	if port != 0 && port != 80 {
		urls = append(urls, fmt.Sprintf("http://127.0.0.1:%d/server-status?auto", port))
	}
	urls = append(urls,
		"http://127.0.0.1/server-status?auto",
		"http://127.0.0.1:80/server-status?auto",
		"http://localhost/server-status?auto",
	)

	// Deduplicate
	seen := make(map[string]bool)
	var deduped []string
	for _, u := range urls {
		if !seen[u] {
			seen[u] = true
			deduped = append(deduped, u)
		}
	}

	for _, u := range deduped {
		resp, err := client.Get(u)
		if err != nil {
			continue
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, 8192))
		resp.Body.Close()
		if err != nil || resp.StatusCode != 200 {
			continue
		}
		text := string(body)
		// Validate it looks like server-status output
		if !strings.Contains(text, "Scoreboard") && !strings.Contains(text, "BusyWorkers") {
			continue
		}
		return parseApacheServerStatus(text)
	}
	return nil
}

// parseApacheServerStatus parses the machine-readable server-status?auto output.
func parseApacheServerStatus(text string) map[string]string {
	m := make(map[string]string)
	scanner := bufio.NewScanner(strings.NewReader(text))
	for scanner.Scan() {
		line := scanner.Text()
		idx := strings.Index(line, ":")
		if idx < 0 {
			continue
		}
		key := strings.TrimSpace(line[:idx])
		val := strings.TrimSpace(line[idx+1:])

		switch key {
		case "Total Accesses":
			m["total_accesses"] = val
		case "Total kBytes":
			m["total_kbytes"] = val
		case "CPULoad":
			m["cpu_load"] = val
		case "Uptime":
			m["server_uptime"] = val
		case "ReqPerSec":
			m["req_per_sec"] = val
		case "BytesPerSec":
			m["bytes_per_sec"] = val
		case "BytesPerReq":
			m["bytes_per_req"] = val
		case "BusyWorkers":
			m["busy_workers"] = val
		case "IdleWorkers":
			m["idle_workers"] = val
		case "Scoreboard":
			m["scoreboard"] = val
			parseScoreboard(val, m)
		default:
			// Store any other key-value pairs from server-status
			normalized := strings.ToLower(strings.ReplaceAll(key, " ", "_"))
			m[normalized] = val
		}
	}
	return m
}

// parseScoreboard counts each character type in the Apache scoreboard.
func parseScoreboard(sb string, m map[string]string) {
	var waiting, starting, reading, writing, keepalive int
	var dns, closing, logging, graceful, idle int

	for _, c := range sb {
		switch c {
		case '_':
			waiting++
		case 'S':
			starting++
		case 'R':
			reading++
		case 'W':
			writing++
		case 'K':
			keepalive++
		case 'D':
			dns++
		case 'C':
			closing++
		case 'L':
			logging++
		case 'G':
			graceful++
		case '.':
			idle++
		}
	}

	m["scoreboard_waiting"] = fmt.Sprintf("%d", waiting)
	m["scoreboard_starting"] = fmt.Sprintf("%d", starting)
	m["scoreboard_reading"] = fmt.Sprintf("%d", reading)
	m["scoreboard_writing"] = fmt.Sprintf("%d", writing)
	m["scoreboard_keepalive"] = fmt.Sprintf("%d", keepalive)
	m["scoreboard_dns"] = fmt.Sprintf("%d", dns)
	m["scoreboard_closing"] = fmt.Sprintf("%d", closing)
	m["scoreboard_logging"] = fmt.Sprintf("%d", logging)
	m["scoreboard_graceful"] = fmt.Sprintf("%d", graceful)
	m["scoreboard_idle"] = fmt.Sprintf("%d", idle)
}

// scoreboardTotal returns the total active scoreboard slots (excluding open/idle slots).
func scoreboardTotal(dm map[string]string) int {
	total := 0
	for _, key := range []string{
		"scoreboard_waiting", "scoreboard_starting", "scoreboard_reading",
		"scoreboard_writing", "scoreboard_keepalive", "scoreboard_dns",
		"scoreboard_closing", "scoreboard_logging", "scoreboard_graceful",
	} {
		v, _ := strconv.Atoi(dm[key])
		total += v
	}
	return total
}

// parseApacheConf parses Apache httpd.conf / apache2.conf for configuration directives.
func parseApacheConf(path string) apacheConfData {
	f, err := os.Open(path)
	if err != nil {
		return apacheConfData{}
	}
	defer f.Close()

	var d apacheConfData
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "#") || line == "" {
			continue
		}
		parseApacheDirective(line, &d)
	}

	// Also scan included MPM config files
	for _, incPath := range []string{
		"/etc/apache2/mods-enabled/mpm_prefork.conf",
		"/etc/apache2/mods-enabled/mpm_worker.conf",
		"/etc/apache2/mods-enabled/mpm_event.conf",
		"/etc/httpd/conf.modules.d/00-mpm.conf",
	} {
		if fi, err := os.Open(incPath); err == nil {
			sc := bufio.NewScanner(fi)
			for sc.Scan() {
				line := strings.TrimSpace(sc.Text())
				if strings.HasPrefix(line, "#") || line == "" {
					continue
				}
				parseApacheDirective(line, &d)
			}
			fi.Close()
		}
	}

	return d
}

// parseApacheDirective parses a single Apache config line into apacheConfData.
func parseApacheDirective(line string, d *apacheConfData) {
	parts := strings.Fields(line)
	if len(parts) < 2 {
		return
	}
	directive := parts[0]
	value := parts[1]

	switch directive {
	case "MaxRequestWorkers", "MaxClients":
		d.maxRequestWorkers, _ = strconv.Atoi(value)
	case "ServerLimit":
		d.serverLimit, _ = strconv.Atoi(value)
	case "StartServers":
		d.startServers, _ = strconv.Atoi(value)
	case "MinSpareServers":
		d.minSpareServers, _ = strconv.Atoi(value)
	case "MaxSpareServers":
		d.maxSpareServers, _ = strconv.Atoi(value)
	case "MinSpareThreads":
		d.minSpareThreads, _ = strconv.Atoi(value)
	case "MaxSpareThreads":
		d.maxSpareThreads, _ = strconv.Atoi(value)
	case "ThreadsPerChild":
		d.threadsPerChild, _ = strconv.Atoi(value)
	case "Timeout":
		d.timeout, _ = strconv.Atoi(value)
	case "KeepAlive":
		d.keepAlive = value
	case "KeepAliveTimeout":
		d.keepAliveTimeout, _ = strconv.Atoi(value)
	case "MaxKeepAliveRequests":
		d.maxKeepAliveRequests, _ = strconv.Atoi(value)
	case "LoadModule":
		// Detect MPM from LoadModule directive
		if len(parts) >= 2 {
			mod := parts[1]
			switch {
			case strings.Contains(mod, "mpm_event"):
				d.mpm = "event"
			case strings.Contains(mod, "mpm_worker"):
				d.mpm = "worker"
			case strings.Contains(mod, "mpm_prefork"):
				d.mpm = "prefork"
			}
		}
	}
}

// detectApacheMPM tries to detect the MPM type from mods-enabled or conf.modules.d.
func detectApacheMPM() string {
	// Check Debian/Ubuntu mods-enabled symlinks
	for _, entry := range []struct {
		path string
		mpm  string
	}{
		{"/etc/apache2/mods-enabled/mpm_event.load", "event"},
		{"/etc/apache2/mods-enabled/mpm_worker.load", "worker"},
		{"/etc/apache2/mods-enabled/mpm_prefork.load", "prefork"},
	} {
		if _, err := os.Stat(entry.path); err == nil {
			return entry.mpm
		}
	}

	// Check RHEL/CentOS conf.modules.d
	confModPath := "/etc/httpd/conf.modules.d/00-mpm.conf"
	data, err := os.ReadFile(confModPath)
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "#") {
			continue
		}
		if strings.Contains(line, "LoadModule") {
			switch {
			case strings.Contains(line, "mpm_event"):
				return "event"
			case strings.Contains(line, "mpm_worker"):
				return "worker"
			case strings.Contains(line, "mpm_prefork"):
				return "prefork"
			}
		}
	}
	return ""
}

// detectApacheVersion runs httpd -v or apache2 -v to get the version.
func detectApacheVersion(comm string) string {
	// Try the detected binary first, then fallback
	binaries := []string{comm, "httpd", "apache2"}
	seen := make(map[string]bool)

	for _, bin := range binaries {
		if bin == "" || seen[bin] {
			continue
		}
		seen[bin] = true

		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		cmd := exec.CommandContext(ctx, bin, "-v")
		out, err := cmd.CombinedOutput()
		cancel()
		if err != nil {
			continue
		}
		s := string(out)
		// Parse "Server version: Apache/2.4.52 (Ubuntu)"
		if idx := strings.Index(s, "Apache/"); idx >= 0 {
			ver := s[idx+7:]
			// Take until space or newline
			for i, c := range ver {
				if c == ' ' || c == '\n' || c == '\r' {
					ver = ver[:i]
					break
				}
			}
			return strings.TrimSpace(ver)
		}
	}
	return ""
}

// procEntries returns all numeric PID directories in /proc.
func procEntries() ([]int, error) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, err
	}
	var pids []int
	for _, e := range entries {
		if pid, err := strconv.Atoi(e.Name()); err == nil {
			pids = append(pids, pid)
		}
	}
	return pids, nil
}

// readPPIDComm reads PPID and comm from /proc/PID/stat.
func readPPIDComm(pid int) (int, string) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return 0, ""
	}
	s := string(data)
	// comm is between ( and )
	i := strings.Index(s, "(")
	j := strings.LastIndex(s, ")")
	if i < 0 || j < 0 || j <= i {
		return 0, ""
	}
	comm := s[i+1 : j]
	fields := strings.Fields(s[j+2:])
	if len(fields) < 2 {
		return 0, comm
	}
	ppid, _ := strconv.Atoi(fields[1])
	return ppid, comm
}
