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
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/ftahirops/xtop/model"
)

type nginxModule struct{}

func NewNginxModule() AppModule { return &nginxModule{} }

func (m *nginxModule) Type() string        { return "nginx" }
func (m *nginxModule) DisplayName() string { return "Nginx" }

func (m *nginxModule) Detect(processes []model.ProcessMetrics) []DetectedApp {
	var apps []DetectedApp
	for _, p := range processes {
		if p.Comm == "nginx" && p.PPID <= 2 {
			// Master process only (PPID=1 or 0)
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

func (m *nginxModule) Collect(app *DetectedApp, secrets *AppSecrets) model.AppInstance {
	inst := model.AppInstance{
		AppType:     "nginx",
		DisplayName: "Nginx",
		PID:         app.PID,
		Port:        app.Port,
		Status:      "active",
		UptimeSec:   readProcUptime(app.PID),
	}

	// Process metrics
	inst.RSSMB = readProcRSS(app.PID)
	inst.Threads = readProcThreads(app.PID)
	inst.FDs = readProcFDs(app.PID)
	inst.Connections = countTCPConnections(app.Port)
	inst.CPUPct = readProcCPUPct(app.PID, inst.UptimeSec)

	// Enumerate workers: count, sum RSS, per-worker CPU/state
	type workerInfo struct {
		pid   int
		rss   float64
		state string // R, S, D, etc.
		utime uint64
		stime uint64
	}
	var workers []workerInfo
	workerRSS := 0.0
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
		if !strings.Contains(s, "(nginx)") {
			continue
		}
		ci := strings.LastIndex(s, ")")
		if ci <= 0 || ci+2 >= len(s) {
			continue
		}
		fields := strings.Fields(s[ci+2:])
		if len(fields) < 14 {
			continue
		}
		ppid, _ := strconv.Atoi(fields[1])
		if ppid != app.PID {
			continue
		}
		rss := readProcRSS(pid)
		workerRSS += rss
		state := fields[0]
		utime, _ := strconv.ParseUint(fields[11], 10, 64)
		stime, _ := strconv.ParseUint(fields[12], 10, 64)
		workers = append(workers, workerInfo{
			pid:   pid,
			rss:   rss,
			state: state,
			utime: utime,
			stime: stime,
		})
	}
	inst.RSSMB += workerRSS
	workerCount := len(workers)

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

	// Config parsing
	confPath := findConfigFile([]string{
		"/etc/nginx/nginx.conf",
		"/usr/local/nginx/conf/nginx.conf",
		"/opt/nginx/conf/nginx.conf",
	})
	inst.ConfigPath = confPath

	inst.DeepMetrics = make(map[string]string)
	inst.DeepMetrics["workers"] = fmt.Sprintf("%d", workerCount)
	inst.DeepMetrics["workers_running"] = fmt.Sprintf("%d", stateR)
	inst.DeepMetrics["workers_sleeping"] = fmt.Sprintf("%d", stateS)
	inst.DeepMetrics["workers_disk_wait"] = fmt.Sprintf("%d", stateD)

	var confData nginxConfData
	if confPath != "" {
		confData = parseNginxConfDeep(confPath)
		if confData.workerProcesses != "" {
			inst.DeepMetrics["worker_processes"] = confData.workerProcesses
		}
		if confData.workerConnections > 0 {
			inst.DeepMetrics["worker_connections"] = fmt.Sprintf("%d", confData.workerConnections)
		}
		if confData.keepaliveTimeout != "" {
			inst.DeepMetrics["keepalive_timeout"] = confData.keepaliveTimeout
		}
		if confData.clientMaxBodySize != "" {
			inst.DeepMetrics["client_max_body_size"] = confData.clientMaxBodySize
		}
		if confData.gzipOn {
			inst.DeepMetrics["gzip"] = "on"
		}
		if confData.upstreamCount > 0 {
			inst.DeepMetrics["upstream_blocks"] = fmt.Sprintf("%d", confData.upstreamCount)
		}
		if confData.serverCount > 0 {
			inst.DeepMetrics["server_blocks"] = fmt.Sprintf("%d", confData.serverCount)
		}
		if confData.stubStatusLocation != "" {
			inst.DeepMetrics["stub_status_location"] = confData.stubStatusLocation
		}
	}

	// stub_status collection
	stub := fetchNginxStubStatus(app.Port, confData.stubStatusLocation)
	if stub != nil {
		inst.HasDeepMetrics = true
		for k, v := range stub {
			inst.DeepMetrics[k] = v
		}
	} else {
		inst.DeepMetrics["stub_status"] = "unavailable"
	}

	// Version
	inst.Version = detectNginxVersion()

	// ---- Health scoring ----
	inst.HealthScore = 100

	// Configured vs actual workers
	configuredWorkers := 0
	if wp, ok := inst.DeepMetrics["worker_processes"]; ok {
		configuredWorkers, _ = strconv.Atoi(wp)
	}
	if configuredWorkers > 0 && workerCount < configuredWorkers {
		inst.HealthScore -= 20
		inst.HealthIssues = append(inst.HealthIssues,
			fmt.Sprintf("only %d/%d workers running — workers may have crashed", workerCount, configuredWorkers))
	}

	// Dropped connections
	if stub != nil {
		dropped, _ := strconv.ParseInt(stub["dropped_connections"], 10, 64)
		if dropped > 0 {
			inst.HealthScore -= 20
			inst.HealthIssues = append(inst.HealthIssues,
				fmt.Sprintf("nginx dropping connections (%d dropped — accepts != handled)", dropped))
		}

		// Active connections vs capacity
		active, _ := strconv.Atoi(stub["active_connections"])
		if confData.workerConnections > 0 && workerCount > 0 {
			capacity := confData.workerConnections * workerCount
			if active > capacity {
				inst.HealthScore -= 15
				inst.HealthIssues = append(inst.HealthIssues,
					fmt.Sprintf("connections (%d) may exceed capacity (%d workers × %d = %d)",
						active, workerCount, confData.workerConnections, capacity))
			}
		}

		// High write ratio — upstream may be slow
		writing, _ := strconv.Atoi(stub["writing"])
		if active > 0 && writing > 0 {
			writeRatio := float64(writing) / float64(active)
			if writeRatio > 0.5 {
				inst.HealthScore -= 5
				inst.HealthIssues = append(inst.HealthIssues,
					fmt.Sprintf("high write ratio (%.0f%%) — upstream may be slow", writeRatio*100))
			}
		}

		// Waiting > 80% of active (only if active is also high)
		waiting, _ := strconv.Atoi(stub["waiting"])
		if active > 100 && waiting > 0 {
			waitRatio := float64(waiting) / float64(active)
			if waitRatio > 0.8 {
				inst.HealthScore -= 5
				inst.HealthIssues = append(inst.HealthIssues,
					fmt.Sprintf("%.0f%% of connections idle (waiting=%d of active=%d)", waitRatio*100, waiting, active))
			}
		}
	}

	// Workers in D state
	if stateD > 0 {
		inst.HealthScore -= 10
		inst.HealthIssues = append(inst.HealthIssues,
			fmt.Sprintf("%d worker(s) in disk-wait (D) state", stateD))
	}

	// FD pressure
	if inst.FDs > 50000 {
		inst.HealthScore -= 10
		inst.HealthIssues = append(inst.HealthIssues,
			fmt.Sprintf("high FD count (%d) — may be approaching ulimit", inst.FDs))
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

// nginxConfData holds parsed nginx.conf results.
type nginxConfData struct {
	workerProcesses    string
	workerConnections  int
	keepaliveTimeout   string
	clientMaxBodySize  string
	gzipOn             bool
	upstreamCount      int
	serverCount        int
	stubStatusLocation string
}

// parseNginxConfDeep does a deeper parse of nginx.conf for config analysis.
func parseNginxConfDeep(path string) nginxConfData {
	f, err := os.Open(path)
	if err != nil {
		return nginxConfData{}
	}
	defer f.Close()

	var d nginxConfData
	scanner := bufio.NewScanner(f)
	inLocation := false
	locationPath := ""

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "#") {
			continue
		}

		if strings.HasPrefix(line, "worker_processes") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				d.workerProcesses = strings.TrimSuffix(parts[1], ";")
			}
		}
		if strings.HasPrefix(line, "worker_connections") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				v := strings.TrimSuffix(parts[1], ";")
				d.workerConnections, _ = strconv.Atoi(v)
			}
		}
		if strings.HasPrefix(line, "keepalive_timeout") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				d.keepaliveTimeout = strings.TrimSuffix(parts[1], ";")
			}
		}
		if strings.HasPrefix(line, "client_max_body_size") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				d.clientMaxBodySize = strings.TrimSuffix(parts[1], ";")
			}
		}
		if strings.Contains(line, "gzip") && strings.Contains(line, "on") &&
			!strings.Contains(line, "gzip_") {
			// Match "gzip on;" but not "gzip_types" etc.
			parts := strings.Fields(line)
			if len(parts) >= 2 && parts[0] == "gzip" && strings.TrimSuffix(parts[1], ";") == "on" {
				d.gzipOn = true
			}
		}
		if strings.HasPrefix(line, "upstream") && strings.Contains(line, "{") {
			d.upstreamCount++
		}
		if strings.HasPrefix(line, "server") && strings.Contains(line, "{") &&
			!strings.HasPrefix(line, "server_") {
			d.serverCount++
		}

		// Detect stub_status location
		if strings.HasPrefix(line, "location") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				locationPath = strings.TrimSuffix(parts[len(parts)-1], "{")
				locationPath = strings.TrimSpace(locationPath)
				inLocation = true
			}
		}
		if inLocation && strings.Contains(line, "stub_status") {
			d.stubStatusLocation = locationPath
			inLocation = false
		}
		if inLocation && strings.Contains(line, "}") {
			inLocation = false
		}
	}
	return d
}

// parseNginxConf is kept for backwards compatibility but now delegates to parseNginxConfDeep.
func parseNginxConf(path string) (workerProcesses string, workerConnections int) {
	d := parseNginxConfDeep(path)
	return d.workerProcesses, d.workerConnections
}

// fetchNginxStubStatus tries to fetch nginx stub_status metrics.
// It tries the config-detected location first, then common URLs.
func fetchNginxStubStatus(port int, configLocation string) map[string]string {
	client := &http.Client{Timeout: 2 * time.Second}

	// Build candidate URLs, config-detected location first
	var urls []string
	if configLocation != "" {
		urls = append(urls, fmt.Sprintf("http://127.0.0.1:%d%s", port, configLocation))
	}
	urls = append(urls,
		fmt.Sprintf("http://127.0.0.1:%d/nginx_status", port),
		fmt.Sprintf("http://127.0.0.1:%d/status", port),
		"http://127.0.0.1/nginx_status",
		"http://127.0.0.1:8080/nginx_status",
		"http://localhost/nginx_status",
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
		body, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
		resp.Body.Close()
		if err != nil || resp.StatusCode != 200 {
			continue
		}
		text := string(body)
		if !strings.Contains(text, "Active connections") {
			continue
		}
		return parseStubStatus(text)
	}
	return nil
}

// parseStubStatus parses nginx stub_status output.
// Format:
//
//	Active connections: 291
//	server accepts handled requests
//	 16630948 16630948 31070465
//	Reading: 6 Writing: 179 Waiting: 106
func parseStubStatus(text string) map[string]string {
	m := make(map[string]string)

	// Active connections
	reActive := regexp.MustCompile(`Active connections:\s*(\d+)`)
	if match := reActive.FindStringSubmatch(text); len(match) == 2 {
		m["active_connections"] = match[1]
	}

	// accepts handled requests — the line with 3 numbers
	reAccepts := regexp.MustCompile(`(?m)^\s*(\d+)\s+(\d+)\s+(\d+)\s*$`)
	if match := reAccepts.FindStringSubmatch(text); len(match) == 4 {
		m["accepts"] = match[1]
		m["handled"] = match[2]
		m["requests"] = match[3]

		accepts, _ := strconv.ParseInt(match[1], 10, 64)
		handled, _ := strconv.ParseInt(match[2], 10, 64)
		requests, _ := strconv.ParseInt(match[3], 10, 64)

		dropped := accepts - handled
		if dropped < 0 {
			dropped = 0
		}
		m["dropped_connections"] = fmt.Sprintf("%d", dropped)

		if handled > 0 {
			rpc := float64(requests) / float64(handled)
			m["requests_per_connection"] = fmt.Sprintf("%.2f", rpc)
		}
	}

	// Reading Writing Waiting
	reRWW := regexp.MustCompile(`Reading:\s*(\d+)\s+Writing:\s*(\d+)\s+Waiting:\s*(\d+)`)
	if match := reRWW.FindStringSubmatch(text); len(match) == 4 {
		m["reading"] = match[1]
		m["writing"] = match[2]
		m["waiting"] = match[3]
	}

	return m
}

// detectNginxVersion runs "nginx -v" to get the version string.
func detectNginxVersion() string {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "nginx", "-v")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return ""
	}
	s := string(out)
	if idx := strings.Index(s, "/"); idx >= 0 {
		ver := strings.TrimSpace(s[idx+1:])
		if nl := strings.IndexByte(ver, '\n'); nl > 0 {
			ver = ver[:nl]
		}
		return ver
	}
	return ""
}
