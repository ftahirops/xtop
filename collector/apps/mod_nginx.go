//go:build linux

package apps

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"

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

	// Sum worker RSS
	workerCount := 0
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
		if strings.Contains(s, "(nginx)") {
			ci := strings.LastIndex(s, ")")
			if ci > 0 && ci+2 < len(s) {
				fields := strings.Fields(s[ci+2:])
				if len(fields) > 1 {
					ppid, _ := strconv.Atoi(fields[1])
					if ppid == app.PID {
						workerCount++
						workerRSS += readProcRSS(pid)
					}
				}
			}
		}
	}
	inst.RSSMB += workerRSS

	// Config parsing
	confPath := findConfigFile([]string{
		"/etc/nginx/nginx.conf",
		"/usr/local/nginx/conf/nginx.conf",
		"/opt/nginx/conf/nginx.conf",
	})
	inst.ConfigPath = confPath

	inst.DeepMetrics = make(map[string]string)
	inst.DeepMetrics["workers"] = fmt.Sprintf("%d", workerCount)

	if confPath != "" {
		wp, wc := parseNginxConf(confPath)
		if wp != "" {
			inst.DeepMetrics["worker_processes"] = wp
		}
		if wc > 0 {
			inst.DeepMetrics["worker_connections"] = fmt.Sprintf("%d", wc)
		}
	}

	// Version from cmdline
	inst.Version = detectNginxVersion()

	// Health
	inst.HealthScore = 100
	configuredWorkers := 0
	if wp, ok := inst.DeepMetrics["worker_processes"]; ok {
		configuredWorkers, _ = strconv.Atoi(wp)
	}
	if configuredWorkers > 0 && workerCount < configuredWorkers {
		inst.HealthScore -= 20
		inst.HealthIssues = append(inst.HealthIssues,
			fmt.Sprintf("only %d/%d workers running — workers may have crashed", workerCount, configuredWorkers))
	}

	return inst
}

func parseNginxConf(path string) (workerProcesses string, workerConnections int) {
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "worker_processes") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				workerProcesses = strings.TrimSuffix(parts[1], ";")
			}
		}
		if strings.HasPrefix(line, "worker_connections") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				v := strings.TrimSuffix(parts[1], ";")
				workerConnections, _ = strconv.Atoi(v)
			}
		}
	}
	return
}

func detectNginxVersion() string {
	// Try reading from the binary
	data, err := os.ReadFile("/proc/self/exe")
	_ = data
	_ = err
	// Simpler: check nginx -v output cached somewhere, or parse binary
	// For now, leave empty — version detection is nice-to-have
	return ""
}
