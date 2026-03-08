//go:build linux

package apps

import (
	"fmt"

	"github.com/ftahirops/xtop/model"
)

type haproxyModule struct{}

func NewHAProxyModule() AppModule { return &haproxyModule{} }

func (m *haproxyModule) Type() string        { return "haproxy" }
func (m *haproxyModule) DisplayName() string { return "HAProxy" }

func (m *haproxyModule) Detect(processes []model.ProcessMetrics) []DetectedApp {
	var apps []DetectedApp
	for _, p := range processes {
		if p.Comm == "haproxy" && p.PPID <= 2 {
			port := findListeningPort(p.PID)
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

func (m *haproxyModule) Collect(app *DetectedApp, secrets *AppSecrets) model.AppInstance {
	inst := model.AppInstance{
		AppType:     "haproxy",
		DisplayName: "HAProxy",
		PID:         app.PID,
		Port:        app.Port,
		Status:      "active",
		UptimeSec:   readProcUptime(app.PID),
		DeepMetrics: make(map[string]string),
	}

	inst.RSSMB = readProcRSS(app.PID)
	inst.Threads = readProcThreads(app.PID)
	inst.FDs = readProcFDs(app.PID)
	if app.Port > 0 {
		inst.Connections = countTCPConnections(app.Port)
	}

	inst.ConfigPath = findConfigFile([]string{
		"/etc/haproxy/haproxy.cfg",
		"/usr/local/etc/haproxy/haproxy.cfg",
	})

	// Count worker processes
	workerCount := countChildProcesses(app.PID, "haproxy")
	inst.DeepMetrics["workers"] = fmt.Sprintf("%d", workerCount)

	inst.HealthScore = 100
	return inst
}

// countChildProcesses counts child processes with given comm name.
func countChildProcesses(parentPID int, comm string) int {
	count := 0
	entries, err := procEntries()
	if err != nil {
		return 0
	}
	for _, pid := range entries {
		if pid == parentPID {
			continue
		}
		ppid, pcomm := readPPIDComm(pid)
		if ppid == parentPID && pcomm == comm {
			count++
		}
	}
	return count
}
