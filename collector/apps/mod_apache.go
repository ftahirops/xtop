//go:build linux

package apps

import (
	"fmt"
	"os"
	"strconv"
	"strings"

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

	workerCount := countChildProcesses(app.PID, app.Comm)
	inst.DeepMetrics["workers"] = fmt.Sprintf("%d", workerCount)

	// Sum worker RSS
	workerRSS := 0.0
	entries, _ := procEntries()
	for _, pid := range entries {
		if pid == app.PID {
			continue
		}
		ppid, pcomm := readPPIDComm(pid)
		if ppid == app.PID && pcomm == app.Comm {
			workerRSS += readProcRSS(pid)
		}
	}
	inst.RSSMB += workerRSS

	inst.HealthScore = 100
	return inst
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
