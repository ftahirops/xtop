//go:build linux

package apps

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/ftahirops/xtop/model"
)

type postgresqlModule struct{}

func NewPostgreSQLModule() AppModule { return &postgresqlModule{} }

func (m *postgresqlModule) Type() string        { return "postgresql" }
func (m *postgresqlModule) DisplayName() string { return "PostgreSQL" }

func (m *postgresqlModule) Detect(processes []model.ProcessMetrics) []DetectedApp {
	var apps []DetectedApp
	for _, p := range processes {
		if p.Comm != "postgres" {
			continue
		}
		// Only detect the postmaster (PPID <= 2 means launched by init/systemd)
		if p.PPID > 2 {
			continue
		}
		port := 5432
		cmdline := readProcCmdline(p.PID)
		// Parse port from cmdline: postgres -p 5433
		fields := strings.Fields(cmdline)
		for i, arg := range fields {
			if arg == "-p" && i+1 < len(fields) {
				if p, err := strconv.Atoi(fields[i+1]); err == nil && p > 0 {
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
	return apps
}

func (m *postgresqlModule) Collect(app *DetectedApp, secrets *AppSecrets) model.AppInstance {
	inst := model.AppInstance{
		AppType:     "postgresql",
		DisplayName: "PostgreSQL",
		PID:         app.PID,
		Port:        app.Port,
		Status:      "active",
		UptimeSec:   readProcUptime(app.PID),
		DeepMetrics: make(map[string]string),
	}

	// Tier 1: process metrics (postmaster)
	inst.RSSMB = readProcRSS(app.PID)
	inst.Threads = readProcThreads(app.PID)
	inst.FDs = readProcFDs(app.PID)
	inst.Connections = countTCPConnections(app.Port)

	// Sum RSS from backend processes (children of the postmaster)
	backendCount := 0
	backendRSS := 0.0
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
		if !strings.Contains(s, "(postgres)") {
			continue
		}
		ci := strings.LastIndex(s, ")")
		if ci > 0 && ci+2 < len(s) {
			fields := strings.Fields(s[ci+2:])
			if len(fields) > 1 {
				ppid, _ := strconv.Atoi(fields[1])
				if ppid == app.PID {
					backendCount++
					backendRSS += readProcRSS(pid)
				}
			}
		}
	}
	inst.RSSMB += backendRSS
	inst.DeepMetrics["backends"] = fmt.Sprintf("%d", backendCount)

	// Config file detection
	confPath := findConfigFile([]string{
		"/etc/postgresql/17/main/postgresql.conf",
		"/etc/postgresql/16/main/postgresql.conf",
		"/etc/postgresql/15/main/postgresql.conf",
		"/etc/postgresql/14/main/postgresql.conf",
		"/etc/postgresql/13/main/postgresql.conf",
		"/etc/postgresql/12/main/postgresql.conf",
		"/var/lib/pgsql/data/postgresql.conf",
		"/var/lib/pgsql/17/data/postgresql.conf",
		"/var/lib/pgsql/16/data/postgresql.conf",
		"/var/lib/pgsql/15/data/postgresql.conf",
		"/var/lib/pgsql/14/data/postgresql.conf",
		"/var/lib/pgsql/13/data/postgresql.conf",
	})
	inst.ConfigPath = confPath

	if confPath != "" {
		maxConn, sharedBuf := parsePostgresqlConf(confPath)
		if maxConn > 0 {
			inst.DeepMetrics["max_connections"] = fmt.Sprintf("%d", maxConn)
		}
		if sharedBuf != "" {
			inst.DeepMetrics["shared_buffers"] = sharedBuf
		}
	}

	// Tier 2: placeholder — raw PostgreSQL wire protocol is complex,
	// deep metrics require libpq or credentials for SQL queries.
	if secrets != nil && secrets.PostgreSQL != nil {
		inst.NeedsCreds = false
		// TODO: connect via PostgreSQL protocol and query pg_stat_activity,
		// pg_stat_database, etc. for deep metrics.
	} else {
		inst.NeedsCreds = true
	}

	// Health: Tier 1 only — score 100, no flags unless deep metrics available
	inst.HealthScore = 100

	return inst
}

// parsePostgresqlConf extracts key settings from postgresql.conf.
func parsePostgresqlConf(path string) (maxConnections int, sharedBuffers string) {
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// Strip inline comments
		if idx := strings.Index(line, "#"); idx > 0 {
			line = strings.TrimSpace(line[:idx])
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		val := strings.TrimSpace(parts[1])
		val = strings.Trim(val, "'\"")
		switch key {
		case "max_connections":
			maxConnections, _ = strconv.Atoi(val)
		case "shared_buffers":
			sharedBuffers = val
		}
	}
	return
}
