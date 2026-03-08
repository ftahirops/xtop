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

type mysqlModule struct{}

func NewMySQLModule() AppModule { return &mysqlModule{} }

func (m *mysqlModule) Type() string        { return "mysql" }
func (m *mysqlModule) DisplayName() string { return "MySQL" }

func (m *mysqlModule) Detect(processes []model.ProcessMetrics) []DetectedApp {
	var apps []DetectedApp
	for _, p := range processes {
		if p.Comm != "mysqld" && p.Comm != "mariadbd" {
			continue
		}
		port := 3306
		cmdline := readProcCmdline(p.PID)
		for _, part := range strings.Fields(cmdline) {
			if strings.HasPrefix(part, "--port=") {
				if v, err := strconv.Atoi(strings.TrimPrefix(part, "--port=")); err == nil && v > 0 {
					port = v
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

func (m *mysqlModule) Collect(app *DetectedApp, secrets *AppSecrets) model.AppInstance {
	displayName := "MySQL"
	if app.Comm == "mariadbd" {
		displayName = "MariaDB"
	}

	inst := model.AppInstance{
		AppType:     "mysql",
		DisplayName: displayName,
		PID:         app.PID,
		Port:        app.Port,
		Status:      "active",
		UptimeSec:   readProcUptime(app.PID),
		DeepMetrics: make(map[string]string),
	}

	// Tier 1: process-level metrics (always available)
	inst.RSSMB = readProcRSS(app.PID)
	inst.Threads = readProcThreads(app.PID)
	inst.FDs = readProcFDs(app.PID)
	inst.Connections = countTCPConnections(app.Port)

	// Config parsing
	confPath := findConfigFile([]string{
		"/etc/mysql/my.cnf",
		"/etc/my.cnf",
		"/etc/mysql/mysql.conf.d/mysqld.cnf",
		"/etc/mysql/mariadb.conf.d/50-server.cnf",
	})
	inst.ConfigPath = confPath

	maxConns, bufferPool := parseMySQLConf(confPath)
	if maxConns > 0 {
		inst.DeepMetrics["max_connections"] = fmt.Sprintf("%d", maxConns)
	}
	if bufferPool != "" {
		inst.DeepMetrics["innodb_buffer_pool_size"] = bufferPool
	}

	// Tier 2: MySQL protocol queries (placeholder)
	// The MySQL wire protocol requires a multi-step handshake (initial handshake
	// packet, auth response with password hashing, OK/ERR parsing) before any
	// COM_QUERY can be sent. A proper implementation will be added later.
	if secrets != nil && secrets.MySQL != nil && secrets.MySQL.Password != "" {
		// TODO: implement raw MySQL protocol handshake + COM_QUERY
		// for SHOW GLOBAL STATUS and SHOW PROCESSLIST
		inst.NeedsCreds = false // creds configured but protocol not yet implemented
		inst.DeepMetrics["tier2_status"] = "pending_implementation"
	} else {
		inst.NeedsCreds = true
	}

	// Health scoring — only flag actual degradation
	inst.HealthScore = 100

	// Connection saturation (Tier 1: compare active connections to configured max)
	if maxConns > 0 && inst.Connections > 0 {
		connPct := float64(inst.Connections) / float64(maxConns) * 100
		inst.DeepMetrics["connection_usage_pct"] = fmt.Sprintf("%.1f%%", connPct)
		if connPct > 80 {
			inst.HealthScore -= 15
			inst.HealthIssues = append(inst.HealthIssues,
				fmt.Sprintf("connections at %.0f%% of max_connections (%d/%d)", connPct, inst.Connections, maxConns))
		}
	}

	// High thread count relative to connections (possible thread leak)
	if inst.Threads > 0 && inst.Connections > 0 && inst.Threads > inst.Connections*4 {
		inst.HealthScore -= 5
		inst.HealthIssues = append(inst.HealthIssues,
			fmt.Sprintf("thread count (%d) is high relative to connections (%d)", inst.Threads, inst.Connections))
	}

	// FD pressure
	if inst.FDs > 50000 {
		inst.HealthScore -= 10
		inst.HealthIssues = append(inst.HealthIssues,
			fmt.Sprintf("high FD usage (%d) — may be approaching system limits", inst.FDs))
	}

	if inst.HealthScore < 0 {
		inst.HealthScore = 0
	}

	return inst
}

// parseMySQLConf extracts max_connections and innodb_buffer_pool_size from a MySQL config file.
func parseMySQLConf(path string) (maxConnections int, bufferPoolSize string) {
	if path == "" {
		return
	}
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}

		// Handle key = value or key=value
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		val := strings.TrimSpace(parts[1])

		switch key {
		case "max_connections":
			maxConnections, _ = strconv.Atoi(val)
		case "innodb_buffer_pool_size":
			bufferPoolSize = val
		}
	}
	return
}
