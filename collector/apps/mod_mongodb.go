//go:build linux

package apps

import (
	"strconv"
	"strings"

	"github.com/ftahirops/xtop/model"
)

type mongoModule struct{}

func NewMongoModule() AppModule { return &mongoModule{} }

func (m *mongoModule) Type() string        { return "mongodb" }
func (m *mongoModule) DisplayName() string { return "MongoDB" }

func (m *mongoModule) Detect(processes []model.ProcessMetrics) []DetectedApp {
	var apps []DetectedApp
	for _, p := range processes {
		if p.Comm != "mongod" && p.Comm != "mongos" {
			continue
		}
		port := 27017
		cmdline := readProcCmdline(p.PID)
		// Parse --port N from cmdline
		fields := strings.Fields(cmdline)
		for i, f := range fields {
			if f == "--port" && i+1 < len(fields) {
				if v, err := strconv.Atoi(fields[i+1]); err == nil && v > 0 {
					port = v
				}
			}
			if strings.HasPrefix(f, "--port=") {
				if v, err := strconv.Atoi(strings.TrimPrefix(f, "--port=")); err == nil && v > 0 {
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

func (m *mongoModule) Collect(app *DetectedApp, secrets *AppSecrets) model.AppInstance {
	inst := model.AppInstance{
		AppType:     "mongodb",
		DisplayName: "MongoDB",
		PID:         app.PID,
		Port:        app.Port,
		Status:      "active",
		UptimeSec:   readProcUptime(app.PID),
		DeepMetrics: make(map[string]string),
	}

	// Tier 1: process metrics
	inst.RSSMB = readProcRSS(app.PID)
	inst.Threads = readProcThreads(app.PID)
	inst.FDs = readProcFDs(app.PID)
	inst.Connections = countTCPConnections(app.Port)

	// Tier 2: placeholder — MongoDB requires a client driver for serverStatus.
	// Flag NeedsCreds if credentials are configured (so the UI can indicate deep metrics are possible).
	if secrets != nil && secrets.MongoDB != nil && secrets.MongoDB.URI != "" {
		inst.NeedsCreds = true
	}

	// Config file detection
	inst.ConfigPath = findConfigFile([]string{
		"/etc/mongod.conf",
		"/etc/mongodb.conf",
		"/usr/local/etc/mongod.conf",
	})

	// Health: baseline healthy since we only have Tier 1
	inst.HealthScore = 100

	return inst
}
