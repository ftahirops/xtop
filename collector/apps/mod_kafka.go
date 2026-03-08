//go:build linux

package apps

import (
	"strings"

	"github.com/ftahirops/xtop/model"
)

type kafkaModule struct{}

func NewKafkaModule() AppModule { return &kafkaModule{} }

func (m *kafkaModule) Type() string        { return "kafka" }
func (m *kafkaModule) DisplayName() string { return "Kafka" }

func (m *kafkaModule) Detect(processes []model.ProcessMetrics) []DetectedApp {
	var apps []DetectedApp
	for _, p := range processes {
		if p.Comm != "java" {
			continue
		}
		cmdline := readProcCmdline(p.PID)
		if !strings.Contains(cmdline, "kafka.Kafka") &&
			!strings.Contains(cmdline, "kafka-server-start") &&
			!strings.Contains(cmdline, "kafka.server") {
			continue
		}
		apps = append(apps, DetectedApp{
			PID:     p.PID,
			Port:    9092,
			Comm:    p.Comm,
			Cmdline: cmdline,
			Index:   len(apps),
		})
	}
	return apps
}

func (m *kafkaModule) Collect(app *DetectedApp, _ *AppSecrets) model.AppInstance {
	inst := model.AppInstance{
		AppType:     "kafka",
		DisplayName: "Kafka",
		PID:         app.PID,
		Port:        app.Port,
		Status:      "active",
		UptimeSec:   readProcUptime(app.PID),
		DeepMetrics: make(map[string]string),
	}

	// Tier 1 only: process metrics
	inst.RSSMB = readProcRSS(app.PID)
	inst.Threads = readProcThreads(app.PID)
	inst.FDs = readProcFDs(app.PID)
	inst.Connections = countTCPConnections(app.Port)

	// No Tier 2: Kafka requires a complex binary protocol client
	inst.HealthScore = 100

	return inst
}
