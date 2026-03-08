//go:build linux

package apps

import (
	"github.com/ftahirops/xtop/model"
)

type traefikModule struct{}

func NewTraefikModule() AppModule { return &traefikModule{} }

func (m *traefikModule) Type() string        { return "traefik" }
func (m *traefikModule) DisplayName() string { return "Traefik" }

func (m *traefikModule) Detect(processes []model.ProcessMetrics) []DetectedApp {
	var apps []DetectedApp
	for _, p := range processes {
		if p.Comm == "traefik" {
			port := findListeningPort(p.PID)
			if port == 0 {
				port = 80
			}
			apps = append(apps, DetectedApp{
				PID: p.PID, Port: port, Comm: p.Comm,
				Cmdline: readProcCmdline(p.PID), Index: len(apps),
			})
		}
	}
	return apps
}

func (m *traefikModule) Collect(app *DetectedApp, secrets *AppSecrets) model.AppInstance {
	inst := model.AppInstance{
		AppType: "traefik", DisplayName: "Traefik",
		PID: app.PID, Port: app.Port, Status: "active",
		UptimeSec: readProcUptime(app.PID), DeepMetrics: make(map[string]string),
	}
	inst.RSSMB = readProcRSS(app.PID)
	inst.Threads = readProcThreads(app.PID)
	inst.FDs = readProcFDs(app.PID)
	inst.Connections = countTCPConnections(app.Port)
	inst.HealthScore = 100
	return inst
}
