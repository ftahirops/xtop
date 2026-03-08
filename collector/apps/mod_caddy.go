//go:build linux

package apps

import (
	"github.com/ftahirops/xtop/model"
)

type caddyModule struct{}

func NewCaddyModule() AppModule { return &caddyModule{} }

func (m *caddyModule) Type() string        { return "caddy" }
func (m *caddyModule) DisplayName() string { return "Caddy" }

func (m *caddyModule) Detect(processes []model.ProcessMetrics) []DetectedApp {
	var apps []DetectedApp
	for _, p := range processes {
		if p.Comm == "caddy" {
			port := findListeningPort(p.PID)
			if port == 0 {
				port = 443
			}
			apps = append(apps, DetectedApp{
				PID: p.PID, Port: port, Comm: p.Comm,
				Cmdline: readProcCmdline(p.PID), Index: len(apps),
			})
		}
	}
	return apps
}

func (m *caddyModule) Collect(app *DetectedApp, secrets *AppSecrets) model.AppInstance {
	inst := model.AppInstance{
		AppType: "caddy", DisplayName: "Caddy",
		PID: app.PID, Port: app.Port, Status: "active",
		UptimeSec: readProcUptime(app.PID), DeepMetrics: make(map[string]string),
	}
	inst.RSSMB = readProcRSS(app.PID)
	inst.Threads = readProcThreads(app.PID)
	inst.FDs = readProcFDs(app.PID)
	inst.Connections = countTCPConnections(app.Port)
	inst.ConfigPath = findConfigFile([]string{"/etc/caddy/Caddyfile", "/home/caddy/Caddyfile"})
	inst.HealthScore = 100
	return inst
}
