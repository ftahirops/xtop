//go:build linux

package apps

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"

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

	// Tier 1: process metrics
	inst.RSSMB = readProcRSS(app.PID)
	inst.Threads = readProcThreads(app.PID)
	inst.FDs = readProcFDs(app.PID)
	inst.Connections = countTCPConnections(app.Port)

	// ---- Tier 2: Deep Metrics ----

	apiPort := 8080

	// Try to detect API port from cmdline
	cmdline := app.Cmdline
	if cmdline == "" {
		cmdline = readProcCmdline(app.PID)
	}
	if p := parseTraefikAPIPort(cmdline); p > 0 {
		apiPort = p
	}
	inst.DeepMetrics["api_port"] = fmt.Sprintf("%d", apiPort)

	// Config file parsing
	confPath := findConfigFile([]string{
		"/etc/traefik/traefik.toml",
		"/etc/traefik/traefik.yml",
		"/etc/traefik/traefik.yaml",
	})
	inst.ConfigPath = confPath

	if confPath != "" {
		cdata := parseTraefikConfig(confPath)
		if cdata.dashboardEnabled {
			inst.DeepMetrics["dashboard_enabled"] = "true"
		}
		if cdata.metricsPrometheus {
			inst.DeepMetrics["metrics_prometheus"] = "true"
		}
		if len(cdata.entryPoints) > 0 {
			inst.DeepMetrics["config_entrypoints"] = strings.Join(cdata.entryPoints, ",")
		}
		inst.HasDeepMetrics = true
	}

	// /ping health check
	healthStatus := traefikPing(apiPort)
	inst.DeepMetrics["health_status"] = healthStatus

	// /api/overview
	overview := traefikAPIOverview(apiPort)
	if overview != nil {
		inst.HasDeepMetrics = true
		for k, v := range overview {
			inst.DeepMetrics[k] = v
		}
	}

	// /api/entrypoints
	if eps := traefikEntrypoints(apiPort); eps != "" {
		inst.DeepMetrics["entrypoints"] = eps
		inst.HasDeepMetrics = true
	}

	// /api/version
	if ver := traefikAPIVersion(apiPort); ver != "" {
		inst.Version = ver
		inst.DeepMetrics["traefik_version"] = ver
	} else if ver := detectTraefikVersionCLI(); ver != "" {
		inst.Version = ver
		inst.DeepMetrics["traefik_version"] = ver
	}

	// ---- Health scoring ----
	inst.HealthScore = 100

	// Health endpoint check
	if healthStatus == "unhealthy" {
		inst.HealthScore -= 20
		inst.HealthIssues = append(inst.HealthIssues,
			"health endpoint (/ping) returned non-200")
	}

	// HTTP router errors
	if overview != nil {
		if errStr, ok := overview["http_router_errors"]; ok && errStr != "0" {
			inst.HealthScore -= 10
			inst.HealthIssues = append(inst.HealthIssues,
				fmt.Sprintf("HTTP router errors: %s", errStr))
		}
		// HTTP service errors
		if errStr, ok := overview["http_service_errors"]; ok && errStr != "0" {
			inst.HealthScore -= 10
			inst.HealthIssues = append(inst.HealthIssues,
				fmt.Sprintf("HTTP service errors: %s", errStr))
		}
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

// traefikConfData holds parsed Traefik config info.
type traefikConfData struct {
	entryPoints       []string
	dashboardEnabled  bool
	metricsPrometheus bool
}

// parseTraefikConfig parses traefik.toml or traefik.yml for key settings.
func parseTraefikConfig(path string) traefikConfData {
	f, err := os.Open(path)
	if err != nil {
		return traefikConfData{}
	}
	defer f.Close()

	var d traefikConfData
	scanner := bufio.NewScanner(f)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		lower := strings.ToLower(line)

		// Detect entryPoints (TOML: [entryPoints.NAME], YAML: entrypoints key)
		if strings.HasPrefix(lower, "[entrypoints.") {
			// TOML format: [entryPoints.web]
			name := strings.TrimPrefix(line, "[entryPoints.")
			name = strings.TrimPrefix(name, "[entrypoints.")
			name = strings.TrimSuffix(name, "]")
			name = strings.Split(name, ".")[0]
			if name != "" {
				d.entryPoints = append(d.entryPoints, name)
			}
		}

		// Dashboard
		if strings.Contains(lower, "dashboard") && (strings.Contains(lower, "true") || strings.Contains(lower, "= true")) {
			d.dashboardEnabled = true
		}

		// Metrics prometheus
		if strings.Contains(lower, "[metrics.prometheus]") || strings.Contains(lower, "prometheus:") {
			d.metricsPrometheus = true
		}
	}
	return d
}

// parseTraefikAPIPort tries to find the API port from cmdline flags.
func parseTraefikAPIPort(cmdline string) int {
	// Look for --api.insecure=true on port or --entrypoints.traefik.address=:XXXX
	// Common: --api.dashboard=true (default 8080)

	// Check for explicit traefik entrypoint address
	for _, prefix := range []string{
		"--entrypoints.traefik.address=:",
		"--entryPoints.traefik.address=:",
	} {
		if idx := strings.Index(cmdline, prefix); idx >= 0 {
			rest := cmdline[idx+len(prefix):]
			end := strings.IndexAny(rest, " /\t")
			if end < 0 {
				end = len(rest)
			}
			port := 0
			fmt.Sscanf(rest[:end], "%d", &port)
			if port > 0 {
				return port
			}
		}
	}
	return 0
}

// traefikPing checks the /ping endpoint. Returns "ok", "unhealthy", or "unavailable".
func traefikPing(apiPort int) string {
	client := &http.Client{Timeout: 2 * time.Second}
	url := fmt.Sprintf("http://127.0.0.1:%d/ping", apiPort)
	resp, err := client.Get(url)
	if err != nil {
		return "unavailable"
	}
	defer resp.Body.Close()
	if resp.StatusCode == 200 {
		return "ok"
	}
	return "unhealthy"
}

// traefikAPIOverview fetches /api/overview and extracts router/service/middleware counts.
func traefikAPIOverview(apiPort int) map[string]string {
	client := &http.Client{Timeout: 2 * time.Second}
	url := fmt.Sprintf("http://127.0.0.1:%d/api/overview", apiPort)
	resp, err := client.Get(url)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
	if err != nil {
		return nil
	}

	// Parse the overview JSON structure
	var raw map[string]interface{}
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil
	}

	result := make(map[string]string)

	// Extract HTTP stats
	if httpData, ok := raw["http"].(map[string]interface{}); ok {
		if routers, ok := httpData["routers"].(map[string]interface{}); ok {
			if total, ok := routers["total"]; ok {
				result["http_routers"] = fmt.Sprintf("%v", total)
			}
			if warnings, ok := routers["warnings"]; ok {
				result["http_router_warnings"] = fmt.Sprintf("%v", warnings)
			}
			if errors, ok := routers["errors"]; ok {
				result["http_router_errors"] = fmt.Sprintf("%v", errors)
			}
		}
		if services, ok := httpData["services"].(map[string]interface{}); ok {
			if total, ok := services["total"]; ok {
				result["http_services"] = fmt.Sprintf("%v", total)
			}
			if errors, ok := services["errors"]; ok {
				result["http_service_errors"] = fmt.Sprintf("%v", errors)
			}
		}
		if middlewares, ok := httpData["middlewares"].(map[string]interface{}); ok {
			if total, ok := middlewares["total"]; ok {
				result["http_middlewares"] = fmt.Sprintf("%v", total)
			}
		}
	}

	// Extract TCP stats
	if tcpData, ok := raw["tcp"].(map[string]interface{}); ok {
		if routers, ok := tcpData["routers"].(map[string]interface{}); ok {
			if total, ok := routers["total"]; ok {
				result["tcp_routers"] = fmt.Sprintf("%v", total)
			}
		}
		if services, ok := tcpData["services"].(map[string]interface{}); ok {
			if total, ok := services["total"]; ok {
				result["tcp_services"] = fmt.Sprintf("%v", total)
			}
		}
	}

	// Extract UDP stats
	if udpData, ok := raw["udp"].(map[string]interface{}); ok {
		if routers, ok := udpData["routers"].(map[string]interface{}); ok {
			if total, ok := routers["total"]; ok {
				result["udp_routers"] = fmt.Sprintf("%v", total)
			}
		}
		if services, ok := udpData["services"].(map[string]interface{}); ok {
			if total, ok := services["total"]; ok {
				result["udp_services"] = fmt.Sprintf("%v", total)
			}
		}
	}

	return result
}

// traefikEntrypoints fetches /api/entrypoints and returns a comma-separated list.
func traefikEntrypoints(apiPort int) string {
	client := &http.Client{Timeout: 2 * time.Second}
	url := fmt.Sprintf("http://127.0.0.1:%d/api/entrypoints", apiPort)
	resp, err := client.Get(url)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return ""
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
	if err != nil {
		return ""
	}

	var eps []map[string]interface{}
	if err := json.Unmarshal(body, &eps); err != nil {
		return ""
	}

	var names []string
	for _, ep := range eps {
		name := ""
		addr := ""
		if n, ok := ep["name"].(string); ok {
			name = n
		}
		if a, ok := ep["address"].(string); ok {
			addr = a
		}
		if name != "" {
			if addr != "" {
				names = append(names, fmt.Sprintf("%s(%s)", name, addr))
			} else {
				names = append(names, name)
			}
		}
	}
	return strings.Join(names, ",")
}

// traefikAPIVersion fetches /api/version from Traefik API.
func traefikAPIVersion(apiPort int) string {
	client := &http.Client{Timeout: 2 * time.Second}
	url := fmt.Sprintf("http://127.0.0.1:%d/api/version", apiPort)
	resp, err := client.Get(url)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return ""
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		return ""
	}

	var raw map[string]interface{}
	if err := json.Unmarshal(body, &raw); err != nil {
		return ""
	}
	if ver, ok := raw["Version"].(string); ok {
		return ver
	}
	if ver, ok := raw["version"].(string); ok {
		return ver
	}
	return ""
}

// detectTraefikVersionCLI runs "traefik version" to get the version.
func detectTraefikVersionCLI() string {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "traefik", "version")
	out, err := cmd.Output()
	if err != nil {
		return ""
	}
	// Output format: "Version:      2.10.4\nCodename: ..."
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "Version:") {
			return strings.TrimSpace(strings.TrimPrefix(line, "Version:"))
		}
	}
	return ""
}
