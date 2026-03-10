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

	// Tier 1: process metrics
	inst.RSSMB = readProcRSS(app.PID)
	inst.Threads = readProcThreads(app.PID)
	inst.FDs = readProcFDs(app.PID)
	inst.Connections = countTCPConnections(app.Port)

	// Config file
	confPath := findConfigFile([]string{
		"/etc/caddy/Caddyfile",
		"/home/caddy/Caddyfile",
		"/srv/Caddyfile",
	})
	inst.ConfigPath = confPath

	// ---- Tier 2: Deep Metrics ----

	// Parse Caddyfile
	if confPath != "" {
		cdata := parseCaddyfile(confPath)
		inst.HasDeepMetrics = true
		if cdata.sites > 0 {
			inst.DeepMetrics["sites"] = fmt.Sprintf("%d", cdata.sites)
		}
		if cdata.reverseProxyCount > 0 {
			inst.DeepMetrics["reverse_proxy_count"] = fmt.Sprintf("%d", cdata.reverseProxyCount)
		}
		if cdata.tlsEnabled {
			inst.DeepMetrics["tls_enabled"] = "true"
		}
		if cdata.encodeGzip {
			inst.DeepMetrics["encode_gzip"] = "true"
		}
	}

	// Version via caddy version
	if ver := detectCaddyVersion(); ver != "" {
		inst.Version = ver
		inst.DeepMetrics["caddy_version"] = ver
	}

	// Admin API (default localhost:2019)
	adminPort := 2019
	adminReachable := false

	// Try /config/ to extract route/site info from live config
	if apiData := caddyAdminConfig(adminPort); apiData != nil {
		adminReachable = true
		inst.HasDeepMetrics = true
		inst.DeepMetrics["admin_api"] = "reachable"

		// Count routes and sites from JSON config
		if routes, ok := apiData["route_count"]; ok {
			inst.DeepMetrics["api_routes"] = routes
		}
		if servers, ok := apiData["server_count"]; ok {
			inst.DeepMetrics["api_servers"] = servers
		}
		if autoHTTPS, ok := apiData["auto_https"]; ok {
			inst.DeepMetrics["auto_https"] = autoHTTPS
		}
	}

	if !adminReachable {
		inst.DeepMetrics["admin_api"] = "unreachable"
	}

	// Try /reverse_proxy/upstreams for upstream health
	if upstreams := caddyUpstreamHealth(adminPort); upstreams != nil {
		for k, v := range upstreams {
			inst.DeepMetrics[k] = v
		}
	}

	// Try /metrics (Prometheus format)
	if promMetrics := caddyPrometheusMetrics(adminPort); promMetrics != nil {
		inst.HasDeepMetrics = true
		for k, v := range promMetrics {
			inst.DeepMetrics[k] = v
		}
	}

	// ---- Health scoring ----
	inst.HealthScore = 100

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

// caddyfileData holds parsed Caddyfile info.
type caddyfileData struct {
	sites             int
	reverseProxyCount int
	tlsEnabled        bool
	encodeGzip        bool
}

// parseCaddyfile parses a Caddyfile for site blocks, reverse_proxy, tls, encode directives.
func parseCaddyfile(path string) caddyfileData {
	f, err := os.Open(path)
	if err != nil {
		return caddyfileData{}
	}
	defer f.Close()

	var d caddyfileData
	scanner := bufio.NewScanner(f)
	braceDepth := 0
	inSiteBlock := false

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Skip comments and empty lines
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Detect site blocks: lines at depth 0 that look like addresses
		// e.g., "example.com {", ":8080 {", "localhost {", "*.example.com {"
		if braceDepth == 0 && !strings.HasPrefix(line, "}") {
			// If line contains { it's likely a site block start
			if strings.Contains(line, "{") && !strings.HasPrefix(line, "import") &&
				!strings.HasPrefix(line, "(") {
				d.sites++
				inSiteBlock = true
			}
		}

		// Count braces
		for _, ch := range line {
			if ch == '{' {
				braceDepth++
			} else if ch == '}' {
				braceDepth--
				if braceDepth <= 0 {
					braceDepth = 0
					inSiteBlock = false
				}
			}
		}

		if !inSiteBlock {
			continue
		}

		// Check for directives inside site blocks
		if strings.HasPrefix(line, "reverse_proxy") {
			d.reverseProxyCount++
		}
		if strings.HasPrefix(line, "tls") {
			d.tlsEnabled = true
		}
		if strings.HasPrefix(line, "encode") && strings.Contains(line, "gzip") {
			d.encodeGzip = true
		}
	}
	return d
}

// detectCaddyVersion runs "caddy version" to get the version string.
func detectCaddyVersion() string {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "caddy", "version")
	out, err := cmd.Output()
	if err != nil {
		return ""
	}
	ver := strings.TrimSpace(string(out))
	// Output is like "v2.7.5 h1:abc123"
	if parts := strings.Fields(ver); len(parts) > 0 {
		return parts[0]
	}
	return ver
}

// caddyAdminConfig fetches /config/ from the admin API and extracts summary info.
func caddyAdminConfig(port int) map[string]string {
	client := &http.Client{Timeout: 2 * time.Second}
	url := fmt.Sprintf("http://127.0.0.1:%d/config/", port)
	resp, err := client.Get(url)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
	if err != nil {
		return nil
	}

	var raw map[string]interface{}
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil
	}

	result := make(map[string]string)

	// Count servers and routes from apps.http.servers
	if apps, ok := raw["apps"].(map[string]interface{}); ok {
		if httpApp, ok := apps["http"].(map[string]interface{}); ok {
			if servers, ok := httpApp["servers"].(map[string]interface{}); ok {
				result["server_count"] = fmt.Sprintf("%d", len(servers))

				totalRoutes := 0
				for _, srv := range servers {
					if srvMap, ok := srv.(map[string]interface{}); ok {
						if routes, ok := srvMap["routes"].([]interface{}); ok {
							totalRoutes += len(routes)
						}
					}
				}
				result["route_count"] = fmt.Sprintf("%d", totalRoutes)
			}

			// Check auto_https
			if _, ok := httpApp["http_port"]; ok {
				result["auto_https"] = "custom"
			} else {
				result["auto_https"] = "enabled"
			}
		}
	}

	return result
}

// caddyUpstreamHealth fetches /reverse_proxy/upstreams for health info.
func caddyUpstreamHealth(port int) map[string]string {
	client := &http.Client{Timeout: 2 * time.Second}
	url := fmt.Sprintf("http://127.0.0.1:%d/reverse_proxy/upstreams", port)
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

	var upstreams []map[string]interface{}
	if err := json.Unmarshal(body, &upstreams); err != nil {
		return nil
	}

	result := make(map[string]string)
	healthy, unhealthy := 0, 0
	for _, u := range upstreams {
		if numReqs, ok := u["num_requests"].(float64); ok {
			result["upstream_total_requests"] = fmt.Sprintf("%.0f", numReqs)
		}
		if h, ok := u["healthy"].(bool); ok {
			if h {
				healthy++
			} else {
				unhealthy++
			}
		}
	}
	result["upstreams_total"] = fmt.Sprintf("%d", len(upstreams))
	result["upstreams_healthy"] = fmt.Sprintf("%d", healthy)
	result["upstreams_unhealthy"] = fmt.Sprintf("%d", unhealthy)

	return result
}

// caddyPrometheusMetrics fetches /metrics and parses key Caddy metrics.
func caddyPrometheusMetrics(port int) map[string]string {
	client := &http.Client{Timeout: 2 * time.Second}
	url := fmt.Sprintf("http://127.0.0.1:%d/metrics", port)
	resp, err := client.Get(url)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
	if err != nil {
		return nil
	}

	text := string(body)
	if !strings.Contains(text, "caddy_") {
		return nil
	}

	result := make(map[string]string)

	// Parse simple aggregate metrics from Prometheus text format
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "#") || line == "" {
			continue
		}
		// caddy_http_requests_total (might have labels)
		if strings.HasPrefix(line, "caddy_http_requests_total") && !strings.Contains(line, "{") {
			if parts := strings.Fields(line); len(parts) == 2 {
				result["http_requests_total"] = parts[1]
			}
		}
	}

	return result
}
