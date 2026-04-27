//go:build linux

package apps

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/ftahirops/xtop/model"
)

// Kibana module — detects Node.js process running Kibana and talks to the
// Status API (default port 5601). /api/status returns plugin health, overall
// status, and various metrics (heap, event loop delay, request stats).

type kibanaModule struct {
	client *http.Client
	prev   map[int]kibanaPrev
}

type kibanaPrev struct {
	reqTotal int64
	at       time.Time
}

func NewKibanaModule() AppModule {
	return &kibanaModule{
		client: &http.Client{
			Timeout:   5 * time.Second,
			Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
		},
		prev: make(map[int]kibanaPrev),
	}
}

func (m *kibanaModule) Close() {
	if m.client != nil {
		m.client.CloseIdleConnections()
	}
}

func (m *kibanaModule) Type() string        { return "kibana" }
func (m *kibanaModule) DisplayName() string { return "Kibana" }

func (m *kibanaModule) Detect(processes []model.ProcessMetrics) []DetectedApp {
	var out []DetectedApp
	seen := make(map[int]bool)
	for _, p := range processes {
		// Kibana runs as node
		if p.Comm != "node" {
			continue
		}
		if isContainerized(p.PID) {
			continue
		}
		cmdline := readProcCmdline(p.PID)
		matched := false
		if strings.Contains(cmdline, "kibana") {
			matched = true
		}
		// Fallback: check cwd for kibana path
		if !matched {
			if cwd, err := os.Readlink(fmt.Sprintf("/proc/%d/cwd", p.PID)); err == nil {
				if strings.Contains(cwd, "kibana") {
					matched = true
				}
			}
		}
		if !matched {
			continue
		}
		// Skip workers — child of another node/kibana
		if p.PPID > 2 {
			pc := readProcCmdline(p.PPID)
			if strings.Contains(pc, "kibana") {
				continue
			}
		}

		port := 5601
		// Try to read server.port from config; otherwise scan listen ports
		if lp := findListeningPort(p.PID); lp > 0 {
			port = lp
		}
		// Also parse --server.port= overrides
		for _, f := range strings.Fields(cmdline) {
			if strings.HasPrefix(f, "--server.port=") {
				if v, err := strconv.Atoi(strings.TrimPrefix(f, "--server.port=")); err == nil {
					port = v
				}
			}
		}
		if seen[port] {
			continue
		}
		seen[port] = true

		out = append(out, DetectedApp{
			PID:     p.PID,
			Port:    port,
			Comm:    p.Comm,
			Cmdline: cmdline,
			Index:   len(out),
		})
	}
	return out
}

func (m *kibanaModule) Collect(app *DetectedApp, secrets *AppSecrets) model.AppInstance {
	inst := model.AppInstance{
		AppType:     "kibana",
		DisplayName: "Kibana",
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
	inst.CPUPct = readProcCPUPct(app.PID, inst.UptimeSec)

	baseURL := fmt.Sprintf("http://127.0.0.1:%d", app.Port)
	raw := kibanaGET(m.client, baseURL+"/api/status")
	if raw == nil {
		baseURL = fmt.Sprintf("https://127.0.0.1:%d", app.Port)
		raw = kibanaGET(m.client, baseURL+"/api/status")
	}
	if raw != nil {
		inst.HasDeepMetrics = true
		m.populateKibanaMetrics(&inst, raw)
	}

	inst.HealthScore = 100
	kibanaHealthRules(&inst)
	if inst.HealthScore < 0 {
		inst.HealthScore = 0
	}
	if inst.HealthScore > 100 {
		inst.HealthScore = 100
	}
	return inst
}

func (m *kibanaModule) populateKibanaMetrics(inst *model.AppInstance, raw map[string]interface{}) {
	dm := inst.DeepMetrics

	// Name/version
	if name, ok := raw["name"].(string); ok {
		dm["node_name"] = name
	}
	if v, ok := raw["version"].(map[string]interface{}); ok {
		if num, ok := v["number"].(string); ok {
			inst.Version = num
			dm["version"] = num
		}
		if build, ok := v["build_number"]; ok {
			dm["build_number"] = fmt.Sprintf("%v", build)
		}
	}

	// Overall status
	if status, ok := raw["status"].(map[string]interface{}); ok {
		if overall, ok := status["overall"].(map[string]interface{}); ok {
			// API has both legacy (.state) and new (.level) formats
			if s, ok := overall["state"].(string); ok {
				dm["status_overall"] = s
			} else if l, ok := overall["level"].(string); ok {
				dm["status_overall"] = l
			}
			if title, ok := overall["title"].(string); ok {
				dm["status_title"] = title
			}
			if summary, ok := overall["summary"].(string); ok {
				dm["status_summary"] = summary
			}
			if nick, ok := overall["nickname"].(string); ok {
				dm["status_nickname"] = nick
			}
		}

		// Plugin/core statuses
		plugins := map[string]interface{}{}
		if core, ok := status["core"].(map[string]interface{}); ok {
			for k, v := range core {
				plugins["core."+k] = v
			}
		}
		if p, ok := status["plugins"].(map[string]interface{}); ok {
			for k, v := range p {
				plugins[k] = v
			}
		} else if arr, ok := status["statuses"].([]interface{}); ok {
			// older format
			for _, it := range arr {
				p, ok := it.(map[string]interface{})
				if !ok {
					continue
				}
				id, _ := p["id"].(string)
				if id == "" {
					continue
				}
				plugins[id] = p
			}
		}

		degraded := 0
		unavail := 0
		var degradedPlugins []string
		var unavailPlugins []string
		for name, pv := range plugins {
			p, ok := pv.(map[string]interface{})
			if !ok {
				continue
			}
			state := ""
			if s, ok := p["state"].(string); ok {
				state = s
			} else if l, ok := p["level"].(string); ok {
				state = l
			}
			switch strings.ToLower(state) {
			case "red", "critical", "unavailable":
				unavail++
				unavailPlugins = append(unavailPlugins, name)
			case "yellow", "degraded":
				degraded++
				degradedPlugins = append(degradedPlugins, name)
			}
		}
		dm["plugins_total"] = fmt.Sprintf("%d", len(plugins))
		dm["plugins_degraded"] = fmt.Sprintf("%d", degraded)
		dm["plugins_unavailable"] = fmt.Sprintf("%d", unavail)
		sort.Strings(degradedPlugins)
		sort.Strings(unavailPlugins)
		if len(degradedPlugins) > 5 {
			degradedPlugins = degradedPlugins[:5]
		}
		if len(unavailPlugins) > 5 {
			unavailPlugins = unavailPlugins[:5]
		}
		if len(degradedPlugins) > 0 {
			dm["plugins_degraded_names"] = strings.Join(degradedPlugins, ",")
		}
		if len(unavailPlugins) > 0 {
			dm["plugins_unavailable_names"] = strings.Join(unavailPlugins, ",")
		}
	}

	// Metrics
	if metrics, ok := raw["metrics"].(map[string]interface{}); ok {
		// Process — heap, event loop, uptime
		if proc, ok := metrics["process"].(map[string]interface{}); ok {
			if mem, ok := proc["memory"].(map[string]interface{}); ok {
				if heap, ok := mem["heap"].(map[string]interface{}); ok {
					used := parseJSONFloat(heap["used_in_bytes"])
					total := parseJSONFloat(heap["total_in_bytes"])
					limit := parseJSONFloat(heap["size_limit"])
					dm["heap_used"] = fmtBytes(used)
					dm["heap_total"] = fmtBytes(total)
					if limit > 0 {
						dm["heap_limit"] = fmtBytes(limit)
						dm["heap_used_pct"] = fmt.Sprintf("%.1f", used/limit*100)
					} else if total > 0 {
						dm["heap_used_pct"] = fmt.Sprintf("%.1f", used/total*100)
					}
				}
				if rss := parseJSONFloat(mem["resident_set_size_in_bytes"]); rss > 0 {
					dm["rss_bytes"] = fmtBytes(rss)
				}
			}
			if eld := parseJSONFloat(proc["event_loop_delay"]); eld > 0 {
				dm["event_loop_delay_ms"] = fmt.Sprintf("%.2f", eld)
			}
			if up := parseJSONFloat(proc["uptime_in_millis"]); up > 0 {
				dm["process_uptime_sec"] = fmt.Sprintf("%.0f", up/1000)
			}
		}

		// OS load / memory
		if osM, ok := metrics["os"].(map[string]interface{}); ok {
			if load, ok := osM["load"].(map[string]interface{}); ok {
				if v := parseJSONFloat(load["1m"]); v > 0 {
					dm["os_load_1m"] = fmt.Sprintf("%.2f", v)
				}
			}
		}

		// Response times
		if rt, ok := metrics["response_times"].(map[string]interface{}); ok {
			if avg := parseJSONFloat(rt["avg_in_millis"]); avg > 0 {
				dm["resp_avg_ms"] = fmt.Sprintf("%.1f", avg)
			}
			if mx := parseJSONFloat(rt["max_in_millis"]); mx > 0 {
				dm["resp_max_ms"] = fmt.Sprintf("%.1f", mx)
			}
		}

		// Requests
		if req, ok := metrics["requests"].(map[string]interface{}); ok {
			total := parseJSONInt(req["total"])
			dis := parseJSONInt(req["disconnects"])
			dm["requests_total"] = fmt.Sprintf("%d", total)
			dm["requests_disconnects"] = fmt.Sprintf("%d", dis)
			// status_codes (map code → count)
			if codes, ok := req["status_codes"].(map[string]interface{}); ok {
				for code, cnt := range codes {
					dm["req_status_"+code] = fmt.Sprintf("%v", parseJSONInt(cnt))
				}
			}

			// Rate calculation
			now := time.Now()
			prev := m.prev[inst.PID]
			if !prev.at.IsZero() {
				elapsed := now.Sub(prev.at).Seconds()
				if elapsed >= 1 {
					d := float64(total-prev.reqTotal) / elapsed
					if d < 0 {
						d = 0
					}
					dm["requests_per_sec"] = fmt.Sprintf("%.2f", d)
				}
			}
			m.prev[inst.PID] = kibanaPrev{reqTotal: total, at: now}
		}

		// Concurrent connections
		if c := parseJSONInt(metrics["concurrent_connections"]); c >= 0 {
			dm["concurrent_connections"] = fmt.Sprintf("%d", c)
		}
	}
}

// kibanaHealthRules applies Kibana health checks.
func kibanaHealthRules(inst *model.AppInstance) {
	if !inst.HasDeepMetrics {
		return
	}
	dm := inst.DeepMetrics

	// 1. Overall status
	switch strings.ToLower(dm["status_overall"]) {
	case "red", "critical", "unavailable":
		inst.HealthScore -= 30
		msg := "Kibana overall status RED — service degraded"
		if dm["status_summary"] != "" {
			msg = fmt.Sprintf("status RED — %s", dm["status_summary"])
		}
		inst.HealthIssues = append(inst.HealthIssues, msg)
	case "yellow", "degraded":
		inst.HealthScore -= 15
		msg := "Kibana status YELLOW"
		if dm["status_summary"] != "" {
			msg = fmt.Sprintf("status YELLOW — %s", dm["status_summary"])
		}
		inst.HealthIssues = append(inst.HealthIssues, msg)
	}

	// 2. Plugins unavailable (critical)
	if n, _ := strconv.Atoi(dm["plugins_unavailable"]); n > 0 {
		inst.HealthScore -= 15
		names := dm["plugins_unavailable_names"]
		inst.HealthIssues = append(inst.HealthIssues,
			fmt.Sprintf("%d plugins unavailable: %s", n, names))
	}

	// 3. Plugins degraded
	if n, _ := strconv.Atoi(dm["plugins_degraded"]); n > 0 {
		inst.HealthScore -= 10
		names := dm["plugins_degraded_names"]
		inst.HealthIssues = append(inst.HealthIssues,
			fmt.Sprintf("%d plugins degraded: %s", n, names))
	}

	// 4. Event loop delay
	if v, err := strconv.ParseFloat(dm["event_loop_delay_ms"], 64); err == nil {
		if v > 500 {
			inst.HealthScore -= 20
			inst.HealthIssues = append(inst.HealthIssues,
				fmt.Sprintf("event loop delay %.0fms — UI will feel frozen", v))
		} else if v > 100 {
			inst.HealthScore -= 10
			inst.HealthIssues = append(inst.HealthIssues,
				fmt.Sprintf("event loop delay %.0fms — UI sluggish", v))
		}
	}

	// 5. Heap pressure
	if pctStr := dm["heap_used_pct"]; pctStr != "" {
		pct, _ := strconv.ParseFloat(pctStr, 64)
		if pct > 90 {
			inst.HealthScore -= 20
			inst.HealthIssues = append(inst.HealthIssues,
				fmt.Sprintf("Node.js heap at %.1f%% — near v8 heap limit", pct))
		} else if pct > 80 {
			inst.HealthScore -= 10
			inst.HealthIssues = append(inst.HealthIssues,
				fmt.Sprintf("Node.js heap at %.1f%% — consider --max-old-space-size", pct))
		}
	}

	// 6. Response time degradation
	if v, err := strconv.ParseFloat(dm["resp_avg_ms"], 64); err == nil {
		if v > 2000 {
			inst.HealthScore -= 15
			inst.HealthIssues = append(inst.HealthIssues,
				fmt.Sprintf("avg response %.0fms — slow UX", v))
		} else if v > 500 {
			inst.HealthScore -= 5
			inst.HealthIssues = append(inst.HealthIssues,
				fmt.Sprintf("avg response %.0fms — degraded", v))
		}
	}

	// 7. 5xx errors
	if v, _ := strconv.ParseInt(dm["req_status_500"], 10, 64); v > 0 {
		inst.HealthScore -= 10
		inst.HealthIssues = append(inst.HealthIssues,
			fmt.Sprintf("%d HTTP 500 responses — backend errors", v))
	}
	if v, _ := strconv.ParseInt(dm["req_status_503"], 10, 64); v > 0 {
		inst.HealthScore -= 10
		inst.HealthIssues = append(inst.HealthIssues,
			fmt.Sprintf("%d HTTP 503 responses — service unavailable", v))
	}

	// 8. Disconnects
	if v, _ := strconv.ParseInt(dm["requests_disconnects"], 10, 64); v > 10 {
		inst.HealthScore -= 5
		inst.HealthIssues = append(inst.HealthIssues,
			fmt.Sprintf("%d request disconnects — clients giving up", v))
	}
}

// ── HTTP ─────────────────────────────────────────────────────────────────

func kibanaGET(client *http.Client, url string) map[string]interface{} {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil
	}
	// Kibana requires this header for API access
	req.Header.Set("kbn-xsrf", "xtop")
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 2*1024*1024))
	if err != nil {
		return nil
	}
	var raw map[string]interface{}
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil
	}
	return raw
}
