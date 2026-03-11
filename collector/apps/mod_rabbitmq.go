//go:build linux

package apps

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/ftahirops/xtop/model"
)

type rabbitmqModule struct{}

func NewRabbitMQModule() AppModule { return &rabbitmqModule{} }

func (m *rabbitmqModule) Type() string        { return "rabbitmq" }
func (m *rabbitmqModule) DisplayName() string { return "RabbitMQ" }

func (m *rabbitmqModule) Detect(processes []model.ProcessMetrics) []DetectedApp {
	var apps []DetectedApp
	for _, p := range processes {
		if p.Comm != "beam.smp" {
			continue
		}
		cmdline := readProcCmdline(p.PID)
		if !strings.Contains(cmdline, "rabbit") {
			continue
		}
		apps = append(apps, DetectedApp{
			PID:     p.PID,
			Port:    5672,
			Comm:    p.Comm,
			Cmdline: cmdline,
			Index:   len(apps),
		})
	}
	return apps
}

func (m *rabbitmqModule) Collect(app *DetectedApp, secrets *AppSecrets) model.AppInstance {
	inst := model.AppInstance{
		AppType:     "rabbitmq",
		DisplayName: "RabbitMQ",
		PID:         app.PID,
		Port:        app.Port,
		Status:      "active",
		UptimeSec:   readProcUptime(app.PID),
		DeepMetrics: make(map[string]string),
	}

	// Tier 1: process metrics
	inst.RSSMB = readProcRSS(app.PID)
	inst.Threads = readProcThreads(app.PID)
	inst.Connections = countTCPConnections(app.Port)
	inst.CPUPct = readProcCPUPct(app.PID, inst.UptimeSec)

	// Tier 2: management API
	host := "127.0.0.1"
	mgmtPort := 15672
	user := "guest"
	password := "guest"
	if secrets != nil && secrets.RabbitMQ != nil {
		if secrets.RabbitMQ.Host != "" {
			host = secrets.RabbitMQ.Host
		}
		if secrets.RabbitMQ.Port > 0 {
			mgmtPort = secrets.RabbitMQ.Port
		}
		if secrets.RabbitMQ.User != "" {
			user = secrets.RabbitMQ.User
		}
		if secrets.RabbitMQ.Password != "" {
			password = secrets.RabbitMQ.Password
		}
	}

	overview := rabbitOverview(host, mgmtPort, user, password)
	if overview != nil {
		inst.HasDeepMetrics = true
		for k, v := range overview {
			inst.DeepMetrics[k] = v
		}

		// Fetch node metrics
		nodes := rabbitNodes(host, mgmtPort, user, password)
		if len(nodes) > 0 {
			for k, v := range nodes[0] {
				inst.DeepMetrics[k] = v
			}
		}

		// Fetch queue summary
		queueStats := rabbitQueues(host, mgmtPort, user, password)
		for k, v := range queueStats {
			inst.DeepMetrics[k] = v
		}
	} else {
		inst.NeedsCreds = true
	}

	// Health scoring
	inst.HealthScore = 100
	if inst.HasDeepMetrics {
		dm := inst.DeepMetrics

		// Unacked messages
		if v := parseMetricFloat(dm, "messages_unacked"); v > 10000 {
			inst.HealthScore -= 20
			inst.HealthIssues = append(inst.HealthIssues,
				fmt.Sprintf("%.0f unacked messages — consumers may be stuck", v))
		} else if v > 1000 {
			inst.HealthScore -= 10
			inst.HealthIssues = append(inst.HealthIssues,
				fmt.Sprintf("%.0f unacked messages — consumers falling behind", v))
		}

		// Messages ready backlog
		if v := parseMetricFloat(dm, "messages_ready"); v > 100000 {
			inst.HealthScore -= 15
			inst.HealthIssues = append(inst.HealthIssues,
				fmt.Sprintf("%.0f messages ready — large message backlog", v))
		} else if v > 10000 {
			inst.HealthScore -= 10
			inst.HealthIssues = append(inst.HealthIssues,
				fmt.Sprintf("%.0f messages ready — growing backlog", v))
		}

		// Memory alarm
		if dm["mem_alarm"] == "true" {
			inst.HealthScore -= 25
			inst.HealthIssues = append(inst.HealthIssues,
				"memory alarm triggered — node may block publishers")
		} else if v := parseMetricFloat(dm, "mem_usage_pct"); v > 80 {
			inst.HealthScore -= 10
			inst.HealthIssues = append(inst.HealthIssues,
				fmt.Sprintf("memory usage %.1f%% — approaching alarm threshold", v))
		}

		// Disk alarm
		if dm["disk_alarm"] == "true" {
			inst.HealthScore -= 25
			inst.HealthIssues = append(inst.HealthIssues,
				"disk alarm — node blocking publishers")
		}

		// FD usage
		if v := parseMetricFloat(dm, "fd_usage_pct"); v > 80 {
			inst.HealthScore -= 10
			inst.HealthIssues = append(inst.HealthIssues,
				fmt.Sprintf("file descriptor usage %.1f%% — risk of connection refusal", v))
		}

		// Socket usage
		if v := parseMetricFloat(dm, "socket_usage_pct"); v > 80 {
			inst.HealthScore -= 10
			inst.HealthIssues = append(inst.HealthIssues,
				fmt.Sprintf("socket usage %.1f%% — may reject new connections", v))
		}

		// Erlang process usage
		if v := parseMetricFloat(dm, "proc_usage_pct"); v > 80 {
			inst.HealthScore -= 10
			inst.HealthIssues = append(inst.HealthIssues,
				fmt.Sprintf("Erlang process usage %.1f%% — node under pressure", v))
		}

		// Idle queues (no consumers)
		if v := parseMetricFloat(dm, "queues_idle"); v > 5 {
			inst.HealthScore -= 5
			inst.HealthIssues = append(inst.HealthIssues,
				fmt.Sprintf("%.0f queues have no consumers", v))
		}

		// Return unroutable
		if v := parseMetricFloat(dm, "return_unroutable"); v > 0 {
			inst.HealthScore -= 5
			inst.HealthIssues = append(inst.HealthIssues,
				"messages being returned — check routing")
		}

		// Redeliver rate
		if v := parseMetricFloat(dm, "redeliver_rate"); v > 10 {
			inst.HealthScore -= 5
			inst.HealthIssues = append(inst.HealthIssues,
				fmt.Sprintf("high redeliver rate (%.1f/s) — consumers may be failing", v))
		}
	}

	if inst.HealthScore < 0 {
		inst.HealthScore = 0
	}
	if inst.HealthScore > 100 {
		inst.HealthScore = 100
	}

	return inst
}

// parseMetricFloat extracts a float64 from deep metrics, returning 0 on missing/error.
func parseMetricFloat(dm map[string]string, key string) float64 {
	s, ok := dm[key]
	if !ok || s == "" {
		return 0
	}
	var v float64
	fmt.Sscanf(s, "%f", &v)
	return v
}

// ---------------- API helpers ----------------

func rabbitAPIGet(host string, port int, user, password, path string) (map[string]interface{}, error) {
	client := &http.Client{Timeout: 2 * time.Second}
	url := fmt.Sprintf("http://%s:%d%s", host, port, path)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.SetBasicAuth(user, password)

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
	if err != nil {
		return nil, err
	}

	var raw map[string]interface{}
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, err
	}
	return raw, nil
}

func rabbitAPIGetList(host string, port int, user, password, path string) ([]interface{}, error) {
	client := &http.Client{Timeout: 2 * time.Second}
	url := fmt.Sprintf("http://%s:%d%s", host, port, path)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.SetBasicAuth(user, password)

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
	if err != nil {
		return nil, err
	}

	var raw []interface{}
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, err
	}
	return raw, nil
}

// ---------------- /api/overview ----------------

func rabbitOverview(host string, port int, user, password string) map[string]string {
	raw, err := rabbitAPIGet(host, port, user, password, "/api/overview")
	if err != nil {
		return nil
	}

	result := make(map[string]string)

	// Queue totals
	if qt, ok := raw["queue_totals"].(map[string]interface{}); ok {
		if v, ok := qt["messages_ready"]; ok {
			result["messages_ready"] = fmt.Sprintf("%v", v)
		}
		if v, ok := qt["messages_unacknowledged"]; ok {
			result["messages_unacked"] = fmt.Sprintf("%v", v)
		}
		if v, ok := qt["messages"]; ok {
			result["messages_total"] = fmt.Sprintf("%v", v)
		}
	}

	// Message stats
	if ms, ok := raw["message_stats"].(map[string]interface{}); ok {
		if v, ok := ms["publish"]; ok {
			result["publish_total"] = fmt.Sprintf("%v", v)
		}
		if det, ok := ms["publish_details"].(map[string]interface{}); ok {
			if r, ok := det["rate"]; ok {
				result["publish_rate"] = fmt.Sprintf("%v", r)
			}
		}
		if v, ok := ms["deliver_get"]; ok {
			result["deliver_total"] = fmt.Sprintf("%v", v)
		}
		if det, ok := ms["deliver_get_details"].(map[string]interface{}); ok {
			if r, ok := det["rate"]; ok {
				result["deliver_rate"] = fmt.Sprintf("%v", r)
			}
		}
		if v, ok := ms["ack"]; ok {
			result["ack_total"] = fmt.Sprintf("%v", v)
		}
		if det, ok := ms["ack_details"].(map[string]interface{}); ok {
			if r, ok := det["rate"]; ok {
				result["ack_rate"] = fmt.Sprintf("%v", r)
			}
		}
		if v, ok := ms["confirm"]; ok {
			result["confirm_total"] = fmt.Sprintf("%v", v)
		}
		if det, ok := ms["confirm_details"].(map[string]interface{}); ok {
			if r, ok := det["rate"]; ok {
				result["confirm_rate"] = fmt.Sprintf("%v", r)
			}
		}
		if v, ok := ms["return_unroutable"]; ok {
			result["return_unroutable"] = fmt.Sprintf("%v", v)
		}
		if det, ok := ms["return_unroutable_details"].(map[string]interface{}); ok {
			if r, ok := det["rate"]; ok {
				result["return_unroutable_rate"] = fmt.Sprintf("%v", r)
			}
		}
		if v, ok := ms["redeliver"]; ok {
			result["redeliver_total"] = fmt.Sprintf("%v", v)
		}
		if det, ok := ms["redeliver_details"].(map[string]interface{}); ok {
			if r, ok := det["rate"]; ok {
				result["redeliver_rate"] = fmt.Sprintf("%v", r)
			}
		}
	}

	// Object totals
	if ot, ok := raw["object_totals"].(map[string]interface{}); ok {
		if v, ok := ot["connections"]; ok {
			result["connections"] = fmt.Sprintf("%v", v)
		}
		if v, ok := ot["channels"]; ok {
			result["channels"] = fmt.Sprintf("%v", v)
		}
		if v, ok := ot["queues"]; ok {
			result["queues"] = fmt.Sprintf("%v", v)
		}
		if v, ok := ot["exchanges"]; ok {
			result["exchanges"] = fmt.Sprintf("%v", v)
		}
		if v, ok := ot["consumers"]; ok {
			result["consumers"] = fmt.Sprintf("%v", v)
		}
	}

	// Version, cluster, node, erlang
	if v, ok := raw["rabbitmq_version"]; ok {
		result["version"] = fmt.Sprintf("%v", v)
	}
	if v, ok := raw["cluster_name"]; ok {
		result["cluster_name"] = fmt.Sprintf("%v", v)
	}
	if v, ok := raw["node"]; ok {
		result["node"] = fmt.Sprintf("%v", v)
	}
	if v, ok := raw["erlang_version"]; ok {
		result["erlang_version"] = fmt.Sprintf("%v", v)
	}

	// Listeners count
	if ls, ok := raw["listeners"].([]interface{}); ok {
		result["listeners"] = fmt.Sprintf("%d", len(ls))
	}

	return result
}

// ---------------- /api/nodes ----------------

func rabbitNodes(host string, port int, user, password string) []map[string]string {
	raw, err := rabbitAPIGetList(host, port, user, password, "/api/nodes")
	if err != nil {
		return nil
	}

	var nodes []map[string]string
	for _, item := range raw {
		node, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		m := make(map[string]string)

		if v, ok := node["name"]; ok {
			m["node_name"] = fmt.Sprintf("%v", v)
		}
		if v, ok := node["type"]; ok {
			m["node_type"] = fmt.Sprintf("%v", v)
		}
		if v, ok := node["running"]; ok {
			m["node_running"] = fmt.Sprintf("%v", v)
		}
		if v, ok := node["uptime"]; ok {
			m["node_uptime"] = fmt.Sprintf("%v", v)
		}

		// Memory
		memUsed := jsonFloat(node, "mem_used")
		memLimit := jsonFloat(node, "mem_limit")
		m["mem_used_mb"] = fmt.Sprintf("%.1f", memUsed/1048576)
		m["mem_limit_mb"] = fmt.Sprintf("%.1f", memLimit/1048576)
		if memLimit > 0 {
			m["mem_usage_pct"] = fmt.Sprintf("%.1f", memUsed/memLimit*100)
		}
		if v, ok := node["mem_alarm"]; ok {
			m["mem_alarm"] = fmt.Sprintf("%v", v)
		}

		// Disk
		diskFree := jsonFloat(node, "disk_free")
		diskLimit := jsonFloat(node, "disk_free_limit")
		m["disk_free_mb"] = fmt.Sprintf("%.1f", diskFree/1048576)
		m["disk_free_limit_mb"] = fmt.Sprintf("%.1f", diskLimit/1048576)
		if v, ok := node["disk_free_alarm"]; ok {
			m["disk_alarm"] = fmt.Sprintf("%v", v)
		}

		// File descriptors
		fdUsed := jsonFloat(node, "fd_used")
		fdTotal := jsonFloat(node, "fd_total")
		m["fd_used"] = fmt.Sprintf("%.0f", fdUsed)
		m["fd_total"] = fmt.Sprintf("%.0f", fdTotal)
		if fdTotal > 0 {
			m["fd_usage_pct"] = fmt.Sprintf("%.1f", fdUsed/fdTotal*100)
		}

		// Sockets
		sockUsed := jsonFloat(node, "sockets_used")
		sockTotal := jsonFloat(node, "sockets_total")
		m["sockets_used"] = fmt.Sprintf("%.0f", sockUsed)
		m["sockets_total"] = fmt.Sprintf("%.0f", sockTotal)
		if sockTotal > 0 {
			m["socket_usage_pct"] = fmt.Sprintf("%.1f", sockUsed/sockTotal*100)
		}

		// Erlang processes
		procUsed := jsonFloat(node, "proc_used")
		procTotal := jsonFloat(node, "proc_total")
		m["proc_used"] = fmt.Sprintf("%.0f", procUsed)
		m["proc_total"] = fmt.Sprintf("%.0f", procTotal)
		if procTotal > 0 {
			m["proc_usage_pct"] = fmt.Sprintf("%.1f", procUsed/procTotal*100)
		}

		// GC
		if v, ok := node["gc_num"]; ok {
			m["gc_num"] = fmt.Sprintf("%v", v)
		}
		if v, ok := node["gc_bytes_reclaimed"]; ok {
			m["gc_bytes_reclaimed"] = fmt.Sprintf("%v", v)
		}

		// IO
		ioRead := jsonFloat(node, "io_read_bytes")
		ioWrite := jsonFloat(node, "io_write_bytes")
		m["io_read_mb"] = fmt.Sprintf("%.1f", ioRead/1048576)
		m["io_write_mb"] = fmt.Sprintf("%.1f", ioWrite/1048576)
		if v, ok := node["io_read_avg_time"]; ok {
			m["io_read_avg_time"] = fmt.Sprintf("%v", v)
		}
		if v, ok := node["io_write_avg_time"]; ok {
			m["io_write_avg_time"] = fmt.Sprintf("%v", v)
		}

		nodes = append(nodes, m)
	}
	return nodes
}

// ---------------- /api/queues ----------------

func rabbitQueues(host string, port int, user, password string) map[string]string {
	raw, err := rabbitAPIGetList(host, port, user, password, "/api/queues")
	if err != nil {
		return nil
	}

	result := make(map[string]string)
	total := len(raw)
	idle := 0
	backlogged := 0
	topName := ""
	topMsgs := 0.0
	notRunning := 0

	for _, item := range raw {
		q, ok := item.(map[string]interface{})
		if !ok {
			continue
		}

		consumers := jsonFloat(q, "consumers")
		if consumers == 0 {
			idle++
		}

		msgs := jsonFloat(q, "messages")
		if msgs > 1000 {
			backlogged++
		}
		if msgs > topMsgs {
			topMsgs = msgs
			if v, ok := q["name"].(string); ok {
				topName = v
			}
		}

		if state, ok := q["state"].(string); ok && state != "running" {
			notRunning++
		}
	}

	result["queues_total"] = fmt.Sprintf("%d", total)
	result["queues_idle"] = fmt.Sprintf("%d", idle)
	result["queues_backlogged"] = fmt.Sprintf("%d", backlogged)
	result["queues_not_running"] = fmt.Sprintf("%d", notRunning)
	if topName != "" {
		result["top_queue_name"] = topName
		result["top_queue_messages"] = fmt.Sprintf("%.0f", topMsgs)
	}

	return result
}

// jsonFloat extracts a numeric value from a JSON map, returning 0 on failure.
func jsonFloat(m map[string]interface{}, key string) float64 {
	v, ok := m[key]
	if !ok {
		return 0
	}
	switch n := v.(type) {
	case float64:
		return n
	case int:
		return float64(n)
	case int64:
		return float64(n)
	default:
		var f float64
		fmt.Sscanf(fmt.Sprintf("%v", v), "%f", &f)
		return f
	}
}
