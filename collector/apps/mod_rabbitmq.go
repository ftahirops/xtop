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
	} else {
		inst.NeedsCreds = true
	}

	// Health scoring
	inst.HealthScore = 100
	if inst.HasDeepMetrics {
		if unacked, ok := overview["messages_unacked"]; ok {
			var v float64
			fmt.Sscanf(unacked, "%f", &v)
			if v > 10000 {
				inst.HealthScore -= 20
				inst.HealthIssues = append(inst.HealthIssues,
					fmt.Sprintf("%.0f unacked messages — consumers may be stuck", v))
			}
		}
	}
	if inst.HealthScore < 0 {
		inst.HealthScore = 0
	}

	return inst
}

// rabbitOverview fetches /api/overview from the RabbitMQ management plugin.
func rabbitOverview(host string, port int, user, password string) map[string]string {
	client := &http.Client{Timeout: 2 * time.Second}
	url := fmt.Sprintf("http://%s:%d/api/overview", host, port)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil
	}
	req.SetBasicAuth(user, password)

	resp, err := client.Do(req)
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

	var raw map[string]interface{}
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil
	}

	result := make(map[string]string)

	// Extract queue_totals
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

	// Extract message_stats for rates
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
	}

	// Version and cluster name
	if v, ok := raw["rabbitmq_version"]; ok {
		result["version"] = fmt.Sprintf("%v", v)
	}
	if v, ok := raw["cluster_name"]; ok {
		result["cluster_name"] = fmt.Sprintf("%v", v)
	}

	return result
}
