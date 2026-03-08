//go:build linux

package apps

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/ftahirops/xtop/model"
)

type esModule struct{}

func NewESModule() AppModule { return &esModule{} }

func (m *esModule) Type() string        { return "elasticsearch" }
func (m *esModule) DisplayName() string { return "Elasticsearch" }

func (m *esModule) Detect(processes []model.ProcessMetrics) []DetectedApp {
	var apps []DetectedApp
	for _, p := range processes {
		if p.Comm != "java" {
			continue
		}
		cmdline := readProcCmdline(p.PID)
		if !strings.Contains(cmdline, "elasticsearch") && !strings.Contains(cmdline, "org.elasticsearch") {
			continue
		}
		apps = append(apps, DetectedApp{
			PID:     p.PID,
			Port:    9200,
			Comm:    p.Comm,
			Cmdline: cmdline,
			Index:   len(apps),
		})
	}
	return apps
}

func (m *esModule) Collect(app *DetectedApp, secrets *AppSecrets) model.AppInstance {
	inst := model.AppInstance{
		AppType:     "elasticsearch",
		DisplayName: "Elasticsearch",
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

	// Tier 2: cluster health via HTTP
	baseURL := fmt.Sprintf("http://127.0.0.1:%d", app.Port)
	user := ""
	password := ""
	if secrets != nil && secrets.Elasticsearch != nil {
		if secrets.Elasticsearch.URL != "" {
			baseURL = strings.TrimRight(secrets.Elasticsearch.URL, "/")
		}
		user = secrets.Elasticsearch.User
		password = secrets.Elasticsearch.Password
	}

	health := esClusterHealth(baseURL, user, password)
	if health != nil {
		inst.HasDeepMetrics = true
		for k, v := range health {
			inst.DeepMetrics[k] = v
		}
	}

	// Health scoring
	inst.HealthScore = 100
	if inst.HasDeepMetrics {
		switch inst.DeepMetrics["status"] {
		case "red":
			inst.HealthScore -= 20
			inst.HealthIssues = append(inst.HealthIssues, "cluster status RED — data loss or unavailability")
		case "yellow":
			inst.HealthScore -= 10
			inst.HealthIssues = append(inst.HealthIssues, "cluster status YELLOW — replica shards unassigned")
		}
		if unassigned, _ := strconv.Atoi(inst.DeepMetrics["unassigned_shards"]); unassigned > 0 {
			inst.HealthIssues = append(inst.HealthIssues,
				fmt.Sprintf("%d unassigned shards", unassigned))
		}
	}
	if inst.HealthScore < 0 {
		inst.HealthScore = 0
	}

	return inst
}

// esClusterHealth fetches /_cluster/health and returns selected fields.
func esClusterHealth(baseURL, user, password string) map[string]string {
	client := &http.Client{Timeout: 2 * time.Second}
	req, err := http.NewRequest("GET", baseURL+"/_cluster/health", nil)
	if err != nil {
		return nil
	}
	if user != "" {
		req.SetBasicAuth(user, password)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return nil
	}

	var raw map[string]interface{}
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil
	}

	result := make(map[string]string)
	for _, key := range []string{
		"status", "cluster_name", "number_of_nodes", "number_of_data_nodes",
		"active_primary_shards", "active_shards", "unassigned_shards",
		"relocating_shards", "initializing_shards",
	} {
		if v, ok := raw[key]; ok {
			result[key] = fmt.Sprintf("%v", v)
		}
	}
	return result
}
