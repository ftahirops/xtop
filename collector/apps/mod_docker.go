//go:build linux

package apps

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/ftahirops/xtop/model"
)

type dockerModule struct{}

func NewDockerModule() AppModule { return &dockerModule{} }

func (m *dockerModule) Type() string        { return "docker" }
func (m *dockerModule) DisplayName() string { return "Docker" }

func (m *dockerModule) Detect(processes []model.ProcessMetrics) []DetectedApp {
	var apps []DetectedApp
	for _, p := range processes {
		if p.Comm != "dockerd" {
			continue
		}
		if _, err := os.Stat("/var/run/docker.sock"); err != nil {
			continue
		}
		apps = append(apps, DetectedApp{
			PID:     p.PID,
			Port:    0,
			Comm:    p.Comm,
			Cmdline: readProcCmdline(p.PID),
			Index:   len(apps),
		})
	}
	return apps
}

func (m *dockerModule) Collect(app *DetectedApp, _ *AppSecrets) model.AppInstance {
	inst := model.AppInstance{
		AppType:     "docker",
		DisplayName: "Docker",
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

	client := dockerClient()

	// Tier 2: Docker API via unix socket
	info := dockerInfo(client)
	if info != nil {
		inst.HasDeepMetrics = true
		if v, ok := info["ServerVersion"]; ok {
			inst.Version = fmt.Sprintf("%v", v)
			inst.DeepMetrics["version"] = inst.Version
		}
		for _, key := range []string{"Containers", "ContainersRunning", "ContainersStopped", "Images"} {
			if v, ok := info[key]; ok {
				short := strings.ToLower(strings.TrimPrefix(key, "Containers"))
				if short == "" {
					short = "container_count"
				}
				inst.DeepMetrics[short] = fmt.Sprintf("%.0f", toFloat(v))
			}
		}
	}

	// Fetch container list
	containers := dockerContainerList(client)
	inst.DeepMetrics["container_list_count"] = fmt.Sprintf("%d", len(containers))

	inst.HealthScore = 100
	for i, c := range containers {
		if i >= 50 {
			break // cap to avoid huge metric maps
		}
		prefix := fmt.Sprintf("c_%d_", i)

		name := ""
		if names, ok := c["Names"].([]interface{}); ok && len(names) > 0 {
			name = fmt.Sprintf("%v", names[0])
			name = strings.TrimPrefix(name, "/")
		}
		inst.DeepMetrics[prefix+"name"] = name

		state := ""
		if v, ok := c["State"].(string); ok {
			state = v
		}
		inst.DeepMetrics[prefix+"state"] = state

		status := ""
		if v, ok := c["Status"].(string); ok {
			status = v
		}
		inst.DeepMetrics[prefix+"status"] = status

		// Health from container inspect if available
		health := ""
		if v, ok := c["Status"].(string); ok {
			if strings.Contains(v, "(unhealthy)") {
				health = "unhealthy"
				inst.HealthScore -= 10
				inst.HealthIssues = append(inst.HealthIssues,
					fmt.Sprintf("container %s is unhealthy", name))
			} else if strings.Contains(v, "(healthy)") {
				health = "healthy"
			}
		}
		inst.DeepMetrics[prefix+"health"] = health

		// Flag non-zero exit codes
		if state == "exited" && strings.Contains(status, "Exited (") {
			// Parse exit code from "Exited (N) ..."
			var code int
			if _, err := fmt.Sscanf(status, "Exited (%d)", &code); err == nil && code != 0 {
				inst.HealthScore -= 5
				inst.HealthIssues = append(inst.HealthIssues,
					fmt.Sprintf("container %s exited with code %d", name, code))
			}
		}

		// Fetch per-container CPU/memory stats for running containers
		if state == "running" {
			if id, ok := c["Id"].(string); ok {
				stats := dockerContainerStats(client, id)
				if stats != nil {
					cpuPct := dockerCalcCPU(stats)
					inst.DeepMetrics[prefix+"cpu_pct"] = fmt.Sprintf("%.1f", cpuPct)

					if memStats, ok := stats["memory_stats"].(map[string]interface{}); ok {
						if usage, ok := memStats["usage"]; ok {
							inst.DeepMetrics[prefix+"mem_bytes"] = fmt.Sprintf("%.0f", toFloat(usage))
						}
						if limit, ok := memStats["limit"]; ok {
							inst.DeepMetrics[prefix+"mem_limit"] = fmt.Sprintf("%.0f", toFloat(limit))
						}
					}
				}
			}
		}
	}

	if inst.HealthScore < 0 {
		inst.HealthScore = 0
	}

	return inst
}

// dockerClient creates an HTTP client that talks over the Docker unix socket.
func dockerClient() *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return net.Dial("unix", "/var/run/docker.sock")
			},
		},
		Timeout: 5 * time.Second,
	}
}

// dockerInfo calls GET /info on the Docker API.
func dockerInfo(client *http.Client) map[string]interface{} {
	resp, err := client.Get("http://localhost/info")
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
	var result map[string]interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil
	}
	return result
}

// dockerContainerList calls GET /containers/json?all=true.
func dockerContainerList(client *http.Client) []map[string]interface{} {
	resp, err := client.Get("http://localhost/containers/json?all=true")
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
	if err != nil {
		return nil
	}
	var result []map[string]interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil
	}
	return result
}

// dockerContainerStats calls GET /containers/{id}/stats?stream=false.
func dockerContainerStats(client *http.Client, id string) map[string]interface{} {
	resp, err := client.Get(fmt.Sprintf("http://localhost/containers/%s/stats?stream=false", id))
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
	var result map[string]interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil
	}
	return result
}

// dockerCalcCPU calculates CPU% from Docker stats response.
func dockerCalcCPU(stats map[string]interface{}) float64 {
	cpuStats, ok := stats["cpu_stats"].(map[string]interface{})
	if !ok {
		return 0
	}
	preCPUStats, ok := stats["precpu_stats"].(map[string]interface{})
	if !ok {
		return 0
	}

	cpuUsage, ok := cpuStats["cpu_usage"].(map[string]interface{})
	if !ok {
		return 0
	}
	preCPUUsage, ok := preCPUStats["cpu_usage"].(map[string]interface{})
	if !ok {
		return 0
	}

	cpuDelta := toFloat(cpuUsage["total_usage"]) - toFloat(preCPUUsage["total_usage"])
	sysDelta := toFloat(cpuStats["system_cpu_usage"]) - toFloat(preCPUStats["system_cpu_usage"])

	if sysDelta <= 0 || cpuDelta < 0 {
		return 0
	}

	numCPU := 1.0
	if online, ok := cpuStats["online_cpus"]; ok {
		if v := toFloat(online); v > 0 {
			numCPU = v
		}
	}

	return (cpuDelta / sysDelta) * numCPU * 100.0
}

// toFloat converts a JSON number (float64) to float64 safely.
func toFloat(v interface{}) float64 {
	switch n := v.(type) {
	case float64:
		return n
	case int:
		return float64(n)
	case int64:
		return float64(n)
	}
	return 0
}
