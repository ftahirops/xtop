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

	inst.RSSMB = readProcRSS(app.PID)
	inst.Threads = readProcThreads(app.PID)
	inst.FDs = readProcFDs(app.PID)

	client := dockerClient()

	// Docker API: /info
	info := dockerInfo(client)
	if info != nil {
		inst.HasDeepMetrics = true
		if v, ok := info["ServerVersion"]; ok {
			inst.Version = fmt.Sprintf("%v", v)
		}
		if v, ok := info["Containers"]; ok {
			inst.DeepMetrics["Total Containers"] = fmt.Sprintf("%.0f", toFloat(v))
		}
		if v, ok := info["ContainersRunning"]; ok {
			inst.DeepMetrics["Running"] = fmt.Sprintf("%.0f", toFloat(v))
		}
		if v, ok := info["ContainersStopped"]; ok {
			inst.DeepMetrics["Stopped"] = fmt.Sprintf("%.0f", toFloat(v))
		}
		if v, ok := info["ContainersPaused"]; ok {
			inst.DeepMetrics["Paused"] = fmt.Sprintf("%.0f", toFloat(v))
		}
		if v, ok := info["Images"]; ok {
			inst.DeepMetrics["Images"] = fmt.Sprintf("%.0f", toFloat(v))
		}
		if v, ok := info["Driver"].(string); ok {
			inst.DeepMetrics["Storage Driver"] = v
		}
		if v, ok := info["CgroupDriver"].(string); ok {
			inst.DeepMetrics["Cgroup Driver"] = v
		}
	}

	// Container list
	containers := dockerContainerList(client)
	inst.HealthScore = 100

	running := 0
	unhealthy := 0
	crashed := 0

	for i, c := range containers {
		if i >= 30 {
			break
		}

		name := ""
		if names, ok := c["Names"].([]interface{}); ok && len(names) > 0 {
			name = strings.TrimPrefix(fmt.Sprintf("%v", names[0]), "/")
		}

		state, _ := c["State"].(string)
		status, _ := c["Status"].(string)

		if state == "running" {
			running++
		}

		// Container health check
		if strings.Contains(status, "(unhealthy)") {
			unhealthy++
			inst.HealthScore -= 10
			inst.HealthIssues = append(inst.HealthIssues,
				fmt.Sprintf("container '%s' is unhealthy", name))
		}

		// Crashed containers (non-zero exit)
		if state == "exited" && strings.Contains(status, "Exited (") {
			var code int
			if _, err := fmt.Sscanf(status, "Exited (%d)", &code); err == nil && code != 0 {
				crashed++
				inst.HealthScore -= 5
				inst.HealthIssues = append(inst.HealthIssues,
					fmt.Sprintf("container '%s' exited with code %d", name, code))
			}
		}

		// Per-container stats for running containers
		if state == "running" {
			if id, ok := c["Id"].(string); ok {
				stats := dockerContainerStats(client, id)
				if stats != nil {
					cpuPct := dockerCalcCPU(stats)
					memUsed := 0.0
					memLimit := 0.0
					if memStats, ok := stats["memory_stats"].(map[string]interface{}); ok {
						memUsed = toFloat(memStats["usage"])
						memLimit = toFloat(memStats["limit"])
					}

					memStr := dockerFmtBytes(memUsed)
					if memLimit > 0 && memLimit < 1e18 { // reasonable limit (not unlimited)
						memStr += " / " + dockerFmtBytes(memLimit)
						pct := memUsed / memLimit * 100
						memStr += fmt.Sprintf(" (%.0f%%)", pct)
						if pct > 90 {
							inst.HealthIssues = append(inst.HealthIssues,
								fmt.Sprintf("container '%s' memory at %.0f%%", name, pct))
							inst.HealthScore -= 5
						}
					}

					label := fmt.Sprintf("[%s]", name)
					inst.DeepMetrics[label+" CPU"] = fmt.Sprintf("%.1f%%", cpuPct)
					inst.DeepMetrics[label+" Memory"] = memStr
					inst.DeepMetrics[label+" Status"] = status
				}
			}
		} else {
			label := fmt.Sprintf("[%s]", name)
			inst.DeepMetrics[label+" Status"] = status
		}
	}

	if unhealthy > 0 {
		inst.DeepMetrics["Unhealthy Containers"] = fmt.Sprintf("%d", unhealthy)
	}
	if crashed > 0 {
		inst.DeepMetrics["Crashed Containers"] = fmt.Sprintf("%d", crashed)
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
		Timeout: 10 * time.Second,
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

// toFloat converts a JSON number to float64 safely.
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

// dockerFmtBytes formats byte values to human-readable.
func dockerFmtBytes(b float64) string {
	switch {
	case b >= 1e12:
		return fmt.Sprintf("%.1f TB", b/1e12)
	case b >= 1e9:
		return fmt.Sprintf("%.1f GB", b/1e9)
	case b >= 1e6:
		return fmt.Sprintf("%.1f MB", b/1e6)
	case b >= 1e3:
		return fmt.Sprintf("%.1f KB", b/1e3)
	default:
		return fmt.Sprintf("%.0f B", b)
	}
}
