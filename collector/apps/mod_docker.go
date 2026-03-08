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

	// Docker API: /info — daemon info
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
		if v, ok := info["KernelVersion"].(string); ok {
			inst.DeepMetrics["Kernel"] = v
		}
		if v, ok := info["OperatingSystem"].(string); ok {
			inst.DeepMetrics["OS"] = v
		}
		if v, ok := info["NCPU"]; ok {
			inst.DeepMetrics["CPUs"] = fmt.Sprintf("%.0f", toFloat(v))
		}
		if v, ok := info["MemTotal"]; ok {
			inst.DeepMetrics["Total Memory"] = dockerFmtBytes(toFloat(v))
		}
	}

	// Docker API: /containers/json?all=true — container list
	containerList := dockerContainerList(client)
	inst.HealthScore = 100

	for i, c := range containerList {
		if i >= 50 {
			break
		}

		dc := model.AppDockerContainer{}

		if id, ok := c["Id"].(string); ok {
			dc.ID = id
			if len(dc.ID) > 12 {
				dc.ID = dc.ID[:12]
			}
		}
		if names, ok := c["Names"].([]interface{}); ok && len(names) > 0 {
			dc.Name = strings.TrimPrefix(fmt.Sprintf("%v", names[0]), "/")
		}
		if img, ok := c["Image"].(string); ok {
			dc.Image = img
		}
		if state, ok := c["State"].(string); ok {
			dc.State = state
		}
		if status, ok := c["Status"].(string); ok {
			dc.Status = status
		}

		// Health check
		if strings.Contains(dc.Status, "(unhealthy)") {
			dc.Health = "unhealthy"
			inst.HealthScore -= 10
			inst.HealthIssues = append(inst.HealthIssues,
				fmt.Sprintf("container '%s' is unhealthy", dc.Name))
		} else if strings.Contains(dc.Status, "(healthy)") {
			dc.Health = "healthy"
		} else {
			dc.Health = "—"
		}

		// Crashed containers
		if dc.State == "exited" {
			var code int
			if _, err := fmt.Sscanf(dc.Status, "Exited (%d)", &code); err == nil {
				dc.ExitCode = code
				if code != 0 {
					inst.HealthScore -= 5
					inst.HealthIssues = append(inst.HealthIssues,
						fmt.Sprintf("container '%s' exited with code %d", dc.Name, code))
				}
			}
		}

		// Per-container stats (running only)
		if dc.State == "running" {
			if fullID, ok := c["Id"].(string); ok {
				stats := dockerContainerStats(client, fullID)
				if stats != nil {
					dc.CPUPct = dockerCalcCPU(stats)

					if memStats, ok := stats["memory_stats"].(map[string]interface{}); ok {
						dc.MemUsedBytes = toFloat(memStats["usage"])
						dc.MemLimitBytes = toFloat(memStats["limit"])
						if dc.MemLimitBytes > 0 && dc.MemLimitBytes < 1e18 {
							dc.MemPct = dc.MemUsedBytes / dc.MemLimitBytes * 100
						}
						if dc.MemPct > 90 {
							inst.HealthScore -= 5
							inst.HealthIssues = append(inst.HealthIssues,
								fmt.Sprintf("container '%s' memory at %.0f%%", dc.Name, dc.MemPct))
						}
					}

					// Network I/O
					if networks, ok := stats["networks"].(map[string]interface{}); ok {
						for _, iface := range networks {
							if nd, ok := iface.(map[string]interface{}); ok {
								dc.NetRxBytes += toFloat(nd["rx_bytes"])
								dc.NetTxBytes += toFloat(nd["tx_bytes"])
							}
						}
					}

					// Block I/O
					if blkio, ok := stats["blkio_stats"].(map[string]interface{}); ok {
						if entries, ok := blkio["io_service_bytes_recursive"].([]interface{}); ok {
							for _, entry := range entries {
								e, ok := entry.(map[string]interface{})
								if !ok {
									continue
								}
								op, _ := e["op"].(string)
								val := toFloat(e["value"])
								switch strings.ToLower(op) {
								case "read":
									dc.BlockRead += val
								case "write":
									dc.BlockWrite += val
								}
							}
						}
					}

					// PIDs
					if pidStats, ok := stats["pids_stats"].(map[string]interface{}); ok {
						dc.PIDs = int(toFloat(pidStats["current"]))
					}
				}
			}
		}

		// Restart count from container inspect
		if fullID, ok := c["Id"].(string); ok {
			if inspect := dockerInspect(client, fullID); inspect != nil {
				if state, ok := inspect["State"].(map[string]interface{}); ok {
					if rc, ok := state["RestartCount"]; ok {
						dc.RestartCount = int(toFloat(rc))
					}
				}
				if rc, ok := inspect["RestartCount"]; ok {
					dc.RestartCount = int(toFloat(rc))
				}
			}
		}

		inst.Containers = append(inst.Containers, dc)
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
		Timeout: 15 * time.Second,
	}
}

func dockerGet(client *http.Client, path string) map[string]interface{} {
	resp, err := client.Get("http://localhost" + path)
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
	var result map[string]interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil
	}
	return result
}

// dockerInfo calls GET /info on the Docker API.
func dockerInfo(client *http.Client) map[string]interface{} {
	return dockerGet(client, "/info")
}

// dockerInspect calls GET /containers/{id}/json.
func dockerInspect(client *http.Client, id string) map[string]interface{} {
	return dockerGet(client, fmt.Sprintf("/containers/%s/json", id))
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
	return dockerGet(client, fmt.Sprintf("/containers/%s/stats?stream=false", id))
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
