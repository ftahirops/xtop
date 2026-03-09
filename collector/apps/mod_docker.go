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
	"sync"
	"time"

	"github.com/ftahirops/xtop/model"
)

type dockerModule struct {
	client *http.Client
}

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

// initClient lazily initializes the shared HTTP client.
func (m *dockerModule) initClient() {
	if m.client == nil {
		m.client = &http.Client{
			Transport: &http.Transport{
				DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
					return net.Dial("unix", "/var/run/docker.sock")
				},
			},
			Timeout: 5 * time.Second,
		}
	}
}

// Close shuts down idle connections on the underlying transport.
func (m *dockerModule) Close() {
	if m.client != nil {
		if t, ok := m.client.Transport.(*http.Transport); ok {
			t.CloseIdleConnections()
		}
	}
}

func (m *dockerModule) Collect(app *DetectedApp, _ *AppSecrets) model.AppInstance {
	m.initClient()

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

	// Docker API: /info — daemon info
	info := dockerInfo(m.client)
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

	// Docker API: /system/df — disk usage (containers, images, volumes)
	if du := dockerGet(m.client, "http://localhost/system/df"); du != nil {
		// Images total size
		if imgs, ok := du["Images"].([]interface{}); ok {
			var totalSize, sharedSize float64
			for _, img := range imgs {
				if m, ok := img.(map[string]interface{}); ok {
					totalSize += toFloat(m["Size"])
					sharedSize += toFloat(m["SharedSize"])
				}
			}
			inst.DeepMetrics["images_total_size"] = dockerFmtBytes(totalSize)
			inst.DeepMetrics["images_shared_size"] = dockerFmtBytes(sharedSize)
		}
		// Volumes
		if vols, ok := du["Volumes"].([]interface{}); ok {
			var volSize float64
			for _, v := range vols {
				if m, ok := v.(map[string]interface{}); ok {
					volSize += toFloat(m["UsageData"].(map[string]interface{})["Size"])
				}
			}
			inst.DeepMetrics["volumes_count"] = fmt.Sprintf("%d", len(vols))
			inst.DeepMetrics["volumes_size"] = dockerFmtBytes(volSize)
		}
		// Build cache
		if bc, ok := du["BuildCache"].([]interface{}); ok {
			var bcSize float64
			for _, b := range bc {
				if m, ok := b.(map[string]interface{}); ok {
					bcSize += toFloat(m["Size"])
				}
			}
			inst.DeepMetrics["buildcache_size"] = dockerFmtBytes(bcSize)
		}
	}

	// Docker API: /networks — network count
	if nets := dockerGetList(m.client, "http://localhost/networks"); nets != nil {
		inst.DeepMetrics["networks_count"] = fmt.Sprintf("%d", len(nets))
	}

	// Docker API: /containers/json?all=true — container list
	containerList := dockerContainerList(m.client)
	inst.HealthScore = 100

	// Pre-process containers: parse basic info and identify running ones.
	type containerEntry struct {
		dc     model.AppDockerContainer
		fullID string
		idx    int
	}

	entries := make([]containerEntry, 0, len(containerList))
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
			}
		}

		fullID, _ := c["Id"].(string)
		entries = append(entries, containerEntry{dc: dc, fullID: fullID, idx: i})
	}

	// Collect stats for running containers in parallel.
	type statsResult struct {
		idx   int
		stats map[string]interface{}
	}

	var runningEntries []int
	for i, e := range entries {
		if e.dc.State == "running" && e.fullID != "" {
			runningEntries = append(runningEntries, i)
		}
	}

	results := make([]statsResult, len(runningEntries))
	sem := make(chan struct{}, 5) // concurrency cap
	var wg sync.WaitGroup

	for ri, ei := range runningEntries {
		wg.Add(1)
		go func(resultIdx, entryIdx int) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			stats := dockerContainerStatsCtx(ctx, m.client, entries[entryIdx].fullID)
			results[resultIdx] = statsResult{idx: entryIdx, stats: stats}
		}(ri, ei)
	}
	wg.Wait()

	// Apply stats results back to entries.
	for _, r := range results {
		if r.stats == nil {
			continue
		}
		dc := &entries[r.idx].dc
		stats := r.stats

		dc.CPUPct = dockerCalcCPU(stats)

		if memStats, ok := stats["memory_stats"].(map[string]interface{}); ok {
			dc.MemUsedBytes = toFloat(memStats["usage"])
			dc.MemLimitBytes = toFloat(memStats["limit"])
			if dc.MemLimitBytes > 0 && dc.MemLimitBytes < 1e18 {
				dc.MemPct = dc.MemUsedBytes / dc.MemLimitBytes * 100
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
			if ioEntries, ok := blkio["io_service_bytes_recursive"].([]interface{}); ok {
				for _, entry := range ioEntries {
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

	// Build final container list and compute health.
	for _, e := range entries {
		dc := e.dc
		if dc.Health == "unhealthy" {
			inst.HealthScore -= 10
			inst.HealthIssues = append(inst.HealthIssues,
				fmt.Sprintf("container '%s' is unhealthy", dc.Name))
		}
		if dc.State == "exited" && dc.ExitCode != 0 {
			inst.HealthScore -= 5
			inst.HealthIssues = append(inst.HealthIssues,
				fmt.Sprintf("container '%s' exited with code %d", dc.Name, dc.ExitCode))
		}
		if dc.MemPct > 90 {
			inst.HealthScore -= 5
			inst.HealthIssues = append(inst.HealthIssues,
				fmt.Sprintf("container '%s' memory at %.0f%%", dc.Name, dc.MemPct))
		}
		inst.Containers = append(inst.Containers, dc)
	}

	if inst.HealthScore < 0 {
		inst.HealthScore = 0
	}

	return inst
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

func dockerGetCtx(ctx context.Context, client *http.Client, path string) map[string]interface{} {
	req, err := http.NewRequestWithContext(ctx, "GET", "http://localhost"+path, nil)
	if err != nil {
		return nil
	}
	resp, err := client.Do(req)
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

// dockerGetList calls a Docker API endpoint that returns a JSON array.
func dockerGetList(client *http.Client, path string) []map[string]interface{} {
	resp, err := client.Get(path)
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
	var result []map[string]interface{}
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

// dockerContainerStatsCtx calls GET /containers/{id}/stats?stream=false with a context.
func dockerContainerStatsCtx(ctx context.Context, client *http.Client, id string) map[string]interface{} {
	return dockerGetCtx(ctx, client, fmt.Sprintf("/containers/%s/stats?stream=false", id))
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
