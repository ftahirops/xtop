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
	"sort"
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

	// Docker API: /info — daemon info + orchestration detection
	info := dockerInfo(m.client)
	orchType := "standalone"
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
		// Swarm detection
		if swarm, ok := info["Swarm"].(map[string]interface{}); ok {
			if state, _ := swarm["LocalNodeState"].(string); state == "active" {
				orchType = "swarm"
			}
		}
	}

	// Docker API: /system/df — disk usage
	rwSizes := map[string]int64{} // container ID → RW layer size
	if du := dockerGet(m.client, "/system/df"); du != nil {
		if imgs, ok := du["Images"].([]interface{}); ok {
			var totalSize, sharedSize float64
			var imgCount int
			for _, img := range imgs {
				im, ok := img.(map[string]interface{})
				if !ok {
					continue
				}
				totalSize += toFloat(im["Size"])
				sharedSize += toFloat(im["SharedSize"])
				if imgCount < 10 {
					tags, _ := im["RepoTags"].([]interface{})
					tag := "<none>"
					if len(tags) > 0 {
						tag = fmt.Sprintf("%v", tags[0])
					}
					inst.DeepMetrics[fmt.Sprintf("img_%d_name", imgCount)] = tag
					inst.DeepMetrics[fmt.Sprintf("img_%d_size", imgCount)] = dockerFmtBytes(toFloat(im["Size"]))
					inst.DeepMetrics[fmt.Sprintf("img_%d_containers", imgCount)] = fmt.Sprintf("%.0f", toFloat(im["Containers"]))
					imgCount++
				}
			}
			inst.DeepMetrics["images_count"] = fmt.Sprintf("%d", len(imgs))
			inst.DeepMetrics["images_total_size"] = dockerFmtBytes(totalSize)
			inst.DeepMetrics["images_reclaimable"] = dockerFmtBytes(totalSize - sharedSize)
		}
		if vols, ok := du["Volumes"].([]interface{}); ok {
			var volSize float64
			for _, v := range vols {
				vm, ok := v.(map[string]interface{})
				if !ok {
					continue
				}
				if ud, ok := vm["UsageData"].(map[string]interface{}); ok {
					volSize += toFloat(ud["Size"])
				}
			}
			inst.DeepMetrics["volumes_count"] = fmt.Sprintf("%d", len(vols))
			inst.DeepMetrics["volumes_size"] = dockerFmtBytes(volSize)
		}
		if bc, ok := du["BuildCache"].([]interface{}); ok {
			var bcSize float64
			for _, b := range bc {
				if bm, ok := b.(map[string]interface{}); ok {
					bcSize += toFloat(bm["Size"])
				}
			}
			inst.DeepMetrics["buildcache_count"] = fmt.Sprintf("%d", len(bc))
			inst.DeepMetrics["buildcache_size"] = dockerFmtBytes(bcSize)
		}
		if ctrs, ok := du["Containers"].([]interface{}); ok {
			var totalRw float64
			for _, c := range ctrs {
				cm, ok := c.(map[string]interface{})
				if !ok {
					continue
				}
				rw := toFloat(cm["SizeRw"])
				totalRw += rw
				if id, ok := cm["Id"].(string); ok {
					rwSizes[id] = int64(rw)
				}
			}
			inst.DeepMetrics["containers_rw_size"] = dockerFmtBytes(totalRw)
		}
	}

	// Docker API: /networks — network list with subnet info
	netSubnets := map[string]string{} // network name → subnet
	if nets := dockerGetList(m.client, "/networks"); nets != nil {
		inst.DeepMetrics["networks_count"] = fmt.Sprintf("%d", len(nets))
		for i, n := range nets {
			name, _ := n["Name"].(string)
			driver, _ := n["Driver"].(string)
			scope, _ := n["Scope"].(string)
			if i < 10 {
				inst.DeepMetrics[fmt.Sprintf("net_%d_name", i)] = name
				inst.DeepMetrics[fmt.Sprintf("net_%d_driver", i)] = driver
				inst.DeepMetrics[fmt.Sprintf("net_%d_scope", i)] = scope
			}
			// Extract subnet from IPAM config
			if ipam, ok := n["IPAM"].(map[string]interface{}); ok {
				if configs, ok := ipam["Config"].([]interface{}); ok {
					for _, cfg := range configs {
						if cm, ok := cfg.(map[string]interface{}); ok {
							if subnet, ok := cm["Subnet"].(string); ok {
								netSubnets[name] = subnet
							}
						}
					}
				}
			}
		}
	}

	// Docker API: /containers/json?all=true — container list
	containerList := dockerContainerList(m.client)
	inst.HealthScore = 100

	type containerEntry struct {
		dc     model.AppDockerContainer
		fullID string
	}

	entries := make([]containerEntry, 0, len(containerList))
	for i, c := range containerList {
		if i >= 50 {
			break
		}

		dc := model.AppDockerContainer{}
		fullID, _ := c["Id"].(string)

		if len(fullID) > 12 {
			dc.ID = fullID[:12]
		} else {
			dc.ID = fullID
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

		// Health from status string
		if strings.Contains(dc.Status, "(unhealthy)") {
			dc.Health = "unhealthy"
		} else if strings.Contains(dc.Status, "(healthy)") {
			dc.Health = "healthy"
		} else {
			dc.Health = "—"
		}

		if dc.State == "exited" {
			var code int
			if _, err := fmt.Sscanf(dc.Status, "Exited (%d)", &code); err == nil {
				dc.ExitCode = code
			}
		}

		// Labels from container list (available without inspect)
		if labels, ok := c["Labels"].(map[string]interface{}); ok {
			if proj, ok := labels["com.docker.compose.project"].(string); ok {
				dc.StackName = proj
				dc.StackType = "compose"
			}
			if _, ok := labels["io.kubernetes.pod.name"].(string); ok {
				dc.StackType = "k8s"
				if ns, ok := labels["io.kubernetes.pod.namespace"].(string); ok {
					dc.StackName = ns
				}
			}
		}
		if dc.StackName == "" {
			dc.StackName = "standalone"
			dc.StackType = "standalone"
		}

		// RW layer size from /system/df
		if rw, ok := rwSizes[fullID]; ok {
			dc.RWLayerSize = rw
		}

		entries = append(entries, containerEntry{dc: dc, fullID: fullID})
	}

	// Parallel: inspect + stats for all containers (inspect is cheap, stats only for running)
	type enrichResult struct {
		idx     int
		inspect map[string]interface{}
		stats   map[string]interface{}
	}

	results := make([]enrichResult, len(entries))
	sem := make(chan struct{}, 5)
	var wg sync.WaitGroup

	for i, e := range entries {
		wg.Add(1)
		go func(idx int, entry containerEntry) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()

			r := enrichResult{idx: idx}
			// Always inspect (lightweight)
			r.inspect = dockerGetCtx(ctx, m.client, fmt.Sprintf("/containers/%s/json", entry.fullID))
			// Stats only for running containers
			if entry.dc.State == "running" {
				r.stats = dockerContainerStatsCtx(ctx, m.client, entry.fullID)
			}
			results[idx] = r
		}(i, e)
	}
	wg.Wait()

	// Apply results
	for _, r := range results {
		dc := &entries[r.idx].dc

		// Apply inspect data
		if insp := r.inspect; insp != nil {
			parseContainerInspect(dc, insp)
		}

		// Apply stats data
		if stats := r.stats; stats != nil {
			applyContainerStats(dc, stats)
		}
	}

	// Group containers into stacks and compute health
	stackMap := map[string]*model.DockerStack{}
	for _, e := range entries {
		dc := e.dc
		key := dc.StackName
		st, ok := stackMap[key]
		if !ok {
			st = &model.DockerStack{
				Name:        key,
				Type:        dc.StackType,
				HealthScore: 100,
			}
			stackMap[key] = st
		}

		// Container-level health penalties
		penalties, issues := containerHealthCheck(&dc)
		st.HealthScore -= penalties
		st.Issues = append(st.Issues, issues...)

		// Global health penalties
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

		st.Containers = append(st.Containers, dc)
		inst.Containers = append(inst.Containers, dc)
	}

	// Finalize stacks
	for _, st := range stackMap {
		if st.HealthScore < 0 {
			st.HealthScore = 0
		}
		// Get compose working dir from first container with it
		for _, c := range st.Containers {
			if c.StackType == "compose" {
				// Working dir comes from inspect labels
				st.WorkingDir = c.Command // will be overridden below
				break
			}
		}
		// Collect unique networks
		netSeen := map[string]bool{}
		for _, c := range st.Containers {
			for _, n := range c.Networks {
				if !netSeen[n.Name] {
					netSeen[n.Name] = true
					sn := model.DockerStackNetwork{Name: n.Name}
					if subnet, ok := netSubnets[n.Name]; ok {
						sn.Subnet = subnet
					}
					st.Networks = append(st.Networks, sn)
				}
			}
		}
		inst.Stacks = append(inst.Stacks, *st)
	}

	// Sort stacks: compose first, then standalone
	sort.Slice(inst.Stacks, func(i, j int) bool {
		if inst.Stacks[i].Type != inst.Stacks[j].Type {
			return inst.Stacks[i].Type < inst.Stacks[j].Type
		}
		return inst.Stacks[i].Name < inst.Stacks[j].Name
	})

	// Determine orchestration type
	hasCompose, hasSwarm, hasK8s, hasStandalone := false, false, false, false
	for _, st := range inst.Stacks {
		switch st.Type {
		case "compose":
			hasCompose = true
		case "swarm":
			hasSwarm = true
		case "k8s":
			hasK8s = true
		case "standalone":
			hasStandalone = true
		}
	}
	if orchType == "swarm" {
		inst.OrchestrationType = "swarm"
	} else if hasK8s {
		inst.OrchestrationType = "k8s"
	} else if hasCompose && hasStandalone {
		inst.OrchestrationType = "mixed"
	} else if hasCompose {
		inst.OrchestrationType = "compose"
	} else {
		inst.OrchestrationType = "standalone"
	}
	_ = hasSwarm // used in orchType above

	if inst.HealthScore < 0 {
		inst.HealthScore = 0
	}

	return inst
}

// parseContainerInspect extracts diagnostic fields from /containers/{id}/json.
func parseContainerInspect(dc *model.AppDockerContainer, insp map[string]interface{}) {
	// Labels → compose working dir
	if config, ok := insp["Config"].(map[string]interface{}); ok {
		if labels, ok := config["Labels"].(map[string]interface{}); ok {
			if wd, ok := labels["com.docker.compose.project.working_dir"].(string); ok && dc.StackType == "compose" {
				dc.Command = wd // temporarily store working dir in Command, will be used by stack
			}
			if cf, ok := labels["com.docker.compose.project.config_files"].(string); ok && dc.StackType == "compose" {
				dc.Entrypoint = cf // temporarily store compose file
			}
		}
		if user, ok := config["User"].(string); ok {
			dc.User = user
		}
		// Health check configured?
		if hc, ok := config["Healthcheck"].(map[string]interface{}); ok {
			if test, ok := hc["Test"].([]interface{}); ok && len(test) > 0 {
				dc.HasHealthChk = true
			}
		}
	}

	// HostConfig — restart policy, privileged, resource limits
	if hc, ok := insp["HostConfig"].(map[string]interface{}); ok {
		if rp, ok := hc["RestartPolicy"].(map[string]interface{}); ok {
			if name, ok := rp["Name"].(string); ok {
				dc.RestartPolicy = name
			}
		}
		if priv, ok := hc["Privileged"].(bool); ok {
			dc.Privileged = priv
		}
		// Memory limit
		if memLimit := toFloat(hc["Memory"]); memLimit > 0 {
			dc.MemLimit = uint64(memLimit)
		}
		// CPU quota → cores
		cpuQuota := toFloat(hc["CpuQuota"])
		cpuPeriod := toFloat(hc["CpuPeriod"])
		if cpuQuota > 0 && cpuPeriod > 0 {
			dc.CPUQuota = cpuQuota / cpuPeriod
		}
		// NanoCPUs (alternative to quota/period)
		if nano := toFloat(hc["NanoCpus"]); nano > 0 {
			dc.CPUQuota = nano / 1e9
		}
	}

	// State — restart count, created
	if state, ok := insp["State"].(map[string]interface{}); ok {
		// Restart count not in State, but the container inspect top-level has it
		_ = state
	}
	if rc := toFloat(insp["RestartCount"]); rc > 0 {
		dc.RestartCount = int(rc)
	}
	if created, ok := insp["Created"].(string); ok {
		dc.CreatedAt = created
	}

	// Mounts
	if mounts, ok := insp["Mounts"].([]interface{}); ok {
		for _, mt := range mounts {
			mm, ok := mt.(map[string]interface{})
			if !ok {
				continue
			}
			dm := model.DockerMount{
				Type:   strVal(mm, "Type"),
				Source: strVal(mm, "Source"),
				Target: strVal(mm, "Destination"),
			}
			if rw, ok := mm["RW"].(bool); ok {
				dm.ReadOnly = !rw
			}
			dc.Mounts = append(dc.Mounts, dm)
		}
	}

	// NetworkSettings — per-network IPs
	if ns, ok := insp["NetworkSettings"].(map[string]interface{}); ok {
		if nets, ok := ns["Networks"].(map[string]interface{}); ok {
			for name, netData := range nets {
				nd, ok := netData.(map[string]interface{})
				if !ok {
					continue
				}
				dc.Networks = append(dc.Networks, model.DockerContainerNet{
					Name:    name,
					IP:      strVal(nd, "IPAddress"),
					Gateway: strVal(nd, "Gateway"),
				})
			}
		}
		// Ports
		if ports, ok := ns["Ports"].(map[string]interface{}); ok {
			for portProto, bindings := range ports {
				parts := strings.SplitN(portProto, "/", 2)
				containerPort := 0
				proto := "tcp"
				if len(parts) >= 1 {
					fmt.Sscanf(parts[0], "%d", &containerPort)
				}
				if len(parts) >= 2 {
					proto = parts[1]
				}
				if bindArr, ok := bindings.([]interface{}); ok {
					for _, b := range bindArr {
						bm, ok := b.(map[string]interface{})
						if !ok {
							continue
						}
						hostPort := 0
						if hp, ok := bm["HostPort"].(string); ok {
							fmt.Sscanf(hp, "%d", &hostPort)
						}
						dc.Ports = append(dc.Ports, model.DockerPort{
							ContainerPort: containerPort,
							HostPort:      hostPort,
							HostIP:        strVal(bm, "HostIp"),
							Protocol:      proto,
						})
					}
				}
			}
		}
	}

	// Fix: move compose file info to proper fields
	if dc.StackType == "compose" {
		// Command was temporarily holding working dir, Entrypoint holding compose file
		wd := dc.Command
		cf := dc.Entrypoint
		dc.Command = ""
		dc.Entrypoint = ""
		// Store in a way the stack builder can access
		if wd != "" {
			dc.Command = wd // working dir
		}
		if cf != "" {
			dc.Entrypoint = cf // compose file path
		}
	}
}

// applyContainerStats applies stats from /containers/{id}/stats to the container.
func applyContainerStats(dc *model.AppDockerContainer, stats map[string]interface{}) {
	dc.CPUPct = dockerCalcCPU(stats)

	if memStats, ok := stats["memory_stats"].(map[string]interface{}); ok {
		dc.MemUsedBytes = toFloat(memStats["usage"])
		dc.MemLimitBytes = toFloat(memStats["limit"])
		if dc.MemLimitBytes > 0 && dc.MemLimitBytes < 1e18 {
			dc.MemPct = dc.MemUsedBytes / dc.MemLimitBytes * 100
		}
	}

	if networks, ok := stats["networks"].(map[string]interface{}); ok {
		for _, iface := range networks {
			if nd, ok := iface.(map[string]interface{}); ok {
				dc.NetRxBytes += toFloat(nd["rx_bytes"])
				dc.NetTxBytes += toFloat(nd["tx_bytes"])
			}
		}
	}

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

	if pidStats, ok := stats["pids_stats"].(map[string]interface{}); ok {
		dc.PIDs = int(toFloat(pidStats["current"]))
	}
}

// containerHealthCheck returns health penalties and issue strings for a container.
func containerHealthCheck(dc *model.AppDockerContainer) (int, []string) {
	var penalty int
	var issues []string

	if dc.Health == "unhealthy" {
		penalty += 15
		issues = append(issues, fmt.Sprintf("'%s' is unhealthy", dc.Name))
	}
	if dc.RestartCount > 3 {
		penalty += 15
		issues = append(issues, fmt.Sprintf("'%s' crash loop (%d restarts)", dc.Name, dc.RestartCount))
	}
	if dc.State == "exited" && dc.ExitCode != 0 {
		penalty += 5
		issues = append(issues, fmt.Sprintf("'%s' exited with code %d", dc.Name, dc.ExitCode))
	}
	// Memory near limit
	if dc.MemLimit > 0 && dc.MemUsedBytes > 0 {
		pct := dc.MemUsedBytes / float64(dc.MemLimit) * 100
		if pct > 90 {
			penalty += 10
			issues = append(issues, fmt.Sprintf("'%s' memory at %.0f%% of limit", dc.Name, pct))
		} else if pct > 80 {
			penalty += 5
			issues = append(issues, fmt.Sprintf("'%s' memory at %.0f%% of limit", dc.Name, pct))
		}
	}
	// CPU near limit
	if dc.CPUQuota > 0 && dc.CPUPct > dc.CPUQuota*80 {
		penalty += 5
		issues = append(issues, fmt.Sprintf("'%s' CPU %.1f%% near limit (%.1f cores)", dc.Name, dc.CPUPct, dc.CPUQuota))
	}
	if dc.CPUPct > 80 {
		penalty += 10
		issues = append(issues, fmt.Sprintf("'%s' high CPU %.1f%%", dc.Name, dc.CPUPct))
	}
	// No restart policy
	if dc.RestartPolicy == "" || dc.RestartPolicy == "no" {
		if dc.State == "running" {
			penalty += 2
			issues = append(issues, fmt.Sprintf("'%s' no restart policy", dc.Name))
		}
	}
	// Privileged
	if dc.Privileged {
		penalty += 3
		issues = append(issues, fmt.Sprintf("'%s' running privileged", dc.Name))
	}
	// Large writable layer
	if dc.RWLayerSize > 1<<30 { // > 1GB
		penalty += 3
		issues = append(issues, fmt.Sprintf("'%s' writable layer %s", dc.Name, dockerFmtBytes(float64(dc.RWLayerSize))))
	}
	// No health check
	if !dc.HasHealthChk && dc.State == "running" {
		// Info-level, low penalty
		penalty += 1
		issues = append(issues, fmt.Sprintf("'%s' no health check configured", dc.Name))
	}

	return penalty, issues
}

func strVal(m map[string]interface{}, key string) string {
	if v, ok := m[key].(string); ok {
		return v
	}
	return ""
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

func dockerInfo(client *http.Client) map[string]interface{} {
	return dockerGet(client, "/info")
}

func dockerGetList(client *http.Client, path string) []map[string]interface{} {
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
	var result []map[string]interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil
	}
	return result
}

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

func dockerContainerStatsCtx(ctx context.Context, client *http.Client, id string) map[string]interface{} {
	return dockerGetCtx(ctx, client, fmt.Sprintf("/containers/%s/stats?stream=false", id))
}

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
