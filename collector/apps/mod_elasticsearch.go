//go:build linux

package apps

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
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
	seen := make(map[int]bool)

	for _, p := range processes {
		if p.Comm != "java" {
			continue
		}

		// Skip if running inside a Docker container (cgroup contains docker/containerd)
		if isContainerized(p.PID) {
			continue
		}

		cmdline := readProcCmdline(p.PID)
		if !strings.Contains(cmdline, "elasticsearch") && !strings.Contains(cmdline, "org.elasticsearch") {
			continue
		}

		// Only detect the main ES process — skip child processes
		if p.PPID > 2 {
			parentCmdline := readProcCmdline(p.PPID)
			if strings.Contains(parentCmdline, "elasticsearch") || strings.Contains(parentCmdline, "org.elasticsearch") {
				continue
			}
		}

		port := 9200
		for _, field := range strings.Fields(cmdline) {
			if strings.HasPrefix(field, "-Ehttp.port=") {
				if p, err := strconv.Atoi(strings.TrimPrefix(field, "-Ehttp.port=")); err == nil {
					port = p
				}
			}
		}

		if seen[port] {
			continue
		}
		seen[port] = true

		apps = append(apps, DetectedApp{
			PID:     p.PID,
			Port:    port,
			Comm:    p.Comm,
			Cmdline: cmdline,
			Index:   len(apps),
		})
	}
	return apps
}

// isContainerized checks if a process runs inside a container.
// Uses multiple detection methods: cgroup path, PID namespace, /proc/1/environ.
func isContainerized(pid int) bool {
	// Method 1: cgroup path contains docker/containerd/lxc/kubepods
	if data, err := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", pid)); err == nil {
		s := string(data)
		if strings.Contains(s, "docker") || strings.Contains(s, "containerd") ||
			strings.Contains(s, "lxc") || strings.Contains(s, "kubepods") {
			return true
		}
	}

	// Method 2: PID namespace differs from init (PID 1)
	hostNS, err1 := os.Readlink("/proc/1/ns/pid")
	procNS, err2 := os.Readlink(fmt.Sprintf("/proc/%d/ns/pid", pid))
	if err1 == nil && err2 == nil && hostNS != procNS {
		return true
	}

	// Method 3: /proc/PID/mountinfo contains docker/overlay paths
	if data, err := os.ReadFile(fmt.Sprintf("/proc/%d/mountinfo", pid)); err == nil {
		s := string(data)
		if strings.Contains(s, "docker") || strings.Contains(s, "overlay") && strings.Contains(s, "containers") {
			return true
		}
	}

	return false
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

	inst.RSSMB = readProcRSS(app.PID)
	inst.Threads = readProcThreads(app.PID)
	inst.FDs = readProcFDs(app.PID)
	inst.Connections = countTCPConnections(app.Port)

	collectESMetrics(&inst, app.Port, secrets)

	return inst
}

// collectESMetrics fetches all ES REST API metrics. Exported for use by Docker module too.
func collectESMetrics(inst *model.AppInstance, port int, secrets *AppSecrets) {
	baseURL := fmt.Sprintf("http://127.0.0.1:%d", port)
	user := ""
	password := ""
	if secrets != nil && secrets.Elasticsearch != nil {
		if secrets.Elasticsearch.URL != "" {
			baseURL = strings.TrimRight(secrets.Elasticsearch.URL, "/")
		}
		user = secrets.Elasticsearch.User
		password = secrets.Elasticsearch.Password
	}

	client := esHTTPClient()

	// Try HTTP first, then HTTPS if HTTP fails
	root := esGet(client, baseURL+"/", user, password)
	if root == nil && strings.HasPrefix(baseURL, "http://") {
		httpsURL := "https://" + baseURL[7:]
		root = esGet(client, httpsURL+"/", user, password)
		if root != nil {
			baseURL = httpsURL
		}
	}

	// 1. Root — version
	if root != nil {
		if v, ok := root["version"].(map[string]interface{}); ok {
			if num, ok := v["number"].(string); ok {
				inst.Version = num
				inst.DeepMetrics["version"] = num
			}
			if luc, ok := v["lucene_version"].(string); ok {
				inst.DeepMetrics["lucene_version"] = luc
			}
		}
		if cn, ok := root["name"].(string); ok {
			inst.DeepMetrics["node_name"] = cn
		}
	}

	// 2. Cluster health
	if health := esGet(client, baseURL+"/_cluster/health", user, password); health != nil {
		inst.HasDeepMetrics = true
		for _, key := range []string{
			"status", "cluster_name", "number_of_nodes", "number_of_data_nodes",
			"active_primary_shards", "active_shards", "unassigned_shards",
			"relocating_shards", "initializing_shards", "delayed_unassigned_shards",
			"number_of_pending_tasks", "active_shards_percent_as_number",
		} {
			if v, ok := health[key]; ok {
				inst.DeepMetrics[key] = fmt.Sprintf("%v", v)
			}
		}
	}

	// 3. Cluster stats — indices, docs, store size, JVM
	if stats := esGet(client, baseURL+"/_cluster/stats", user, password); stats != nil {
		inst.HasDeepMetrics = true
		if indices, ok := stats["indices"].(map[string]interface{}); ok {
			if count, ok := indices["count"]; ok {
				inst.DeepMetrics["index_count"] = fmt.Sprintf("%v", count)
			}
			if docs, ok := indices["docs"].(map[string]interface{}); ok {
				if c, ok := docs["count"]; ok {
					inst.DeepMetrics["doc_count"] = fmtLargeNum(c)
				}
				if d, ok := docs["deleted"]; ok {
					inst.DeepMetrics["deleted_docs"] = fmtLargeNum(d)
				}
			}
			if store, ok := indices["store"].(map[string]interface{}); ok {
				if sb, ok := store["size_in_bytes"]; ok {
					inst.DeepMetrics["store_size"] = fmtBytes(sb)
				}
			}
			if segs, ok := indices["segments"].(map[string]interface{}); ok {
				if c, ok := segs["count"]; ok {
					inst.DeepMetrics["segment_count"] = fmt.Sprintf("%v", c)
				}
				if mem, ok := segs["memory_in_bytes"]; ok {
					inst.DeepMetrics["segment_memory"] = fmtBytes(mem)
				}
			}
			if fd, ok := indices["fielddata"].(map[string]interface{}); ok {
				if mem, ok := fd["memory_size_in_bytes"]; ok {
					inst.DeepMetrics["fielddata_memory"] = fmtBytes(mem)
				}
				if ev, ok := fd["evictions"]; ok {
					inst.DeepMetrics["fielddata_evictions"] = fmt.Sprintf("%v", ev)
				}
			}
			if qc, ok := indices["query_cache"].(map[string]interface{}); ok {
				if mem, ok := qc["memory_size_in_bytes"]; ok {
					inst.DeepMetrics["query_cache_memory"] = fmtBytes(mem)
				}
				if hits, ok := qc["hit_count"]; ok {
					inst.DeepMetrics["query_cache_hits"] = fmtLargeNum(hits)
				}
				if misses, ok := qc["miss_count"]; ok {
					inst.DeepMetrics["query_cache_misses"] = fmtLargeNum(misses)
				}
			}
		}
		if nodes, ok := stats["nodes"].(map[string]interface{}); ok {
			if jvm, ok := nodes["jvm"].(map[string]interface{}); ok {
				if mem, ok := jvm["mem"].(map[string]interface{}); ok {
					if heapUsed, ok := mem["heap_used_in_bytes"]; ok {
						inst.DeepMetrics["jvm_heap_used"] = fmtBytes(heapUsed)
					}
					if heapMax, ok := mem["heap_max_in_bytes"]; ok {
						inst.DeepMetrics["jvm_heap_max"] = fmtBytes(heapMax)
					}
				}
			}
		}
	}

	// 4. Node stats — GC, indexing, search throughput
	if nodeStats := esGet(client, baseURL+"/_nodes/stats/jvm,indices,os,http", user, password); nodeStats != nil {
		if nodes, ok := nodeStats["nodes"].(map[string]interface{}); ok {
			for _, nodeData := range nodes {
				nd, ok := nodeData.(map[string]interface{})
				if !ok {
					continue
				}
				// JVM GC
				if jvm, ok := nd["jvm"].(map[string]interface{}); ok {
					if gc, ok := jvm["gc"].(map[string]interface{}); ok {
						if collectors, ok := gc["collectors"].(map[string]interface{}); ok {
							for name, coll := range collectors {
								c, ok := coll.(map[string]interface{})
								if !ok {
									continue
								}
								prefix := "gc_" + name
								if count, ok := c["collection_count"]; ok {
									inst.DeepMetrics[prefix+"_count"] = fmt.Sprintf("%v", count)
								}
								if ms, ok := c["collection_time_in_millis"]; ok {
									inst.DeepMetrics[prefix+"_time_ms"] = fmt.Sprintf("%v", ms)
								}
							}
						}
					}
					if mem, ok := jvm["mem"].(map[string]interface{}); ok {
						if heapPct, ok := mem["heap_used_percent"]; ok {
							inst.DeepMetrics["jvm_heap_used_pct"] = fmt.Sprintf("%v%%", heapPct)
						}
					}
				}
				// Indexing & Search
				if indices, ok := nd["indices"].(map[string]interface{}); ok {
					if indexing, ok := indices["indexing"].(map[string]interface{}); ok {
						if total, ok := indexing["index_total"]; ok {
							inst.DeepMetrics["index_total"] = fmtLargeNum(total)
						}
						if ms, ok := indexing["index_time_in_millis"]; ok {
							inst.DeepMetrics["index_time_ms"] = fmt.Sprintf("%v", ms)
						}
					}
					if search, ok := indices["search"].(map[string]interface{}); ok {
						if total, ok := search["query_total"]; ok {
							inst.DeepMetrics["search_query_total"] = fmtLargeNum(total)
						}
						if ms, ok := search["query_time_in_millis"]; ok {
							inst.DeepMetrics["search_query_time_ms"] = fmt.Sprintf("%v", ms)
						}
					}
					if merges, ok := indices["merges"].(map[string]interface{}); ok {
						if total, ok := merges["total"]; ok {
							inst.DeepMetrics["merge_total"] = fmt.Sprintf("%v", total)
						}
					}
				}
				// OS CPU
				if osData, ok := nd["os"].(map[string]interface{}); ok {
					if cpu, ok := osData["cpu"].(map[string]interface{}); ok {
						if pct, ok := cpu["percent"]; ok {
							inst.DeepMetrics["os_cpu_pct"] = fmt.Sprintf("%v%%", pct)
						}
					}
				}
				// HTTP connections
				if httpData, ok := nd["http"].(map[string]interface{}); ok {
					if curr, ok := httpData["current_open"]; ok {
						inst.DeepMetrics["http_current_open"] = fmt.Sprintf("%v", curr)
					}
				}
				break // first node only
			}
		}
	}

	// 5. Index health summary
	if catData := esGetRaw(client, baseURL+"/_cat/indices?format=json&bytes=b&s=store.size:desc&h=index,health,status,pri,rep,docs.count,store.size", user, password); catData != nil {
		var indices []map[string]interface{}
		if err := json.Unmarshal(catData, &indices); err == nil {
			inst.DeepMetrics["total_indices"] = fmt.Sprintf("%d", len(indices))
			greenCount, yellowCount, redCount := 0, 0, 0
			for _, idx := range indices {
				switch fmt.Sprintf("%v", idx["health"]) {
				case "green":
					greenCount++
				case "yellow":
					yellowCount++
				case "red":
					redCount++
				}
			}
			inst.DeepMetrics["indices_green"] = fmt.Sprintf("%d", greenCount)
			inst.DeepMetrics["indices_yellow"] = fmt.Sprintf("%d", yellowCount)
			inst.DeepMetrics["indices_red"] = fmt.Sprintf("%d", redCount)
		}
	}

	// Health scoring
	inst.HealthScore = 100
	if inst.HasDeepMetrics {
		switch inst.DeepMetrics["status"] {
		case "red":
			inst.HealthScore -= 30
			inst.HealthIssues = append(inst.HealthIssues, "cluster status RED — data loss risk")
		case "yellow":
			inst.HealthScore -= 10
			inst.HealthIssues = append(inst.HealthIssues, "cluster status YELLOW — replicas unassigned")
		}
		if unassigned, _ := strconv.Atoi(inst.DeepMetrics["unassigned_shards"]); unassigned > 0 {
			inst.HealthIssues = append(inst.HealthIssues,
				fmt.Sprintf("%d unassigned shards", unassigned))
		}
		if pctStr := inst.DeepMetrics["jvm_heap_used_pct"]; pctStr != "" {
			pct, _ := strconv.ParseFloat(strings.TrimSuffix(pctStr, "%"), 64)
			if pct > 85 {
				inst.HealthScore -= 15
				inst.HealthIssues = append(inst.HealthIssues,
					fmt.Sprintf("JVM heap pressure: %s used", pctStr))
			}
		}
		if ev, _ := strconv.ParseInt(inst.DeepMetrics["fielddata_evictions"], 10, 64); ev > 100 {
			inst.HealthScore -= 10
			inst.HealthIssues = append(inst.HealthIssues,
				fmt.Sprintf("fielddata evictions: %d", ev))
		}
		if redCount, _ := strconv.Atoi(inst.DeepMetrics["indices_red"]); redCount > 0 {
			inst.HealthIssues = append(inst.HealthIssues,
				fmt.Sprintf("%d indices in RED state", redCount))
		}
	}
	if inst.HealthScore < 0 {
		inst.HealthScore = 0
	}
}

func esHTTPClient() *http.Client {
	return &http.Client{
		Timeout: 3 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
}

func esGet(client *http.Client, url, user, password string) map[string]interface{} {
	req, err := http.NewRequest("GET", url, nil)
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
	body, err := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
	if err != nil {
		return nil
	}
	var raw map[string]interface{}
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil
	}
	return raw
}

func esGetRaw(client *http.Client, url, user, password string) []byte {
	req, err := http.NewRequest("GET", url, nil)
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
	body, err := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
	if err != nil {
		return nil
	}
	return body
}

func fmtLargeNum(v interface{}) string {
	var f float64
	switch n := v.(type) {
	case float64:
		f = n
	case json.Number:
		f, _ = n.Float64()
	default:
		return fmt.Sprintf("%v", v)
	}
	switch {
	case f >= 1e9:
		return fmt.Sprintf("%.1fB", f/1e9)
	case f >= 1e6:
		return fmt.Sprintf("%.1fM", f/1e6)
	case f >= 1e3:
		return fmt.Sprintf("%.1fK", f/1e3)
	default:
		return fmt.Sprintf("%.0f", f)
	}
}

func fmtBytes(v interface{}) string {
	var f float64
	switch n := v.(type) {
	case float64:
		f = n
	case json.Number:
		f, _ = n.Float64()
	default:
		return fmt.Sprintf("%v", v)
	}
	switch {
	case f >= 1e12:
		return fmt.Sprintf("%.1f TB", f/1e12)
	case f >= 1e9:
		return fmt.Sprintf("%.1f GB", f/1e9)
	case f >= 1e6:
		return fmt.Sprintf("%.1f MB", f/1e6)
	case f >= 1e3:
		return fmt.Sprintf("%.1f KB", f/1e3)
	default:
		return fmt.Sprintf("%.0f B", f)
	}
}
