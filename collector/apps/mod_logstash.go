//go:build linux

package apps

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/ftahirops/xtop/model"
)

// Logstash module — talks to the Logstash Node Stats API (default port 9600).
// Endpoint reference: https://www.elastic.co/guide/en/logstash/current/node-stats-api.html

type logstashModule struct {
	client *http.Client
	prev   map[int]logstashPrev
}

type logstashPrev struct {
	events struct {
		in   int64
		out  int64
		flt  int64
	}
	at time.Time
}

func NewLogstashModule() AppModule {
	return &logstashModule{
		client: &http.Client{
			Timeout:   5 * time.Second,
			Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
		},
		prev: make(map[int]logstashPrev),
	}
}

func (m *logstashModule) Close() {
	if m.client != nil {
		m.client.CloseIdleConnections()
	}
}

func (m *logstashModule) Type() string        { return "logstash" }
func (m *logstashModule) DisplayName() string { return "Logstash" }

func (m *logstashModule) Detect(processes []model.ProcessMetrics) []DetectedApp {
	var out []DetectedApp
	seen := make(map[int]bool)
	for _, p := range processes {
		if p.Comm != "java" {
			continue
		}
		if isContainerized(p.PID) {
			continue
		}
		cmdline := readProcCmdline(p.PID)
		if !strings.Contains(cmdline, "org.logstash.Logstash") && !strings.Contains(cmdline, "logstash") {
			continue
		}
		// Skip if parent is logstash (child worker)
		if p.PPID > 2 {
			pc := readProcCmdline(p.PPID)
			if strings.Contains(pc, "org.logstash.Logstash") {
				continue
			}
		}

		port := 9600
		// Logstash has --http.port config — extract if present
		for _, f := range strings.Fields(cmdline) {
			if strings.HasPrefix(f, "--http.port=") {
				if v, err := strconv.Atoi(strings.TrimPrefix(f, "--http.port=")); err == nil {
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

func (m *logstashModule) Collect(app *DetectedApp, secrets *AppSecrets) model.AppInstance {
	inst := model.AppInstance{
		AppType:     "logstash",
		DisplayName: "Logstash",
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

	// Tier 2 — query Node Stats API. If not reachable, skip gracefully.
	baseURL := fmt.Sprintf("http://127.0.0.1:%d", app.Port)
	nodeStats := logstashGET(m.client, baseURL+"/_node/stats")
	if nodeStats == nil {
		// try HTTPS
		baseURL = fmt.Sprintf("https://127.0.0.1:%d", app.Port)
		nodeStats = logstashGET(m.client, baseURL+"/_node/stats")
	}
	if nodeStats != nil {
		inst.HasDeepMetrics = true
		m.populateLogstashMetrics(&inst, nodeStats)
		// Pipeline overview (per-pipeline view)
		if raw := logstashGET(m.client, baseURL+"/_node/pipelines"); raw != nil {
			m.populateLogstashPipelines(&inst, raw)
		}
	}

	// Health scoring
	inst.HealthScore = 100
	logstashHealthRules(&inst)
	if inst.HealthScore < 0 {
		inst.HealthScore = 0
	}
	if inst.HealthScore > 100 {
		inst.HealthScore = 100
	}
	return inst
}

// populateLogstashMetrics extracts core metrics from /_node/stats response.
func (m *logstashModule) populateLogstashMetrics(inst *model.AppInstance, stats map[string]interface{}) {
	dm := inst.DeepMetrics

	if ver, ok := stats["version"].(string); ok {
		inst.Version = ver
		dm["version"] = ver
	}
	if host, ok := stats["host"].(string); ok {
		dm["host"] = host
	}
	if nameStr, ok := stats["name"].(string); ok {
		dm["node_name"] = nameStr
	}
	if status, ok := stats["status"].(string); ok {
		dm["status"] = status
	}

	// JVM heap
	if jvm, ok := stats["jvm"].(map[string]interface{}); ok {
		if mem, ok := jvm["mem"].(map[string]interface{}); ok {
			heapUsed := parseJSONFloat(mem["heap_used_in_bytes"])
			heapMax := parseJSONFloat(mem["heap_max_in_bytes"])
			heapPct := parseJSONFloat(mem["heap_used_percent"])
			dm["jvm_heap_used"] = fmtBytes(heapUsed)
			dm["jvm_heap_max"] = fmtBytes(heapMax)
			if heapPct > 0 {
				dm["jvm_heap_used_pct"] = fmt.Sprintf("%.0f", heapPct)
			} else if heapMax > 0 {
				dm["jvm_heap_used_pct"] = fmt.Sprintf("%.0f", heapUsed/heapMax*100)
			}
		}
		if gc, ok := jvm["gc"].(map[string]interface{}); ok {
			if collectors, ok := gc["collectors"].(map[string]interface{}); ok {
				for name, coll := range collectors {
					c, ok := coll.(map[string]interface{})
					if !ok {
						continue
					}
					prefix := "gc_" + sanitizeKey(name)
					dm[prefix+"_count"] = fmt.Sprintf("%d", parseJSONInt(c["collection_count"]))
					dm[prefix+"_time_ms"] = fmt.Sprintf("%d", parseJSONInt(c["collection_time_in_millis"]))
				}
			}
		}
		if up, ok := jvm["uptime_in_millis"]; ok {
			dm["jvm_uptime_ms"] = fmt.Sprintf("%d", parseJSONInt(up))
		}
	}

	// Process
	if proc, ok := stats["process"].(map[string]interface{}); ok {
		if cpu, ok := proc["cpu"].(map[string]interface{}); ok {
			if p := parseJSONFloat(cpu["percent"]); p > 0 {
				dm["process_cpu_pct"] = fmt.Sprintf("%.0f", p)
			}
			if l, ok := cpu["load_average"].(map[string]interface{}); ok {
				if v := parseJSONFloat(l["1m"]); v > 0 {
					dm["load_avg_1m"] = fmt.Sprintf("%.2f", v)
				}
			}
		}
		if fd := parseJSONInt(proc["open_file_descriptors"]); fd > 0 {
			dm["open_fds"] = fmt.Sprintf("%d", fd)
		}
		if peak := parseJSONInt(proc["peak_open_file_descriptors"]); peak > 0 {
			dm["peak_open_fds"] = fmt.Sprintf("%d", peak)
		}
		if max := parseJSONInt(proc["max_file_descriptors"]); max > 0 {
			dm["max_fds"] = fmt.Sprintf("%d", max)
		}
	}

	// Events (top-level aggregated)
	if ev, ok := stats["events"].(map[string]interface{}); ok {
		in := parseJSONInt(ev["in"])
		out := parseJSONInt(ev["out"])
		flt := parseJSONInt(ev["filtered"])
		dm["events_in"] = fmt.Sprintf("%d", in)
		dm["events_out"] = fmt.Sprintf("%d", out)
		dm["events_filtered"] = fmt.Sprintf("%d", flt)
		if dur := parseJSONInt(ev["duration_in_millis"]); dur > 0 {
			dm["events_duration_ms"] = fmt.Sprintf("%d", dur)
		}
		if qpp := parseJSONInt(ev["queue_push_duration_in_millis"]); qpp > 0 {
			dm["events_queue_push_ms"] = fmt.Sprintf("%d", qpp)
		}

		// Delta-based rates
		now := time.Now()
		prev := m.prev[inst.PID]
		if !prev.at.IsZero() {
			elapsed := now.Sub(prev.at).Seconds()
			if elapsed >= 1 {
				dIn := float64(in-prev.events.in) / elapsed
				dOut := float64(out-prev.events.out) / elapsed
				dFlt := float64(flt-prev.events.flt) / elapsed
				if dIn < 0 {
					dIn = 0
				}
				if dOut < 0 {
					dOut = 0
				}
				if dFlt < 0 {
					dFlt = 0
				}
				dm["events_in_per_sec"] = fmt.Sprintf("%.1f", dIn)
				dm["events_out_per_sec"] = fmt.Sprintf("%.1f", dOut)
				dm["events_filtered_per_sec"] = fmt.Sprintf("%.1f", dFlt)
			}
		}
		m.prev[inst.PID] = logstashPrev{
			at: now,
			events: struct {
				in  int64
				out int64
				flt int64
			}{in: in, out: out, flt: flt},
		}
	}

	// Reloads
	if rl, ok := stats["reloads"].(map[string]interface{}); ok {
		dm["reload_successes"] = fmt.Sprintf("%d", parseJSONInt(rl["successes"]))
		dm["reload_failures"] = fmt.Sprintf("%d", parseJSONInt(rl["failures"]))
	}

	// Pipelines — aggregated
	if pipelines, ok := stats["pipelines"].(map[string]interface{}); ok {
		pCount := 0
		var pipeNames []string
		totalQueueEvents := int64(0)
		totalQueueMaxBytes := int64(0)
		totalQueueCurBytes := int64(0)
		totalDLQEvents := int64(0)
		slowestFilterMs := 0.0
		slowestFilterName := ""

		for pname, pval := range pipelines {
			pCount++
			pipeNames = append(pipeNames, pname)
			pipe, ok := pval.(map[string]interface{})
			if !ok {
				continue
			}
			pipePrefix := "pipe_" + sanitizeKey(pname) + "_"

			// events per pipeline
			if e, ok := pipe["events"].(map[string]interface{}); ok {
				dm[pipePrefix+"events_in"] = fmt.Sprintf("%d", parseJSONInt(e["in"]))
				dm[pipePrefix+"events_out"] = fmt.Sprintf("%d", parseJSONInt(e["out"]))
				dm[pipePrefix+"events_filtered"] = fmt.Sprintf("%d", parseJSONInt(e["filtered"]))
			}

			// queue
			if q, ok := pipe["queue"].(map[string]interface{}); ok {
				if t, ok := q["type"].(string); ok {
					dm[pipePrefix+"queue_type"] = t
				}
				qEvents := parseJSONInt(q["events_count"])
				qMax := parseJSONInt(q["max_queue_size_in_bytes"])
				qCur := parseJSONInt(q["queue_size_in_bytes"])
				dm[pipePrefix+"queue_events"] = fmt.Sprintf("%d", qEvents)
				dm[pipePrefix+"queue_size"] = fmtBytes(float64(qCur))
				dm[pipePrefix+"queue_max"] = fmtBytes(float64(qMax))
				if qMax > 0 {
					dm[pipePrefix+"queue_pct"] = fmt.Sprintf("%.1f", float64(qCur)/float64(qMax)*100)
				}
				totalQueueEvents += qEvents
				totalQueueMaxBytes += qMax
				totalQueueCurBytes += qCur
			}

			// DLQ
			if dlq, ok := pipe["dead_letter_queue"].(map[string]interface{}); ok {
				dlqEvents := parseJSONInt(dlq["queue_size_in_bytes"])
				dlqCount := parseJSONInt(dlq["dropped_events"])
				dm[pipePrefix+"dlq_size"] = fmtBytes(float64(dlqEvents))
				dm[pipePrefix+"dlq_dropped"] = fmt.Sprintf("%d", dlqCount)
				totalDLQEvents += dlqCount
			}

			// Slowest filter
			if plugins, ok := pipe["plugins"].(map[string]interface{}); ok {
				if filters, ok := plugins["filters"].([]interface{}); ok {
					type fEntry struct {
						id   string
						name string
						ms   float64
					}
					var list []fEntry
					for _, f := range filters {
						fm, ok := f.(map[string]interface{})
						if !ok {
							continue
						}
						ev, _ := fm["events"].(map[string]interface{})
						dur := parseJSONFloat(ev["duration_in_millis"])
						cnt := parseJSONFloat(ev["out"])
						id, _ := fm["id"].(string)
						name, _ := fm["name"].(string)
						avg := 0.0
						if cnt > 0 {
							avg = dur / cnt
						}
						list = append(list, fEntry{id: id, name: name, ms: avg})
					}
					sort.Slice(list, func(i, j int) bool { return list[i].ms > list[j].ms })
					topN := len(list)
					if topN > 3 {
						topN = 3
					}
					for i := 0; i < topN; i++ {
						dm[pipePrefix+fmt.Sprintf("slowfilter_%d_name", i)] = list[i].name
						dm[pipePrefix+fmt.Sprintf("slowfilter_%d_id", i)] = list[i].id
						dm[pipePrefix+fmt.Sprintf("slowfilter_%d_avg_ms", i)] = fmt.Sprintf("%.3f", list[i].ms)
						if list[i].ms > slowestFilterMs {
							slowestFilterMs = list[i].ms
							slowestFilterName = list[i].name
						}
					}
				}
			}
		}
		dm["pipeline_count"] = fmt.Sprintf("%d", pCount)
		sort.Strings(pipeNames)
		if len(pipeNames) > 10 {
			pipeNames = pipeNames[:10]
		}
		dm["pipeline_names"] = strings.Join(pipeNames, ",")
		dm["queue_total_events"] = fmt.Sprintf("%d", totalQueueEvents)
		dm["queue_total_max"] = fmtBytes(float64(totalQueueMaxBytes))
		dm["queue_total_cur"] = fmtBytes(float64(totalQueueCurBytes))
		if totalQueueMaxBytes > 0 {
			dm["queue_total_pct"] = fmt.Sprintf("%.1f", float64(totalQueueCurBytes)/float64(totalQueueMaxBytes)*100)
		}
		dm["dlq_total_events"] = fmt.Sprintf("%d", totalDLQEvents)
		if slowestFilterName != "" {
			dm["slowest_filter_name"] = slowestFilterName
			dm["slowest_filter_ms"] = fmt.Sprintf("%.3f", slowestFilterMs)
		}
	}
}

// populateLogstashPipelines parses /_node/pipelines for workers / batch_size.
func (m *logstashModule) populateLogstashPipelines(inst *model.AppInstance, raw map[string]interface{}) {
	dm := inst.DeepMetrics
	pipelines, ok := raw["pipelines"].(map[string]interface{})
	if !ok {
		return
	}
	for pname, pval := range pipelines {
		p, ok := pval.(map[string]interface{})
		if !ok {
			continue
		}
		prefix := "pipe_" + sanitizeKey(pname) + "_"
		if w := parseJSONInt(p["workers"]); w > 0 {
			dm[prefix+"workers"] = fmt.Sprintf("%d", w)
		}
		if b := parseJSONInt(p["batch_size"]); b > 0 {
			dm[prefix+"batch_size"] = fmt.Sprintf("%d", b)
		}
		if bd := parseJSONInt(p["batch_delay"]); bd > 0 {
			dm[prefix+"batch_delay"] = fmt.Sprintf("%d", bd)
		}
	}
}

// logstashHealthRules applies health checks and adjusts HealthScore/HealthIssues.
func logstashHealthRules(inst *model.AppInstance) {
	dm := inst.DeepMetrics

	if !inst.HasDeepMetrics {
		return
	}

	// 1. Node status
	if s := dm["status"]; s != "" && s != "green" {
		switch s {
		case "red":
			inst.HealthScore -= 30
			inst.HealthIssues = append(inst.HealthIssues,
				fmt.Sprintf("Logstash status %s — node not processing", s))
		case "yellow":
			inst.HealthScore -= 15
			inst.HealthIssues = append(inst.HealthIssues,
				fmt.Sprintf("Logstash status %s — degraded", s))
		}
	}

	// 2. Heap pressure
	if pctStr := dm["jvm_heap_used_pct"]; pctStr != "" {
		pct, _ := strconv.ParseFloat(pctStr, 64)
		if pct > 90 {
			inst.HealthScore -= 25
			inst.HealthIssues = append(inst.HealthIssues,
				fmt.Sprintf("JVM heap at %s%% — GC pressure imminent", pctStr))
		} else if pct > 80 {
			inst.HealthScore -= 15
			inst.HealthIssues = append(inst.HealthIssues,
				fmt.Sprintf("JVM heap at %s%% — consider resizing", pctStr))
		}
	}

	// 3. Pipeline stall — in > 0 but out_per_sec ≈ 0
	in, _ := strconv.ParseFloat(dm["events_in_per_sec"], 64)
	out, _ := strconv.ParseFloat(dm["events_out_per_sec"], 64)
	if in > 10 && out < 0.1 {
		inst.HealthScore -= 30
		inst.HealthIssues = append(inst.HealthIssues,
			fmt.Sprintf("pipeline stalled: %.1f events/s in but ~0 out — blocked filter or output", in))
	} else if in > 0 && out > 0 && out < in*0.5 {
		inst.HealthScore -= 15
		inst.HealthIssues = append(inst.HealthIssues,
			fmt.Sprintf("pipeline lagging: in=%.1f/s out=%.1f/s — throughput halved", in, out))
	}

	// 4. Queue near capacity
	if pctStr := dm["queue_total_pct"]; pctStr != "" {
		pct, _ := strconv.ParseFloat(pctStr, 64)
		if pct > 90 {
			inst.HealthScore -= 20
			inst.HealthIssues = append(inst.HealthIssues,
				fmt.Sprintf("persistent queue at %.1f%% — back-pressure will drop events", pct))
		} else if pct > 75 {
			inst.HealthScore -= 10
			inst.HealthIssues = append(inst.HealthIssues,
				fmt.Sprintf("persistent queue at %.1f%% — growing backlog", pct))
		}
	}

	// 5. Dead-letter queue growth
	if dlq, _ := strconv.ParseInt(dm["dlq_total_events"], 10, 64); dlq > 0 {
		inst.HealthScore -= 10
		inst.HealthIssues = append(inst.HealthIssues,
			fmt.Sprintf("%d events in dead-letter queue — output rejecting events", dlq))
	}

	// 6. Slow filters (>50ms average)
	if msStr := dm["slowest_filter_ms"]; msStr != "" {
		ms, _ := strconv.ParseFloat(msStr, 64)
		if ms > 50 {
			name := dm["slowest_filter_name"]
			inst.HealthScore -= 10
			inst.HealthIssues = append(inst.HealthIssues,
				fmt.Sprintf("filter %q averaging %.1fms — bottleneck", name, ms))
		} else if ms > 10 {
			inst.HealthScore -= 5
			name := dm["slowest_filter_name"]
			inst.HealthIssues = append(inst.HealthIssues,
				fmt.Sprintf("filter %q averaging %.1fms — review", name, ms))
		}
	}

	// 7. Reload failures
	if r, _ := strconv.ParseInt(dm["reload_failures"], 10, 64); r > 0 {
		inst.HealthScore -= 10
		inst.HealthIssues = append(inst.HealthIssues,
			fmt.Sprintf("%d config-reload failures — check logs", r))
	}

	// 8. FD pressure
	fdOpen, _ := strconv.ParseInt(dm["open_fds"], 10, 64)
	fdMax, _ := strconv.ParseInt(dm["max_fds"], 10, 64)
	if fdMax > 0 && fdOpen > 0 {
		pct := float64(fdOpen) / float64(fdMax) * 100
		if pct > 85 {
			inst.HealthScore -= 10
			inst.HealthIssues = append(inst.HealthIssues,
				fmt.Sprintf("open FDs %d/%d (%.0f%%) — near ulimit", fdOpen, fdMax, pct))
		}
	}

	// 9. CPU saturation (process-level)
	if v, _ := strconv.ParseFloat(dm["process_cpu_pct"], 64); v > 90 {
		inst.HealthScore -= 10
		inst.HealthIssues = append(inst.HealthIssues,
			fmt.Sprintf("Logstash CPU at %.0f%% — workers saturated", v))
	}
}

// ── HTTP helper ───────────────────────────────────────────────────────────

func logstashGET(client *http.Client, url string) map[string]interface{} {
	req, err := http.NewRequest("GET", url, nil)
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
