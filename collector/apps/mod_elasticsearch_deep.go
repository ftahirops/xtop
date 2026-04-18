//go:build linux

package apps

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/ftahirops/xtop/model"
)

// collectESDeepMetrics gathers thread-pool, circuit-breaker, shard, index-lifecycle,
// JVM-GC, pending-task and per-index search/index latency data from Elasticsearch.
//
// Best-effort: every endpoint that fails is silently skipped (cluster may be on an
// older version, auth may differ, etc.). Any successful call sets HasDeepMetrics.
func collectESDeepMetrics(client *http.Client, inst *model.AppInstance, baseURL, user, password string) {
	dm := inst.DeepMetrics
	if dm == nil {
		dm = make(map[string]string)
		inst.DeepMetrics = dm
	}

	collectESThreadPools(client, dm, baseURL, user, password)
	collectESCircuitBreakers(client, dm, baseURL, user, password)
	collectESShardStats(client, dm, baseURL, user, password)
	collectESIndexLifecycle(client, dm, baseURL, user, password)
	collectESJVMGC(client, dm, baseURL, user, password)
	collectESPendingTasks(client, dm, baseURL, user, password)
	collectESSlowIndices(client, dm, baseURL, user, password)
}

// ── Thread Pools ──────────────────────────────────────────────────────────

func collectESThreadPools(client *http.Client, dm map[string]string, baseURL, user, password string) {
	raw := esGetRaw(client, baseURL+"/_cat/thread_pool?format=json&h=name,active,queue,rejected,completed", user, password)
	if raw == nil {
		return
	}
	var arr []map[string]interface{}
	if err := json.Unmarshal(raw, &arr); err != nil {
		return
	}

	// Aggregate across nodes, focus on write/search/bulk
	interested := map[string]bool{"write": true, "search": true, "bulk": true, "get": true, "refresh": true, "flush": true, "management": true}
	type agg struct {
		active, queue, rejected, completed int64
	}
	totals := map[string]*agg{}
	totalRejected := int64(0)

	for _, row := range arr {
		name, _ := row["name"].(string)
		if name == "" {
			continue
		}
		a, _ := totals[name]
		if a == nil {
			a = &agg{}
			totals[name] = a
		}
		a.active += parseJSONInt(row["active"])
		a.queue += parseJSONInt(row["queue"])
		a.rejected += parseJSONInt(row["rejected"])
		a.completed += parseJSONInt(row["completed"])
		totalRejected += parseJSONInt(row["rejected"])
	}

	for name, a := range totals {
		if !interested[name] {
			continue
		}
		dm["tp_"+name+"_active"] = fmt.Sprintf("%d", a.active)
		dm["tp_"+name+"_queue"] = fmt.Sprintf("%d", a.queue)
		dm["tp_"+name+"_rejected"] = fmt.Sprintf("%d", a.rejected)
		dm["tp_"+name+"_completed"] = fmt.Sprintf("%d", a.completed)
	}
	dm["tp_total_rejected"] = fmt.Sprintf("%d", totalRejected)
}

// ── Circuit Breakers ──────────────────────────────────────────────────────

func collectESCircuitBreakers(client *http.Client, dm map[string]string, baseURL, user, password string) {
	raw := esGet(client, baseURL+"/_nodes/stats/breaker", user, password)
	if raw == nil {
		return
	}
	nodes, ok := raw["nodes"].(map[string]interface{})
	if !ok {
		return
	}
	totalTrips := int64(0)
	for _, nd := range nodes {
		n, ok := nd.(map[string]interface{})
		if !ok {
			continue
		}
		breakers, ok := n["breakers"].(map[string]interface{})
		if !ok {
			continue
		}
		for bname, bv := range breakers {
			b, ok := bv.(map[string]interface{})
			if !ok {
				continue
			}
			estSize := parseJSONFloat(b["estimated_size_in_bytes"])
			limit := parseJSONFloat(b["limit_size_in_bytes"])
			trips := parseJSONInt(b["tripped"])
			totalTrips += trips
			prefix := "cb_" + sanitizeKey(bname)
			dm[prefix+"_size"] = fmtBytes(estSize)
			dm[prefix+"_limit"] = fmtBytes(limit)
			dm[prefix+"_tripped"] = fmt.Sprintf("%d", trips)
			if limit > 0 {
				dm[prefix+"_pct"] = fmt.Sprintf("%.1f", estSize/limit*100)
			}
		}
		break // first node only
	}
	dm["cb_total_tripped"] = fmt.Sprintf("%d", totalTrips)
}

// ── Shard-level Analysis ──────────────────────────────────────────────────

func collectESShardStats(client *http.Client, dm map[string]string, baseURL, user, password string) {
	raw := esGetRaw(client, baseURL+"/_cat/shards?format=json&bytes=b&h=index,shard,prirep,state,docs,store,node", user, password)
	if raw == nil {
		return
	}
	var arr []map[string]interface{}
	if err := json.Unmarshal(raw, &arr); err != nil {
		return
	}

	unassigned := 0
	oversized := 0
	undersized := 0
	largestShardBytes := int64(0)
	largestShardName := ""

	for _, row := range arr {
		state, _ := row["state"].(string)
		if state == "UNASSIGNED" || state == "INITIALIZING" {
			if state == "UNASSIGNED" {
				unassigned++
			}
		}
		storeStr, _ := row["store"].(string)
		if storeStr == "" {
			continue
		}
		// store is in bytes (we requested bytes=b)
		bytes, _ := strconv.ParseInt(storeStr, 10, 64)
		if bytes > largestShardBytes {
			largestShardBytes = bytes
			idxName, _ := row["index"].(string)
			shard, _ := row["shard"].(string)
			largestShardName = idxName + ":" + shard
		}
		if bytes > 50*1024*1024*1024 {
			oversized++
		}
		// Only count primaries for undersized check (avoid double-counting via replicas)
		prirep, _ := row["prirep"].(string)
		if prirep == "p" && bytes > 0 && bytes < 1024*1024*1024 {
			undersized++
		}
	}

	dm["shards_unassigned_cat"] = fmt.Sprintf("%d", unassigned)
	dm["shards_oversized"] = fmt.Sprintf("%d", oversized)
	dm["shards_undersized"] = fmt.Sprintf("%d", undersized)
	if largestShardBytes > 0 {
		dm["largest_shard"] = largestShardName
		dm["largest_shard_size"] = fmtBytes(largestShardBytes)
	}
}

// ── Index Lifecycle ───────────────────────────────────────────────────────

func collectESIndexLifecycle(client *http.Client, dm map[string]string, baseURL, user, password string) {
	raw := esGetRaw(client, baseURL+"/_cat/indices?format=json&bytes=b&h=index,creation.date,docs.count,store.size,health", user, password)
	if raw == nil {
		return
	}
	var arr []map[string]interface{}
	if err := json.Unmarshal(raw, &arr); err != nil {
		return
	}

	now := time.Now().Unix()
	old90 := 0
	empty := 0
	tiny := 0
	for _, row := range arr {
		cdStr, _ := row["creation.date"].(string)
		if cdStr != "" {
			if cd, err := strconv.ParseInt(cdStr, 10, 64); err == nil {
				ageSec := now - cd/1000
				if ageSec > 90*24*3600 {
					old90++
				}
			}
		}
		docStr, _ := row["docs.count"].(string)
		storeStr, _ := row["store.size"].(string)
		docs, _ := strconv.ParseInt(docStr, 10, 64)
		storeBytes, _ := strconv.ParseInt(storeStr, 10, 64)
		if docs == 0 {
			empty++
		}
		if storeBytes > 0 && storeBytes < 100*1024 {
			tiny++
		}
	}
	dm["indices_total_cat"] = fmt.Sprintf("%d", len(arr))
	dm["indices_aging_90d"] = fmt.Sprintf("%d", old90)
	dm["indices_empty"] = fmt.Sprintf("%d", empty)
	dm["indices_tiny"] = fmt.Sprintf("%d", tiny)
}

// ── JVM GC details ────────────────────────────────────────────────────────

// Tracks previous GC counter values per instance for rate derivation.
type esGCPrev struct {
	youngCount int64
	youngMS    int64
	oldCount   int64
	oldMS      int64
	at         time.Time
}

var esGCState = struct {
	m map[string]*esGCPrev
}{m: map[string]*esGCPrev{}}

func collectESJVMGC(client *http.Client, dm map[string]string, baseURL, user, password string) {
	raw := esGet(client, baseURL+"/_nodes/stats/jvm", user, password)
	if raw == nil {
		return
	}
	nodes, ok := raw["nodes"].(map[string]interface{})
	if !ok {
		return
	}
	for nodeID, nd := range nodes {
		n, ok := nd.(map[string]interface{})
		if !ok {
			continue
		}
		jvm, ok := n["jvm"].(map[string]interface{})
		if !ok {
			continue
		}
		gc, ok := jvm["gc"].(map[string]interface{})
		if !ok {
			continue
		}
		collectors, ok := gc["collectors"].(map[string]interface{})
		if !ok {
			continue
		}

		young, _ := collectors["young"].(map[string]interface{})
		old, _ := collectors["old"].(map[string]interface{})
		yc := parseJSONInt(young["collection_count"])
		ym := parseJSONInt(young["collection_time_in_millis"])
		oc := parseJSONInt(old["collection_count"])
		om := parseJSONInt(old["collection_time_in_millis"])

		now := time.Now()
		prev := esGCState.m[nodeID]
		if prev != nil {
			elapsed := now.Sub(prev.at).Seconds()
			if elapsed > 1 {
				dYoung := yc - prev.youngCount
				dOld := oc - prev.oldCount
				dYoungMS := ym - prev.youngMS
				dOldMS := om - prev.oldMS
				if dYoung < 0 {
					dYoung = 0
				}
				if dOld < 0 {
					dOld = 0
				}
				dm["gc_young_per_min"] = fmt.Sprintf("%.1f", float64(dYoung)/elapsed*60)
				dm["gc_old_per_min"] = fmt.Sprintf("%.1f", float64(dOld)/elapsed*60)
				if dYoung > 0 {
					dm["gc_young_avg_ms"] = fmt.Sprintf("%.1f", float64(dYoungMS)/float64(dYoung))
				}
				if dOld > 0 {
					dm["gc_old_avg_ms"] = fmt.Sprintf("%.1f", float64(dOldMS)/float64(dOld))
				}
				// frequency = young+old per minute
				dm["gc_frequency"] = fmt.Sprintf("%.1f", float64(dYoung+dOld)/elapsed*60)
			}
		}
		// Also derive lifetime averages as fallback (pause approx)
		if yc > 0 {
			dm["gc_young_lifetime_avg_ms"] = fmt.Sprintf("%.1f", float64(ym)/float64(yc))
		}
		if oc > 0 {
			dm["gc_old_lifetime_avg_ms"] = fmt.Sprintf("%.1f", float64(om)/float64(oc))
		}

		// p95 approximation — we only have mean and count, so approximate using
		// simple heuristic: p95 ≈ 2x mean for typical GC distributions.
		if yc > 0 {
			dm["gc_young_p95_approx_ms"] = fmt.Sprintf("%.1f", float64(ym)/float64(yc)*2)
		}
		if oc > 0 {
			dm["gc_old_p95_approx_ms"] = fmt.Sprintf("%.1f", float64(om)/float64(oc)*2)
		}

		esGCState.m[nodeID] = &esGCPrev{youngCount: yc, youngMS: ym, oldCount: oc, oldMS: om, at: now}
		break
	}
}

// ── Pending Tasks ─────────────────────────────────────────────────────────

func collectESPendingTasks(client *http.Client, dm map[string]string, baseURL, user, password string) {
	raw := esGet(client, baseURL+"/_cluster/pending_tasks", user, password)
	if raw == nil {
		return
	}
	tasks, ok := raw["tasks"].([]interface{})
	if !ok {
		return
	}
	dm["pending_tasks_count"] = fmt.Sprintf("%d", len(tasks))
	if len(tasks) > 0 {
		// find oldest pending
		var oldestMS int64
		var oldestSource string
		for _, t := range tasks {
			tm, ok := t.(map[string]interface{})
			if !ok {
				continue
			}
			ms := parseJSONInt(tm["time_in_queue_millis"])
			if ms > oldestMS {
				oldestMS = ms
				oldestSource, _ = tm["source"].(string)
			}
		}
		dm["pending_tasks_oldest_ms"] = fmt.Sprintf("%d", oldestMS)
		if oldestSource != "" {
			if len(oldestSource) > 80 {
				oldestSource = oldestSource[:80]
			}
			dm["pending_tasks_oldest_source"] = oldestSource
		}
	}
}

// ── Per-Index Search/Indexing latency ─────────────────────────────────────

type idxStat struct {
	name          string
	searchTimeMS  int64
	searchCount   int64
	indexTimeMS   int64
	indexCount    int64
}

func collectESSlowIndices(client *http.Client, dm map[string]string, baseURL, user, password string) {
	raw := esGet(client, baseURL+"/_stats/search,indexing?level=indices", user, password)
	if raw == nil {
		return
	}
	indices, ok := raw["indices"].(map[string]interface{})
	if !ok {
		return
	}
	var stats []idxStat
	for name, v := range indices {
		if strings.HasPrefix(name, ".") {
			// skip system indices for slowness ranking
			continue
		}
		m, ok := v.(map[string]interface{})
		if !ok {
			continue
		}
		total, _ := m["total"].(map[string]interface{})
		search, _ := total["search"].(map[string]interface{})
		indexing, _ := total["indexing"].(map[string]interface{})
		st := idxStat{
			name:         name,
			searchTimeMS: parseJSONInt(search["query_time_in_millis"]),
			searchCount:  parseJSONInt(search["query_total"]),
			indexTimeMS:  parseJSONInt(indexing["index_time_in_millis"]),
			indexCount:   parseJSONInt(indexing["index_total"]),
		}
		stats = append(stats, st)
	}

	// Slowest by average search latency (min 100 queries)
	sort.Slice(stats, func(i, j int) bool {
		ai := float64(0)
		aj := float64(0)
		if stats[i].searchCount >= 100 {
			ai = float64(stats[i].searchTimeMS) / float64(stats[i].searchCount)
		}
		if stats[j].searchCount >= 100 {
			aj = float64(stats[j].searchTimeMS) / float64(stats[j].searchCount)
		}
		return ai > aj
	})

	topN := len(stats)
	if topN > 3 {
		topN = 3
	}
	dm["slow_index_count"] = fmt.Sprintf("%d", topN)
	for i := 0; i < topN; i++ {
		s := stats[i]
		prefix := fmt.Sprintf("slow_index_%d_", i)
		dm[prefix+"name"] = s.name
		if s.searchCount > 0 {
			dm[prefix+"search_avg_ms"] = fmt.Sprintf("%.2f", float64(s.searchTimeMS)/float64(s.searchCount))
		}
		if s.indexCount > 0 {
			dm[prefix+"index_avg_ms"] = fmt.Sprintf("%.2f", float64(s.indexTimeMS)/float64(s.indexCount))
		}
		dm[prefix+"search_count"] = fmt.Sprintf("%d", s.searchCount)
	}
}

// ── Helpers ────────────────────────────────────────────────────────────────

func parseJSONInt(v interface{}) int64 {
	switch n := v.(type) {
	case float64:
		return int64(n)
	case int64:
		return n
	case int:
		return int64(n)
	case json.Number:
		i, _ := n.Int64()
		return i
	case string:
		i, _ := strconv.ParseInt(n, 10, 64)
		return i
	}
	return 0
}

func parseJSONFloat(v interface{}) float64 {
	switch n := v.(type) {
	case float64:
		return n
	case int64:
		return float64(n)
	case int:
		return float64(n)
	case json.Number:
		f, _ := n.Float64()
		return f
	case string:
		f, _ := strconv.ParseFloat(n, 64)
		return f
	}
	return 0
}

func sanitizeKey(s string) string {
	s = strings.ToLower(s)
	s = strings.ReplaceAll(s, " ", "_")
	s = strings.ReplaceAll(s, "-", "_")
	s = strings.ReplaceAll(s, ".", "_")
	return s
}
