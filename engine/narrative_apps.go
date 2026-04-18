package engine

import (
	"fmt"
	"strings"

	"github.com/ftahirops/xtop/model"
)

// EnrichNarrativeWithApps adds app-specific context to RCA narratives.
func EnrichNarrativeWithApps(narr *model.Narrative, result *model.AnalysisResult, apps []model.AppInstance) {
	if narr == nil || result == nil || len(apps) == 0 {
		return
	}

	domain := strings.ToLower(result.PrimaryBottleneck)

	// Only enrich with app context if the app is actually the culprit
	// or is unhealthy. Don't blindly add "MySQL likely..." just because
	// MySQL exists on the system.
	culprit := strings.ToLower(result.PrimaryAppName)
	if culprit == "" {
		culprit = strings.ToLower(result.PrimaryProcess)
	}

	for _, app := range apps {
		appType := strings.ToLower(app.AppType)
		// Only enrich if this app IS the culprit or is degraded
		isCulprit := strings.Contains(culprit, appType) || strings.Contains(culprit, strings.ToLower(app.DisplayName))
		isDegraded := app.HealthScore > 0 && app.HealthScore < 70

		if !isCulprit && !isDegraded {
			continue
		}

		switch {
		case strings.Contains(domain, "io") && isDBApp(appType):
			enrichIOWithDB(narr, app)
		case strings.Contains(domain, "memory") && isMemHeavyApp(appType):
			enrichMemWithApp(narr, app)
		case strings.Contains(domain, "cpu") && isComputeApp(appType):
			enrichCPUWithApp(narr, app)
		case strings.Contains(domain, "network") && isNetApp(appType):
			enrichNetWithApp(narr, app)
		}

		// Always apply ELK-specific enrichment if this culprit is an ELK component,
		// regardless of domain — since ELK problems often span CPU+Memory+IO+Net.
		if isELKApp(appType) && isCulprit {
			enrichELKWithApp(narr, app)
		}
	}

	// Flag unhealthy apps as evidence — only if actually degraded
	for _, app := range apps {
		if app.HealthScore > 0 && app.HealthScore < 70 {
			narr.Evidence = append(narr.Evidence,
				fmt.Sprintf("[%s] health degraded (score: %d/100)", app.DisplayName, app.HealthScore))
			// Only show issues for degraded apps
			for _, issue := range app.HealthIssues {
				if len(narr.Evidence) < 8 {
					narr.Evidence = append(narr.Evidence,
						fmt.Sprintf("[%s] %s", app.DisplayName, issue))
				}
			}
		}
	}
}

func isDBApp(t string) bool {
	switch t {
	case "mysql", "mariadb", "postgresql", "mongodb", "redis", "elasticsearch", "memcached":
		return true
	}
	return false
}

func isMemHeavyApp(t string) bool {
	switch t {
	case "redis", "elasticsearch", "memcached", "mongodb", "mysql", "postgresql", "logstash", "kibana":
		return true
	}
	return false
}

func isComputeApp(t string) bool {
	switch t {
	case "mysql", "postgresql", "elasticsearch", "php-fpm", "logstash":
		return true
	}
	return false
}

func isNetApp(t string) bool {
	switch t {
	case "nginx", "apache", "haproxy", "traefik", "caddy", "kibana":
		return true
	}
	return false
}

// isELKApp returns true if app is part of the ELK/Elastic stack.
func isELKApp(t string) bool {
	switch t {
	case "elasticsearch", "logstash", "kibana":
		return true
	}
	return false
}

func enrichIOWithDB(narr *model.Narrative, app model.AppInstance) {
	switch strings.ToLower(app.AppType) {
	case "mysql", "mariadb":
		narr.RootCause += " — MySQL likely generating heavy disk IO"
		if v, ok := app.DeepMetrics["buffer_pool_hit_ratio"]; ok {
			narr.Evidence = append(narr.Evidence,
				fmt.Sprintf("[MySQL] Buffer pool hit ratio: %s%% — low ratio means reads hitting disk", v))
		}
		if v, ok := app.DeepMetrics["slow_queries_rate"]; ok && v != "0" {
			narr.Evidence = append(narr.Evidence,
				fmt.Sprintf("[MySQL] Slow queries: %s/s — possible full table scans", v))
		}
	case "postgresql":
		narr.RootCause += " — PostgreSQL likely generating disk IO"
		if v, ok := app.DeepMetrics["cache_hit_ratio"]; ok {
			narr.Evidence = append(narr.Evidence,
				fmt.Sprintf("[PostgreSQL] Cache hit ratio: %s%% — low means reads going to disk", v))
		}
	case "mongodb":
		narr.RootCause += " — MongoDB WiredTiger cache may be undersized"
	case "elasticsearch":
		narr.RootCause += " — Elasticsearch indexing/merge IO likely contributing"
	}
}

func enrichMemWithApp(narr *model.Narrative, app model.AppInstance) {
	switch strings.ToLower(app.AppType) {
	case "redis":
		narr.RootCause += " — Redis in-memory dataset consuming memory"
		if v, ok := app.DeepMetrics["evicted_keys_rate"]; ok && v != "0" {
			narr.Evidence = append(narr.Evidence,
				fmt.Sprintf("[Redis] Evicting keys at %s/s — maxmemory reached", v))
		}
	case "elasticsearch":
		narr.RootCause += " — Elasticsearch JVM heap pressure"
	case "mysql", "mariadb":
		narr.RootCause += " — MySQL buffer pool or temp tables consuming memory"
	case "memcached":
		narr.RootCause += " — Memcached slab allocation consuming memory"
	}
}

func enrichCPUWithApp(narr *model.Narrative, app model.AppInstance) {
	switch strings.ToLower(app.AppType) {
	case "mysql", "mariadb":
		narr.RootCause += " — MySQL query processing consuming CPU"
		if v, ok := app.DeepMetrics["threads_running"]; ok {
			narr.Evidence = append(narr.Evidence,
				fmt.Sprintf("[MySQL] %s threads running", v))
		}
	case "postgresql":
		narr.RootCause += " — PostgreSQL query execution consuming CPU"
	case "php-fpm":
		narr.RootCause += " — PHP-FPM workers saturated"
	}
}

func enrichNetWithApp(narr *model.Narrative, app model.AppInstance) {
	switch strings.ToLower(app.AppType) {
	case "nginx":
		narr.RootCause += " — Nginx connection handling may be affected"
	case "haproxy":
		narr.RootCause += " — HAProxy backend health may be degraded"
	case "apache":
		narr.RootCause += " — Apache worker slots may be exhausted"
	case "kibana":
		narr.RootCause += " — Kibana event loop or backend ES calls slow"
	}
}

// enrichELKWithApp pinpoints the specific failing component within the ELK stack.
func enrichELKWithApp(narr *model.Narrative, app model.AppInstance) {
	dm := app.DeepMetrics
	switch strings.ToLower(app.AppType) {
	case "elasticsearch":
		if v := dm["status"]; v == "red" {
			narr.RootCause += " — Elasticsearch cluster RED (data loss risk)"
		} else if v == "yellow" {
			narr.RootCause += " — Elasticsearch cluster YELLOW (replicas unassigned)"
		}
		if rej, _ := strToInt(dm["tp_total_rejected"]); rej > 0 {
			narr.Evidence = append(narr.Evidence,
				"[Elasticsearch] thread pool rejections — indexing/search queues saturated")
		}
		if trips, _ := strToInt(dm["cb_total_tripped"]); trips > 0 {
			narr.Evidence = append(narr.Evidence,
				"[Elasticsearch] circuit breakers tripped — requests rejected to protect heap")
		}
		if v := dm["jvm_heap_used_pct"]; v != "" {
			if h, _ := strToFloat(strings.TrimSuffix(v, "%")); h > 85 {
				narr.Evidence = append(narr.Evidence,
					"[Elasticsearch] JVM heap "+v+" used — GC pressure / heap sizing issue")
			}
		}
		if n, _ := strToInt(dm["pending_tasks_count"]); n > 10 {
			narr.Evidence = append(narr.Evidence,
				"[Elasticsearch] cluster pending tasks queued — master overloaded")
		}
		if n, _ := strToInt(dm["shards_unassigned_cat"]); n > 0 {
			narr.Evidence = append(narr.Evidence,
				"[Elasticsearch] unassigned shards — allocation blocked / nodes missing")
		}
		if cnt, _ := strToInt(dm["slow_index_count"]); cnt > 0 {
			if name := dm["slow_index_0_name"]; name != "" {
				if ms, _ := strToFloat(dm["slow_index_0_search_avg_ms"]); ms > 200 {
					narr.Evidence = append(narr.Evidence,
						"[Elasticsearch] index "+name+" averaging "+dm["slow_index_0_search_avg_ms"]+"ms/query")
				}
			}
		}
	case "logstash":
		in, _ := strToFloat(dm["events_in_per_sec"])
		out, _ := strToFloat(dm["events_out_per_sec"])
		switch {
		case in > 10 && out < 0.1:
			narr.RootCause += " — Logstash pipeline STALLED (events in, nothing out)"
			narr.Evidence = append(narr.Evidence,
				"[Logstash] blocked filter or output — check slowest filter / ES connectivity")
		case in > 0 && out > 0 && out < in*0.5:
			narr.RootCause += " — Logstash pipeline lagging (out < 50% of in)"
		}
		if v := dm["queue_total_pct"]; v != "" {
			if p, _ := strToFloat(v); p > 75 {
				narr.Evidence = append(narr.Evidence,
					"[Logstash] persistent queue "+v+"% — back-pressure imminent")
			}
		}
		if dlq, _ := strToInt(dm["dlq_total_events"]); dlq > 0 {
			narr.Evidence = append(narr.Evidence,
				"[Logstash] dead-letter queue growing — output rejecting events")
		}
		if name := dm["slowest_filter_name"]; name != "" {
			if ms, _ := strToFloat(dm["slowest_filter_ms"]); ms > 50 {
				narr.Evidence = append(narr.Evidence,
					"[Logstash] slowest filter: "+name+" @ "+dm["slowest_filter_ms"]+"ms avg")
			}
		}
	case "kibana":
		if v := dm["status_overall"]; v != "" && strings.ToLower(v) != "green" {
			narr.RootCause += " — Kibana overall status " + strings.ToUpper(v)
			if summary := dm["status_summary"]; summary != "" {
				narr.Evidence = append(narr.Evidence, "[Kibana] "+summary)
			}
		}
		if n, _ := strToInt(dm["plugins_unavailable"]); n > 0 {
			narr.Evidence = append(narr.Evidence,
				"[Kibana] plugins unavailable: "+dm["plugins_unavailable_names"])
		}
		if v := dm["event_loop_delay_ms"]; v != "" {
			if d, _ := strToFloat(v); d > 100 {
				narr.Evidence = append(narr.Evidence,
					"[Kibana] event loop delay "+v+"ms — UI sluggish, likely blocked by ES backend")
			}
		}
		if v := dm["heap_used_pct"]; v != "" {
			if h, _ := strToFloat(v); h > 80 {
				narr.Evidence = append(narr.Evidence,
					"[Kibana] Node.js heap "+v+"% — approaching v8 limit")
			}
		}
	}
}

// strToInt / strToFloat are local tolerant parsers (ignore errors, return 0).
func strToInt(s string) (int64, error) {
	if s == "" {
		return 0, nil
	}
	var v int64
	_, err := fmt.Sscanf(s, "%d", &v)
	return v, err
}

func strToFloat(s string) (float64, error) {
	if s == "" {
		return 0, nil
	}
	var v float64
	_, err := fmt.Sscanf(s, "%f", &v)
	return v, err
}
