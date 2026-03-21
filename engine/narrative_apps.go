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

	for _, app := range apps {
		appType := strings.ToLower(app.AppType)

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
	}

	// Flag unhealthy apps as evidence
	for _, app := range apps {
		if app.HealthScore > 0 && app.HealthScore < 70 {
			narr.Evidence = append(narr.Evidence,
				fmt.Sprintf("[%s] health degraded (score: %d/100)", app.DisplayName, app.HealthScore))
		}
		for _, issue := range app.HealthIssues {
			if len(narr.Evidence) < 8 {
				narr.Evidence = append(narr.Evidence,
					fmt.Sprintf("[%s] %s", app.DisplayName, issue))
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
	case "redis", "elasticsearch", "memcached", "mongodb", "mysql", "postgresql":
		return true
	}
	return false
}

func isComputeApp(t string) bool {
	switch t {
	case "mysql", "postgresql", "elasticsearch", "php-fpm":
		return true
	}
	return false
}

func isNetApp(t string) bool {
	switch t {
	case "nginx", "apache", "haproxy", "traefik", "caddy":
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
	}
}
