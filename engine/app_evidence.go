package engine

import (
	"fmt"
	"strconv"

	"github.com/ftahirops/xtop/model"
)

// AppEvidenceInjector bridges app deep metrics into the RCA domain analyzers.
// It reads already-collected app metrics from the snapshot and emits EvidenceV2
// entries that feed into domain scoring. Zero-cost when no apps are detected.
type AppEvidenceInjector struct{}

// NewAppEvidenceInjector creates an injector.
func NewAppEvidenceInjector() *AppEvidenceInjector {
	return &AppEvidenceInjector{}
}

// appFloat parses a string value from DeepMetrics. Returns 0 and false if missing.
func appFloat(m map[string]string, key string) (float64, bool) {
	v, ok := m[key]
	if !ok {
		return 0, false
	}
	f, err := strconv.ParseFloat(v, 64)
	if err != nil {
		return 0, false
	}
	return f, true
}

// InjectIOEvidence scans app metrics and appends IO-domain evidence.
// Called from analyzeIO after system-level evidence is gathered.
func (aei *AppEvidenceInjector) InjectIOEvidence(curr *model.Snapshot, r *model.RCAEntry) {
	for _, app := range curr.Global.Apps.Instances {
		switch app.AppType {
		case "mysql", "mariadb":
			if ratio, ok := appFloat(app.DeepMetrics, "buffer_pool_hit_ratio"); ok && ratio > 0 {
				missPct := (1 - ratio) * 100
				if missPct >= 5 {
					w, c := thresholdAdaptive("app.mysql.buffer_miss", 5, 15, curr)
					conf := 0.85
					if missPct >= 15 {
						conf = 0.95
					}
					r.EvidenceV2 = append(r.EvidenceV2, emitEvidence("app.mysql.buffer_miss", model.DomainIO,
						missPct, w, c, true, conf,
						fmt.Sprintf("MySQL buffer pool miss %.1f%% (ratio=%.3f)", missPct, ratio), "1s",
						nil, map[string]string{"app": app.AppType, "app_id": app.ID}))
				}
			}
			if pending, ok := appFloat(app.DeepMetrics, "innodb_pending_flushes"); ok && pending > 0 {
				if pending >= 10 {
					w, c := thresholdAdaptive("app.mysql.flush_pressure", 10, 50, curr)
					r.EvidenceV2 = append(r.EvidenceV2, emitEvidence("app.mysql.flush_pressure", model.DomainIO,
						pending, w, c, true, 0.9,
						fmt.Sprintf("MySQL flush pressure: %.0f pending flushes", pending), "1s",
						nil, map[string]string{"app": app.AppType, "app_id": app.ID}))
				}
			}
			if slow, ok := appFloat(app.DeepMetrics, "slow_queries_rate"); ok && slow > 0 {
				if slow >= 1 {
					w, c := thresholdAdaptive("app.mysql.slow_queries", 1, 10, curr)
					r.EvidenceV2 = append(r.EvidenceV2, emitEvidence("app.mysql.slow_queries", model.DomainIO,
						slow, w, c, true, 0.8,
						fmt.Sprintf("MySQL slow queries=%.1f/s", slow), "1s",
						nil, map[string]string{"app": app.AppType, "app_id": app.ID}))
				}
			}

		case "mongodb":
			if dirty, ok := appFloat(app.DeepMetrics, "wiredtiger_cache_dirty_pct"); ok && dirty > 0 {
				if dirty >= 10 {
					w, c := thresholdAdaptive("app.mongodb.dirty_cache", 10, 25, curr)
					r.EvidenceV2 = append(r.EvidenceV2, emitEvidence("app.mongodb.dirty_cache", model.DomainIO,
						dirty, w, c, true, 0.9,
						fmt.Sprintf("MongoDB WiredTiger dirty cache %.1f%%", dirty), "1s",
						nil, map[string]string{"app": app.AppType, "app_id": app.ID}))
				}
			}
			if tickets, ok := appFloat(app.DeepMetrics, "wiredtiger_read_tickets"); ok && tickets > 0 {
				if tickets >= 100 {
					w, c := thresholdAdaptive("app.mongodb.ticket_exhaustion", 100, 200, curr)
					r.EvidenceV2 = append(r.EvidenceV2, emitEvidence("app.mongodb.ticket_exhaustion", model.DomainIO,
						tickets, w, c, true, 0.85,
						fmt.Sprintf("MongoDB read tickets=%.0f (cache contention)", tickets), "1s",
						nil, map[string]string{"app": app.AppType, "app_id": app.ID}))
				}
			}
			if pageFaults, ok := appFloat(app.DeepMetrics, "page_faults_delta"); ok && pageFaults > 0 {
				if pageFaults >= 100 {
					w, c := thresholdAdaptive("app.mongodb.page_faults", 100, 500, curr)
					r.EvidenceV2 = append(r.EvidenceV2, emitEvidence("app.mongodb.page_faults", model.DomainIO,
						pageFaults, w, c, true, 0.8,
						fmt.Sprintf("MongoDB page faults=%.0f/s", pageFaults), "1s",
						nil, map[string]string{"app": app.AppType, "app_id": app.ID}))
				}
			}

		case "elasticsearch":
			if merge, ok := appFloat(app.DeepMetrics, "merge_current"); ok && merge > 0 {
				if merge >= 5 {
					w, c := thresholdAdaptive("app.es.merge_io", 5, 20, curr)
					r.EvidenceV2 = append(r.EvidenceV2, emitEvidence("app.es.merge_io", model.DomainIO,
						merge, w, c, true, 0.75,
						fmt.Sprintf("ES merge operations=%.0f active", merge), "1s",
						nil, map[string]string{"app": app.AppType, "app_id": app.ID}))
				}
			}
		}
	}
}

// InjectMemoryEvidence scans app metrics and appends Memory-domain evidence.
func (aei *AppEvidenceInjector) InjectMemoryEvidence(curr *model.Snapshot, r *model.RCAEntry) {
	for _, app := range curr.Global.Apps.Instances {
		switch app.AppType {
		case "redis":
			if usedPct, ok := appFloat(app.DeepMetrics, "used_memory_pct"); ok && usedPct > 0 {
				if usedPct >= 80 {
					w, c := thresholdAdaptive("app.redis.memory_pressure", 80, 95, curr)
					conf := 0.85
					if usedPct >= 95 {
						conf = 0.95
					}
					r.EvidenceV2 = append(r.EvidenceV2, emitEvidence("app.redis.memory_pressure", model.DomainMemory,
						usedPct, w, c, true, conf,
						fmt.Sprintf("Redis memory pressure %.1f%%", usedPct), "1s",
						nil, map[string]string{"app": app.AppType, "app_id": app.ID}))
				}
			}
			if evict, ok := appFloat(app.DeepMetrics, "evicted_keys_delta"); ok && evict > 0 {
				if evict >= 10 {
					w, c := thresholdAdaptive("app.redis.evictions", 10, 1000, curr)
					r.EvidenceV2 = append(r.EvidenceV2, emitEvidence("app.redis.evictions", model.DomainMemory,
						evict, w, c, true, 0.9,
						fmt.Sprintf("Redis evictions=%.0f keys/s", evict), "1s",
						nil, map[string]string{"app": app.AppType, "app_id": app.ID}))
				}
			}

		case "mysql", "mariadb":
			if bpUsage, ok := appFloat(app.DeepMetrics, "buffer_pool_used_pct"); ok && bpUsage > 0 {
				if bpUsage >= 95 {
					w, c := thresholdAdaptive("app.mysql.buffer_full", 95, 99, curr)
					r.EvidenceV2 = append(r.EvidenceV2, emitEvidence("app.mysql.buffer_full", model.DomainMemory,
						bpUsage, w, c, true, 0.8,
						fmt.Sprintf("MySQL buffer pool %.1f%% full", bpUsage), "1s",
						nil, map[string]string{"app": app.AppType, "app_id": app.ID}))
				}
			}

		case "mongodb":
			if cachePct, ok := appFloat(app.DeepMetrics, "wiredtiger_cache_usage_pct"); ok && cachePct > 0 {
				if cachePct >= 90 {
					w, c := thresholdAdaptive("app.mongodb.cache_pressure", 90, 98, curr)
					conf := 0.85
					if cachePct >= 98 {
						conf = 0.95
					}
					r.EvidenceV2 = append(r.EvidenceV2, emitEvidence("app.mongodb.cache_pressure", model.DomainMemory,
						cachePct, w, c, true, conf,
						fmt.Sprintf("MongoDB WiredTiger cache %.1f%%", cachePct), "1s",
						nil, map[string]string{"app": app.AppType, "app_id": app.ID}))
				}
			}

		case "elasticsearch":
			if heapPct, ok := appFloat(app.DeepMetrics, "jvm_heap_used_pct"); ok && heapPct > 0 {
				if heapPct >= 85 {
					w, c := thresholdAdaptive("app.es.heap_pressure", 85, 95, curr)
					r.EvidenceV2 = append(r.EvidenceV2, emitEvidence("app.es.heap_pressure", model.DomainMemory,
						heapPct, w, c, true, 0.85,
						fmt.Sprintf("ES JVM heap %.1f%%", heapPct), "1s",
						nil, map[string]string{"app": app.AppType, "app_id": app.ID}))
				}
			}

		case "memcached":
			if bytesPct, ok := appFloat(app.DeepMetrics, "bytes_used_pct"); ok && bytesPct > 0 {
				if bytesPct >= 90 {
					w, c := thresholdAdaptive("app.memcached.memory_pressure", 90, 98, curr)
					r.EvidenceV2 = append(r.EvidenceV2, emitEvidence("app.memcached.memory_pressure", model.DomainMemory,
						bytesPct, w, c, true, 0.8,
						fmt.Sprintf("Memcached memory %.1f%%", bytesPct), "1s",
						nil, map[string]string{"app": app.AppType, "app_id": app.ID}))
				}
			}
		}
	}
}

// InjectCPUEvidence scans app metrics and appends CPU-domain evidence.
func (aei *AppEvidenceInjector) InjectCPUEvidence(curr *model.Snapshot, r *model.RCAEntry) {
	for _, app := range curr.Global.Apps.Instances {
		switch app.AppType {
		case "mysql", "mariadb":
			if threads, ok := appFloat(app.DeepMetrics, "threads_running"); ok && threads > 0 {
				if threads >= 20 {
					w, c := thresholdAdaptive("app.mysql.thread_contention", 20, 100, curr)
					r.EvidenceV2 = append(r.EvidenceV2, emitEvidence("app.mysql.thread_contention", model.DomainCPU,
						threads, w, c, true, 0.8,
						fmt.Sprintf("MySQL threads_running=%.0f", threads), "1s",
						nil, map[string]string{"app": app.AppType, "app_id": app.ID}))
				}
			}

		case "mongodb":
			if lockQueue, ok := appFloat(app.DeepMetrics, "lock_queue_total"); ok && lockQueue > 0 {
				if lockQueue >= 5 {
					w, c := thresholdAdaptive("app.mongodb.lock_contention", 5, 20, curr)
					r.EvidenceV2 = append(r.EvidenceV2, emitEvidence("app.mongodb.lock_contention", model.DomainCPU,
						lockQueue, w, c, true, 0.85,
						fmt.Sprintf("MongoDB lock queue=%.0f", lockQueue), "1s",
						nil, map[string]string{"app": app.AppType, "app_id": app.ID}))
				}
			}
			if active, ok := appFloat(app.DeepMetrics, "global_lock_active_clients"); ok && active > 0 {
				if active >= 50 {
					w, c := thresholdAdaptive("app.mongodb.active_clients", 50, 200, curr)
					r.EvidenceV2 = append(r.EvidenceV2, emitEvidence("app.mongodb.active_clients", model.DomainCPU,
						active, w, c, true, 0.75,
						fmt.Sprintf("MongoDB active clients=%.0f", active), "1s",
						nil, map[string]string{"app": app.AppType, "app_id": app.ID}))
				}
			}

		case "postgresql":
			if active, ok := appFloat(app.DeepMetrics, "active_connections"); ok && active > 0 {
				if max, ok := appFloat(app.DeepMetrics, "max_connections"); ok && max > 0 {
					pct := active / max * 100
					if pct >= 80 {
						w, c := thresholdAdaptive("app.pgsql.connection_pressure", 80, 95, curr)
						r.EvidenceV2 = append(r.EvidenceV2, emitEvidence("app.pgsql.connection_pressure", model.DomainCPU,
							pct, w, c, true, 0.8,
							fmt.Sprintf("PostgreSQL connections %.0f/%.0f (%.0f%%)", active, max, pct), "1s",
							nil, map[string]string{"app": app.AppType, "app_id": app.ID}))
					}
				}
			}

		case "php-fpm":
			if active, ok := appFloat(app.DeepMetrics, "active_processes"); ok && active > 0 {
				if max, ok := appFloat(app.DeepMetrics, "max_children"); ok && max > 0 {
					pct := active / max * 100
					if pct >= 80 {
						w, c := thresholdAdaptive("app.phpfpm.worker_saturation", 80, 95, curr)
						r.EvidenceV2 = append(r.EvidenceV2, emitEvidence("app.phpfpm.worker_saturation", model.DomainCPU,
							pct, w, c, true, 0.85,
							fmt.Sprintf("PHP-FPM workers %.0f/%.0f (%.0f%%)", active, max, pct), "1s",
							nil, map[string]string{"app": app.AppType, "app_id": app.ID}))
					}
				}
			}
		}
	}
}

// InjectNetworkEvidence scans app metrics and appends Network-domain evidence.
func (aei *AppEvidenceInjector) InjectNetworkEvidence(curr *model.Snapshot, r *model.RCAEntry) {
	for _, app := range curr.Global.Apps.Instances {
		switch app.AppType {
		case "nginx":
			if drops, ok := appFloat(app.DeepMetrics, "dropped_connections"); ok && drops > 0 {
				if drops >= 1 {
					w, c := thresholdAdaptive("app.nginx.dropped_conns", 1, 50, curr)
					r.EvidenceV2 = append(r.EvidenceV2, emitEvidence("app.nginx.dropped_conns", model.DomainNetwork,
						drops, w, c, true, 0.85,
						fmt.Sprintf("Nginx dropped connections=%.0f/s", drops), "1s",
						nil, map[string]string{"app": app.AppType, "app_id": app.ID}))
				}
			}
			if waiting, ok := appFloat(app.DeepMetrics, "waiting_connections"); ok && waiting > 0 {
				if maxConn, ok := appFloat(app.DeepMetrics, "max_connections"); ok && maxConn > 0 {
					pct := waiting / maxConn * 100
					if pct >= 80 {
						w, c := thresholdAdaptive("app.nginx.conn_saturation", 80, 95, curr)
						r.EvidenceV2 = append(r.EvidenceV2, emitEvidence("app.nginx.conn_saturation", model.DomainNetwork,
							pct, w, c, true, 0.8,
							fmt.Sprintf("Nginx waiting=%.0f max=%.0f (%.0f%%)", waiting, maxConn, pct), "1s",
							nil, map[string]string{"app": app.AppType, "app_id": app.ID}))
					}
				}
			}

		case "mysql", "mariadb":
			if aborted, ok := appFloat(app.DeepMetrics, "aborted_connects_delta"); ok && aborted > 0 {
				if aborted >= 1 {
					w, c := thresholdAdaptive("app.mysql.aborted_conns", 1, 10, curr)
					r.EvidenceV2 = append(r.EvidenceV2, emitEvidence("app.mysql.aborted_conns", model.DomainNetwork,
						aborted, w, c, true, 0.75,
						fmt.Sprintf("MySQL aborted connects=%.0f/s", aborted), "1s",
						nil, map[string]string{"app": app.AppType, "app_id": app.ID}))
				}
			}

		case "redis":
			if rejected, ok := appFloat(app.DeepMetrics, "rejected_connections_delta"); ok && rejected > 0 {
				if rejected >= 1 {
					w, c := thresholdAdaptive("app.redis.rejected_conns", 1, 10, curr)
					r.EvidenceV2 = append(r.EvidenceV2, emitEvidence("app.redis.rejected_conns", model.DomainNetwork,
						rejected, w, c, true, 0.85,
						fmt.Sprintf("Redis rejected connections=%.0f/s", rejected), "1s",
						nil, map[string]string{"app": app.AppType, "app_id": app.ID}))
				}
			}

		case "elasticsearch":
			if rejected, ok := appFloat(app.DeepMetrics, "http_connections_opened"); ok && rejected > 0 {
				// Not a direct network signal but useful for ES load
			}
			if queue, ok := appFloat(app.DeepMetrics, "thread_pool_search_queue"); ok && queue > 0 {
				if queue >= 50 {
					w, c := thresholdAdaptive("app.es.search_queue", 50, 200, curr)
					r.EvidenceV2 = append(r.EvidenceV2, emitEvidence("app.es.search_queue", model.DomainNetwork,
						queue, w, c, true, 0.75,
						fmt.Sprintf("ES search queue=%.0f", queue), "1s",
						nil, map[string]string{"app": app.AppType, "app_id": app.ID}))
				}
			}
		}
	}
}

// AppCulpritReason returns a human-readable reason when an app is the top
// process for a given domain. Returns "" when no app-specific reason applies.
func AppCulpritReason(appType string, deepMetrics map[string]string, domain model.Domain) string {
	switch domain {
	case model.DomainIO:
		switch appType {
		case "mysql", "mariadb":
			if p, ok := appFloat(deepMetrics, "innodb_pending_flushes"); ok && p >= 10 {
				return fmt.Sprintf("MySQL flush pressure (pending=%.0f)", p)
			}
			if r, ok := appFloat(deepMetrics, "buffer_pool_hit_ratio"); ok && r < 0.95 {
				return fmt.Sprintf("MySQL buffer miss %.1f%%", (1-r)*100)
			}
			if s, ok := appFloat(deepMetrics, "slow_queries_rate"); ok && s >= 1 {
				return fmt.Sprintf("MySQL slow queries=%.1f/s", s)
			}
		case "mongodb":
			if d, ok := appFloat(deepMetrics, "wiredtiger_cache_dirty_pct"); ok && d >= 10 {
				return fmt.Sprintf("MongoDB dirty cache %.1f%%", d)
			}
			if t, ok := appFloat(deepMetrics, "wiredtiger_read_tickets"); ok && t >= 100 {
				return fmt.Sprintf("MongoDB ticket exhaustion (%.0f)", t)
			}
		case "elasticsearch":
			if m, ok := appFloat(deepMetrics, "merge_current"); ok && m >= 5 {
				return fmt.Sprintf("ES merge IO (%.0f active)", m)
			}
		}
	case model.DomainMemory:
		switch appType {
		case "redis":
			if u, ok := appFloat(deepMetrics, "used_memory_pct"); ok && u >= 80 {
				return fmt.Sprintf("Redis memory pressure %.1f%%", u)
			}
			if e, ok := appFloat(deepMetrics, "evicted_keys_delta"); ok && e >= 10 {
				return fmt.Sprintf("Redis evictions=%.0f keys/s", e)
			}
		case "mysql", "mariadb":
			if b, ok := appFloat(deepMetrics, "buffer_pool_used_pct"); ok && b >= 95 {
				return fmt.Sprintf("MySQL buffer pool %.1f%% full", b)
			}
		case "mongodb":
			if c, ok := appFloat(deepMetrics, "wiredtiger_cache_usage_pct"); ok && c >= 90 {
				return fmt.Sprintf("MongoDB cache %.1f%%", c)
			}
		case "elasticsearch":
			if h, ok := appFloat(deepMetrics, "jvm_heap_used_pct"); ok && h >= 85 {
				return fmt.Sprintf("ES JVM heap %.1f%%", h)
			}
		}
	case model.DomainCPU:
		switch appType {
		case "mysql", "mariadb":
			if t, ok := appFloat(deepMetrics, "threads_running"); ok && t >= 20 {
				return fmt.Sprintf("MySQL threads_running=%.0f", t)
			}
		case "mongodb":
			if l, ok := appFloat(deepMetrics, "lock_queue_total"); ok && l >= 5 {
				return fmt.Sprintf("MongoDB lock queue=%.0f", l)
			}
		case "postgresql":
			if a, ok := appFloat(deepMetrics, "active_connections"); ok && a >= 50 {
				return fmt.Sprintf("PostgreSQL active=%.0f", a)
			}
		case "php-fpm":
			if a, ok := appFloat(deepMetrics, "active_processes"); ok && a >= 20 {
				return fmt.Sprintf("PHP-FPM active=%.0f", a)
			}
		}
	case model.DomainNetwork:
		switch appType {
		case "nginx":
			if d, ok := appFloat(deepMetrics, "dropped_connections"); ok && d >= 1 {
				return fmt.Sprintf("Nginx dropped=%.0f/s", d)
			}
		case "mysql", "mariadb":
			if a, ok := appFloat(deepMetrics, "aborted_connects_delta"); ok && a >= 1 {
				return fmt.Sprintf("MySQL aborted=%.0f/s", a)
			}
		case "redis":
			if r, ok := appFloat(deepMetrics, "rejected_connections_delta"); ok && r >= 1 {
				return fmt.Sprintf("Redis rejected=%.0f/s", r)
			}
		}
	}
	return ""
}
