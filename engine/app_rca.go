package engine

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/ftahirops/xtop/model"
)

// Per-app RCA rule engine.
//
// Cost contract: this file MUST NOT spawn subprocesses, walk /proc, or do
// any work that scales with host size. It reads ONLY from already-collected
// DeepMetrics on each AppInstance and produces findings via map lookups and
// threshold comparisons. Total cost target: <1 ms per tick across all apps.
//
// When Guardian is at level >= 1, deep metrics are stale (collection skipped
// upstream by SetSkipDeepProbes). The engine returns nothing in that case —
// honest "we don't know right now" rather than misleading findings off old
// data.

// appRule describes one diagnostic check.
type appRule struct {
	id       string                                // stable ID
	appType  string                                // matches AppInstance.AppType
	severity string                                // info | warn | crit
	title    string                                // displayed headline
	check    func(dm map[string]string) (ok bool,  // returns (matched, finding details)
		val float64, thresh float64, detail string, action string)
}

// EvaluateAppRCA runs the per-app rule library against the current snapshot
// and returns the findings. Skips entirely when guard level >= 1.
func EvaluateAppRCA(snap *model.Snapshot, guardLevel int) []model.AppRCAFinding {
	if snap == nil || guardLevel >= 1 {
		return nil
	}
	if len(snap.Global.Apps.Instances) == 0 {
		return nil
	}

	var findings []model.AppRCAFinding
	for _, app := range snap.Global.Apps.Instances {
		if !app.HasDeepMetrics || len(app.DeepMetrics) == 0 {
			continue // Manager is in tier-1 mode (Guardian skip or first tick)
		}
		rules := rulesForAppType(app.AppType)
		for _, r := range rules {
			matched, val, thresh, detail, action := r.check(app.DeepMetrics)
			if !matched {
				continue
			}
			findings = append(findings, model.AppRCAFinding{
				App:       app.ID,
				AppType:   app.AppType,
				Rule:      r.id,
				Severity:  r.severity,
				Title:     r.title,
				Detail:    detail,
				Action:    action,
				Value:     val,
				Threshold: thresh,
			})
		}
	}

	// Stable order: crit > warn > info, then by app then by rule id.
	severityRank := map[string]int{"crit": 0, "warn": 1, "info": 2}
	sort.SliceStable(findings, func(i, j int) bool {
		if severityRank[findings[i].Severity] != severityRank[findings[j].Severity] {
			return severityRank[findings[i].Severity] < severityRank[findings[j].Severity]
		}
		if findings[i].App != findings[j].App {
			return findings[i].App < findings[j].App
		}
		return findings[i].Rule < findings[j].Rule
	})
	return findings
}

// rulesForAppType returns the rule set for one app type. Add new app types
// by appending a case here. Rules within a case are evaluated in order but
// independently — one rule failing doesn't stop the others.
func rulesForAppType(appType string) []appRule {
	switch appType {
	case "mongodb":
		return mongoRules
	case "mysql", "mariadb":
		return mysqlRules
	case "postgresql":
		return postgresRules
	case "redis":
		return redisRules
	case "elasticsearch":
		return esRules
	case "nginx":
		return nginxRules
	}
	return nil
}

// ── helpers used by all rule sets ───────────────────────────────────────────

// readF parses a DeepMetrics value as float64. Missing / unparseable → 0.
func readF(dm map[string]string, key string) float64 {
	v, _ := strconv.ParseFloat(dm[key], 64)
	return v
}

// pct formats X.X% — most rule details want this.
func pct(v float64) string { return fmt.Sprintf("%.1f%%", v) }

// safeRatio returns num/den, or 0 if den is 0. Used for hit-ratios and
// scan/return ratios where a zero denominator means "no traffic — N/A".
func safeRatio(num, den float64) float64 {
	if den <= 0 {
		return 0
	}
	return num / den
}

// ── MongoDB rules ───────────────────────────────────────────────────────────
//
// All checks read serverStatus-derived DeepMetrics already collected by
// mongoModule.Collect. The most actionable signals first.

var mongoRules = []appRule{
	{
		id:       "mongo.cache.fill.crit",
		appType:  "mongodb",
		severity: "crit",
		title:    "WiredTiger cache near full — eviction will start dropping useful pages",
		check: func(dm map[string]string) (bool, float64, float64, string, string) {
			pctV := readF(dm, "cache_usage_pct")
			if pctV < 95 {
				return false, 0, 0, "", ""
			}
			return true, pctV, 95,
				fmt.Sprintf("WiredTiger cache fill is %s — past the 95%% eviction-pressure threshold. Frequent page evictions degrade reads.", pct(pctV)),
				"Increase storage.wiredTiger.engineConfig.cacheSizeGB or shed working set (drop hot collections, prune dead docs)."
		},
	},
	{
		id:       "mongo.cache.dirty.high",
		appType:  "mongodb",
		severity: "warn",
		title:    "Dirty cache fraction high — write storm in progress",
		check: func(dm map[string]string) (bool, float64, float64, string, string) {
			used := readF(dm, "cache_used_mb")
			dirty := readF(dm, "cache_dirty_mb")
			if used <= 0 {
				return false, 0, 0, "", ""
			}
			ratio := dirty / used * 100
			if ratio < 5 {
				return false, 0, 0, "", ""
			}
			sev := "warn"
			_ = sev
			return true, ratio, 5,
				fmt.Sprintf("Dirty cache is %s of cache used (%.0f MB / %.0f MB). Background eviction is falling behind disk flush.", pct(ratio), dirty, used),
				"Check disk write latency; if disk is healthy, the workload's write rate may exceed sustained capacity. Consider sharding writes or reviewing journal commit interval."
		},
	},
	{
		id:       "mongo.scan.ratio.bad",
		appType:  "mongodb",
		severity: "crit",
		title:    "Scan ratio too high — queries reading much more than they return",
		check: func(dm map[string]string) (bool, float64, float64, string, string) {
			scannedKeys := readF(dm, "scanned_keys_rate")
			scannedObjs := readF(dm, "scanned_objects_rate")
			returned := readF(dm, "doc_returned_rate")
			worstScan := scannedKeys
			if scannedObjs > worstScan {
				worstScan = scannedObjs
			}
			if returned <= 0 || worstScan <= 100 {
				return false, 0, 0, "", "" // need real traffic to judge
			}
			ratio := worstScan / returned
			if ratio < 100 {
				return false, 0, 0, "", ""
			}
			return true, ratio, 100,
				fmt.Sprintf("Reading %.0f items per item returned (%.0f scanned/s vs %.0f returned/s). Query is reading %.0fx more data than the client gets.", ratio, worstScan, returned, ratio),
				"Run db.currentOp() to find the offending query and add an index covering its predicate. Most likely a missing compound index or $ne / $nin on a high-cardinality field."
		},
	},
	{
		id:       "mongo.coll.scans.any",
		appType:  "mongodb",
		severity: "warn",
		title:    "Collection scans happening — index missing or wrong",
		check: func(dm map[string]string) (bool, float64, float64, string, string) {
			rate := readF(dm, "collection_scans_rate")
			if rate < 0.1 {
				return false, 0, 0, "", ""
			}
			return true, rate, 0.1,
				fmt.Sprintf("Full collection scans firing at %.2f/s. Each scan reads every document.", rate),
				"db.collection.getIndexes() and db.currentOp() to identify which collection / query. Add an index for the predicate."
		},
	},
	{
		id:       "mongo.write.lat.crit",
		appType:  "mongodb",
		severity: "crit",
		title:    "Write latency above 50 ms",
		check: func(dm map[string]string) (bool, float64, float64, string, string) {
			us := readF(dm, "avg_write_latency_us")
			if us < 50000 {
				return false, 0, 0, "", ""
			}
			return true, us, 50000,
				fmt.Sprintf("Average write latency %.1f ms — disk, journal commit, or replication lag.", us/1000),
				"Check disk await on the WiredTiger data path; check journal device; if replicated, check oplog replication lag."
		},
	},
	{
		id:       "mongo.read.lat.warn",
		appType:  "mongodb",
		severity: "warn",
		title:    "Read latency unusually high",
		check: func(dm map[string]string) (bool, float64, float64, string, string) {
			us := readF(dm, "avg_read_latency_us")
			if us < 5000 {
				return false, 0, 0, "", ""
			}
			return true, us, 5000,
				fmt.Sprintf("Average read latency %.1f ms — usually means cache misses going to disk.", us/1000),
				"Check cache_usage_pct and page_faults_rate. Working set may exceed cacheSizeGB."
		},
	},
	{
		id:       "mongo.conn.pool.high",
		appType:  "mongodb",
		severity: "warn",
		title:    "Connection pool > 70% utilised",
		check: func(dm map[string]string) (bool, float64, float64, string, string) {
			cur := readF(dm, "conn_current")
			avail := readF(dm, "conn_available")
			cap := cur + avail
			if cap < 1 {
				return false, 0, 0, "", ""
			}
			util := cur / cap * 100
			if util < 70 {
				return false, 0, 0, "", ""
			}
			return true, util, 70,
				fmt.Sprintf("%s of connection pool used (%.0f / %.0f).", pct(util), cur, cap),
				"Audit clients for connection-pool runaway. Each conn keeps file descriptors and a thread on the server side."
		},
	},
	{
		id:       "mongo.conn.churn.high",
		appType:  "mongodb",
		severity: "warn",
		title:    "Connection-churn rate high — clients not pooling",
		check: func(dm map[string]string) (bool, float64, float64, string, string) {
			rate := readF(dm, "conn_total_created_rate")
			if rate < 50 {
				return false, 0, 0, "", ""
			}
			return true, rate, 50,
				fmt.Sprintf("New connections at %.0f/s — clients are reconnecting instead of reusing.", rate),
				"Configure client driver pooling (maxPoolSize), or check for short-lived script invocations."
		},
	},
	{
		id:       "mongo.assert.user.high",
		appType:  "mongodb",
		severity: "warn",
		title:    "User-assertion rate elevated — schema / API errors",
		check: func(dm map[string]string) (bool, float64, float64, string, string) {
			tot := readF(dm, "assert_user")
			if tot < 100000 {
				return false, 0, 0, "", ""
			}
			return true, tot, 100000,
				fmt.Sprintf("%.0f cumulative user assertions — clients sending invalid queries / write conflicts.", tot),
				"Check mongod.log for 'assertion' lines; usually app-side bug (duplicate key, schema validation failure)."
		},
	},
	{
		id:       "mongo.cursor.timeout.any",
		appType:  "mongodb",
		severity: "info",
		title:    "Cursors timing out — long-running queries / network drops",
		check: func(dm map[string]string) (bool, float64, float64, string, string) {
			tot := readF(dm, "cursor_timed_out")
			if tot < 100 {
				return false, 0, 0, "", ""
			}
			return true, tot, 100,
				fmt.Sprintf("%.0f cursor timeouts — clients holding cursors longer than 10 min default.", tot),
				"Either set noCursorTimeout when intentional (and close manually), or speed up the consuming client."
		},
	},
	{
		id:       "mongo.lock.queue.crit",
		appType:  "mongodb",
		severity: "crit",
		title:    "Lock queue saturated — operations blocking",
		check: func(dm map[string]string) (bool, float64, float64, string, string) {
			q := readF(dm, "lock_queue_total")
			if q < 5 {
				return false, 0, 0, "", ""
			}
			return true, q, 5,
				fmt.Sprintf("%.0f operations queued waiting for locks. Throughput collapsed.", q),
				"Use db.currentOp() to find the holder. Common causes: long-running aggregation, schema change with collection lock, journaling delay."
		},
	},
}

// ── MySQL / MariaDB rules ───────────────────────────────────────────────────

var mysqlRules = []appRule{
	{
		id:       "mysql.connections.full",
		appType:  "mysql",
		severity: "crit",
		title:    "Approaching max_connections",
		check: func(dm map[string]string) (bool, float64, float64, string, string) {
			cur := readF(dm, "Threads_connected")
			max := readF(dm, "max_connections")
			if max <= 0 || cur <= 0 {
				return false, 0, 0, "", ""
			}
			util := cur / max * 100
			if util < 85 {
				return false, 0, 0, "", ""
			}
			return true, util, 85,
				fmt.Sprintf("%.0f / %.0f connections used (%s) — new clients will be refused soon.", cur, max, pct(util)),
				"Look for connection-pool runaways in app servers. SHOW PROCESSLIST."
		},
	},
	{
		id:       "mysql.innodb.bp.miss",
		appType:  "mysql",
		severity: "warn",
		title:    "InnoDB buffer pool hit ratio degraded",
		check: func(dm map[string]string) (bool, float64, float64, string, string) {
			reads := readF(dm, "Innodb_buffer_pool_reads")
			req := readF(dm, "Innodb_buffer_pool_read_requests")
			if req < 10000 {
				return false, 0, 0, "", ""
			}
			missPct := safeRatio(reads, req) * 100
			if missPct < 1 {
				return false, 0, 0, "", ""
			}
			return true, missPct, 1,
				fmt.Sprintf("Buffer pool miss rate %s — reads going to disk.", pct(missPct)),
				"Increase innodb_buffer_pool_size to fit working set. Aim for <0.1% miss rate on a steady workload."
		},
	},
	{
		id:       "mysql.slow.queries.rate",
		appType:  "mysql",
		severity: "warn",
		title:    "Slow query rate elevated",
		check: func(dm map[string]string) (bool, float64, float64, string, string) {
			rate := readF(dm, "Slow_queries_rate")
			if rate < 1 {
				return false, 0, 0, "", ""
			}
			return true, rate, 1,
				fmt.Sprintf("%.1f slow queries per second — exceeding long_query_time.", rate),
				"Enable slow query log if not on; pt-query-digest the file. Most often missing index or full-table scan."
		},
	},
	{
		id:       "mysql.deadlocks.recent",
		appType:  "mysql",
		severity: "warn",
		title:    "Deadlocks happening",
		check: func(dm map[string]string) (bool, float64, float64, string, string) {
			rate := readF(dm, "Innodb_deadlocks_rate")
			if rate < 0.05 {
				return false, 0, 0, "", ""
			}
			return true, rate, 0.05,
				fmt.Sprintf("%.2f deadlocks/s — transactions are conflicting on row locks.", rate),
				"SHOW ENGINE INNODB STATUS \\G — look at LATEST DETECTED DEADLOCK. Order writes consistently across transactions."
		},
	},
	{
		id:       "mysql.replication.lag",
		appType:  "mysql",
		severity: "crit",
		title:    "Replication lag — replica behind primary",
		check: func(dm map[string]string) (bool, float64, float64, string, string) {
			lag := readF(dm, "Seconds_Behind_Master")
			if lag < 30 {
				return false, 0, 0, "", ""
			}
			return true, lag, 30,
				fmt.Sprintf("Replica is %.0f s behind primary. Reads from replica are stale.", lag),
				"Check replica SQL thread; common causes: slow queries on replica, single-threaded apply (multi-source / parallel replication can help)."
		},
	},
}

// ── PostgreSQL rules ────────────────────────────────────────────────────────

var postgresRules = []appRule{
	{
		id:       "pg.cache.hit.bad",
		appType:  "postgresql",
		severity: "warn",
		title:    "Buffer cache hit ratio low",
		check: func(dm map[string]string) (bool, float64, float64, string, string) {
			hit := readF(dm, "blks_hit")
			read := readF(dm, "blks_read")
			tot := hit + read
			if tot < 100000 {
				return false, 0, 0, "", ""
			}
			ratio := safeRatio(hit, tot) * 100
			if ratio >= 99 {
				return false, 0, 0, "", ""
			}
			return true, ratio, 99,
				fmt.Sprintf("Buffer cache hit ratio %s — going to disk too often.", pct(ratio)),
				"Increase shared_buffers (typically 25%% of RAM); confirm working set fits."
		},
	},
	{
		id:       "pg.idle.in.txn",
		appType:  "postgresql",
		severity: "warn",
		title:    "Idle-in-transaction connections",
		check: func(dm map[string]string) (bool, float64, float64, string, string) {
			n := readF(dm, "idle_in_transaction")
			if n < 5 {
				return false, 0, 0, "", ""
			}
			return true, n, 5,
				fmt.Sprintf("%.0f connections idle inside an open transaction — they hold locks.", n),
				"App is leaking transactions. Set idle_in_transaction_session_timeout to auto-kill."
		},
	},
	{
		id:       "pg.lock.waits",
		appType:  "postgresql",
		severity: "crit",
		title:    "Lock waits — queries blocking each other",
		check: func(dm map[string]string) (bool, float64, float64, string, string) {
			waits := readF(dm, "blocked_queries")
			if waits < 1 {
				return false, 0, 0, "", ""
			}
			return true, waits, 1,
				fmt.Sprintf("%.0f queries waiting on locks held by others.", waits),
				"SELECT pid, query FROM pg_stat_activity WHERE wait_event_type='Lock'; — find the blocker; consider lock_timeout."
		},
	},
}

// ── Redis rules ─────────────────────────────────────────────────────────────

var redisRules = []appRule{
	{
		id:       "redis.mem.fragmentation",
		appType:  "redis",
		severity: "warn",
		title:    "Memory fragmentation ratio > 1.5",
		check: func(dm map[string]string) (bool, float64, float64, string, string) {
			ratio := readF(dm, "mem_fragmentation_ratio")
			if ratio < 1.5 {
				return false, 0, 0, "", ""
			}
			return true, ratio, 1.5,
				fmt.Sprintf("Fragmentation ratio %.2f — RSS is %.0f%% larger than logical data size.", ratio, (ratio-1)*100),
				"CONFIG SET activedefrag yes (Redis 4+) or restart during a maintenance window."
		},
	},
	{
		id:       "redis.evicted.high",
		appType:  "redis",
		severity: "crit",
		title:    "Evictions happening — memory limit reached",
		check: func(dm map[string]string) (bool, float64, float64, string, string) {
			rate := readF(dm, "evicted_keys_rate")
			if rate < 1 {
				return false, 0, 0, "", ""
			}
			return true, rate, 1,
				fmt.Sprintf("%.0f keys evicted per second — past maxmemory limit.", rate),
				"Increase maxmemory or change eviction policy; check for unexpected key growth (DEBUG OBJECT)."
		},
	},
	{
		id:       "redis.expired.high",
		appType:  "redis",
		severity: "info",
		title:    "Expiration rate elevated",
		check: func(dm map[string]string) (bool, float64, float64, string, string) {
			rate := readF(dm, "expired_keys_rate")
			if rate < 100 {
				return false, 0, 0, "", ""
			}
			return true, rate, 100,
				fmt.Sprintf("%.0f keys/s expiring — high TTL turnover.", rate),
				"Mostly informational; if accompanied by evictions, see maxmemory tuning."
		},
	},
}

// ── Elasticsearch rules ─────────────────────────────────────────────────────

var esRules = []appRule{
	{
		id:       "es.heap.pressure",
		appType:  "elasticsearch",
		severity: "crit",
		title:    "JVM heap > 85% — GC will dominate",
		check: func(dm map[string]string) (bool, float64, float64, string, string) {
			pctV := readF(dm, "jvm_heap_used_pct")
			if pctV < 85 {
				return false, 0, 0, "", ""
			}
			return true, pctV, 85,
				fmt.Sprintf("Heap usage %s — old-gen sweeps will dominate CPU.", pct(pctV)),
				"Increase ES_HEAP_SIZE (≤ 32 GB cap due to compressed pointers); reduce field-data and shard count if relevant."
		},
	},
	{
		id:       "es.unassigned.shards",
		appType:  "elasticsearch",
		severity: "crit",
		title:    "Unassigned shards — cluster health red/yellow",
		check: func(dm map[string]string) (bool, float64, float64, string, string) {
			n := readF(dm, "unassigned_shards")
			if n < 1 {
				return false, 0, 0, "", ""
			}
			return true, n, 1,
				fmt.Sprintf("%.0f shards unassigned — data unavailable or under-replicated.", n),
				"GET _cluster/allocation/explain — usually disk full / failed node / mapping conflict."
		},
	},
	{
		id:       "es.pending.tasks",
		appType:  "elasticsearch",
		severity: "warn",
		title:    "Cluster has pending tasks",
		check: func(dm map[string]string) (bool, float64, float64, string, string) {
			n := readF(dm, "pending_tasks")
			if n < 5 {
				return false, 0, 0, "", ""
			}
			return true, n, 5,
				fmt.Sprintf("%.0f pending cluster tasks — master is queueing state changes.", n),
				"GET _cluster/pending_tasks — if many index-creation tasks, throttle index template usage; if stuck on master, check master node health."
		},
	},
}

// ── Nginx rules ─────────────────────────────────────────────────────────────

var nginxRules = []appRule{
	{
		id:       "nginx.5xx.rate",
		appType:  "nginx",
		severity: "crit",
		title:    "5xx rate elevated",
		check: func(dm map[string]string) (bool, float64, float64, string, string) {
			rate := readF(dm, "status_5xx_rate")
			if rate < 1 {
				return false, 0, 0, "", ""
			}
			return true, rate, 1,
				fmt.Sprintf("%.1f 5xx responses per second — upstream errors or nginx itself failing.", rate),
				"Check upstream health and access.log for the failing path. 502/504 = upstream timeout; 503 = limit_req triggered."
		},
	},
	{
		id:       "nginx.4xx.rate",
		appType:  "nginx",
		severity: "warn",
		title:    "4xx rate elevated",
		check: func(dm map[string]string) (bool, float64, float64, string, string) {
			rate := readF(dm, "status_4xx_rate")
			if rate < 5 {
				return false, 0, 0, "", ""
			}
			return true, rate, 5,
				fmt.Sprintf("%.0f 4xx responses per second — clients sending bad requests or auth failures.", rate),
				"grep ' 401\\| 403\\| 404 ' /var/log/nginx/access.log — could be a probe / missing route."
		},
	},
	{
		id:       "nginx.upstream.timeout",
		appType:  "nginx",
		severity: "crit",
		title:    "Upstream timeouts",
		check: func(dm map[string]string) (bool, float64, float64, string, string) {
			rate := readF(dm, "upstream_timeout_rate")
			if rate < 0.1 {
				return false, 0, 0, "", ""
			}
			return true, rate, 0.1,
				fmt.Sprintf("%.2f upstream timeouts per second — backend can't keep up.", rate),
				"Check upstream service health (CPU, queue depth). proxy_read_timeout may need adjustment but root cause is usually backend slowness."
		},
	},
	{
		id:       "nginx.workers.busy",
		appType:  "nginx",
		severity: "warn",
		title:    "Workers near saturation",
		check: func(dm map[string]string) (bool, float64, float64, string, string) {
			active := readF(dm, "active_connections")
			limit := readF(dm, "worker_connections")
			workers := readF(dm, "worker_processes")
			if limit <= 0 || workers <= 0 {
				return false, 0, 0, "", ""
			}
			cap := limit * workers
			util := safeRatio(active, cap) * 100
			if util < 70 {
				return false, 0, 0, "", ""
			}
			return true, util, 70,
				fmt.Sprintf("%.0f active connections / %.0f cap (%s).", active, cap, pct(util)),
				"Increase worker_connections / worker_processes if CPU has room, or front with a queue-aware LB."
		},
	},
}

// summarizeAppRCA returns a short one-line summary for the trace narrative
// or status line — useful when many findings exist and we want to call out
// the worst.
func summarizeAppRCA(findings []model.AppRCAFinding) string {
	if len(findings) == 0 {
		return ""
	}
	var crit, warn int
	for _, f := range findings {
		switch f.Severity {
		case "crit":
			crit++
		case "warn":
			warn++
		}
	}
	parts := []string{}
	if crit > 0 {
		parts = append(parts, fmt.Sprintf("%d crit", crit))
	}
	if warn > 0 {
		parts = append(parts, fmt.Sprintf("%d warn", warn))
	}
	if len(parts) == 0 {
		parts = append(parts, fmt.Sprintf("%d info", len(findings)))
	}
	return "App RCA: " + strings.Join(parts, ", ")
}
