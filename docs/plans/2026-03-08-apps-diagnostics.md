# Apps Diagnostics Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Auto-detect 14 applications (nginx, apache, haproxy, caddy, traefik, mysql, postgresql, mongodb, redis, elasticsearch, docker, rabbitmq, kafka, memcached) and show deep health diagnostics on a dedicated `Y` key page.

**Architecture:** Follow the existing RuntimeModule pattern in `collector/runtime/`. New `collector/apps/` package with AppModule interface, AppManager collector, per-app modules. Two-tier metrics: Tier 1 (process-level, zero config) always available, Tier 2 (protocol-level, needs credentials from `~/.config/xtop/secrets.json`) unlocks deep metrics. UI page with app list view + per-app drill-down.

**Tech Stack:** Go, raw TCP/unix socket connections for DB protocols, HTTP for REST APIs, `/proc` filesystem for process metrics.

---

## Phase 1: Foundation (model + manager + secrets + UI shell)

### Task 1: Model types

**Files:**
- Create: `model/apps.go`

```go
package model

// AppInstance represents a detected application instance.
type AppInstance struct {
    ID           string            // "mysql-1", "nginx-0"
    AppType      string            // "mysql", "nginx", etc.
    DisplayName  string            // "MySQL (1)", "Nginx"
    PID          int
    Port         int
    Status       string            // "active"
    Version      string
    UptimeSec    int64

    // Tier 1: process-level (always available)
    CPUPct       float64
    RSSMB        float64
    Threads      int
    FDs          int
    Connections  int               // from /proc/net/tcp

    // Tier 2: deep metrics (needs credentials)
    HasDeepMetrics bool
    DeepMetrics    map[string]string // app-specific key-value pairs

    // Health
    HealthScore  int
    HealthIssues []string

    // Config hints
    ConfigPath   string            // detected config file path
    NeedsCreds   bool              // true if deep metrics available but no creds
}

// AppMetrics holds all detected application instances.
type AppMetrics struct {
    Instances []AppInstance
}
```

Add to `GlobalMetrics` struct in `model/metrics.go`:
```go
Apps AppMetrics
```

### Task 2: Secrets loader

**Files:**
- Create: `collector/apps/secrets.go`

Load `~/.config/xtop/secrets.json` (mode 0600). Return empty map if not found (not an error). Reload every 60s. Structure:

```go
type AppSecrets struct {
    MySQL         *DBCreds
    PostgreSQL    *PGCreds
    MongoDB       *MongoCreds
    Redis         *RedisCreds
    RabbitMQ      *RabbitCreds
    Elasticsearch *ESCreds
}

type DBCreds struct {
    Host     string `json:"host"`
    Port     int    `json:"port"`
    User     string `json:"user"`
    Password string `json:"password"`
}
// ... etc per the design doc
```

### Task 3: AppModule interface + AppManager

**Files:**
- Create: `collector/apps/module.go`
- Create: `collector/apps/manager.go`

Follow `collector/runtime/module.go` and `manager.go` patterns exactly.

```go
// module.go
type AppModule interface {
    Type() string                                    // "mysql", "nginx"
    DisplayName() string                             // "MySQL", "Nginx"
    Detect(processes []model.ProcessMetrics) []DetectedApp
    Collect(app *DetectedApp, secrets *AppSecrets) model.AppInstance
}

type DetectedApp struct {
    PID     int
    Port    int
    Comm    string
    Cmdline string
    Index   int    // instance number (0-based)
}
```

Manager: 30s detection scan, per-tick collection. Populates `snap.Global.Apps`.

### Task 4: Process-level helpers

**Files:**
- Create: `collector/apps/prochelpers.go`

Shared helpers for all Tier 1 modules:
- `countTCPConnections(port int) int` — parse `/proc/net/tcp` for connections to a port
- `readProcessCPU(pid int) float64` — read from snap.Processes
- `detectVersion(pid int) string` — try `--version` output or binary strings
- `findConfigFile(paths []string) string` — return first existing path

### Task 5: Register AppManager in engine

**Files:**
- Modify: `engine/engine.go` — add `apps.NewManager()` after runtime manager registration

### Task 6: UI page shell — app list view

**Files:**
- Modify: `ui/app.go` — add `PageApps` to page enum, `Y` key binding, render dispatch
- Create: `ui/page_apps.go` — app list + detail rendering

Model fields needed in `ui/app.go`:
```go
appsSelectedIdx int       // cursor position in app list
appsDetailMode  bool      // true = showing detail for selected app
```

Page rendering: if `appsDetailMode` → render detail for selected app, else render app list table.

Key bindings on Apps page:
- `j`/`k` — navigate app list
- `Enter` — drill into detail
- `Esc` — back to list (or back to overview if on list)

---

## Phase 2: Web server modules (no credentials needed)

### Task 7: Nginx module

**Files:**
- Create: `collector/apps/mod_nginx.go`

Detection: comm=`nginx`, master process (PPID=1 or systemd). Count worker processes.
Config: parse `/etc/nginx/nginx.conf` for `worker_processes`, `worker_connections`.
Tier 1: CPU%, RSS (sum of workers), thread count, connections from `/proc/net/tcp` port 80/443.
Health: only flag if workers crashed (fewer than configured) or FDs near limit.

### Task 8: Apache module

**Files:**
- Create: `collector/apps/mod_apache.go`

Detection: comm=`httpd` or `apache2`.
Config: parse `/etc/httpd/conf/httpd.conf` or `/etc/apache2/apache2.conf` for `MaxRequestWorkers`, `ServerLimit`.
Tier 1: CPU%, RSS, worker count, connections.

### Task 9: HAProxy module

**Files:**
- Create: `collector/apps/mod_haproxy.go`

Detection: comm=`haproxy`.
Tier 1: CPU%, RSS, connections. Parse stats socket if available (`/var/run/haproxy/admin.sock` or from config).
Deep (no creds needed): HAProxy stats socket gives backend/frontend stats, session rates, error rates, health checks.

### Task 10: Caddy module

**Files:**
- Create: `collector/apps/mod_caddy.go`

Detection: comm=`caddy`.
Tier 1: CPU%, RSS, connections.
Deep: admin API at `localhost:2019/config/` (default, no auth).

### Task 11: Traefik module

**Files:**
- Create: `collector/apps/mod_traefik.go`

Detection: comm=`traefik`.
Tier 1: CPU%, RSS, connections.
Deep: API at `localhost:8080/api/overview` (default dashboard).

---

## Phase 3: Database modules (credentials unlock deep metrics)

### Task 12: Redis module

**Files:**
- Create: `collector/apps/mod_redis.go`

Detection: comm=`redis-server`. Port from cmdline or default 6379.
Tier 1: CPU%, RSS, connections from `/proc/net/tcp`.
Tier 2 (with password): raw TCP `INFO` command → parse response.
Key metrics: ops/sec, hit_ratio, used_memory/maxmemory, evicted_keys, connected_clients, replication role/lag.
Health: flag if evictions > 0, memory > 90% of max, replication lag > 5s.

### Task 13: MySQL module

**Files:**
- Create: `collector/apps/mod_mysql.go`

Detection: comm=`mysqld` or `mariadbd`. Port from cmdline or 3306.
Tier 1: CPU%, RSS, threads, connections from `/proc/net/tcp`.
Config: parse `/etc/mysql/my.cnf` or `/etc/my.cnf` for `max_connections`, `innodb_buffer_pool_size`.
Tier 2 (with creds): use `database/sql` + `go-sql-driver/mysql` → `SHOW GLOBAL STATUS`, `SHOW PROCESSLIST`.
Key metrics: QPS (Queries), slow_queries, Threads_connected/max_connections, Innodb_buffer_pool_read_requests vs reads (hit%), Seconds_Behind_Master.
Health: flag slow queries > 10/min, connections > 80% max, buffer hit < 95%, replication lag > 10s.

### Task 14: PostgreSQL module

**Files:**
- Create: `collector/apps/mod_postgresql.go`

Detection: comm=`postgres` (postmaster process, PPID=1). Port from cmdline or 5432.
Tier 1: CPU%, RSS (sum of backends), connections from `/proc/net/tcp`.
Config: parse `postgresql.conf` for `max_connections`, `shared_buffers`.
Tier 2 (with creds): use `database/sql` + `lib/pq` → `pg_stat_activity`, `pg_stat_database`, `pg_stat_replication`.
Key metrics: active queries, tx/s, cache hit ratio, dead tuples, replication lag, locks waiting.
Health: flag cache hit < 95%, dead tuples > 10K, replication lag > 10s, connections > 80% max.

### Task 15: MongoDB module

**Files:**
- Create: `collector/apps/mod_mongodb.go`

Detection: comm=`mongod` or `mongos`. Port from cmdline or 27017.
Tier 1: CPU%, RSS, connections from `/proc/net/tcp`.
Tier 2 (with URI): raw TCP MongoDB wire protocol → `serverStatus` command, `replSetGetStatus`.
Key metrics: opcounters (insert/query/update/delete/s), connections current/available, replication lag, wiredTiger cache dirty%, globalLock.
Health: flag replication lag > 5s, cache dirty > 20%, connections > 80% available.

### Task 16: Elasticsearch module

**Files:**
- Create: `collector/apps/mod_elasticsearch.go`

Detection: java process + cmdline contains `elasticsearch` or `org.elasticsearch`. Port 9200.
Tier 1: CPU%, RSS, connections.
Tier 2 (with url): HTTP GET `/_cluster/health`, `/_nodes/stats`.
Key metrics: cluster status (green/yellow/red), active shards, unassigned shards, heap%, GC time, indexing rate, search latency.
Health: flag cluster yellow/red, heap > 85%, unassigned shards > 0.

### Task 17: Memcached module

**Files:**
- Create: `collector/apps/mod_memcached.go`

Detection: comm=`memcached`. Port from cmdline or 11211.
Tier 1: CPU%, RSS, connections.
Tier 2 (no creds needed): raw TCP `stats\r\n` command.
Key metrics: get_hits/get_misses (hit ratio), curr_connections, evictions, bytes used/limit_maxbytes.
Health: flag hit ratio < 80%, evictions > 0, memory > 90%.

---

## Phase 4: Message queues + Docker

### Task 18: RabbitMQ module

**Files:**
- Create: `collector/apps/mod_rabbitmq.go`

Detection: comm=`beam.smp` + cmdline contains `rabbit`. Port 5672/15672.
Tier 1: CPU%, RSS, connections.
Tier 2 (with creds): HTTP GET `http://host:15672/api/overview` with basic auth.
Key metrics: messages ready/unacked, publish/deliver rate, connections, queue count, node memory.
Health: flag messages_unacked > 10K, memory alarm, disk alarm.

### Task 19: Kafka module

**Files:**
- Create: `collector/apps/mod_kafka.go`

Detection: java + cmdline contains `kafka.Kafka` or `kafka-server-start`.
Tier 1: CPU%, RSS, connections on port 9092.
Tier 2: no standard simple API without client library. Use JMX-over-HTTP if jolokia present, else Tier 1 only.
Key metrics (if JMX): messages/s, bytes in/out, under-replicated partitions, ISR shrinks.

### Task 20: Docker module

**Files:**
- Create: `collector/apps/mod_docker.go`

Detection: comm=`dockerd` + `/var/run/docker.sock` exists.
Tier 1: dockerd CPU%, RSS.
Tier 2 (no creds — unix socket): HTTP over unix socket to Docker Engine API.
- `GET /containers/json?all=true` → container list with status, names
- `GET /containers/{id}/stats?stream=false` → per-container CPU%, memory, net I/O
- `GET /images/json` → image count, total size
- `GET /volumes` → volume count
- `GET /info` → docker version, total containers, images

Key metrics per container: status, CPU%, RSS, net rx/tx, health check status.
Health: flag unhealthy containers, containers with restart policy that keep restarting, exited with error.

---

## Phase 5: UI detail views

### Task 21: Per-app detail renderers

**Files:**
- Modify: `ui/page_apps.go` — add detail view renderers

Each app type gets a `renderAppDetail_<type>()` function that renders the drill-down view.
Layout follows existing patterns: `boxSection()`, `styledPad()`, `bar()`, color thresholds.

Generic detail renderer for apps without custom layout.
Custom detail renderers for: MySQL, PostgreSQL, MongoDB, Redis, Docker, Elasticsearch.

### Task 22: Credential hint + template generation

**Files:**
- Modify: `ui/page_apps.go`

When a DB is detected without credentials:
```
  ℹ Add credentials to ~/.config/xtop/secrets.json for deep metrics
```

Add `Y` then `T` key to generate a template secrets file with detected apps pre-filled.

---

## Implementation Order

Build and verify after each phase:
1. Phase 1 (Tasks 1-6): foundation, empty page renders
2. Phase 2 (Tasks 7-11): web servers work immediately
3. Phase 3 (Tasks 12-17): databases with Tier 1 immediately, Tier 2 with creds
4. Phase 4 (Tasks 18-20): queues + docker
5. Phase 5 (Tasks 21-22): detail views + polish

Each phase: `go build ./...` + `go vet ./...` + deploy to test server.

---

## Dependencies

For Tier 2 DB connections:
- MySQL: `github.com/go-sql-driver/mysql` (or raw protocol)
- PostgreSQL: `github.com/lib/pq` (or raw protocol)
- MongoDB: raw wire protocol (avoid heavy `go.mongodb.org/mongo-driver`)
- Redis: raw RESP protocol (no library needed)
- Elasticsearch: `net/http` (REST API)
- RabbitMQ: `net/http` (REST API)
- Memcached: raw ASCII protocol (no library needed)
- Docker: `net/http` over unix socket (no library needed)

Recommendation: use raw protocols where simple (Redis, Memcached, Docker, ES, RabbitMQ).
Use `database/sql` drivers only for MySQL and PostgreSQL (complex wire protocols).
MongoDB: use raw wire protocol for `serverStatus` (single command, avoid 50MB driver dependency).
