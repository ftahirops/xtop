# Apps Diagnostics Design

## Overview

Auto-detect running applications and show deep health diagnostics. `A` key opens the Apps page with a list of detected apps. Enter drills into per-app detail view with the deepest possible metrics.

## Detection

Zero-config process detection via comm/cmdline matching. Only shows actively running apps.

| App | Detection | Port |
|-----|-----------|------|
| Nginx | comm=`nginx` | 80/443 |
| Apache | comm=`httpd`/`apache2` | 80/443 |
| HAProxy | comm=`haproxy` | config |
| Caddy | comm=`caddy` | 80/443 |
| Traefik | comm=`traefik` | 80/443 |
| MySQL/MariaDB | comm=`mysqld`/`mariadbd` | 3306 |
| PostgreSQL | comm=`postgres` (main) | 5432 |
| MongoDB | comm=`mongod`/`mongos` | 27017 |
| Redis | comm=`redis-server` | 6379 |
| Elasticsearch | java + cmdline `elasticsearch` | 9200 |
| Docker | comm=`dockerd` | unix socket |
| RabbitMQ | comm=`beam.smp` + `rabbit` | 5672 |
| Kafka | java + cmdline `kafka` | 9092 |
| Memcached | comm=`memcached` | 11211 |

Multiple instances: detected by separate PIDs listening on different ports. Shown as `mysql (1)`, `mysql (2)`.

## Two-Tier Metrics

### Tier 1 (no credentials — always available)
- Process: CPU%, RSS, threads, FDs, open connections from `/proc/net/tcp`
- Config file parsing: max_connections, buffer sizes, listen ports
- Uptime, PID, port, version (from cmdline/binary)

### Tier 2 (with credentials — deep metrics)
Credentials stored in `~/.config/xtop/secrets.json` (mode 0600).

| App | Method | Key Metrics |
|-----|--------|-------------|
| MySQL | `SHOW GLOBAL STATUS`, `SHOW PROCESSLIST` | QPS, slow queries, connections, replication lag, buffer pool hit%, InnoDB row ops |
| PostgreSQL | `pg_stat_activity`, `pg_stat_database` | active queries, tx/s, cache hit%, replication lag, dead tuples, locks |
| MongoDB | `db.serverStatus()`, `rs.status()` | ops/s, connections, replication lag, wiredTiger cache |
| Redis | `INFO` command | ops/s, hit ratio, memory used/max, evictions, replication lag |
| Elasticsearch | `/_cluster/health`, `/_nodes/stats` | cluster status, shards, heap%, indexing rate |
| RabbitMQ | HTTP API `/api/overview` | messages ready/unacked, publish/deliver rates |

Apps without DB protocols (Nginx, Apache, HAProxy, Docker, Caddy, Traefik, Memcached, Kafka) get full metrics from config files, `/proc`, status pages, or unix sockets.

### Secrets File Format

```json
{
  "mysql": {"host": "127.0.0.1", "port": 3306, "user": "monitor", "password": "xxx"},
  "postgresql": {"host": "127.0.0.1", "port": 5432, "user": "monitor", "password": "xxx", "dbname": "postgres"},
  "mongodb": {"uri": "mongodb://user:pass@127.0.0.1:27017"},
  "redis": {"host": "127.0.0.1", "port": 6379, "password": ""},
  "rabbitmq": {"host": "127.0.0.1", "port": 15672, "user": "guest", "password": "guest"},
  "elasticsearch": {"url": "http://127.0.0.1:9200", "user": "", "password": ""}
}
```

When a DB is detected without credentials, show hint:
`MySQL detected — add credentials to ~/.config/xtop/secrets.json for deep metrics`

## UI

### Key Binding
`A` — opens Apps Diagnostics page (replaces current `A` if conflicting)

### App List View (default)
```
APPS DIAGNOSTICS                                     14 detected
────────────────────────────────────────────────────────────────
 #  APP              STATUS   CPU%   RSS     CONNS   HEALTH
 1  nginx            active   2.1%   45M     1.2K    100
 2  mysql (1)        active   15.2%  2.1G    48       85
    └─ 12 slow queries/min — check slow_query_log
 3  redis            active   1.2%   128M    22      100

j/k:navigate  Enter:drill down  Esc:back
```

- Issue line only when health < 100 with root-cause explanation
- j/k navigate, Enter drills into detail, Esc returns

### App Detail View (per-app)
Each app has a tailored detail layout. Example for MySQL:
```
MYSQL (1)  PID:4521  up:45d  port:3306                  85
────────────────────────────────────────────────────────────────
 PROCESS       CPU: 15.2%  RSS: 2.1G  Threads: 42  FDs: 380
 CONNECTIONS   Active: 48/151 max  Aborted: 3/s
 QUERIES       QPS: 1,240  Slow: 12/min  Select: 68%  Insert: 22%
 INNODB        Buffer hit: 99.2%  Row ops: 8.4K/s
 REPLICATION   Role: replica  Lag: 0.2s  IO: running  SQL: running

 └─ 12 slow queries/min — check slow_query_log
```

### Docker Detail View (special)
```
DOCKER  v24.0.7  12 containers (10 up, 2 stopped)
────────────────────────────────────────────────────────────────
 DAEMON        CPU: 4.5%  RSS: 890M  Goroutines: 142
 IMAGES        38 total  12.4G  5 dangling
 VOLUMES       18 total  8.2G

 CONTAINER     STATUS  CPU%   RSS     NET I/O      HEALTH
 app-web-1     UP 45d  12.1%  512M    1.2/0.8M     healthy
 worker-1      UP 3d   45.2%  1.8G    —            unhealthy
   └─ health check failing
```

Docker uses `/var/run/docker.sock` API directly — no external deps.

## Architecture

```
collector/apps/
  module.go          AppModule interface
  manager.go         AppManager (Collector, 30s detect, per-tick collect)
  detect.go          process scanning + port checking
  secrets.go         ~/.config/xtop/secrets.json loader
  mod_nginx.go       Nginx module
  mod_apache.go      Apache module
  mod_haproxy.go     HAProxy module
  mod_caddy.go       Caddy module
  mod_traefik.go     Traefik module
  mod_mysql.go       MySQL/MariaDB module
  mod_postgresql.go  PostgreSQL module
  mod_mongodb.go     MongoDB module
  mod_redis.go       Redis module
  mod_elasticsearch.go  Elasticsearch module
  mod_docker.go      Docker module (unix socket API)
  mod_rabbitmq.go    RabbitMQ module
  mod_kafka.go       Kafka module
  mod_memcached.go   Memcached module

model/apps.go        AppMetrics, AppInstance, AppDetail types
ui/page_apps.go      App list + detail rendering
```

## Health Scoring

Same philosophy as Proxmox: only flag actual degradation.
- Slow queries alone: not an issue unless query latency is spiking
- High memory: not an issue unless evictions or OOM
- Replication lag: only flag if > threshold (e.g., > 5s)
- Connection count: only flag if approaching max_connections

## Non-Goals (v1)
- No log parsing (too heavy, use dedicated log tools)
- No query analysis (show counts, not individual queries)
- No auto-tuning recommendations (just show what's wrong)
