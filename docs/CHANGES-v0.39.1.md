# xtop 0.37.4 → 0.39.0 — Change Report

Everything that shipped, shaped by what you'll actually see and do differently.

## TL;DR

- **4 new subcommands**: `hub`, `fleet`, `postmortem`/`pm`, `cost`/`rightsize`, `baseline`
- **1 new flag family** on the main TUI: `--fleet-hub`, `--fleet-token`
- **7 new RCA enhancements** that appear automatically inside every incident box — no new page to learn, no flag to enable
- **1 new web dashboard** at `http://your-hub:9898/`
- Zero breaking changes to existing TUI pages, keybindings, or output modes

## Verification status

| Layer | Status |
|---|---|
| Unit tests (59 new), race detector, `go vet`, `go build` | ✅ all clean |
| Postmortem / cost / baseline subcommands smoke-tested with synthetic data | ✅ |
| Hub + agents over HTTPS under real load | ⚠️ not yet run end-to-end |
| Web dashboard in a browser | ⚠️ not validated |
| Kubepods resolver on a real k8s node | ⚠️ not validated |
| Log tailer / config drift / OTel correlator against real feeds | ⚠️ synthetic only |

Integration soak against a real fleet is its own follow-up task.

---

## Before → After, feature by feature

### 1. Fleet / multi-host (tasks 35 + 47–51)

**Before**
- xtop ran on one server. To check 10 servers you SSH'd to each.
- No cross-host incident view, no shared history, no alerting source of truth.

**After**
- One **hub process** collects heartbeats and incidents from every agent.
- **Web dashboard** at `http://hub:9898/` shows all hosts as cards, colored by health, live-streaming over SSE.
- **TUI fleet view**: `xtop fleet --hub=... --token=...` → the same table in your terminal, with keyboard-only navigation.
- **JSON API**: `GET /v1/hosts`, `/v1/host/{name}`, `/v1/incidents?hours=24`, `/v1/stream` (SSE).

**What you'll see in the web UI**

```
┌──────────────────────────────────────────────────────────┐
│  xtop  fleet     ● streaming live · 4 hosts · updated…  │
├──────────────────────────────────────────────────────────┤
│ Hosts                              [filter…] [☐unhealthy]│
│ ┌──────────────┐ ┌──────────────┐ ┌──────────────┐       │
│ │ db-prod-01   │ │ web-prod-03  │ │ cache-01     │       │
│ │ [critical]   │ │ [ok]         │ │ [ok]         │       │
│ │ io · 88%…    │ │ no bottleneck│ │ no bottleneck│       │
│ │ cpu 42 mem 71│ │ cpu 9  mem 33│ │ cpu 18 mem 60│       │
│ │ seen 3s ago  │ │ seen 3s ago  │ │ seen 3s ago  │       │
│ └──────────────┘ └──────────────┘ └──────────────┘       │
│                                                          │
│ Recent Incidents                     [last 24h ▾]        │
│ host          bottleneck  peak  conf  culprit   when     │
│ db-prod-01    io          88%   92%   mysqld    4m ago   │
│ web-prod-03   cpu         72%   84%   nginx     2h ago   │
└──────────────────────────────────────────────────────────┘
```

Click any card → side drawer with the same host's full stats + "vs history" panel + recent incidents table.

**How to use**

```bash
# On the hub server, one-time setup:
export XTOP_PG_PASSWORD=$(openssl rand -hex 16)
export XTOP_HUB_TOKEN=$(openssl rand -hex 24)
docker compose -f packaging/hub/docker-compose.yml up -d

# On every monitored server:
sudo xtop --fleet-hub=https://hub.example:9898 --fleet-token=$XTOP_HUB_TOKEN
```

Port **9898** is the default. Override with `--listen=:NNNN` or `XTOP_HUB_LISTEN`.

---

### 2. Incident diff — "is this worse than usual?" (task 37)

**Before**
The RCA box said something like:
```
CRITICAL · cpu · 82%
Culprit: mysqld (PID 3241)
Evidence:
  - runqueue latency elevated
  - CPU saturation 4/4 cores
```
…but you had no idea if this happened yesterday too.

**After**
Same RCA box, one new line at the top:
```
RCA · CRITICAL · cpu · 82%
  vs history: +13 pts worse than usual (median 69%) · new signals: swap_churn
  Culprit: mysqld (PID 3241)
  ...
```

And a new `result.IncidentDiff` is populated, which the web drawer and `xtop postmortem` render in detail:

```
vs history (matched 4 past incidents)
  Severity:      +13 pts vs median 69%
  Repeat Culprit: mysqld (3/4 incidents)
  New Signals:   swap_churn
  Time-of-Day:   3/4 prior matches occurred at this hour
```

Everything is **automatic** — no action required, as long as you've been running xtop long enough to build a history file.

---

### 3. Config drift detection (task 45)

**Before**
If someone edited `/etc/nginx/nginx.conf` 8 minutes before an incident, you had to figure that out from `last -a`, shell history, or git blame.

**After**
Top of the RCA box now shows:
```
CONFIG CHANGED 8m before degradation: /etc/nginx/nginx.conf
```

Covers ~60 paths out of the box: sysctl, limits, fstab, systemd units, cron, and common server configs (nginx/apache/mysql/postgres/redis/elasticsearch/haproxy/docker/netplan).

- First run is silent — establishes a baseline at `~/.xtop/config-baseline.json`.
- On every scan (30 s) only changes since the baseline emit events.
- When an incident fires and a config changed within 30 minutes, the newest file is shown inline.

**Extend it**: `XTOP_CONFIG_WATCH=/etc/my-app/:/opt/custom.conf xtop`

---

### 4. Operator runbook library (task 42)

**Before**
No way to encode "if mysql fires on IO, here's what to run." You either remembered or re-learned.

**After**
Drop markdown files into `~/.xtop/runbooks/` and xtop surfaces the matching one inline:

```
RUNBOOK: MySQL slow-query / IO pressure  (~/.xtop/runbooks/mysql-slow-queries.md)
```

File format (frontmatter + markdown body):

```markdown
---
name: MySQL slow-query / IO pressure
bottleneck: io, cpu
app: mysql, mariadb
culprit: mysqld, mariadbd
---

## Diagnosis
...
## Fix
...
```

Match scoring: bottleneck +4, app substring +3, culprit substring +2, each evidence ID +1, signature exact match +5. Runbooks with a field that **doesn't** match are disqualified — no false fires.

**Starter library** ships at `packaging/runbooks/`:
- `nginx-worker-saturation.md`
- `mysql-slow-queries.md`
- `memory-swap-thrash.md`
- `disk-io-saturation.md`

Copy those into `~/.xtop/runbooks/` on first install.

Hot-reloads every 60 s — edit a runbook, no restart.

---

### 5. Post-mortem tooling (task 41)

**Before**
After an incident resolved, you could grep `~/.xtop/rca-history.jsonl` by hand.

**After**
```
$ sudo xtop pm
  xtop postmortem — 20 most-recent incidents
  #    ID                      STARTED              BOTTLENECK  SCORE  DUR     CULPRIT
  @1   20260419-1430-cpu-cpu_  2026-04-19 14:30:00  cpu         95.0   4m00s   nginx
  @2   20260419-0915-cpu-cpu_  2026-04-19 09:15:00  cpu         76.0   2m00s   nginx
  @3   20260418-1400-cpu-cpu_  2026-04-18 14:00:00  cpu         82.0   2m30s   nginx
```

```
$ sudo xtop pm @1
  SUMMARY
    Bottleneck:  cpu
    Peak Score:  95
    Confidence:  92%
    Culprit:     nginx
    Pattern:     nginx worker saturation

  TIMELINE
    Started:     2026-04-19 14:30:00 UTC
    Ended:       2026-04-19 14:34:00 UTC
    Duration:    4m00s
    Hour-of-Day: 14:30 (UTC)

  EVIDENCE AT PEAK
    - runqueue latency elevated
    - CPU saturation 4/4 cores
    - swap_churn new
    (firing IDs: runqlat_high, cpu_saturation, swap_churn)

  VS HISTORY (matched 2 past incidents)
    Severity:       +13 pts vs median 82%
    Repeat Culprit: nginx (2/2 incidents)
    New Signals:    swap_churn

  RECENT SIMILAR (2)
    04-19 09:15  score=76   dur=2m00s  culprit=nginx
    04-18 14:00  score=82   dur=2m30s  culprit=nginx

  MATCHING RUNBOOK
    Nginx worker saturation  (score 10)
    ~/.xtop/runbooks/nginx-worker-saturation.md

    ## Diagnosis
      Nginx workers are saturated. The most common causes are:
      ...
```

Output modes: ANSI (default), `--md` for tickets/PRs, `--json` for scripts.

---

### 6. VM right-sizing report (task 46)

**Before**
No idea whether you should resize your VM until the cloud bill arrived.

**After**
xtop now writes `~/.xtop/usage-history.jsonl` — one compact rollup per minute (max / p95 / p50 / avg across CPU, mem, IO, load). Call:

```
$ sudo xtop cost --days 7

  xtop cost — 7-day right-sizing report

  COVERAGE
    Samples:         10080 minutes (7.0d of data)
    Range:           2026-04-12 23:00 → 2026-04-19 23:00
    Coverage:        100% of expected minutes
    Current size:    8 vCPU · 32 GiB RAM

  UTILIZATION
             state   p50 max   p95 max   peak      avg
    CPU %    cold    18%       22%       31%       9%
    Mem %    cold    28%       33%       41%       22%
    IO %     idle    5%        8%        15%       3%
    Load/CPU cold    0.22      0.28      0.45      0.14

  RECOMMENDATION  DOWNSIZE
    - CPU: p95 max 22% / peak 31% — headroom above 40% is ample.
    - Memory: p95 max 33% / peak 41% — fits comfortably after a downsize.

    8 vCPU → 4 vCPU (~50% compute cost)
    Halving vCPUs typically halves compute cost...
```

Four verdict states: **HOLD** · **DOWNSIZE** · **UPSIZE** · **INSUFFICIENT_DATA**.

Conservative by design:
- Downsize requires ≥72 h of data AND p95 < 35% CPU AND p95 < 45% memory.
- Upsize fires on peak ≥90% OR p95 ≥70%.

`--md` for tickets, `--json` for scripts.

---

### 7. Known-good baselines (task 43)

**Before**
After a deploy, you had no structured way to say "the system used to behave like X, now it behaves like Y."

**After**
```
# Quiet Sunday, pre-deploy
$ sudo xtop baseline save pre-deploy --note "4.1.2 branch"
Saved baseline "pre-deploy" from 7.0d of data (100% coverage)
→ ~/.xtop/baselines/pre-deploy.json

# Deploy happens, week passes
$ sudo xtop baseline compare pre-deploy --days 3

  xtop baseline compare — "pre-deploy"
  BASELINE    saved 2026-04-12 22:00 (7.0d of 7d data)
              4.1.2 branch
  CURRENT     last 3d (3.0d of 4320m samples)
  VERDICT     DEGRADED

           baseline     current      delta        flag
  CPU p95  25%          55%          +30.0pp (+120%)  *
  MEM p95  35%          62%          +27.0pp (+77%)   *
  IO p95   10%          22%          +12.0pp (+120%)  *
  LOAD p95 0.35         0.85         +0.50 (+143%)    *

  * marked metrics moved materially (≥10pp or ≥25% relative)
```

Commit the baseline JSON into your infra repo; use `baseline import` to push the same reference to every host in the fleet.

Full command set:
```bash
xtop baseline save <name> [--days N] [--note "..."]
xtop baseline list
xtop baseline compare <name> [--days N] [--md | --json]
xtop baseline delete <name>
xtop baseline export <name> > baseline.json
xtop baseline import baseline.json
```

---

### 8. App-log correlation (task 36)

**Before**
RCA said "mysqld is the culprit." You then had to `tail -f /var/log/mysql/error.log` yourself.

**After**
Same RCA box, one new line:
```
SLOW from mysql @ mysql/error.log: [Warning] slow query took 5.2s: SELECT * FROM huge_table
```

Or an errored nginx:
```
ERROR from nginx @ nginx/error.log: upstream timed out while reading response from upstream, client: 1.2.3.4
```

Covers **nginx, apache/httpd, mysql/mariadb, postgresql, redis, elasticsearch, docker/containerd** out of the box. When a service writes to the systemd journal instead of a file, xtop falls back to `journalctl -u <unit> --since=2m`.

Rate-limited to once every 10 s per app, bounded at 25 ms wall-clock per tick — safe to leave on permanently. Log content never leaves the local machine (no fleet push).

---

### 9. Confidence calibration (task 38)

**Before**
The "Confidence: 85%" number was a static heuristic. If your workload was spiky it was over-confident; if it was quiet it was under-confident. You couldn't tell.

**After**
xtop now tracks per-bottleneck outcome labels as incidents resolve:
- **true positive**: lasted ≥30 s AND peak ≥60.
- **false positive**: resolved in <8 s AND peak <40.
- Everything else: excluded from the math.

After ≥5 labelled incidents for a given bottleneck, the raw confidence is multiplied by a factor between **0.85** (half of your incidents on this bottleneck were noise) and **1.10** (you're reliably right).

**What you'll see**: the confidence number just becomes more honest over time. No UI change.

Calibration state is persisted to `~/.xtop/confidence-calibration.json` so it survives restarts.

---

### 10. CUSUM change-point tuning (task 40)

**Before**
Change-point detection used one set of thresholds (K=0.5σ, H=4σ) for everything. Packet-drop metrics — which are **naturally spiky** — churned the baseline on every minor blip, producing false change-points.

**After**
Each evidence metric is now classified as **normal** / **right-skewed** / **bimodal**, and CUSUM uses a different tuning for each:

| distribution   | K mul  | H mul  | example metrics                        |
|----------------|--------|--------|----------------------------------------|
| normal         | 0.5    | 4.0    | CPU%, memory%, load average            |
| right-skewed   | 1.0    | 6.0    | tcp_retrans, packet drops, OOM kills   |
| bimodal        | 0.75   | 5.0    | PSI pressure signals                   |

All six knobs are env-tunable without rebuild:
```
XTOP_CUSUM_NORMAL_K, XTOP_CUSUM_NORMAL_H
XTOP_CUSUM_SKEW_K,   XTOP_CUSUM_SKEW_H
XTOP_CUSUM_BIMODAL_K, XTOP_CUSUM_BIMODAL_H
```

**What you'll see**: fewer "phantom" change-point resets on spiky metrics → baselines stay warmer longer → anomaly detection is more trustworthy.

---

### 11. Kubernetes pod-aware view (task 39)

**Before**
On a k8s node, the cgroup page showed opaque slices like `/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod9e5d1e42_b8f4_4f7a_9a67_7c9a4e3f21ab.slice`.

**After**
The same cgroup is now labeled:
```
default/api-server-78b5f:api-server   QoS=Burstable
```

Works for:
- cgroup v2 with systemd driver (`.slice/.scope`)
- cgroup v2 with cgroupfs driver (`/kubepods/<qos>/pod<uid>/<container>`)
- cgroup v1 (legacy)

Namespace + pod name are resolved by reading `/var/log/pods/` if it's present; pod UID + QoS come from the cgroup path alone (works even without kubelet logs).

Available anywhere xtop shows a cgroup: CGroups page, process table, RCA culprit line.

---

### 12. OpenTelemetry trace correlation (task 44)

**Before**
If you run Jaeger/Tempo, the slow trace that caused an incident sat in a different UI.

**After**
Point your OTel collector at `~/.xtop/otel-samples.jsonl` (one `TraceSample` JSON per line), and xtop automatically correlates traces to active incidents:

```
TRACE: ERROR api GET /checkout took 1.24s (+3 more)
```

Plus a structured `result.TraceSamples` list (up to 5 samples, errors first, then by duration, scoped to the culprit service).

Minimal sample shape (what your collector needs to emit):
```json
{"trace_id":"abc123","service":"api","operation":"GET /checkout","duration_ms":1240,"status_code":"ERROR","start_time":"2026-04-19T14:30:05Z","url":"https://jaeger.example/trace/abc123"}
```

Override the feed path with `$XTOP_OTEL_SAMPLES_FILE`. Fully optional — silent no-op when no feed exists.

---

## New CLI surface (summary)

| command                              | purpose                                              |
|--------------------------------------|------------------------------------------------------|
| `xtop hub`                           | Start the central fleet aggregator (port 9898)       |
| `xtop fleet [--hub ...] [--token ...]` | Live multi-host TUI dashboard                      |
| `xtop fleet --once`                  | Single-shot JSON snapshot for scripts                |
| `xtop postmortem` (alias `pm`)       | List or render incident post-mortems                 |
| `xtop postmortem @1 --md`            | Markdown export for a ticket                         |
| `xtop cost` (alias `rightsize`)      | 7-day VM right-sizing report                         |
| `xtop baseline save/list/compare/...`| Named utilization baselines                          |

New **global flags** on the main TUI (applies to `sudo xtop` with no subcommand):
```
--fleet-hub=URL         push heartbeats/incidents to this hub
--fleet-token=TOKEN     auth token for the hub
--fleet-insecure        allow self-signed hub TLS (default true for first run)
```

---

## Files xtop now writes under `~/.xtop/`

```
~/.xtop/
├── agent-id                        # stable fleet-agent UUID (one-time generated)
├── rca-history.jsonl               # incident summaries (existed; now with evidence_ids)
├── config-baseline.json            # config-drift baseline (new)
├── usage-history.jsonl             # per-minute utilization rollups (new)
├── confidence-calibration.json     # learned per-bottleneck bias (new)
├── fleet-queue.jsonl               # offline hub-push queue (new)
├── baselines/
│   └── pre-deploy.json             # your saved baselines (new)
├── runbooks/                       # operator runbooks you drop here (new)
│   ├── nginx-worker-saturation.md
│   └── ...
└── otel-samples.jsonl              # OTel trace feed (optional, you write it)
```

Hub-side (when running `xtop hub`):
```
~/.xtop/
├── hub.json                        # hub config (optional; env/CLI also work)
├── hub-cache.sqlite                # hot cache (last 1h)
└── ...
```

---

## What the "incident" box shows today (end-to-end)

Concrete example — all new lines are **prepended to narrative evidence** so they just appear in every existing RCA renderer:

```
RCA · CRITICAL · cpu · 95% · Confidence 88%
Culprit: nginx (PID 2187)

  TRACE: ERROR api GET /checkout took 1.24s (+2 more)
  SLOW from nginx @ nginx/error.log: upstream timed out
  RUNBOOK: Nginx worker saturation  (~/.xtop/runbooks/nginx-worker-saturation.md)
  vs history: +13 pts worse than usual (median 82%) · new signals: swap_churn
  CONFIG CHANGED 8m before degradation: /etc/nginx/nginx.conf
  RECURRING: This pattern has fired 3 times in the last 24h — "nginx" is the repeat culprit (3/3)
  runqueue latency elevated (p99 = 48ms)
  CPU saturation 4/4 cores busy
  worker processes: 2  (system has 4 CPUs)
```

That's six new context sources + the original RCA evidence, all in one glance.

---

## How to upgrade

1. Pull and build: `CGO_ENABLED=0 go build -ldflags="-s -w -X github.com/ftahirops/xtop/cmd.Version=0.39.0" -o xtop .`
2. Copy to your servers (same as before).
3. Copy starter runbooks: `cp -r packaging/runbooks/*.md ~/.xtop/runbooks/`
4. (Optional) spin up the hub: `docker compose -f packaging/hub/docker-compose.yml up -d`, then point agents at it with `--fleet-hub=...`.

**No config migration required** — every new feature gracefully no-ops when its data file is missing. First run builds baselines silently.

---

## Quality bar

- **17/17 roadmap tasks complete** in v0.39.0.
- `go vet ./...` clean across the whole tree.
- `go test -race ./...` clean — all new goroutines (calibrator persistence, log tailer, trace polling, hub janitor, fleet-client worker) pass the race detector.
- **~5.6 KLOC** of new code, zero TODO/FIXME/HACK markers.
- All new persistence files use atomic write (tmp + rename).
- Path-traversal guards on every user-typed name.
- Log/trace content deliberately kept local — never sent to the fleet hub.
- No new runtime deps beyond the already-vendored `pgx` and `modernc.org/sqlite`.
