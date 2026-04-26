# xtop — complete usage guide

Everything xtop does, organized so you can look up a feature and find the exact
command, flag, data file, and UI surface. Companion to the top-level
[README.md](../README.md); that file pitches the tool, this one explains how
to drive it.

**Version**: 0.39.0 · **Platform**: Linux (kernel ≥ 5.x recommended) · **License**: MIT

---

## Table of contents

1. [Installation](#1-installation)
2. [Concepts](#2-concepts)
3. [The live TUI](#3-the-live-tui)
4. [Subcommands](#4-subcommands)
   - [`xtop` (main TUI)](#41-xtop-main-tui)
   - [`xtop why / top / proc`](#42-one-shot-diagnostics)
   - [`xtop doctor / app-doctor / discover / diagnose`](#43-health-checks)
   - [`xtop incidents / incident`](#44-daemon-incident-store)
   - [`xtop postmortem` / `pm`](#45-postmortem-rich-reports)
   - [`xtop cost` / `rightsize`](#46-cost-vm-right-sizing)
   - [`xtop baseline`](#47-baseline-known-good-snapshots)
   - [`xtop hub`](#48-hub-central-fleet-aggregator)
   - [`xtop fleet`](#49-fleet-multi-host-tui)
   - [`xtop export / flame / forensics / shell-init / tmux-status / cron-install`](#410-utilities)
5. [RCA engine — what the incident box is telling you](#5-rca-engine)
6. [Automatic enhancements (no configuration)](#6-automatic-enhancements)
7. [Operator-controlled enhancements (you provide data)](#7-operator-controlled-enhancements)
8. [Fleet architecture](#8-fleet-architecture)
9. [Web dashboard](#9-web-dashboard)
10. [Configuration reference](#10-configuration-reference)
11. [Environment variables](#11-environment-variables)
12. [Data files under `~/.xtop/`](#12-data-files)
13. [Security & privacy](#13-security--privacy)
14. [Troubleshooting](#14-troubleshooting)
15. [Upgrade notes](#15-upgrade-notes)

---

## 1. Installation

### Quick install (Debian/Ubuntu)
```bash
wget https://github.com/ftahirops/xtop/releases/download/v0.39.0/xtop_0.39.0-1_amd64.deb
sudo dpkg -i xtop_0.39.0-1_amd64.deb
sudo xtop
```

### Arch Linux
```bash
# From AUR — see packaging/archlinux/PKGBUILD
makepkg -si
```

### Build from source
```bash
git clone https://github.com/ftahirops/xtop.git
cd xtop
CGO_ENABLED=0 go build -ldflags="-s -w -X github.com/ftahirops/xtop/cmd.Version=0.39.0" -o xtop .
sudo install -Dm755 xtop /usr/local/bin/xtop
```

**Root required at runtime** for `/proc/*/io`, eBPF probes, and access to
`/sys/fs/cgroup/`. Running as a non-root user works but drops several metrics.

### First-run setup (recommended)

```bash
# Create config / data directories
mkdir -p ~/.xtop/{runbooks,baselines}

# Copy the starter runbook library
sudo cp /usr/share/xtop/runbooks/*.md ~/.xtop/runbooks/  # or from packaging/runbooks/
```

---

## 2. Concepts

- **Collector** — reads raw metrics each tick (CPU, memory, IO, network,
  cgroups, processes, apps, GPU, etc). Each collector is registered in
  `collector/collector.go`.
- **Tick** — one full collection + analysis cycle. Default interval: **3 s**.
- **Snapshot** — a single tick's data, passed to the analysis engine.
- **RateSnapshot** — computed deltas between two snapshots (CPU %, IO rates).
- **Analysis engine** — runs 4 bottleneck detectors (CPU / memory / IO /
  network), 68 evidence checks, 32 pattern matchers, and attaches narrative,
  diff, runbook, log excerpts, and trace samples.
- **Incident** — a period where `Health > OK`. Tracked, persisted to
  `rca-history.jsonl`, and matched against future incidents by signature.
- **Signature** — stable hash of `bottleneck | sorted-top-3-evidence-ids`.
  Used for similarity matching across time and hosts.
- **Confidence** — heuristic score (0–100) for how certain the RCA is. Now
  calibrated from historical outcomes.
- **Fleet / hub / agent** — multi-host mode. Hub is a central server;
  agents are regular `xtop` processes pushing heartbeats.

---

## 3. The live TUI

The core experience is `sudo xtop` — a Bubbletea TUI with 18 pages and 6
layout styles.

### Pages

| Key | Page | Purpose |
|-----|------|---------|
| 1 / overview | Overview | At-a-glance health + RCA box + recent activity |
| 2 / cpu | CPU | Per-core utilization, runqueue, frequency, PSI |
| 3 / mem | Memory | RAM + swap, cgroup breakdown, reclaim pressure |
| 4 / io | IO | Per-disk throughput, utilization, latency, writeback |
| 5 / net | Network | Interface rates, sockets, TCP stats, drops |
| 6 / cgroup | CGroups | systemd services + k8s pods with live metrics |
| 7 / timeline | Timeline | Score-over-time chart with incident markers |
| 8 / events | Events | Kernel/app events + recent activity |
| 9 / probe | Probe | eBPF probe status (sentinel/watchdog/deep-dive) |
| 0 / thresholds | Thresholds | Current alert thresholds |
| D | DiskGuard | Filesystem fullness + growth ETA |
| L | Security | Security watchdog output |
| W | Diagnostics | Per-service deep diagnostics |
| X | Intel | System profile + detection results |
| Y | Apps | Per-app health (databases, web servers, etc.) |
| O | Profiler | Server role + optimization audit |
| U | GPU | NVIDIA GPU metrics (via `nvidia-smi`) |
| (auto) | Proxmox | PVE node/VM/container overview |
| `/` | Picker | Fuzzy-searchable page picker |

### Layouts

| Key | Layout |
|-----|--------|
| A | Two-column |
| B | Compact |
| C | Adaptive |
| D | Grid |
| E | htop-style |
| F | btop-style |
| v | Cycle forward |
| V | Cycle backward |

### Key bindings

| Key | Action |
|-----|--------|
| `q` or `Ctrl-C` | Quit |
| `?` / `h` | Help overlay |
| `/` | Page picker |
| `S` | Save RCA as JSON |
| `H` | Export Dracula-themed HTML report → `~/.xtop/reports/` |
| `P` | Export markdown report |
| `N` | Verdict mode (colored badges on every metric) |
| `E` | Explain panel |
| `I` | Trigger deep-dive eBPF probe (off-CPU / IO latency / lock wait / TCP retrans) |
| `A` / `B` | Advanced / Beginner mode |
| `R` / `r` | Resume frozen view (DiskGuard) |
| `G` | Scroll down |

---

## 4. Subcommands

### 4.1 `xtop` (main TUI)

```
sudo xtop [flags]
```

| Flag | Default | Description |
|------|---------|-------------|
| `--interval <sec>` | 3 | Collection interval |
| `--history <n>` | 600 | Ring-buffer size (30 min at 3 s) |
| `--watch` | off | CLI mode, no TUI |
| `--section <name>` | overview | Section for `--watch` mode |
| `--count <n>` | 0 | Iterations for `--watch` (0 = infinite) |
| `--json` | off | Single JSON snapshot to stdout |
| `--md` | off | Single markdown incident report to stdout |
| `--daemon` | off | Background collector, no TUI |
| `--datadir <path>` | `~/.xtop/` | Data directory override |
| `--record <file>` | — | Record snapshots for replay |
| `--replay <file>` | — | Replay recorded snapshots |
| `--prom` | off | Enable Prometheus endpoint |
| `--prom-addr <addr>` | `127.0.0.1:9100` | Prometheus listen address |
| `--alert-webhook <url>` | — | Alert webhook URL |
| `--alert-command <cmd>` | — | Shell command to run on alerts |
| `--fleet-hub <url>` | — | Push heartbeats/incidents to hub |
| `--fleet-token <token>` | — | Hub auth token |
| `--fleet-insecure` | true | Allow self-signed hub certs |
| `--mask-ips` | off | Mask IP addresses in output (demos) |
| `--version` | — | Print version and exit |
| `--update` | — | Self-update from GitHub releases |

### 4.2 One-shot diagnostics

```bash
sudo xtop why                  # Plain-English RCA summary
sudo xtop why --json           # Same, as JSON
sudo xtop why --md             # Markdown incident report

sudo xtop top                  # Impact-scored process table (top 20)
sudo xtop top -n 10 --sort cpu # Top 10 by CPU impact
sudo xtop top --json           # Process table as JSON

sudo xtop proc 1234            # Deep report for a single PID
sudo xtop proc 1234 --json
```

All three collect **2 ticks** (≈6 s) and exit — safe for cron.

### 4.3 Health checks

```bash
sudo xtop --doctor             # Comprehensive system health check
sudo xtop --doctor --watch     # Continuous health mode
sudo xtop --app-doctor         # Deep app health analysis + saved report
sudo xtop --diagnose nginx     # Per-service deep diagnostics
sudo xtop --forensics          # Retroactive analysis from system logs
sudo xtop --discover           # Interactive server discovery & tuning
```

Doctor mode supports `--cron` (silent when OK) and `--alert` (fire on state
change) for use as a monitoring check.

### 4.4 Daemon incident store

When the daemon is running (`--daemon`), incidents are persisted to the
SQLite store at `~/.xtop/incidents.db`:

```bash
sudo xtop incidents                      # List recent incidents
sudo xtop incidents --fingerprint abc123 # Filter by pattern fingerprint
sudo xtop incidents --json
sudo xtop incident <id>                  # Full report
sudo xtop incident <id> --md             # Markdown (ticket-ready)
```

This store is separate from `~/.xtop/rca-history.jsonl` — the JSONL log is
used by `xtop postmortem` and the history-aware RCA enhancements.

### 4.5 Postmortem — rich reports

```bash
sudo xtop postmortem                     # List recent incidents (@1=newest)
sudo xtop pm @1                          # Full ANSI report for the most recent
sudo xtop pm @3 --md                     # 3rd-most-recent, markdown
sudo xtop pm 20260419-1430-cpu-cpu_      # By full ID
sudo xtop pm 20260419 --json             # Prefix match + JSON
```

Assembles: summary, timeline, evidence-at-peak, root cause, vs-history diff,
recent similar incidents, and any matching runbook inline.

### 4.6 Cost — VM right-sizing

```bash
sudo xtop cost                # 7-day ANSI report
sudo xtop cost --days 30      # Monthly
sudo xtop cost --md           # Markdown
sudo xtop cost --json         # Machine-readable
sudo xtop rightsize --days 14 # Same thing, alternative name
```

Four verdicts: **HOLD** · **DOWNSIZE** · **UPSIZE** · **INSUFFICIENT_DATA**.

Requires ≥ 72 h of `~/.xtop/usage-history.jsonl` data (auto-collected while
xtop runs).

### 4.7 Baseline — known-good snapshots

```bash
# Save current utilization stats as a baseline
sudo xtop baseline save pre-deploy --days 7 --note "Quiet Sunday"

# List saved baselines
sudo xtop baseline list

# Compare current state to a saved baseline
sudo xtop baseline compare pre-deploy --days 3
sudo xtop baseline compare pre-deploy --md  # markdown output

# Share / version-control / replicate
sudo xtop baseline export pre-deploy > pre-deploy-baseline.json
sudo xtop baseline import pre-deploy-baseline.json

# Remove
sudo xtop baseline delete pre-deploy
```

Verdicts: STABLE · DEGRADED · IMPROVED · MIXED.

### 4.8 Hub — central fleet aggregator

```bash
sudo xtop hub                            # Reads ~/.xtop/hub.json
sudo xtop hub --listen=:9898 --token=... --postgres="postgres://..."
sudo xtop hub --print-config             # Show effective config, exit
```

**Config precedence** (highest to lowest):

1. CLI flags
2. Environment variables
3. `~/.xtop/hub.json`
4. Built-in defaults (listen `:9898`)

See [§8 Fleet architecture](#8-fleet-architecture) for deployment.

### 4.9 Fleet — multi-host TUI

```bash
# Live dashboard (needs a running hub)
xtop fleet --hub=https://hub:9898 --token=$TOKEN

# Using env / config defaults
XTOP_FLEET_HUB=https://hub:9898 XTOP_FLEET_TOKEN=... xtop fleet

# Single JSON snapshot (scripting / CI)
xtop fleet --hub=... --token=... --once

# Refresh cadence
xtop fleet --hub=... --token=... --refresh 2s
```

Streams from the hub's SSE endpoint, reconnects with exponential backoff,
sorts unhealthy hosts first, color-codes by state.

### 4.10 Utilities

```bash
sudo xtop --record snapshots.jsonl       # Record for later analysis
sudo xtop --replay snapshots.jsonl       # Replay a recording

xtop --shell-init bash >> ~/.bashrc      # Health widget in your prompt
xtop --shell-init zsh  >> ~/.zshrc
xtop --tmux-status                       # Tmux status segment
xtop --cron-install                      # Print crontab line for daily check

xtop flame <pid> 30 -o flame.html        # 30s flame graph for a PID
xtop flame <pid> 30 --ascii              # ASCII flame graph in terminal

xtop --forensics                         # Reconstruct past incidents from logs
xtop export ...                          # Export snapshot data (see --help)
```

---

## 5. RCA engine

The incident box — shown on every page, not just Overview — is the heart of
xtop. In v0.39.0 it can contain up to **eight** different kinds of evidence
lines, automatically assembled:

```
RCA · CRITICAL · cpu · 95% · Confidence 88%
Culprit: nginx (PID 2187)

  TRACE: ERROR api GET /checkout took 1.24s (+2 more)                 ← §7 OTel
  SLOW from nginx @ nginx/error.log: upstream timed out               ← §6 logs
  RUNBOOK: Nginx worker saturation (~/.xtop/runbooks/nginx-...)       ← §7 runbooks
  vs history: +13 pts worse than usual · new signals: swap_churn      ← §6 diff
  CONFIG CHANGED 8m before degradation: /etc/nginx/nginx.conf         ← §6 drift
  RECURRING: fired 3× in 24h — "nginx" is the repeat culprit (3/3)    ← §6 history
  runqueue latency elevated (p99 = 48ms)                              ← base RCA
  CPU saturation 4/4 cores busy                                       ← base RCA
```

### Bottlenecks

- **CPU** — saturation, runqueue latency, iowait, throttling, context-switch rate
- **Memory** — allocation pressure, swap churn, direct reclaim, OOM risk
- **IO** — utilization, latency, writeback stalls, PSI
- **Network** — drops, retransmits, conntrack/ephemeral exhaustion,
  bandwidth saturation

### Verdict badges (N key — verdict mode)

A small colored badge (GOOD / WARN / CRIT) appears next to every metric on
every page, colored by its own threshold. Metrics are never hidden —
verdict mode only **adds** badges.

### eBPF probes

Three tiers auto-activate on demand:

| Tier | Purpose |
|------|---------|
| **Sentinel** (always on) | kfreeskb, tcpreset, sockstate, modload, oomkill, directreclaim, cgthrottle, execsnoop, ptracedetect + tcpretrans/tcpconnlat |
| **Watchdog** (auto-triggered) | runqlat, wbstall, pgfault, swapevict, syscalldissect, sockio |
| **Deep dive** (press `I`) | offcpu, iolatency, lockwait, tcpretrans |

### Output as markdown / JSON

```bash
sudo xtop --md                 # Markdown for one tick
sudo xtop --json               # JSON for one tick
sudo xtop why --md             # Formal "why" incident report
```

---

## 6. Automatic enhancements (no configuration)

These are on by default. No flag, no file, no action — just run xtop.

### Incident history + diff

- Every incident that lasts > 10 s and peaks ≥ 30% is persisted to
  `~/.xtop/rca-history.jsonl`.
- Future incidents with the same **signature** (bottleneck + top-3 evidence
  IDs) are correlated: score delta, repeat-culprit detection, new/missing
  signals, time-of-day pattern.
- Appears inline: `vs history: +13 pts worse than usual · new signals: X`
- Queryable: `sudo xtop pm`

### Config drift detection

- First run snapshots ~60 curated `/etc/*` paths (and systemd units, cron,
  netplan, etc.) to `~/.xtop/config-baseline.json`.
- Every 30 s: stat-shortcut check; SHA256 when mtime moves.
- When an incident fires + a config changed within 30 min → inline:
  `CONFIG CHANGED 8m before degradation: /etc/nginx/nginx.conf`

**Customize the watchlist**: `XTOP_CONFIG_WATCH=/etc/my-app/:/opt/foo.conf xtop`

### App-log correlation

- When RCA fingers nginx/apache/mysql/postgres/redis/elasticsearch/docker,
  xtop tails the last 64 KiB of the app's error log.
- Severity regex filters ERROR/WARN/SLOW/OOM/TIMEOUT lines.
- Top 5 matches attached to `result.LogExcerpts`; first one shown inline.
- Systemd journal fallback (`journalctl -u <unit> --since=2m`) when no file
  matches.
- Rate-limited to once per 10 s per app, 25 ms wall-clock budget per tick.
- **Log content never leaves the host** — not pushed to the fleet hub.

### Recurrence detection

- After ≥ 2 matching past incidents: `Pattern seen N times before (last: Xm ago)`
- After ≥ 3 matches in 24 h: `RECURRING: fired N× in 24h`
- If one culprit appears in ≥ 2 matches: `"mysqld" is the repeat culprit (3/5 incidents)`

### Confidence calibration

- Incident outcomes are auto-labelled as incidents resolve:
  - **TP**: duration ≥ 30 s AND peak ≥ 60
  - **FP**: duration < 8 s AND peak < 40
  - else: indeterminate (excluded)
- After ≥ 5 labelled outcomes per bottleneck, confidence is multiplied by a
  factor in **[0.85, 1.10]** based on precision.
- Persisted to `~/.xtop/confidence-calibration.json`.

### CUSUM change-point tuning

- Each evidence metric is classified as normal / right-skewed / bimodal.
- CUSUM K and H thresholds now differ per distribution so packet-drop spikes
  don't churn the baseline.
- Tune via `XTOP_CUSUM_*` env vars (see [§11](#11-environment-variables)).

### Kubernetes pod resolution

- Cgroups under `kubepods.slice` (or the v1 equivalent) are automatically
  resolved to `namespace/pod:container` with QoS class.
- Appears in CGroups page, process table, RCA culprit line.
- No kubelet API access required — parses the cgroup path + reads
  `/var/log/pods/` if present.

### Per-minute utilization rollup

- Every minute, xtop summarizes max / p95 / p50 / avg for CPU / mem / IO /
  load-ratio into one line of `~/.xtop/usage-history.jsonl`.
- Drives the `cost` and `baseline` commands.
- ~150 bytes/minute; auto-pruned to 90 days.

---

## 7. Operator-controlled enhancements (you provide data)

### Runbook library

**File format**: markdown with small YAML-like frontmatter at
`~/.xtop/runbooks/*.md`.

```markdown
---
name: Nginx worker saturation
bottleneck: cpu, network
app: nginx
culprit: nginx
evidence: runqlat_high, conn_queue_overflow
min_score: 3
---

## Diagnosis
Check the worker count vs CPU cores:

```bash
nginx -T | grep worker_processes
nproc
```

## Fix
Set `worker_processes auto;` and reload nginx.
```

**Match scoring** (higher wins; runbook disqualified if any specified field misses):

| Field | Score |
|-------|-------|
| `bottleneck` exact | +4 |
| `app` substring | +3 |
| `culprit` substring | +2 |
| each matched `evidence` ID | +1 |
| `signature` exact | +5 |
| `min_score` | minimum to fire |

Hot-reloads every 60 s — edit and save, no restart.

**Starter library** ships in `packaging/runbooks/`:

- `nginx-worker-saturation.md`
- `mysql-slow-queries.md`
- `memory-swap-thrash.md`
- `disk-io-saturation.md`

### OpenTelemetry trace correlation

Point your existing OTel collector at a JSONL file:

**Default**: `~/.xtop/otel-samples.jsonl` (override with
`$XTOP_OTEL_SAMPLES_FILE`).

**Line format** (one JSON per line):
```json
{"trace_id":"abc","service":"api","operation":"GET /x","duration_ms":1240,"status_code":"ERROR","start_time":"2026-04-19T14:30:05Z","url":"https://jaeger/abc"}
```

See `packaging/otel/README.md` for a sample collector pipeline using the
`file` exporter.

**What xtop does**: polls the file every 5 s; during an active incident,
returns up to 5 samples — errors first, then by duration, scoped to the
culprit service when identifiable.

### Named baselines

See [§4.7](#47-baseline-known-good-snapshots). Commit baseline JSON files
into your infra repo to share "this is what normal looks like" across hosts.

---

## 8. Fleet architecture

```
┌──────────────┐     ┌──────────────┐     ┌──────────────┐
│ agent host A │     │ agent host B │     │ agent host C │
│  (xtop)      │     │  (xtop)      │     │  (xtop)      │
└──────┬───────┘     └──────┬───────┘     └──────┬───────┘
       │                    │                    │
       │  POST /v1/heartbeat (every 3 s)         │
       │  POST /v1/incident  (on state change)   │
       ▼                    ▼                    ▼
       ┌─────────────────────────────────┐
       │          xtop hub :9898         │
       │                                 │
       │  - Postgres (long-term)         │
       │  - SQLite (hot cache, 1h)       │
       │  - HTTP JSON API                │
       │  - SSE event stream             │
       │  - Embedded web dashboard       │
       └──────────────┬──────────────────┘
                      │
            ┌─────────┴──────────┐
            ▼                    ▼
     ┌─────────────┐      ┌─────────────┐
     │ Web browser │      │ xtop fleet  │
     │             │      │ (TUI)       │
     └─────────────┘      └─────────────┘
```

### Deployment (Docker)

```bash
# On hub host
export XTOP_PG_PASSWORD=$(openssl rand -hex 16)
export XTOP_HUB_TOKEN=$(openssl rand -hex 24)
export XTOP_HUB_PORT=9898   # optional

docker build -f packaging/hub/Dockerfile -t xtop-hub:latest .
docker compose -f packaging/hub/docker-compose.yml up -d
```

### Deployment (no Docker)

```bash
# Install Postgres 14+
createdb xtopfleet
createuser xtop --pwprompt

# Option A — config file
cat > ~/.xtop/hub.json <<EOF
{
  "listen_addr": ":9898",
  "auth_token": "<random>",
  "postgres_dsn": "postgres://xtop:<pw>@localhost:5432/xtopfleet?sslmode=disable"
}
EOF
sudo xtop hub

# Option B — env vars
XTOP_HUB_LISTEN=:9898 \
XTOP_HUB_TOKEN=<random> \
XTOP_HUB_POSTGRES="postgres://xtop:<pw>@localhost:5432/xtopfleet?sslmode=disable" \
sudo xtop hub
```

### Connect agents

```bash
sudo xtop --fleet-hub=https://hub.example:9898 --fleet-token=$XTOP_HUB_TOKEN
```

**NAT'd hosts**: use an SSH reverse tunnel rather than exposing the hub:
```bash
# From the NAT'd host, to a bastion that the hub trusts:
ssh -R 9898:localhost:9898 bastion.example
# Then the agent on the NAT'd host points at http://localhost:9898
```

### HTTP endpoints

| Method | Path | Auth | Purpose |
|--------|------|------|---------|
| POST | `/v1/heartbeat` | `X-XTop-Token` | Agent → hub, per tick |
| POST | `/v1/incident` | `X-XTop-Token` | Agent → hub, on incident state change |
| GET | `/v1/hosts` | optional | List all known hosts |
| GET | `/v1/host/{hostname}` | optional | Single host |
| GET | `/v1/incidents?hours=N&host=H&limit=N` | optional | Recent incidents |
| GET | `/v1/stream` | optional | SSE event stream (snapshot + heartbeat + incident) |
| GET | `/health` | no | Health check |
| GET | `/` | no | Web dashboard |

### Offline queue

Agents queue payloads in RAM when the hub is unreachable; overflow spills to
`~/.xtop/fleet-queue.jsonl`. On reconnect, oldest-first replay; 1 h stale
cutoff prevents a bottomless backlog.

### Retention

- Postgres heartbeats: **48 h** default (set `heartbeat_retention_hours` in config)
- Postgres incidents: **30 d** default (set `incident_retention_days`)
- SQLite hot cache: **1 h**
- Janitor runs every hour in the background

---

## 9. Web dashboard

Served by the hub at `http://<hub>:9898/`. Single-page app built with plain
JS (no framework, no build step), ~8 KB total after minification. All DOM
content is constructed via `document.createElement` + `textContent` — no
`innerHTML` with dynamic data, so there's zero XSS surface even if an agent
pushes a hostile hostname.

### Screens

- **Header bar**: live/disconnected indicator, host count, last-update time
- **Host cards**: one per host, color-coded by state; filterable by
  hostname / bottleneck / culprit; "unhealthy only" checkbox
- **Host drawer** (click a card): full stats + "vs history" panel + the
  host's 7-day incident log
- **Recent Incidents table**: filterable by window (1h / 6h / 24h / 7d)

### Live behavior

On page load:
1. Fetches `/v1/incidents?hours=24` for the table.
2. Connects to `/v1/stream` (SSE).
3. First SSE event is `snapshot` — seeds the host map.
4. Subsequent `heartbeat` events merge into the map; re-render is 5-second
   throttled.
5. `incident` events debounce a refresh of the incident table.

### Static assets

Embedded via `go:embed` — no CDN, no external fonts, works on air-gapped
networks.

---

## 10. Configuration reference

### `~/.xtop/config.json` (main xtop)

```json
{
  "interval_sec": 3,
  "history_size": 600,
  "section": "overview",
  "threshold_profile": "default",
  "prometheus": { "enabled": false, "addr": "127.0.0.1:9100" },
  "alerts": {
    "webhook": "",
    "command": "",
    "email": "",
    "slack_webhook": "",
    "telegram_bot_token": "",
    "telegram_chat_id": ""
  }
}
```

### `~/.xtop/hub.json` (hub)

```json
{
  "listen_addr": ":9898",
  "auth_token": "change-me",
  "postgres_dsn": "postgres://xtop:pw@localhost:5432/xtopfleet?sslmode=disable",
  "sqlite_cache_path": "/var/lib/xtop/hub-cache.sqlite",
  "incident_retention_days": 30,
  "heartbeat_retention_hours": 48,
  "tls_cert": "",
  "tls_key": ""
}
```

### `~/.xtop/fleet.json` (agent → hub)

```json
{
  "hub_url": "https://hub.example:9898",
  "token": "<random>",
  "tags": ["role=db", "env=prod"],
  "queue_path": "~/.xtop/fleet-queue.jsonl",
  "max_queue_size": 10000,
  "insecure_skip_verify": false
}
```

### `~/.xtop_secrets` (app-doctor credentials, optional)

JSON file with credentials for deeper app introspection (Elasticsearch
cluster auth, MySQL admin user, etc). Format documented in
`packaging/app-doctor/README.md`.

---

## 11. Environment variables

| Variable | Applies to | Purpose |
|----------|-----------|---------|
| `XTOP_HUB_LISTEN` | hub | Listen address (e.g. `:9898`) |
| `XTOP_HUB_POSTGRES` | hub | Postgres DSN |
| `XTOP_HUB_TOKEN` | hub | Auth token |
| `XTOP_HUB_TLS_CERT`, `XTOP_HUB_TLS_KEY` | hub | TLS cert paths |
| `XTOP_HUB_SQLITE_CACHE_PATH` | hub | SQLite cache path |
| `XTOP_HUB_PORT` | docker-compose | Convenience: container port |
| `XTOP_FLEET_HUB` | `xtop fleet` | Default hub URL |
| `XTOP_FLEET_TOKEN` | `xtop fleet` | Default auth token |
| `XTOP_CONFIG_WATCH` | main TUI | Extra config-drift paths (`:`-separated) |
| `XTOP_OTEL_SAMPLES_FILE` | main TUI | OTel JSONL feed path |
| `XTOP_CUSUM_NORMAL_K` / `_H` | main TUI | CUSUM tuning for normal-dist metrics |
| `XTOP_CUSUM_SKEW_K` / `_H` | main TUI | CUSUM tuning for right-skewed metrics |
| `XTOP_CUSUM_BIMODAL_K` / `_H` | main TUI | CUSUM tuning for bimodal metrics |

---

## 12. Data files

All under `~/.xtop/` (or `--datadir` target).

```
~/.xtop/
├── config.json                  # main TUI config
├── agent-id                     # stable UUID (fleet identity)
├── incidents.db                 # daemon-mode SQLite (if --daemon used)
├── rca-history.jsonl            # JSONL incident log (foreground mode)
├── config-baseline.json         # config-drift fingerprint baseline
├── usage-history.jsonl          # per-minute utilization rollups
├── confidence-calibration.json  # learned per-bottleneck bias
├── fleet-queue.jsonl            # offline hub-push overflow
├── otel-samples.jsonl           # optional OTel trace feed
├── baselines/
│   ├── pre-deploy.json          # your named baselines
│   └── prod-normal.json
├── runbooks/
│   ├── nginx-worker-saturation.md
│   ├── mysql-slow-queries.md
│   └── ...
└── reports/                     # HTML exports (H key)
    └── xtop-report-<timestamp>.html
```

Hub-side (when running `xtop hub`):
```
~/.xtop/
├── hub.json                     # hub config
├── hub-cache.sqlite             # SQLite hot cache
```

All JSON writes use atomic tmp + rename. Path-traversal guards on every
user-typed name (baseline names, runbook filenames, hub config path).

---

## 13. Security & privacy

### Single-host

- Runs as root to read `/proc/*/io` and attach eBPF probes — this is
  unavoidable for the kind of visibility xtop provides.
- No outbound network traffic by default; the tool is entirely offline.
- `--mask-ips` redacts IP addresses for screenshots/demos.
- eBPF programs are kernel-verified; sentinel set is always-on, watchdogs
  and deep-dives are opt-in/triggered.

### Fleet

- All agent → hub traffic uses HTTPS when the hub is started with
  `--tls-cert` / `--tls-key`.
- Auth is a shared bearer token sent as `X-XTop-Token`. Rotate by restarting
  the hub with a new token and updating agents; there's no dynamic rotation
  yet.
- **Log content (`LogExcerpts`) and trace content (`TraceSamples`) are
  never pushed to the hub** — only numeric metrics, bottleneck name,
  culprit process/app, and structured evidence IDs.
- The hub stores raw heartbeat/incident JSON in Postgres. If that's a
  concern, enable row-level encryption on the Postgres side.

### Web dashboard

- Zero-XSS-surface DOM construction (no `innerHTML` with dynamic data).
- Long-cache headers on `/static/*`; `no-store` on the HTML shell.
- Same `X-XTop-Token` gate when an auth token is set.

---

## 14. Troubleshooting

### "No RCA shown — just metrics"

The engine needs **two ticks** before it can compute rates and run RCA. With
the default 3 s interval, that's 6 s after startup. If you still see
nothing after 10 s:

- Check `/proc/pressure/*` exists (kernel ≥ 4.20).
- Confirm you're running as root.
- Look at the Probe page (key `9`) — sentinel probes should show as attached.

### "Collection interval shows as 1 s instead of 3 s"

Legacy config migration: a stale `~/.xtop/config.json` from an old version
had `interval_sec: 1`. xtop v0.37.3+ auto-upgrades that field to 3 on
startup. If yours didn't, delete the line or the whole file.

### "Hub unreachable — agents queue forever"

Queue is capped at 10 000 messages and spills to
`~/.xtop/fleet-queue.jsonl`. When disk usage is a concern, truncate that file;
the agent will lose the backlog but keep running.

### "fleet view shows 'disconnected'"

`xtop fleet` reconnects with exponential backoff (up to 30 s). Check:
- `curl -H "X-XTop-Token: $TOKEN" http://hub:9898/health` — should return
  `{"ok":true, "hosts":N}`.
- Firewall: hub's port (9898) reachable from the fleet-view client.
- Token matches between hub and agent.

### "Web dashboard loads, 'disconnected'"

Same as above. Browser SSE connections share the same auth cookie path.
Open devtools → Network → `/v1/stream` should be `200` and stay open.

### "Kubernetes pods show as raw slice names"

- Confirm xtop is running on the k8s node, not inside a pod.
- Check `/var/log/pods/` readable by xtop's user (root).
- Regex patterns in `collector/cgroup/kubepods.go` cover the common kubelet
  drivers; unusual container runtimes may need a patch — open an issue.

### "Runbook doesn't fire"

Check `sudo xtop pm @1` — if the incident's bottleneck/app/culprit don't
match any of your runbook's gating fields, it's disqualified. The "LOAD"
column on `xtop pm` shows the top matched runbook.

### "Config drift emits lots of noise on first run"

Expected — the baseline is empty, so xtop has to snapshot every current
file. v0.38.2+ silently establishes the baseline (zero events on first
scan); upgrade if you're on an earlier build.

---

## 15. Upgrade notes

| Version | Highlights |
|---------|-----------|
| **v0.39.0** | Confidence calibration, CUSUM tuning, k8s pod view, OTel correlation; code-quality audit pass |
| **v0.38.7** | App-log correlation |
| **v0.38.6** | Known-good baseline save/compare/export/import |
| **v0.38.5** | Cost / VM right-sizing report |
| **v0.38.4** | Post-mortem tooling (`xtop pm`) |
| **v0.38.3** | Runbook library |
| **v0.38.2** | Config drift detection |
| **v0.38.1** | Incident diff ("vs history") |
| **v0.38.0** | Fleet hub + agents + web dashboard (Phases 1–5) |
| **v0.37.4** | Config auto-migration (interval=1 → 3) |
| **v0.37.3** | Verdict-mode polish |
| **v0.37.2** | Two-column gap closure |
| **v0.37.1** | ELK page redesign |

### Migrating from < v0.38

- Run once and let it build `~/.xtop/config-baseline.json` (silent).
- Copy starter runbooks if desired: `cp packaging/runbooks/*.md ~/.xtop/runbooks/`
- Existing `rca-history.jsonl` records will be missing the `evidence_ids`
  field — the diff engine falls back to legacy-format parsing, no manual
  migration needed.

### Migrating from < v0.39

- Port default changed 9200 → **9898**. Update your hub CLI / config /
  firewall rules.
- `FleetIncident.Diff` is a new optional field; older hubs silently drop it
  — forward-compatible wire format.
- No on-disk format changes for `rca-history.jsonl` or
  `usage-history.jsonl`.

---

## Getting help

- Bug reports / feature requests: https://github.com/ftahirops/xtop/issues
- Commercial support / deployment help: mtahir5060@gmail.com
- Project index & architecture notes: [`PROJECT_INDEX.md`](../PROJECT_INDEX.md)
- Release notes: [`CHANGES-v0.39.0.md`](CHANGES-v0.39.0.md)

---

*Last updated for xtop v0.39.0 · 2026-04-20*
