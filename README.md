<p align="center">
  <img src="https://img.shields.io/badge/xtop-v0.46.2-00d4aa?style=for-the-badge&logo=linux&logoColor=white" alt="version"/>
  <img src="https://img.shields.io/badge/Go-1.25+-00ADD8?style=for-the-badge&logo=go&logoColor=white" alt="go"/>
  <img src="https://img.shields.io/badge/eBPF-Powered-ff6600?style=for-the-badge&logo=linux&logoColor=white" alt="ebpf"/>
  <img src="https://img.shields.io/badge/License-MIT-green?style=for-the-badge" alt="license"/>
  <img src="https://img.shields.io/badge/Platform-Linux-FCC624?style=for-the-badge&logo=linux&logoColor=black" alt="platform"/>
</p>

<h1 align="center">
  <br>
  xtop
  <br>
</h1>

<h3 align="center">
  <em>Stop monitoring. Start diagnosing.</em>
</h3>

<p align="center">
  <strong>The next-generation Linux performance console that doesn't just show <em>what</em> is happening —<br>
  it tells you <em>why</em> it's happening, <em>who</em> is causing it, and <em>how</em> to fix it.</strong>
</p>

<p align="center">
  <img src="assets/xtop-demo.gif" alt="xtop in action — RCA engine identifies bottleneck, culprit process, and suggests fix" width="100%"/>
</p>

<p align="center">
  <em>xtop detects the bottleneck, identifies the culprit process, and tells you exactly what to do.</em>
</p>

<p align="center">
  <a href="#quick-start"><b>Install Now</b></a> &nbsp;&bull;&nbsp;
  <a href="#the-problem">Why xtop?</a> &nbsp;&bull;&nbsp;
  <a href="#features">Features</a> &nbsp;&bull;&nbsp;
  <a href="#installation">Full Install Guide</a> &nbsp;&bull;&nbsp;
  <a href="#documentation">Docs</a>
</p>

---

## What's new in v0.46.2

- **Startup performance** — collectors now run concurrently, `DiagCollector` skips heavy subprocesses on first tick, and `SecurityCollector` `w` command has a 2s timeout. Fixes 10-second hangs on overloaded servers (load 500+).
- **Module profiles** — `xtop modules` subcommand with presets (minimal/standard/sre/investigation) and per-collector toggles.
- **Resource Guardian** — self-throttling and memory-pressure protection with automatic collector skip.
- **eBPF security watchdogs** — TC ingress classifiers for TLS fingerprinting, DNS tunneling, and C2 beacon detection.

## What's new in v0.39.1

- **Multi-host fleet hub** with live web dashboard at `http://hub:9898/` (`xtop hub`)
- **Fleet TUI** — browse every host's RCA from one terminal (`xtop fleet`)
- **Post-mortem reports** per incident (`xtop pm @1`)
- **VM right-sizing** report (`xtop cost`) + named **baselines** (`xtop baseline`)
- **Runbook library** — drop markdown files in `~/.xtop/runbooks/` and xtop shows the matching one inline
- **Auto-correlation** in every incident: config drift, app logs, OTel traces, past-incident diff
- **Kubernetes pod-aware** cgroup view (auto-detects `kubepods.slice`)
- **Confidence calibration** — RCA learns from incident outcomes

Full change log: [`docs/CHANGES-v0.39.1.md`](docs/CHANGES-v0.39.1.md) · Complete usage guide: [`docs/USAGE.md`](docs/USAGE.md)

---

## Table of Contents

- [The Problem](#the-problem) — Why traditional tools fail
- [How xtop Solves It](#how-xtop-solves-it) — What xtop answers in 5 seconds
- [Features](#features)
  - [Root-Cause Analysis Engine](#root-cause-analysis-engine) — 68 evidence checks, 4 bottleneck detectors
  - [RCA Decision Engine](#rca-decision-engine-v0310) — Narrative, pattern detection, temporal causality, blame
  - [Statistical RCA Intelligence](#statistical-rca-intelligence-v0310) — EWMA baselines, z-score anomaly, Pearson correlation, Holt forecasting, seasonal awareness, process profiling, golden signals, causal learning
  - [Health Levels](#health-levels) — OK / Inconclusive / Degraded / Critical
  - [17 Interactive Pages](#17-interactive-pages) — Overview, CPU, Memory, IO, Network, Cgroups, Timeline, Events, Probe, Thresholds, DiskGuard, Security, Logs, Services, Diagnostics, Intel, Apps, Proxmox
  - [6 Overview Layouts](#6-overview-layouts) — Two-Column, Compact, Adaptive, Grid, htop, btop
- [eBPF Deep Investigation](#ebpf-deep-investigation) — Off-CPU, IO latency, lock contention, TCP retransmits
- [eBPF Network Security Intelligence](#ebpf-network-security-intelligence-v0210) — SYN flood, port scan, DNS, C2 beacon, exfiltration
- [Predictive Exhaustion Warnings](#predictive-exhaustion-warnings) — Memory, swap, conntrack trend prediction
- [Anomaly Onset Tracking](#anomaly-onset-tracking) — Timestamped bottleneck origins
- [Network Intelligence](#network-intelligence) — Interface classification, TCP state analysis, conntrack
- [SMART Disk Health](#smart-disk-health) — Temperature, wear level, reallocated sectors
- [Incident Recording & Replay](#incident-recording--replay) — Flight recorder for postmortem
- [Event Detection](#event-detection) — Automatic incident detection and logging
- [Doctor Mode](#doctor-mode) — Comprehensive health check (CLI, JSON, Markdown, cron, alerts)
- [Application Diagnostics & RCA](#application-diagnostics--rca) — 15 auto-detected apps with deep health analysis
  - [Supported Applications](#supported-applications) — MySQL, PostgreSQL, Redis, Nginx, and 11 more
  - [Deep Metrics Collection](#deep-metrics-collection) — Tier 1 (process) + Tier 2 (protocol/CLI) metrics
  - [Credential Configuration](#credential-configuration) — ~/.xtop_secrets setup
- [Active Service Detection](#active-service-detection) — Auto-detect MySQL, Redis, Docker, K8s, etc.
- [Shell Health Widget](#shell-health-widget) — Bash/Zsh prompt integration
- [Cron Integration](#cron-integration) — Automated health checks
- [9 Output Modes](#9-output-modes) — TUI, watch, doctor, JSON, Markdown, daemon, record/replay, shell widget
- [Quick Start](#quick-start) — One-liner install
- [Installation](#installation) — .deb, .rpm, Arch Linux, from source, uninstall
- [Documentation](#documentation)
  - [CLI Reference](#cli-reference) — All flags and options
  - [Key Bindings](#key-bindings) — Keyboard shortcuts
  - [Data Sources](#data-sources) — 20+ Linux kernel interfaces
  - [Examples](#examples) — Usage examples
- [Configuration](#configuration)

---

## The Problem

You're on-call. A page fires at 3 AM. Your server is slow. **Now what?**

```
You open htop...           → 200 processes. Which one? Why?
You run top...             → CPU is 80%. So what? Is it user? system? steal? throttled?
You check iostat...        → Disk util 95%. Which cgroup? Which process? Is it the root cause or a symptom?
You run vmstat...          → Pages swapping. But why? Who allocated all the memory?
You try dmesg...           → OOM killer fired. 10 minutes ago. You're reading the past.
You open 6 more terminals... → ss, nstat, sar, perf, dstat, iotop...
```

**45 minutes later**, you're still correlating data from 12 different tools, none of which talk to each other, none of which tell you the actual root cause, and none of which tell you what to do about it.

**This is broken.**

Traditional Linux monitoring tools were designed in the 1990s for a world where one admin watched one server. They show you **raw numbers** and expect **you** to be the correlation engine. In production, that's not monitoring — that's archaeology.

---

## How xtop Solves It

**xtop** replaces the entire traditional troubleshooting workflow with a single command:

```bash
sudo xtop
```

Instead of 50+ fragmented tools, xtop gives you **one unified console** that:

| Traditional Approach | xtop Approach |
|---|---|
| Raw metrics across 12+ tools | **Unified dashboard** — all subsystems in one view |
| You manually correlate signals | **Automatic RCA engine** — correlates CPU, memory, IO, network, cgroups |
| "CPU is 80%" | **"CPU Contention: api-server throttled 34% in user.slice — Confidence: 72%"** |
| Read man pages for thresholds | **Evidence-based scoring** — 68 evidence checks, weighted formulas |
| Guess who's causing it | **Culprit attribution** — pinpoints the cgroup and PID responsible |
| Google for remediation | **Actionable suggestions** — tells you what commands to run |
| Lose context between snapshots | **Anomaly tracking** — "Started 62s ago, triggered by IO PSI spike" |
| No history, no replay | **Flight recorder** — record incidents, replay them later for postmortem |
| Plaintext stdout | **Incident reports** — one-command Markdown export for tickets |

### What xtop Answers in Under 5 Seconds

```
✦ What is the bottleneck?     → IO Starvation (score: 78%)
✦ Who is causing it?          → mysql (PID 14923) in db.slice
✦ How confident are we?       → 85% — 4/4 evidence groups confirmed
✦ How long has this been?     → Started 2m 14s ago, triggered by IO PSI full spike
✦ What should I do?           → iotop -oP | Check cgroup io.max for db.slice
✦ What's the causal chain?    → sda await 45ms → IO PSI full 12% → 3 D-state → load 8.2 → app latency risk
✦ What's next at risk?        → Memory at 78% — exhaustion in ~22 minutes at current trend
```

---

## Features

### Root-Cause Analysis Engine

The heart of xtop. Four parallel bottleneck detectors continuously score system health using **68 evidence checks** across **4 independent signal groups**:

| Bottleneck | Evidence Groups | What It Detects |
|---|---|---|
| **IO Starvation** | PSI, D-state tasks, Disk latency/util, Dirty pages | Storage-bound workloads, saturated disks, writeback storms |
| **Memory Pressure** | PSI, Available RAM, Swap activity, Direct reclaim, Major faults, OOM kills | Memory exhaustion, cache thrashing, swap storms, OOM events |
| **CPU Contention** | PSI, Run queue depth, Context switches, Cgroup throttling, CPU steal | Overcommitted CPUs, throttled containers, noisy neighbors, stolen cycles |
| **Network Overload** | Packet drops, TCP retransmits, Conntrack pressure, SoftIRQ overhead, TCP state anomalies, Errors | Saturated NICs, connection leaks, firewall table exhaustion |

**Trust Gating:** A bottleneck is only reported when **2+ independent evidence groups** confirm it. This eliminates false positives from single-metric spikes. Confidence scales from 30% (2 groups) to 98% (5+ groups).

### RCA Decision Engine (v0.39.1)

Beyond raw signals, xtop's **decision engine** tells you EXACTLY what's wrong, why, what caused it, and what to do:

- **Narrative Engine** — Human-readable root cause explanations replace raw metric names. Instead of "CPU Contention" you see *"CPU throttle cascade — cgroup limits saturating run queue"* with top evidence lines and impact summary
- **Pattern Detection** — 32 named failure patterns (OOM Crisis, Memory-Induced IO Storm, CPU Throttle Cascade, Disk IO Saturation, VM Noisy Neighbor, Network Congestion, Socket Leak, Conntrack Exhaustion, DDoS SYN Flood, Port Scan Attack, C2 Beacon Active, Data Exfiltration, Slab Leak, IRQ Imbalance, and more) checked by priority
- **Temporal Causality** — Tracks signal onset times to identify which signal fired first and builds chains like `retransmits (T+0s) → drops (T+3s) → threads blocked (T+12s)`
- **Blame Attribution** — Top offending processes per bottleneck domain with process-specific metrics (cpu%, threads, ctxsw, mem%, RSS, IO MB/s, CLOSE_WAIT count)
- **Security Evidence** — BPF sentinel and watchdog probes feed security-specific evidence (SYN flood, port scan, lateral movement, data exfiltration, DNS tunneling, C2 beacon) into the RCA scoring with dedicated threat score bypass
- **Statistical Intelligence** — EWMA baselines, z-score anomaly detection, Pearson cross-metric correlation, Holt double-exponential trend forecasting, seasonal hour-of-day awareness, per-process behavior profiling, and causal strength learning — all pure math, zero external dependencies
- **Application-Level RCA** — 15 auto-detected application modules with deep health diagnostics. Each module scores health from 100 down, applying weighted penalties for degraded metrics (e.g., MySQL buffer pool hit ratio < 95% = -15, PostgreSQL deadlocks > 0 = -10, HAProxy servers DOWN = -15 each). Total of **120+ application health rules** across all modules correlating internal app state with system-level bottlenecks

Press `e` (Explain) to see the full ROOT CAUSE → EVIDENCE → IMPACT → TEMPORAL CAUSALITY → TOP OFFENDERS breakdown.
Press `Y` to see per-application health diagnostics with deep metrics.

### Statistical RCA Intelligence (v0.39.1)

xtop doesn't just check thresholds — it **learns your system's normal behavior** and detects anomalies that static rules would miss. Eight statistical modules run continuously with zero configuration:

| Module | What It Does | How It Works |
|---|---|---|
| **EWMA Baselines** | Learns dynamic "normal" for every metric | Exponentially Weighted Moving Average with Welford's online variance — adapts to drift, flags deviations > 3σ |
| **Z-Score Anomaly** | Detects relative anomalies in sliding windows | 60-sample sliding window z-score — catches sudden spikes even when absolute values are normal |
| **Pearson Correlation** | Discovers cause-effect relationships between metrics | Streaming Pearson R across 20 pre-defined metric pairs — surfaces correlations |R| > 0.7 |
| **Holt Forecasting** | Predicts where metrics are heading | Double exponential smoothing with trend — "Memory exhaustion in ~22 minutes" with ETA-to-threshold |
| **Seasonal Awareness** | Learns recurring patterns by hour-of-day | Per-hour EWMA baselines suppress alerts for known patterns — "CPU always high at 2AM during backups" |
| **Process Profiling** | Detects when a process deviates from its own baseline | Per-Comm EWMA for CPU, memory, IO — flags when `mysql` suddenly uses 3x its normal CPU |
| **Golden Signals** | Google SRE signal approximation from /proc data | Latency (IO PSI + await), Traffic (net bytes + disk IOPS), Errors (retransmits + drops + OOM), Saturation (run queue + mem pressure + conntrack) |
| **Causal Learning** | Blends observed causality with hardcoded rules | Tracks rule prediction accuracy, blends 70% hardcoded + 30% observed weight (after 20+ observations) |

**Key design:**
- Pure math — zero external dependencies, no ML frameworks, no Python, no GPUs
- Online algorithms — constant memory, O(1) per update, no batch processing
- 100-sample warmup — baselines are silent until statistically meaningful
- Minimum stddev floor — prevents false anomalies on perfectly stable metrics
- Thread-safe — all trackers use `sync.RWMutex` for concurrent access

### Health Levels

| Level | Meaning | Action |
|---|---|---|
| **OK** | All evidence groups inactive | System healthy at 95% confidence |
| **INCONCLUSIVE** | Signals present but fewer than 2 evidence groups confirm | Possible issue — run eBPF probe for deeper investigation |
| **DEGRADED** | Score 25-59%, 2+ evidence groups | Active bottleneck identified — investigate culprit |
| **CRITICAL** | Score 60%+, 2+ evidence groups | Severe bottleneck — immediate action required |

---

### 17 Interactive Pages

| Key | Page | What You See |
|---|---|---|
| `0` | **Overview** | Health banner, PSI pressure bars, capacity headroom, resource owners, causal chain, RCA scores, trend sparklines |
| `1` | **CPU** | Utilization breakdown (user/sys/iowait/steal/softirq), cgroup CPU rankings, throttle detection, per-process CPU table |
| `2` | **Memory** | Full 13-category memory breakdown, active/inactive pages, swap status, vmstat counters, hugepages, cgroup + process memory rankings |
| `3` | **IO** | Per-device performance table (MB/s, IOPS, await, util%, queue depth), IO type analysis (sequential/random), raw counters, SMART disk health, D-state tracking |
| `4` | **Network** | Health verdict, aggregate throughput, TCP connection state distribution with visual bars, per-interface table with link state/speed/type/master detection, protocol health (TCP/UDP), conntrack usage, top consumers, kernel SoftIRQ overhead |
| `5` | **Cgroups** | Full sortable table of all cgroups — sort by CPU%, throttle%, memory, OOM kills, IO rate. Auto-detects cgroup v1/v2/hybrid |
| `6` | **Timeline** | 5-minute rolling ASCII sparkline charts — 16 time series across CPU, memory, IO, network |
| `7` | **Events** | Automatically detected incidents with timestamps, duration, peak scores, bottleneck type, culprit attribution |
| `8` | **Probe** | Real-time eBPF investigation results — off-CPU analysis, IO latency histograms, lock contention, TCP retransmit tracking |
| `9` | **Thresholds** | Live view of all RCA threshold values vs current readings — see exactly which checks are passing/failing |
| `D` | **DiskGuard** | Filesystem space monitor with auto-contain — SIGSTOP/SIGCONT top disk writers when mounts cross critical thresholds |
| `L` | **Security** | eBPF network security intelligence — 14 collapsible sections with threat detection, attack analysis, flow intelligence |
| `O` | **Logs** | Live system log viewer with filtering |
| `H` | **Services** | Active service health monitoring |
| `W` | **Diagnostics** | System diagnostics and troubleshooting |
| `X` | **Intel** | Impact scores, cross-signal correlation, runtime detection, SLO status, autopilot actions, incident history |
| `Y` | **Apps** | Application diagnostics — auto-detected MySQL, PostgreSQL, Redis, Nginx, Apache, HAProxy, PHP-FPM, MongoDB, Memcached, RabbitMQ, Kafka, Elasticsearch, Docker, Caddy, Traefik with deep health RCA |
| `Z` | **Proxmox** | Proxmox VE host dashboard — host CPU/RAM/load/PSI, network interfaces, disk IO/SMART health, VM status table, per-VM details, storage pools (auto-detected, hidden on non-PVE hosts) |

### 6 Overview Layouts

Switch instantly with `v` / `V` / `F1-F6`:

| Layout | Style | Best For |
|---|---|---|
| **Two-Column** (F1) | Subsystems left, owners + chain right | Daily monitoring, wide terminals |
| **Compact** (F2) | Dense single-column summary | Narrow terminals, quick glance |
| **Adaptive** (F3) | Healthy=1 line, unhealthy=expanded | Busy systems with mixed health |
| **Grid** (F4) | 2x2 subsystem dashboard | Executive overview, presentations |
| **htop** (F5) | htop-style process list | Familiar process monitoring |
| **btop** (F6) | btop-style resource dashboard | System resource overview |

Press `Ctrl+D` to save your preferred layout as the default.

---

### eBPF Deep Investigation

When the RCA engine identifies a bottleneck but you need **process-level proof**, press `I` to launch a 10-second eBPF probe. Four kernel-level packs run simultaneously:

| Probe Pack | Kernel Tracepoint | What It Reveals |
|---|---|---|
| **Off-CPU Analysis** | `sched_switch` | Which processes are being forced off-CPU, for how long, and why (futex lock, disk IO, network wait, epoll) |
| **IO Latency** | `block_rq_issue` + `block_rq_complete` | Per-device I/O latency distribution with P50/P95/P99 percentiles — identifies slow disks and heavy writers |
| **Lock Contention** | `sys_enter_futex` + `sys_exit_futex` | Which processes are blocked on mutex/futex locks, total wait time, contention hotspots |
| **TCP Retransmits** | `tcp_retransmit_skb` | Per-process retransmit counts with destination IP:port — identifies flaky network paths |

**Key design decisions:**
- Pure Go implementation via [cilium/ebpf](https://github.com/cilium/ebpf) — no CGo, no clang at runtime
- Filters out kernel threads, idle daemons, and the monitoring process itself
- Off-CPU probe tracks only **involuntary** off-CPU time (preemption + D-state), not voluntary sleep
- Graceful degradation: if one probe fails to attach, the others continue
- Results boost RCA confidence when they corroborate the detected bottleneck

---

### eBPF Network Security Intelligence (v0.21.0+)

Press `L` to open the **Security Monitor** — a dedicated page with 14 collapsible sections powered by always-on BPF sentinel probes and auto-triggered watchdog probes.

**Sentinel Probes (always-on, zero-config):**

| Probe | Kernel Hook | What It Detects |
|---|---|---|
| **SYN Flood** | `tcp_conn_request` | Distributed SYN floods — per-source-IP SYN rate and half-open ratio |
| **Port Scan** | `tcp_v4_send_reset` | Sequential/randomized port scans — unique port diversity from single source |
| **DNS Monitor** | `udp_sendmsg` + `udp_recvmsg` | DNS query anomalies — high query rates, unusual query lengths |
| **Connection Rate** | `inet_sock_set_state` | Lateral movement — processes connecting to unusually many unique destinations |
| **Outbound Volume** | `tcp_sendmsg` | Data exfiltration — large sustained outbound transfers to external IPs |

**Watchdog Probes (auto-triggered when sentinels detect anomalies):**

| Probe | Attachment | What It Inspects |
|---|---|---|
| **TCP Flags** | TC ingress classifier | XMAS, NULL, SYN+FIN — crafted packet detection |
| **DNS Deep** | TC ingress classifier | DNS tunneling indicators — TXT ratio, query length entropy |
| **TLS Fingerprint** | TC ingress classifier | JA3 fingerprinting — detect known C2 framework TLS signatures |
| **Beacon Detect** | `tcp_sendmsg` | C2 beacon detection — periodic low-jitter connection patterns |

**Security Page sections:** SSH/Auth, Listening Ports, SUID Anomalies, Process Executions, Ptrace Detection, Reverse Shells, Fileless Processes, Kernel Module Loads, Network Threat Overview, Attack Detection, DNS Intelligence, Flow Intelligence, TLS/Beacon Analysis.

**Smart filtering:** Loopback (127.x), private IPs (10.x, 172.16-31.x, 192.168.x), and xtop's own PID are automatically excluded. Proxy-aware thresholds prevent false positives on forward proxy servers.

---

### Predictive Exhaustion Warnings

xtop doesn't just tell you what's wrong **now** — it predicts what will go wrong **next**:

| Resource | What It Tracks | Alert |
|---|---|---|
| **Memory** | MemAvailable trend over 60 samples | "Memory exhaustion in ~22 minutes at current trend" |
| **Swap** | Swap usage growth rate | "Swap full in ~8 minutes" |
| **Conntrack** | Connection table growth | "Conntrack table full in ~15 minutes" |

Requires 30+ seconds of history. Fires when predicted exhaustion is under 60 minutes.

---

### Anomaly Onset Tracking

Every bottleneck is timestamped to its origin:

```
IO Starvation — Score: 72% — Started 2m 14s ago
  Triggered by: IO PSI full avg10 crossed 5% → currently 12.3%
  Culprit: mysql (PID 14923) — top consumer since 1m 48s
  Biggest change (30s): IO PSI full +8.2 percentage points
```

This eliminates the "how long has this been happening?" question that plagues traditional monitoring.

---

### Network Intelligence

xtop's network page goes far beyond `ifconfig` or `ip -s`:

- **Interface classification**: Automatically identifies physical, virtual, bridge, bond, veth, VLAN, tunnel, and WiFi interfaces
- **Bridge/bond slave detection**: If `enX1` shows 0 traffic because it's a bridge slave, xtop shows: `└─ slave of br0 — traffic counters may be on master`
- **Link state & speed**: Shows UP/DOWN status and negotiated speed for every interface
- **TCP state analysis**: Visual bars for all 9 connection states with anomaly thresholds (TIME_WAIT>5K, CLOSE_WAIT>100)
- **Conntrack monitoring**: Table usage percentage with exhaustion prediction
- **Protocol health**: TCP retransmit rate, UDP buffer errors, segment rates, SoftIRQ overhead

### SMART Disk Health

Page 3 (IO) includes physical disk health via `smartctl`:

- Health status (PASSED/FAILED)
- Temperature with thermal thresholds
- Wear level percentage (SSD/NVMe)
- Reallocated sector count (early failure indicator)
- Pending sector count (active failure indicator)
- Power-on hours
- Model identification

---

### Incident Recording & Replay

**Record** a live session as a flight recorder:
```bash
sudo xtop -record /var/log/xtop-incident.wlog
```

**Replay** it later for postmortem analysis — no root required:
```bash
xtop -replay /var/log/xtop-incident.wlog
```

Every snapshot is preserved with full fidelity: metrics, rates, RCA results, evidence checks, causal chains. Review exactly what the system looked like during the incident.

---

### Event Detection

xtop automatically detects and logs incidents:

- **Debounced transitions**: 3 consecutive non-OK ticks required to open an event (prevents flapping)
- **Per-event tracking**: Peak health level, peak RCA score, bottleneck type, culprit process/cgroup
- **Metrics captured**: Peak CPU%, peak memory%, peak IO PSI for each incident
- **Persistent logging**: Events written to `~/.xtop/events.jsonl` in daemon mode
- **Full audit trail**: Start time, end time, duration, evidence, causal chain

---

### Doctor Mode

Comprehensive health check that scans every subsystem in one shot:

```bash
sudo xtop -doctor                    # Beautiful aligned CLI report
sudo xtop -doctor -watch             # Auto-refreshing (like top)
sudo xtop -doctor -watch -interval 5 -count 3  # 3 iterations at 5s
sudo xtop -doctor -json              # Machine-readable JSON
sudo xtop -doctor -md                # Markdown for tickets
sudo xtop -doctor -cron              # Cron-friendly (silent if OK, exit codes)
sudo xtop -doctor -alert             # Send alerts on state changes
```

**What it checks:**

| Category | Checks |
|---|---|
| **CPU** | Utilization, load average (with IO-blocked decomposition), PSI pressure |
| **Memory** | Usage %, swap %, PSI, absolute available threshold |
| **Disk** | Per-mount usage, DiskGuard state, per-device latency/util, inode usage, PSI IO |
| **Network** | Overall health, TCP retransmits, drops, conntrack, CLOSE_WAIT leaks |
| **System** | File descriptors, systemd failed units, NTP sync, security updates pending |
| **Security** | Fileless process detection with forensic detail (exe, cmd, cwd, RSS, FDs, network connections) |
| **Docker** | Disk usage, container health |
| **SSL** | Let's Encrypt certificate expiration |
| **Services** | Auto-detected active services with deep health checks (MySQL, PostgreSQL, Redis, Docker, K8s, WireGuard) |

**Alert dispatch:** Supports webhooks, Slack, Telegram, email, and custom commands. Only fires on state changes (OK→WARN, WARN→CRIT, etc.) to prevent alert fatigue.

**Exit codes:** `0` = OK, `1` = warnings, `2` = critical — integrate directly into monitoring pipelines.

---

### Application Diagnostics & RCA

Press `Y` to open the **Apps** page — xtop auto-detects 15 applications and runs deep root-cause analysis on each. No agents, no plugins, no configuration required. If the process is running, xtop finds it and starts collecting.

#### How It Works

The RCA engine uses a **two-tier collection strategy**:

- **Tier 1 (always available)** — Process-level metrics from `/proc`: RSS memory, thread count, file descriptors, TCP connections, uptime. Works for every detected app with zero configuration.

- **Tier 2 (deep metrics)** — Protocol-level collection via native APIs, CLI tools, or raw protocol:
  - **MySQL**: `SHOW GLOBAL STATUS` (27 key variables), `SHOW PROCESSLIST`, `SHOW ENGINE INNODB STATUS`, `SHOW REPLICA STATUS`
  - **PostgreSQL**: `pg_stat_activity`, `pg_stat_database`, `pg_stat_bgwriter`, dead tuples, lock contention, replication lag
  - **Redis**: Raw RESP protocol `INFO ALL` + `SLOWLOG GET` — 80+ metrics including memory, latency percentiles (p50/p99/p99.9), replication lag, keyspace, persistence, command stats, fork timing, client capacity, plus workload-driven recommendations engine
  - **Elasticsearch**: REST API — cluster health, shard status, JVM heap, index counts, node stats
  - **MongoDB**: `mongosh` — serverStatus, WiredTiger cache, opCounters, lock queues, replication lag
  - **Nginx**: `stub_status` HTTP endpoint — active connections, accepts/handled/requests, reading/writing/waiting
  - **Apache**: `mod_status` endpoint — scoreboard analysis, request rates, worker utilization, MPM detection
  - **HAProxy**: Unix socket `show stat`/`show info`/`show sess` — CSV stats parsing, backend health, session rates, queue depth, latency breakdown (queue/connect/response/total), slow backend spotlight, retry & redispatch analysis, denied request tracking, peak vs current sessions, config warnings, server state change tracking, per-direction TCP state analysis, top IP breakdown, connection error RCA with per-backend blame
  - **PHP-FPM**: Pool config parsing + per-worker state analysis via `/proc/PID/stat` — active/idle workers, utilization, memory tracking
  - **RabbitMQ**: Management API — messages, queues, node resources, memory/disk alarms, consumer health
  - **Memcached**: Raw TCP `stats`/`stats slabs` — hit ratio, evictions, slab analysis, memory pressure
  - **Kafka**: Config parsing + CLI tools — broker ID, topic/group counts, log dir usage, JVM hsperfdata
  - **Caddy**: Admin API (`:2019`) — live config, upstream health, metrics
  - **Traefik**: API (`:8080`) — routers/services/middlewares, entrypoints, health check
  - **Docker**: Unix socket — containers, images, networks, disk usage, health checks

#### Supported Applications

| Application | Detection | Deep Metrics | Health Checks | Credentials |
|---|---|---|---|---|
| **MySQL / MariaDB** | `mysqld`, `mariadbd` | InnoDB buffer pool, slow queries, replication, deadlocks, lock waits, temp tables | 17 rules | Required |
| **PostgreSQL** | `postgres` (postmaster) | Cache hit ratio, dead tuples, vacuum lag, blocked queries, bgwriter, replication | 12 rules | Required |
| **Redis** | `redis-server` | Memory, latency p50/p99/p99.9, hit ratio, evictions, fragmentation, RSS ratio, persistence, fork timing, replication lag, keyspace, command stats, slow log, client capacity, pub/sub, workload recommendations | 16 rules | If AUTH enabled |
| **Elasticsearch** | Java + ES cmdline | Cluster health, shards, JVM heap, indices, node stats | 8 rules | If X-Pack enabled |
| **MongoDB** | `mongod`, `mongos` | WiredTiger cache, opCounters, lock queues, replication lag, slow ops | 10 rules | If auth enabled |
| **Nginx** | `nginx` (master) | Active connections, request rate, dropped connections, worker state, scoreboard | 7 rules | No |
| **Apache** | `httpd`, `apache2` | Scoreboard, worker utilization, request rate, MPM config, CPU load | 8 rules | No |
| **HAProxy** | `haproxy` (master) | Backend server health, session rates, queue depth, 5xx rate, CPU idle, latency breakdown, slow backends, retry/redispatch, denied requests, peak vs current, config warnings, state changes, TCP direction analysis | 11 rules | No |
| **PHP-FPM** | `php-fpm*` (master) | Worker utilization, max_children saturation, per-worker memory, pool config | 7 rules | No |
| **RabbitMQ** | `beam.smp` + rabbit | Message backlog, unacked, memory/disk alarms, queue health, node resources | 11 rules | Default guest/guest |
| **Memcached** | `memcached` | Hit ratio, evictions, slab waste, memory pressure, connection rejection | 9 rules | No |
| **Kafka** | Java + kafka cmdline | Broker config, topic count, consumer groups, log dir size, JVM hsperfdata | 4 rules | No |
| **Caddy** | `caddy` | Live config, upstream health, TLS, Caddyfile analysis | Basic | No |
| **Traefik** | `traefik` | Routers/services, health check, entrypoints, error rates | 3 rules | No |
| **Docker** | `dockerd` | Containers, images, networks, disk usage, health diagnostics | 5 rules | No |

#### Deep Metrics Collection

Each application module follows the same RCA pattern:

1. **Detect** — Scan process list every tick, match by `comm` name and cmdline
2. **Collect Tier 1** — Read `/proc/PID/{status,stat,fd}` + `/proc/net/tcp` for connections
3. **Collect Tier 2** — Query the app via its native protocol/CLI/API (with timeout, graceful fallback)
4. **Compute** — Derive ratios (cache hit%, connection usage%, lock contention%, etc.)
5. **Score Health** — Start at 100, apply weighted penalties per issue, clamp to [0, 100]
6. **Report Issues** — Each penalty generates a human-readable health issue with context

The health score drives a diagnostic badge: **OK** (80-100), **WARN** (50-79), **CRIT** (0-49).

#### Credential Configuration

Apps that need authentication show a **CREDENTIALS REQUIRED** notice at the top of their detail page with the exact JSON template to copy.

Create `~/.xtop_secrets` (JSON format, `chmod 600`):

```json
{
  "mysql": {
    "host": "127.0.0.1",
    "port": 3306,
    "user": "root",
    "password": "YOUR_MYSQL_PASSWORD"
  },
  "postgresql": {
    "host": "127.0.0.1",
    "port": 5432,
    "user": "postgres",
    "password": "YOUR_PG_PASSWORD",
    "dbname": "postgres"
  },
  "mongodb": {
    "uri": "mongodb://user:password@127.0.0.1:27017/admin"
  },
  "redis": {
    "host": "127.0.0.1",
    "port": 6379,
    "password": "YOUR_REDIS_PASSWORD"
  },
  "rabbitmq": {
    "host": "127.0.0.1",
    "port": 15672,
    "user": "guest",
    "password": "guest"
  },
  "elasticsearch": {
    "url": "http://127.0.0.1:9200",
    "user": "elastic",
    "password": "YOUR_ES_PASSWORD"
  }
}
```

Only include the apps you use. Apps without authentication (Nginx, Apache, HAProxy, PHP-FPM, Memcached, Kafka, Caddy, Traefik, Docker) work automatically with zero configuration.

---

### Active Service Detection

Doctor mode auto-detects running services and runs health checks — no pre-configuration needed:

| Service | Health Check |
|---|---|
| **sshd** | Process running |
| **nginx / apache / caddy** | Process running, stub_status/server-status check |
| **MySQL / MariaDB** | Process running, SHOW GLOBAL STATUS analysis |
| **PostgreSQL** | Process running, pg_stat_database analysis |
| **Redis** | `INFO` command via RESP protocol |
| **Docker** | Container count, unhealthy/restarting detection |
| **Kubernetes** | kubelet running, `kubectl get nodes` status |
| **WireGuard** | Interface active (`wg0`, etc.) |
| **HAProxy** | Stats socket analysis, backend health, latency breakdown, config warnings |
| **MongoDB** | serverStatus via mongosh |
| **RabbitMQ** | Management API health |
| **Elasticsearch** | Cluster health API |
| **Memcached** | `stats` command via TCP |
| **Kafka** | Process running, broker config |
| **PHP-FPM** | Pool utilization, worker state |
| **DNS (named/dnsmasq/unbound)** | Process running |

Services that aren't installed are silently skipped — only active services appear in the report.

---

### Shell Health Widget

Add system health to your shell prompt:

```bash
# Bash
eval "$(xtop -shell-init bash)"

# Zsh
eval "$(xtop -shell-init zsh)"

# Tmux status bar
xtop -tmux-status
```

Shows a colored health indicator (OK/WARN/CRIT) that updates from the daemon's last health check.

---

### Cron Integration

```bash
# Print crontab line for automated health checks
xtop -cron-install

# Example cron entry (runs every 5 minutes, alerts on state change)
*/5 * * * * /usr/local/bin/xtop -doctor -cron -alert 2>/dev/null
```

---

## 9 Output Modes

| Mode | Command | Use Case |
|---|---|---|
| **Interactive TUI** | `sudo xtop` | Live monitoring and investigation |
| **Watch Mode** | `sudo xtop -watch -section cpu` | Headless CLI output, SSH-friendly |
| **Doctor** | `sudo xtop -doctor` | Comprehensive health check report |
| **Doctor Watch** | `sudo xtop -doctor -watch` | Auto-refreshing health checks (like `top`) |
| **JSON Export** | `sudo xtop -json \| jq` | Scripting, alerting, integrations |
| **Markdown Report** | `sudo xtop -md > incident.md` | Jira/Slack/GitHub ticket attachment |
| **Daemon Mode** | `sudo xtop -daemon &` | Background collection + event logging |
| **Record/Replay** | `sudo xtop -record file` | Flight recorder for postmortem |
| **Shell Widget** | `eval "$(xtop -shell-init bash)"` | System health in your bash/zsh prompt |

---

## Quick Start

### One-liner Install

```bash
# Ubuntu/Debian (amd64)
wget https://github.com/ftahirops/xtop/releases/download/v0.46.2/xtop_0.46.1-1_amd64.deb
sudo dpkg -i xtop_0.46.1-1_amd64.deb

# RHEL/Rocky/Fedora (x86_64)
wget https://github.com/ftahirops/xtop/releases/download/v0.46.2/xtop-0.46.1-1.x86_64.rpm
sudo rpm -i xtop-0.46.1-1.x86_64.rpm

# Arch Linux
git clone https://github.com/ftahirops/xtop.git
cd xtop/packaging/archlinux && makepkg -si
```

### Build from Source

```bash
git clone https://github.com/ftahirops/xtop.git
cd xtop
CGO_ENABLED=0 go build -ldflags="-s -w -X github.com/ftahirops/xtop/cmd.Version=0.46.1" -o xtop .
sudo install -m 755 xtop /usr/local/bin/xtop
```

### Run

```bash
sudo xtop              # Full TUI, 3s refresh
sudo xtop 5            # 5-second intervals
sudo xtop -watch       # CLI mode, no TUI
sudo xtop -doctor      # Health check report
sudo xtop -json | jq   # JSON for scripting
```

---

## Installation

### Requirements

| Requirement | Details |
|---|---|
| **OS** | Linux (kernel 4.20+ recommended for PSI) |
| **Architecture** | amd64 (x86_64) |
| **Cgroups** | v1, v2, or hybrid (auto-detected) |
| **Terminal** | Unicode support (for sparklines and box drawing) |
| **Permissions** | Root recommended for full `/proc/*/io` access and eBPF probes |
| **eBPF** (optional) | Kernel with BTF (`/sys/kernel/btf/vmlinux`) + root for probe packs |

### From .deb Package (Ubuntu 22.04/24.04, Debian)

```bash
wget https://github.com/ftahirops/xtop/releases/download/v0.46.2/xtop_0.46.1-1_amd64.deb
sudo dpkg -i xtop_0.46.1-1_amd64.deb
```

### From .rpm Package (Rocky Linux, RHEL, AlmaLinux, Fedora)

```bash
wget https://github.com/ftahirops/xtop/releases/download/v0.46.2/xtop-0.46.1-1.x86_64.rpm
sudo rpm -i xtop-0.46.1-1.x86_64.rpm
```

### Arch Linux (PKGBUILD)

```bash
# Build and install from PKGBUILD
git clone https://github.com/ftahirops/xtop.git
cd xtop/packaging/archlinux
makepkg -si

# Or with an AUR helper (once published to AUR)
# yay -S xtop
```

Builds from source automatically. Optional dependencies: `nvidia-utils` (GPU monitoring), `docker` (container name resolution).

### From Source

```bash
git clone https://github.com/ftahirops/xtop.git
cd xtop
CGO_ENABLED=0 go build -ldflags="-s -w -X github.com/ftahirops/xtop/cmd.Version=0.46.1" -o xtop .
sudo install -m 755 xtop /usr/local/bin/xtop
```

### Uninstall

```bash
sudo dpkg -r xtop        # Debian/Ubuntu
sudo rpm -e xtop          # RHEL/Rocky
sudo pacman -R xtop       # Arch Linux
# or
sudo rm /usr/local/bin/xtop
```

---

## Documentation

### CLI Reference

```
xtop [OPTIONS] [INTERVAL]

Modes:
  (default)         Interactive TUI (fullscreen)
  -watch            CLI output mode — prints to terminal with auto-refresh
  -json             Single JSON snapshot to stdout, then exit
  -md               Single Markdown incident report to stdout, then exit
  -daemon           Background collector (writes events to datadir)
  -doctor           Comprehensive health check report
  -version          Print version and exit
  -update           Check GitHub for latest release and install it

Doctor Options:
  -doctor -watch    Auto-refreshing doctor (like top/watch)
  -doctor -json     Health check as JSON
  -doctor -md       Health check as Markdown table
  -cron             Cron-friendly output (silent if OK, exit codes 0/1/2)
  -alert            Send alert on health state change
  -cron-install     Print crontab line for automated health checks

Shell Widget:
  -shell-init SHELL Output shell init script (bash or zsh)
  -tmux-status      Output tmux-formatted status segment

Options:
  -interval N       Collection interval in seconds (default: 3)
  -history N        Snapshots to keep in ring buffer (default: 600)
  -section NAME     Section for -watch mode (overview,cpu,mem,io,net,cgroup,rca)
  -count N          Iterations for -watch and -doctor -watch (0 = infinite)
  -datadir PATH     Data directory for daemon mode (default: ~/.xtop/)
  -record FILE      Record snapshots to file during TUI session
  -replay FILE      Replay recorded file through TUI (no root needed)
  -prom             Enable Prometheus metrics endpoint
  -prom-addr ADDR   Prometheus listen address (default: 127.0.0.1:9100)
  -alert-webhook URL  Webhook URL for alert notifications
  -alert-command CMD  Command to execute on alert notifications
```

### Key Bindings

| Key | Action |
|---|---|
| `0` - `9` | Switch to page (Overview, CPU, Memory, IO, Network, Cgroups, Timeline, Events, Probe, Thresholds) |
| `L` | Security Monitor — eBPF network threat detection |
| `O` | System Logs viewer |
| `H` | Active Services health |
| `W` | Diagnostics page |
| `X` | Intel page |
| `Z` | Proxmox dashboard (auto-detected) |
| `Y` | Application diagnostics — 15 auto-detected apps with deep RCA |
| `D` | Open DiskGuard page |
| `b` / `Esc` | Back to Overview |
| `j` / `k` | Scroll down / up |
| `g` / `G` | Jump to top / Jump down |
| `v` / `V` | Cycle overview layout forward / backward |
| `F1` - `F4` | Direct layout selection |
| `Ctrl+D` | Save current layout as default |
| `I` | Start 10-second eBPF probe investigation |
| `Tab` | Navigate collapsible sections (Security, Network, Probe pages) |
| `Enter` | Expand/collapse selected section |
| `A` / `C` | Expand all / Collapse all sections |
| `E` | Toggle Explain side panel — metric glossary for current page |
| `a` | Toggle auto-refresh (pause/resume) |
| `n` | Step one frame (replay mode while paused) |
| `P` | Export page to Markdown file |
| `S` | Save RCA snapshot to JSON file |
| `s` | Cycle sort column (Cgroups page) |
| `?` | Toggle help overlay |
| `q` / `Ctrl+C` | Quit |

### Data Sources

xtop reads from **20+ Linux kernel interfaces** — no agents, no daemons, no external dependencies:

| Source | Metrics |
|---|---|
| `/proc/pressure/*` | PSI (Pressure Stall Information) — the most important signal modern Linux provides |
| `/proc/stat` | CPU time breakdown across all states |
| `/proc/loadavg` | Load averages and runnable task count |
| `/proc/meminfo` | 30+ memory metrics (anon, cache, slab, shmem, mapped, hugepages, etc.) |
| `/proc/vmstat` | Page faults, reclaim, swap, OOM, THP counters |
| `/proc/diskstats` | Per-device IO counters (reads, writes, sectors, time, queue) |
| `/proc/net/dev` | Per-interface packet and byte counters |
| `/proc/net/snmp` | TCP/UDP protocol-level counters |
| `/proc/net/tcp{,6}` | Per-connection TCP state tracking |
| `/proc/net/sockstat` | Socket allocation summary |
| `/proc/softirqs` | Per-CPU softirq counters |
| `/proc/sys/net/netfilter/*` | Conntrack table usage and limits |
| `/proc/sys/fs/file-nr` | File descriptor allocation |
| `/proc/[pid]/stat,status,io,cgroup` | Per-process CPU, memory, IO, scheduling |
| `/sys/fs/cgroup/` | Cgroup v1/v2 metrics (CPU, memory, IO, throttling, OOM) |
| `/sys/class/net/` | Interface metadata (operstate, speed, master, type) |
| `smartctl` | SMART disk health (temperature, wear, reallocated sectors) |
| eBPF tracepoints | `sched_switch`, `block_rq_*`, `futex`, `tcp_retransmit_skb` |
| eBPF security sentinels | `tcp_conn_request`, `tcp_v4_send_reset`, `tcp_sendmsg`, `udp_sendmsg`, `inet_sock_set_state` |
| eBPF security watchdogs | TC ingress classifiers (TCP flags, DNS deep, TLS fingerprint), beacon detection |

### Examples

```bash
# === Interactive TUI ===
sudo xtop                              # Default 3s refresh
sudo xtop 5                            # 5-second refresh interval

# === CLI Watch Mode (no TUI, SSH-friendly) ===
sudo xtop -watch                       # Overview section, 3s refresh
sudo xtop -watch -section cpu          # CPU details only
sudo xtop -watch -section io 3         # IO section, 3s interval
sudo xtop -watch -section rca          # RCA analysis only
sudo xtop -watch -section mem -count 5 # Memory, 5 iterations then exit
sudo xtop -watch -section net -interval 2

# === Doctor Health Checks ===
sudo xtop -doctor                      # One-shot health report
sudo xtop -doctor -watch               # Auto-refreshing (like top)
sudo xtop -doctor -watch -interval 5 -count 3  # 3 iterations at 5s
sudo xtop -doctor -json                # JSON output for scripting
sudo xtop -doctor -md                  # Markdown for tickets
sudo xtop -doctor -cron                # Cron-friendly (silent if OK)
sudo xtop -doctor -alert               # Alert on state change

# === Shell Health Widget ===
eval "$(xtop -shell-init bash)"        # Add to ~/.bashrc
eval "$(xtop -shell-init zsh)"         # Add to ~/.zshrc
xtop -tmux-status                      # Tmux status bar segment
xtop -cron-install                     # Print crontab line

# === Machine-Readable Output ===
sudo xtop -json | jq '.analysis.Health'
sudo xtop -json | jq '.analysis.RCA[] | select(.Score > 0)'
sudo xtop -json | jq '.analysis.PrimaryBottleneck'

# === Incident Reports ===
sudo xtop -md > /tmp/incident-$(date +%Y%m%d).md

# === Flight Recorder ===
sudo xtop -record /var/log/xtop-$(date +%Y%m%d-%H%M).wlog
xtop -replay /var/log/xtop-20260218-0300.wlog    # No root needed

# === Background Daemon ===
sudo xtop -daemon &
sudo xtop -daemon -datadir /var/lib/xtop -interval 2

# === Prometheus Exporter ===
sudo xtop -prom -prom-addr :9100
curl -s http://localhost:9100 | head

# === Alert Hooks ===
sudo xtop -daemon -alert-webhook https://example.com/xtop
sudo xtop -daemon -alert-command 'logger -t xtop \"$XTOP_EVENT\"'
```

---

## Configuration

xtop loads defaults from `~/.config/xtop/config.json` (or `XDG_CONFIG_HOME`).
Use `config.example.json` as a starting point.

```json
{
  "default_layout": 0,
  "interval_sec": 1,
  "history_size": 300,
  "default_section": "overview",
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

---

## Prometheus Metrics

When `-prom` is enabled, xtop exposes a minimal metrics set including:

- Health and primary RCA score
- PSI (CPU/MEM/IO)
- CPU busy/user/system/iowait/steal
- Memory used %, total, available
- Disk max util, per-device read/write/util/await, and await histogram
- Network retrans, drops/errors (global + per-interface rx/tx/util)
- Top 50 cgroups by CPU (cpu/mem/io/throttle)

---

## Alert Payloads

Alerts are emitted by both daemon mode and doctor mode (`-alert`) when health state changes.
Supported channels: **webhook**, **Slack**, **Telegram**, **email**, and **custom command**.
Events include: `health_critical`, `health_ok`, `event_closed`, and `doctor_alert`.

Webhook payload example:

```json
{
  "event": "health_critical",
  "payload": {
    "bottleneck": "IO Starvation",
    "score": 78,
    "culprit": "/system.slice/docker-abc.scope",
    "process": "postgres",
    "pid": 1234
  },
  "ts": "2026-02-19T12:00:00Z"
}
```

Alert command environment variables:

- `XTOP_EVENT` — event name
- `XTOP_PAYLOAD` — JSON payload string

## Demo Scenarios

Seven ready-to-run scripts simulate real-world incidents for testing and demonstration:

| Script | Scenario | What xtop Detects |
|---|---|---|
| `demos/01-io-stall.sh` | Sync write storm with fsync | IO PSI spike, D-state tasks, disk latency, writeback pressure |
| `demos/02-memory-pressure.sh` | Allocate 70% of RAM | Memory PSI, low available, swap activity, direct reclaim |
| `demos/03-cpu-throttle.sh` | Cgroup-limited CPU burn | CPU PSI, run queue saturation, cgroup throttle %, stolen time |
| `demos/04-network-drops.sh` | tc netem packet loss | Packet drops, TCP retransmits, network error rate |
| `demos/05-port-exhaustion.sh` | TIME_WAIT connection storm | TCP state anomaly, port exhaustion prediction |
| `demos/06-conntrack-flood.sh` | Conntrack table exhaustion | Conntrack >80%, connection drop risk, exhaustion prediction |
| `demos/all-stress.sh` | All subsystems simultaneously | Multi-bottleneck detection, priority ranking, causal chains |

```bash
# Terminal 1: Start the demo
sudo bash demos/01-io-stall.sh

# Terminal 2: Watch xtop detect it in real-time
sudo xtop
```

---

## Why Not Just Use...

| Tool | What It Does | What It Doesn't Do |
|---|---|---|
| `htop` / `top` | Shows process list sorted by CPU/MEM | No RCA, no correlation, no cgroup awareness, no evidence scoring, no network analysis |
| `iostat` | Shows disk throughput and latency | No process attribution, no PSI, no cgroup mapping, no health verdict |
| `vmstat` | Shows memory and swap activity | No root cause, no trend, no prediction, no actionable output |
| `sar` | Historical metric collection | No real-time RCA, no correlation, no TUI, requires post-processing |
| `dstat` | Multi-metric live output | No analysis, no evidence scoring, no bottleneck detection |
| `nstat` / `ss` | Network counters and sockets | No health verdict, no interface classification, no correlation with other subsystems |
| `perf` | Deep CPU profiling | Steep learning curve, single-subsystem, no live dashboard |
| `bpftrace` | Custom eBPF scripts | Requires writing programs, no built-in RCA, expert-only |
| **xtop** | **All of the above, unified, with automatic RCA** | **One tool. One command. Full diagnosis.** |

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        xtop TUI / CLI                           │
│  17 pages • 6 layouts • watch mode • doctor • shell widget      │
├─────────────────────────────────────────────────────────────────┤
│                    Statistical Intelligence                      │
│   EWMA Baselines • Z-Score Anomaly • Pearson Correlation         │
│   Holt Forecasting • Seasonal Awareness • Process Profiling      │
│   Golden Signals • Causal Strength Learning                      │
├─────────────────────────────────────────────────────────────────┤
│                       Analysis Engine                            │
│   RCA Scoring • Evidence Gating • Anomaly Tracking               │
│   Causal Chains • Capacity Prediction • Owner Attribution        │
│   Security Evidence • Threat Scoring • 32 Pattern Library        │
├─────────────────────────────────────────────────────────────────┤
│                       Doctor Engine                              │
│   Health checks • Service detection • SSL • Alerts • Cron        │
│   MySQL/Postgres/Redis probes • Docker • K8s • WireGuard         │
├───────────────────────┬─────────────────────────────────────────┤
│    Collector Layer     │         eBPF Probe Layer                │
│   /proc • /sys • cgroup│   Deep Dive: sched_switch • block_rq    │
│   smartctl • netfilter │     • futex • tcp_retransmit_skb        │
│   security • auth logs │   Sentinel: synflood • portscan • dns   │
│                        │     • connrate • outbound • exec • oom  │
│                        │   Watchdog: tcpflags • dnsdeep           │
│                        │     • tlsfinger • beacondetect           │
└───────────────────────┴─────────────────────────────────────────┘
              │                          │
              ▼                          ▼
     Linux Kernel (/proc, /sys)    eBPF Tracepoints + TC (BTF)
```

**Built with:**
- [Go](https://go.dev/) — Fast, single-binary, zero runtime dependencies
- [Bubbletea](https://github.com/charmbracelet/bubbletea) — Terminal UI framework
- [Lipgloss](https://github.com/charmbracelet/lipgloss) — Styled terminal rendering (Dracula palette)
- [cilium/ebpf](https://github.com/cilium/ebpf) — Pure Go eBPF (no CGo, no clang at runtime)

---

## Installed Files

```
/usr/local/bin/xtop                  — Binary (~17 MB, statically linked)
/usr/share/man/man1/xtop.1.gz        — Man page
/usr/share/doc/xtop/copyright         — MIT license
~/.xtop/                              — Runtime data (config, event logs, daemon state)
```

---

## Contributing

Contributions are welcome. Please open an issue to discuss significant changes before submitting a PR.

```bash
git clone https://github.com/ftahirops/xtop.git
cd xtop
go build ./...
go vet ./...
sudo ./xtop
```

---

## Roadmap

What's coming next for xtop:

| Feature | Status | Description |
|---|---|---|
| **Language Runtime Detection** | In Progress | Auto-discover JVM, .NET, Python, Node.js, Go runtimes — zero-config JVM hsperfdata parsing, GC/heap/thread metrics, GIL-bound detection |
| **JVM Deep RCA** | In Progress | GC pause evidence, heap pressure alerts, hsperfdata binary parser — correlates JVM GC storms with CPU run queue spikes |
| **Distributed Tracing Correlation** | Planned | Correlate xtop RCA findings with OpenTelemetry spans — "this IO spike caused 200ms P99 on /api/checkout" |
| **Kubernetes Pod RCA** | Planned | Per-pod bottleneck detection with cgroup v2 mapping — "Pod X OOMKilled because Node Y memory pressure hit 85%" |
| **GPU Monitoring** | Planned | NVIDIA GPU utilization, memory, temperature via nvml — detect GPU contention for ML workloads |
| **Anomaly Clustering** | Planned | Group related anomalies into incident timelines — "these 5 metrics deviated together at T+0" |
| **Remote Agent Mode** | Planned | Lightweight agent reports to central xtop instance — fleet-wide bottleneck detection |
| **Custom Evidence Plugins** | Planned | User-defined evidence checks via YAML — "if redis.connected_clients > 10000, fire redis.client.flood" |

Want to influence the roadmap? [Open an issue](https://github.com/ftahirops/xtop/issues).

---

## License

MIT License. Copyright 2024-2026 Farhan Tahir.

---

<p align="center">
  <strong>xtop</strong> — Because the answer to "what's wrong with my server?" shouldn't take 12 tools and 45 minutes.
</p>
