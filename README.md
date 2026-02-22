<p align="center">
  <img src="https://img.shields.io/badge/xtop-v0.8.9-00d4aa?style=for-the-badge&logo=linux&logoColor=white" alt="version"/>
  <img src="https://img.shields.io/badge/Go-1.21+-00ADD8?style=for-the-badge&logo=go&logoColor=white" alt="go"/>
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
  <a href="#-quick-start">Quick Start</a> •
  <a href="#-the-problem">The Problem</a> •
  <a href="#-how-xtop-solves-it">The Solution</a> •
  <a href="#-features">Features</a> •
  <a href="#-screenshots">Pages</a> •
  <a href="#-ebpf-deep-investigation">eBPF Probes</a> •
  <a href="#-doctor-mode">Doctor</a> •
  <a href="#-server-identity-discovery">Identity</a> •
  <a href="#-installation">Installation</a> •
  <a href="#-documentation">Docs</a>
</p>

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
| Read man pages for thresholds | **Evidence-based scoring** — 21 evidence checks, weighted formulas |
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

The heart of xtop. Four parallel bottleneck detectors continuously score system health using **21 evidence checks** across **4 independent signal groups**:

| Bottleneck | Evidence Groups | What It Detects |
|---|---|---|
| **IO Starvation** | PSI, D-state tasks, Disk latency/util, Dirty pages | Storage-bound workloads, saturated disks, writeback storms |
| **Memory Pressure** | PSI, Available RAM, Swap activity, Direct reclaim, Major faults, OOM kills | Memory exhaustion, cache thrashing, swap storms, OOM events |
| **CPU Contention** | PSI, Run queue depth, Context switches, Cgroup throttling, CPU steal | Overcommitted CPUs, throttled containers, noisy neighbors, stolen cycles |
| **Network Overload** | Packet drops, TCP retransmits, Conntrack pressure, SoftIRQ overhead, TCP state anomalies, Errors | Saturated NICs, connection leaks, firewall table exhaustion |

**Trust Gating:** A bottleneck is only reported when **2+ independent evidence groups** confirm it. This eliminates false positives from single-metric spikes. Confidence scales from 30% (2 groups) to 98% (5+ groups).

### Health Levels

| Level | Meaning | Action |
|---|---|---|
| **OK** | All evidence groups inactive | System healthy at 95% confidence |
| **INCONCLUSIVE** | Signals present but fewer than 2 evidence groups confirm | Possible issue — run eBPF probe for deeper investigation |
| **DEGRADED** | Score 25-59%, 2+ evidence groups | Active bottleneck identified — investigate culprit |
| **CRITICAL** | Score 60%+, 2+ evidence groups | Severe bottleneck — immediate action required |

---

### 11 Interactive Pages

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

### 4 Overview Layouts

Switch instantly with `v` / `V` / `F1-F4`:

| Layout | Style | Best For |
|---|---|---|
| **Two-Column** (F1) | Subsystems left, owners + chain right | Daily monitoring, wide terminals |
| **Compact** (F2) | Dense single-column summary | Narrow terminals, quick glance |
| **Adaptive** (F3) | Healthy=1 line, unhealthy=expanded | Busy systems with mixed health |
| **Grid** (F4) | 2x2 subsystem dashboard | Executive overview, presentations |

Press `D` to save your preferred layout as the default.

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
| **Identity** | Service health checks based on discovered server roles |

**Alert dispatch:** Supports webhooks, Slack, Telegram, email, and custom commands. Only fires on state changes (OK→WARN, WARN→CRIT, etc.) to prevent alert fatigue.

**Exit codes:** `0` = OK, `1` = warnings, `2` = critical — integrate directly into monitoring pipelines.

---

### Server Identity Discovery

xtop can discover what your server actually does and tailor health checks accordingly:

```bash
sudo xtop -discover         # Interactive discovery
sudo xtop -discover -json   # JSON output
```

**Detected roles:**

| Role | Detection Method |
|---|---|
| **Web Server** | Nginx/Apache/Caddy processes, config files, listening ports (80/443) |
| **Database** | PostgreSQL/MySQL/MongoDB/Redis processes and ports |
| **Docker Host** | Docker daemon, containers, images |
| **Kubernetes** | kubelet, kube-apiserver, etcd |
| **NAT/Router** | ip_forward enabled, iptables MASQUERADE rules |
| **VPN Gateway** | WireGuard interfaces, OpenVPN processes |
| **Load Balancer** | HAProxy, keepalived with VIP discovery |
| **DNS Server** | named/dnsmasq/systemd-resolved |

Once discovered, identity is saved to `~/.config/xtop/config.json` and doctor mode runs role-specific health checks automatically.

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

## 10 Output Modes

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
| **Identity Discovery** | `sudo xtop -discover` | Detect server roles and services |
| **Shell Widget** | `eval "$(xtop -shell-init bash)"` | System health in your bash/zsh prompt |

---

## Quick Start

### One-liner Install

```bash
# Ubuntu/Debian (amd64)
wget https://github.com/ftahirops/xtop/releases/download/v0.8.9/xtop_0.8.9-1_amd64.deb
sudo dpkg -i xtop_0.8.9-1_amd64.deb

# RHEL/Rocky/Fedora (x86_64)
wget https://github.com/ftahirops/xtop/releases/download/v0.8.9/xtop-0.8.9-1.x86_64.rpm
sudo rpm -i xtop-0.8.9-1.x86_64.rpm
```

### Build from Source

```bash
git clone https://github.com/ftahirops/xtop.git
cd xtop
CGO_ENABLED=0 go build -ldflags="-s -w -X github.com/ftahirops/xtop/cmd.Version=0.8.9" -o xtop .
sudo install -m 755 xtop /usr/local/bin/xtop
```

### Run

```bash
sudo xtop              # Full TUI, 1s refresh
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
wget https://github.com/ftahirops/xtop/releases/download/v0.8.9/xtop_0.8.9-1_amd64.deb
sudo dpkg -i xtop_0.8.9-1_amd64.deb
```

### From .rpm Package (Rocky Linux, RHEL, AlmaLinux, Fedora)

```bash
wget https://github.com/ftahirops/xtop/releases/download/v0.8.9/xtop-0.8.9-1.x86_64.rpm
sudo rpm -i xtop-0.8.9-1.x86_64.rpm
```

### From Source

```bash
git clone https://github.com/ftahirops/xtop.git
cd xtop
CGO_ENABLED=0 go build -ldflags="-s -w -X github.com/ftahirops/xtop/cmd.Version=0.8.9" -o xtop .
sudo install -m 755 xtop /usr/local/bin/xtop
```

### Uninstall

```bash
sudo dpkg -r xtop        # Debian/Ubuntu
sudo rpm -e xtop          # RHEL/Rocky
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
  -discover         Run server identity discovery
  -version          Print version and exit

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
  -interval N       Collection interval in seconds (default: 1)
  -history N        Snapshots to keep in ring buffer (default: 300)
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
| `D` | Open DiskGuard page |
| `b` / `Esc` | Back to Overview |
| `j` / `k` | Scroll down / up |
| `g` / `G` | Jump to top / Jump down |
| `v` / `V` | Cycle overview layout forward / backward |
| `F1` - `F4` | Direct layout selection |
| `Ctrl+D` | Save current layout as default |
| `I` | Start 10-second eBPF probe investigation |
| `a` | Toggle auto-refresh (pause/resume) |
| `n` | Step one frame (replay mode while paused) |
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

### Examples

```bash
# === Interactive TUI ===
sudo xtop                              # Default 1s refresh
sudo xtop 5                            # 5-second refresh interval

# === CLI Watch Mode (no TUI, SSH-friendly) ===
sudo xtop -watch                       # Overview section, 1s refresh
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

# === Server Identity Discovery ===
sudo xtop -discover                    # Detect server roles
sudo xtop -discover -json              # JSON output

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
│  11 pages • 4 layouts • watch mode • doctor • shell widget      │
├─────────────────────────────────────────────────────────────────┤
│                       Analysis Engine                            │
│   RCA Scoring • Evidence Gating • Anomaly Tracking               │
│   Causal Chains • Capacity Prediction • Owner Attribution        │
├──────────────────────┬──────────────────────────────────────────┤
│   Doctor Engine       │         Identity Discovery              │
│   Health checks • SSL │   Role detection • Service probing       │
│   Alerts • Cron       │   Docker • K8s • VPN • DB • Web          │
├──────────────────────┴──────────────────────────────────────────┤
│                      Rate Calculator                             │
│   Delta computation • Per-device/interface/cgroup/process rates   │
├───────────────────────┬─────────────────────────────────────────┤
│    Collector Layer     │         eBPF Probe Layer                │
│   /proc • /sys • cgroup│   sched_switch • block_rq • futex       │
│   smartctl • netfilter │   tcp_retransmit_skb                    │
└───────────────────────┴─────────────────────────────────────────┘
              │                          │
              ▼                          ▼
     Linux Kernel (/proc, /sys)    eBPF Tracepoints (BTF)
```

**Built with:**
- [Go](https://go.dev/) — Fast, single-binary, zero runtime dependencies
- [Bubbletea](https://github.com/charmbracelet/bubbletea) — Terminal UI framework
- [Lipgloss](https://github.com/charmbracelet/lipgloss) — Styled terminal rendering (Dracula palette)
- [cilium/ebpf](https://github.com/cilium/ebpf) — Pure Go eBPF (no CGo, no clang at runtime)

---

## Installed Files

```
/usr/local/bin/xtop                  — Binary (~5.7 MB, statically linked)
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

## License

MIT License. Copyright 2024-2026 Farhan Tahir.

---

<p align="center">
  <strong>xtop</strong> — Because the answer to "what's wrong with my server?" shouldn't take 12 tools and 45 minutes.
</p>
