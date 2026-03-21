# xtop Project Index

> v0.36.6 | 270 Go files | 87,566 lines | Pure Go + eBPF

## Architecture Overview

```
┌─ cmd/root.go ─────────────────────────────────────────┐
│  CLI entry → Engine init → Bubbletea TUI              │
├───────────────────────────────────────────────────────┤
│ ▼ Collection (every 3s)                               │
│  collector/ → Registry.CollectAll(snap)               │
│  ├── /proc parsers (cpu, mem, disk, net, process)     │
│  ├── /sys collectors (cgroup, softirq, sysctl)        │
│  ├── App modules (MySQL, Redis, Nginx... 16 apps)     │
│  ├── Runtime modules (JVM, .NET, Python, Node, Go)    │
│  ├── eBPF sentinel probes (9 always-on)               │
│  └── GPU collector (nvidia-smi)                       │
│  ▼ Result: model.Snapshot                             │
├───────────────────────────────────────────────────────┤
│ ▼ Analysis (engine/)                                  │
│  ComputeRates() → AnalyzeRCA() → BuildNarrative()    │
│  ├── 4 bottleneck detectors (IO/Mem/CPU/Net)          │
│  ├── 68 evidence checks, trust-gated (min 2 groups)   │
│  ├── 32 failure patterns + narrative templates         │
│  ├── Temporal causality + causal learning              │
│  ├── App-aware enrichment (narrative_apps.go)          │
│  └── Statistical: EWMA, z-score, Pearson, Holt        │
│  ▼ Result: model.AnalysisResult                       │
├───────────────────────────────────────────────────────┤
│ ▼ UI (ui/)                                            │
│  Bubbletea Model → 18 pages × 6 layout modes          │
│  ├── Page picker (/ key, searchable overlay)           │
│  ├── Verdict mode (N key, metric badges)               │
│  ├── HTML export (H key, Dracula-themed report)        │
│  └── Container name resolution (Docker socket)         │
└───────────────────────────────────────────────────────┘
```

## Directory Structure

### `/cmd` — CLI & Entry Points (4,591 lines)
| File | Lines | Purpose |
|------|-------|---------|
| `root.go` | 875 | Main CLI, flags, TUI launch, markdown export |
| `doctor.go` | 1,494 | `xtop doctor` — 12-category health check |
| `appdoctor.go` | 1,867 | `xtop app-doctor` — per-app deep diagnostics |
| `watch.go` | 1,221 | `xtop watch` — headless monitoring mode |
| `forensics.go` | 759 | `xtop forensics` — incident replay |
| `monitor/main.go` | — | Daemon mode entry |

### `/model` — Data Structures (1,100+ lines)
| File | Lines | Purpose |
|------|-------|---------|
| `metrics.go` | 962 | GlobalMetrics, 60+ metric structs (PSI, CPU, Memory, Disk, Network, Conntrack, etc.) |
| `snapshot.go` | ~150 | Snapshot, AnalysisResult, Narrative, TemporalChain, Owner, Evidence |
| `apps.go` | 144 | AppInstance, AppDockerContainer, DockerStack, WebsiteMetrics |
| `gpu.go` | 30 | GPUDevice, GPUProcess, GPUSnapshot |
| `profiler.go` | ~100 | ServerProfile, ProfileDomain, ProfileRule |

### `/collector` — Data Collection (12,000+ lines)
| File | Lines | Purpose |
|------|-------|---------|
| `collector.go` | 78 | Registry, Collector interface, NewRegistry() |
| `cpu.go` | ~200 | /proc/stat parser, CPU times, load average |
| `memory.go` | ~250 | /proc/meminfo, 29 memory categories |
| `disk.go` | ~200 | /proc/diskstats, per-device IOPS/throughput/latency |
| `network.go` | ~400 | /sys/class/net, interface metadata, conntrack |
| `process.go` | ~300 | /proc/PID/stat+status+cmdline, top-N processes |
| `psi.go` | ~80 | /proc/pressure/cpu+memory+io |
| `socket.go` | ~200 | /proc/net/tcp, TCP states, ephemeral ports |
| `softirq.go` | ~100 | /proc/softirqs, per-CPU interrupt counts |
| `sysctl.go` | ~400 | Conntrack stats, nf_conntrack table parser |
| `filesystem.go` | ~200 | statfs, mount points, inode usage |
| `security.go` | ~300 | SUID, fileless, reverse shells, auth.log |
| `diag.go` | 1,173 | System diagnostics (FDs, NTP, SSL, systemd) |
| `proxmox.go` | 1,019 | Proxmox VE host/VM metrics |
| `gpu.go` | 85 | NVIDIA GPU via nvidia-smi |
| `container.go` | 105 | Docker socket → container name resolver |
| `identity.go` | ~200 | Process → AppIdentity resolution |

### `/collector/apps` — Application Modules (8,000+ lines)
| File | Lines | App | Detection | Deep Metrics |
|------|-------|-----|-----------|-------------|
| `mod_mysql.go` | 914 | MySQL/MariaDB | `mysqld` comm | SHOW GLOBAL STATUS, PROCESSLIST, INNODB, REPLICA |
| `mod_redis.go` | 851 | Redis | `redis-server` | INFO ALL (80+ metrics), SLOWLOG |
| `mod_mongodb.go` | 1,080 | MongoDB | `mongod`/`mongos` | serverStatus, WiredTiger, opCounters |
| `mod_haproxy.go` | 2,159 | HAProxy | `haproxy` | show stat/info/sess, per-backend |
| `mod_docker.go` | 881 | Docker | `dockerd` | Unix socket, containers, stacks |
| `mod_nginx.go` | ~300 | Nginx | `nginx` master | stub_status |
| `mod_apache.go` | 639 | Apache | `httpd`/`apache2` | mod_status scoreboard |
| `mod_postgres.go` | ~500 | PostgreSQL | `postgres` | pg_stat_activity/database/bgwriter |
| `mod_elasticsearch.go` | ~400 | Elasticsearch | Java + ES cmdline | Cluster health, JVM, shards |
| `mod_phpfpm.go` | ~300 | PHP-FPM | `php-fpm*` | Pool config, worker stats |
| `mod_rabbitmq.go` | ~400 | RabbitMQ | `beam.smp` + rabbit | Management API |
| `mod_memcached.go` | ~300 | Memcached | `memcached` | stats/slabs |
| `mod_kafka.go` | ~200 | Kafka | Java + kafka | Log dirs, JVM hsperfdata |
| `mod_caddy.go` | ~200 | Caddy | `caddy` | Admin API |
| `mod_traefik.go` | ~200 | Traefik | `traefik` | API routers/services |
| `mod_plesk.go` | ~200 | Plesk | `plesk*` | Domain configs |

### `/collector/ebpf` — eBPF Probes (5,000+ lines)
| File | Lines | Purpose |
|------|-------|---------|
| `sentinel.go` | 904 | Always-on probes: packet drops, TCP resets, OOM, exec, ptrace |
| `runner.go` | 817 | Probe lifecycle: start/stop/results, 4 deep dive packs |
| `kfreeskb.go` | 263 | Packet drop tracing, 50+ drop reason strings |
| `offcpu.go` | ~200 | Off-CPU analysis via sched_switch |
| `iolatency.go` | ~200 | Block IO latency histograms |
| `lockwait.go` | ~150 | Futex contention tracing |
| `tcpretrans.go` | ~150 | TCP retransmit tracking |
| `bpf/*.c` | — | BPF C source programs (pre-compiled to .o) |

### `/collector/runtime` — Language Runtime Detection
| File | Runtime | Method |
|------|---------|--------|
| `mod_jvm.go` | JVM | hsperfdata binary parsing |
| `mod_dotnet.go` | .NET | EventPipe (experimental) |
| `mod_python.go` | Python | Cmdline detection |
| `mod_node.go` | Node.js | Cmdline detection |
| `mod_go.go` | Go | Cmdline detection |

### `/engine` — Analysis Engine (10,000+ lines)
| File | Lines | Purpose |
|------|-------|---------|
| `engine.go` | ~200 | Engine struct, Tick() loop, collection→analysis pipeline |
| `rca.go` | 1,988 | 4 bottleneck detectors, 68 evidence checks, scoring |
| `narrative.go` | ~400 | BuildNarrative(), 30 templates, impact estimation |
| `narrative_apps.go` | 140 | App-aware enrichment (MySQL+IO, Redis+Memory, etc.) |
| `patterns.go` | ~400 | 32 failure patterns (OOM, IO Storm, CPU Throttle...) |
| `temporal.go` | ~300 | Signal onset tracking, BuildTemporalChain() |
| `blame.go` | ~300 | ComputeBlame() per-domain attribution |
| `anomaly.go` | 912 | EWMA baselines, z-score sliding window detection |
| `correlate.go` | ~300 | Pearson R cross-signal correlation |
| `forecast.go` | ~200 | Holt-Winters exponential smoothing |
| `scoring.go` | ~200 | Golden signal scoring (latency/traffic/errors/saturation) |
| `probe.go` | 790 | ProbeManager, probe packs, findings |
| `slo.go` | ~200 | SLO target tracking |
| `metrics.go` | ~200 | Multi-resolution time series buffer |
| `impact.go` | ~150 | Impact estimation from RCA |
| `warnings.go` | ~150 | Exhaustion/degradation warnings |
| `eventlog.go` | ~200 | Incident event detection + flight recorder |

### `/ui` — Terminal UI (18,000+ lines)
| File | Lines | Purpose |
|------|-------|---------|
| `app.go` | 2,343 | Model struct, Update(), View(), key handling, status bar |
| `overview.go` | 2,364 | extractSubsystems(), 6 shared blocks (RCA, Owners, Capacity...) |
| `layout_a.go`–`layout_f.go` | ~600 | 6 overview layout modes |
| `page_cpu.go` | ~400 | CPU detail page |
| `page_mem.go` | ~400 | Memory detail page |
| `page_io.go` | ~400 | IO detail page |
| `page_net.go` | 2,672 | Network page, 6 collapsible sections, intelligence engine |
| `page_apps.go` | 5,509 | Apps page, 16 app renderers, detail drill-down |
| `page_security.go` | 1,385 | Security page, 14 eBPF-powered sections |
| `page_intel.go` | 718 | Intel page, cross-correlation, runtimes, SLO |
| `page_probe.go` | 657 | Probe results, 13 collapsible sections |
| `page_gpu.go` | 110 | GPU monitoring (nvidia-smi) |
| `page_picker.go` | 170 | `/` key page picker overlay with search |
| `export_html.go` | 240 | HTML incident report generator |
| `components.go` | ~400 | Shared: boxTop/Bot/Row, metricVerdict, pageFooter, fmtBytes |
| `styles.go` | ~50 | Dracula palette lipgloss styles |
| `explain.go` | ~300 | Side panel metric glossary |
| `page_beginner.go` | ~200 | Plain-English beginner mode |
| `page_thresholds.go` | ~200 | Live threshold viewer |
| `page_timeline.go` | ~200 | ASCII sparkline charts |
| `page_events.go` | ~200 | Incident event list |
| `page_cgroup.go` | ~300 | CGroup table (sortable) |
| `page_diskguard.go` | ~300 | Disk space monitor + auto-contain |
| `page_diag.go` | ~200 | System diagnostics |
| `page_profiler.go` | ~400 | Optimization audit |
| `page_proxmox.go` | 880 | Proxmox VE host/VM dashboard |

### `/config` — User Configuration
| File | Purpose |
|------|---------|
| `config.go` | ~/.xtop/config.yaml loading, experience level, default layout, roles |

### `/api` — REST API (partial)
| File | Purpose |
|------|---------|
| `server.go` | HTTP API server (basic) |

## Pages (18 total)

| Key | Page | File | Sections |
|-----|------|------|----------|
| `0` | Overview | overview.go + layout_*.go | 5 subsystem boxes + RCA + Owners + Capacity + Apps + Security |
| `1` | CPU | page_cpu.go | Usage, load, processes, cgroups, process tree |
| `2` | Memory | page_mem.go | Usage, breakdown, swap, VMStat, hugepages, processes |
| `3` | IO | page_io.go | Per-device stats, SMART health, D-state, processes |
| `4` | Network | page_net.go | 6 collapsible: Quality, Connections, Conntrack, Traffic, Processes, Talkers |
| `5` | CGroups | page_cgroup.go | Sortable table (CPU%, throttle%, memory, OOM, IO) |
| `6` | Timeline | page_timeline.go | 16 rolling sparklines (5-min window) |
| `7` | Events | page_events.go | Auto-detected incidents with blame |
| `8` | Probe | page_probe.go | 13 collapsible: eBPF results (off-CPU, IO lat, locks, retrans...) |
| `9` | Thresholds | page_thresholds.go | Live RCA checks vs current values |
| `D` | DiskGuard | page_diskguard.go | Filesystem monitor, auto-contain (SIGSTOP writers) |
| `L` | Security | page_security.go | 14 sections: SSH, ports, SUID, exec, ptrace, C2 beacons... |
| `W` | Diagnostics | page_diag.go | FDs, NTP, SSL certs, Docker, systemd units |
| `X` | Intel | page_intel.go | Cross-correlation, runtimes, SLO, autopilot, incidents |
| `Y` | Apps | page_apps.go | 16 apps, health scores, deep metrics, websites |
| `O` | Profiler | page_profiler.go | 7-domain optimization audit (0-100 scores) |
| `U` | GPU | page_gpu.go | NVIDIA GPU util, VRAM, temp, power, processes |
| `Z` | Proxmox | page_proxmox.go | Auto-detected on PVE hosts only |

## Key Bindings

| Key | Action | Context |
|-----|--------|---------|
| `/` | Page picker (searchable) | Global |
| `N` | Toggle verdict badges | Global |
| `H` | Export HTML report | Global |
| `E` | Toggle explain panel | Global |
| `I` | Run eBPF deep dive (10s) | Global |
| `S` | Save RCA to JSON | Global |
| `P` | Export markdown report | Global |
| `?` | Help screen | Global |
| `q` | Quit | Global |
| `j/k` | Scroll down/up | Global |
| `v/V` | Layout forward/backward | Overview |
| `d` | Toggle compact/detail | Overview |
| `A/C` | Expand/collapse all | Network, Probe, Security |
| `Enter` | Toggle section | Collapsible pages |
| `F9` | Kill/signal process | CPU, Memory, IO |
| `t` | Toggle anomaly filter | Thresholds |

## Test Coverage

| Package | Files | Coverage | Notes |
|---------|-------|----------|-------|
| `engine` | 9 test files | 34.8% | Baseline, z-score, correlation, forecast, scoring, alert, diskguard, normalize, recorder |
| `cmd` | 1 test file | 0.8% | Regression fixes |
| `collector` | 1 test file | 0.6% | Regression fixes |
| `ui` | 1 test file | 0.6% | Regression fixes |

## Build & Release

```bash
# Build
CGO_ENABLED=0 go build -ldflags="-s -w -X github.com/ftahirops/xtop/cmd.Version=0.36.6" -o xtop .

# Package .deb
cp xtop packaging/xtop_0.36.6-1_amd64/usr/local/bin/xtop
dpkg-deb --build packaging/xtop_0.36.6-1_amd64 packaging/xtop_0.36.6-1_amd64.deb

# Install
sudo dpkg -i xtop_0.36.6-1_amd64.deb
# Binary: /usr/local/bin/xtop (requires sudo)

# Release
gh release create v0.36.6 packaging/xtop_0.36.6-1_amd64.deb --title "..."
```

## Dependencies

- `github.com/charmbracelet/bubbletea` — TUI framework
- `github.com/charmbracelet/lipgloss` — Terminal styling
- `github.com/cilium/ebpf` — Pure-Go eBPF library
- No CGo, no runtime BPF compilation
