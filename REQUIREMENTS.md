# xtop — Root-Cause Oriented htop

## Overview

A Linux system diagnostics TUI tool that goes beyond htop by correlating signals
across CPU/memory/IO/network/cgroups to produce ranked root-cause hypotheses.

## Data Sources

- `/proc/pressure/{cpu,memory,io}` — PSI (Pressure Stall Information)
- `/proc/stat` — Per-CPU time breakdown
- `/proc/loadavg` — System load averages
- `/proc/meminfo` — Memory counters (30+ fields)
- `/proc/vmstat` — VM statistics (pgfault, reclaim, swap counters)
- `/proc/diskstats` — Per-device IO counters
- `/sys/block/*/queue/` — Disk queue parameters
- `/proc/net/dev` — Per-interface network counters
- `/proc/net/snmp` — TCP retransmit counters
- `/proc/[pid]/stat` — Per-process CPU/scheduling
- `/proc/[pid]/status` — Per-process memory/state
- `/proc/[pid]/io` — Per-process IO counters
- `/sys/fs/cgroup/` — cgroup v2 metrics
- `/sys/fs/cgroup/{cpu,memory,blkio}/` — cgroup v1 metrics

## Metrics Schema

### GlobalMetrics
- PSI: some/full avg10/avg60/avg300 for cpu, memory, io
- CPU: per-CPU user/nice/system/idle/iowait/irq/softirq/steal, total summary
- Load: 1m, 5m, 15m, nr_running, nr_total
- Memory: total, free, available, buffers, cached, swap total/free/used, dirty, writeback
- VMStat: pgfault, pgmajfault, pgpgin/out, pswpin/out, pgsteal, allocstall, compact_stall, oom_kill
- Disk: per-device reads/writes completed, sectors read/written, time in queue, io_ticks
- Network: per-iface rx/tx bytes/packets/errors/drops; TCP retransmits

### CgroupMetrics
- Path, CPU usage_usec, user_usec, system_usec, throttled_usec, nr_throttled, nr_periods
- Memory current, limit (max/high), swap, oom_kill count, pgfault, pgmajfault
- IO rbytes/wbytes/rios/wios per device
- PID count, PID limit

### ProcessMetrics
- PID, comm, state, PPID, cgroup path
- CPU utime, stime, num_threads, processor
- Memory RSS, VmSize, VmSwap, minor_fault, major_fault
- IO read_bytes, write_bytes, syscr, syscw
- voluntary_ctxt_switches, nonvoluntary_ctxt_switches

### Snapshot
- Timestamp + GlobalMetrics + []CgroupMetrics + []ProcessMetrics

## Cgroup v1/v2 Detection

1. Check `/sys/fs/cgroup/cgroup.controllers` — if present, v2
2. Fall back to checking v1 hierarchies under `/sys/fs/cgroup/{cpu,memory,blkio}`
3. Support hybrid mode (v2 root with v1 controllers)

## Correlation Rules (RCA Engine)

### IO Starvation (0-100)
- io PSI full avg10 > 5% → +30
- D-state process count > 2 → +20
- Any disk await > 50ms → +25
- Any disk util > 90% → +25
- Top offender: cgroup with highest IO bytes/s

### Memory Pressure (0-100)
- mem PSI full avg10 > 5% → +25
- pgsteal_direct rising → +20
- Swap activity (pswpin+pswpout) > 0 → +20
- OOM kill events → +35
- Top offender: cgroup closest to memory limit

### CPU Contention (0-100)
- cpu PSI some avg10 > 10% → +25
- nr_running > num_cpus × 1.5 → +25
- Context switches > 50k/s per core → +20
- Cgroup throttle ratio > 10% → +30
- Top offender: cgroup with highest throttle%

### Network Overload (0-100)
- rx/tx drops rising → +25
- rx/tx errors rising → +25
- TCP retransmits rising → +25
- softirq NET_RX high → +25
- Top offender: process with highest network activity

## UI Panels

### Panel A: Pressure Dashboard
Three PSI bars (cpu/mem/io) + load average + swap rate + network drops

### Panel B: RCA Summary
Primary bottleneck name, confidence %, evidence bullet points, causal chain

### Panel C: Cgroup Table
Sortable columns: Name, CPU%, Throttle%, Mem%, MemUsage, OOM, IO_R, IO_W
Highlight offending cgroups

### Panel D: Process Drilldown
Processes within selected cgroup, sortable by CPU%/Mem/IO/State

### Panel E: Causal Chain
Arrow-connected timeline of correlated events

## Keyboard Controls
- `tab` — Switch between panels
- `j/k` — Scroll up/down
- `s` — Change sort column
- `q` — Quit
- `?` — Help overlay

## Sampling Strategy
- 1-second collection interval (configurable via --interval flag)
- 60-snapshot ring buffer for trend detection
- Top-N process limiting (default 50) to avoid /proc scan overhead
