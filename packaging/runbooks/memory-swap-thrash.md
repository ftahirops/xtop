---
name: Memory pressure — swap thrash
bottleneck: memory
evidence: swap_churn, direct_reclaim, oom_kill
---

## Diagnosis

The kernel is evicting pages under pressure. If `swap_churn` or `direct_reclaim` are firing,
a process is allocating faster than reclaim can keep up.

Collect evidence:

```bash
# Who is using memory?
ps -eo pid,rss,comm --sort=-rss | head -10
# Swap rate
vmstat 1 3
# Direct reclaim / compaction stats
grep -E "pgscan_direct|pgsteal_direct|compact_" /proc/vmstat
# Per-cgroup memory (systemd units)
systemd-cgtop -b --depth=2 -n 3 | sed -n '1,20p'
```

## Fix

Short-term:
- Identify the top RSS consumer and check whether a restart / scale-down is acceptable.
- If swap is close to 0 bytes free, consider `swapoff -a; swapon -a` to defragment — but only
  if you've identified what caused the pressure, otherwise it will come right back.

Structural:
- Set a memory limit on the offending unit via `systemctl edit <unit>` with `MemoryMax=…`.
- For databases (MySQL `innodb_buffer_pool_size`, Redis `maxmemory`, Elasticsearch `-Xmx`):
  make sure the configured heap + OS overhead fits within physical RAM.
- Consider swappiness tuning: `sysctl vm.swappiness=10` (conservative) — persist in
  `/etc/sysctl.d/99-xtop-tuning.conf`.
