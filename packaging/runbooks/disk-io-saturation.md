---
name: Disk I/O saturation
bottleneck: io
evidence: iowait_high, wbstall, psi_io_full
---

## Diagnosis

Disk is saturated — writeback is stalling or iowait is high. Common culprits:

1. A backup / rsync / pg_dump is running.
2. A log rotation or `journald` flush is happening.
3. A database checkpoint (MySQL `innodb_flush_log_at_trx_commit=1`, Postgres checkpoint storm).
4. Noisy neighbour on a shared VM/disk.

Collect evidence:

```bash
# Top I/O processes
iotop -b -n 2 -o -k | head -20
# Per-disk utilization
iostat -xz 1 3
# Writeback pressure
grep -E "nr_dirty|nr_writeback" /proc/meminfo
# PSI
cat /proc/pressure/io
```

## Fix

- If it's a backup: throttle with `ionice -c 3` or reschedule to a quieter window.
- For databases: stagger checkpoints, increase checkpoint targets, or move the data volume to
  faster storage.
- For writeback stalls: consider tuning `vm.dirty_background_ratio` (default 10) and
  `vm.dirty_ratio` (default 20) — lower values trigger flushes sooner and avoid big stalls.
- Check that the filesystem isn't degraded: `dmesg | grep -iE "i/o error|remount"`.
