---
name: Nginx worker saturation
bottleneck: cpu, network
app: nginx
culprit: nginx
---

## Diagnosis

Nginx workers are saturated. The most common causes are:

1. `worker_processes` is too low for the CPU count.
2. `worker_connections` is hitting the limit under burst traffic.
3. A backend upstream is slow and tying up workers in `connect()` / `read()`.

Inspect the current config:

```bash
nginx -T 2>/dev/null | grep -E "worker_processes|worker_connections"
nproc
ss -tan state established '( dport = :80 or dport = :443 )' | wc -l
```

## Fix

- Set `worker_processes auto;` (defaults to CPU count).
- Bump `worker_connections` in the `events {}` block if connection counts are close to the limit.
- If the culprit is a slow upstream, look at `upstream` timings in your access log or enable
  `log_format` with `$upstream_response_time`.

Apply with:

```bash
nginx -t && systemctl reload nginx
```
