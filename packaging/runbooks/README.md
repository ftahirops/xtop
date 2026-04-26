# xtop runbook library

Drop markdown files into `~/.xtop/runbooks/` and xtop will automatically
surface the matching one inline when a relevant incident fires. The matcher
lives in `engine/runbook.go`.

## File format

Plain markdown with an optional YAML-ish frontmatter block:

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
Workers are maxed. Check:
```bash
nginx -T | grep worker_processes
```

## Fix
Set `worker_processes auto;` in `/etc/nginx/nginx.conf` and `systemctl reload nginx`.
```

All frontmatter fields are optional. Leave a field out and that dimension
stops narrowing the match — if you omit `app`, the runbook can match any
incident; if you omit `bottleneck`, it matches across bottlenecks.

## Matcher fields

| field       | match semantics                  | score |
|-------------|----------------------------------|-------|
| `bottleneck`| exact token (cpu/memory/io/network) | +4 |
| `app`       | substring of `PrimaryAppName`    | +3    |
| `culprit`   | substring of process+app name    | +2    |
| `evidence`  | exact ID in current firing set   | +1 each |
| `signature` | exact match of RCA signature     | +5    |
| `min_score` | minimum score for this runbook to win | — |

Multi-value fields take comma-separated values OR a YAML list:

```yaml
bottleneck:
  - cpu
  - network
```

If a runbook specifies a dimension (`bottleneck:`, `app:`, `culprit:`) and
the incident doesn't match it, the runbook is disqualified — so you can
safely author very narrow runbooks without worrying about them firing on
unrelated incidents.

## Getting started

```bash
mkdir -p ~/.xtop/runbooks
cp /usr/share/xtop/runbooks/*.md ~/.xtop/runbooks/
# edit, delete, or add as needed
```

Runbooks reload automatically every 60 seconds — no xtop restart required.
