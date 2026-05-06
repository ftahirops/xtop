# xtop RCA overhaul — phases 1 through 7 + TODOs 1–6

**Date snapshot:** 2026-05-05 (updated 19:00 UTC after deferred TODOs landed)
**Branch:** main (working tree)
**Build label:** `0.46.3-todo1to6`
**Author:** Claude Code session driven by Farhan Tahir

## Latest: deferred TODOs 1–6 landed

| TODO | Subject                                          | Outcome                                                                                       |
|------|--------------------------------------------------|-----------------------------------------------------------------------------------------------|
| #2   | Daemon → ModeLean by default                     | RSS **224 MB → 23 MB** (~10× smaller). CPU **8% → 0.5%** (~16×). Threads 18 → 13. `XTOP_DAEMON_RICH=1` overrides. |
| #5   | Fleet hub schema migration                       | Added `state` + `confirmed_at` hot columns to `fleet_incidents`; populated by agent at confirm. Idempotent ALTER. |
| #3   | PSI `poll(2)` event-driven onset                 | FastPulse now uses `unix.Poll` against `/proc/pressure/{cpu,memory,io}` triggers. Falls back to ticker on permission error. |
| #1   | SQLite persistence for baselines + drift         | New tables `app_baselines`, `drift_trackers`. Daemon loads on start, flushes every 10 min + on shutdown. |
| #6   | Negative evidence in trace dump                  | Per-domain `EvidenceRejected[]` block surfaces what was checked but didn't fire. |
| #4   | eBPF off-CPU probe (minimum viable)              | `XTOP_PROBES_EBPF=1` adds bpftrace off-CPU + syscall-top probes (perf fallback). |

Final daemon footprint with all changes: **23 MB RSS, 0.5% CPU, 13 threads**.

---

This document records the design, implementation, and verification of a
seven-phase overhaul of xtop's root-cause analysis engine. The goal stated
by the user: **rock-solid, minute-level-accurate RCA with no false positives
in production**, with a verification workflow ("100000% verify the extreme
minute-level pinpoint accuracy of every single RCA").

All seven phases are merged into the working tree; production binaries build
clean (`CGO_ENABLED=0 go build`); `go vet ./...` and `go test ./...` are
both green.

---

## Table of contents

1. [Design questions and the answers that shaped the plan](#design-questions)
2. [Resource audit — actual RSS / CPU / IOPS](#resource-audit)
3. [Seven-phase plan, side-by-side comparisons](#seven-phase-plan)
4. [Phase 1 — verdict discipline](#phase-1)
5. [Phase 2 — fast pulse (sub-second PSI)](#phase-2)
6. [Phase 3 — trace mode (verification tool)](#phase-3)
7. [Phase 4 — per-app behavioral baselines](#phase-4)
8. [Phase 5 — multi-scale drift detection (boiling-frog)](#phase-5)
9. [Phase 6 — active investigation probes](#phase-6)
10. [Phase 7 — change correlation + fleet peer comparison](#phase-7)
11. [End-to-end workflow](#end-to-end)
12. [Deliberately deferred (TODOs)](#todos)
13. [File-by-file change index](#change-index)
14. [Test inventory](#test-inventory)

---

## Design questions <a name="design-questions"></a>

These shaped the plan. Captured here so future readers don't have to
re-derive the rationale.

**Tick-based vs event-based vs hybrid?** Hybrid wins. Pure ticks miss
sub-second onsets; pure events drown you during real incidents. Build a
fast tier (≤500 ms) for hot signals + a slow tier (3 s default) for
expensive collectors + kernel events as suspicion-raisers, never as direct
verdict drivers.

**Per-app baselines feasible?** Yes. xtop already has app identity in
`identity/`; what was missing was binding metrics to that identity over
time. Anchor on cgroup, not PID; key by hour-of-week so weekday/weekend
distributions stay separate.

**Slow drift / boiling frog — how does industry handle it?** Multi-scale
baselines (short vs long vs frozen reference); never let learning happen
during a Confirmed incident; release-anchored baseline reset; SLO burn-rate
alerts (Google SRE Workbook ch. 5); fleet comparison.

**How much manual SRE practice should be encoded?** Three layers:
deterministic rules decide; statistical baselines explain; advisory
history prioritizes. **Never** let learning override a deterministic check.
Keep auditability: every Confirmed incident's trace must record which gate
each ring passed.

**Probes / shell-out auto-trigger or explicit-arm?** Explicit-arm
(`XTOP_PROBES=1`) in v1. Safer for production; user can flip the default
later once confidence is built.

---

## Resource audit <a name="resource-audit"></a>

Measured on 2026-05-05 with the phase-1-to-7 binary in `-daemon` mode at
3 s tick interval, observed for 30 s.

| Metric                           | Value                                |
|----------------------------------|--------------------------------------|
| RSS (steady)                     | 224 MB (peak 230 MB)                 |
| %CPU (steady)                    | 8.4% (after ~17% startup spike)      |
| Threads                          | 18                                   |
| Disk read                        | 0 B (all `/proc` reads are cached)   |
| Disk write                       | ~5 KB/s (rca-history.jsonl + audit)  |
| Syscall reads                    | ~5 k/s (mostly /proc)                |

**User's earlier concern of 4-8 GB / 10-20% CPU on "crtop":** that was a
different tool (or much older snapshot). Current xtop is two orders of
magnitude below that.

**Cost added by phases 1-7 vs vanilla xtop:** ~7 MB RSS, +2% CPU. All
new structures are bounded by *structure*, not by uptime:

| Phase | Structure                         | Per item     | Bound                      | Total at scale       |
|-------|-----------------------------------|--------------|----------------------------|----------------------|
| 2     | FastPulse maps                    | ~150 B/key   | fixed 3 (cpu/mem/io)       | ~450 B               |
| 3     | TraceArmer state                  | ~50 B        | 1                          | ~50 B                |
| 3     | Trace files on disk               | ~50 KB each  | only on Confirmed          | rotate via logrotate |
| 4     | appBaselineBucket (Welford)       | 32 B         | 168 hours × N apps × 2     | 50 apps → ~540 KB    |
| 5     | driftTracker (3 windows)          | 96 B         | 5 metrics                  | ~480 B               |
| 6     | ProbeRunner state                 | ~200 B       | 4 probes                   | ~1 KB                |
| 6     | Probe transient (when running)    | ~80 KB/probe | 3 concurrent max           | ~240 KB              |
| 7     | RCAIncident.ChangesAtConfirm      | per change   | 20 entries cap             | ~2 KB/incident       |

**Outstanding optimization (not yet done):** daemon mode uses `ModeRich`
in `cmd/root.go`. Switching to `ModeLean` would drop steady RSS from ~220
MB to ~80 MB (matches the `xtop-agent` binary's footprint). One-line change;
deferred because it's outside the phases-1-7 scope and warrants its own
test pass.

---

## Seven-phase plan <a name="seven-phase-plan"></a>

| # | Title                                   | What it adds                                                  | Status        |
|---|-----------------------------------------|---------------------------------------------------------------|---------------|
| 1 | Verdict discipline                      | Sustained-evidence gate, Suspected→Confirmed lifecycle        | shipped       |
| 2 | Fast pulse                              | 500 ms PSI sub-second onset                                   | shipped       |
| 3 | Trace mode                              | A→Z reasoning dump per Confirmed incident                     | shipped       |
| 4 | Per-app baselines                       | Welford histograms per (app, metric, hour-of-week)            | shipped       |
| 5 | Multi-scale drift                       | short/long/ref divergence + Holt exhaustion ETAs              | shipped       |
| 6 | Active probes                           | Explicit-arm read-only shell probes, hard-budgeted            | shipped       |
| 7 | Change correlation + fleet stamping     | dpkg/dnf history; Confirmed incidents stamp changes + peers   | shipped       |

### Tick-based vs hybrid (what was already there vs what we added)

| Dimension                           | Vanilla xtop (3 s tick)         | xtop with phases 1-7                             |
|-------------------------------------|---------------------------------|--------------------------------------------------|
| Time resolution                     | 3 s                             | 500 ms via FastPulse for hot signals             |
| Onset accuracy                      | "in the last 3 s"               | wall-clock-precise                               |
| Single-bad-sample false positive    | possible                        | eliminated by sustained-evidence gate            |
| Boundary flapping                   | hysteresis already existed      | unchanged                                        |
| Persisted noise from flickers       | one JSONL line per non-OK tick  | none — Suspected-only never persists             |
| "Build server is normally hot"      | possible false positive         | mitigated via per-app per-hour-of-week baseline  |
| Slow drift over 30 days             | invisible                       | detected by short-vs-long-vs-ref divergence      |
| Verification: "why did it fire?"    | narrative text only             | full trace JSON+MD with gate audit               |
| Active hypothesis testing           | manual                          | optional explicit-arm probes                     |
| Cost during real incident           | fixed                           | slight bump from probes (capped at 80 KB × 3)    |
| Cost when idle                      | full collect every 3 s          | unchanged (FastPulse adds ~30 ms CPU/min)        |

---

## Phase 1 — verdict discipline <a name="phase-1"></a>

### What I found already in xtop

xtop *already* had:
- `engine/alertstate.go` — hysteresis (5 pt band), sustained-threshold
  transitions (escalation 2 ticks, de-escalation 3-4 ticks), oscillation
  damping, instant escalation on critical evidence.
- `engine/scoring.go:v2TrustGate` — required ≥2 evidence groups + ≥1
  measured high-confidence + diversity across ≥2 weight categories.
- `engine/rca_history.go` — incident start/end with signature matching.

So the planned hysteresis and diversity-gate work was redundant. The real
gaps were:

1. **Per-evidence sustained tracking.** Every tick produced fresh `Evidence`
   with no memory of how long it had been firing.
2. **Suspected → Confirmed lifecycle.** Any non-OK tick was immediately
   recorded as an active incident; no in-memory "investigating" phase.
3. **Suspected-only filtering on persistence.** Noise flickers polluted
   `~/.xtop/rca-history.jsonl`.

### What shipped

Files: `model/snapshot.go` (+9 lines), `engine/evidence_tracker.go` (new,
95 lines), `engine/rca.go` (+6 lines hook), `engine/rca_history.go`
(rewrite of `Record()`), `engine/engine.go` (+1 line for calibrator gate).

Key constants:
- `minSustainedSec = 6.0` — evidence must have been firing this long for
  the confirmed gate to accept it.
- `IncidentSuspected | IncidentConfirmed | IncidentResolved` lifecycle
  states on `RCAIncident`.

Behavior:
- A single tick of pressure no longer pollutes JSONL.
- Confidence calibrator only learns from Confirmed→Resolved cycles, never
  from Suspected-only flickers.

Tests (13): `engine/evidence_tracker_test.go`, `engine/lifecycle_test.go`.

---

## Phase 2 — fast pulse (sub-second PSI) <a name="phase-2"></a>

### Design

A 500 ms goroutine reads `/proc/pressure/{cpu,memory,io}`. For each signal
it tracks the timestamp at which the current above-threshold streak began.
`SustainedAbove(id)` returns wall-clock-precise duration. Off in lean
(agent) mode and when `XTOP_FASTPULSE=0`.

Integrates with Phase 1: `stampSustainedDurations` takes `max(coarse_tick_onset,
fastpulse_onset)` so the sustained value is the most honest available.

Files: `engine/fastpulse.go` (new), `engine/history.go` (+1 field),
`engine/engine.go` (+8 lines), `engine/evidence_tracker.go` (+max-of-both
logic).

Tests (4): `engine/fastpulse_test.go`.

---

## Phase 3 — trace mode (the verification tool) <a name="phase-3"></a>

### Modes

| Trigger                          | Behavior                                          |
|----------------------------------|---------------------------------------------------|
| `XTOP_TRACE_NEXT=1`              | Dumps the very next tick, then disarms            |
| `XTOP_TRACE_ON_CONFIRMED=1`      | Dumps every Suspected→Confirmed transition        |
| `xtop trace --once`              | CLI wrapper for next-tick                         |
| `xtop trace --watch-confirmed`   | CLI wrapper for continuous Confirmed              |

### Output

Two files per dump in `~/.xtop/traces/`:
- `trace-<unix>.json` — stable schema `xtop.trace.v1`
- `trace-<unix>.md` — sysadmin-readable notebook

### Trace contents

For one tick:
1. **Inputs xtop measured** — PSI, runqueue, memory, swap, OOM, retrans,
   conntrack — table form.
2. **Per-domain analysis** — bottleneck name, score, domain confidence,
   evidence list with sustained durations, value vs threshold, weight tag,
   measured/derived flag, top process/cgroup.
3. **Gate audit** — v2 trust gate pass/fail and *reason* (which condition
   broke), confirmed trust gate pass/fail with sustained vs required, the
   weight categories firing, runner-up domain + score gap (counterfactual).
4. **Correlations**, **blame attribution**, **causal chain summary**.
5. **Per-app baseline anomalies** (Phase 4).
6. **Slow-drift warnings** (Phase 5).
7. **Recent system changes** (Phase 7).
8. **Fleet peer correlation** (Phase 7).
9. **Active probe captures** (Phase 6).

Files: `engine/trace.go` (new), `cmd/trace.go` (new), `cmd/root.go` (+1).

Tests (4): `engine/trace_test.go`.

---

## Phase 4 — per-app behavioral baselines <a name="phase-4"></a>

### Design

Per-app, per-(metric, hour-of-week) Welford bucket. Welford gives exact
mean+variance over the full sample window with no warmup quirks. Anchored
on cgroup-derived app role.

**Frozen during incident.** While a Confirmed incident is active, no
baseline updates occur. This is the single biggest learning-time
correctness rule per Google SRE practice — prevents the bad data from
being absorbed as "normal."

### Outputs

`result.AppAnomalies []AppBehaviorAnomaly` — surfaced in trace markdown
with hour-of-week mean ± std and σ.

Files: `engine/baseline_app.go` (new), `model/snapshot.go` (+ struct +
field on AnalysisResult), `engine/engine.go` (+5 lines wiring).

Constants:
- `appBaselineSigma = 3.0` — z-score threshold (≈ 0.27% expected FP rate
  on a normal distribution).
- `appBaselineMinSamples = 20` — warm-up gate.
- `appCPUMinPct = 0.5`, `appRSSMinMB = 50.0` — don't track effectively-idle apps.

Tests (4): `engine/baseline_app_test.go`.

---

## Phase 5 — multi-scale drift detection <a name="phase-5"></a>

### Design

Three Welford windows per drift-tracked metric:
- `short` — last ~hour, rolling.
- `long` — last few days, rolling.
- `ref` — frozen reference, captured once at long-warmup.

Drift fires when `|short.mean - long.mean| < ε` AND `|long.mean - ref.mean|
> δ`. Translates to: short and long are in sync (no acute spike) but long
has drifted from the reference. This is the signature of slow leak.

Plus `HoltExhaustionEvidence()` walks xtop's existing `HoltForecaster`
ETAs and emits 7-day warnings.

**Frozen during incident** — same rule as Phase 4.

### Outputs

`result.Degradations` — surfaced in trace markdown.

Files: `engine/drift.go` (new), `engine/engine.go` (+4 lines).

Constants:
- `driftShortMax = 1200`, `driftLongMax = 86400` — sample budgets at 3 s tick.
- `driftEpsilonRel = 0.05` — short ≈ long when within 5%.
- `driftDeltaRel = 0.25` — long has drifted from ref when ≥25% relative change.
- `driftMinValue = 1.0` — don't track near-zero metrics.

Drift-tracked metric IDs: `cpu.busy`, `mem.available.low`, `io.disk.util`,
`io.disk.latency`, `net.conntrack`.

Tests (5): `engine/drift_test.go`.

---

## Phase 6 — active investigation probes <a name="phase-6"></a>

### Design — every constant is a load-bearing safety rail

| Limit                           | Value                          | Purpose                                       |
|---------------------------------|--------------------------------|-----------------------------------------------|
| Default state                   | **OFF**                        | `XTOP_PROBES=1` to enable                     |
| Per-probe deadline              | 5 s (`context.WithTimeout`)    | One probe never blocks indefinitely           |
| WaitDelay                       | 1 s after kill                 | `cmd.Wait` never stalls on dead pipes         |
| Stdout cap                      | 64 KB                          | Output flood is silently truncated            |
| Stderr cap                      | 16 KB                          | Same                                          |
| Per-class rate limit            | 30 s                           | Same probe class can't re-fire on flapping    |
| Concurrent probes (system-wide) | 3                              | Bounded forks                                 |
| Trigger window                  | only Suspected→Confirmed       | Never under noise; never on unrelated ticks   |

### Built-in probes (v1)

All read-only, all bounded. No eBPF, no perf events, no fork-bombs.

| Probe                        | Triggers (evidence IDs)                      | Command (with static args)                                            |
|------------------------------|----------------------------------------------|-----------------------------------------------------------------------|
| `top_cpu_processes`          | `cpu.busy`, `cpu.psi`, `cpu.runqueue`        | `ps -eo pid,pcpu,pmem,state,comm,args --sort=-pcpu`                   |
| `dstate_processes`           | `io.dstate`, `io.psi`                        | `ps -eo pid,state,wchan:30,comm,args`                                 |
| `kernel_slab_top`            | `mem.slab.leak`, `mem.psi`, `mem.alloc.stall`| `head -30 /proc/slabinfo`                                             |
| `tcp_retrans_summary`        | `net.tcp.retrans`, `net.drops`               | `ss -tin state established`                                           |

### Worst-case Phase 6 cost

Memory: 4 probes × 80 KB output buffers = ~320 KB transient.
Wall-clock: 5 s × 3 concurrent = 15 s aggregate per Confirmed incident.

### Output

`result.ProbeResults []ProbeResult` — captured into the next trace dump.
Each result carries: name, evidence ID that triggered, started_at,
duration_ms, exit_code, output (truncated), stderr, truncated flag, error.

Files: `engine/probes.go` (new, ~250 lines), `model/snapshot.go` (+ struct
+ field), `engine/engine.go` (+8 lines).

Tests (6): `engine/probes_test.go` — including `TestProbeRunner_TimeoutBudgetEnforced`
which proves a `sleep 30` probe is killed within the budget.

---

## Phase 7 — change correlation + fleet peer comparison <a name="phase-7"></a>

### Design

Mostly composition over xtop's existing detectors:
- `engine/changes.go` — already tracked dpkg log + new/stopped processes.
  Extended with **dnf/yum history** parsing for RHEL/CentOS/Fedora hosts.
- `engine/config_drift.go` — already tracks watched config files in /etc.
- Result-level: `result.Changes` and `result.CrossHostCorrelation` are
  already populated by the engine.

### What was missing

When an incident is Confirmed, the snapshot of those fields wasn't
persisted on the incident itself. Phase 7 adds:

```go
type RCAIncident struct {
    // ... existing fields ...
    ChangesAtConfirm    []model.SystemChange `json:"changes_at_confirm,omitempty"`
    FleetPeersAtConfirm string               `json:"fleet_peers_at_confirm,omitempty"`
}
```

These are stamped at the moment of Suspected→Confirmed promotion (and
captured at any of three promotion paths: first-tick edge case, signature
change, same-signature continuation). After promotion they are immutable —
post-mortem analysis still has them even if live state moves on.

### Output

Persisted in `~/.xtop/rca-history.jsonl`; rendered in trace markdown.

Files: `engine/changes.go` (+50 lines for dnf/yum), `engine/rca_history.go`
(+30 lines for stamping + helper).

Tests (3): `engine/phase7_test.go`.

---

## End-to-end workflow <a name="end-to-end"></a>

```bash
# 1. Build (or use the prebuilt /tmp/xtop-p7)
CGO_ENABLED=0 go build -ldflags="-s -w -X github.com/ftahirops/xtop/cmd.Version=0.46.3-phase1to7" -o xtop .

# 2. Run xtop daemon with continuous Confirmed-only tracing + probes
sudo XTOP_TRACE_ON_CONFIRMED=1 XTOP_PROBES=1 ./xtop -daemon &

# 3. Trigger a sustained pressure event (must exceed minSustainedSec=6s
#    for verdict promotion):
stress-ng --cpu 0 --timeout 30

# 4. xtop writes one trace per Confirmed transition into ~/.xtop/traces/
ls -la ~/.xtop/traces/
# trace-<unix>.json   stable schema xtop.trace.v1
# trace-<unix>.md     sysadmin-readable notebook

# 5. The .md will contain, for that one Confirmed incident:
#    - Every metric value xtop measured
#    - Every evidence item that fired, with sustained-for, value, threshold
#    - Gate audit (which trust gates passed/failed and why)
#    - Runner-up domain + score gap (the counterfactual)
#    - Per-app baseline anomalies (e.g. postgres at this hour-of-week vs normal)
#    - Drift warnings (if a metric drifted from 30/90 d reference)
#    - Active probe captures (top, D-state list, slabtop, ss -tin)
#    - Recent system changes (dpkg/dnf entries from last 30 min)
#    - Fleet peer correlation (if hub configured + peers report similar)

# 6. Audit: every claim in the verdict has its own row of evidence.
#    Open the .md, follow the chain, validate.

# 7. Verify xtop's own footprint while running:
ps -o pid,rss,%cpu,comm $(pgrep -fx "./xtop -daemon")
```

Suspected-only flickers (anything < 6 s sustained, anything failing the
diversity gate) produce **no trace files** and **no JSONL entries** — they
stay in-memory and disappear when health returns to OK. This is the primary
false-positive guard.

---

## Deliberately deferred (TODOs) <a name="todos"></a>

These keep the v1 surface sane and don't block the verification workflow:

| # | Item                                                              | Rationale to defer                                |
|---|-------------------------------------------------------------------|---------------------------------------------------|
| 1 | SQLite persistence for app baselines + drift trackers             | In-memory only today; survives ticks but not restart |
| 2 | Daemon mode using `ModeLean` (one-line in `cmd/root.go`)          | Would drop daemon RSS ~220 MB → ~80 MB; needs own test pass |
| 3 | PSI `poll()` event-driven onset (vs 500 ms polling)               | Same outcome, lower CPU; nice-to-have             |
| 4 | eBPF-driven probes (off-CPU stack, sched latency) for Phase 6     | Requires CAP_BPF, wider blast radius              |
| 5 | Fleet hub schema migration for new `state`/`confirmed_at`/`changes_at_confirm`/`fleet_peers_at_confirm` fields | Local engine works; hub sees them as unknown JSON |
| 6 | Negative evidence (rejected evaluations) in trace dump            | Adds "what xtop checked and ruled out"; needs touching all 4 detectors |
| 7 | Per-PID-lineage app baselines (currently cgroup-anchored only)    | Cgroup is more robust; PID lineage is brittle    |
| 8 | Fleet-wide priors for cold-start app baselines                    | Hub has the data; cross-host fetch is a separate small job |
| 9 | Release-anchored baseline reset on deploy event                   | Phase 7 reads change events but doesn't reset baselines on them yet |

---

## File-by-file change index <a name="change-index"></a>

### New files

| Path                                  | Phase | Purpose                                                  |
|---------------------------------------|-------|----------------------------------------------------------|
| `engine/evidence_tracker.go`          | 1     | Per-evidence sustained tracking + confirmed trust gate  |
| `engine/lifecycle_test.go`            | 1     | Lifecycle (Suspected→Confirmed→Resolved) tests          |
| `engine/evidence_tracker_test.go`     | 1     | Sustained-duration + gate tests                          |
| `engine/fastpulse.go`                 | 2     | 500 ms PSI sampler                                       |
| `engine/fastpulse_test.go`            | 2     | FastPulse tests                                          |
| `engine/trace.go`                     | 3     | TraceArmer + JSON/MD rendering                          |
| `engine/trace_test.go`                | 3     | Trace tests                                              |
| `cmd/trace.go`                        | 3     | `xtop trace` subcommand                                  |
| `engine/baseline_app.go`              | 4     | Per-app, per-hour-of-week Welford baselines              |
| `engine/baseline_app_test.go`         | 4     | App baseline tests                                       |
| `engine/drift.go`                     | 5     | Multi-scale drift + Holt exhaustion                      |
| `engine/drift_test.go`                | 5     | Drift tests                                              |
| `engine/probes.go`                    | 6     | Active probes (explicit-arm, hard-budgeted)              |
| `engine/probes_test.go`               | 6     | Probe tests including timeout budget                     |
| `engine/phase7_test.go`               | 7     | Change/peer stamping tests                               |
| `docs/RCA_OVERHAUL_PROGRESS.md`       | doc   | This file                                                |

### Modified files

| Path                              | Phases | Change summary                                                       |
|-----------------------------------|--------|----------------------------------------------------------------------|
| `model/snapshot.go`               | 1,4,6  | `Evidence.{FirstSeenAt,SustainedForSec}`, `AppBehaviorAnomaly`, `ProbeResult`, fields on `AnalysisResult` |
| `engine/rca.go`                   | 1      | `stampSustainedDurations()` hook before health decision              |
| `engine/rca_history.go`           | 1,7    | Lifecycle states; Confirmed-only persistence; ChangesAtConfirm stamping |
| `engine/history.go`               | 2      | `History.FastPulse` field                                            |
| `engine/engine.go`                | 1-7    | NewEngine wiring (FastPulse, TraceArmer, ProbeRunner) + Tick hook    |
| `engine/changes.go`               | 7      | dnf/yum history parsing in addition to dpkg                          |
| `cmd/root.go`                     | 3      | `trace` subcommand registration                                      |

### Untouched / deliberately not refactored

- All four detectors (`engine/rca_cpu.go`, `engine/rca_memory.go`,
  `engine/rca_io.go`, `engine/rca_network.go`) — their `v2TrustGate` calls
  remain duration-agnostic by design (they're for per-domain score bumps,
  not lifecycle promotion).
- `engine/alertstate.go` — already had hysteresis + sustained transitions.
- `engine/scoring.go:v2TrustGate` — already had diversity gate.
- `engine/config_drift.go`, `engine/changes.go` (process tracking) — already
  populated `result.Changes`.

---

## Test inventory <a name="test-inventory"></a>

39 new tests across 7 phases. All passing. Full `go test ./...` is clean.
`go vet ./...` is clean.

| Phase | File                                | Tests | Notable cases                                              |
|-------|-------------------------------------|-------|------------------------------------------------------------|
| 1     | `engine/evidence_tracker_test.go`   | 8     | Tick-1 sustained=0; tick-2 sustained=~3 s; v2-fails-blocks-confirm |
| 1     | `engine/lifecycle_test.go`          | 5     | Single bad sample stays Suspected; Confirmed persists; flapping doesn't persist |
| 2     | `engine/fastpulse_test.go`          | 4     | Streak accrues; below-threshold resets; refines SustainedFor over coarse |
| 3     | `engine/trace_test.go`              | 4     | Self-disarm after dump; off-mode no-op; runner-up gap captured; gate fail reason |
| 4     | `engine/baseline_app_test.go`       | 4     | Normal load no-anomaly; abnormal load triggers; frozen-during-incident |
| 5     | `engine/drift_test.go`              | 5     | Steady no-warning; slow rise triggers; frozen-during-incident; below-min ignored |
| 6     | `engine/probes_test.go`             | 6     | Disabled by default; rate limit; output capped; **timeout budget enforced** (key) |
| 7     | `engine/phase7_test.go`             | 3     | 20-entry cap; changes stamped at Confirm; fleet peers stamped       |

### Total runtime of new tests

`go test ./engine/ -run 'evidence|lifecycle|FastPulse|Trace|AppBaseline|Drift|Probe|phase7' -v`
runs in ~7 s (the ProbeRunner timeout-budget test alone takes 6 s by design
— it spawns a `sleep 30` and verifies xtop kills it within budget).

---

## Snapshot record

This document was written **2026-05-05** at the conclusion of the
phase-1-through-7 implementation. The repository git status was clean
(no uncommitted changes from previous work) at the start of this session;
all changes from this session are in the working tree, not yet committed.

To commit the work as one logical unit:

```bash
git add model/ engine/ cmd/ docs/RCA_OVERHAUL_PROGRESS.md
git commit -m "$(cat <<'EOF'
RCA overhaul phases 1-7: verdict discipline + verification toolchain

Phase 1: per-evidence sustained tracking, Suspected→Confirmed lifecycle,
         Suspected-only never persists.
Phase 2: 500ms PSI fast pulse for sub-second onset.
Phase 3: trace mode — full A→Z reasoning to ~/.xtop/traces/trace-*.{json,md}.
Phase 4: per-app, per-hour-of-week Welford baselines, frozen during incident.
Phase 5: multi-scale drift detection (short/long/ref) + Holt exhaustion ETAs.
Phase 6: explicit-arm active investigation probes, hard-budgeted.
Phase 7: dpkg+dnf change correlation, Confirmed incidents stamp changes
         and fleet peers at promotion time.

Resource cost: ~7 MB RSS, +2% CPU vs vanilla. All structures bounded.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```
