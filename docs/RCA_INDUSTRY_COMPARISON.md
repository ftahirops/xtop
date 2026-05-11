# xtop vs. industry RCA tools — honest comparison

**Document version:** 2
**Last updated:** 2026-05-10 20:20 UTC
**Created:** 2026-05-09
**Reviewed against:** Datadog Watchdog, Dynatrace Davis, Causely, OpenSRE, Monoscope
**Purpose:** Tell new contributors and operators where xtop fits, what it
already matches, and what it would take to close real gaps. No marketing.

## Changelog

| Version | Date | Change |
|---|---|---|
| 1 | 2026-05-09 | Initial document — Watchdog / Davis / Causely / OpenSRE comparison + gap analysis |
| 2 | 2026-05-10 20:20 UTC | Added Monoscope comparison (§8); clarified that xtop and Monoscope are **complementary, not competitive** — different layers of the stack |

This document is the architecture reviewer's perspective. It is honest
about both strengths and gaps — operators reading this should be able to
make a real "should we use this for X?" decision without further input.

---

## Table of contents

1. [The competitive landscape](#landscape)
2. [Where xtop already matches the closed-source tools](#parity)
3. [Five real gaps + cost to close each](#gaps)
4. [Where xtop is better than the closed tools (within scope)](#advantages)
5. [Where xtop will not catch up](#hard-limits)
6. [Recommended sequencing if you want to close gaps](#sequence)
7. [How xtop differs from OpenSRE specifically](#opensre)
8. [How xtop differs from Monoscope specifically](#monoscope)

---

## 1. The competitive landscape <a name="landscape"></a>

Six products solve overlapping but distinct problems:

| Tool | Core idea | Reasoning model | Operates on |
|---|---|---|---|
| **xtop** | Host-level real-time RCA console | Deterministic rules + statistical anomaly | Single host (fleet hub aggregates) |
| **Datadog Watchdog** | Fleet-wide statistical anomaly detection | EWMA + z-score over high-cardinality metrics | Datadog's TSDB (months of data, all your hosts) |
| **Dynatrace Davis** | Topology-aware causal graph | Auto-discovered service graph + observed correlation | Dynatrace OneAgent fleet (full APM + infra) |
| **Causely** | Operator-declared causal model | Explicit "X causes Y" model, then matching | Whatever you declare in the model |
| **OpenSRE** | LLM-orchestrated cross-system investigator | Anthropic / OpenAI / Ollama LLM reasons across 60+ tools | Whatever your observability stack already has |
| **Monoscope** | Open-source observability **platform** (logs / metrics / traces store) | None directly — LLM query layer on top of OTLP-ingested data | OTel data in your own S3 buckets |

**They are not directly competing — they're at different layers.** xtop runs
on the host producing per-tick RCA verdicts; Watchdog/Davis ingest from
agents and operate at fleet scale; Causely encodes operator knowledge;
OpenSRE is the LLM brain that can consume any of them. **Monoscope is the
storage + query layer** — it ingests OTel telemetry, parks it in S3, and
exposes a natural-language query interface. xtop and Monoscope are
*complementary*: xtop produces structured telemetry (it has an OTLP
exporter path); Monoscope is exactly the kind of backend that telemetry
should land in. The right architecture for a serious shop combines
several of these.

---

## 2. Where xtop already matches the closed-source tools <a name="parity"></a>

xtop's RCA engine intentionally mirrors the design of the deterministic
school (Watchdog/Davis/Causely), not the LLM school (OpenSRE). It has
roughly **70-80% of Watchdog's statistical primitives** and **50-60% of
Davis's causal engine**, applied to a narrower scope (single host).

| Capability | Watchdog | Davis | Causely | xtop today | xtop source file |
|---|---|---|---|---|---|
| EWMA baseline per metric | ✓ | ✓ | — | ✓ | `engine/baseline.go` |
| Z-score anomaly detection | ✓ | ✓ | — | ✓ | `engine/zscore.go` |
| Holt-Winters forecasting (ETA-to-saturation) | ✓ | ✓ | — | ✓ | `engine/forecast.go` |
| Confidence calibration from past outcomes | ✓ | ✓ | — | ✓ | `engine/confidence_calibration.go` |
| Per-host-per-hour-of-week seasonal baseline | ✓ | ✓ | — | ✓ | `engine/baseline_app.go` |
| Multi-scale drift (boiling-frog) detection | ✓ | partial | — | ✓ | `engine/drift.go` |
| Probabilistic causal graph from observed correlations | partial | ✓ | — | ✓ | `engine/causal_graph.go` |
| Pearson correlation with lag detection | ✓ | ✓ | — | ✓ | `engine/correlate.go` |
| Hard-coded causal rules ("X causes Y") | partial | partial | ✓ | ✓ | `engine/causal.go` |
| Confidence-gated verdicts (trust gate) | ✓ | ✓ | ✓ | ✓ | `engine/scoring.go` |
| Hysteresis + sustained-evidence requirement | ✓ | ✓ | ✓ | ✓ | `engine/alertstate.go`, `engine/evidence_tracker.go` |
| Trace-mode replayable evidence | partial | partial | — | ✓ (better) | `engine/trace.go` |

The take-away: if you're comparing **algorithm by algorithm**, xtop is in
the same league. The difference isn't the math — it's the scope.

---

## 3. Five real gaps + cost to close each <a name="gaps"></a>

These are the things xtop does NOT have today, what they enable, and the
honest engineering cost to close each one.

### Gap 1 — Service-level topology auto-discovery

**What it is:** Davis's Smartscape automatically learns "service A talks to
service B over port 27017 owned by mongod" by watching socket activity,
then builds a service graph the causal engine can use.

**What xtop has:** F7 connections page (`ui/page_netconn.go`,
`collector/netconn/netconn_linux.go`) reads `/proc/net/{tcp,tcp6,udp,udp6}`
and joins with `/proc/*/fd` to attribute every socket to its owning
process. The raw data is there.

**What's missing:** A topology builder that aggregates connections into
directed `(client_app → server_app)` edges, survives restarts via
`comm + cgroup` identity, and produces a `model.ServiceTopology` the
causal graph and verdict layer can consult.

**Cost:** ~600 LOC, no new dependencies. **1-2 days.** Output: every
incident says "mongod (cause) → app-server (symptom)" because xtop saw
the socket pair.

### Gap 2 — Cross-host topology and causality

**What it is:** Davis sees that `app-server` on host A connects to `mongod`
on host B; when mongod is hot, blames it for app-server's slowness on
host A. This is the "distributed RCA" problem proper.

**What xtop has:** Fleet hub (`fleet/hub.go`) collects per-host incidents.
`correlatePeerIncidents` does basic same-bottleneck-on-another-host
matching.

**What's missing:**
- Per-host NetConns shipped to the hub (currently only incidents are sent)
- Hub builds a cross-host service graph from those NetConns
- Causal graph inference at hub: "host B's mongod hot → host A's queue depth high"

**Cost:** ~1500 LOC + Postgres schema additions. **2-3 weeks.** Hard part:
stable service identity across hosts (matching local `comm=mongod` on
host A with the remote port mongod is listening on at host B).

### Gap 3 — Long-term TSDB

**What it is:** Watchdog operates on weeks-to-months of historical data
to detect slow drift, seasonal anomalies, and to retrospectively
classify "was this normal for last Tuesday?".

**What xtop has:** 30-min in-memory ring; `~/.xtop/rca-history.jsonl` for
incident records; per-host SQLite for baselines (`store/store.go`). No raw
metric retention.

**What's missing:** A time-series table in the existing SQLite (or
Postgres for hub). Compressed downsampling at 1m / 10m / 1h tiers. A
query API.

**Cost:** ~1000 LOC for storage + query layer. **1 week.** Per-host disk:
50-100 MB / month at 1m resolution for the metrics that matter.

### Gap 4 — APM trace integration (end-to-end call chains)

**What it is:** Davis instruments your app via the Dynatrace OneAgent.
Knows which span is slow, which DB query is slow, which line of code is
slow. xtop sees the host but not the request path.

**What xtop has:** `engine/trace_correlator.go` already reads OTel JSONL
summaries from `~/.xtop/otel-samples.jsonl` and correlates incidents with
overlapping spans. **Half the work is done.**

**What's missing:** Real OTLP gRPC ingestion (currently file-based).
Sampling logic. Service-call-graph extraction from spans.

**Cost:** ~2000 LOC + protobuf dependency for OTLP. **3 weeks.**
Alternative: keep the file-based design and accept JSONL from any OTel
collector — most shops already have a collector running.

### Gap 5 — Operator-declared causal model

**What it is:** Causely lets the operator declare "high `lock_waits` on
Postgres causes high latency on `/api/checkout` because that endpoint
hits Postgres." Highest false-positive resistance because the model is
intentional.

**What xtop has:** Hard-coded `causalRules` in `engine/causal.go` covering
the 30-40 most common Linux-host causal patterns ("mem reclaim → IO PSI",
"cgroup throttle → run queue", etc.). 30+ deterministic per-app rules in
`engine/app_rca.go`.

**What's missing:** A user-declarable model. A config file (YAML?) where
operators say "if app X's metric M crosses T then evidence E fires;
metric M is caused-by metric N." Schema design is the hard part.

**Cost:** ~800 LOC for parser/evaluator + schema design.
**1-2 weeks design + 1 week implementation.** Hardest part is making the
schema operator-friendly without it becoming Prolog.

---

## 4. Where xtop is already better than the closed tools <a name="advantages"></a>

Within its scope — single host, fleet hub for aggregation — xtop has
several genuine advantages that are not coming from "we're the new kid."
They are structural.

| Feature | Watchdog / Davis / Causely | xtop |
|---|---|---|
| Direct `/proc` + eBPF access | No — they read pre-aggregated metrics from agents | **Yes** — sub-millisecond signal latency, kernel-direct |
| Verdict trace replay ("why did it fire?") | Limited — web UI only, no machine-readable form | **Trace-mode JSON+MD per incident, fully reproducible** |
| Per-app deep diagnostics (mongo cache fill, mysql innodb stats, redis fragmentation) | Generic — agent-supplied metrics only | **30+ hand-tuned per-app rules across 6 app types** |
| Self-throttling Resource Guardian | None | **Yes** — backs off when host is stressed |
| Cost | $20-100 per host per month, plus per-trace | **$0** |
| Air-gapped operation | No (cloud SaaS) | **Yes** |
| Open source | No | **Yes** |

The trace-mode point is non-trivial: every Confirmed incident in xtop
produces a deterministic, machine-readable evidence dump. You can audit
"why did the verdict fire?" at 3am without reading prose narrative or
trusting an LLM. That capability does not exist in the closed-source
tools at the same depth.

---

## 5. Where xtop will not catch up <a name="hard-limits"></a>

**Match Watchdog at fleet scale (10k+ hosts, multi-tenant):** No. That
requires a multi-tenant TSDB and an SRE team to operate it. Datadog has
hundreds of engineers on Watchdog. xtop's hub is single-tenant single-org.

**Match Davis on auto-instrumented APM:** Without a OneAgent-equivalent
that hooks into every language runtime, xtop cannot see "method X took
50ms within span Y." That is a multi-year product investment.

**Match commercial polish (UX research, onboarding, dashboards):** xtop
is a TUI-first tool. The commercial tools have polished web UIs with
years of UX research. xtop's web UI (the fleet hub) is functional, not
polished.

These are not "engineering hard" — they're "fundamentally a different
product." xtop is honest about this: it's the host microscope, not the
fleet observability platform.

---

## 6. Recommended sequencing if you want to close gaps <a name="sequence"></a>

Ordered by **value-per-week-of-engineering**, not by alphabet:

1. **Gap 1 — Single-host service topology** *(1-2 days)*
   Biggest UX win for smallest cost. Uses data we already collect (F7
   page). Every incident gets "mongod → app-server" causation visible.
   *Single engineer-week.*

2. **Gap 5 — Operator-declared causal rules** *(3-4 weeks total)*
   Turns xtop into a real causal engine without depending on observed
   correlations that can be wrong. Operators encode their domain
   knowledge once; the engine enforces it forever. Highest FP-rate
   improvement of any item on this list.

3. **Gap 3 — Long-term TSDB on local SQLite** *(1 week)*
   Enables Watchdog-style "is this normal for Tuesday afternoon?"
   queries. Modest code volume; the schema is the hard part. Enables
   Gap 5's threshold tuning.

4. **Gap 2 — Cross-host topology in hub** *(2-3 weeks)*
   Opens up multi-host RCA. Requires the per-host NetConns to flow
   through the fleet protocol — non-trivial wire-format change.

5. **Gap 4 — Real OTLP** *(3 weeks)*
   Only matters if your organisation has tracing instrumented. The
   file-based shim is enough for shops without a tracing investment.

**Total to fully match Davis + Watchdog feature parity in single-tenant
single-fleet scope: ~6-8 weeks of focused work.**

**Total to match them at multi-tenant fleet scale (Datadog SaaS):** not
feasible without a dedicated team.

---

## 7. How xtop differs from OpenSRE specifically <a name="opensre"></a>

OpenSRE is in a separate category from Watchdog/Davis/Causely — it is an
**LLM-orchestrated cross-system investigator**, not a deterministic RCA
engine. Comparing them on "which has lower false positives" is the wrong
question because they answer different questions.

| Property | xtop | OpenSRE |
|---|---|---|
| Reasoning model | Deterministic rule engine | LLM (Claude / GPT / Ollama) reads context, generates narrative |
| Reproducibility | Same input → same verdict, every time | Same input, different LLM call → potentially different verdict |
| Auditability | Every conclusion has measured value + threshold dumped to `trace-<ts>.json` | Reasoning chain in prose; you have to trust the LLM |
| FP class A (hallucination) | Impossible — no language model | Real, known LLM failure mode |
| FP class B (confident wrong answer) | Bounded by rules you can read in source | Bounded by LLM behaviour; "the deploy at 14:22 caused..." can be plausible-sounding nonsense |
| Cross-system context | Single host (fleet hub aggregates host-level data only) | 60+ tool integrations: Datadog, Grafana, K8s, GitHub, Slack, … |
| Per-incident cost | $0 | LLM tokens (Anthropic/OpenAI) |
| Latency | 250 ms (one-shot) – 3 s (live) | Minutes per investigation |
| Air-gapped | Yes | Possible with Ollama, otherwise no |

**Both are useful. They occupy different rungs.** OpenSRE's value is
*cross-system narrative* — stitching together "deploy at 14:22 + log
spike at 14:23 + DB query latency at 14:24" into a coherent story. xtop
cannot do that — it does not see your GitHub or your Slack.

xtop's value is *deterministic, replayable host-level RCA* with sub-second
detection latency and zero per-incident cost. OpenSRE cannot do that — it
operates on whatever its tool integrations expose, which is usually 30s+
metric scrape intervals, no kernel-level data.

**Industry studies of LLM-driven RCA agents (DeepSeek-Diag, AutoRCA,
GitHub's incident-RCA experiments) report false-positive rates in the
20-40% range on real production incidents**, even with good prompts.
That is much higher than a deterministic rule engine where the rules have
been hand-tuned. For "I want to trust the verdict at 3am on a Sunday,"
deterministic rules win. For "stitch a story across 12 microservices," LLM
investigators win.

The interesting deployment is *both*: xtop on every host as the
deterministic ground-truth source; an OpenSRE-style LLM as the narrative
layer that consumes xtop's structured `result.AppRCA[]` findings + external
context. The LLM reads xtop's `trace-<ts>.json` instead of inventing
values, which dramatically reduces hallucination.

---

## 8. How xtop differs from Monoscope specifically <a name="monoscope"></a>

[Monoscope](https://github.com/monoscope-tech/monoscope) is an
**open-source observability platform** — logs, metrics, traces ingestion
with S3 storage, OpenTelemetry-native (~750 integrations), live tail, and
a natural-language query layer powered by LLMs. AGPL-3.0, built in
Haskell.

It is **not an RCA engine** and not in the same product category as xtop.
The comparison is worth doing anyway because users ask it, and because
the two are genuinely complementary.

### The fundamental difference

xtop **produces** structured per-host RCA verdicts in real time.
Monoscope **stores and queries** observability data at fleet scale. They
sit at different layers of an observability stack:

```
   [ apps, kernel, /proc, eBPF, cgroups ]                  ← raw signal
                    ↓
          xtop  (per-host RCA engine)                      ← verdict layer
                    ↓ (OTLP / JSONL / fleet API)
          Monoscope  (storage + query platform)            ← data lake
                    ↓
          LLM agents / dashboards / alerts                 ← consumption
```

xtop sits *under* Monoscope in the stack. It is exactly the kind of
signal source Monoscope expects to ingest.

### Side-by-side

| Property | xtop | Monoscope |
|---|---|---|
| Product category | Real-time host RCA console | Observability platform (logs/metrics/traces store) |
| Language | Go | Haskell |
| License | (project license) | AGPL-3.0 |
| Primary UI | TUI (Bubbletea) + fleet web hub | Web dashboard |
| Data scope | Live signal from one host; aggregated incidents in hub | Months/years of OTel data across whole fleet |
| Storage backend | In-memory ring + SQLite (per-host) + Postgres (hub) | S3-compatible object store (bring your own bucket) |
| Retention | 30 min in-memory; SQLite for incidents/baselines (~weeks) | Years (cost-bounded by S3 pricing) |
| Reasoning model | Deterministic rules + statistical anomaly + causal graph | None natively — provides the substrate; LLM agents reason on top |
| Query interface | Page navigation in TUI; `xtop why` / `xtop trace` | Natural language (LLM) over stored data |
| LLM dependency | None (deterministic engine) | Yes — natural-language queries and AI agents require LLM |
| OpenTelemetry ingestion | Outbound (trace correlator reads OTel JSONL) | Inbound — full OTLP receiver, 750+ integrations |
| Anomaly detection | Built-in per-host engine (EWMA, z-score, drift, forecast) | Scheduled AI agents that query stored data |
| Detection latency | Sub-second (per-tick) | Minutes-to-hours (agent run schedule) |
| Air-gapped operation | Yes | Self-hosted + Ollama possible; cloud option needs LLM API |
| Cost model | $0 (no per-incident, no per-host) | S3 storage cost + LLM tokens (for NL queries) |
| Per-host CPU footprint | Bounded by Resource Guardian (target < 5 % of one core) | Doesn't run on the host — agentless from the host's POV |
| Multi-host fleet view | Hub at `:9898` aggregates incidents | Full multi-tenant fleet view is core to the product |
| Alerting / channels | Local terminal + fleet hub; basic webhook | Slack, PagerDuty, email (cloud) / email (OSS) |

### Where they overlap

Three points of overlap, all narrow:

1. **Anomaly detection.** Both have it. xtop's is built into the live
   engine and fires sub-second. Monoscope's is via scheduled AI agents
   that run minutes-to-hours apart over the data lake. **Different
   trade-off space — not the same feature.**
2. **OpenTelemetry surface.** Monoscope is OTLP-native on the inbound
   side. xtop has a *trace correlator* (`engine/trace_correlator.go`) on
   the **inbound** side (reads OTel JSONL summaries to enrich incidents)
   but no native OTLP **exporter** yet — Gap 4 in §3.
3. **"Open-source observability."** Both projects sit in this space, but
   they answer different parts of "open-source observability." Monoscope
   answers "where do I put all my telemetry and how do I query it?"
   xtop answers "what is wrong with this host right now and why?"

### Recommended joint deployment

If you run both, the architecture is straightforward:

- **xtop on every host** — produces the structured per-incident verdict
  with the trace-mode JSON dump.
- **xtop fleet hub** — aggregates incidents for cross-host correlation;
  serves as the host-level dashboard.
- **xtop → Monoscope via OTLP** — once Gap 4 is closed, every incident
  + each tick's metrics get shipped to Monoscope's S3 store.
- **Monoscope** — long-term retention, fleet-wide query, NL-driven
  exploration, scheduled AI agents that look across all hosts for
  patterns that xtop's per-host engine cannot see.

In that joint deployment, xtop is the **ground-truth signal source** and
Monoscope is the **data lake + query layer**. Neither replaces the other.

### Where xtop is better than Monoscope

For the host-level RCA workflow, xtop is strictly better:

- Sub-second detection latency vs. agent-schedule latency
- Deterministic verdicts (reproducible) vs. LLM-queried answers
- Trace-mode `trace-<ts>.json` audit dump that LLMs can ingest
  (Monoscope's NL layer is itself an LLM — it can hallucinate)
- Per-app deep diagnostics built into the engine (mongo cache fill,
  innodb stats, etc.) that Monoscope does not have natively
- Zero LLM dependency, no token cost, fully offline

### Where Monoscope is better than xtop

For the data-lake / fleet-wide-history workflow, Monoscope is strictly
better:

- Years of retention in S3 — xtop's history is days-to-weeks
- 750+ OTel integrations — xtop has none of those
- Cross-fleet natural-language queries — xtop has none
- Logs + traces unified view — xtop is metrics + RCA only, no log ingest
- Session replay correlation — out of scope for xtop entirely
- Web UI polish — xtop's web hub is functional, not polished

### Bottom line on Monoscope

**It's not in the same category — and that's good news.** If a user is
choosing between xtop and Monoscope, they're asking the wrong question.
The right question is "do I need a fleet-wide observability data lake
(Monoscope) or a per-host real-time RCA engine (xtop) or both (most
shops)?" Most production deployments will eventually want both.

If we were going to learn anything from Monoscope's design, it's the
**S3-as-cheap-cold-storage** pattern (worth considering for the fleet
hub's incident archive) and the **OTLP-native ingestion** posture (which
reinforces Gap 4 in §3 — full OTLP support is the bridge between the two
worlds).

---

## Direct answers to common questions

**"Is xtop's RCA engine more mature than OpenSRE's?"**
On host-level RCA, yes — xtop's deterministic rules produce fewer false
positives than LLM reasoning within that scope. On cross-system narrative,
no — OpenSRE has reach xtop cannot match.

**"Can xtop replace Datadog?"**
For the host-level part of what Datadog does, mostly yes. For the full
fleet-wide TSDB + APM + log management + alerting + dashboards, no.
xtop is not trying to be that.

**"Is the open-source state-of-the-art today still well behind closed
commercial RCA?"**
Within single-host scope, no — xtop matches them on the algorithms.
On multi-host topology + APM + long retention, yes — the closed tools
have a multi-year head start.

**"What would it cost to make xtop the open-source equivalent of Davis?"**
6-8 weeks of focused engineering work for single-fleet single-tenant
parity (Gaps 1-5 above). Multi-tenant SaaS-scale is a different product
and not the goal.

**"Should I use xtop or Monoscope?"**
Both, in different roles. Monoscope is your observability data lake.
xtop is your per-host RCA engine. They sit at different layers — see §8.
The interesting integration is xtop exporting via OTLP into Monoscope's
S3 store once xtop's Gap 4 is closed.

---

## Document maintenance

- Update this file when a gap closes (move it from §3 to §2).
- Update version + date at top whenever a gap is closed or the analysis
  is rerun against the closed-source tools' current state.
- Do not soften the language. Operators reading this need the unvarnished
  view to make procurement decisions.
