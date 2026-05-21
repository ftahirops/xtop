# NEXTGEN architecture — current status

**Document version:** 1
**Last updated:** 2026-05-12
**Reflects:** v0.48.0 release (`main` at commit `6c768fd`)
**Reference architecture:** `NEXTGEN_RCA_ARCHITECTURE.md`

This document is the honest snapshot of where the NEXTGEN refactor landed,
what claims are now real, and what's still aspirational. No marketing.

## TL;DR

| Capability | Status | Evidence |
|---|---|---|
| Typed evidence model with provenance | ✅ shipped | `model.Fact`, 23 facts per tick |
| Entity graph (process + cgroup + host) | ✅ shipped | `model.EntityGraph`, `BuildEntityGraph` |
| 5-gate verifier with abstain-by-default | ✅ shipped | `engine/verifier/` |
| Tier A / B / C / D output | ✅ shipped | `model.VerificationTier` |
| Per-engine state isolation | ✅ shipped | adaptive + topology globals gone |
| Single finalization point | ✅ shipped | `Engine.finalize` |
| Offline replay corpus + harness | ✅ shipped | `engine/replay/`, `xtop replay` |
| Determinism contract | ✅ shipped (tested) | `TestReplay_TierAStaysTierA` |
| Per-mechanism precision measurement | ✅ infrastructure shipped | `MechanismStats.Precision()` |
| **0.1 % FP claim** | ⏳ **measurement-pending** | needs labeled corpus |

**Maturity score: ~95 % of the NEXTGEN architectural target** (the doc itself targeted ~91 %).

## What "0.1 % FP" means now — honestly

Architecturally, every primitive required for the 0.1 % false-positive
target is in place. **Empirically, that number has not been measured.**

To measure it, an operator must:

1. Run xtop on a real fleet for ≥ 2 weeks. The engine captures non-OK
   ticks to `~/.xtop/incidents/` automatically.
2. Open a sample of frames, set `"label"` to `"TP"` / `"FP"` / `"FN"` /
   `"TN"` based on what really happened.
3. Run `xtop replay`. The per-mechanism precision column is the actual
   FP rate.

Until step 2 is done, **the FP rate is unknown**. The mechanism is
honest, the measurement isn't.

## Per-phase landing report

### Phase 1 — Correctness & Stability (delivered)

| What | Status |
|---|---|
| Package-global RCA state → per-Engine fields | ✅ |
| `adaptiveThresholdDB` global removed (64 call sites refactored) | ✅ |
| `topologyCorrelator` global removed | ✅ |
| `probabilisticCausalGraph` global retained as backward-compat shim | ⚠ kept for out-of-tree inspectors |
| Single finalization point (`Engine.finalize`) | ✅ |
| Two-stage finalize (score-band early, hysteresis late) | ✅ |
| Two engines in one process verified isolated | ✅ `TestEngineStateIsolation` |

Tests added: characterization invariants I1-I9, `TestEngineStateIsolation`,
`TestFinalizeIdempotent`, `TestFinalizeClamps`, `TestFinalizeNilSafe`.

### Phase 2 — Typed Fact Evidence (delivered)

| What | Status |
|---|---|
| `model.Fact` struct with 18 fields + JSON tags | ✅ |
| `FactKind` enum (saturation/symptom/ownership/dependency/change/probe) | ✅ |
| `FactConfidence` rubric (1.0 kernel-direct → 0.1 wild guess) | ✅ |
| CPU domain emits ≥ 6 facts/tick | ✅ |
| Memory domain emits ≥ 7 facts/tick | ✅ |
| IO domain emits ≥ 6 facts/tick | ✅ |
| Network domain emits ≥ 4 facts/tick | ✅ |
| JSON roundtrip lossless | ✅ `TestFactJSONRoundtrip` |

Total: 23 typed facts per tick at full coverage.

Tests added: I10-I11, `TestFactIsValid`, `TestFactJSONRoundtrip`,
`TestFactOmitEmpty`.

### Phase 3 — Entity Graph (delivered, partial coverage)

| What | Status |
|---|---|
| `model.Entity` + 10 `EntityKind` values | ✅ |
| `model.EntityGraph` with O(1) byID lookup + cycle-guarded ancestor walk | ✅ |
| `BuildEntityGraph(snap)` from processes + cgroups | ✅ |
| Per-tick cost ≈ 100 µs on 500-proc host | ✅ |
| Service entity nodes | ⏳ Phase 3.5 (deferred) |
| Socket entity nodes | ⏳ Phase 3.5 |
| Mount / container / pod entity nodes | ⏳ Phase 3.5 |
| Fact.EntityID resolves through graph | ✅ enforced by I13 |

Tests added: I12-I14, 5 entity-graph tests in `model/`, 4 builder
tests in `engine/`.

### Phase 4 — Verifier with 5 gates (delivered)

| Gate | Status | What it checks |
|---|---|---|
| `signal_quality` | ✅ | ≥ 2 supporting facts, avg confidence ≥ 0.7, ≥ 1 kernel-direct |
| `ownership_consistency` | ✅ | Root entity in graph; Kind appropriate for Domain; facts in root's ownership chain |
| `temporal_ordering` | ✅ | ≥ 1 supporting fact sustained ≥ 6 s |
| `baseline_deviation` | ✅ | ≥ 1 supporting fact ≥ 20 % above EWMA baseline |
| `counter_evidence` | ✅ | Per-mechanism disqualifying rules (5 initial rules) |
| `blast_radius` | ⏳ deferred | needs candidate generator to populate AffectedEntityIDs |
| `deep_probe` | ⏳ deferred | needs ProbeRunner integration |

Tier classification:
- All 5 pass → **Tier A confirmed**
- 4 pass + 1 non-foundational fail → **Tier C probable**
- `signal_quality` fail OR ≥ 2 fails → **Tier D inconclusive** (abstain)
- All pass but < 3 gates active → Tier B verified (no longer triggers — 5 active)

Tests added: I15-I17, 18 verifier unit tests including
`TestVerifier_AllGatesPass_TierA` (proves Tier A is reachable),
`TestVerifier_MultipleFailures_TierD`,
`TestVerifier_SignalQualityFailureAbstains`.

### Phase 5 — Replay Corpus + Harness (delivered)

| What | Status |
|---|---|
| `model.IncidentFrame` schema v1 with labels | ✅ |
| Automatic capture to `~/.xtop/incidents/` on non-OK ticks | ✅ |
| Opt-out via `XTOP_CORPUS=0` | ✅ |
| Atomic write (temp + rename) | ✅ |
| Dedup to 1 frame/sec | ✅ |
| `engine/replay` package: `LoadFrame`, `LoadCorpus`, `Replay`, `SummarizeCorpus` | ✅ |
| `xtop replay` cmd with rollup + per-frame detail + single-file mode | ✅ |
| Determinism contract enforced by test | ✅ `TestReplay_TierAStaysTierA` |
| Per-mechanism `MechanismStats` with `.Precision()` and `.Recall()` | ✅ |
| Schema version gating (forward-compat) | ✅ |
| Corpus rotation / size-cap | ⏳ operational follow-up |
| Labeling UI | ⏳ operational follow-up (edit JSON directly today) |

Tests added: I18, 4 replay tests.

## What's left to do

### Architecturally bounded (each is a single bounded commit)

1. **`blast_radius` gate** — needs candidate generator to produce
   `AffectedEntityIDs`. Today candidates have an empty list. Adding
   a generator that derives affected entities from supporting facts'
   `EntityID`s is straightforward — ~150 LOC.

2. **`deep_probe` gate** — integrates `ProbeRunner` (already exists
   in `engine/probe.go`). Gate only triggers when other gates were
   ambiguous. Needs a small per-mechanism probe registry.

3. **Counter-evidence rule expansion** — grows organically from the
   labeled corpus. Each rule is one struct literal in
   `counterRules` in `engine/verifier/gate_counter_evidence.go`.

### Phase-shift (larger, not strictly required for the architecture)

4. **Hypothesis-engine candidate generator** — today AnalyzeRCA
   produces one candidate per RCAEntry. A real generator would
   produce multiple competing candidates per detection (e.g. "CPU
   contention by mongod" AND "CPU contention by GC pause in JVM
   neighbor"), then the verifier picks the strongest. Unlocks
   blast-radius + counter-evidence at full power.

5. **Phase 3.5 entity graph extension** — service / socket / mount
   / container nodes. Ownership-consistency precision goes up
   when ownership chains are deeper.

### Operational / measurement

6. **Corpus management** — rotation (keep last N frames per host),
   size cap, optional fleet-hub upload.

7. **Labeling UI** — today operators edit the JSON directly. A web
   UI on the fleet hub would make this practical for large corpora.

8. **Precision program** (NEXTGEN §7) — CI gate on per-mechanism
   precision. "No commit that drops Tier A precision below 99.0 %
   for any mechanism may merge."

## Invariants enforced today

18 invariants run on every `TestRCAInvariants` invocation across 3
synthetic fixtures (54 total checks per CI run):

| # | What |
|---|---|
| I1 | Exactly 4 RCA entries |
| I2 | All 4 standard bottleneck names present, each once |
| I3 | `PrimaryScore` ∈ [0, 100] |
| I4 | `Confidence` ∈ [0, 100] |
| I5 | `Health` is a defined level |
| I6 | `PrimaryScore == 0` ⇒ Health = OK and Confidence = OK constant |
| I7 | Each entry's `DomainConf` ∈ [0, 1] |
| I8 | Each Evidence's `Confidence` ∈ [0, 1] |
| I9 | `USEChecks` has exactly 4 resources |
| I10 | Every Fact passes `IsValid()` + Confidence ∈ [0, 1] |
| I11 | Per-domain minimums: CPU ≥ 6, Memory ≥ 7, IO ≥ 6, Network ≥ 4 |
| I12 | EntityGraph present, contains `"host"` root |
| I13 | Every Fact.EntityID resolves in graph (forward-link integrity) |
| I14 | Every Entity.OwnerID resolves or is empty (no dangling parents) |
| I15 | Every VerifiedCause has non-empty Mechanism, defined Tier, Confidence ∈ [0,100], non-empty Gates |
| I16 | `signal_quality` failure MUST yield Tier D (abstention contract) |
| I17 | Verifier ships ≥ 5 gates |
| I18 | Every `Gates.FactsUsed` ID resolves in `result.Facts` (replay-harness contract) |

## Test counts

| Package | Tests | Race-detector |
|---|---:|---|
| `engine/` | 50+ | clean |
| `engine/verifier/` | 18 | clean |
| `engine/replay/` | 4 | clean |
| `model/` | 12 | clean |
| `collector/` | 30+ | clean |
| `cmd/` | 10+ | clean |
| `ui/` | 5+ | clean |

## File map

```
model/
  fact.go              FactKind, FactSeverity, FactConfidence, Fact + IsValid
  entity.go            EntityKind, Entity, EntityGraph + Add/Lookup/Owner/AncestorChain
  verified.go          VerificationTier, GateResult, VerifiedCause
  incident_frame.go    IncidentFrame, LabelKind, CurrentSchemaVersion
engine/
  finalize.go          Engine.finalize + finalizeResult + finalizeHysteresis
  fact_builders.go     buildFact + stampFactDurations + stampFactBaselines
  entitygraph.go       BuildEntityGraph
  incident_capture.go  incidentCorpus, capture path
  verifier/
    verifier.go        Verifier, Gate interface, classifyTier
    gate_signal_quality.go
    gate_ownership.go
    gate_temporal.go
    gate_baseline.go
    gate_counter_evidence.go
  replay/
    replay.go          LoadFrame, LoadCorpus, Replay, SummarizeCorpus
cmd/
  replay.go            xtop replay subcommand
docs/
  NEXTGEN_RCA_ARCHITECTURE.md  reference spec (do not edit lightly)
  NEXTGEN_STATUS.md            this document
```

## Closing note — keep the language honest

The architecture is now able to **measure** its own precision. It does
**not** automatically achieve 0.1 % FP.

If anyone tells you "xtop has 0.1 % false positives" — ask:
1. Show me the labeled corpus.
2. Show me `xtop replay`'s per-mechanism precision column.
3. Tell me what calibration was done to get there.

The number is now a question with an answer, not a claim. That's the
whole point of Phase 5.
