# Next-Generation RCA Architecture for xtop

## Goal

Refactor `xtop` from a heuristic scorer into a proof-oriented, enterprise-grade RCA platform for multi-app Linux hosts.

Primary design target:

- Extremely high precision
- Very low false positives
- Strong multi-level verification
- Baseline-aware analysis
- SRE-aligned reasoning
- Clear abstention when proof is insufficient

Important constraint:

- A generic engine for "most apps on one host" cannot honestly guarantee 99.9% precision on every case.
- The only realistic path toward a 0.1% false-positive target is strict abstention.
- The engine must prefer `INCONCLUSIVE` over weak or speculative RCA.

This design therefore optimizes for:

- Precision over coverage
- Formal proof chains over heuristic narratives
- Deterministic replay and validation over ad hoc confidence claims

## Current Code Anchors

These are the main current integration points to evolve:

- Collection entry: [collector/collector.go](/home/xtop/collector/collector.go:158)
- Snapshot model: [model/snapshot.go](/home/xtop/model/snapshot.go:5)
- Engine tick orchestration: [engine/engine.go](/home/xtop/engine/engine.go:387)
- Current RCA pass: [engine/rca.go](/home/xtop/engine/rca.go:184)
- Current causal graph: [engine/causal_graph.go](/home/xtop/engine/causal_graph.go:13)
- Current temporal correlation: [engine/temporal.go](/home/xtop/engine/temporal.go:13)

## Architectural Principles

1. Raw facts first, explanations later.
2. User-visible symptoms come before bottleneck scoring.
3. Ownership must be explicit.
4. Causality requires temporal ordering, not co-occurrence.
5. Baselines support detection, not proof by themselves.
6. RCA output must include both supporting and rejected hypotheses.
7. Every high-confidence RCA must be replayable from stored evidence.
8. LLM-style narrative generation must never sit in the decision path.

## Target System Overview

Build the RCA engine around six cores:

1. Fact Collection Layer
2. Evidence Normalization Layer
3. Entity Graph Layer
4. Hypothesis Engine
5. Multi-Level Verification Layer
6. Incident and Learning Layer

The result is not "smarter scoring". It is a local proof system.

## 1. Fact Collection Layer

Collectors should acquire evidence only. They should not perform RCA.

### Always-on low-cost inputs

- `/proc`
- `/sys`
- cgroups
- PSI
- conntrack
- TCP state tables
- sockets
- file descriptor pressure
- mount usage and growth
- process tree
- systemd units
- container and pod identity

### Always-on event stream

Use eBPF as a first-class source for hard cases:

- off-CPU time
- scheduler delay
- lock and futex wait
- direct reclaim stalls
- block IO latency
- writeback stalls
- cgroup throttling
- TCP retransmits
- drop reasons
- resets
- OOM events
- exec events
- DNS anomalies

### App telemetry adapters

Two adapter classes:

- Generic adapters
  - process-level
  - port/socket-level
  - runtime-level
  - health endpoint
  - logs
  - config and deploy signals
- Deep adapters
  - MySQL
  - PostgreSQL
  - Redis
  - MongoDB
  - Nginx
  - Apache
  - PHP-FPM
  - JVM
  - .NET
  - Node.js
  - queues and brokers

### Change feed

Track likely initiating events:

- config drift
- deploy markers
- package upgrades
- service restarts
- container image changes
- kernel and sysctl changes

## 2. Evidence Normalization Layer

All raw signals must become typed facts with provenance.

### New package

- `facts/`

### Fact schema

Each signal becomes a `Fact`:

- `ID`
- `Type`
- `Source`
- `EntityID`
- `OwnerID`
- `Domain`
- `Metric`
- `Value`
- `Unit`
- `MeasuredAt`
- `FirstSeenAt`
- `LastSeenAt`
- `Duration`
- `Confidence`
- `BaselineDelta`
- `Tags`

### Evidence classes

Facts should be classified into:

- symptom facts
- saturation facts
- ownership facts
- dependency facts
- change facts
- verification probe facts

No RCA logic should live here.

## 3. Entity Graph Layer

The engine needs a live same-host graph, not just flat metrics.

### New package

- `entitygraph/`

### Graph edges

Model:

- process -> process tree
- process -> cgroup
- process -> service
- process -> runtime
- process -> container or pod
- process -> socket
- process -> fd
- process -> mount or disk activity
- service -> port
- service -> upstream dependency
- service -> downstream client

### Why this matters

For "most apps on one host", strong RCA depends on answering:

- who owns the resource?
- who is affected?
- who is upstream?
- who is downstream?
- what changed?

Without this graph, the engine can detect saturation but cannot prove blame.

## 4. Hypothesis Engine

Replace the current monolithic RCA scoring pass with bounded candidate generation.

### New package

- `hypothesis/`

### Candidate model

Each candidate should be explicit:

- mechanism
- root entity
- affected entities
- expected facts
- optional corroborating facts
- disqualifying facts
- preliminary score

### Examples

- CPU contention in service `X`
- memory pressure causing reclaim in service `Y`
- swap-induced disk stall impacting service `Z`
- lock contention in process group `A`
- conntrack exhaustion causing inbound packet loss for app `B`
- downstream database stall propagating to web tier on same host
- deploy regression introducing GC or lock amplification

### Candidate sources

Generate candidates from:

- symptom detectors
- saturation detectors
- ownership graph
- change events
- app adapters

The hypothesis engine proposes. It does not confirm.

## 5. Multi-Level Verification Layer

This layer is the core of the design.

### New package

- `verifier/`

### Required gates

Every RCA candidate must pass these gates:

1. Signal quality gate
   - data complete enough?
   - collection quality sufficient?
   - source confidence acceptable?

2. Baseline deviation gate
   - is the signal abnormal for this host, service, entity, and time-of-week?

3. Temporal ordering gate
   - did the claimed cause start before the effect?
   - did it sustain long enough?

4. Ownership consistency gate
   - does the claimed root entity actually own the stressed resource?

5. Blast-radius consistency gate
   - do the affected entities match the proposed cause?

6. Counter-evidence rejection gate
   - is there strong evidence against the mechanism?

7. Deep probe confirmation gate
   - if needed, run bounded active confirmation probes

### Verification tiers

Use four output tiers:

- `Tier A Confirmed`
  - 3 or more independent evidence families
  - correct temporal sequence
  - owner match
  - no counter-evidence
  - deep confirmation if required
- `Tier B Verified`
  - 2 strong evidence families
  - no major contradictions
- `Tier C Probable`
  - plausible, but not proven
- `Tier D Inconclusive`
  - impact exists, root cause not sufficiently proven

Only `Tier A Confirmed` should count toward a 0.1% false-positive target.

### Core rule

If proof is weak, return `INCONCLUSIVE`.

## 6. Incident and Learning Layer

Learning is useful, but it must not masquerade as proof.

### New package

- `incident/`

### Incident lifecycle

- `suspected`
- `verified`
- `confirmed`
- `resolved`

### Persisted incident frame

Store:

- raw facts
- entity graph snapshot
- candidates
- verifier decisions
- probes run
- final RCA
- rejected RCA candidates

This must support full offline replay.

### Learning use cases

Use learning for:

- adaptive thresholds
- seasonal baselines
- service normal envelopes
- expected variance
- prior likelihoods
- calibration

Do not use learning alone to assert causality.

## Package Layout

Add the following packages:

- `facts/`
  - typed evidence model
- `entitygraph/`
  - host-local dependency and ownership graph
- `detectors/`
  - pure detection modules
- `hypothesis/`
  - candidate RCA generation
- `verifier/`
  - multi-level proof engine
- `incident/`
  - ledger, lifecycle, replay data
- `adapters/`
  - generic and deep app adapters
- `scheduler/`
  - collector dependency DAG
- `bench/`
  - replay, precision scoring, corpus tooling

Keep:

- `collector/` for acquisition
- `engine/` for orchestration
- `model/` for shared structs

Thin out `engine/rca.go` so it becomes orchestration, not the full inference body.

## Data Model Changes

Extend [model/snapshot.go](/home/xtop/model/snapshot.go:5) with:

- `Facts []Fact`
- `Entities EntityGraphSnapshot`
- `Symptoms []Symptom`
- `Candidates []RCACandidate`
- `Verified []VerifiedCause`
- `DecisionTrace DecisionTrace`
- `CollectionQuality CollectionQuality`

### Core new structs

#### `Fact`

- `ID`
- `Type`
- `Source`
- `EntityID`
- `OwnerID`
- `Domain`
- `Metric`
- `Value`
- `Unit`
- `MeasuredAt`
- `FirstSeenAt`
- `LastSeenAt`
- `Duration`
- `Confidence`
- `BaselineDelta`
- `Tags`

#### `Entity`

Represents:

- process
- service
- cgroup
- container
- runtime
- socket endpoint
- mount
- disk owner
- dependency endpoint

#### `RCACandidate`

- `Mechanism`
- `RootEntityID`
- `AffectedEntityIDs`
- `RequiredFacts`
- `OptionalFacts`
- `RejectedBy`
- `PreliminaryScore`

#### `VerifiedCause`

- `Tier`
- `Mechanism`
- `RootEntityID`
- `BlastRadius`
- `ProofFacts`
- `RejectionChecksRun`
- `Confidence`

#### `DecisionTrace`

- all gates passed
- all gates failed
- evidence used
- evidence ignored
- probes executed
- candidates rejected

## Processing Pipeline

Replace the current single RCA pass with this sequence:

1. `CollectRaw`
   - gather collector outputs and event streams
2. `NormalizeFacts`
   - convert raw metrics and events into typed facts
3. `BuildEntityGraph`
   - connect processes, services, sockets, cgroups, mounts, and dependencies
4. `DetectSymptoms`
   - identify user-visible impact first
5. `GenerateCandidates`
   - propose bounded RCA hypotheses
6. `VerifyCandidates`
   - apply all proof gates
7. `RankOrAbstain`
   - return confirmed causes or `INCONCLUSIVE`
8. `PersistIncidentFrame`
   - store everything required for replay

## Collector Execution Model

Current concurrent collection in [collector/collector.go](/home/xtop/collector/collector.go:162) assumes non-security collectors are independent. That is not correct enough for enterprise RCA.

Replace it with a dependency-aware scheduler.

### New package

- `scheduler/`

### Phase plan

#### Phase 0: static identity

- sysinfo
- host identity
- environment metadata

#### Phase 1: base metrics

- CPU
- memory
- PSI
- disk
- network
- filesystem

#### Phase 2: ownership and topology sources

- process
- cgroup
- sockets
- fd
- identity

#### Phase 3: enrichment

- runtime
- apps
- profiler
- security
- logs

#### Phase 4: expensive confirmation probes

- only when an incident is active
- hard budgets
- rate limiting
- abortable

### Collector rule

Collectors should ideally write into isolated result objects, then merge centrally.

Do not allow concurrent mutation of shared snapshot regions that other collectors read.

## Detector Model

### New package

- `detectors/`

### Detector responsibilities

Each detector emits facts and candidate hints, not final RCA.

Examples:

- CPU saturation detector
- memory pressure detector
- reclaim detector
- slab leak detector
- writeback stall detector
- block queue saturation detector
- network retrans/drop detector
- conntrack exhaustion detector
- lock wait detector
- off-CPU stall detector
- GC pause detector
- deploy/config regression detector

## Baseline Strategy

Use multiple baselines, not one.

### Required baseline scopes

- host baseline
- service baseline
- entity baseline
- hour-of-week seasonal baseline

### Baseline outputs

For each fact:

- absolute abnormality
- delta from local norm
- deviation from entity norm
- expected periodicity
- variance band

### Strict rule

Baselines support anomaly detection.
They do not prove root cause.

## Generic Mode and Deep Adapter Mode

To support "most apps on one host", split support into two modes.

### Generic Mode

Works for almost everything using:

- process
- cgroup
- runtime
- sockets
- network ownership
- logs
- config
- generic health checks

Expected outcome:

- strong resource RCA
- medium blame precision
- high abstention

### Deep Adapter Mode

For major supported stacks with deeper internals:

- db engines
- caches
- web servers
- PHP-FPM
- JVM
- .NET
- queues

Expected outcome:

- better app-specific proof
- lower abstention
- higher precision

This is the only realistic way to support "most apps" without pretending all stacks are equally observable.

## Cross-App Same-Host RCA

For multiple apps on the same host, support these cause classes explicitly:

- one app saturates CPU and starves another
- one app triggers reclaim and causes swap or IO pressure that hurts others
- one app floods local sockets or conntrack
- one app fills a shared filesystem or inode pool
- one app causes block or lock contention in shared dependencies
- one runtime stalls the scheduler or CPU cache and affects neighbors

Each class must have:

- formal candidate generator
- formal verifier gates
- formal negative-evidence checks
- replay tests

## Enterprise Guardrails

### Determinism

- same input facts must produce same RCA output

### Auditability

- every RCA must include proof facts and rejected alternatives

### Replayability

- every incident frame must be re-runnable offline

### Bounded probes

- no unbounded active probing
- budgets and deadlines required

### Self-preservation

- the observer must not materially worsen host health

### Separation of concerns

- collection
- normalization
- graphing
- detection
- verification
- narrative

must remain separate

## SRE Principles Embedded

This architecture follows:

- Golden Signals for impact
- USE for resource saturation
- dependency-aware blast-radius analysis
- change correlation before speculation
- error-budget and burn-rate hooks where available
- precision-first abstention
- root-cause vs symptom separation
- contributing factor vs initiating event separation

## What Must Change in Current xtop

### 1. Remove package-global RCA state

Current globals in [engine/rca.go](/home/xtop/engine/rca.go:15) must become `Engine` fields.

This includes:

- adaptive threshold DB
- causal graph
- topology correlator

### 2. Fix collector scheduling

Current assumptions in [collector/collector.go](/home/xtop/collector/collector.go:162) are not strong enough for deterministic enterprise RCA.

Introduce a collector DAG and isolated merge model.

### 3. Fix result finalization ordering

`PrimaryScore`, `Health`, and `Confidence` must be finalized once at the end of the pipeline.

Current post-health score mutation must be removed.

### 4. Demote current probabilistic causal graph

[engine/causal_graph.go](/home/xtop/engine/causal_graph.go:13) should not be the primary RCA logic.

Use it only as:

- weak prior
- offline exploratory learner
- replay analysis tool

Never as proof by itself.

### 5. Split current RCA into stages

Current [engine/rca.go](/home/xtop/engine/rca.go:184) should be decomposed into:

- detection
- candidate generation
- verification
- ranking
- finalization

### 6. Add incident replay harness

Every serious RCA rule must be benchmarked against stored incident corpora.

## Recommended Rollout Plan

### Phase 1: Correctness and Stability

- fix collector dependency and shared-state issues
- fix score and health finalization ordering
- move global RCA state into engine instances
- keep current RCA outputs for compatibility

### Phase 2: Fact Model

- introduce `Fact`
- normalize existing metrics into typed facts
- add decision trace skeleton

### Phase 3: Entity Graph

- implement process/service/socket/cgroup/mount graph
- add owner mapping for CPU, memory, IO, network

### Phase 4: Candidate and Verifier Split

- migrate current heuristic rules into candidate generators
- build verifier gates
- introduce `INCONCLUSIVE` as a first-class result

### Phase 5: Incident Ledger and Replay

- store incident frames
- build offline replay harness
- start measuring precision by mechanism

### Phase 6: Deep Adapters

- add major app adapters
- promote only well-verified stacks to higher RCA confidence tiers

### Phase 7: Precision Program

- gate releases on replay precision
- report Tier A precision separately from overall coverage
- reject over-claiming

## Success Criteria

The design is successful when:

- no high-confidence RCA is emitted without a stored proof chain
- replay of an incident yields the same RCA output
- precision is measured per mechanism and per adapter
- `INCONCLUSIVE` is treated as healthy behavior for weak evidence
- Tier A precision becomes the main KPI
- the system is trusted because it refuses weak calls

## Final Position

The best next-generation enterprise design for `xtop` is:

- a host-local observability substrate
- with typed facts
- a live entity graph
- deterministic candidate generation
- multi-level verification
- strict abstention
- replayable decision traces
- workload-specific deep adapters where available

That is the realistic architecture for extremely low false positives on multi-app Linux hosts.
