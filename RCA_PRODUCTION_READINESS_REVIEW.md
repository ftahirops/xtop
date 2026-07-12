# xtop RCA Production Readiness Review

Date: 2026-07-12

## Verdict

The RCA engine is not fully production-ready for "all server types" or "all production issue types."

It is a substantial Linux host RCA system with useful coverage for CPU, memory, IO, network, some app metrics, journal signatures, config drift, narratives, actions, history, and runbooks. But it is not a complete causal diagnosis engine. Several features are advisory, post-verdict, or only partially wired into the final RCA decision.

Standard verification:

- `go vet ./...` passed.
- `go test ./...` passed outside the sandbox.
- The first sandboxed `go test ./...` run failed only because the sandbox blocked Unix socket options and writes under `/root/.xtop`.

No code was changed for this review.

## Resolution Status — branch `fix/rca-attribution` (2026-07-12)

All findings below have been addressed on this branch (TDD, one commit each; full suite 928 green):

| # | Status | Commit / note |
|---|---|---|
| #1 Proxmox evidence after scoring | ✅ Fixed | pve.vm.* evidence now emitted before scoring |
| #2 Config drift mutates score after finalization | ✅ Fixed | `correlateConfigDrift` + change detection moved into `AnalyzeRCA` before verifier/finalize via `e.detectChanges`; narrative hint kept in `Tick`. **Residual (follow-up):** a boosted non-primary domain does not re-select `PrimaryBottleneck` — ordering is fixed, primary re-selection is out of scope. |
| #3 Journal Tier-1 post-verdict | ✅ Fixed | `injectJournalTier1` moved before the verifier loop (monotonic — can only strengthen a tier) |
| #4 Verifier additive, not authoritative | ✅ Addressed (additive + label) | `AnalysisResult.PrimaryVerified`; RCA box labels `(unverified)` when the verifier didn't confirm a degraded/critical verdict |
| #5 Fact/evidence ID mismatch | ✅ Fixed | duration stamping falls back to the `.avg10`-stripped base ID for PSI |
| #6 Lean-mode reduced coverage | ✅ Fixed | `AnalysisResult.Coverage {Mode, OmittedSignals}` surfaces the reduced signal set |
| #7 Duplicated OOM score-floor | ✅ Fixed | dead duplicate removed |

## Key Findings

### 1. Proxmox memory evidence is appended after scoring

Severity: High

In `engine/rca_memory.go`, memory scoring, evidence group counting, and checks conversion finish before Proxmox VM memory evidence is appended.

Relevant code:

- `engine/rca_memory.go:261` starts v2 scoring.
- `engine/rca_memory.go:284` sets `EvidenceGroups`.
- `engine/rca_memory.go:285` sets `Checks`.
- `engine/rca_memory.go:400` starts appending Proxmox VM memory evidence.

Impact:

Proxmox VM OOM, swap, memory-limit, and VM memory PSI evidence can appear in `EvidenceV2` but cannot affect `Score`, `EvidenceGroups`, `Checks`, health, or primary RCA for that tick.

This directly undermines production readiness for Proxmox hosts.

Recommended fix:

Move Proxmox VM memory evidence before scoring, then include it in `Facts` where appropriate. Add a regression test proving a VM OOM/memory-pressure scenario affects memory score and health.

### 2. Config drift mutates score after health finalization

Severity: High

`AnalyzeRCA` finalizes health inside `engine/rca.go`, then `Engine.Tick` later calls `correlateConfigDrift`.

Relevant code:

- `engine/rca.go:405` runs finalization.
- `engine/engine.go:614` calls `correlateConfigDrift`.
- `engine/configdrift_evidence.go:275` boosts `entry.Score`.
- `engine/configdrift_evidence.go:281` updates `PrimaryScore`.

Impact:

Config drift can change `PrimaryScore` after health, confidence, verifier output, causal DAG, actions, and much of the narrative have already been computed. This can produce score/verdict inconsistencies.

Recommended fix:

Feed config-drift evidence into the RCA pipeline before finalization, or rerun the finalization/verifier/narrative stages after score mutation. Prefer the first option so the pipeline remains single-pass and deterministic.

### 3. Journal Tier-1 RCA is post-verdict evidence

Severity: High

Journal findings are injected near the end of `AnalyzeRCA`, after verification and health decisions.

Relevant code:

- `engine/rca.go:374` computes `VerifiedCauses`.
- `engine/rca.go:405` finalizes health.
- `engine/rca.go:620` calls `injectJournalTier1`.
- `engine/journal_tier1.go:228` converts journal findings to facts.
- `engine/journal_tier1.go:231` appends journal facts to `result.Facts`.

Impact:

Journal RCA is useful UI/context evidence, but it does not strengthen the verified cause or change the core RCA verdict in the same tick.

Recommended fix:

Make journal Tier-1 evidence available before verification/finalization, or explicitly document and label it as post-verdict supporting context.

### 4. The formal verifier is additive, not authoritative

Severity: High

The engine computes `VerifiedCauses`, but health is still decided by raw score plus `v2TrustGate`.

Relevant code:

- `engine/rca.go:374` computes verifier output.
- `engine/finalize.go:90` decides health by score bands and `v2TrustGate`.

Impact:

The UI or fleet payload can report degraded/critical RCA even when the formal verifier abstains. That is not "fully verified RCA."

Recommended fix:

Decide product semantics:

- If the engine claims verified RCA, `VerifiedCauses` must gate the final claim.
- If the engine is heuristic RCA plus optional verification, the UI/API should label unverified results clearly.

### 5. Fact/evidence ID mismatches weaken temporal verification

Severity: Medium-High

Duration stamping joins facts to evidence strictly by ID.

Relevant code:

- `engine/fact_builders.go:124` builds the evidence-ID to sustained-duration map.
- `engine/fact_builders.go:133` stamps duration only when fact ID matches evidence ID.
- `engine/rca_cpu.go:82` emits evidence ID `cpu.psi`.
- `engine/rca_cpu.go:113` emits fact ID `cpu.psi.avg10`.
- `engine/rca_memory.go:130` emits evidence ID `mem.psi`.
- `engine/rca_memory.go:161` emits fact ID `mem.psi.avg10`.

Impact:

PSI facts often miss sustained-duration data. That weakens the temporal-ordering verifier gate on core pressure signals.

Recommended fix:

Unify evidence and fact IDs or maintain an explicit mapping table. Add tests that sustained PSI evidence stamps matching fact durations.

### 6. Fleet/lean mode intentionally has reduced RCA coverage

Severity: Medium

Lean mode omits several collectors.

Relevant code:

- `collector/collector.go:77` documents lean mode exclusions.
- `collector/collector.go:135` defines lean collectors.

Omitted in lean mode:

- logs
- sockets
- softirq
- sysctl
- security
- diag
- Proxmox
- GPU
- deleted-open
- fileless
- bigfile

Impact:

Fleet agents cannot claim full RCA coverage. They run with a reduced signal set by design.

Recommended fix:

Make this explicit in product/docs/API output. Consider a "coverage" or "signal availability" field so fleet users know which RCA classes were observable.

### 7. Memory scoring has duplicated OOM score-floor logic

Severity: Low-Medium

Relevant code:

- `engine/rca_memory.go:266` sets `r.Score = int(v2Score)`.
- `engine/rca_memory.go:268` applies OOM floor.
- `engine/rca_memory.go:271` resets `r.Score = int(v2Score)`.
- `engine/rca_memory.go:272` applies OOM floor again.

Impact:

Current behavior is mostly preserved because the OOM floor block is duplicated too, but the code is fragile and indicates patch-layer drift.

Recommended fix:

Remove the duplicate assignment/block and add a targeted OOM score-floor regression test.

## Coverage Assessment

Implemented reasonably well:

- CPU contention
- memory pressure
- IO starvation
- network overload
- PSI-based detection
- cgroup/process attribution
- OOM deltas
- disk latency/utilization
- TCP retrans/drop/conntrack issues
- some BPF sentinel signals
- app-specific hints for common databases/web stacks
- journal signature classification
- config-drift detection
- narratives/actions/history/runbooks

Not fully implemented:

- authoritative verified RCA
- all app failure modes
- all server roles
- full service/entity graph
- complete dependency causality
- full Kubernetes/container RCA
- full Proxmox production-grade RCA
- fleet dashboard journal propagation
- strong cloud/hypervisor-specific RCA
- service/business impact RCA
- root-cause proof for issues where host metrics look normal

## Production Readiness Assessment

For an operator-facing Linux troubleshooting TUI, this is useful and has meaningful diagnostics.

For an automated claim of "fully correct RCA for all production servers and all incident types," it is not ready.

The biggest architectural issue is pipeline ordering. Evidence should be collected and normalized before scoring, verification, finalization, causal DAG construction, actions, and narrative generation. Today, some important evidence arrives after those stages.

## Priority Fix Plan

1. Move all evidence emission before scoring/finalization.
2. Make config drift and journal Tier-1 evidence first-class verifier inputs or clearly mark them as post-verdict context.
3. Decide whether `VerifiedCauses` gates final RCA claims.
4. Fix fact/evidence ID mismatches.
5. Move Proxmox memory evidence before memory scoring.
6. Add RCA coverage metadata for lean/fleet mode.
7. Add golden scenario tests for Proxmox OOM, config drift near incident onset, journal crash loop, CPU PSI duration stamping, and lean-mode reduced-signal behavior.
