# xtop RCA Engine — Correctness Audit

**Method:** the RCA engine is a pure function `model.Snapshot → AnalysisResult`. Every finding below was located in code, given a concrete triggering metric scenario, and **adversarially verified** (a second agent tried to refute it by tracing the real matcher/branch with the scenario numbers). 27 confirmed, 2 rejected as unreachable/pre-empted.

**Headline:** the bugs collapse into **7 structural classes**. The dominant one — *a specific-cause narrative firing without its defining evidence* — appears **~9 times** across CPU, memory, IO, network, and VM. Fixing the class fixes them all. That is why prior one-off patches never made it stick.

Matcher semantics (verified, for reference): `MatchPattern` iterates patterns by **descending Priority**; first match wins and its narrative overrides templates. A pattern matches iff no `Required:true` evidence is missing **and** `count(fired conditions) ≥ MinMatch`. "Fired" = `normalize(value,warn,crit) > 0`.

---

## Class 1 — Specific narrative fires without its defining evidence  *(systemic, ~9 instances)*

The pattern names a specific cause but `MinMatch` is low enough (or the defining condition isn't `Required`) that a **generic, high-base-rate** signal (PSI, latency, busy) alone satisfies it. Result: confident, specific, **wrong** WHY.

| Sev | File:line | Bug |
|---|---|---|
| **CRIT** | `engine/patterns.go:55` | `Memory-Induced IO Storm` (P90) defining ID **`mem.swap.activity` is never emitted anywhere**. With MinMatch:1 it fires "swap thrashing" on *pure disk IO*, and at P90 it **hijacks essentially every IO-latency incident**. (Found independently by 3 lanes.) |
| **CRIT** | `engine/patterns.go:59` | Same phantom `mem.swap.activity` — "memory pressure spilling to swap → IO" narrative with no swap signal. |
| **HIGH** | `engine/patterns.go` `VM Noisy Neighbor` | **SEED-A** — MinMatch:1 over {`cpu.steal`(≥0.1), `cpu.psi`} → `cpu.psi` alone prints "hypervisor stealing CPU time" at 1.1% steal. |
| **HIGH** | `engine/patterns.go:343` | `VM CPU Throttle` MinMatch:1 → `pve.vm.cpupsi` alone claims "hitting cgroup CPU limit" with `throttle=0`. (2 lanes.) |
| **HIGH** | `engine/patterns.go:187` | `Network Congestion` (P60) asserts "retransmits" without requiring `net.tcp.retrans`; masks the correct conntrack narrative. |
| **HIGH** | `engine/narrative.go:26` | Template "…cascading to IO via swap" (P90) fires from `mem.psi`+`io.disk.latency` with **no swap evidence**. |
| **MED** | `engine/patterns.go:354` | `pve.vm.memlimit` narrative without the limit signal firing. |
| **MED** | `engine/patterns.go:108` | `Disk IO Saturation` claims "processes in D-state" without `io.dstate` firing. |
| **LOW** | `engine/patterns.go:105` | Same D-state clause, second site. |

**Structural fix:** mark each pattern's *defining* evidence `Required:true` (the technique already used correctly by `CPU Throttle Cascade`), and **either emit `mem.swap.activity` or delete the patterns that depend on it.** One matcher-discipline pass + one evidence fix removes the whole class.

---

## Class 2 — Bonus/score applied without the gating signal firing

| Sev | File:line | Bug |
|---|---|---|
| **HIGH** | `engine/rca_cpu.go:232` | Steal bonus (+10) gated only on generic `v2TrustGate` and applied **before** ScoreFloor → 6% steal can resurrect/flip the CPU domain even when steal evidence didn't fire. |
| **HIGH** | `engine/rca_memory.go:114` | Reclaim PSI-dampening lowers **confidence**, but the matcher keys off **strength** → `Direct Reclaim Storm` still fires with PSI=0. |
| **MED** | `engine/rca_network.go:511` | drops/softirq bonus added without either underlying signal firing. |
| **LOW** | `ui/app.go:2219` | `pinnedResolvedSec` computed but never read. |

**Structural fix:** gate every bonus on the *specific* evidence's strength, and apply bonuses relative to the score floor, not before it.

---

## Class 3 — Normalize/unit bugs (evidence always-fires or is dead)

| Sev | File:line | Bug |
|---|---|---|
| **HIGH** | `engine/rca_io.go:112` | `io.writeback` warn/crit thresholds (5/20) are in the wrong unit vs the byte-valued metric → **strength pinned at 1.0 on every host**. Permanent false "writeback pressure". |
| **HIGH** | `engine/rca_io.go:141` | fs-full dampener compares **FREE%** against `95` when it means **USED%** → dampener is dead code; any static 85–95%-full mount hijacks the narrative at 0.9 confidence. |

**Structural fix:** add a unit assertion/test per evidence: feed a known-quiet snapshot, assert strength 0; feed a known-critical one, assert 1.0.

---

## Class 4 — WHO contradicts WHY (blame ≠ narrative)

The most user-visible tell (WHO=`sentinel` while WHY=hypervisor on your screen).

| Sev | File:line | Bug |
|---|---|---|
| **HIGH** | `engine/rca_io.go:257` | IO culprit uses bare `SwapInRate>0 \|\| DirectReclaimRate>0` → blames an idle top-RSS process over the real writer. |
| **HIGH** | `engine/blame.go:163` | `blameMemory` has no slab-aware branch → a **kernel slab leak** is blamed on an innocent userspace top-RSS process. |
| **HIGH** | `ui/app.go:2057` | Sticky pin re-pins only on strictly-higher score → a *different* current cause is masked by the pinned one. |
| **MED** | `engine/blame.go:150` | CPU steal→hypervisor blame uses a different entry threshold than the narrative, so they diverge in a band. |
| **MED** | `ui/overview_header.go:48` | Header shows pinned health while the body is live. |

**Structural fix:** a single post-classification invariant — *if WHY names an external/kernel/hypervisor cause, WHO must not be a local userspace PID (and vice-versa)* — enforced in one place, with a test.

---

## Class 5 — Confidence decoupled from evidence *(explains the on-screen 93%)*

| Sev | File:line | Bug |
|---|---|---|
| **HIGH** | `engine/scoring.go:100` | `domainConfidence` ignores signal **strength** and the **selected narrative** → a weak, misattributed cause is still displayed at 93%+. This is why the wrong narrative looked authoritative. |

**Structural fix:** confidence must be a function of the fired evidence strength backing the *chosen* narrative, not the domain score alone.

---

## Class 6 — Live data rendered next to pinned/stale RCA  *(SEED Bug B family)*

| Sev | File:line | Bug |
|---|---|---|
| **MED** | `ui/overview_blocks.go:1832` | Pinned owners shown against live IO. |
| **MED** | `ui/overview_blocks.go:713` | Pinned capacities vs live subsystem capacity (the 30.9%-vs-93% split). |
| **LOW** | `engine/adaptive_threshold.go:155` | Adaptive thresholds with no observations silently pinned to base (looks tuned, isn't). |

**Structural fix:** render a snapshot atomically — either freeze the whole panel set with the pinned result, or clearly label pinned sections "(held Xs)". Never mix in one frame.

---

## Class 7 — Priority ordering / wrong source

| Sev | File:line | Bug |
|---|---|---|
| **HIGH** | `engine/patterns.go:91` | `CPU Oversubscription` (P78) has no steal-exclusion, so it can pre-empt genuine steal/noisy-neighbor patterns (P65/58) in the reverse scenario. |
| **HIGH** | `engine/rca_cpu.go` | **SEED-B** — run-queue derived from `Load1/nCPUs` not instantaneous `procs_running` → real saturation never fires, disqualifying the correct pattern. |
| **MED** | `engine/patterns.go:208` | conntrack-exhaustion pattern reads the wrong drop source. |

---

## Rejected by adversarial verification (2)

Two candidate findings were traced and found **unreachable/pre-empted** — not reported as bugs. (Kept out deliberately; the point of the verify pass is to not cry wolf.)

---

## Systemic recommendations (fix classes, not screenshots)

1. **Matcher discipline pass** — every specific-cause pattern marks its defining evidence `Required:true`; audit every `MinMatch`. Kills Class 1 (~9 bugs).
2. **Emit-or-remove `mem.swap.activity`** — the single phantom evidence ID behind both CRITICALs.
3. **Evidence unit tests** — quiet-snapshot→strength 0, critical-snapshot→1.0, for every evidence ID. Kills Class 3, prevents regressions.
4. **WHO/WHY invariant** — one post-classification consistency check. Kills Class 4.
5. **Confidence from chosen-narrative strength.** Kills Class 5.
6. **Atomic frame rendering** (live vs pinned never mixed). Kills Class 6.
7. **Golden-scenario test suite** — table of real `Snapshot`s (incl. your xgen1 capture) → asserted RCA. This is the regression net that makes it stay fixed across servers.
</content>
