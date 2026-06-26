package engine

// journal_e2e_test.go — End-to-end validation of the Journal-Driven Service RCA
// pipeline (P2.7).  All tests use the injectable JournalQueryFn stub so no live
// journalctl is needed; they compile and run on any platform.
//
// Scenarios covered:
//   E2E1 – Crash-restart-loop: mysqld is the active CPU-suspect; realistic
//           crash-loop entries arrive via the stub; the final AnalysisResult
//           must contain a FactKindLogEvidence Fact with crash_restart_loop,
//           high confidence (≥ 0.85, per the HIGH tier rubric), the Fact
//           attached to both result.Facts and the top RCAEntry.Facts, and a
//           JournalFinding summary mentioning "crash_restart_loop".
//
//   E2E2 – OOM-killed: mysqld is the OOM culprit in a memory-pressure snapshot;
//           realistic OOM journal entries arrive; the result must contain a
//           FactKindLogEvidence Fact with oom_killed and crit severity.
//
//   E2E3 – Non-suspect isolation: a unit that is NOT in the RCA suspect list
//           (low score) must NEVER have its journal queried.  Closes the loop on
//           the scoping contract of injectJournalTier1.

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ftahirops/xtop/collector/journal"
	"github.com/ftahirops/xtop/model"
)

// ─── realistic journal entry builders ────────────────────────────────────────

// crashLoopEntries returns a slice of realistic systemd crash-restart-loop
// journal entries for the given unit, mimicking what journalctl -u mysql.service
// -p warning -o json would surface during a crash loop.
func crashLoopEntries(unit string) []journal.Entry {
	now := time.Now()
	return []journal.Entry{
		{
			Priority: 3, // ERR
			Message:  "start request repeated too quickly for " + unit,
			Unit:     unit,
			At:       now.Add(-4 * time.Minute),
		},
		{
			Priority: 3,
			Message:  unit + "[12345]: main process exited, code=exited, status=1/FAILURE",
			Unit:     unit,
			At:       now.Add(-3*time.Minute - 30*time.Second),
		},
		{
			Priority: 3,
			Message:  "Failed with result 'exit-code'.",
			Unit:     unit,
			At:       now.Add(-3 * time.Minute),
		},
		{
			Priority: 3,
			Message:  "scheduled restart job for " + unit,
			Unit:     unit,
			At:       now.Add(-2 * time.Minute),
		},
	}
}

// oomEntries returns a slice of realistic OOM-kill journal entries for the
// given unit, mimicking kernel oom-killer output.
func oomEntries(unit string, pid int) []journal.Entry {
	now := time.Now()
	return []journal.Entry{
		{
			Priority: 2, // CRIT
			Message:  "Out of memory: killed process " + unit,
			Unit:     unit,
			PID:      pid,
			At:       now.Add(-2 * time.Minute),
		},
		{
			Priority: 3,
			Message:  "oom-kill event: total-vm:4096000kB, anon-rss:3900000kB",
			Unit:     unit,
			PID:      pid,
			At:       now.Add(-90 * time.Second),
		},
	}
}

// ─── E2E helpers ─────────────────────────────────────────────────────────────

// makeScopedStub returns a JournalQueryFn that returns targetEntries when
// queried for targetUnit, nil for every other unit, and records all queried
// unit names. A mutex guards the called slice for race-safety.
func makeScopedStub(targetUnit string, targetEntries []journal.Entry) (JournalQueryFn, *[]string) {
	var mu sync.Mutex
	var called []string
	fn := func(_ context.Context, unit string, _ time.Time) ([]journal.Entry, error) {
		mu.Lock()
		called = append(called, unit)
		mu.Unlock()
		if unit == targetUnit {
			return targetEntries, nil
		}
		return nil, nil
	}
	return fn, &called
}

// ─── E2E Scenario 1: crash-restart-loop ──────────────────────────────────────

// TestJournalE2E_CrashRestartLoop drives the complete Tier-1 pipeline with a
// CPU-saturated snapshot where mysqld is the active RCA suspect (highest score).
// The stub injects realistic crash-loop entries for mysql.service.
//
// Assertions on the FINAL AnalysisResult:
//   (a) result.Facts contains a FactKindLogEvidence Fact
//   (b) That Fact has signature="crash_restart_loop" in its Tags
//   (c) Confidence ≥ 0.85 (HIGH tier — direct init-reported event)
//   (d) Severity = FactSeverityCrit
//   (e) The Fact also appears in the top RCAEntry.Facts
//   (f) result.JournalFindings contains a "logs" category entry mentioning
//       "crash_restart_loop"
func TestJournalE2E_CrashRestartLoop(t *testing.T) {
	const targetUnit = "mysql.service"
	entries := crashLoopEntries(targetUnit)
	fn, called := makeScopedStub(targetUnit, entries)

	e := makeEngineWithStub(fn)
	snap, rates := cpuSnapWithCgroup("/system.slice/mysql.service", "mysql")
	h := newTestHistory()
	feedHistory(h, snap, rates, 10)

	result := AnalyzeRCA(snap, rates, h, nil, e)

	// (a) At least one FactKindLogEvidence must be present.
	var logFacts []model.Fact
	for _, f := range result.Facts {
		if f.Kind == model.FactKindLogEvidence {
			logFacts = append(logFacts, f)
		}
	}
	if len(logFacts) == 0 {
		t.Fatalf("E2E1: expected ≥1 FactKindLogEvidence in result.Facts, got none; all facts=%+v", result.Facts)
	}

	// Find the crash_restart_loop fact specifically.
	var crashFact *model.Fact
	for i := range logFacts {
		if logFacts[i].Tags["signature"] == "crash_restart_loop" {
			crashFact = &logFacts[i]
			break
		}
	}
	if crashFact == nil {
		t.Fatalf("E2E1: no FactKindLogEvidence with signature=crash_restart_loop; facts=%+v", logFacts)
	}

	// (b) Tag[signature] = crash_restart_loop (already asserted above by find).

	// (c) Confidence ≥ 0.85 (HIGH tier).
	if crashFact.Confidence < 0.85 {
		t.Errorf("E2E1: Confidence=%.2f, want ≥ 0.85 (HIGH tier for crash_restart_loop)", crashFact.Confidence)
	}

	// (d) Severity = crit.
	if crashFact.Severity != model.FactSeverityCrit {
		t.Errorf("E2E1: Severity=%q, want %q", crashFact.Severity, model.FactSeverityCrit)
	}

	// (e) The fact must also appear in at least one RCAEntry.Facts.
	foundInRCA := false
	for _, entry := range result.RCA {
		for _, f := range entry.Facts {
			if f.Kind == model.FactKindLogEvidence && f.Tags["signature"] == "crash_restart_loop" {
				foundInRCA = true
				break
			}
		}
	}
	if !foundInRCA {
		t.Error("E2E1: crash_restart_loop fact not found in any RCAEntry.Facts")
	}

	// (f) JournalFindings must surface crash_restart_loop.
	if len(result.JournalFindings) == 0 {
		t.Fatal("E2E1: result.JournalFindings is empty")
	}
	foundFinding := false
	for _, jf := range result.JournalFindings {
		if jf.Category == "logs" && strings.Contains(jf.Summary, "crash_restart_loop") {
			foundFinding = true
			break
		}
	}
	if !foundFinding {
		t.Errorf("E2E1: no JournalFinding with category=logs mentioning crash_restart_loop; findings=%+v", result.JournalFindings)
	}

	// Confirm the stub was called for mysql.service.
	calledTarget := false
	for _, u := range *called {
		if u == targetUnit {
			calledTarget = true
			break
		}
	}
	if !calledTarget {
		t.Errorf("E2E1: stub was never called for %q; all calls=%v", targetUnit, *called)
	}
}

// ─── E2E Scenario 2: OOM-killed ──────────────────────────────────────────────

// TestJournalE2E_OOMKilled drives the Tier-1 pipeline with a memory-OOM
// snapshot where mysqld is the active RCA suspect (the top cgroup is
// mysql.service; OOM kills have fired).  The stub returns realistic OOM
// journal entries.
//
// Assertions on the FINAL AnalysisResult:
//   (a) result.Facts contains a FactKindLogEvidence Fact with oom_killed
//   (b) Confidence ≥ 0.85 (HIGH tier — kernel-reported OOM event)
//   (c) Severity = FactSeverityCrit
//   (d) result.JournalFindings mentions "oom_killed"
func TestJournalE2E_OOMKilled(t *testing.T) {
	const targetUnit = "mysql.service"
	const targetPID = 99001
	entries := oomEntries(targetUnit, targetPID)
	fn, _ := makeScopedStub(targetUnit, entries)

	e := makeEngineWithStub(fn)

	// Use a memory-OOM snapshot with mysql as the cgroup suspect.
	snap, rates := memOOMSnap()
	rates.CgroupRates = []model.CgroupRate{
		{Path: "/system.slice/mysql.service", Name: "mysql", CPUPct: 10, ThrottlePct: 0},
	}
	rates.ProcessRates[0] = model.ProcessRate{
		PID:    targetPID,
		Comm:   "mysql",
		CPUPct: 10.0,
		State:  "R",
		RSS:    6 * 1024 * 1024 * 1024, // 6 GiB — dominates memory
	}
	snap.Processes[0] = model.ProcessMetrics{
		PID:   targetPID,
		Comm:  "mysql",
		State: "R",
		RSS:   6 * 1024 * 1024 * 1024,
	}

	h := newTestHistory()
	feedHistory(h, snap, rates, 10)

	result := AnalyzeRCA(snap, rates, h, nil, e)

	// (a) oom_killed FactKindLogEvidence.
	var oomFact *model.Fact
	for i := range result.Facts {
		f := &result.Facts[i]
		if f.Kind == model.FactKindLogEvidence && f.Tags["signature"] == "oom_killed" {
			oomFact = f
			break
		}
	}
	if oomFact == nil {
		t.Fatalf("E2E2: no FactKindLogEvidence with signature=oom_killed in result.Facts; all=%+v", result.Facts)
	}

	// (b) Confidence HIGH.
	if oomFact.Confidence < 0.85 {
		t.Errorf("E2E2: Confidence=%.2f, want ≥ 0.85 (HIGH) for oom_killed", oomFact.Confidence)
	}

	// (c) Severity crit.
	if oomFact.Severity != model.FactSeverityCrit {
		t.Errorf("E2E2: Severity=%q, want %q", oomFact.Severity, model.FactSeverityCrit)
	}

	// (d) JournalFindings surface oom_killed.
	foundOOM := false
	for _, jf := range result.JournalFindings {
		if strings.Contains(jf.Summary, "oom_killed") {
			foundOOM = true
			break
		}
	}
	if !foundOOM {
		t.Errorf("E2E2: JournalFindings do not mention oom_killed; findings=%+v", result.JournalFindings)
	}

	// (e) The oom_killed fact must also appear in at least one RCAEntry.Facts
	//     (the consumer path that the UI/verifier gates read).
	foundInRCA := false
	for _, entry := range result.RCA {
		for _, f := range entry.Facts {
			if f.Kind == model.FactKindLogEvidence && f.Tags["signature"] == "oom_killed" {
				foundInRCA = true
			}
		}
	}
	if !foundInRCA {
		t.Error("E2E2: oom_killed fact not found in any RCAEntry.Facts")
	}
}

// ─── E2E Scenario 3: Non-suspect isolation ───────────────────────────────────

// TestJournalE2E_NonSuspectIsolation verifies the scoping contract end-to-end:
// the journal of a unit that did NOT make the suspect list (score < 1 or simply
// absent from the snapshot's RCA entries) is NEVER queried.
//
// Part A — absent units:
//   - Snapshot makes mysql.service the sole top-scoring suspect.
//   - Stub accepts calls for "unrelated-svc.service" and "redis.service".
//   - After AnalyzeRCA, those two units must have zero query calls.
//
// Part B — score filter:
//   - A crafted AnalysisResult has two entries: mysql.service (Score=80, above
//     minSuspectScore) and lowscore.service (Score=0, below minSuspectScore).
//   - After injectJournalTier1, lowscore.service must never be queried while
//     mysql.service IS queried — proving the score guard fires end-to-end.
func TestJournalE2E_NonSuspectIsolation(t *testing.T) {
	const targetUnit = "mysql.service"
	const bystander1 = "unrelated-svc.service"
	const bystander2 = "redis.service"
	const lowScoreUnit = "lowscore.service"

	entries := crashLoopEntries(targetUnit)

	// ── Part A: absent-unit isolation via full AnalyzeRCA ────────────────────
	var muA sync.Mutex
	var calledA []string
	fnA := func(_ context.Context, unit string, _ time.Time) ([]journal.Entry, error) {
		muA.Lock()
		calledA = append(calledA, unit)
		muA.Unlock()
		if unit == targetUnit {
			return entries, nil
		}
		return nil, nil
	}

	eA := makeEngineWithStub(fnA)
	snap, rates := cpuSnapWithCgroup("/system.slice/mysql.service", "mysql")
	h := newTestHistory()
	feedHistory(h, snap, rates, 10)

	AnalyzeRCA(snap, rates, h, nil, eA)

	muA.Lock()
	snapshotA := append([]string(nil), calledA...)
	muA.Unlock()

	for _, u := range snapshotA {
		if u == bystander1 {
			t.Errorf("E2E3 PartA: non-suspect unit %q was queried (leaked query scope)", bystander1)
		}
		if u == bystander2 {
			t.Errorf("E2E3 PartA: non-suspect unit %q was queried (leaked query scope)", bystander2)
		}
	}

	// Sanity: mysql WAS queried.
	calledMySQL := false
	for _, u := range snapshotA {
		if u == targetUnit {
			calledMySQL = true
			break
		}
	}
	if !calledMySQL {
		t.Errorf("E2E3 PartA: expected %q to be queried (it is the suspect), but got calls=%v", targetUnit, snapshotA)
	}

	// ── Part B: score-filter isolation via injectJournalTier1 ────────────────
	// Craft a result with one high-score entry (will be queried) and one
	// zero-score entry (must NOT be queried, proving the minSuspectScore guard).
	var muB sync.Mutex
	var calledB []string
	fnB := func(_ context.Context, unit string, _ time.Time) ([]journal.Entry, error) {
		muB.Lock()
		calledB = append(calledB, unit)
		muB.Unlock()
		if unit == targetUnit {
			return entries, nil
		}
		return nil, nil
	}

	eB := makeEngineWithStub(fnB)
	result := &model.AnalysisResult{
		RCA: []model.RCAEntry{
			{
				Bottleneck: "CPU Contention",
				Score:      80, // above minSuspectScore — must be queried
				TopCgroup:  "/system.slice/" + targetUnit,
			},
			{
				Bottleneck: "Disk I/O",
				Score:      0, // below minSuspectScore — must NOT be queried
				TopCgroup:  "/system.slice/" + lowScoreUnit,
			},
		},
	}

	injectJournalTier1(result, nil, eB)

	muB.Lock()
	snapshotB := append([]string(nil), calledB...)
	muB.Unlock()

	for _, u := range snapshotB {
		if u == lowScoreUnit {
			t.Errorf("E2E3 PartB: low-score unit %q was queried; score filter not working", lowScoreUnit)
		}
	}
	queriedHigh := false
	for _, u := range snapshotB {
		if u == targetUnit {
			queriedHigh = true
			break
		}
	}
	if !queriedHigh {
		t.Errorf("E2E3 PartB: high-score unit %q was never queried; expected ≥1 call", targetUnit)
	}
}
