package engine

// configdrift_e2e_test.go — P4.6: end-to-end validation of Config-Drift RCA.
//
// Drives the ENTIRE config-drift pipeline end-to-end using a STUBBED config
// snapshot (no real /proc reads or writes). Asserts that the following chain
// works correctly:
//
//	Seeded baseline + stub snapshot → Detect → SystemChange → correlate → Fact + boost + narrative hint
//
// Three scenarios:
//  1. Positive (matching domain + recent timing): memory drift boosts memory anomaly,
//     FactKindConfigChange Fact attached, Narrative SUGGESTED hint appended.
//  2. Negative (domain mismatch): network drift does NOT boost memory anomaly.
//  3. Flag-off: configDriftEnabled=false → snapshot fn never called, no Fact.

import (
	"strings"
	"testing"
	"time"

	"github.com/ftahirops/xtop/model"
)

// buildE2EMemoryAnomalyResult constructs a minimal AnalysisResult that looks
// like an active memory-pressure anomaly. It includes a Narrative so that
// correlateConfigDrift can append the SUGGESTED evidence line.
func buildE2EMemoryAnomalyResult(score int) *model.AnalysisResult {
	return &model.AnalysisResult{
		PrimaryBottleneck: BottleneckMemory,
		PrimaryScore:      score,
		AnomalyStartedAgo: 60,
		RCA: []model.RCAEntry{
			{
				Bottleneck: BottleneckMemory,
				Score:      score,
			},
		},
		Narrative: &model.Narrative{
			RootCause:  "Memory Pressure — high swappiness degrading performance",
			Evidence:   []string{},
			Confidence: 72,
		},
	}
}

// TestConfigDriftE2E_FullPipeline drives the entire config-drift pipeline
// end-to-end using a stubbed snapshot. No real /proc reads or writes occur.
//
// Scenario: baseline vm.swappiness="10", stub returns "60" (drifted),
// memory-pressure anomaly is active. The pipeline must:
//
//	(a) emit a FactKindConfigChange Fact with Source="config", Domain=memory,
//	    Tags key=vm.swappiness old=10 new=60
//	(b) boost the memory RCA candidate's score
//	(c) append a "SUGGESTED: consider restoring ... sysctl -w ..." hint to Narrative.Evidence
//	(d) not write anything (structural guarantee: the pipeline is DETECT+EXPLAIN only;
//	    confirmed by TestSuggestedRemediationNoWrite in configdrift_wire_test.go)
func TestConfigDriftE2E_FullPipeline(t *testing.T) {
	t.Parallel()
	now := time.Now()

	// -----------------------------------------------------------------------
	// Step 1: seed the in-memory detector with a known baseline.
	// -----------------------------------------------------------------------
	detector := NewParamDriftDetector([]ConfigBaselineRecord{
		{
			Key:       "vm.swappiness",
			Value:     "10",
			Domain:    "memory",
			FirstSeen: now.Add(-1 * time.Hour),
			Acked:     false,
		},
	})

	// -----------------------------------------------------------------------
	// Step 2: stub configSnapshotFn returns a drifted value.
	// The drift timestamp (now) is within driftCorrelationWindow (5 min).
	// -----------------------------------------------------------------------
	snapshotCalled := 0
	stubSnapshotFn := func() (map[string]string, error) {
		snapshotCalled++
		return map[string]string{"vm.swappiness": "60"}, nil
	}

	live, err := stubSnapshotFn()
	if err != nil {
		t.Fatalf("stub snapshot error: %v", err)
	}
	if snapshotCalled != 1 {
		t.Fatalf("expected stub called once during setup, got %d", snapshotCalled)
	}

	// -----------------------------------------------------------------------
	// Step 3: Detect — produces config_drift_memory SystemChange.
	// -----------------------------------------------------------------------
	changes, newBaselines := detector.Detect(live, now)

	if len(changes) != 1 {
		t.Fatalf("expected 1 drift change from Detect, got %d: %+v", len(changes), changes)
	}
	if changes[0].Type != "config_drift_memory" {
		t.Errorf("change Type = %q, want \"config_drift_memory\"", changes[0].Type)
	}
	if !strings.Contains(changes[0].Detail, "vm.swappiness") {
		t.Errorf("change Detail should contain key name, got %q", changes[0].Detail)
	}
	if !strings.Contains(changes[0].Detail, "10") || !strings.Contains(changes[0].Detail, "60") {
		t.Errorf("change Detail should contain old→new values, got %q", changes[0].Detail)
	}
	if len(newBaselines) != 0 {
		t.Errorf("drift on existing baseline must not produce newBaselines, got %d", len(newBaselines))
	}

	// -----------------------------------------------------------------------
	// Step 4: craft an active memory-pressure AnalysisResult and append
	// the drift changes (exactly as the engine Tick does at line 602-603).
	// -----------------------------------------------------------------------
	origScore := 55
	result := buildE2EMemoryAnomalyResult(origScore)
	result.Changes = append(result.Changes, changes...)

	// -----------------------------------------------------------------------
	// Step 5: correlateConfigDrift — the same call the engine Tick makes
	// at engine.go ~line 615.
	// -----------------------------------------------------------------------
	correlateConfigDrift(result, result.Changes, now)

	// -----------------------------------------------------------------------
	// Assertion (a): FactKindConfigChange Fact with correct Source + tags.
	// -----------------------------------------------------------------------
	var driftFact *model.Fact
	for i := range result.Facts {
		f := &result.Facts[i]
		if f.Kind == model.FactKindConfigChange && f.Source == "config" {
			driftFact = f
			break
		}
	}
	if driftFact == nil {
		t.Fatalf("expected FactKindConfigChange with Source=\"config\" in result.Facts; got facts: %+v", result.Facts)
	}
	if driftFact.Tags["key"] != "vm.swappiness" {
		t.Errorf("Tags[key] = %q, want \"vm.swappiness\"", driftFact.Tags["key"])
	}
	if driftFact.Tags["old"] != "10" {
		t.Errorf("Tags[old] = %q, want \"10\"", driftFact.Tags["old"])
	}
	if driftFact.Tags["new"] != "60" {
		t.Errorf("Tags[new] = %q, want \"60\"", driftFact.Tags["new"])
	}
	if driftFact.Domain != model.DomainMemory {
		t.Errorf("Fact.Domain = %q, want %q", driftFact.Domain, model.DomainMemory)
	}
	if driftFact.EntityID != "host" {
		t.Errorf("Fact.EntityID = %q, want \"host\"", driftFact.EntityID)
	}

	// -----------------------------------------------------------------------
	// Assertion (b): memory RCA candidate score was boosted.
	// -----------------------------------------------------------------------
	if result.RCA[0].Score <= origScore {
		t.Errorf("memory RCA score not boosted: got %d, original %d", result.RCA[0].Score, origScore)
	}
	if result.PrimaryScore != result.RCA[0].Score {
		t.Errorf("PrimaryScore %d out of sync with boosted RCA entry %d",
			result.PrimaryScore, result.RCA[0].Score)
	}

	// -----------------------------------------------------------------------
	// Assertion (c): Narrative.Evidence contains SUGGESTED remediation hint
	//   naming the key, the old value (10), the new value (60), and "sysctl".
	//   The hint must convey the drift: old → new.
	// -----------------------------------------------------------------------
	if result.Narrative == nil {
		t.Fatal("Narrative is nil after correlateConfigDrift — SUGGESTED hint not appended")
	}
	foundSuggestion := false
	for _, ev := range result.Narrative.Evidence {
		if strings.HasPrefix(ev, "SUGGESTED:") &&
			strings.Contains(ev, "vm.swappiness") &&
			strings.Contains(ev, "10") && // old value
			strings.Contains(ev, "60") && // new value — drift conveyance
			strings.Contains(ev, "sysctl") {
			foundSuggestion = true
			break
		}
	}
	if !foundSuggestion {
		t.Errorf("expected SUGGESTED remediation with old→new drift in Narrative.Evidence; got: %v", result.Narrative.Evidence)
	}

	// -----------------------------------------------------------------------
	// Assertion (d): DETECT+EXPLAIN only — no writes.
	// The pipeline never writes to /proc/sys or /sys by construction (enforced
	// by TestSuggestedRemediationNoWrite in configdrift_wire_test.go which
	// statically scans all configdrift*.go files for forbidden write calls).
	// No additional runtime assertion needed here.
	// -----------------------------------------------------------------------
}

// TestConfigDriftE2E_NegativeDomainMismatch verifies that a network-key drift
// during a memory-pressure anomaly does NOT boost the memory candidate.
// The domain gate (rd.dom != entryDomain) must reject the correlation.
func TestConfigDriftE2E_NegativeDomainMismatch(t *testing.T) {
	t.Parallel()
	now := time.Now()

	// Seed baseline for a NETWORK key.
	detector := NewParamDriftDetector([]ConfigBaselineRecord{
		{
			Key:       "net.core.somaxconn",
			Value:     "128",
			Domain:    "network",
			FirstSeen: now.Add(-1 * time.Hour),
		},
	})

	// Stub returns a drifted network value.
	live := map[string]string{"net.core.somaxconn": "4096"}
	changes, _ := detector.Detect(live, now)

	if len(changes) != 1 || changes[0].Domain != "network" {
		t.Fatalf("expected 1 network drift change, got: %+v", changes)
	}

	// Active anomaly is MEMORY domain.
	origScore := 55
	result := buildE2EMemoryAnomalyResult(origScore)
	result.Changes = append(result.Changes, changes...)

	correlateConfigDrift(result, result.Changes, now)

	// Memory score must NOT be boosted: network drift ≠ memory domain.
	if result.RCA[0].Score != origScore {
		t.Errorf("memory score should NOT change for network drift: got %d, want %d",
			result.RCA[0].Score, origScore)
	}
	if result.PrimaryScore != origScore {
		t.Errorf("PrimaryScore should NOT change for domain mismatch: got %d, want %d",
			result.PrimaryScore, origScore)
	}

	// No FactKindConfigChange must appear in result.Facts.
	for _, f := range result.Facts {
		if f.Kind == model.FactKindConfigChange {
			t.Errorf("unexpected FactKindConfigChange fact for domain-mismatched drift: %+v", f)
		}
	}

	// SUGGESTED hint must NOT appear in Narrative.Evidence.
	if result.Narrative != nil {
		for _, ev := range result.Narrative.Evidence {
			if strings.HasPrefix(ev, "SUGGESTED:") {
				t.Errorf("SUGGESTED hint must not appear for domain-mismatched drift: %q", ev)
			}
		}
	}
}

// TestConfigDriftE2E_FlagOff verifies that when configDriftEnabled=false the
// snapshot function is never called and no config_drift Fact appears in the
// result. Drives the engine Tick path (same as TestConfigDriftWire_FlagOff but
// additionally asserts result.Facts contains no FactKindConfigChange).
func TestConfigDriftE2E_FlagOff(t *testing.T) {
	t.Parallel()

	eng := NewEngine(10, 1)
	defer eng.Close()

	eng.paramDriftDetector = NewParamDriftDetector([]ConfigBaselineRecord{
		{Key: "vm.swappiness", Value: "10", Domain: "memory", FirstSeen: time.Now()},
	})
	snapshotCalled := 0
	eng.configSnapshotFn = func() (map[string]string, error) {
		snapshotCalled++
		return map[string]string{"vm.swappiness": "60"}, nil
	}
	eng.configDriftEnabled = false // FLAG OFF

	// Force tick count to trigger the 30-tick check window.
	eng.tickCount = 29
	eng.Tick()
	eng.tickCount = 29
	_, _, result := eng.Tick()

	// Snapshot fn must never be called when flag is off.
	if snapshotCalled != 0 {
		t.Errorf("configSnapshotFn must NOT be called when configDriftEnabled=false; called %d times", snapshotCalled)
	}

	// No config_drift_* Changes or FactKindConfigChange Facts may appear.
	if result != nil {
		for _, ch := range result.Changes {
			if strings.HasPrefix(ch.Type, "config_drift_") {
				t.Errorf("unexpected config_drift_* Change when flag=off: %+v", ch)
			}
		}
		for _, f := range result.Facts {
			if f.Kind == model.FactKindConfigChange {
				t.Errorf("unexpected FactKindConfigChange Fact when flag=off: %+v", f)
			}
		}
	}
}

// TestConfigDriftE2E_ThroughTickEnabled verifies that the Tick() pipeline
// properly drives config-drift detection through the full path when
// configDriftEnabled=true. This exercises the wiring:
// Tick → (every 30 ticks) configSnapshotFn → Detect → correlateConfigDrift.
//
// Complement to TestConfigDriftE2E_FlagOff which verifies the flag-off path
// through Tick. This ensures the positive (flag-on) Tick path is covered.
func TestConfigDriftE2E_ThroughTickEnabled(t *testing.T) {
	t.Parallel()

	eng := NewEngine(10, 1)
	defer eng.Close()

	eng.paramDriftDetector = NewParamDriftDetector([]ConfigBaselineRecord{
		{Key: "vm.swappiness", Value: "10", Domain: "memory", FirstSeen: time.Now()},
	})

	snapshotCalled := 0
	eng.configSnapshotFn = func() (map[string]string, error) {
		snapshotCalled++
		return map[string]string{"vm.swappiness": "60"}, nil
	}
	eng.configDriftEnabled = true // FLAG ON

	// Force tick count to trigger the 30-tick check window.
	eng.tickCount = 29
	eng.Tick()
	eng.tickCount = 29
	_, _, result := eng.Tick()

	// Snapshot fn must be called at least once when flag is on.
	if snapshotCalled < 1 {
		t.Errorf("configSnapshotFn must be called when configDriftEnabled=true; called %d times", snapshotCalled)
	}

	// Config-drift SystemChange and FactKindConfigChange must appear when flag is on.
	if result != nil {
		var foundConfigDriftChange bool
		var foundConfigDriftFact bool

		for _, ch := range result.Changes {
			if strings.HasPrefix(ch.Type, "config_drift_") {
				foundConfigDriftChange = true
				if !strings.Contains(ch.Detail, "vm.swappiness") ||
					!strings.Contains(ch.Detail, "10") ||
					!strings.Contains(ch.Detail, "60") {
					t.Errorf("config_drift change Detail should contain key and old→new values, got %q", ch.Detail)
				}
				break
			}
		}
		if !foundConfigDriftChange {
			t.Errorf("expected config_drift_* Change when flag=on; got changes: %+v", result.Changes)
		}

		for _, f := range result.Facts {
			if f.Kind == model.FactKindConfigChange && f.Source == "config" {
				foundConfigDriftFact = true
				if f.Tags["key"] != "vm.swappiness" ||
					f.Tags["old"] != "10" ||
					f.Tags["new"] != "60" {
					t.Errorf("config_drift Fact tags incorrect: %+v", f.Tags)
				}
				break
			}
		}
		if !foundConfigDriftFact {
			t.Errorf("expected FactKindConfigChange Fact with Source=\"config\" when flag=on; got facts: %+v", result.Facts)
		}
	}
}
