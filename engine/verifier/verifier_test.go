package verifier

import (
	"testing"
	"time"

	"github.com/ftahirops/xtop/model"
)

// makeFact creates a Fact with sensible defaults for tests.
func makeFact(id string, entityID string, conf float64) model.Fact {
	return model.Fact{
		ID:         id,
		Kind:       model.FactKindSaturation,
		Source:     "procfs",
		EntityID:   entityID,
		Domain:     model.DomainCPU,
		Metric:     id,
		Value:      50,
		MeasuredAt: time.Date(2026, 5, 12, 0, 0, 0, 0, time.UTC),
		Severity:   model.FactSeverityWarn,
		Confidence: model.FactConfidence(conf),
	}
}

// ─── signalQualityGate ────────────────────────────────────────────────

func TestSignalQuality_TooFewFacts(t *testing.T) {
	c := Candidate{SupportingFactIDs: []string{"cpu.psi.avg10"}}
	r := signalQualityGate{}.Evaluate(c, []model.Fact{makeFact("cpu.psi.avg10", "host", 0.9)}, nil)
	if r.Passed {
		t.Errorf("expected fail on 1 supporting fact; got pass")
	}
}

func TestSignalQuality_LowConfidence(t *testing.T) {
	c := Candidate{SupportingFactIDs: []string{"a", "b"}}
	facts := []model.Fact{
		makeFact("a", "host", 0.5),
		makeFact("b", "host", 0.6),
	}
	r := signalQualityGate{}.Evaluate(c, facts, nil)
	if r.Passed {
		t.Errorf("expected fail on avg conf 0.55; got pass")
	}
}

func TestSignalQuality_NoKernelDirect(t *testing.T) {
	c := Candidate{SupportingFactIDs: []string{"a", "b", "c"}}
	facts := []model.Fact{
		makeFact("a", "host", 0.75),
		makeFact("b", "host", 0.75),
		makeFact("c", "host", 0.80),
	}
	r := signalQualityGate{}.Evaluate(c, facts, nil)
	if r.Passed {
		t.Errorf("expected fail on no fact ≥ 0.85; got pass: %s", r.Reason)
	}
}

func TestSignalQuality_Passes(t *testing.T) {
	c := Candidate{SupportingFactIDs: []string{"a", "b"}}
	facts := []model.Fact{
		makeFact("a", "host", 0.9), // kernel-direct
		makeFact("b", "host", 0.7),
	}
	r := signalQualityGate{}.Evaluate(c, facts, nil)
	if !r.Passed {
		t.Errorf("expected pass; got fail: %s", r.Reason)
	}
}

// ─── ownershipConsistencyGate ─────────────────────────────────────────

func makeGraph() *model.EntityGraph {
	g := model.NewEntityGraph()
	g.Add(model.Entity{ID: "host", Kind: model.EntityKindHost})
	g.Add(model.Entity{ID: "cgroup:/system.slice", Kind: model.EntityKindCgroup, OwnerID: "host"})
	g.Add(model.Entity{ID: "cgroup:/system.slice/mongod.service",
		Kind: model.EntityKindCgroup, OwnerID: "cgroup:/system.slice"})
	g.Add(model.Entity{ID: "pid:1234", Kind: model.EntityKindProcess,
		OwnerID: "cgroup:/system.slice/mongod.service"})
	return g
}

func TestOwnership_NilGraph(t *testing.T) {
	c := Candidate{RootEntityID: "pid:1"}
	r := ownershipConsistencyGate{}.Evaluate(c, nil, nil)
	if r.Passed {
		t.Errorf("expected fail on nil graph; got pass")
	}
}

func TestOwnership_RootMissing(t *testing.T) {
	c := Candidate{RootEntityID: "pid:99999", Domain: model.DomainCPU}
	r := ownershipConsistencyGate{}.Evaluate(c, nil, makeGraph())
	if r.Passed {
		t.Errorf("expected fail on missing root; got pass: %s", r.Reason)
	}
}

func TestOwnership_HostScopeConsistent(t *testing.T) {
	// Empty RootEntityID + host-scope facts → pass.
	c := Candidate{SupportingFactIDs: []string{"f1", "f2"}}
	facts := []model.Fact{
		makeFact("f1", "host", 0.9),
		makeFact("f2", "host", 0.7),
	}
	r := ownershipConsistencyGate{}.Evaluate(c, facts, makeGraph())
	if !r.Passed {
		t.Errorf("expected pass for host-scope; got fail: %s", r.Reason)
	}
}

func TestOwnership_HostScopeInconsistent(t *testing.T) {
	// Empty RootEntityID but a fact pointing to a specific cgroup → fail.
	c := Candidate{SupportingFactIDs: []string{"f1"}}
	facts := []model.Fact{
		makeFact("f1", "cgroup:/system.slice/mongod.service", 0.9),
	}
	r := ownershipConsistencyGate{}.Evaluate(c, facts, makeGraph())
	if r.Passed {
		t.Errorf("expected fail on inconsistent host-scope; got pass")
	}
}

func TestOwnership_OwnedFactPasses(t *testing.T) {
	// RootEntityID = mongod cgroup; fact points to a child pid in
	// that cgroup → must walk up the chain and pass.
	c := Candidate{
		RootEntityID:      "cgroup:/system.slice/mongod.service",
		Domain:            model.DomainCPU,
		SupportingFactIDs: []string{"f1"},
	}
	facts := []model.Fact{
		makeFact("f1", "pid:1234", 0.9),
	}
	r := ownershipConsistencyGate{}.Evaluate(c, facts, makeGraph())
	if !r.Passed {
		t.Errorf("expected pass when fact is in ownership chain; got fail: %s", r.Reason)
	}
}

func TestOwnership_UnrelatedFactFails(t *testing.T) {
	c := Candidate{
		RootEntityID:      "cgroup:/system.slice/mongod.service",
		Domain:            model.DomainCPU,
		SupportingFactIDs: []string{"f1"},
	}
	g := makeGraph()
	g.Add(model.Entity{ID: "cgroup:/user.slice", Kind: model.EntityKindCgroup, OwnerID: "host"})
	facts := []model.Fact{
		makeFact("f1", "cgroup:/user.slice", 0.9),
	}
	r := ownershipConsistencyGate{}.Evaluate(c, facts, g)
	if r.Passed {
		t.Errorf("expected fail on unrelated fact; got pass: %s", r.Reason)
	}
}

func TestOwnership_WrongKindForDomain(t *testing.T) {
	g := model.NewEntityGraph()
	g.Add(model.Entity{ID: "host", Kind: model.EntityKindHost})
	g.Add(model.Entity{ID: "mount:/var", Kind: model.EntityKindMount, OwnerID: "host"})

	c := Candidate{RootEntityID: "mount:/var", Domain: model.DomainCPU}
	r := ownershipConsistencyGate{}.Evaluate(c, nil, g)
	if r.Passed {
		t.Errorf("expected fail — mount can't own CPU; got pass")
	}
	// But mount CAN own IO.
	c.Domain = model.DomainIO
	r = ownershipConsistencyGate{}.Evaluate(c, nil, g)
	if !r.Passed {
		t.Errorf("expected pass — mount owns IO; got fail: %s", r.Reason)
	}
}

// ─── Verifier orchestrator ────────────────────────────────────────────

func TestVerifier_AbstainsWithoutGates(t *testing.T) {
	v := New() // no gates
	out := v.Verify(Candidate{Mechanism: "x"}, nil, nil)
	if out.Tier != model.TierDInconclusive {
		t.Errorf("empty verifier should abstain (D), got %s", out.Tier)
	}
}

// TestVerifier_DefaultGateCount asserts the Default verifier ships
// the expected number of gates. Bumps when new gates land — keeps the
// other tier-classification tests honest about how many gates ran.
func TestVerifier_DefaultGateCount(t *testing.T) {
	v := Default()
	out := v.Verify(Candidate{
		Mechanism:         "smoke",
		SupportingFactIDs: []string{"x"},
	}, []model.Fact{makeFact("x", "host", 0.9)}, makeGraph())
	if len(out.Gates) != 5 {
		t.Errorf("Default() should have 5 gates today; got %d. Update this test when gates are added.", len(out.Gates))
	}
}

// TestVerifier_AllGatesPass_TierA asserts a candidate that genuinely
// passes ALL 5 gates reaches TierA. Requires non-zero Fact.Duration +
// non-zero BaselineDelta + ownership consistent + signal quality +
// counter-evidence rules satisfied (cpu.busy ≥ 20 for CPU candidates).
func TestVerifier_AllGatesPass_TierA(t *testing.T) {
	now := time.Date(2026, 5, 12, 0, 0, 0, 0, time.UTC)
	mkF := func(id, ent string, conf, val float64, dur time.Duration, baselineDelta float64) model.Fact {
		return model.Fact{
			ID: id, Source: "procfs", EntityID: ent, Domain: model.DomainCPU,
			Metric: id, Value: val, Confidence: model.FactConfidence(conf),
			Severity: model.FactSeverityWarn, MeasuredAt: now,
			Duration: dur, BaselineDelta: baselineDelta,
			Kind: model.FactKindSaturation,
		}
	}
	v := Default()
	c := Candidate{
		Mechanism:         "CPU contention on mongod cgroup",
		RootEntityID:      "cgroup:/system.slice/mongod.service",
		Domain:            model.DomainCPU,
		SupportingFactIDs: []string{"cpu.psi.avg10", "cpu.busy"},
	}
	facts := []model.Fact{
		// PSI: sustained, baselined-above
		mkF("cpu.psi.avg10", "pid:1234", 0.9, 65, 12*time.Second, 50),
		// cpu.busy: required by counter-evidence rule (≥ 20%)
		mkF("cpu.busy", "cgroup:/system.slice/mongod.service", 0.85, 85, 10*time.Second, 40),
	}
	out := v.Verify(c, facts, makeGraph())
	if out.Tier != model.TierAConfirmed {
		t.Errorf("expected TierAConfirmed with all 5 gates passing; got %s. gates=%+v",
			out.Tier, out.Gates)
	}
}

// TestVerifier_OneNonCriticalFailure_TierC asserts a candidate that
// passes signal-quality but fails exactly one OTHER gate reaches
// Tier C. With 5 gates, that means 4 pass + 1 fails (non-signal-quality).
func TestVerifier_OneNonCriticalFailure_TierC(t *testing.T) {
	now := time.Date(2026, 5, 12, 0, 0, 0, 0, time.UTC)
	v := Default()
	// Setup: candidate passes signal + ownership + temporal +
	// counter-evidence (cpu.busy supplied), but fails baseline
	// (no BaselineDelta data on any supporting fact).
	c := Candidate{
		Mechanism:         "CPU contention on mongod cgroup",
		RootEntityID:      "cgroup:/system.slice/mongod.service",
		Domain:            model.DomainCPU,
		SupportingFactIDs: []string{"cpu.psi.avg10", "cpu.busy"},
	}
	mkF := func(id, ent string, conf, val float64, dur time.Duration) model.Fact {
		return model.Fact{
			ID: id, Source: "procfs", EntityID: ent, Domain: model.DomainCPU,
			Metric: id, Value: val, Confidence: model.FactConfidence(conf),
			Severity: model.FactSeverityWarn, MeasuredAt: now,
			Duration: dur, Kind: model.FactKindSaturation,
			// no BaselineDelta — baseline gate fails
		}
	}
	facts := []model.Fact{
		mkF("cpu.psi.avg10", "pid:1234", 0.9, 60, 10*time.Second),
		mkF("cpu.busy", "cgroup:/system.slice/mongod.service", 0.85, 85, 8*time.Second),
	}
	out := v.Verify(c, facts, makeGraph())
	if out.Tier != model.TierCProbable {
		t.Errorf("expected Tier C; got %s. gates=%+v", out.Tier, out.Gates)
	}
}

// TestVerifier_MultipleFailures_TierD asserts 2+ failures drop to D
// even if signal-quality passed.
func TestVerifier_MultipleFailures_TierD(t *testing.T) {
	v := Default()
	c := Candidate{
		Mechanism:         "fictitious",
		RootEntityID:      "pid:99999", // doesn't exist → ownership fail
		Domain:            model.DomainCPU,
		SupportingFactIDs: []string{"f1", "f2"},
	}
	facts := []model.Fact{
		makeFact("f1", "host", 0.9),  // no Duration → temporal fail
		makeFact("f2", "host", 0.85), // no BaselineDelta → baseline fail
	}
	out := v.Verify(c, facts, makeGraph())
	if out.Tier != model.TierDInconclusive {
		t.Errorf("expected Tier D with 3 failures; got %s", out.Tier)
	}
}

func TestVerifier_SignalQualityFailureAbstains(t *testing.T) {
	v := Default()
	c := Candidate{
		Mechanism:         "fictitious",
		RootEntityID:      "cgroup:/system.slice/mongod.service",
		Domain:            model.DomainCPU,
		SupportingFactIDs: []string{"f1"}, // only 1 — signal quality fails
	}
	facts := []model.Fact{
		makeFact("f1", "pid:1234", 0.9),
	}
	out := v.Verify(c, facts, makeGraph())
	if out.Tier != model.TierDInconclusive {
		t.Errorf("signal_quality failure must drive Tier D; got %s", out.Tier)
	}
}
