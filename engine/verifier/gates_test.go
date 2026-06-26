package verifier

// Individual gate unit tests: baselineDeviationGate, temporalOrderingGate,
// counterEvidenceGate. Each test crafts a Candidate + Fact slice that should
// PASS or FAIL the gate, then asserts GateResult.Passed.
//
// signalQualityGate and ownershipConsistencyGate are covered in verifier_test.go.

import (
	"testing"
	"time"

	"github.com/ftahirops/xtop/model"
)

// ─── baselineDeviationGate ────────────────────────────────────────────────────

func TestBaselineDeviation_NoBaselineData(t *testing.T) {
	// No supporting fact has BaselineDelta set → gate must fail.
	c := Candidate{SupportingFactIDs: []string{"cpu.psi.avg10"}}
	facts := []model.Fact{makeFact("cpu.psi.avg10", "host", 0.9)}
	r := baselineDeviationGate{}.Evaluate(c, facts, nil)
	if r.Passed {
		t.Errorf("expected fail (no baseline data); got pass: %s", r.Reason)
	}
}

func TestBaselineDeviation_BelowThreshold(t *testing.T) {
	// BaselineDelta / Value = 5/100 = 5% — below 20% threshold.
	f := makeFact("cpu.psi.avg10", "host", 0.9)
	f.Value = 100
	f.BaselineDelta = 5 // 5% deviation
	c := Candidate{SupportingFactIDs: []string{"cpu.psi.avg10"}}
	r := baselineDeviationGate{}.Evaluate(c, []model.Fact{f}, nil)
	if r.Passed {
		t.Errorf("expected fail (5%% < 20%% threshold); got pass: %s", r.Reason)
	}
}

func TestBaselineDeviation_AtThreshold(t *testing.T) {
	// BaselineDelta / Value = 20/100 = 20% — exactly at threshold → pass.
	f := makeFact("cpu.psi.avg10", "host", 0.9)
	f.Value = 100
	f.BaselineDelta = 20 // exactly 20%
	c := Candidate{SupportingFactIDs: []string{"cpu.psi.avg10"}}
	r := baselineDeviationGate{}.Evaluate(c, []model.Fact{f}, nil)
	if !r.Passed {
		t.Errorf("expected pass at 20%% threshold; got fail: %s", r.Reason)
	}
}

func TestBaselineDeviation_AboveThreshold(t *testing.T) {
	// BaselineDelta / Value = 50/100 = 50% — well above 20% threshold.
	f := makeFact("cpu.psi.avg10", "host", 0.9)
	f.Value = 100
	f.BaselineDelta = 50
	c := Candidate{SupportingFactIDs: []string{"cpu.psi.avg10"}}
	r := baselineDeviationGate{}.Evaluate(c, []model.Fact{f}, nil)
	if !r.Passed {
		t.Errorf("expected pass (50%% > 20%%); got fail: %s", r.Reason)
	}
	if r.GateID != "baseline_deviation" {
		t.Errorf("GateID=%q, want baseline_deviation", r.GateID)
	}
}

func TestBaselineDeviation_NoFacts(t *testing.T) {
	// Empty SupportingFactIDs → fail.
	c := Candidate{}
	r := baselineDeviationGate{}.Evaluate(c, nil, nil)
	if r.Passed {
		t.Errorf("expected fail on empty facts; got pass")
	}
}

func TestBaselineDeviation_BestFactWins(t *testing.T) {
	// Two facts: one at 10% delta (below threshold) and one at 30% (above).
	// Gate should pass because the BEST fact clears the threshold.
	f1 := makeFact("cpu.psi.avg10", "host", 0.9)
	f1.Value = 100
	f1.BaselineDelta = 10 // 10% — below threshold alone

	f2 := makeFact("cpu.throttle", "host", 0.9)
	f2.Value = 100
	f2.BaselineDelta = 30 // 30% — above threshold

	c := Candidate{SupportingFactIDs: []string{"cpu.psi.avg10", "cpu.throttle"}}
	r := baselineDeviationGate{}.Evaluate(c, []model.Fact{f1, f2}, nil)
	if !r.Passed {
		t.Errorf("expected pass (best fact at 30%%); got fail: %s", r.Reason)
	}
}

// ─── temporalOrderingGate ─────────────────────────────────────────────────────

func TestTemporalOrdering_NoFacts(t *testing.T) {
	c := Candidate{}
	r := temporalOrderingGate{}.Evaluate(c, nil, nil)
	if r.Passed {
		t.Errorf("expected fail on no facts; got pass")
	}
}

func TestTemporalOrdering_TooShort(t *testing.T) {
	// Duration = 3s < 6s minimum.
	f := makeFact("cpu.psi.avg10", "host", 0.9)
	f.Duration = 3 * time.Second
	c := Candidate{SupportingFactIDs: []string{"cpu.psi.avg10"}}
	r := temporalOrderingGate{}.Evaluate(c, []model.Fact{f}, nil)
	if r.Passed {
		t.Errorf("expected fail on 3s duration; got pass: %s", r.Reason)
	}
}

func TestTemporalOrdering_ExactlyAtThreshold(t *testing.T) {
	// Duration = 6s — exactly at threshold → pass.
	f := makeFact("cpu.psi.avg10", "host", 0.9)
	f.Duration = 6 * time.Second
	c := Candidate{SupportingFactIDs: []string{"cpu.psi.avg10"}}
	r := temporalOrderingGate{}.Evaluate(c, []model.Fact{f}, nil)
	if !r.Passed {
		t.Errorf("expected pass at exactly 6s; got fail: %s", r.Reason)
	}
}

func TestTemporalOrdering_Passes(t *testing.T) {
	// Duration = 12s >> 6s minimum.
	f := makeFact("cpu.psi.avg10", "host", 0.9)
	f.Duration = 12 * time.Second
	c := Candidate{SupportingFactIDs: []string{"cpu.psi.avg10"}}
	r := temporalOrderingGate{}.Evaluate(c, []model.Fact{f}, nil)
	if !r.Passed {
		t.Errorf("expected pass on 12s; got fail: %s", r.Reason)
	}
	if r.GateID != "temporal_ordering" {
		t.Errorf("GateID=%q, want temporal_ordering", r.GateID)
	}
}

func TestTemporalOrdering_LongestFactWins(t *testing.T) {
	// Two facts: one short (2s), one long (10s). Gate passes because the
	// longest one clears the 6s threshold.
	f1 := makeFact("a", "host", 0.9)
	f1.Duration = 2 * time.Second

	f2 := makeFact("b", "host", 0.9)
	f2.Duration = 10 * time.Second

	c := Candidate{SupportingFactIDs: []string{"a", "b"}}
	r := temporalOrderingGate{}.Evaluate(c, []model.Fact{f1, f2}, nil)
	if !r.Passed {
		t.Errorf("expected pass (longest=10s); got fail: %s", r.Reason)
	}
}

func TestTemporalOrdering_ZeroDurationFails(t *testing.T) {
	// makeFact produces Duration=0 (zero value) — gate must fail.
	f := makeFact("cpu.psi.avg10", "host", 0.9)
	c := Candidate{SupportingFactIDs: []string{"cpu.psi.avg10"}}
	r := temporalOrderingGate{}.Evaluate(c, []model.Fact{f}, nil)
	if r.Passed {
		t.Errorf("expected fail on zero Duration; got pass")
	}
}

// ─── counterEvidenceGate ──────────────────────────────────────────────────────

func TestCounterEvidence_NoDomain_Passes(t *testing.T) {
	// No domain set → conservative pass (no rules apply).
	c := Candidate{Mechanism: "some unknown thing"}
	r := counterEvidenceGate{}.Evaluate(c, nil, nil)
	if !r.Passed {
		t.Errorf("expected pass with no domain; got fail: %s", r.Reason)
	}
}

func TestCounterEvidence_CPU_BusyBelowThreshold_Fails(t *testing.T) {
	// CPU domain but cpu.busy = 5% (< 20%) → disqualified.
	cpuBusy := makeFact("cpu.busy", "host", 0.9)
	cpuBusy.Value = 5
	c := Candidate{
		Domain:            model.DomainCPU,
		Mechanism:         "CPU contention",
		SupportingFactIDs: []string{"cpu.busy"},
	}
	r := counterEvidenceGate{}.Evaluate(c, []model.Fact{cpuBusy}, nil)
	if r.Passed {
		t.Errorf("expected fail (cpu.busy=5%% < 20%%); got pass: %s", r.Reason)
	}
}

func TestCounterEvidence_CPU_BusyAboveThreshold_Passes(t *testing.T) {
	// CPU domain, cpu.busy = 80% (≥ 20%) → passes counter-evidence check.
	cpuBusy := makeFact("cpu.busy", "host", 0.9)
	cpuBusy.Value = 80
	c := Candidate{
		Domain:            model.DomainCPU,
		Mechanism:         "CPU contention",
		SupportingFactIDs: []string{"cpu.busy"},
	}
	r := counterEvidenceGate{}.Evaluate(c, []model.Fact{cpuBusy}, nil)
	if !r.Passed {
		t.Errorf("expected pass (cpu.busy=80%% ≥ 20%%); got fail: %s", r.Reason)
	}
}

func TestCounterEvidence_CPU_MissingFact_Fails(t *testing.T) {
	// CPU domain, cpu.busy fact missing entirely → disqualified.
	c := Candidate{
		Domain:    model.DomainCPU,
		Mechanism: "CPU contention",
	}
	r := counterEvidenceGate{}.Evaluate(c, nil, nil)
	if r.Passed {
		t.Errorf("expected fail (cpu.busy missing); got pass: %s", r.Reason)
	}
}

func TestCounterEvidence_Throttle_MechanismHintMatching(t *testing.T) {
	// CPU throttle mechanism → also checks cpu.cgroup.throttle rule.
	// Supply cpu.busy ≥ 20 to pass that rule, but omit cpu.cgroup.throttle.
	cpuBusy := makeFact("cpu.busy", "host", 0.9)
	cpuBusy.Value = 60
	c := Candidate{
		Domain:            model.DomainCPU,
		Mechanism:         "cgroup throttle causing latency",
		SupportingFactIDs: []string{"cpu.busy"},
	}
	r := counterEvidenceGate{}.Evaluate(c, []model.Fact{cpuBusy}, nil)
	// cpu.cgroup.throttle is missing → "throttle" rule triggers → fail
	if r.Passed {
		t.Errorf("expected fail: throttle rule fires (cpu.cgroup.throttle missing); got pass: %s", r.Reason)
	}
}

func TestCounterEvidence_IO_DiskUtilZero_Fails(t *testing.T) {
	// IO domain, io.disk.util = 0 → disqualified.
	diskUtil := makeFact("io.disk.util", "host", 0.9)
	diskUtil.Value = 0
	diskUtil.Domain = model.DomainIO
	c := Candidate{
		Domain:            model.DomainIO,
		Mechanism:         "IO contention causing latency",
		SupportingFactIDs: []string{"io.disk.util"},
	}
	r := counterEvidenceGate{}.Evaluate(c, []model.Fact{diskUtil}, nil)
	if r.Passed {
		t.Errorf("expected fail (io.disk.util=0); got pass: %s", r.Reason)
	}
}

func TestCounterEvidence_IO_DiskUtilAbove_Passes(t *testing.T) {
	// IO domain, io.disk.util = 50 → passes.
	diskUtil := makeFact("io.disk.util", "host", 0.9)
	diskUtil.Value = 50
	diskUtil.Domain = model.DomainIO
	c := Candidate{
		Domain:            model.DomainIO,
		Mechanism:         "IO contention causing latency",
		SupportingFactIDs: []string{"io.disk.util"},
	}
	r := counterEvidenceGate{}.Evaluate(c, []model.Fact{diskUtil}, nil)
	if !r.Passed {
		t.Errorf("expected pass (io.disk.util=50); got fail: %s", r.Reason)
	}
	if r.GateID != "counter_evidence" {
		t.Errorf("GateID=%q, want counter_evidence", r.GateID)
	}
}

func TestCounterEvidence_Network_NoMatchingMechanism(t *testing.T) {
	// Network domain but "retransmit" mechanism — "drop" hint rule doesn't
	// match, so the gate passes conservatively.
	c := Candidate{
		Domain:    model.DomainNetwork,
		Mechanism: "tcp retransmit storm",
	}
	r := counterEvidenceGate{}.Evaluate(c, nil, nil)
	if !r.Passed {
		t.Errorf("expected pass (no matching rule for retransmit); got fail: %s", r.Reason)
	}
}
