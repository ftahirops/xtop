package model

import (
	"encoding/json"
	"testing"
	"time"
)

// TestVerificationTierConstants asserts the four tier constant values are
// stable strings. These values travel over the wire (JSON) and into the
// replay corpus; changing them is a breaking change.
func TestVerificationTierConstants(t *testing.T) {
	cases := []struct {
		tier VerificationTier
		want string
	}{
		{TierAConfirmed, "A_confirmed"},
		{TierBVerified, "B_verified"},
		{TierCProbable, "C_probable"},
		{TierDInconclusive, "D_inconclusive"},
	}
	for _, tc := range cases {
		if string(tc.tier) != tc.want {
			t.Errorf("tier %q: got %q, want %q", tc.want, tc.tier, tc.want)
		}
	}
}

// TestVerificationTierOrdering asserts the string ordering matches the
// semantic ordering A > B > C > D (ascending ASCII).
func TestVerificationTierOrdering(t *testing.T) {
	// A < B < C < D in string comparison — correct because they encode
	// the rank in the first character.
	tiers := []VerificationTier{
		TierAConfirmed,
		TierBVerified,
		TierCProbable,
		TierDInconclusive,
	}
	for i := 1; i < len(tiers); i++ {
		if string(tiers[i-1]) >= string(tiers[i]) {
			t.Errorf("ordering broken: %q >= %q", tiers[i-1], tiers[i])
		}
	}
}

// TestVerifiedCauseJSONRoundtrip asserts VerifiedCause serializes
// losslessly. This matters for the Phase 5 replay corpus: the verifier
// output must survive marshal→unmarshal without drift.
func TestVerifiedCauseJSONRoundtrip(t *testing.T) {
	now := time.Date(2026, 5, 12, 10, 30, 0, 0, time.UTC)
	orig := VerifiedCause{
		Mechanism:    "CPU contention on mongod cgroup",
		Tier:         TierAConfirmed,
		RootEntityID: "cgroup:/system.slice/mongod.service",
		BlastRadius:  []string{"pid:1234", "pid:5678"},
		Confidence:   87,
		EvaluatedAt:  now,
		Gates: []GateResult{
			{GateID: "signal_quality", Passed: true, Reason: "2 facts, avg conf 0.9"},
			{GateID: "baseline_deviation", Passed: true, Reason: "50% above baseline", FactsUsed: []string{"cpu.psi.avg10"}},
			{GateID: "temporal_ordering", Passed: true, Reason: "sustained 12s"},
			{GateID: "ownership_consistency", Passed: true, Reason: "entity in chain"},
			{GateID: "counter_evidence", Passed: false, Reason: "cpu.busy below threshold", FactsUsed: []string{"cpu.busy"}},
		},
	}

	data, err := json.Marshal(orig)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var got VerifiedCause
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if got.Mechanism != orig.Mechanism {
		t.Errorf("Mechanism: %q vs %q", got.Mechanism, orig.Mechanism)
	}
	if got.Tier != orig.Tier {
		t.Errorf("Tier: %q vs %q", got.Tier, orig.Tier)
	}
	if got.RootEntityID != orig.RootEntityID {
		t.Errorf("RootEntityID: %q vs %q", got.RootEntityID, orig.RootEntityID)
	}
	if got.Confidence != orig.Confidence {
		t.Errorf("Confidence: %d vs %d", got.Confidence, orig.Confidence)
	}
	if !got.EvaluatedAt.Equal(orig.EvaluatedAt) {
		t.Errorf("EvaluatedAt: %v vs %v", got.EvaluatedAt, orig.EvaluatedAt)
	}
	if len(got.BlastRadius) != len(orig.BlastRadius) {
		t.Errorf("BlastRadius len: %d vs %d", len(got.BlastRadius), len(orig.BlastRadius))
	}
	if len(got.Gates) != len(orig.Gates) {
		t.Fatalf("Gates len: %d vs %d", len(got.Gates), len(orig.Gates))
	}
	for i, g := range got.Gates {
		o := orig.Gates[i]
		if g.GateID != o.GateID {
			t.Errorf("Gates[%d].GateID: %q vs %q", i, g.GateID, o.GateID)
		}
		if g.Passed != o.Passed {
			t.Errorf("Gates[%d].Passed: %v vs %v", i, g.Passed, o.Passed)
		}
	}
}

// TestGateResultOmitEmpty asserts GateResult omits empty optional fields.
func TestGateResultOmitEmpty(t *testing.T) {
	gr := GateResult{GateID: "signal_quality", Passed: true}
	data, err := json.Marshal(gr)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	s := string(data)
	for _, key := range []string{"reason", "facts_used"} {
		if idx := indexOf(s, `"`+key+`":`); idx >= 0 {
			t.Errorf("expected omitempty for %q but found in %q", key, s)
		}
	}
}
