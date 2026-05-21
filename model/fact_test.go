package model

import (
	"encoding/json"
	"testing"
	"time"
)

// TestFactIsValid asserts the schema contract: ID, Domain, MeasuredAt
// are required; everything else is optional.
func TestFactIsValid(t *testing.T) {
	now := time.Date(2026, 5, 12, 0, 0, 0, 0, time.UTC)
	cases := []struct {
		name  string
		f     Fact
		valid bool
	}{
		{
			"complete",
			Fact{ID: "cpu.psi.avg10", Domain: "cpu", MeasuredAt: now},
			true,
		},
		{
			"missing-id",
			Fact{Domain: "cpu", MeasuredAt: now},
			false,
		},
		{
			"missing-domain",
			Fact{ID: "cpu.psi.avg10", MeasuredAt: now},
			false,
		},
		{
			"zero-measured-at",
			Fact{ID: "cpu.psi.avg10", Domain: "cpu"},
			false,
		},
		{
			"with-optional-fields",
			func() Fact {
				first := now.Add(-30 * time.Second)
				last := now
				return Fact{
					ID:            "cpu.psi.avg10",
					Kind:          FactKindSaturation,
					Source:        "procfs",
					EntityID:      "host",
					Domain:        "cpu",
					Metric:        "psi.avg10",
					Value:         42.5,
					Unit:          "%",
					MeasuredAt:    now,
					FirstSeenAt:   &first,
					LastSeenAt:    &last,
					Duration:      30 * time.Second,
					Severity:      FactSeverityWarn,
					Confidence:    0.9,
					BaselineDelta: 35.0,
					Tags:          map[string]string{"weight": "psi"},
				}
			}(),
			true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.f.IsValid(); got != tc.valid {
				t.Errorf("IsValid() = %v, want %v", got, tc.valid)
			}
		})
	}
}

// TestFactJSONRoundtrip asserts JSON serialization is lossless — this
// is required for the replay corpus (Phase 5) and for shipping facts
// across the fleet wire.
func TestFactJSONRoundtrip(t *testing.T) {
	now := time.Date(2026, 5, 12, 0, 0, 0, 0, time.UTC)
	first := now.Add(-30 * time.Second)
	last := now
	original := Fact{
		ID:            "cpu.psi.avg10",
		Kind:          FactKindSaturation,
		Source:        "procfs",
		EntityID:      "host",
		OwnerID:       "host",
		Domain:        "cpu",
		Metric:        "psi.avg10",
		Value:         42.5,
		Unit:          "%",
		MeasuredAt:    now,
		FirstSeenAt:   &first,
		LastSeenAt:    &last,
		Duration:      30 * time.Second,
		Severity:      FactSeverityWarn,
		Confidence:    0.9,
		BaselineDelta: 35.0,
		Tags:          map[string]string{"weight": "psi"},
	}
	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var restored Fact
	if err := json.Unmarshal(data, &restored); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	// Compare field-by-field rather than struct equality because
	// time.Time comparison via == is location-sensitive.
	if restored.ID != original.ID {
		t.Errorf("ID drift: %q vs %q", restored.ID, original.ID)
	}
	if restored.Kind != original.Kind {
		t.Errorf("Kind drift: %v vs %v", restored.Kind, original.Kind)
	}
	if restored.Value != original.Value {
		t.Errorf("Value drift: %v vs %v", restored.Value, original.Value)
	}
	if !restored.MeasuredAt.Equal(original.MeasuredAt) {
		t.Errorf("MeasuredAt drift: %v vs %v", restored.MeasuredAt, original.MeasuredAt)
	}
	if restored.FirstSeenAt == nil || !restored.FirstSeenAt.Equal(*original.FirstSeenAt) {
		t.Errorf("FirstSeenAt drift: %v vs %v", restored.FirstSeenAt, original.FirstSeenAt)
	}
	if restored.Duration != original.Duration {
		t.Errorf("Duration drift: %v vs %v", restored.Duration, original.Duration)
	}
	if restored.Confidence != original.Confidence {
		t.Errorf("Confidence drift: %v vs %v", restored.Confidence, original.Confidence)
	}
	if restored.Tags["weight"] != original.Tags["weight"] {
		t.Errorf("Tags drift: %v vs %v", restored.Tags, original.Tags)
	}
}

// TestFactOmitEmpty asserts the JSON output omits zero-valued optional
// fields — keeps the wire format compact for the replay corpus.
func TestFactOmitEmpty(t *testing.T) {
	now := time.Date(2026, 5, 12, 0, 0, 0, 0, time.UTC)
	minimal := Fact{
		ID: "cpu.psi.avg10", Kind: FactKindSaturation, Source: "procfs",
		Domain: "cpu", Metric: "psi.avg10", Value: 0, MeasuredAt: now,
		Severity: FactSeverityInfo, Confidence: 0.9,
	}
	data, err := json.Marshal(minimal)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	s := string(data)
	for _, key := range []string{"entity_id", "owner_id", "unit",
		"first_seen_at", "last_seen_at", "duration", "baseline_delta", "tags"} {
		if got := containsKey(s, key); got {
			t.Errorf("expected omitempty for %q but it appears in %q", key, s)
		}
	}
}

func containsKey(s, key string) bool {
	// Cheap substring check — sufficient because field names are unique.
	return indexOf(s, `"`+key+`":`) >= 0
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
