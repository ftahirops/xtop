package engine

import (
	"testing"

	"github.com/ftahirops/xtop/collector"
	"github.com/ftahirops/xtop/model"
)

// TestFinalizeIdempotent asserts that calling finalize() twice on the
// same AnalysisResult produces no further changes. Centralization is
// only useful if it's safe to call repeatedly — that's the contract.
func TestFinalizeIdempotent(t *testing.T) {
	e := NewEngineMode(60, 3, collector.ModeLean)
	defer e.Close()

	cases := []struct {
		name string
		in   *model.AnalysisResult
	}{
		{
			"healthy-ok",
			&model.AnalysisResult{
				Health:       model.HealthOK,
				Confidence:   95,
				PrimaryScore: 0,
			},
		},
		{
			"degraded-cpu",
			&model.AnalysisResult{
				Health:       model.HealthDegraded,
				Confidence:   70,
				PrimaryScore: 55,
				RCA: []model.RCAEntry{
					{Bottleneck: BottleneckCPU, Score: 55, EvidenceGroups: 2},
				},
			},
		},
		{
			"score-overflow-clamps",
			&model.AnalysisResult{
				PrimaryScore: 250, // out of range — finalize must clamp
				Confidence:   -5,  // also out of range
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e.finalize(tc.in, nil, nil)
			h1, c1, s1 := tc.in.Health, tc.in.Confidence, tc.in.PrimaryScore
			e.finalize(tc.in, nil, nil)
			if tc.in.Health != h1 || tc.in.Confidence != c1 || tc.in.PrimaryScore != s1 {
				t.Errorf("finalize not idempotent: was (%v,%d,%d), got (%v,%d,%d)",
					h1, c1, s1, tc.in.Health, tc.in.Confidence, tc.in.PrimaryScore)
			}
			// Bounds checks
			if tc.in.PrimaryScore < 0 || tc.in.PrimaryScore > 100 {
				t.Errorf("PrimaryScore=%d out of [0,100]", tc.in.PrimaryScore)
			}
			if tc.in.Confidence < 0 || tc.in.Confidence > 100 {
				t.Errorf("Confidence=%d out of [0,100]", tc.in.Confidence)
			}
		})
	}
}

// TestFinalizeClamps asserts the explicit clamping behavior — values
// outside [0,100] are pulled into the range.
func TestFinalizeClamps(t *testing.T) {
	e := NewEngineMode(60, 3, collector.ModeLean)
	defer e.Close()

	r := &model.AnalysisResult{PrimaryScore: 250, Confidence: -10}
	e.finalize(r, nil, nil)
	if r.PrimaryScore != 100 {
		t.Errorf("PrimaryScore=%d after clamp, want 100", r.PrimaryScore)
	}
	if r.Confidence != 0 {
		t.Errorf("Confidence=%d after clamp, want 0", r.Confidence)
	}
}

// TestFinalizeNilSafe asserts finalize doesn't panic on a nil result.
func TestFinalizeNilSafe(t *testing.T) {
	e := NewEngineMode(60, 3, collector.ModeLean)
	defer e.Close()
	e.finalize(nil, nil, nil) // must not panic
}
