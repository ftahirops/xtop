package engine

import (
	"strings"
	"testing"

	"github.com/ftahirops/xtop/model"
)

// TestNarrativeSigmaZeroNotPrinted verifies that when a BaselineAnomaly is detected
// but ZScore/Sigma is 0 (flat baseline, stddev < 1e-9), the narrative does NOT
// emit "0.0 sigma" which would be misleading to the user.
func TestNarrativeSigmaZeroNotPrinted(t *testing.T) {
	// Build a minimal AnalysisResult that will reach the BaselineAnomalies enrichment.
	// Health must not be HealthOK, and there must be at least one fired evidence.
	result := &model.AnalysisResult{
		Health:           model.HealthDegraded,
		PrimaryBottleneck: "cpu",
		RCA: []model.RCAEntry{
			{
				Bottleneck: "cpu",
				Score:      80,
				EvidenceV2: []model.Evidence{
					{
						ID:       "cpu.busy",
						Strength: 0.9,
						Domain:   model.DomainCPU,
					},
				},
			},
		},
		BaselineAnomalies: []model.BaselineAnomaly{
			{
				EvidenceID: "cpu.busy",
				Value:      95.0,
				Baseline:   50.0,
				StdDev:     0, // flat baseline — stddev below 1e-9 guard
				ZScore:     0, // zScore() returned 0 due to flat stddev
				Sigma:      0,
			},
		},
	}

	n := BuildNarrative(result, nil, nil)
	if n == nil {
		t.Fatal("BuildNarrative returned nil; expected a narrative")
	}

	for _, ev := range n.Evidence {
		if strings.Contains(ev, "0.0 sigma") {
			t.Errorf("narrative evidence contains misleading '0.0 sigma': %q", ev)
		}
	}

	// Also verify that an anomaly with non-zero sigma still prints the sigma phrase.
	result2 := &model.AnalysisResult{
		Health:           model.HealthDegraded,
		PrimaryBottleneck: "cpu",
		RCA: []model.RCAEntry{
			{
				Bottleneck: "cpu",
				Score:      80,
				EvidenceV2: []model.Evidence{
					{ID: "cpu.busy", Strength: 0.9, Domain: model.DomainCPU},
				},
			},
		},
		BaselineAnomalies: []model.BaselineAnomaly{
			{
				EvidenceID: "cpu.busy",
				Value:      95.0,
				Baseline:   50.0,
				StdDev:     5.0,
				ZScore:     9.0,
				Sigma:      9.0,
			},
		},
	}

	n2 := BuildNarrative(result2, nil, nil)
	if n2 == nil {
		t.Fatal("BuildNarrative returned nil for non-zero sigma case")
	}

	found := false
	for _, ev := range n2.Evidence {
		if strings.Contains(ev, "sigma") && strings.Contains(ev, "9.0") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected '9.0 sigma' phrase in evidence, got: %v", n2.Evidence)
	}
}

// TestProcessAnomalySigmaZeroNotPrinted verifies that when a ProcessAnomaly is detected
// but Sigma is 0 (flat baseline), the narrative does NOT emit "0.0 sigma".
func TestProcessAnomalySigmaZeroNotPrinted(t *testing.T) {
	// Case 1: ProcessAnomaly with Sigma == 0
	result := &model.AnalysisResult{
		Health:           model.HealthDegraded,
		PrimaryBottleneck: "cpu",
		RCA: []model.RCAEntry{
			{
				Bottleneck: "cpu",
				Score:      80,
				EvidenceV2: []model.Evidence{
					{
						ID:       "cpu.busy",
						Strength: 0.9,
						Domain:   model.DomainCPU,
					},
				},
			},
		},
		ProcessAnomalies: []model.ProcessAnomaly{
			{
				Comm:     "python",
				PID:      12345,
				Metric:   "cpu_percent",
				Current:  95.0,
				Baseline: 50.0,
				Sigma:    0, // flat baseline — sigma not computable
			},
		},
	}

	n := BuildNarrative(result, nil, nil)
	if n == nil {
		t.Fatal("BuildNarrative returned nil; expected a narrative")
	}

	for _, ev := range n.Evidence {
		if strings.Contains(ev, "0.0 sigma") {
			t.Errorf("narrative evidence contains misleading '0.0 sigma' for ProcessAnomaly: %q", ev)
		}
	}

	// Verify that sigma=0 case includes "above baseline" phrasing
	found := false
	for _, ev := range n.Evidence {
		if strings.Contains(ev, "python") && strings.Contains(ev, "PID 12345") && strings.Contains(ev, "above baseline") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected 'above baseline' phrase for ProcessAnomaly with sigma=0, got: %v", n.Evidence)
	}

	// Case 2: ProcessAnomaly with non-zero Sigma should still print sigma phrase
	result2 := &model.AnalysisResult{
		Health:           model.HealthDegraded,
		PrimaryBottleneck: "cpu",
		RCA: []model.RCAEntry{
			{
				Bottleneck: "cpu",
				Score:      80,
				EvidenceV2: []model.Evidence{
					{ID: "cpu.busy", Strength: 0.9, Domain: model.DomainCPU},
				},
			},
		},
		ProcessAnomalies: []model.ProcessAnomaly{
			{
				Comm:     "python",
				PID:      12345,
				Metric:   "cpu_percent",
				Current:  95.0,
				Baseline: 50.0,
				Sigma:    8.5,
			},
		},
	}

	n2 := BuildNarrative(result2, nil, nil)
	if n2 == nil {
		t.Fatal("BuildNarrative returned nil for non-zero sigma case")
	}

	found = false
	for _, ev := range n2.Evidence {
		if strings.Contains(ev, "python") && strings.Contains(ev, "8.5 sigma") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected '8.5 sigma' phrase for ProcessAnomaly with non-zero sigma, got: %v", n2.Evidence)
	}
}
