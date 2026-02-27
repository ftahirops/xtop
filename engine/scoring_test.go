package engine

import (
	"testing"

	"github.com/ftahirops/xtop/model"
)

func makeEvidence(id string, strength, conf float64, measured bool, weight string) model.Evidence {
	return model.Evidence{
		ID:         id,
		Strength:   strength,
		Confidence: conf,
		Measured:   measured,
		Domain:     model.DomainIO,
		Tags:       map[string]string{"weight": weight},
	}
}

func TestV2TrustGate(t *testing.T) {
	tests := []struct {
		name string
		evs  []model.Evidence
		want bool
	}{
		{
			"passes: 2 groups fired, 1 measured high conf",
			[]model.Evidence{
				makeEvidence("io.psi", 0.5, 0.9, true, "psi"),
				makeEvidence("io.dstate", 0.4, 0.7, false, "queue"),
			},
			true,
		},
		{
			"fails: only 1 group fired",
			[]model.Evidence{
				makeEvidence("io.psi", 0.5, 0.9, true, "psi"),
				makeEvidence("io.dstate", 0.1, 0.7, false, "queue"),
			},
			false,
		},
		{
			"fails: 2 groups but no measured high conf",
			[]model.Evidence{
				makeEvidence("io.psi", 0.5, 0.7, false, "psi"),
				makeEvidence("io.dstate", 0.4, 0.7, false, "queue"),
			},
			false,
		},
		{
			"passes: 3 groups, measured",
			[]model.Evidence{
				makeEvidence("io.psi", 0.8, 0.9, true, "psi"),
				makeEvidence("io.dstate", 0.6, 0.8, true, "queue"),
				makeEvidence("io.disk.latency", 0.5, 0.7, false, "latency"),
			},
			true,
		},
		{
			"empty evidence",
			[]model.Evidence{},
			false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := v2TrustGate(tt.evs)
			if got != tt.want {
				t.Errorf("v2TrustGate() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestWeightedDomainScore(t *testing.T) {
	tests := []struct {
		name string
		evs  []model.Evidence
		min  float64 // minimum expected score
		max  float64 // maximum expected score
	}{
		{
			"all slots maxed",
			[]model.Evidence{
				makeEvidence("io.psi", 1.0, 1.0, true, "psi"),
				makeEvidence("io.disk.latency", 1.0, 1.0, false, "latency"),
				makeEvidence("io.dstate", 1.0, 1.0, true, "queue"),
				makeEvidence("io.writeback", 1.0, 1.0, false, "secondary"),
			},
			99, 100,
		},
		{
			"only PSI fires",
			[]model.Evidence{
				makeEvidence("io.psi", 0.8, 0.9, true, "psi"),
			},
			20, 30,
		},
		{
			"nothing fires",
			[]model.Evidence{
				makeEvidence("io.psi", 0.0, 0.9, true, "psi"),
				makeEvidence("io.dstate", 0.0, 0.7, false, "queue"),
			},
			0, 0.1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := weightedDomainScore(tt.evs)
			if got < tt.min || got > tt.max {
				t.Errorf("weightedDomainScore() = %v, want [%v, %v]", got, tt.min, tt.max)
			}
		})
	}
}

func TestDomainConfidence(t *testing.T) {
	tests := []struct {
		name string
		evs  []model.Evidence
		min  float64
		max  float64
	}{
		{
			"no fired evidence",
			[]model.Evidence{
				makeEvidence("io.psi", 0.1, 0.9, true, "psi"),
			},
			0, 0,
		},
		{
			"1 fired group",
			[]model.Evidence{
				makeEvidence("io.psi", 0.5, 0.9, true, "psi"),
			},
			0.3, 0.98,
		},
		{
			"3 fired groups high conf",
			[]model.Evidence{
				makeEvidence("io.psi", 0.8, 0.9, true, "psi"),
				makeEvidence("io.dstate", 0.6, 0.8, true, "queue"),
				makeEvidence("io.disk.latency", 0.5, 0.9, false, "latency"),
			},
			0.8, 0.98,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := domainConfidence(tt.evs)
			if got < tt.min || got > tt.max {
				t.Errorf("domainConfidence() = %v, want [%v, %v]", got, tt.min, tt.max)
			}
		})
	}
}

func TestEvidenceToChecks(t *testing.T) {
	evs := []model.Evidence{
		{
			ID: "io.psi", Message: "IO PSI some=10%", Strength: 0.5,
			Confidence: 0.9, Measured: true,
		},
		{
			ID: "io.dstate", Message: "3 D-state tasks", Strength: 0.1,
			Confidence: 0.7, Measured: false,
		},
	}

	checks := evidenceToChecks(evs)
	if len(checks) != 2 {
		t.Fatalf("expected 2 checks, got %d", len(checks))
	}

	// First check should be the passed one (strength >= 0.35)
	if !checks[0].Passed {
		t.Error("first check should be passed")
	}
	if checks[0].Confidence != "H" {
		t.Errorf("expected H confidence, got %s", checks[0].Confidence)
	}

	// Second check should not be passed
	if checks[1].Passed {
		t.Error("second check should not be passed")
	}
}

func TestAlertStateUpdate(t *testing.T) {
	// At 3s interval: 15/3 = 5 ticks required
	as := NewAlertState(3)

	// Should start at OK
	h := as.Update(model.HealthOK, false)
	if h != model.HealthOK {
		t.Errorf("initial health = %v, want OK", h)
	}

	// 4 ticks at Critical — should still be OK (not sustained)
	for i := 0; i < 4; i++ {
		h = as.Update(model.HealthCritical, false)
	}
	if h != model.HealthOK {
		t.Errorf("after 4 ticks at Critical = %v, want OK (not sustained)", h)
	}

	// 5th tick — should transition to Critical
	h = as.Update(model.HealthCritical, false)
	if h != model.HealthCritical {
		t.Errorf("after 5 ticks at Critical = %v, want Critical", h)
	}

	// Instant override: should bypass sustained requirement
	as2 := NewAlertState(3)
	h = as2.Update(model.HealthCritical, true)
	if h != model.HealthCritical {
		t.Errorf("crit evidence bypass = %v, want Critical", h)
	}

	// Trust gate respected: Inconclusive should NOT escalate to Critical
	as3 := NewAlertState(3)
	for i := 0; i < 10; i++ {
		h = as3.Update(model.HealthInconclusive, false)
	}
	if h != model.HealthInconclusive {
		t.Errorf("inconclusive sustained = %v, want Inconclusive", h)
	}
}

func TestAlertStateIntervalScaling(t *testing.T) {
	// 1s interval: 15/1 = 15 ticks
	as1 := NewAlertState(1)
	if as1.sustainedRequired != 15 {
		t.Errorf("1s interval: sustainedRequired = %d, want 15", as1.sustainedRequired)
	}

	// 3s interval: 15/3 = 5 ticks
	as3 := NewAlertState(3)
	if as3.sustainedRequired != 5 {
		t.Errorf("3s interval: sustainedRequired = %d, want 5", as3.sustainedRequired)
	}

	// 10s interval: 15/10 = 1, clamped to minimum 3
	as10 := NewAlertState(10)
	if as10.sustainedRequired != 3 {
		t.Errorf("10s interval: sustainedRequired = %d, want 3 (minimum)", as10.sustainedRequired)
	}
}
