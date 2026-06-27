package engine

import (
	"testing"
	"time"

	"github.com/ftahirops/xtop/model"
)

// ---------------------------------------------------------------------------
// InjectConfigDriftEvidence
// ---------------------------------------------------------------------------

func TestInjectConfigDriftEvidence_MemoryDrift(t *testing.T) {
	now := time.Now()

	changes := []model.SystemChange{
		{
			Type:   "config_drift_memory",
			Detail: "vm.swappiness: 60 → 100",
			Domain: "memory",
			When:   now.Add(-30 * time.Second),
		},
	}

	facts := InjectConfigDriftEvidence(nil, changes, now)

	if len(facts) != 1 {
		t.Fatalf("expected 1 fact, got %d", len(facts))
	}
	f := facts[0]

	if f.Kind != model.FactKindConfigChange {
		t.Errorf("Kind = %q, want %q", f.Kind, model.FactKindConfigChange)
	}
	if f.Source != "config" {
		t.Errorf("Source = %q, want %q", f.Source, "config")
	}
	if f.EntityID != "host" {
		t.Errorf("EntityID = %q, want \"host\"", f.EntityID)
	}
	if f.Domain != model.DomainMemory {
		t.Errorf("Domain = %q, want %q", f.Domain, model.DomainMemory)
	}
	if f.Metric != "vm.swappiness" {
		t.Errorf("Metric = %q, want \"vm.swappiness\"", f.Metric)
	}
	if f.Value != 1.0 {
		t.Errorf("Value = %v, want 1.0", f.Value)
	}
	if float64(f.Confidence) < 0.55 || float64(f.Confidence) > 0.65 {
		t.Errorf("Confidence = %v, want ~0.6 (moderate)", f.Confidence)
	}
	if f.Tags["key"] != "vm.swappiness" {
		t.Errorf("Tags[key] = %q, want \"vm.swappiness\"", f.Tags["key"])
	}
	if f.Tags["old"] == "" {
		t.Error("Tags[old] should be set")
	}
	if f.Tags["new"] == "" {
		t.Error("Tags[new] should be set")
	}
	if f.Tags["domain"] != "memory" {
		t.Errorf("Tags[domain] = %q, want \"memory\"", f.Tags["domain"])
	}
}

func TestInjectConfigDriftEvidence_CPUDrift(t *testing.T) {
	now := time.Now()
	changes := []model.SystemChange{
		{
			Type:   "config_drift_cpu",
			Detail: "cpu.governor: powersave → performance",
			Domain: "cpu",
			When:   now,
		},
	}

	facts := InjectConfigDriftEvidence(nil, changes, now)

	if len(facts) != 1 {
		t.Fatalf("expected 1 fact, got %d", len(facts))
	}
	if facts[0].Domain != model.DomainCPU {
		t.Errorf("Domain = %q, want %q", facts[0].Domain, model.DomainCPU)
	}
}

func TestInjectConfigDriftEvidence_NetworkDrift(t *testing.T) {
	now := time.Now()
	changes := []model.SystemChange{
		{
			Type:   "config_drift_network",
			Detail: "net.core.somaxconn: 128 → 1024",
			Domain: "network",
			When:   now,
		},
	}

	facts := InjectConfigDriftEvidence(nil, changes, now)

	if len(facts) != 1 {
		t.Fatalf("expected 1 fact, got %d", len(facts))
	}
	if facts[0].Domain != model.DomainNetwork {
		t.Errorf("Domain = %q, want %q", facts[0].Domain, model.DomainNetwork)
	}
}

func TestInjectConfigDriftEvidence_IODrift(t *testing.T) {
	now := time.Now()
	changes := []model.SystemChange{
		{
			Type:   "config_drift_io",
			Detail: "vm.dirty_ratio: 20 → 40",
			Domain: "io",
			When:   now,
		},
	}

	facts := InjectConfigDriftEvidence(nil, changes, now)

	if len(facts) != 1 {
		t.Fatalf("expected 1 fact, got %d", len(facts))
	}
	if facts[0].Domain != model.DomainIO {
		t.Errorf("Domain = %q, want %q", facts[0].Domain, model.DomainIO)
	}
}

func TestInjectConfigDriftEvidence_NonDriftChangesSkipped(t *testing.T) {
	now := time.Now()
	changes := []model.SystemChange{
		{
			Type:   "new_process",
			Detail: "nginx started",
			Domain: "",
			When:   now,
		},
		{
			Type:   "package_install",
			Detail: "curl",
			Domain: "",
			When:   now,
		},
	}

	facts := InjectConfigDriftEvidence(nil, changes, now)
	if len(facts) != 0 {
		t.Errorf("expected 0 facts for non-drift changes, got %d", len(facts))
	}
}

func TestInjectConfigDriftEvidence_EmptyChanges(t *testing.T) {
	facts := InjectConfigDriftEvidence(nil, nil, time.Now())
	if facts != nil {
		t.Errorf("expected nil for empty input, got %v", facts)
	}
}

// ---------------------------------------------------------------------------
// correlateConfigDrift — onset correlation
// ---------------------------------------------------------------------------

// makeMemoryAnomalyResult creates a minimal AnalysisResult with a memory
// bottleneck that started recentSec seconds ago.
func makeMemoryAnomalyResult(recentSec int) *model.AnalysisResult {
	return &model.AnalysisResult{
		PrimaryBottleneck: BottleneckMemory,
		PrimaryScore:      55,
		AnomalyStartedAgo: recentSec,
		RCA: []model.RCAEntry{
			{
				Bottleneck: BottleneckMemory,
				Score:      55,
			},
		},
	}
}

func TestCorrelateConfigDrift_MemoryDriftBoostsMemoryAnomaly(t *testing.T) {
	now := time.Now()

	// Drift happened 45s ago; anomaly started 60s ago. Within the 5-minute window.
	driftAt := now.Add(-45 * time.Second)
	changes := []model.SystemChange{
		{
			Type:   "config_drift_memory",
			Detail: "vm.swappiness: 60 → 100",
			Domain: "memory",
			When:   driftAt,
		},
	}

	result := makeMemoryAnomalyResult(60)
	origScore := result.RCA[0].Score

	correlateConfigDrift(result, changes, now)

	if result.RCA[0].Score <= origScore {
		t.Errorf("expected score boost: got %d, original was %d", result.RCA[0].Score, origScore)
	}

	// PrimaryScore must be kept in sync with the boosted RCA entry score because
	// the entry's Bottleneck matches the PrimaryBottleneck.
	if result.PrimaryScore != result.RCA[0].Score {
		t.Errorf("PrimaryScore = %d, want %d (should mirror boosted RCA entry)",
			result.PrimaryScore, result.RCA[0].Score)
	}

	// Verify a config-change fact was attached to the host-level facts.
	foundFact := false
	for _, f := range result.Facts {
		if f.Kind == model.FactKindConfigChange {
			foundFact = true
		}
	}
	if !foundFact {
		t.Error("expected a FactKindConfigChange fact attached to result.Facts")
	}
}

func TestCorrelateConfigDrift_WrongDomainNoBoost(t *testing.T) {
	now := time.Now()

	// Network drift, but anomaly is memory-domain — should NOT boost.
	driftAt := now.Add(-30 * time.Second)
	changes := []model.SystemChange{
		{
			Type:   "config_drift_network",
			Detail: "net.core.somaxconn: 128 → 1024",
			Domain: "network",
			When:   driftAt,
		},
	}

	result := makeMemoryAnomalyResult(60)
	origScore := result.RCA[0].Score

	correlateConfigDrift(result, changes, now)

	if result.RCA[0].Score != origScore {
		t.Errorf("score should not change for domain mismatch: got %d, want %d",
			result.RCA[0].Score, origScore)
	}
}

func TestCorrelateConfigDrift_StaleDriftNoBoost(t *testing.T) {
	now := time.Now()

	// Drift happened 10 minutes ago — outside the correlation window.
	driftAt := now.Add(-10 * time.Minute)
	changes := []model.SystemChange{
		{
			Type:   "config_drift_memory",
			Detail: "vm.swappiness: 60 → 100",
			Domain: "memory",
			When:   driftAt,
		},
	}

	result := makeMemoryAnomalyResult(60)
	origScore := result.RCA[0].Score

	correlateConfigDrift(result, changes, now)

	if result.RCA[0].Score != origScore {
		t.Errorf("score should not change for stale drift: got %d, want %d",
			result.RCA[0].Score, origScore)
	}
}

func TestCorrelateConfigDrift_NoActiveAnomaly(t *testing.T) {
	now := time.Now()

	driftAt := now.Add(-30 * time.Second)
	changes := []model.SystemChange{
		{
			Type:   "config_drift_memory",
			Detail: "vm.swappiness: 60 → 100",
			Domain: "memory",
			When:   driftAt,
		},
	}

	// No active anomaly (score=0, AnomalyStartedAgo=0)
	result := &model.AnalysisResult{
		PrimaryScore:      0,
		AnomalyStartedAgo: 0,
	}

	correlateConfigDrift(result, changes, now)

	// Nothing should be attached
	if len(result.Facts) > 0 {
		t.Errorf("expected no facts when no anomaly, got %d", len(result.Facts))
	}
}

// TestInjectConfigDriftEvidence_TagsParsedFromDetail ensures the old/new
// values are correctly extracted from the "key: old → new" detail string.
// Uses EXACT equality so a stray leading byte (e.g. from an off-by-N UTF-8
// slice) causes a clear failure rather than a silent pass.
func TestInjectConfigDriftEvidence_TagsParsedFromDetail(t *testing.T) {
	now := time.Now()

	cases := []struct {
		detail  string
		wantKey string
		wantOld string
		wantNew string
	}{
		{
			detail:  "vm.swappiness: 60 → 100",
			wantKey: "vm.swappiness",
			wantOld: "60",
			wantNew: "100",
		},
		{
			detail:  "net.core.somaxconn: 128 → 4096",
			wantKey: "net.core.somaxconn",
			wantOld: "128",
			wantNew: "4096",
		},
		{
			detail:  "cpu.governor: powersave -> performance",
			wantKey: "cpu.governor",
			wantOld: "powersave",
			wantNew: "performance",
		},
	}

	for _, tc := range cases {
		t.Run(tc.detail, func(t *testing.T) {
			changes := []model.SystemChange{
				{
					Type:   "config_drift_memory",
					Detail: tc.detail,
					Domain: "memory",
					When:   now,
				},
			}

			facts := InjectConfigDriftEvidence(nil, changes, now)
			if len(facts) != 1 {
				t.Fatalf("expected 1 fact, got %d", len(facts))
			}
			f := facts[0]

			if f.Tags["key"] != tc.wantKey {
				t.Errorf("Tags[key] = %q, want %q", f.Tags["key"], tc.wantKey)
			}
			if f.Tags["old"] != tc.wantOld {
				t.Errorf("Tags[old] = %q, want exactly %q", f.Tags["old"], tc.wantOld)
			}
			if f.Tags["new"] != tc.wantNew {
				t.Errorf("Tags[new] = %q, want exactly %q", f.Tags["new"], tc.wantNew)
			}
		})
	}
}
