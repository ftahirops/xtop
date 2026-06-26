package engine

import (
	"testing"
	"time"

	"github.com/ftahirops/xtop/collector/journal"
	"github.com/ftahirops/xtop/model"
)

func makeGraph(ids ...string) *model.EntityGraph {
	g := model.NewEntityGraph()
	for _, id := range ids {
		g.Add(model.Entity{ID: id, Kind: model.EntityKindService})
	}
	return g
}

func TestInjectJournalEvidence_CrashRestartLoop(t *testing.T) {
	now := time.Now()
	svcID := "service:nginx"
	graph := makeGraph(svcID)

	findings := []journal.JournalFinding{
		{
			Signature: "crash_restart_loop",
			Severity:  model.DiagCrit,
			Count:     5,
			Sample:    "main process exited, code=exited, status=1/FAILURE",
			PID:       1234,
			FirstSeen: now.Add(-10 * time.Minute),
			LastSeen:  now,
		},
	}

	facts := InjectJournalEvidence(graph, svcID, findings, now)

	if len(facts) != 1 {
		t.Fatalf("expected 1 fact, got %d", len(facts))
	}
	f := facts[0]

	if f.Kind != model.FactKindLogEvidence {
		t.Errorf("Kind = %q, want %q", f.Kind, model.FactKindLogEvidence)
	}
	if f.Source != "journald" {
		t.Errorf("Source = %q, want %q", f.Source, "journald")
	}
	if f.EntityID != svcID {
		t.Errorf("EntityID = %q, want %q", f.EntityID, svcID)
	}
	if f.Value != float64(5) {
		t.Errorf("Value = %v, want 5", f.Value)
	}
	if f.Confidence < 0.85 {
		t.Errorf("Confidence = %v, expected high (>=0.85) for crash_restart_loop", f.Confidence)
	}
	if f.Severity != model.FactSeverityCrit {
		t.Errorf("Severity = %q, want %q", f.Severity, model.FactSeverityCrit)
	}
	if f.Tags["signature"] != "crash_restart_loop" {
		t.Errorf("Tags[signature] = %q, want crash_restart_loop", f.Tags["signature"])
	}
}

func TestInjectJournalEvidence_ErrorRateSpike_LowerConfidence(t *testing.T) {
	now := time.Now()
	svcID := "service:mysql"
	graph := makeGraph(svcID)

	findings := []journal.JournalFinding{
		{
			Signature: "error_rate_spike",
			Severity:  model.DiagWarn,
			Count:     42,
			Sample:    "high priority error rate",
			LastSeen:  now,
		},
	}

	facts := InjectJournalEvidence(graph, svcID, findings, now)

	if len(facts) != 1 {
		t.Fatalf("expected 1 fact, got %d", len(facts))
	}
	f := facts[0]

	// error_rate_spike is INTERPRETED — confidence should be low (~0.4)
	if f.Confidence >= 0.6 {
		t.Errorf("Confidence = %v, expected interpreted (< 0.6) for error_rate_spike", f.Confidence)
	}
	if f.Kind != model.FactKindLogEvidence {
		t.Errorf("Kind = %q, want %q", f.Kind, model.FactKindLogEvidence)
	}
}

func TestInjectJournalEvidence_EntityNotInGraph_FallsBackToHost(t *testing.T) {
	now := time.Now()
	svcID := "service:unknown-svc"
	// Graph does NOT contain svcID.
	graph := makeGraph("service:other")

	findings := []journal.JournalFinding{
		{
			Signature: "oom_killed",
			Severity:  model.DiagCrit,
			Count:     1,
			Sample:    "oom-kill event",
			LastSeen:  now,
		},
	}

	facts := InjectJournalEvidence(graph, svcID, findings, now)

	// Must still produce a fact (not silently dropped).
	if len(facts) != 1 {
		t.Fatalf("expected 1 fact (host fallback), got %d", len(facts))
	}
	f := facts[0]
	if f.Kind != model.FactKindLogEvidence {
		t.Errorf("Kind = %q, want %q", f.Kind, model.FactKindLogEvidence)
	}
	// EntityID should be "host" as fallback.
	if f.EntityID != "host" {
		t.Errorf("EntityID = %q, want \"host\" for fallback", f.EntityID)
	}
}

func TestInjectJournalEvidence_NilGraph(t *testing.T) {
	now := time.Now()
	svcID := "service:redis"

	findings := []journal.JournalFinding{
		{
			Signature: "dependency_failure",
			Severity:  model.DiagWarn,
			Count:     3,
			Sample:    "connection refused",
			LastSeen:  now,
		},
	}

	// nil graph — should not panic; entity ID should be used as-is.
	facts := InjectJournalEvidence(nil, svcID, findings, now)

	if len(facts) != 1 {
		t.Fatalf("expected 1 fact, got %d", len(facts))
	}
	f := facts[0]
	if f.Kind != model.FactKindLogEvidence {
		t.Errorf("Kind = %q, want %q", f.Kind, model.FactKindLogEvidence)
	}
}
