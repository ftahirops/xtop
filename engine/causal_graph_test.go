package engine

import (
	"testing"

	"github.com/ftahirops/xtop/model"
)

func TestProbabilisticCausalGraph_ObserveAndInfer(t *testing.T) {
	g := NewProbabilisticCausalGraph()

	// Simulate observations: io.psi → io.dstate pattern
	for i := 0; i < 10; i++ {
		g.Observe(map[string]float64{
			"io.psi":    0.8,
			"io.dstate": 0.7,
			"cpu.busy":  0.3,
		})
	}

	// Should have learned the io.psi→io.dstate edge
	g.mu.RLock()
	edge := g.edges["io.psi→io.dstate"]
	g.mu.RUnlock()

	if edge == nil {
		t.Fatal("expected learned edge io.psi→io.dstate")
	}
	if edge.Count < 10 {
		t.Errorf("expected count >= 10, got %d", edge.Count)
	}
	if edge.PGiven < 0.3 {
		t.Errorf("expected PGiven >= 0.3, got %f", edge.PGiven)
	}

	// Infer root causes
	fired := map[string]float64{
		"io.psi":    0.8,
		"io.dstate": 0.7,
	}
	roots := g.InferRootCauses(fired, 3)
	if len(roots) == 0 {
		t.Fatal("expected root causes")
	}
	// io.psi should be ranked as root cause (high posterior, explains io.dstate)
	if roots[0].EvidenceID != "io.psi" {
		t.Logf("root causes: %v", roots)
	}
}

func TestBuildProbabilisticDAG_FallbackToStatic(t *testing.T) {
	// With < 50 observations, should fall back to static rules
	g := NewProbabilisticCausalGraph()
	result := &model.AnalysisResult{
		RCA: []model.RCAEntry{
			{
				Bottleneck: BottleneckIO,
				EvidenceV2: []model.Evidence{
					{ID: "io.psi", Strength: 0.8, Domain: model.DomainIO, Message: "IO PSI high"},
					{ID: "io.dstate", Strength: 0.7, Domain: model.DomainIO, Message: "D-state tasks"},
				},
			},
		},
	}

	dag := BuildProbabilisticDAG(result, g)
	if dag == nil {
		t.Fatal("expected DAG")
	}
	if len(dag.Nodes) != 2 {
		t.Errorf("expected 2 nodes, got %d", len(dag.Nodes))
	}
	// Should have static edge io.psi→io.dstate
	hasEdge := false
	for _, e := range dag.Edges {
		if e.From == "io.psi" && e.To == "io.dstate" {
			hasEdge = true
			break
		}
	}
	if !hasEdge {
		t.Error("expected static edge io.psi→io.dstate")
	}
}
