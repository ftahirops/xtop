package engine

import (
	"testing"

	"github.com/ftahirops/xtop/collector"
)

// TestEngineStateIsolation asserts two Engine instances do NOT share
// RCA state. This is the contract NEXTGEN Phase 1 establishes:
// adaptive thresholds, causal graphs, and topology correlators are
// per-Engine, not package-globals.
func TestEngineStateIsolation(t *testing.T) {
	e1 := NewEngineMode(60, 3, collector.ModeLean)
	defer e1.Close()
	e2 := NewEngineMode(60, 3, collector.ModeLean)
	defer e2.Close()

	if e1.adaptiveThresholdDB == nil {
		t.Fatal("e1.adaptiveThresholdDB must be set by constructor")
	}
	if e2.adaptiveThresholdDB == nil {
		t.Fatal("e2.adaptiveThresholdDB must be set by constructor")
	}
	if e1.adaptiveThresholdDB == e2.adaptiveThresholdDB {
		t.Fatal("two engines must not share adaptiveThresholdDB")
	}
	if e1.probabilisticCausalGraph == nil {
		t.Fatal("e1.probabilisticCausalGraph must be set")
	}
	if e2.probabilisticCausalGraph == nil {
		t.Fatal("e2.probabilisticCausalGraph must be set")
	}
	if e1.probabilisticCausalGraph == e2.probabilisticCausalGraph {
		t.Fatal("two engines must not share probabilisticCausalGraph")
	}
	if e1.topologyCorrelator == nil {
		t.Fatal("e1.topologyCorrelator must be set")
	}
	if e2.topologyCorrelator == nil {
		t.Fatal("e2.topologyCorrelator must be set")
	}
	if e1.topologyCorrelator == e2.topologyCorrelator {
		t.Fatal("two engines must not share topologyCorrelator")
	}
}
