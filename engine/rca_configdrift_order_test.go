//go:build linux

package engine

import (
	"testing"

	"github.com/ftahirops/xtop/model"
)

// detectChanges must be callable and return an empty slice without panicking
// when the engine has no detectors configured (the common test path).
func TestDetectChangesNoDetectors(t *testing.T) {
	e := &Engine{} // no changeDetector / configDrift / paramDriftDetector
	got := e.detectChanges(&model.Snapshot{})
	if len(got) != 0 {
		t.Fatalf("expected no changes with no detectors, got %d", len(got))
	}
}
