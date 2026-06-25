package collector

import (
	"testing"
)

// TestPruneHistory verifies that stale service history is removed
// while tracked service history is preserved.
func TestPruneHistory(t *testing.T) {
	l := &LogsCollector{
		history: make(map[string]*logHistory),
	}

	// Seed history with a tracked unit and a stale unit
	trackedUnit := "nginx.service"
	staleUnit := "apache2.service"

	l.history[trackedUnit] = &logHistory{
		totalErrors: 10,
		totalWarns:  5,
		lastError:   "nginx error",
		ringBuf:     make([]float64, 60),
	}

	l.history[staleUnit] = &logHistory{
		totalErrors: 20,
		totalWarns:  10,
		lastError:   "apache error",
		ringBuf:     make([]float64, 60),
	}

	// Set trackedUnits to only include the tracked one
	l.trackedUnits = []string{trackedUnit}

	// Call pruneHistory
	l.pruneHistory()

	// Assert that the tracked unit is preserved
	if _, ok := l.history[trackedUnit]; !ok {
		t.Errorf("tracked unit %q was unexpectedly removed from history", trackedUnit)
	}

	// Assert that the stale unit was removed
	if _, ok := l.history[staleUnit]; ok {
		t.Errorf("stale unit %q was not removed from history", staleUnit)
	}
}

// TestPruneHistoryWithNilHistory tests that pruneHistory handles nil history gracefully.
func TestPruneHistoryWithNilHistory(t *testing.T) {
	l := &LogsCollector{
		history: nil,
	}

	l.trackedUnits = []string{"nginx.service"}

	// Should not panic
	l.pruneHistory()

	// history should still be nil
	if l.history != nil {
		t.Errorf("expected history to remain nil, got %v", l.history)
	}
}

// TestPruneHistoryEmptyTrackedUnits tests that all history is removed
// when there are no tracked units.
func TestPruneHistoryEmptyTrackedUnits(t *testing.T) {
	l := &LogsCollector{
		history: make(map[string]*logHistory),
	}

	// Seed history with some units
	l.history["nginx.service"] = &logHistory{ringBuf: make([]float64, 60)}
	l.history["apache2.service"] = &logHistory{ringBuf: make([]float64, 60)}

	// No tracked units
	l.trackedUnits = []string{}

	// Call pruneHistory
	l.pruneHistory()

	// Assert that all history was removed
	if len(l.history) != 0 {
		t.Errorf("expected all history to be removed, got %d entries", len(l.history))
	}
}
