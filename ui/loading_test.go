package ui

import (
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
)

// ---------------------------------------------------------------------------
// Task 6.5: Loading-state spinner tests
// ---------------------------------------------------------------------------

// TestRenderLoadingState_ContainsSpinnerAndElapsed checks that renderLoadingState
// produces output with a spinner frame and the elapsed-seconds counter.
// We inject a fixed startTime so the test is deterministic.
func TestRenderLoadingState_ContainsSpinnerAndElapsed(t *testing.T) {
	startTime := time.Now().Add(-5 * time.Second) // fake 5 seconds ago
	out := renderLoadingState(3, startTime)

	// Should contain a spinner frame (braille character from the set)
	hasFrame := false
	for _, f := range spinnerFrames {
		if strings.Contains(out, f) {
			hasFrame = true
			break
		}
	}
	if !hasFrame {
		t.Errorf("renderLoadingState: expected a spinner frame from %v, got %q", spinnerFrames, out)
	}

	// Should contain the collecting text
	if !strings.Contains(out, "Collecting") {
		t.Errorf("renderLoadingState: expected 'Collecting' in output, got %q", out)
	}

	// Should contain an elapsed time in seconds (format: "(Ns)")
	if !strings.Contains(out, "s)") {
		t.Errorf("renderLoadingState: expected elapsed seconds '(Ns)' in output, got %q", out)
	}
}

// TestRenderLoadingState_SpinnerCycles checks that different spinnerIdx values
// produce different frames (i.e. the spinner actually cycles).
func TestRenderLoadingState_SpinnerCycles(t *testing.T) {
	start := time.Now()
	out0 := renderLoadingState(0, start)
	out1 := renderLoadingState(1, start)
	if out0 == out1 {
		t.Errorf("expected different frames for spinnerIdx 0 and 1, both got %q", out0)
	}
	// Frame at index 0 should match spinnerFrames[0]
	if !strings.HasPrefix(out0, spinnerFrames[0]) {
		t.Errorf("spinnerIdx=0 should start with %q, got %q", spinnerFrames[0], out0)
	}
}

// TestFirstSampleView_ShowsLoadingState verifies that View() returns the loading
// indicator when m.snap == nil, including after a WindowSizeMsg.
func TestFirstSampleView_ShowsLoadingState(t *testing.T) {
	m := Model{
		// snap is nil (zero value) — pre-first-sample state
		startTime:  time.Now().Add(-2 * time.Second),
		spinnerIdx: 2,
		width:      80,
		height:     24,
	}

	// Process a WindowSizeMsg so width/height are set (View checks width != 0)
	updated, _ := m.Update(tea.WindowSizeMsg{Width: 80, Height: 24})
	view := updated.(Model).View()

	if !strings.Contains(view, "Collecting") {
		t.Errorf("View() pre-first-sample: expected 'Collecting', got %q", view)
	}
	hasFrame := false
	for _, f := range spinnerFrames {
		if strings.Contains(view, f) {
			hasFrame = true
			break
		}
	}
	if !hasFrame {
		t.Errorf("View() pre-first-sample: expected spinner frame, got %q", view)
	}
}

// TestSpinnerTickMsg_AdvancesIndex checks that handling spinnerTickMsg advances
// spinnerIdx, and re-schedules the ticker only while snap == nil.
func TestSpinnerTickMsg_AdvancesIndex(t *testing.T) {
	m := Model{
		startTime:  time.Now(),
		spinnerIdx: 5,
		width:      80,
		height:     24,
		// snap remains nil
	}

	updated, cmd := m.Update(spinnerTickMsg{})
	newModel := updated.(Model)

	// Index should have advanced
	if newModel.spinnerIdx != 6 {
		t.Errorf("spinnerIdx after spinnerTickMsg: got %d, want 6", newModel.spinnerIdx)
	}
	// A cmd should be returned (re-schedule) while snap == nil
	if cmd == nil {
		t.Error("expected non-nil cmd (re-schedule) when snap == nil, got nil")
	}
}

// TestSpinnerTickMsg_StopsAfterFirstSnapshot checks that spinnerTickMsg returns
// nil cmd once m.snap is set (no runaway ticker).
func TestSpinnerTickMsg_StopsAfterFirstSnapshot(t *testing.T) {
	m := Model{
		startTime:  time.Now(),
		spinnerIdx: 3,
		snap:       testSnapshot(), // first snapshot has arrived
		width:      80,
		height:     24,
	}

	_, cmd := m.Update(spinnerTickMsg{})
	if cmd != nil {
		t.Error("expected nil cmd (no re-schedule) when snap != nil, got non-nil cmd")
	}
}
