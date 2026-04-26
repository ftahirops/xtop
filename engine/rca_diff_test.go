package engine

import (
	"testing"
	"time"

	"github.com/ftahirops/xtop/model"
)

// mkResult is a tiny builder so each test case reads top-to-bottom: what's the
// situation, what do we expect in the diff.
func mkResult(bottleneck string, score int, culprit string, evIDs ...string) *model.AnalysisResult {
	ev := make([]model.Evidence, 0, len(evIDs))
	for _, id := range evIDs {
		ev = append(ev, model.Evidence{ID: id, Strength: 0.7})
	}
	return &model.AnalysisResult{
		Health:            model.HealthDegraded,
		PrimaryBottleneck: bottleneck,
		PrimaryScore:      score,
		PrimaryProcess:    culprit,
		RCA: []model.RCAEntry{{
			Bottleneck: bottleneck,
			EvidenceV2: ev,
		}},
	}
}

func mkRecorder(history []RCAIncident) *IncidentRecorder {
	r := &IncidentRecorder{
		path:           "/tmp/xtop-diff-test-nonexistent",
		maxKeep:        500,
		signatureIndex: make(map[string][]int),
		history:        history,
	}
	r.rebuildIndex()
	return r
}

func TestDiffAgainstHistory_NoPriorMatches(t *testing.T) {
	r := mkRecorder(nil)
	got := r.DiffAgainstHistory(mkResult("cpu", 80, "foo", "runqlat"))
	if got != nil {
		t.Fatalf("expected nil diff when history is empty, got %+v", got)
	}
}

func TestDiffAgainstHistory_RepeatCulprit(t *testing.T) {
	// Three prior incidents with the same signature, same culprit, similar score.
	sig := signatureFromResult(mkResult("cpu", 80, "x", "runqlat"))
	hist := []RCAIncident{
		{StartedAt: time.Now().Add(-72 * time.Hour), Bottleneck: "cpu", PeakScore: 78,
			Culprit: "mysqld", Signature: sig, EvidenceIDs: []string{"runqlat"}, DurationSec: 120},
		{StartedAt: time.Now().Add(-48 * time.Hour), Bottleneck: "cpu", PeakScore: 82,
			Culprit: "mysqld", Signature: sig, EvidenceIDs: []string{"runqlat"}, DurationSec: 140},
		{StartedAt: time.Now().Add(-24 * time.Hour), Bottleneck: "cpu", PeakScore: 80,
			Culprit: "mysqld", Signature: sig, EvidenceIDs: []string{"runqlat"}, DurationSec: 150},
	}
	r := mkRecorder(hist)

	// Current incident — same signature, same culprit, score normal.
	cur := mkResult("cpu", 80, "mysqld", "runqlat")
	diff := r.DiffAgainstHistory(cur)
	if diff == nil {
		t.Fatal("expected non-nil diff")
	}
	if diff.MatchCount != 3 {
		t.Errorf("MatchCount = %d, want 3", diff.MatchCount)
	}
	if !diff.CulpritIsRepeat {
		t.Error("expected CulpritIsRepeat=true for mysqld 3/3")
	}
	if diff.TopCulprit != "mysqld" || diff.TopCulpritCount != 3 {
		t.Errorf("top culprit = %s (%d), want mysqld (3)", diff.TopCulprit, diff.TopCulpritCount)
	}
	if diff.MedianPeakScore != 80 {
		t.Errorf("MedianPeakScore = %d, want 80", diff.MedianPeakScore)
	}
}

func TestDiffAgainstHistory_NewSignalFiring(t *testing.T) {
	// Past incidents fired "runqlat" only. Now runqlat + swap_churn fire:
	// the diff should flag swap_churn as a new signal.
	sig := signatureFromResult(mkResult("cpu", 80, "x", "runqlat"))
	hist := []RCAIncident{
		{StartedAt: time.Now().Add(-36 * time.Hour), Bottleneck: "cpu", PeakScore: 75,
			Culprit: "foo", Signature: sig, EvidenceIDs: []string{"runqlat"}, DurationSec: 60},
		{StartedAt: time.Now().Add(-12 * time.Hour), Bottleneck: "cpu", PeakScore: 78,
			Culprit: "foo", Signature: sig, EvidenceIDs: []string{"runqlat"}, DurationSec: 90},
	}
	r := mkRecorder(hist)

	// NOTE: signature is derived from evidence IDs, so to get a match we need
	// the current result to share at least one firing ID AND bottleneck. We
	// pick the SAME signature inputs so it matches, then the diff itself
	// operates on the full evidence union.
	cur := &model.AnalysisResult{
		Health:            model.HealthDegraded,
		PrimaryBottleneck: "cpu",
		PrimaryScore:      80,
		PrimaryProcess:    "foo",
		RCA: []model.RCAEntry{{
			Bottleneck: "cpu",
			EvidenceV2: []model.Evidence{
				{ID: "runqlat", Strength: 0.7},
				{ID: "swap_churn", Strength: 0.8},
			},
		}},
	}
	// Force matching signature by using the same id-set the history was
	// indexed under (signatureFromResult takes top 3 sorted).
	if signatureFromResult(cur) != sig {
		// Adjust: both share "runqlat" as the lowest sort-order ID, so top-3
		// of {runqlat, swap_churn} sorted is ["runqlat","swap_churn"]; sig
		// won't match history. For this test, we pre-set the history
		// signature to whatever cur produces so the match lookup succeeds.
		newSig := signatureFromResult(cur)
		for i := range hist {
			hist[i].Signature = newSig
		}
		r = mkRecorder(hist)
	}
	diff := r.DiffAgainstHistory(cur)
	if diff == nil {
		t.Fatal("expected non-nil diff")
	}
	found := false
	for _, id := range diff.NewEvidence {
		if id == "swap_churn" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected 'swap_churn' in NewEvidence, got %v", diff.NewEvidence)
	}
}

func TestDiffAgainstHistory_ScoreDelta(t *testing.T) {
	sig := signatureFromResult(mkResult("memory", 50, "x", "swap_churn"))
	hist := []RCAIncident{
		{StartedAt: time.Now().Add(-48 * time.Hour), Bottleneck: "memory", PeakScore: 50,
			Culprit: "x", Signature: sig, EvidenceIDs: []string{"swap_churn"}, DurationSec: 30},
		{StartedAt: time.Now().Add(-24 * time.Hour), Bottleneck: "memory", PeakScore: 55,
			Culprit: "x", Signature: sig, EvidenceIDs: []string{"swap_churn"}, DurationSec: 30},
	}
	r := mkRecorder(hist)
	cur := mkResult("memory", 90, "x", "swap_churn")
	diff := r.DiffAgainstHistory(cur)
	if diff == nil {
		t.Fatal("expected non-nil diff")
	}
	if diff.CurrentPeakScore != 90 {
		t.Errorf("CurrentPeakScore = %d, want 90", diff.CurrentPeakScore)
	}
	// median of [50,55] = 55, delta = 35
	if diff.ScoreDeltaFromMedian < 30 {
		t.Errorf("ScoreDeltaFromMedian = %d, want >= 30", diff.ScoreDeltaFromMedian)
	}
	if diff.DriftHint == "" {
		t.Error("expected non-empty DriftHint for a large score delta")
	}
}
