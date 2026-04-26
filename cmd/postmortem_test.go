package cmd

import (
	"testing"
	"time"

	"github.com/ftahirops/xtop/engine"
	"github.com/ftahirops/xtop/model"
)

// Tests the internal helpers that can be exercised without a real
// ~/.xtop/rca-history.jsonl file on disk.

func TestIdFor_IsStableAndHumanTypeable(t *testing.T) {
	r := &engine.RCAIncident{
		StartedAt: time.Date(2026, 3, 15, 14, 27, 0, 0, time.UTC),
		Signature: "cpu|runqlat_high,swap_churn,",
	}
	got := idFor(r)
	// Format: YYYYMMDD-HHMM-<8-char-signature-slug>.
	// "cpu|runqlat_high,swap_churn," → "cpu-runq" after | → -, comma-strip, and 8-char trim.
	want := "20260315-1427-cpu-runq"
	if got != want {
		t.Errorf("id = %q, want %q", got, want)
	}
}

func TestIdFor_EmptySignatureDegradesGracefully(t *testing.T) {
	r := &engine.RCAIncident{
		StartedAt: time.Date(2026, 1, 2, 3, 4, 0, 0, time.UTC),
	}
	got := idFor(r)
	if got != "20260102-0304-unknown" {
		t.Errorf("id = %q, want 20260102-0304-unknown", got)
	}
}

func TestFindIncident_AcceptsAtShorthand(t *testing.T) {
	records := []engine.RCAIncident{
		{StartedAt: time.Now().Add(-1 * time.Hour), Bottleneck: "cpu", Signature: "cpu|a,"},
		{StartedAt: time.Now().Add(-3 * time.Hour), Bottleneck: "memory", Signature: "mem|b,"},
	}
	// @1 → newest → cpu (records are already sorted newest first by caller)
	got, err := findIncident(records, "@1")
	if err != nil {
		t.Fatal(err)
	}
	if got.Bottleneck != "cpu" {
		t.Errorf("@1 = %q, want cpu", got.Bottleneck)
	}
	got2, err := findIncident(records, "@2")
	if err != nil {
		t.Fatal(err)
	}
	if got2.Bottleneck != "memory" {
		t.Errorf("@2 = %q, want memory", got2.Bottleneck)
	}

	// Out-of-range shorthand returns a clear error.
	if _, err := findIncident(records, "@99"); err == nil {
		t.Error("expected error for @99 with only 2 records")
	}
	// Garbage shorthand.
	if _, err := findIncident(records, "@abc"); err == nil {
		t.Error("expected error for @abc")
	}
}

func TestFindIncident_AcceptsIDPrefix(t *testing.T) {
	r := engine.RCAIncident{
		StartedAt: time.Date(2026, 3, 15, 14, 27, 0, 0, time.UTC),
		Signature: "cpu|runqlat_high,",
		Bottleneck: "cpu",
	}
	records := []engine.RCAIncident{r}
	full := idFor(&r)
	// Full match
	if got, err := findIncident(records, full); err != nil || got.Bottleneck != "cpu" {
		t.Errorf("full-id match failed: %v, %+v", err, got)
	}
	// Prefix match (first 13 chars → "20260315-1427")
	if got, err := findIncident(records, full[:13]); err != nil || got.Bottleneck != "cpu" {
		t.Errorf("prefix-id match failed: %v, %+v", err, got)
	}
}

func TestComputeRecordDiff_ProducesCoherentStats(t *testing.T) {
	target := &engine.RCAIncident{
		StartedAt:   time.Date(2026, 3, 15, 14, 0, 0, 0, time.UTC),
		PeakScore:   90,
		CulpritApp:  "mysql",
		Signature:   "cpu|runqlat_high,",
		EvidenceIDs: []string{"runqlat_high", "swap_churn"},
	}
	similar := []engine.RCAIncident{
		{StartedAt: time.Date(2026, 3, 14, 14, 0, 0, 0, time.UTC), PeakScore: 60, CulpritApp: "mysql",
			Signature: target.Signature, EvidenceIDs: []string{"runqlat_high"}, DurationSec: 30},
		{StartedAt: time.Date(2026, 3, 13, 14, 0, 0, 0, time.UTC), PeakScore: 65, CulpritApp: "mysql",
			Signature: target.Signature, EvidenceIDs: []string{"runqlat_high"}, DurationSec: 45},
		{StartedAt: time.Date(2026, 3, 12, 3, 0, 0, 0, time.UTC), PeakScore: 70, CulpritApp: "mysql",
			Signature: target.Signature, EvidenceIDs: []string{"runqlat_high"}, DurationSec: 40},
	}
	d := computeRecordDiff(target, similar)
	if d == nil {
		t.Fatal("expected non-nil diff")
	}
	if d.MatchCount != 3 {
		t.Errorf("MatchCount = %d, want 3", d.MatchCount)
	}
	if d.CurrentPeakScore != 90 || d.MedianPeakScore != 65 {
		t.Errorf("scores: current=%d median=%d; want 90/65", d.CurrentPeakScore, d.MedianPeakScore)
	}
	if d.ScoreDeltaFromMedian != 25 {
		t.Errorf("delta = %d, want 25", d.ScoreDeltaFromMedian)
	}
	if !d.CulpritIsRepeat || d.TopCulprit != "mysql" {
		t.Errorf("expected mysql as repeat culprit, got %+v", d)
	}
	// Two matches occurred at the same hour (14:00 UTC) → SameHourOfDay=2.
	if d.SameHourOfDay != 2 {
		t.Errorf("SameHourOfDay = %d, want 2", d.SameHourOfDay)
	}
	// swap_churn fires now but never in past incidents → NewEvidence.
	found := false
	for _, id := range d.NewEvidence {
		if id == "swap_churn" {
			found = true
		}
	}
	if !found {
		t.Errorf("swap_churn should appear in NewEvidence, got %v", d.NewEvidence)
	}
}

func TestSynthesizeResult_PopulatesMatcherInputs(t *testing.T) {
	r := &engine.RCAIncident{
		Bottleneck:  "io",
		PeakScore:   77,
		Confidence:  85,
		Culprit:     "mysqld",
		CulpritApp:  "mysql",
		EvidenceIDs: []string{"iowait_high", "wbstall"},
	}
	got := synthesizeResult(r)
	if got.PrimaryBottleneck != "io" || got.PrimaryAppName != "mysql" {
		t.Errorf("unexpected synthesis: %+v", got)
	}
	if got.Health != model.HealthDegraded {
		t.Errorf("health = %v, want Degraded", got.Health)
	}
	if len(got.RCA) != 1 || len(got.RCA[0].EvidenceV2) != 2 {
		t.Errorf("expected 2 evidence entries, got %+v", got.RCA)
	}
}

func TestFmtDurationShort(t *testing.T) {
	cases := map[int]string{
		0:    "—",
		45:   "45s",
		120:  "2m00s",
		3700: "1h01m",
	}
	for sec, want := range cases {
		if got := fmtDurationShort(sec); got != want {
			t.Errorf("fmtDurationShort(%d) = %q, want %q", sec, got, want)
		}
	}
}
