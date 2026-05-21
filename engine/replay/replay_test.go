package replay

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ftahirops/xtop/model"
)

// makeFrame builds a self-consistent IncidentFrame for testing.
func makeFrame(t *testing.T, dir string, name string, label model.LabelKind) string {
	t.Helper()
	now := time.Date(2026, 5, 12, 0, 0, 0, 0, time.UTC)
	g := model.NewEntityGraph()
	g.Add(model.Entity{ID: "host", Kind: model.EntityKindHost})
	g.Add(model.Entity{ID: "cgroup:/system.slice/mongod.service",
		Kind: model.EntityKindCgroup, OwnerID: "host"})

	frame := model.IncidentFrame{
		SchemaVersion: model.CurrentSchemaVersion,
		HostID:        "test-host",
		EngineVersion: "test",
		CapturedAt:    now,
		AnalysisTime:  now,
		Facts: []model.Fact{
			{
				ID: "cpu.psi.avg10", Domain: model.DomainCPU, Source: "procfs",
				EntityID: "cgroup:/system.slice/mongod.service",
				Metric:   "psi.avg10", Value: 65, Unit: "%",
				MeasuredAt: now, Severity: model.FactSeverityWarn,
				Confidence: 0.9, Duration: 12 * time.Second, BaselineDelta: 50,
				Kind: model.FactKindSaturation,
			},
			{
				ID: "cpu.busy", Domain: model.DomainCPU, Source: "procfs",
				EntityID: "cgroup:/system.slice/mongod.service",
				Metric:   "busy_pct", Value: 85, Unit: "%",
				MeasuredAt: now, Severity: model.FactSeverityWarn,
				Confidence: 0.85, Duration: 10 * time.Second, BaselineDelta: 40,
				Kind: model.FactKindSaturation,
			},
		},
		Entities: g,
		VerifiedCauses: []model.VerifiedCause{
			{
				Mechanism:    "CPU Contention in domain cpu (score=85)",
				Tier:         model.TierAConfirmed,
				RootEntityID: "cgroup:/system.slice/mongod.service",
				Confidence:   90,
				Gates: []model.GateResult{
					{GateID: "signal_quality", Passed: true,
						FactsUsed: []string{"cpu.psi.avg10", "cpu.busy"}},
					{GateID: "ownership_consistency", Passed: true,
						FactsUsed: []string{"cpu.psi.avg10", "cpu.busy"}},
					{GateID: "temporal_ordering", Passed: true,
						FactsUsed: []string{"cpu.psi.avg10"}},
					{GateID: "baseline_deviation", Passed: true,
						FactsUsed: []string{"cpu.psi.avg10"}},
					{GateID: "counter_evidence", Passed: true,
						FactsUsed: []string{"cpu.psi.avg10", "cpu.busy"}},
				},
				EvaluatedAt: now,
			},
		},
		HealthAtCapture: model.HealthCritical,
		Label:           label,
	}
	data, err := json.MarshalIndent(&frame, "", "  ")
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	return path
}

// TestLoadFrame_RoundtripDeterministic verifies that saving a frame
// and re-loading it preserves all fields needed by the replay harness.
func TestLoadFrame_RoundtripDeterministic(t *testing.T) {
	dir := t.TempDir()
	path := makeFrame(t, dir, "f1.json", model.LabelTruePositive)
	f, err := LoadFrame(path)
	if err != nil {
		t.Fatalf("LoadFrame: %v", err)
	}
	if f.SchemaVersion != model.CurrentSchemaVersion {
		t.Errorf("schema_version drift: got %d want %d", f.SchemaVersion, model.CurrentSchemaVersion)
	}
	if len(f.Facts) != 2 {
		t.Errorf("facts dropped: got %d", len(f.Facts))
	}
	if f.Entities == nil || f.Entities.Lookup("host") == nil {
		t.Error("entity graph not reindexed on load")
	}
	if f.Label != model.LabelTruePositive {
		t.Errorf("label drift: got %q", f.Label)
	}
}

// TestReplay_TierAStaysTierA proves the engine is deterministic on
// a known-good frame — replay reproduces the captured Tier A.
func TestReplay_TierAStaysTierA(t *testing.T) {
	dir := t.TempDir()
	path := makeFrame(t, dir, "f1.json", model.LabelTruePositive)
	f, err := LoadFrame(path)
	if err != nil {
		t.Fatalf("LoadFrame: %v", err)
	}
	r := Replay(f)
	if r.FlipFlops != 0 {
		t.Errorf("replay flipped tier on %d mechanisms; expected determinism", r.FlipFlops)
	}
	if len(r.Replayed) != 1 {
		t.Fatalf("expected 1 replayed cause; got %d", len(r.Replayed))
	}
	if r.Replayed[0].Tier != model.TierAConfirmed {
		t.Errorf("replayed tier=%s; want TierAConfirmed. gates=%+v",
			r.Replayed[0].Tier, r.Replayed[0].Gates)
	}
}

// TestLoadCorpus_ReadsAll asserts a directory of frames is loaded
// chronologically and bad files are reported (not silently skipped).
func TestLoadCorpus_ReadsAll(t *testing.T) {
	dir := t.TempDir()
	makeFrame(t, dir, "1.json", model.LabelTruePositive)
	makeFrame(t, dir, "2.json", model.LabelFalsePositive)
	makeFrame(t, dir, "3.json", model.LabelUnlabeled)
	// Bad file: present but unparseable.
	_ = os.WriteFile(filepath.Join(dir, "broken.json"), []byte("not-json"), 0o644)
	// Non-JSON file: skipped silently.
	_ = os.WriteFile(filepath.Join(dir, "readme.txt"), []byte("readme"), 0o644)
	// Temp file: skipped silently.
	_ = os.WriteFile(filepath.Join(dir, "9.json.tmp"), []byte("{}"), 0o644)

	frames, warnings, err := LoadCorpus(dir)
	if err != nil {
		t.Fatalf("LoadCorpus: %v", err)
	}
	if len(frames) != 3 {
		t.Errorf("loaded %d frames; want 3", len(frames))
	}
	if len(warnings) != 1 {
		t.Errorf("warnings=%v; want 1 for broken.json", warnings)
	}
}

// TestSummarizeCorpus computes per-mechanism precision over labeled frames.
func TestSummarizeCorpus(t *testing.T) {
	dir := t.TempDir()
	makeFrame(t, dir, "1.json", model.LabelTruePositive)
	makeFrame(t, dir, "2.json", model.LabelTruePositive)
	makeFrame(t, dir, "3.json", model.LabelFalsePositive)
	frames, _, _ := LoadCorpus(dir)
	sum := SummarizeCorpus(frames)
	if sum.Frames != 3 {
		t.Errorf("Frames=%d; want 3", sum.Frames)
	}
	if sum.LabeledFrames != 3 {
		t.Errorf("LabeledFrames=%d; want 3", sum.LabeledFrames)
	}
	// Each frame produces one mechanism: "CPU Contention in domain cpu (score=85)"
	// — 2 TPs + 1 FP. Precision = 2/3 = 0.666...
	for mech, st := range sum.PerMechanism {
		if st.TP != 2 || st.FP != 1 {
			t.Errorf("mechanism %q: TP=%d FP=%d; want 2/1", mech, st.TP, st.FP)
		}
		got := st.Precision()
		want := 2.0 / 3.0
		if got < want-0.001 || got > want+0.001 {
			t.Errorf("mechanism %q: precision=%g; want %g", mech, got, want)
		}
	}
}
