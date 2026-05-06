package engine

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ftahirops/xtop/model"
)

func TestTraceArmer_NextSelfDisarms(t *testing.T) {
	dir := t.TempDir()
	a := &TraceArmer{dir: dir}
	a.mode.Store(int32(TraceModeNext))

	res := &model.AnalysisResult{
		Health:            model.HealthDegraded,
		PrimaryBottleneck: BottleneckIO,
		PrimaryScore:      55,
		Confidence:        80,
		RCA: []model.RCAEntry{{
			Bottleneck: BottleneckIO,
			Score:      55,
			EvidenceV2: []model.Evidence{
				makeEvidenceWithSustained("io.psi", 0.7, 0.9, true, "psi", 10),
				makeEvidenceWithSustained("io.dstate", 0.5, 0.8, true, "queue", 10),
			},
		}, {
			Bottleneck: BottleneckCPU,
			Score:      30,
		}},
	}

	a.MaybeDump(&model.Snapshot{}, nil, res, NewHistory(10, 3), nil)

	if a.Mode() != TraceModeOff {
		t.Errorf("after dump, mode = %v, want Off (self-disarm)", a.Mode())
	}

	files, _ := os.ReadDir(dir)
	if len(files) != 2 { // .json + .md
		t.Fatalf("expected 2 trace files, got %d", len(files))
	}
}

func TestTraceArmer_OffMeansNoDump(t *testing.T) {
	dir := t.TempDir()
	a := &TraceArmer{dir: dir}
	// mode left at default (Off)

	a.MaybeDump(&model.Snapshot{}, nil, &model.AnalysisResult{
		RCA: []model.RCAEntry{{Bottleneck: BottleneckIO, EvidenceV2: []model.Evidence{
			makeEvidenceWithSustained("io.psi", 0.7, 0.9, true, "psi", 10),
		}}},
	}, NewHistory(10, 3), nil)

	if files, _ := os.ReadDir(dir); len(files) != 0 {
		t.Errorf("Off mode must not write any files, got %d", len(files))
	}
}

func TestTraceArmer_ContentRoundtrip(t *testing.T) {
	dir := t.TempDir()
	a := &TraceArmer{dir: dir}
	a.mode.Store(int32(TraceModeNext))

	res := &model.AnalysisResult{
		Health:            model.HealthDegraded,
		PrimaryBottleneck: BottleneckIO,
		PrimaryScore:      55,
		Confidence:        80,
		RCA: []model.RCAEntry{{
			Bottleneck: BottleneckIO,
			Score:      55,
			EvidenceV2: []model.Evidence{
				makeEvidenceWithSustained("io.psi", 0.7, 0.9, true, "psi", 10),
				makeEvidenceWithSustained("io.dstate", 0.5, 0.8, true, "queue", 10),
			},
		}, {
			Bottleneck: BottleneckCPU,
			Score:      40,
		}},
	}
	a.MaybeDump(&model.Snapshot{}, nil, res, NewHistory(10, 3), nil)

	files, _ := os.ReadDir(dir)
	var jsonFile string
	for _, f := range files {
		if strings.HasSuffix(f.Name(), ".json") {
			jsonFile = filepath.Join(dir, f.Name())
		}
	}
	data, err := os.ReadFile(jsonFile)
	if err != nil {
		t.Fatalf("read trace json: %v", err)
	}
	var tf TraceFile
	if err := json.Unmarshal(data, &tf); err != nil {
		t.Fatalf("unmarshal trace: %v", err)
	}
	if tf.Schema != "xtop.trace.v1" {
		t.Errorf("schema = %q", tf.Schema)
	}
	if tf.Verdict.PrimaryBottleneck != BottleneckIO {
		t.Errorf("primary = %q", tf.Verdict.PrimaryBottleneck)
	}
	if !tf.GateAudit.V2TrustGatePassed {
		t.Errorf("v2 gate must pass for this fixture")
	}
	if !tf.GateAudit.ConfirmedTrustGatePassed {
		t.Errorf("confirmed gate must pass — sustained=10s")
	}
	if tf.GateAudit.RunnerUpDomain != BottleneckCPU {
		t.Errorf("runner-up = %q, want %q", tf.GateAudit.RunnerUpDomain, BottleneckCPU)
	}
	if tf.GateAudit.ScoreGapToRunnerUp != 15 {
		t.Errorf("score gap = %d, want 15", tf.GateAudit.ScoreGapToRunnerUp)
	}
}

func TestBuildGateAudit_FailureReason(t *testing.T) {
	// Two PSI items only — same weight category, fails diversity check.
	res := &model.AnalysisResult{
		PrimaryBottleneck: BottleneckCPU,
		RCA: []model.RCAEntry{{
			Bottleneck: BottleneckCPU,
			EvidenceV2: []model.Evidence{
				makeEvidenceWithSustained("cpu.psi", 0.8, 0.9, true, "psi", 30),
				makeEvidenceWithSustained("mem.psi", 0.7, 0.9, true, "psi", 30),
			},
		}},
	}
	a := buildGateAudit(res)
	if a.V2TrustGatePassed {
		t.Error("v2 gate should fail (single weight category)")
	}
	if !strings.Contains(a.V2TrustGateFailReason, "diversity") {
		t.Errorf("fail reason = %q, want diversity-related", a.V2TrustGateFailReason)
	}
}
