// Package replay is the offline RCA harness — load an IncidentFrame
// from disk, re-feed its facts + entity graph to the verifier, and
// compare the fresh output against the captured output.
//
// This is the substrate of NEXTGEN's precision program (§7). Without
// it, every "we caught 99.9% of incidents" claim is unfalsifiable.
// With it, an operator can:
//
//  1. label the captured corpus (TP / FP / TN / FN)
//  2. run the harness across all labeled frames
//  3. compute per-mechanism precision (TP / (TP + FP))
//  4. set release gates: "no commit that drops Tier A precision
//     below 99.0% per mechanism may merge"
//
// Phase 5 ships the harness. The labeling UI + corpus management are
// follow-up tooling that builds on these primitives.

package replay

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/ftahirops/xtop/engine/verifier"
	"github.com/ftahirops/xtop/model"
)

// LoadFrame reads a single IncidentFrame from disk. Rejects frames
// from a future schema version (operator must upgrade xtop) and
// rebuilds the entity-graph byID index after deserialization.
func LoadFrame(path string) (*model.IncidentFrame, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read frame: %w", err)
	}
	var f model.IncidentFrame
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, fmt.Errorf("parse frame: %w", err)
	}
	if f.SchemaVersion > model.CurrentSchemaVersion {
		return nil, fmt.Errorf("frame schema_version=%d exceeds engine support=%d — upgrade xtop",
			f.SchemaVersion, model.CurrentSchemaVersion)
	}
	if f.Entities != nil {
		f.Entities.Reindex()
	}
	return &f, nil
}

// LoadCorpus reads every *.json file in dir as an IncidentFrame.
// Files that fail to parse are skipped with a warning string in the
// returned slice (one entry per error).
func LoadCorpus(dir string) ([]*model.IncidentFrame, []string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, nil, fmt.Errorf("read dir: %w", err)
	}
	var frames []*model.IncidentFrame
	var warnings []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !strings.HasSuffix(name, ".json") || strings.HasSuffix(name, ".tmp") {
			continue
		}
		path := filepath.Join(dir, name)
		f, err := LoadFrame(path)
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("%s: %v", name, err))
			continue
		}
		frames = append(frames, f)
	}
	// Chronological order by AnalysisTime for deterministic output.
	sort.SliceStable(frames, func(i, j int) bool {
		return frames[i].AnalysisTime.Before(frames[j].AnalysisTime)
	})
	return frames, warnings, nil
}

// ReplayResult is the per-frame harness output.
type ReplayResult struct {
	FrameFile string

	// Original is what the engine emitted at capture time.
	Original []model.VerifiedCause

	// Replayed is what the verifier emits NOW on the same inputs.
	Replayed []model.VerifiedCause

	// TierMatch reports per-mechanism whether the replayed tier
	// equals the original tier. true → deterministic, the engine
	// has not drifted; false → behavior changed since capture.
	TierMatch map[string]bool

	// FlipFlops counts mechanisms whose tier CHANGED between
	// capture and replay. Sentinel for engine non-determinism or
	// behavioral regression.
	FlipFlops int
}

// Replay re-runs the configured verifier against the frame's stored
// facts + entity graph. Returns a ReplayResult comparing original
// versus fresh output. Uses verifier.Default() — to test a custom
// gate set, build your own Verifier and call its Verify method
// directly on each candidate derived from the frame.
//
// Determinism contract: with verifier.Default() AND no engine code
// changes since the frame was captured, Replayed MUST equal Original
// tier-for-tier. Any divergence is reported in FlipFlops.
func Replay(frame *model.IncidentFrame) *ReplayResult {
	if frame == nil {
		return &ReplayResult{}
	}
	v := verifier.Default()

	// Derive candidates from the ORIGINAL VerifiedCauses — each
	// original cause becomes one candidate, with the same
	// supporting fact IDs it used at capture. We can't reconstruct
	// the AffectedEntityIDs without the hypothesis engine, so
	// blast-radius gate (when it lands) replays with empty
	// affected-list — appropriate for today's gate set.
	replayed := make([]model.VerifiedCause, 0, len(frame.VerifiedCauses))
	tierMatch := make(map[string]bool, len(frame.VerifiedCauses))
	flipFlops := 0
	for _, orig := range frame.VerifiedCauses {
		c := verifier.Candidate{
			Mechanism:         orig.Mechanism,
			RootEntityID:      orig.RootEntityID,
			Domain:            domainFromMechanism(orig.Mechanism),
			SupportingFactIDs: factIDsFromOriginalGates(orig),
		}
		fresh := v.Verify(c, frame.Facts, frame.Entities)
		replayed = append(replayed, fresh)

		matched := fresh.Tier == orig.Tier
		tierMatch[orig.Mechanism] = matched
		if !matched {
			flipFlops++
		}
	}
	return &ReplayResult{
		Original:  frame.VerifiedCauses,
		Replayed:  replayed,
		TierMatch: tierMatch,
		FlipFlops: flipFlops,
	}
}

// CorpusSummary is the per-mechanism precision rollup over a labeled
// corpus. Computed by SummarizeCorpus.
type CorpusSummary struct {
	// Frames is the total number of frames analyzed.
	Frames int

	// LabeledFrames is the subset that had an operator-provided Label.
	LabeledFrames int

	// PerMechanism maps mechanism → its TP/FP/FN counts. Precision is
	// TP/(TP+FP); recall is TP/(TP+FN).
	PerMechanism map[string]*MechanismStats

	// FlipFlops is the total count of mechanisms whose tier changed
	// between capture and replay across the entire corpus.
	FlipFlops int
}

// MechanismStats is one mechanism's count breakdown.
type MechanismStats struct {
	TP, FP, FN, TN int
	// AvgTier is the average tier rank for replayed outputs
	// (A=4, B=3, C=2, D=1, unknown=0).
	AvgTierRank float64
}

// Precision returns TP / (TP + FP), or 0 if no positives ever observed.
func (m *MechanismStats) Precision() float64 {
	denom := m.TP + m.FP
	if denom == 0 {
		return 0
	}
	return float64(m.TP) / float64(denom)
}

// Recall returns TP / (TP + FN), or 0 if no actuals ever observed.
func (m *MechanismStats) Recall() float64 {
	denom := m.TP + m.FN
	if denom == 0 {
		return 0
	}
	return float64(m.TP) / float64(denom)
}

// SummarizeCorpus aggregates replay results across a labeled corpus.
// Frames without a Label contribute to FlipFlops + tier rank but not
// to precision/recall (we don't know the ground truth).
func SummarizeCorpus(frames []*model.IncidentFrame) *CorpusSummary {
	sum := &CorpusSummary{
		PerMechanism: map[string]*MechanismStats{},
	}
	tierRankSum := map[string]float64{}
	tierRankN := map[string]int{}
	for _, f := range frames {
		sum.Frames++
		if f.Label != model.LabelUnlabeled {
			sum.LabeledFrames++
		}
		r := Replay(f)
		sum.FlipFlops += r.FlipFlops
		for i, vc := range r.Replayed {
			mech := vc.Mechanism
			st := sum.PerMechanism[mech]
			if st == nil {
				st = &MechanismStats{}
				sum.PerMechanism[mech] = st
			}
			tierRankSum[mech] += tierRank(vc.Tier)
			tierRankN[mech]++
			// Use the frame's label as ground truth.
			switch f.Label {
			case model.LabelTruePositive:
				st.TP++
			case model.LabelFalsePositive:
				st.FP++
			case model.LabelFalseNegative:
				st.FN++
			case model.LabelTrueNegative:
				st.TN++
			}
			_ = i // silence unused if loop body simplifies later
		}
	}
	for mech, st := range sum.PerMechanism {
		if n := tierRankN[mech]; n > 0 {
			st.AvgTierRank = tierRankSum[mech] / float64(n)
		}
	}
	return sum
}

func tierRank(t model.VerificationTier) float64 {
	switch t {
	case model.TierAConfirmed:
		return 4
	case model.TierBVerified:
		return 3
	case model.TierCProbable:
		return 2
	case model.TierDInconclusive:
		return 1
	}
	return 0
}

// domainFromMechanism is a heuristic — captured Candidates didn't
// store Domain explicitly. We infer it from the mechanism string the
// AnalyzeRCA pipeline produced. Fragile, but the only option until
// we extend the on-disk schema.
func domainFromMechanism(m string) model.Domain {
	lower := strings.ToLower(m)
	switch {
	case strings.Contains(lower, "cpu"):
		return model.DomainCPU
	case strings.Contains(lower, "memory"), strings.Contains(lower, "mem "), strings.Contains(lower, "swap"):
		return model.DomainMemory
	case strings.Contains(lower, "io"), strings.Contains(lower, "disk"):
		return model.DomainIO
	case strings.Contains(lower, "network"), strings.Contains(lower, "net"):
		return model.DomainNetwork
	}
	return ""
}

// factIDsFromOriginalGates extracts the FactsUsed lists from a
// VerifiedCause's gate audit. Returns deduplicated, deterministically-
// sorted IDs.
func factIDsFromOriginalGates(vc model.VerifiedCause) []string {
	seen := map[string]bool{}
	for _, g := range vc.Gates {
		for _, id := range g.FactsUsed {
			seen[id] = true
		}
	}
	out := make([]string, 0, len(seen))
	for id := range seen {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}
