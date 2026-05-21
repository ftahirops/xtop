// Incident frame — NEXTGEN Phase 5 replay primitive.
//
// Per NEXTGEN_RCA_ARCHITECTURE.md §6: "every incident frame must be
// re-runnable offline". This file defines the minimum the engine
// must persist per incident for that to be possible.
//
// What an IncidentFrame is:
//
//   - the EXACT inputs the verifier saw (facts + entity graph)
//   - the EXACT outputs it produced (VerifiedCauses + each gate's
//     verdict)
//   - metadata for indexing (host, timestamp, engine version)
//
// What it intentionally is NOT:
//
//   - a full snapshot of every collector's output (too big, mostly
//     irrelevant once facts have been distilled)
//   - the post-RCA narrative or UI rendering (derived; replay
//     reconstructs)
//
// The Phase 5 contract: feeding an IncidentFrame back through the
// engine's verifier MUST produce byte-identical VerifiedCauses. If
// it doesn't, the engine is non-deterministic and the 0.1% precision
// claim is unfounded.

package model

import "time"

// IncidentFrame is the persisted, replayable record of one analysis
// tick that produced a non-OK verdict. Stored as one JSON object per
// file in ~/.xtop/incidents/<unix_nano>.json.
//
// Schema version is embedded so future format changes are detectable;
// older frames can be rejected by an upgraded engine cleanly.
type IncidentFrame struct {
	// SchemaVersion is the on-disk format version. v1 = the initial
	// Phase 5 ship. Bumped on breaking changes.
	SchemaVersion int `json:"schema_version"`

	// HostID is the host this incident occurred on (snap.HostID).
	HostID string `json:"host_id,omitempty"`

	// EngineVersion is the xtop version that produced this frame.
	// Replays produced by a different version are flagged in the
	// harness output.
	EngineVersion string `json:"engine_version,omitempty"`

	// CapturedAt is wall-clock time when this frame was written. Used
	// for chronological ordering of the corpus, NOT as part of the
	// determinism contract (replay doesn't depend on this).
	CapturedAt time.Time `json:"captured_at"`

	// AnalysisTime is the snap.Timestamp the verifier saw. Replay
	// MUST use this — most facts are wall-clock relative.
	AnalysisTime time.Time `json:"analysis_time"`

	// Facts is the exact Fact slice the verifier received. Lossless
	// JSON roundtrip is enforced by TestFactJSONRoundtrip.
	Facts []Fact `json:"facts"`

	// Entities is the exact entity graph snapshot. The byID index is
	// rebuilt via Reindex() after deserialization.
	Entities *EntityGraph `json:"entities"`

	// VerifiedCauses is what the verifier emitted at capture time.
	// Replay compares fresh output against this for determinism.
	VerifiedCauses []VerifiedCause `json:"verified_causes"`

	// HealthAtCapture is the headline AnalysisResult.Health value at
	// capture time. Used to filter the corpus ("show me all the
	// frames where xtop said Critical").
	HealthAtCapture HealthLevel `json:"health_at_capture"`

	// PrimaryBottleneck and PrimaryScore preserve the legacy verdict
	// for cross-referencing with the audit trail. Phase 4 verdicts
	// (VerifiedCauses) supersede these, but the legacy field is what
	// goes into incident notifications + the fleet hub, so it must
	// be in the corpus.
	PrimaryBottleneck string `json:"primary_bottleneck,omitempty"`
	PrimaryScore      int    `json:"primary_score,omitempty"`

	// Label is operator-provided ground truth ("was this a real
	// incident, and did the engine call it correctly?"). Empty when
	// unlabeled. Used by the replay harness to compute precision per
	// mechanism. See LabelKind for the enum.
	Label LabelKind `json:"label,omitempty"`

	// LabelReason is the operator's free-text note explaining the
	// label. Optional but recommended for FN cases ("real incident
	// the engine missed because X").
	LabelReason string `json:"label_reason,omitempty"`
}

// LabelKind is the operator's ground-truth verdict on an IncidentFrame.
// Used to compute precision (TP / (TP+FP)) and recall (TP / (TP+FN))
// per mechanism over the corpus.
type LabelKind string

const (
	// LabelUnlabeled is the default — operator hasn't reviewed yet.
	LabelUnlabeled LabelKind = ""

	// LabelTruePositive: engine called X, X really was happening.
	LabelTruePositive LabelKind = "TP"

	// LabelFalsePositive: engine called X, X was NOT happening.
	// These are what the 0.1% target measures.
	LabelFalsePositive LabelKind = "FP"

	// LabelTrueNegative: engine abstained (Tier D or OK), nothing
	// was wrong. Rarely interesting per-incident — the corpus only
	// captures non-OK ticks — but included for completeness.
	LabelTrueNegative LabelKind = "TN"

	// LabelFalseNegative: engine missed a real incident. Operators
	// add these manually when xtop didn't catch something but should
	// have. Recall metric depends on FN counts.
	LabelFalseNegative LabelKind = "FN"
)

// CurrentSchemaVersion is the on-disk schema version this engine
// writes. Frames with a higher version are rejected by the replay
// harness (operator must upgrade); lower versions can be migrated.
const CurrentSchemaVersion = 1
