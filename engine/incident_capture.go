package engine

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/ftahirops/xtop/model"
)

// incidentCorpus is the per-engine writer that captures non-OK ticks
// to disk for offline replay. Writes are best-effort — a failed write
// is logged but never affects the tick.
//
// NEXTGEN Phase 5: the corpus is the substrate for the precision
// program. Once labeled by operators, it gives us the per-mechanism
// false-positive rate the 0.1% target requires.
type incidentCorpus struct {
	mu      sync.Mutex
	dir     string // resolved absolute path; empty if disabled
	written int    // total frames captured this process lifetime
	// dedup: don't write more than one frame per analyzed-second
	// (the engine ticks faster than that and would otherwise spam
	// the corpus with near-identical frames).
	lastWriteAt time.Time
}

// newIncidentCorpus initializes the capture path. dir is the parent
// (~/.xtop/incidents). If creation fails, capture becomes a no-op —
// the engine never panics on filesystem trouble.
func newIncidentCorpus(dir string) *incidentCorpus {
	if dir == "" {
		return &incidentCorpus{}
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return &incidentCorpus{}
	}
	return &incidentCorpus{dir: dir}
}

// capture writes an IncidentFrame if the result is non-OK and we
// haven't already written one this second. Best-effort — never returns
// an error to the tick path.
//
// What triggers a write:
//   - result is non-nil
//   - result.Health is NOT HealthOK (something fired)
//   - at least 1 second since the last write (dedup)
//   - any VerifiedCause has Tier A/B/C (worth saving for replay) —
//     pure Tier D abstain alone is too noisy to corpus today
//
// Future Phase 5 follow-up: capture ALL non-OK frames once disk
// rotation + size cap are in place.
func (c *incidentCorpus) capture(snap *model.Snapshot, result *model.AnalysisResult, engineVersion string) {
	if c == nil || c.dir == "" || result == nil || snap == nil {
		return
	}
	if result.Health == model.HealthOK {
		return
	}
	if !c.hasWorthwhileVerifiedCause(result) {
		return
	}
	c.mu.Lock()
	if time.Since(c.lastWriteAt) < time.Second {
		c.mu.Unlock()
		return
	}
	c.lastWriteAt = time.Now()
	c.written++
	c.mu.Unlock()

	frame := model.IncidentFrame{
		SchemaVersion:     model.CurrentSchemaVersion,
		HostID:            snap.HostID,
		EngineVersion:     engineVersion,
		CapturedAt:        time.Now(),
		AnalysisTime:      snap.Timestamp,
		Facts:             result.Facts,
		Entities:          result.Entities,
		VerifiedCauses:    result.VerifiedCauses,
		HealthAtCapture:   result.Health,
		PrimaryBottleneck: result.PrimaryBottleneck,
		PrimaryScore:      result.PrimaryScore,
	}
	c.writeFrame(frame)
}

func (c *incidentCorpus) hasWorthwhileVerifiedCause(r *model.AnalysisResult) bool {
	for _, vc := range r.VerifiedCauses {
		switch vc.Tier {
		case model.TierAConfirmed, model.TierBVerified, model.TierCProbable:
			return true
		}
	}
	return false
}

func (c *incidentCorpus) writeFrame(frame model.IncidentFrame) {
	// Filename uses unix-nanos so chronological order = lexicographic.
	name := fmt.Sprintf("%d.json", frame.CapturedAt.UnixNano())
	path := filepath.Join(c.dir, name)
	data, err := json.MarshalIndent(&frame, "", "  ")
	if err != nil {
		return
	}
	// Atomic write: temp + rename. The corpus must never contain
	// half-written files (the replay harness would crash on them).
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return
	}
	_ = os.Rename(tmp, path)
}

// IncidentCorpusStats reports how many frames this engine has captured.
// Useful for operators wanting to know "is xtop building me a corpus?".
type IncidentCorpusStats struct {
	Dir         string `json:"dir"`
	WrittenLife int    `json:"written_lifetime"`
}

// CorpusStats returns the current capture stats.
func (e *Engine) CorpusStats() IncidentCorpusStats {
	if e.corpus == nil {
		return IncidentCorpusStats{}
	}
	e.corpus.mu.Lock()
	defer e.corpus.mu.Unlock()
	return IncidentCorpusStats{Dir: e.corpus.dir, WrittenLife: e.corpus.written}
}
