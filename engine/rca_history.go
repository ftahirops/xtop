package engine

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/ftahirops/xtop/model"
)

// RCAIncident is a recorded past incident for learning.
type RCAIncident struct {
	StartedAt      time.Time `json:"started_at"`
	EndedAt        time.Time `json:"ended_at,omitempty"`
	DurationSec    int       `json:"duration_sec"`
	Bottleneck     string    `json:"bottleneck"`
	Pattern        string    `json:"pattern,omitempty"`
	PeakScore      int       `json:"peak_score"`
	Confidence     int       `json:"confidence"`
	Culprit        string    `json:"culprit,omitempty"`
	CulpritApp     string    `json:"culprit_app,omitempty"`
	RootCause      string    `json:"root_cause,omitempty"`
	Evidence       []string  `json:"evidence,omitempty"`

	// EvidenceIDs are the firing evidence IDs at incident peak — used by
	// DiffAgainstHistory to compute which signals are new or missing this
	// time around. Older history files may lack this field; diff gracefully
	// degrades to using the narrative Evidence strings instead.
	EvidenceIDs []string `json:"evidence_ids,omitempty"`

	// Signature for similarity matching — stable hash of firing evidence IDs
	Signature string `json:"signature"`

	// Resolution — set if we detected how the incident ended
	Resolution string `json:"resolution,omitempty"` // "auto-recovered", "sustained", "escalated"
}

// IncidentRecorder tracks ongoing incidents and persists completed ones to disk.
type IncidentRecorder struct {
	mu       sync.RWMutex
	active   *RCAIncident         // current incident, nil if healthy
	history  []RCAIncident        // past incidents loaded from disk
	path     string               // ~/.xtop/rca-history.jsonl
	maxKeep  int                  // max history entries
	signatureIndex map[string][]int // signature → list of history indices
}

// Active returns a copy of the currently active incident, or nil if the
// system is healthy. Used by the confidence calibrator to detect incident
// completions at the moment health flips back to OK.
func (r *IncidentRecorder) Active() *RCAIncident {
	if r == nil {
		return nil
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.active == nil {
		return nil
	}
	cp := *r.active
	return &cp
}

// NewIncidentRecorder creates a recorder that persists to ~/.xtop/rca-history.jsonl.
func NewIncidentRecorder() *IncidentRecorder {
	home, _ := os.UserHomeDir()
	dir := filepath.Join(home, ".xtop")
	_ = os.MkdirAll(dir, 0755)
	r := &IncidentRecorder{
		path:           filepath.Join(dir, "rca-history.jsonl"),
		maxKeep:        500,
		signatureIndex: make(map[string][]int),
	}
	r.load()
	return r
}

// load reads past incidents from disk.
func (r *IncidentRecorder) load() {
	f, err := os.Open(r.path)
	if err != nil {
		return // no history yet
	}
	defer f.Close()

	dec := json.NewDecoder(f)
	for dec.More() {
		var inc RCAIncident
		if err := dec.Decode(&inc); err != nil {
			continue
		}
		r.history = append(r.history, inc)
	}

	r.rebuildIndex()
}

func (r *IncidentRecorder) rebuildIndex() {
	r.signatureIndex = make(map[string][]int)
	for i, inc := range r.history {
		r.signatureIndex[inc.Signature] = append(r.signatureIndex[inc.Signature], i)
	}
}

// Record processes the current RCA result, tracking incident start/end.
// Returns the currently active incident (nil if healthy).
func (r *IncidentRecorder) Record(result *model.AnalysisResult) *RCAIncident {
	r.mu.Lock()
	defer r.mu.Unlock()

	if result == nil {
		return r.active
	}

	isHealthy := result.Health == model.HealthOK

	if isHealthy {
		// End of incident (if one was active)
		if r.active != nil {
			r.active.EndedAt = time.Now()
			r.active.DurationSec = int(r.active.EndedAt.Sub(r.active.StartedAt).Seconds())
			r.active.Resolution = "auto-recovered"
			r.appendToHistory(*r.active)
			r.active = nil
		}
		return nil
	}

	// System is degraded/critical
	sig := signatureFromResult(result)

	if r.active == nil {
		// New incident starting
		r.active = &RCAIncident{
			StartedAt:  time.Now(),
			Bottleneck: result.PrimaryBottleneck,
			PeakScore:  result.PrimaryScore,
			Confidence: result.Confidence,
			Culprit:    result.PrimaryProcess,
			CulpritApp: result.PrimaryAppName,
			Signature:  sig,
		}
		if result.Narrative != nil {
			r.active.RootCause = result.Narrative.RootCause
			r.active.Pattern = result.Narrative.Pattern
			// Take top 3 evidence items
			n := 3
			if len(result.Narrative.Evidence) < n {
				n = len(result.Narrative.Evidence)
			}
			r.active.Evidence = append([]string(nil), result.Narrative.Evidence[:n]...)
		}
		r.active.EvidenceIDs = collectFiringEvidenceIDs(result)
	} else {
		// Update active incident with worst values seen
		if result.PrimaryScore > r.active.PeakScore {
			r.active.PeakScore = result.PrimaryScore
		}
		if result.Confidence > r.active.Confidence {
			r.active.Confidence = result.Confidence
		}
		// If the incident signature changed, close the current one and start new
		if sig != r.active.Signature && sig != "" {
			r.active.EndedAt = time.Now()
			r.active.DurationSec = int(r.active.EndedAt.Sub(r.active.StartedAt).Seconds())
			r.active.Resolution = "escalated"
			r.appendToHistory(*r.active)
			r.active = &RCAIncident{
				StartedAt:  time.Now(),
				Bottleneck: result.PrimaryBottleneck,
				PeakScore:  result.PrimaryScore,
				Confidence: result.Confidence,
				Culprit:    result.PrimaryProcess,
				CulpritApp: result.PrimaryAppName,
				Signature:  sig,
			}
			if result.Narrative != nil {
				r.active.RootCause = result.Narrative.RootCause
				r.active.Pattern = result.Narrative.Pattern
			}
			r.active.EvidenceIDs = collectFiringEvidenceIDs(result)
		} else {
			// Same signature — refresh the snapshot of IDs so "new evidence"
			// in DiffAgainstHistory reflects the incident at its current peak.
			if ids := collectFiringEvidenceIDs(result); len(ids) > 0 {
				r.active.EvidenceIDs = ids
			}
		}
	}

	return r.active
}

// collectFiringEvidenceIDs returns the evidence IDs currently firing (strength
// > 0.35) for the primary bottleneck. Mirrors the set used by
// signatureFromResult but keeps all firing IDs, not just the top 3.
func collectFiringEvidenceIDs(result *model.AnalysisResult) []string {
	if result == nil {
		return nil
	}
	var ids []string
	for _, rca := range result.RCA {
		if rca.Bottleneck != result.PrimaryBottleneck {
			continue
		}
		for _, ev := range rca.EvidenceV2 {
			if ev.Strength > 0.35 && ev.ID != "" {
				ids = append(ids, ev.ID)
			}
		}
		break
	}
	sort.Strings(ids)
	return ids
}

// appendToHistory adds a completed incident to history and persists to disk.
func (r *IncidentRecorder) appendToHistory(inc RCAIncident) {
	// Skip noise — incidents shorter than 10s or score <30 aren't worth remembering
	if inc.DurationSec < 10 || inc.PeakScore < 30 {
		return
	}

	r.history = append(r.history, inc)
	r.signatureIndex[inc.Signature] = append(r.signatureIndex[inc.Signature], len(r.history)-1)

	// Trim old history
	if len(r.history) > r.maxKeep {
		// Keep the most recent maxKeep
		r.history = r.history[len(r.history)-r.maxKeep:]
		r.rebuildIndex()
	}

	// Persist (append-only log)
	f, err := os.OpenFile(r.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return
	}
	defer f.Close()
	if data, err := json.Marshal(inc); err == nil {
		_, _ = f.Write(data)
		_, _ = f.WriteString("\n")
	}
}

// FindSimilar returns past incidents matching the current pattern/signature.
// Used to enrich the current RCA with historical context.
func (r *IncidentRecorder) FindSimilar(result *model.AnalysisResult) []RCAIncident {
	if result == nil || result.Health == model.HealthOK {
		return nil
	}
	r.mu.RLock()
	defer r.mu.RUnlock()

	sig := signatureFromResult(result)
	indices := r.signatureIndex[sig]
	if len(indices) == 0 {
		return nil
	}

	var matches []RCAIncident
	for _, i := range indices {
		if i < len(r.history) {
			matches = append(matches, r.history[i])
		}
	}

	// Sort by recency (newest first)
	sort.Slice(matches, func(i, j int) bool {
		return matches[i].StartedAt.After(matches[j].StartedAt)
	})

	// Cap at 5 most recent similar incidents
	if len(matches) > 5 {
		matches = matches[:5]
	}
	return matches
}

// HistoryContext builds a human-readable context string from similar past incidents.
// Used to enrich current RCA narratives with "this happened N times before" insights.
func (r *IncidentRecorder) HistoryContext(result *model.AnalysisResult) string {
	similar := r.FindSimilar(result)
	if len(similar) == 0 {
		return ""
	}

	// Count recurrences in last 24h / 7d
	var last24h, last7d int
	now := time.Now()
	for _, s := range similar {
		age := now.Sub(s.StartedAt)
		if age < 24*time.Hour {
			last24h++
		}
		if age < 7*24*time.Hour {
			last7d++
		}
	}

	// Analyze common culprit
	culprits := make(map[string]int)
	for _, s := range similar {
		if s.Culprit != "" {
			culprits[s.Culprit]++
		}
	}
	var topCulprit string
	var topCulpritCount int
	for c, n := range culprits {
		if n > topCulpritCount {
			topCulpritCount = n
			topCulprit = c
		}
	}

	// Build context message
	var msg string
	if last24h >= 3 {
		msg = fmt.Sprintf("RECURRING: This pattern has fired %d times in the last 24h", last24h)
	} else if last7d >= 3 {
		msg = fmt.Sprintf("RECURRING: This pattern has fired %d times in the last 7 days", last7d)
	} else if len(similar) >= 2 {
		msg = fmt.Sprintf("Pattern seen %d times before (last: %s ago)", len(similar), fmtAge(int(now.Sub(similar[0].StartedAt).Seconds())))
	}

	if topCulprit != "" && topCulpritCount >= 2 && msg != "" {
		msg += fmt.Sprintf(" — %q is the repeat culprit (%d/%d incidents)", topCulprit, topCulpritCount, len(similar))
	}

	// Average duration
	if len(similar) >= 2 {
		var totalDur int
		for _, s := range similar {
			totalDur += s.DurationSec
		}
		avgDur := totalDur / len(similar)
		if avgDur > 30 && msg != "" {
			msg += fmt.Sprintf(" (avg duration: %s)", fmtAge(avgDur))
		}
	}

	return msg
}

// signatureFromResult builds a stable signature of the incident for matching.
// Same bottleneck + top 3 evidence IDs = same signature.
func signatureFromResult(result *model.AnalysisResult) string {
	if result == nil || len(result.RCA) == 0 {
		return ""
	}

	// Use primary bottleneck + top 3 evidence IDs sorted alphabetically
	sig := result.PrimaryBottleneck + "|"
	var ids []string
	for _, rca := range result.RCA {
		if rca.Bottleneck != result.PrimaryBottleneck {
			continue
		}
		for _, ev := range rca.EvidenceV2 {
			if ev.Strength > 0.35 {
				ids = append(ids, ev.ID)
			}
		}
		break
	}
	sort.Strings(ids)
	if len(ids) > 3 {
		ids = ids[:3]
	}
	for _, id := range ids {
		sig += id + ","
	}
	return sig
}

// HistoryStats returns aggregate statistics for the status line.
func (r *IncidentRecorder) HistoryStats() (total int, last24h int, top3Bottlenecks []string) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	total = len(r.history)
	now := time.Now()
	bottleneckCounts := make(map[string]int)

	for _, inc := range r.history {
		if now.Sub(inc.StartedAt) < 24*time.Hour {
			last24h++
		}
		bottleneckCounts[inc.Bottleneck]++
	}

	// Sort bottlenecks by frequency
	type kv struct {
		k string
		v int
	}
	var pairs []kv
	for k, v := range bottleneckCounts {
		pairs = append(pairs, kv{k, v})
	}
	sort.Slice(pairs, func(i, j int) bool { return pairs[i].v > pairs[j].v })
	for i, p := range pairs {
		if i >= 3 {
			break
		}
		top3Bottlenecks = append(top3Bottlenecks, fmt.Sprintf("%s:%d", p.k, p.v))
	}
	return
}
