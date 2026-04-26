package engine

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/ftahirops/xtop/model"
)

// DiffAgainstHistory compares the current RCA result against the last N similar
// incidents (same signature) and returns a structured IncidentDiff.
//
// This is the mechanical heart of the "this vs last N similar" feature:
// the UI/narrative layer reads the returned struct to surface things like
// "score is 15 points worse than usual" or "swap_churn is firing this time
// but wasn't in the last 4 incidents — check why we're swapping now."
//
// Returns nil when there are no prior matches (first occurrence, or history
// file not populated yet).
func (r *IncidentRecorder) DiffAgainstHistory(result *model.AnalysisResult) *model.IncidentDiff {
	if result == nil || result.Health == model.HealthOK {
		return nil
	}
	similar := r.FindSimilar(result)
	if len(similar) == 0 {
		return nil
	}

	diff := &model.IncidentDiff{
		MatchCount:       len(similar),
		CurrentPeakScore: result.PrimaryScore,
		CurrentCulprit:   pickCulprit(result),
		CulpritFrequency: make(map[string]int),
	}

	// Oldest first, so FirstSeen is the earliest past match.
	// similar is already sorted newest-first by FindSimilar.
	diff.LastSeen = similar[0].StartedAt
	diff.FirstSeen = similar[len(similar)-1].StartedAt

	// Score distribution
	scores := make([]int, 0, len(similar))
	durations := make([]int, 0, len(similar))
	nowHour := time.Now().Hour()
	for _, s := range similar {
		scores = append(scores, s.PeakScore)
		if s.DurationSec > 0 {
			durations = append(durations, s.DurationSec)
		}
		// culprit tallies — prefer app name when available
		c := s.CulpritApp
		if c == "" {
			c = s.Culprit
		}
		if c != "" {
			diff.CulpritFrequency[c]++
		}
		if s.StartedAt.Hour() == nowHour {
			diff.SameHourOfDay++
		}
	}
	diff.MaxPeakScore = sliceMax(scores)
	diff.MedianPeakScore = sliceMedian(scores)
	diff.MedianDurationSec = sliceMedian(durations)
	diff.ScoreDeltaFromMedian = diff.CurrentPeakScore - diff.MedianPeakScore

	// Most common culprit
	for c, n := range diff.CulpritFrequency {
		if n > diff.TopCulpritCount {
			diff.TopCulpritCount = n
			diff.TopCulprit = c
		}
	}
	if diff.CurrentCulprit != "" && diff.CurrentCulprit == diff.TopCulprit && diff.TopCulpritCount >= 2 {
		diff.CulpritIsRepeat = true
	}

	// Evidence set diff — which IDs are firing now that weren't in the
	// baseline (or were in the baseline but aren't now). This is the signal
	// operators should actually read: "what's different this time."
	currentSet := currentEvidenceIDs(result)
	baselineSet := baselineEvidenceUnion(similar)
	diff.NewEvidence = stringSetDiff(currentSet, baselineSet)
	diff.MissingEvidence = stringSetDiff(baselineSet, currentSet)

	diff.DriftHint = composeDriftHint(diff)
	return diff
}

// composeDriftHint builds a single short sentence summarizing what's
// interesting about this incident relative to its history. Empty when
// there's nothing noteworthy — the UI should only render non-empty hints.
func composeDriftHint(d *model.IncidentDiff) string {
	if d == nil {
		return ""
	}
	var parts []string

	// Score delta — only call out meaningful swings.
	switch {
	case d.ScoreDeltaFromMedian >= 15:
		parts = append(parts, fmt.Sprintf("%d pts worse than usual (median %d%%)",
			d.ScoreDeltaFromMedian, d.MedianPeakScore))
	case d.ScoreDeltaFromMedian <= -15:
		parts = append(parts, fmt.Sprintf("%d pts milder than usual (median %d%%)",
			-d.ScoreDeltaFromMedian, d.MedianPeakScore))
	}

	// Evidence changes — cap at 3 to keep the hint scannable.
	if len(d.NewEvidence) > 0 {
		parts = append(parts, fmt.Sprintf("new signals: %s",
			trimIDList(d.NewEvidence, 3)))
	}
	if len(d.MissingEvidence) > 0 {
		parts = append(parts, fmt.Sprintf("usually firing but absent: %s",
			trimIDList(d.MissingEvidence, 3)))
	}

	// Scheduled / time-of-day clue.
	if d.SameHourOfDay >= 2 && d.MatchCount >= 3 {
		parts = append(parts, fmt.Sprintf("%d/%d prior matches occurred at this hour — check cron/scheduled jobs",
			d.SameHourOfDay, d.MatchCount))
	}

	return strings.Join(parts, " · ")
}

// pickCulprit returns the most descriptive name for the current culprit —
// app name if known, otherwise process name.
func pickCulprit(result *model.AnalysisResult) string {
	if result.PrimaryAppName != "" {
		return result.PrimaryAppName
	}
	return result.PrimaryProcess
}

// currentEvidenceIDs returns the set of evidence IDs currently firing with
// non-trivial strength for the primary bottleneck.
func currentEvidenceIDs(result *model.AnalysisResult) map[string]bool {
	set := make(map[string]bool)
	for _, rca := range result.RCA {
		if rca.Bottleneck != result.PrimaryBottleneck {
			continue
		}
		for _, ev := range rca.EvidenceV2 {
			if ev.Strength > 0.35 && ev.ID != "" {
				set[ev.ID] = true
			}
		}
		break
	}
	return set
}

// baselineEvidenceUnion returns the set of evidence IDs that appeared in any
// of the prior similar incidents. New-format records carry EvidenceIDs
// directly; legacy records from before structured IDs were stored fall back to
// parsing the human-readable Evidence strings (best-effort).
func baselineEvidenceUnion(similar []RCAIncident) map[string]bool {
	set := make(map[string]bool)
	for _, inc := range similar {
		if len(inc.EvidenceIDs) > 0 {
			for _, id := range inc.EvidenceIDs {
				set[id] = true
			}
			continue
		}
		for _, e := range inc.Evidence {
			if id := extractEvidenceID(e); id != "" {
				set[id] = true
			}
		}
	}
	return set
}

// extractEvidenceID pulls an "id=<ID>" token out of a narrative evidence
// string when present. Returns "" if no structured ID is found.
func extractEvidenceID(s string) string {
	i := strings.Index(s, "id=")
	if i < 0 {
		return ""
	}
	rest := s[i+3:]
	end := strings.IndexAny(rest, " \t,]")
	if end < 0 {
		return rest
	}
	return rest[:end]
}

func stringSetDiff(a, b map[string]bool) []string {
	var out []string
	for k := range a {
		if !b[k] {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}

func trimIDList(ids []string, max int) string {
	if len(ids) <= max {
		return strings.Join(ids, ", ")
	}
	return strings.Join(ids[:max], ", ") + fmt.Sprintf(" (+%d more)", len(ids)-max)
}

func sliceMax(v []int) int {
	m := 0
	for _, x := range v {
		if x > m {
			m = x
		}
	}
	return m
}

func sliceMedian(v []int) int {
	if len(v) == 0 {
		return 0
	}
	c := append([]int(nil), v...)
	sort.Ints(c)
	return c[len(c)/2]
}
