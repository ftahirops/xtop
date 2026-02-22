package engine

import (
	"sort"

	"github.com/ftahirops/xtop/model"
)

// Slot weights for weightedDomainScore.
var slotWeights = map[string]float64{
	"psi":       0.35,
	"latency":   0.25,
	"queue":     0.20,
	"secondary": 0.20,
}

// v2TrustGate returns true if evidence meets the v2 trust requirements:
// 2+ groups with strength >= 0.35 AND at least 1 measured with confidence >= 0.8.
func v2TrustGate(evs []model.Evidence) bool {
	groups := evidenceGroupsFired(evs, 0.35)
	if groups < 2 {
		return false
	}
	return hasMeasuredHighConf(evs, 0.35, 0.8)
}

// weightedDomainScore computes a weighted sum across weight-category slots.
// For each slot (psi, latency, queue, secondary), it takes the maximum
// strength*confidence of evidence in that slot, then applies slot weights.
// Returns 0..100.
func weightedDomainScore(evs []model.Evidence) float64 {
	// Collect best strength*confidence per slot
	slotBest := map[string]float64{
		"psi":       0,
		"latency":   0,
		"queue":     0,
		"secondary": 0,
	}

	for _, e := range evs {
		cat := e.Tags["weight"]
		if cat == "" {
			cat = "secondary"
		}
		sc := e.Strength * e.Confidence
		if sc > slotBest[cat] {
			slotBest[cat] = sc
		}
	}

	// Weighted sum
	score := 0.0
	for slot, weight := range slotWeights {
		score += weight * slotBest[slot]
	}

	// Scale to 0..100
	result := score * 100
	if result > 100 {
		result = 100
	}
	return result
}

// domainConfidence computes domain-level confidence.
// Formula: clamp(0.3 + 0.2*(groups_fired-1) + 0.5*avg_confidence, 0..0.98)
func domainConfidence(evs []model.Evidence) float64 {
	fired := evidenceGroupsFired(evs, 0.35)
	if fired == 0 {
		return 0
	}

	// Average confidence of fired evidence
	var sumConf float64
	var count int
	for _, e := range evs {
		if e.Strength >= 0.35 {
			sumConf += e.Confidence
			count++
		}
	}
	avgConf := sumConf / float64(count)

	conf := 0.3 + 0.2*float64(fired-1) + 0.5*avgConf
	if conf < 0 {
		conf = 0
	}
	if conf > 0.98 {
		conf = 0.98
	}
	return conf
}

// evidenceToChecks converts v2 Evidence objects to legacy EvidenceCheck
// for backward compatibility with all TUI/watch/monitor consumers.
func evidenceToChecks(evs []model.Evidence) []model.EvidenceCheck {
	checks := make([]model.EvidenceCheck, 0, len(evs))
	for _, e := range evs {
		confStr := "L"
		if e.Confidence >= 0.8 {
			confStr = "H"
		} else if e.Confidence >= 0.6 {
			confStr = "M"
		}

		source := "derived"
		if e.Measured {
			source = "procfs"
		}

		checks = append(checks, model.EvidenceCheck{
			Group:      e.ID,
			Label:      e.Message,
			Passed:     e.Strength >= 0.35,
			Value:      e.Message,
			Confidence: confStr,
			Source:     source,
			Strength:   e.Strength,
		})
	}

	// Sort: passed checks first, then by strength descending
	sort.Slice(checks, func(i, j int) bool {
		if checks[i].Passed != checks[j].Passed {
			return checks[i].Passed
		}
		return checks[i].Strength > checks[j].Strength
	})

	return checks
}
