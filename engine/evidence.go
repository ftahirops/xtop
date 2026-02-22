package engine

import "github.com/ftahirops/xtop/model"

// Weight categories for evidence IDs.
// Used by weightedDomainScore to assign slot weights.
var evidenceWeightCategory = map[string]string{
	// CPU
	"cpu.psi":              "psi",
	"cpu.runqueue":         "queue",
	"cpu.ctxswitch":        "secondary",
	"cpu.steal":            "secondary",
	"cpu.cgroup.throttle":  "latency",

	// Memory
	"mem.psi":              "psi",
	"mem.available.low":    "latency",
	"mem.reclaim.direct":   "queue",
	"mem.swap.activity":    "latency",
	"mem.major.faults":     "secondary",
	"mem.oom.kills":        "psi", // OOM is highest priority

	// IO
	"io.psi":               "psi",
	"io.dstate":            "queue",
	"io.disk.latency":      "latency",
	"io.disk.util":         "latency",
	"io.writeback":         "secondary",
	"io.fsfull":            "secondary",

	// Network
	"net.drops":            "latency",
	"net.tcp.retrans":      "psi",
	"net.conntrack":        "queue",
	"net.softirq":          "secondary",
	"net.tcp.state":        "secondary",
}

// emitEvidence creates a v2 Evidence object with smooth normalization.
func emitEvidence(id string, domain model.Domain, value, warn, crit float64,
	measured bool, conf float64, msg, window string,
	owners []model.OwnerAttribution, tags map[string]string) model.Evidence {

	strength := normalize(value, warn, crit)

	sev := model.SeverityInfo
	if strength >= 0.7 {
		sev = model.SeverityCrit
	} else if strength >= 0.01 {
		sev = model.SeverityWarn
	}

	if tags == nil {
		tags = make(map[string]string)
	}
	if cat, ok := evidenceWeightCategory[id]; ok {
		tags["weight"] = cat
	}

	return model.Evidence{
		ID:         id,
		Message:    msg,
		Window:     window,
		Domain:     domain,
		Severity:   sev,
		Strength:   strength,
		Confidence: conf,
		Value:      value,
		Threshold:  crit,
		Measured:   measured,
		Owners:     owners,
		Tags:       tags,
	}
}

// evidenceGroupsFired counts how many unique evidence IDs have strength >= minStrength.
func evidenceGroupsFired(evs []model.Evidence, minStrength float64) int {
	count := 0
	for _, e := range evs {
		if e.Strength >= minStrength {
			count++
		}
	}
	return count
}

// hasMeasuredHighConf returns true if at least one evidence is measured,
// has strength >= minStrength, and confidence >= minConf.
func hasMeasuredHighConf(evs []model.Evidence, minStrength, minConf float64) bool {
	for _, e := range evs {
		if e.Measured && e.Strength >= minStrength && e.Confidence >= minConf {
			return true
		}
	}
	return false
}
