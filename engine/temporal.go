package engine

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/ftahirops/xtop/model"
)

// UpdateSignalOnsets updates the signal onset tracking map in History.
// Call this each tick with the latest analysis result.
func UpdateSignalOnsets(hist *History, result *model.AnalysisResult) {
	if hist == nil || result == nil {
		return
	}
	hist.mu.Lock()
	defer hist.mu.Unlock()

	now := time.Now()
	currentlyFiring := make(map[string]bool)

	for _, rca := range result.RCA {
		for _, ev := range rca.EvidenceV2 {
			if ev.Strength > 0 {
				currentlyFiring[ev.ID] = true
				if _, exists := hist.signalOnsets[ev.ID]; !exists {
					hist.signalOnsets[ev.ID] = now
				}
			}
		}
	}

	// Clear signals that are no longer firing
	for id := range hist.signalOnsets {
		if !currentlyFiring[id] {
			delete(hist.signalOnsets, id)
		}
	}
}

// BuildTemporalChain constructs a temporal causality chain from the currently
// firing evidence, sorted by onset time (earliest first).
func BuildTemporalChain(result *model.AnalysisResult, hist *History) *model.TemporalChain {
	if hist == nil || result == nil {
		return nil
	}
	hist.mu.RLock()
	defer hist.mu.RUnlock()

	if len(hist.signalOnsets) == 0 {
		return nil
	}

	// Collect events for currently firing evidence
	var events []model.TemporalEvent
	seen := make(map[string]bool)

	for _, rca := range result.RCA {
		for _, ev := range rca.EvidenceV2 {
			if ev.Strength > 0 && !seen[ev.ID] {
				seen[ev.ID] = true
				onset, ok := hist.signalOnsets[ev.ID]
				if !ok {
					continue
				}
				events = append(events, model.TemporalEvent{
					EvidenceID: ev.ID,
					Label:      ev.Message,
					FirstSeen:  onset,
				})
			}
		}
	}

	if len(events) == 0 {
		return nil
	}

	// Sort by onset time (earliest first)
	sort.Slice(events, func(i, j int) bool {
		return events[i].FirstSeen.Before(events[j].FirstSeen)
	})

	// Assign sequence numbers and build summary
	earliest := events[0].FirstSeen
	var summaryParts []string
	for i := range events {
		events[i].Sequence = i
		offset := events[i].FirstSeen.Sub(earliest)
		label := shortLabel(events[i].EvidenceID)
		summaryParts = append(summaryParts, fmt.Sprintf("%s (T+%ds)", label, int(offset.Seconds())))
	}

	// Limit summary to top 5 events
	if len(summaryParts) > 5 {
		summaryParts = summaryParts[:5]
	}

	chain := &model.TemporalChain{
		Events:     events,
		Summary:    strings.Join(summaryParts, " → "),
		FirstMover: events[0].EvidenceID,
	}

	return chain
}

// shortLabel converts an evidence ID like "cpu.cgroup.throttle" to a short display label.
func shortLabel(id string) string {
	labels := map[string]string{
		"cpu.psi":              "CPU PSI",
		"cpu.runqueue":         "runqueue",
		"cpu.ctxswitch":        "ctx-switch",
		"cpu.steal":            "steal",
		"cpu.cgroup.throttle":  "cg-throttle",
		"cpu.sentinel.throttle": "BPF throttle",
		"mem.psi":              "mem PSI",
		"mem.available.low":    "mem-low",
		"mem.reclaim.direct":   "direct-reclaim",
		"mem.swap.activity":    "swap",
		"mem.major.faults":     "major-faults",
		"mem.oom.kills":        "OOM",
		"mem.sentinel.oom":     "BPF OOM",
		"mem.sentinel.reclaim": "BPF reclaim",
		"io.psi":               "IO PSI",
		"io.dstate":            "D-state",
		"io.disk.latency":      "disk-latency",
		"io.disk.util":         "disk-util",
		"io.writeback":         "writeback",
		"io.fsfull":            "fs-full",
		"net.drops":            "drops",
		"net.tcp.retrans":      "retransmits",
		"net.conntrack":        "conntrack",
		"net.softirq":          "softirq",
		"net.tcp.state":        "tcp-state",
		"net.closewait":        "CLOSE_WAIT",
		"net.sentinel.drops":   "BPF drops",
		"net.sentinel.resets":  "BPF resets",
	}
	if l, ok := labels[id]; ok {
		return l
	}
	// Fallback: use last segment
	parts := strings.Split(id, ".")
	return parts[len(parts)-1]
}
