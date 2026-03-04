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

// crossSignalPair defines a predefined cause-effect relationship across domains.
type crossSignalPair struct {
	Cause       string
	Effect      string
	Explanation string
}

// predefinedPairs are known cause-effect signal relationships.
var predefinedPairs = []crossSignalPair{
	{"cpu.busy", "cpu.runqueue", "High CPU utilization driving run queue saturation"},
	{"cpu.runqueue", "io.disk.latency", "CPU saturation causing IO scheduling delays"},
	{"mem.reclaim.direct", "io.disk.latency", "Direct page reclaim blocking on disk IO"},
	{"dotnet.gc.pause", "cpu.runqueue", ".NET GC stop-the-world pauses adding to run queue"},
	{"net.tcp.retrans", "net.softirq", "TCP retransmits driving softIRQ CPU overhead"},
	{"mem.swap.activity", "io.disk.latency", "Swap thrashing competing with disk IO"},
	{"cpu.cgroup.throttle", "net.tcp.retrans", "CPU throttling causing TCP retransmit timeouts"},
	{"dotnet.alloc.storm", "mem.reclaim.direct", ".NET allocation storm triggering direct reclaim"},
	{"mem.oom.kills", "cpu.runqueue", "OOM kill recovery causing CPU scheduling storms"},
	{"io.writeback", "io.disk.latency", "Dirty page writeback flooding disk queue"},
	{"net.conntrack", "net.drops", "Conntrack table pressure causing packet drops"},
	{"jvm.gc.pause", "cpu.runqueue", "JVM GC stop-the-world pauses adding to run queue"},
	{"jvm.heap.pressure", "mem.reclaim.direct", "JVM heap pressure triggering kernel direct reclaim"},
	{"sec.synflood", "net.conntrack.growth", "SYN flood driving conntrack table growth"},
	{"sec.portscan", "net.sentinel.resets", "Port scanning causing TCP RST responses"},
	{"sec.dns.anomaly", "sec.dns.tunnel", "Elevated DNS leading to tunneling detection"},
	{"sec.beacon", "sec.outbound.exfil", "C2 beacon associated with data exfiltration"},
}

// BuildCrossCorrelation analyzes signal onset ordering across domains to detect
// cause-effect relationships. It checks predefined signal pairs and computes
// lead times from signal onsets tracked in History.
func BuildCrossCorrelation(result *model.AnalysisResult, hist *History) []model.CrossCorrelation {
	if hist == nil || result == nil {
		return nil
	}
	hist.mu.RLock()
	defer hist.mu.RUnlock()

	if len(hist.signalOnsets) < 2 {
		return nil
	}

	// Build map of currently firing evidence with strength
	fired := make(map[string]float64)
	for _, rca := range result.RCA {
		for _, ev := range rca.EvidenceV2 {
			if ev.Strength > 0 {
				fired[ev.ID] = ev.Strength
			}
		}
	}

	var correlations []model.CrossCorrelation

	for _, pair := range predefinedPairs {
		causeStr, causeOK := fired[pair.Cause]
		effectStr, effectOK := fired[pair.Effect]
		if !causeOK || !effectOK {
			continue
		}

		causeOnset, cOK := hist.signalOnsets[pair.Cause]
		effectOnset, eOK := hist.signalOnsets[pair.Effect]
		if !cOK || !eOK {
			continue
		}

		// Cause must have started before or at the same time as effect
		leadTime := effectOnset.Sub(causeOnset).Seconds()
		if leadTime < 0 {
			continue // effect started first — not this correlation
		}

		// Confidence based on: lead time plausibility + signal strengths
		confidence := 0.5
		if leadTime > 0 && leadTime < 30 {
			confidence += 0.3 // strong temporal evidence
		} else if leadTime == 0 {
			confidence += 0.1 // simultaneous — weaker
		}
		// Boost for strong signals
		avgStr := (causeStr + effectStr) / 2
		if avgStr > 0.5 {
			confidence += 0.15
		}
		if confidence > 1.0 {
			confidence = 1.0
		}

		correlations = append(correlations, model.CrossCorrelation{
			Cause:       pair.Cause,
			Effect:      pair.Effect,
			LeadTimeSec: leadTime,
			Confidence:  confidence,
			Explanation: pair.Explanation,
		})
	}

	// Sort by confidence descending
	sort.Slice(correlations, func(i, j int) bool {
		return correlations[i].Confidence > correlations[j].Confidence
	})

	// Limit to top 5
	if len(correlations) > 5 {
		correlations = correlations[:5]
	}

	return correlations
}

// shortLabel converts an evidence ID like "cpu.cgroup.throttle" to a short display label.
func shortLabel(id string) string {
	labels := map[string]string{
		"cpu.psi":              "CPU PSI",
		"cpu.busy":             "CPU busy",
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
		"net.sentinel.drops":            "BPF drops",
		"net.sentinel.resets":           "BPF resets",
		"net.conntrack.drops":           "ct-drops",
		"net.conntrack.insertfail":      "ct-insertfail",
		"net.conntrack.growth":          "ct-growth",
		"net.conntrack.invalid":         "ct-invalid",
		"net.conntrack.hashcontention":  "ct-hash",
		"dotnet.gc.pause":               ".NET GC",
		"dotnet.alloc.storm":            ".NET alloc",
		"dotnet.threadpool.queue":       ".NET tp-queue",
		"jvm.gc.pause":                  "JVM GC",
		"jvm.heap.pressure":             "JVM heap",
		"sec.synflood":                  "SYN flood",
		"sec.portscan":                  "port scan",
		"sec.dns.anomaly":               "DNS anomaly",
		"sec.dns.tunnel":                "DNS tunnel",
		"sec.outbound.exfil":            "data exfil",
		"sec.lateral":                   "lateral mvmt",
		"sec.beacon":                    "C2 beacon",
		"sec.tcp.flags":                 "TCP flags",
	}
	if l, ok := labels[id]; ok {
		return l
	}
	// Fallback: use last segment
	parts := strings.Split(id, ".")
	return parts[len(parts)-1]
}
