package engine

import (
	"fmt"
	"sort"
	"strings"

	"github.com/ftahirops/xtop/model"
)

// narrativeRule maps a set of evidence IDs to a human-readable root cause sentence.
type narrativeRule struct {
	ids      []string // evidence IDs that must fire (at least minMatch)
	minMatch int      // how many of ids must fire (0 = all)
	text     string   // natural-language root cause
}

// narrativeTemplates are checked in order; first match wins.
// Cross-domain rules are listed first (highest priority).
var narrativeTemplates = []narrativeRule{
	// Cross-domain (highest priority)
	{ids: []string{"mem.swap.activity", "io.psi"}, text: "Memory pressure causing IO storm via swap thrashing"},
	{ids: []string{"mem.reclaim.direct", "io.disk.latency"}, text: "Memory reclaim driving disk latency"},
	{ids: []string{"mem.oom.kills"}, text: "OOM crisis — kernel killing processes to free memory"},
	{ids: []string{"mem.swap.activity", "mem.psi", "io.disk.latency"}, minMatch: 2, text: "Memory pressure cascading into IO latency via swap"},

	// CPU
	{ids: []string{"cpu.cgroup.throttle", "cpu.runqueue"}, text: "CPU throttle cascade — cgroup limits saturating run queue"},
	{ids: []string{"cpu.cgroup.throttle", "cpu.psi"}, text: "CPU throttling — cgroup limits causing CPU pressure stalls"},
	{ids: []string{"cpu.steal", "cpu.psi"}, text: "Noisy neighbor — hypervisor stealing CPU time"},
	{ids: []string{"cpu.runqueue", "cpu.psi"}, text: "CPU saturation — run queue overloaded"},
	{ids: []string{"cpu.psi"}, text: "CPU pressure — tasks stalling on CPU access"},
	{ids: []string{"cpu.runqueue"}, text: "CPU contention — elevated run queue depth"},
	{ids: []string{"cpu.sentinel.throttle"}, text: "CPU throttling detected by BPF sentinel"},

	// Memory
	{ids: []string{"mem.reclaim.direct", "mem.psi"}, text: "Direct reclaim storm — kernel blocking on memory allocation"},
	{ids: []string{"mem.swap.activity", "mem.psi"}, text: "Swap thrashing — heavy swap IO causing memory pressure"},
	{ids: []string{"mem.available.low", "mem.psi"}, text: "Memory exhaustion — available memory critically low"},
	{ids: []string{"mem.available.low"}, text: "Memory pressure from low available memory"},
	{ids: []string{"mem.psi"}, text: "Memory pressure — tasks stalling on allocation"},
	{ids: []string{"mem.sentinel.oom"}, text: "OOM events detected by BPF sentinel"},
	{ids: []string{"mem.sentinel.reclaim"}, text: "Direct reclaim events detected by BPF sentinel"},

	// IO
	{ids: []string{"io.disk.util", "io.dstate", "io.disk.latency"}, minMatch: 2, text: "Disk IO saturation causing D-state threads"},
	{ids: []string{"io.fsfull"}, text: "Filesystem nearing capacity"},
	{ids: []string{"io.writeback", "io.disk.latency"}, text: "Writeback flood driving disk latency"},
	{ids: []string{"io.psi", "io.dstate"}, text: "IO saturation — D-state processes accumulating"},
	{ids: []string{"io.psi", "io.disk.latency"}, text: "IO pressure — elevated disk latency"},
	{ids: []string{"io.psi"}, text: "IO pressure — tasks stalling on disk access"},

	// Network
	{ids: []string{"net.tcp.retrans", "net.drops"}, text: "Network congestion — retransmits with packet drops"},
	{ids: []string{"net.closewait"}, text: "Socket leak — CLOSE_WAIT accumulating, application not closing connections"},
	{ids: []string{"net.conntrack", "net.drops"}, text: "Conntrack exhaustion — table full causing packet drops"},
	{ids: []string{"net.conntrack"}, text: "Conntrack table pressure — approaching capacity"},
	{ids: []string{"net.tcp.retrans"}, text: "TCP retransmits elevated — possible network congestion"},
	{ids: []string{"net.drops"}, text: "Packet drops detected — interface or kernel buffer overflows"},
	{ids: []string{"net.sentinel.drops"}, text: "Packet drops detected by BPF sentinel"},
	{ids: []string{"net.sentinel.resets"}, text: "TCP resets detected by BPF sentinel"},
}

// BuildNarrative produces a human-readable root cause narrative from analysis results.
func BuildNarrative(result *model.AnalysisResult, curr *model.Snapshot, rates *model.RateSnapshot) *model.Narrative {
	if result == nil || result.Health == model.HealthOK {
		return nil
	}

	// Collect all fired evidence across all RCA entries
	fired := collectFiredEvidence(result)
	if len(fired) == 0 {
		return nil
	}

	n := &model.Narrative{
		Confidence: result.Confidence,
	}

	// Try pattern match first (Phase 2 integration point)
	if pat := MatchPattern(result); pat != nil {
		n.RootCause = pat.Narrative
		n.Pattern = pat.Name
	} else {
		// Fall back to narrative templates
		n.RootCause = matchNarrativeTemplate(fired)
	}

	// If no template matched, use the primary bottleneck name
	if n.RootCause == "" {
		n.RootCause = result.PrimaryBottleneck
	}

	n.Evidence = selectTopEvidence(result, 4)
	n.Impact = estimateImpact(result, curr, rates)

	return n
}

// collectFiredEvidence returns a set of evidence IDs that have fired (strength > 0).
func collectFiredEvidence(result *model.AnalysisResult) map[string]model.Evidence {
	fired := make(map[string]model.Evidence)
	for _, rca := range result.RCA {
		for _, ev := range rca.EvidenceV2 {
			if ev.Strength > 0 {
				if existing, ok := fired[ev.ID]; !ok || ev.Strength > existing.Strength {
					fired[ev.ID] = ev
				}
			}
		}
	}
	return fired
}

// matchNarrativeTemplate finds the first narrative template whose required evidence IDs fire.
func matchNarrativeTemplate(fired map[string]model.Evidence) string {
	for _, rule := range narrativeTemplates {
		minMatch := rule.minMatch
		if minMatch == 0 {
			minMatch = len(rule.ids)
		}
		matched := 0
		for _, id := range rule.ids {
			if _, ok := fired[id]; ok {
				matched++
			}
		}
		if matched >= minMatch {
			return rule.text
		}
	}
	return ""
}

// selectTopEvidence picks the top N fired evidence lines by strength,
// formatted as "- {message}" strings.
func selectTopEvidence(result *model.AnalysisResult, n int) []string {
	var all []model.Evidence
	seen := make(map[string]bool)
	for _, rca := range result.RCA {
		for _, ev := range rca.EvidenceV2 {
			if ev.Strength > 0 && !seen[ev.ID] {
				seen[ev.ID] = true
				all = append(all, ev)
			}
		}
	}

	sort.Slice(all, func(i, j int) bool {
		return all[i].Strength > all[j].Strength
	})

	if len(all) > n {
		all = all[:n]
	}

	lines := make([]string, 0, len(all))
	for _, ev := range all {
		lines = append(lines, fmt.Sprintf("- %s", ev.Message))
	}
	return lines
}

// estimateImpact builds a one-line impact string from PSI stalls, latency, and exhaustion ETAs.
func estimateImpact(result *model.AnalysisResult, curr *model.Snapshot, rates *model.RateSnapshot) string {
	var parts []string

	// PSI stall percentages
	if curr != nil {
		if v := curr.Global.PSI.CPU.Some.Avg10; v > 1 {
			parts = append(parts, fmt.Sprintf("CPU stall %.0f%%", v))
		}
		if v := curr.Global.PSI.Memory.Some.Avg10; v > 1 {
			parts = append(parts, fmt.Sprintf("Mem stall %.0f%%", v))
		}
		if v := curr.Global.PSI.IO.Full.Avg10; v > 1 {
			parts = append(parts, fmt.Sprintf("IO stall %.0f%%", v))
		}
	}

	// Exhaustion ETAs
	for _, ex := range result.Exhaustions {
		if ex.EstMinutes > 0 && ex.EstMinutes < 120 {
			parts = append(parts, fmt.Sprintf("%s exhaustion in %.0fm", ex.Resource, ex.EstMinutes))
		}
	}

	// Degradation trends
	for _, d := range result.Degradations {
		if d.Duration > 60 {
			parts = append(parts, fmt.Sprintf("%s %s", d.Metric, d.Direction))
		}
	}

	if len(parts) == 0 {
		return ""
	}
	// Limit to 3 items
	if len(parts) > 3 {
		parts = parts[:3]
	}
	return strings.Join(parts, "; ")
}
