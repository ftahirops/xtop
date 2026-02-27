package engine

import (
	"sort"

	"github.com/ftahirops/xtop/model"
)

// Pattern is a named failure pattern that matches a combination of evidence signals.
type Pattern struct {
	Name       string
	Conditions []PatternCondition
	MinMatch   int     // how many conditions must fire
	Priority   int     // higher = checked first
	MinStr     float64 // minimum evidence strength to count (default 0.01)
	Narrative  string  // human-readable root cause sentence
}

// PatternCondition is a single evidence requirement within a pattern.
type PatternCondition struct {
	EvidenceID  string
	MinStrength float64 // 0 = any non-zero strength
}

// patternLibrary is the built-in pattern library, ordered by priority (highest first).
var patternLibrary = []Pattern{
	{
		Name:     "OOM Crisis",
		Priority: 100,
		Conditions: []PatternCondition{
			{EvidenceID: "mem.oom.kills"},
		},
		MinMatch:  1,
		Narrative: "OOM crisis — kernel killing processes to free memory",
	},
	{
		Name:     "Filesystem Full",
		Priority: 95,
		Conditions: []PatternCondition{
			{EvidenceID: "io.fsfull"},
		},
		MinMatch:  1,
		Narrative: "Filesystem nearing capacity — write operations at risk",
	},
	{
		Name:     "Memory-Induced IO Storm",
		Priority: 90,
		Conditions: []PatternCondition{
			{EvidenceID: "mem.swap.activity"},
			{EvidenceID: "io.psi"},
			{EvidenceID: "io.disk.latency"},
		},
		MinMatch:  2,
		Narrative: "Memory pressure causing IO storm via swap thrashing",
	},
	{
		Name:     "Direct Reclaim Storm",
		Priority: 85,
		Conditions: []PatternCondition{
			{EvidenceID: "mem.reclaim.direct"},
			{EvidenceID: "io.disk.latency"},
		},
		MinMatch:  2,
		Narrative: "Direct reclaim storm — memory allocation blocking on disk IO",
	},
	{
		Name:     "CPU Throttle Cascade",
		Priority: 80,
		Conditions: []PatternCondition{
			{EvidenceID: "cpu.cgroup.throttle"},
			{EvidenceID: "cpu.runqueue"},
			{EvidenceID: "cpu.psi"},
		},
		MinMatch:  2,
		Narrative: "CPU throttle cascade — cgroup limits saturating run queue",
	},
	{
		Name:     "Disk IO Saturation",
		Priority: 75,
		Conditions: []PatternCondition{
			{EvidenceID: "io.disk.util"},
			{EvidenceID: "io.dstate"},
			{EvidenceID: "io.disk.latency"},
		},
		MinMatch:  2,
		Narrative: "Disk IO saturation — D-state threads accumulating",
	},
	{
		Name:     "Writeback Flood",
		Priority: 70,
		Conditions: []PatternCondition{
			{EvidenceID: "io.writeback"},
			{EvidenceID: "io.disk.latency"},
			{EvidenceID: "io.psi"},
		},
		MinMatch:  2,
		Narrative: "Writeback flood — dirty page flush driving IO stalls",
	},
	{
		Name:     "VM Noisy Neighbor",
		Priority: 65,
		Conditions: []PatternCondition{
			{EvidenceID: "cpu.steal", MinStrength: 0.1},
			{EvidenceID: "cpu.psi"},
		},
		MinMatch:  1,
		Narrative: "Noisy neighbor — hypervisor stealing CPU time",
	},
	{
		Name:     "Network Congestion",
		Priority: 60,
		Conditions: []PatternCondition{
			{EvidenceID: "net.tcp.retrans"},
			{EvidenceID: "net.drops"},
			{EvidenceID: "net.softirq"},
		},
		MinMatch:  2,
		Narrative: "Network congestion — retransmits with packet drops",
	},
	{
		Name:     "Conntrack Exhaustion",
		Priority: 55,
		Conditions: []PatternCondition{
			{EvidenceID: "net.conntrack"},
			{EvidenceID: "net.drops"},
		},
		MinMatch:  1,
		Narrative: "Conntrack exhaustion — connection tracking table saturated",
	},
	{
		Name:     "Socket Leak",
		Priority: 50,
		Conditions: []PatternCondition{
			{EvidenceID: "net.closewait"},
		},
		MinMatch:  1,
		Narrative: "Socket leak — CLOSE_WAIT accumulating, application not closing connections",
	},
	{
		Name:     "Memory Leak",
		Priority: 45,
		Conditions: []PatternCondition{
			{EvidenceID: "mem.available.low"},
		},
		MinMatch:  1,
		Narrative: "Memory pressure from low available memory",
	},
}

func init() {
	// Sort library by priority descending so matchPattern checks highest-priority first.
	sort.Slice(patternLibrary, func(i, j int) bool {
		return patternLibrary[i].Priority > patternLibrary[j].Priority
	})
}

// MatchPattern iterates the pattern library and returns the first matching pattern, or nil.
func MatchPattern(result *model.AnalysisResult) *Pattern {
	if result == nil {
		return nil
	}

	fired := collectFiredEvidence(result)
	if len(fired) == 0 {
		return nil
	}

	for i := range patternLibrary {
		pat := &patternLibrary[i]
		matched := 0
		for _, cond := range pat.Conditions {
			ev, ok := fired[cond.EvidenceID]
			if !ok {
				continue
			}
			minStr := cond.MinStrength
			if minStr == 0 {
				minStr = pat.MinStr
			}
			if minStr == 0 {
				minStr = 0.01
			}
			if ev.Strength >= minStr {
				matched++
			}
		}
		if matched >= pat.MinMatch {
			return pat
		}
	}
	return nil
}
