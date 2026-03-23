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
	priority int      // higher = checked first; cross-domain ~90, single-domain ~70, fallback ~50
}

// narrativeTemplates are sorted by priority descending; first match wins.
// Cross-domain cascades ~90, multi-signal single-domain ~70, single-signal ~50.
var narrativeTemplates = []narrativeRule{
	// Cross-domain (highest priority)
	{ids: []string{"mem.swap.activity", "io.psi"}, text: "Memory pressure causing IO storm via swap thrashing", priority: 95},
	{ids: []string{"mem.reclaim.direct", "io.disk.latency"}, text: "Memory reclaim driving disk latency", priority: 93},
	{ids: []string{"mem.oom.kills"}, text: "OOM crisis — kernel killing processes to free memory", priority: 92},
	{ids: []string{"mem.swap.activity", "mem.psi", "io.disk.latency"}, minMatch: 2, text: "Memory pressure cascading into IO latency via swap", priority: 90},

	// CPU multi-signal
	{ids: []string{"cpu.cgroup.throttle", "cpu.runqueue"}, text: "CPU throttle cascade — cgroup limits saturating run queue", priority: 80},
	{ids: []string{"cpu.cgroup.throttle", "cpu.psi"}, text: "CPU throttling — cgroup limits causing CPU pressure stalls", priority: 78},
	{ids: []string{"cpu.steal", "cpu.psi"}, text: "Noisy neighbor — hypervisor stealing CPU time", priority: 77},
	{ids: []string{"cpu.runqueue", "cpu.psi"}, text: "CPU saturation — run queue overloaded", priority: 75},
	// CPU single-signal
	{ids: []string{"cpu.psi"}, text: "CPU pressure — tasks stalling on CPU access", priority: 55},
	{ids: []string{"cpu.runqueue"}, text: "CPU contention — elevated run queue depth", priority: 53},
	{ids: []string{"cpu.sentinel.throttle"}, text: "CPU throttling detected by BPF sentinel", priority: 50},

	// Memory multi-signal
	{ids: []string{"mem.psi.acceleration", "mem.reclaim.direct"}, text: "Sudden memory pressure onset — PSI spiking with direct reclaim active", priority: 80},
	{ids: []string{"mem.slab.leak", "mem.available.low"}, text: "Kernel slab leak — unreclaimable memory growing, consuming available RAM", priority: 78},
	{ids: []string{"mem.alloc.stall", "mem.psi"}, text: "Allocation stall storm — processes blocking on memory allocation", priority: 77},
	{ids: []string{"mem.reclaim.direct", "mem.psi"}, text: "Direct reclaim storm — kernel blocking on memory allocation", priority: 76},
	{ids: []string{"mem.swap.activity", "mem.psi"}, text: "Swap thrashing — heavy swap IO causing memory pressure", priority: 75},
	{ids: []string{"mem.available.low", "mem.psi"}, text: "Memory exhaustion — available memory critically low", priority: 73},
	// Memory single-signal
	{ids: []string{"mem.available.low"}, text: "Memory pressure from low available memory", priority: 55},
	{ids: []string{"mem.psi"}, text: "Memory pressure — tasks stalling on allocation", priority: 53},
	{ids: []string{"mem.sentinel.oom"}, text: "OOM events detected by BPF sentinel", priority: 52},
	{ids: []string{"mem.sentinel.reclaim"}, text: "Direct reclaim events detected by BPF sentinel", priority: 50},

	// IO multi-signal / cross-domain
	{ids: []string{"cpu.iowait", "io.disk.latency", "io.psi"}, minMatch: 2, text: "CPU IOWait cascade — disk latency stalling CPU on IO completion", priority: 85},
	{ids: []string{"io.disk.queuedepth", "io.disk.latency"}, text: "Disk queue saturated — deep queue driving elevated latency", priority: 78},
	{ids: []string{"io.disk.util", "io.dstate", "io.disk.latency"}, minMatch: 2, text: "Disk IO saturation causing D-state threads", priority: 76},
	{ids: []string{"io.writeback", "io.disk.latency"}, text: "Writeback flood driving disk latency", priority: 73},
	{ids: []string{"io.psi", "io.dstate"}, text: "IO saturation — D-state processes accumulating", priority: 72},
	{ids: []string{"io.psi", "io.disk.latency"}, text: "IO pressure — elevated disk latency", priority: 70},
	// IO single-signal
	{ids: []string{"io.fsfull"}, text: "Filesystem nearing capacity", priority: 60},
	{ids: []string{"io.psi"}, text: "IO pressure — tasks stalling on disk access", priority: 53},

	// Security threats (high priority — always important)
	{ids: []string{"sec.synflood", "net.drops"}, text: "DDoS SYN flood — half-open connections exhausting resources and causing drops", priority: 88},
	{ids: []string{"sec.synflood"}, text: "SYN flood detected — high rate of unanswered SYN packets from single source", priority: 85},
	{ids: []string{"sec.portscan", "sec.tcp.flags"}, text: "Port scan with evasion — anomalous TCP flags indicate stealth scanning", priority: 83},
	{ids: []string{"sec.portscan"}, text: "Port scan detected — reconnaissance probing multiple ports", priority: 80},
	{ids: []string{"sec.dns.tunnel"}, text: "DNS tunneling — data exfiltration encoded in DNS queries", priority: 82},
	{ids: []string{"sec.beacon"}, text: "C2 beacon — periodic fixed-interval callbacks to external host", priority: 81},
	{ids: []string{"sec.outbound.exfil"}, text: "Data exfiltration — large outbound data volume to single destination", priority: 80},
	{ids: []string{"sec.lateral"}, text: "Lateral movement — process connecting to many internal hosts", priority: 79},

	// Network multi-signal / cross-domain
	{ids: []string{"net.ephemeral", "net.tcp.timewait"}, text: "Ephemeral port exhaustion — TIME_WAIT churn consuming available ports", priority: 78},
	{ids: []string{"net.tcp.synsent", "net.tcp.attemptfails"}, text: "Upstream unreachable — SYN_SENT accumulation with connection failures", priority: 77},
	{ids: []string{"net.drops.rx", "net.tcp.retrans"}, text: "Inbound buffer overflow — RX drops driving TCP retransmits", priority: 76},
	{ids: []string{"cpu.irq.imbalance", "net.drops"}, text: "IRQ imbalance — single CPU overloaded with network interrupts causing drops", priority: 85},
	{ids: []string{"net.tcp.retrans", "net.drops"}, text: "Network congestion — retransmits with packet drops", priority: 73},
	{ids: []string{"net.closewait"}, text: "Socket leak — CLOSE_WAIT accumulating, application not closing connections", priority: 70},
	{ids: []string{"net.conntrack", "net.drops"}, text: "Conntrack exhaustion — table full causing packet drops", priority: 75},
	// Network single-signal
	{ids: []string{"net.conntrack"}, text: "Conntrack table pressure — approaching capacity", priority: 55},
	{ids: []string{"net.tcp.retrans"}, text: "TCP retransmits elevated — possible network congestion", priority: 53},
	{ids: []string{"net.drops"}, text: "Packet drops detected — interface or kernel buffer overflows", priority: 52},
	{ids: []string{"net.sentinel.drops"}, text: "Packet drops detected by BPF sentinel", priority: 50},
	{ids: []string{"net.sentinel.resets"}, text: "TCP resets detected by BPF sentinel", priority: 50},
}

func init() {
	// Sort narrativeTemplates by priority descending for deterministic matching.
	sort.Slice(narrativeTemplates, func(i, j int) bool {
		return narrativeTemplates[i].priority > narrativeTemplates[j].priority
	})
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

	// Enrich narrative with statistical findings
	if len(result.BaselineAnomalies) > 0 {
		top := result.BaselineAnomalies[0]
		n.Evidence = append(n.Evidence, fmt.Sprintf("- %s deviating %.1f sigma from baseline (%.1f vs normal %.1f)",
			top.EvidenceID, top.Sigma, top.Value, top.Baseline))
	}
	if len(result.Correlations) > 0 {
		top := result.Correlations[0]
		n.Evidence = append(n.Evidence, fmt.Sprintf("- %s and %s correlated (r=%.2f, %s)",
			top.MetricA, top.MetricB, top.Coefficient, top.Strength))
	}
	if len(result.ProcessAnomalies) > 0 {
		top := result.ProcessAnomalies[0]
		n.Evidence = append(n.Evidence, fmt.Sprintf("- %s (PID %d) %s: %.1f vs baseline %.1f (%.1f sigma)",
			top.Comm, top.PID, top.Metric, top.Current, top.Baseline, top.Sigma))
	}

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

// selectTopEvidence picks the top N fired evidence lines, prioritizing
// evidence from the primary bottleneck domain. This prevents cross-domain
// noise (e.g., TCP retransmit showing in CPU bottleneck evidence).
func selectTopEvidence(result *model.AnalysisResult, n int) []string {
	primaryDomain := model.Domain("")
	if len(result.RCA) > 0 {
		// Map bottleneck name to domain
		switch result.RCA[0].Bottleneck {
		case BottleneckCPU:
			primaryDomain = model.DomainCPU
		case BottleneckMemory:
			primaryDomain = model.DomainMemory
		case BottleneckIO:
			primaryDomain = model.DomainIO
		case BottleneckNetwork:
			primaryDomain = model.DomainNetwork
		}
	}

	// Collect evidence, primary domain first
	var primary, secondary []model.Evidence
	seen := make(map[string]bool)
	for _, rca := range result.RCA {
		for _, ev := range rca.EvidenceV2 {
			if ev.Strength > 0 && !seen[ev.ID] {
				seen[ev.ID] = true
				if ev.Domain == primaryDomain {
					primary = append(primary, ev)
				} else {
					secondary = append(secondary, ev)
				}
			}
		}
	}

	sort.Slice(primary, func(i, j int) bool { return primary[i].Strength > primary[j].Strength })
	sort.Slice(secondary, func(i, j int) bool { return secondary[i].Strength > secondary[j].Strength })

	// Take from primary first, fill remaining from secondary
	var selected []model.Evidence
	for _, ev := range primary {
		if len(selected) >= n {
			break
		}
		selected = append(selected, ev)
	}
	for _, ev := range secondary {
		if len(selected) >= n {
			break
		}
		selected = append(selected, ev)
	}

	lines := make([]string, 0, len(selected))
	for _, ev := range selected {
		lines = append(lines, fmt.Sprintf("- %s", ev.Message))
	}
	return lines
}

// estimateImpact builds a human-readable impact narrative from system state.
// Translates raw metrics into production-level impact descriptions.
func estimateImpact(result *model.AnalysisResult, curr *model.Snapshot, rates *model.RateSnapshot) string {
	if curr == nil {
		return ""
	}

	var parts []string
	ncpu := curr.Global.CPU.NumCPUs
	if ncpu == 0 {
		ncpu = 1
	}

	// ── CPU impact ──
	cpuPSI := curr.Global.PSI.CPU.Some.Avg10
	if cpuPSI > 1 {
		effectiveCores := float64(ncpu) * (1 - cpuPSI/100)
		if effectiveCores < 0 {
			effectiveCores = 0
		}
		capacityLoss := fmt.Sprintf("%.0f%% CPU capacity lost (%d→%.1f effective cores)", cpuPSI, ncpu, effectiveCores)

		// Estimate latency impact from run queue
		rq := curr.Global.CPU.LoadAvg.Running
		if rq > uint64(ncpu) {
			queueRatio := float64(rq) / float64(ncpu)
			if queueRatio > 2 {
				capacityLoss += fmt.Sprintf(". Requests queueing %.0fx — response times ~%.0fx normal", queueRatio, queueRatio)
			} else {
				capacityLoss += fmt.Sprintf(". Run queue %d/%d — mild queueing, latency +%.0f%%", rq, ncpu, (queueRatio-1)*100)
			}
		}

		// Check for cgroup throttling detail
		for _, rca := range result.RCA {
			for _, ev := range rca.EvidenceV2 {
				if ev.ID == "cpu.cgroup.throttle" && ev.Strength > 0 {
					capacityLoss += ". Container CPU-throttled — request processing stalled during throttle windows"
					break
				}
			}
		}

		// Sustained vs spike
		load1 := curr.Global.CPU.LoadAvg.Load1
		load5 := curr.Global.CPU.LoadAvg.Load5
		if load5 > 0 && load1 > load5*1.5 {
			capacityLoss += ". Spike (1m load >> 5m) — may self-resolve"
		} else if load5 > 0 && load1 <= load5*1.1 && result.AnomalyStartedAgo > 30 {
			capacityLoss += fmt.Sprintf(". Sustained %ds — not a spike, intervention likely needed", result.AnomalyStartedAgo)
		}

		parts = append(parts, capacityLoss)
	}

	// ── Memory impact ──
	memPSI := curr.Global.PSI.Memory.Some.Avg10
	if memPSI > 1 {
		memImpact := fmt.Sprintf("%.0f%% memory pressure", memPSI)
		if rates != nil && rates.DirectReclaimRate > 100 {
			memImpact += fmt.Sprintf(" — kernel reclaiming %.0f pages/s, all allocations slowed", rates.DirectReclaimRate)
		}
		if rates != nil && (rates.SwapInRate+rates.SwapOutRate) > 10 {
			memImpact += fmt.Sprintf(". Swapping %.0f pages/s — severe latency for swapped processes", rates.SwapInRate+rates.SwapOutRate)
		}

		// OOM risk
		for _, ex := range result.Exhaustions {
			if ex.Resource == "Memory" || ex.Resource == "memory" {
				memImpact += fmt.Sprintf(". OOM kill risk in ~%.0fm if trend continues", ex.EstMinutes)
				break
			}
		}
		parts = append(parts, memImpact)
	}

	// ── IO impact ──
	ioPSI := curr.Global.PSI.IO.Full.Avg10
	if ioPSI > 1 {
		ioImpact := fmt.Sprintf("%.0f%% IO stall", ioPSI)
		// Find worst disk
		if rates != nil {
			var worstDisk string
			var worstUtil, worstAwait float64
			for _, d := range rates.DiskRates {
				if d.UtilPct > worstUtil {
					worstUtil = d.UtilPct
					worstAwait = d.AvgAwaitMs
					worstDisk = d.Name
				}
			}
			if worstUtil > 80 {
				ioImpact += fmt.Sprintf(" — %s at %.0f%% util, %.0fms await", worstDisk, worstUtil, worstAwait)
				if worstAwait > 20 {
					multiplier := worstAwait / 5.0 // assume 5ms is normal
					ioImpact += fmt.Sprintf(". Disk latency %.0fx normal — DB queries, file ops, logging all delayed", multiplier)
				}
			}
		}
		parts = append(parts, ioImpact)
	}

	// ── Network impact (only if significant) ──
	if rates != nil && rates.RetransRate > 50 {
		netImpact := fmt.Sprintf("TCP retransmits %.0f/s — connection quality degraded", rates.RetransRate)
		if rates.RetransRate > 500 {
			netImpact += ". Severe — client timeouts likely"
		}
		parts = append(parts, netImpact)
	}

	// ── Cross-reference with apps for concrete production impact ──
	if curr != nil && len(curr.Global.Apps.Instances) > 0 {
		for _, app := range curr.Global.Apps.Instances {
			if app.HealthScore >= 80 || !app.HasDeepMetrics {
				continue
			}
			dm := app.DeepMetrics
			switch app.AppType {
			case "redis":
				if p99 := dm["latency_percentiles_usec_p99"]; p99 != "" {
					var p99v float64
					fmt.Sscanf(p99, "%f", &p99v)
					if p99v > 5000 { // >5ms is bad for redis
						parts = append(parts, fmt.Sprintf("%s p99 latency %.1fms — client-facing reads/writes affected", app.DisplayName, p99v/1000))
					}
				}
			case "mysql", "postgresql":
				if sl := dm["slow_queries"]; sl != "" && sl != "0" {
					parts = append(parts, fmt.Sprintf("%s has %s slow queries — database throughput reduced", app.DisplayName, sl))
				}
			case "elasticsearch":
				if st := dm["status"]; st == "red" {
					parts = append(parts, fmt.Sprintf("%s cluster RED — search/indexing unavailable", app.DisplayName))
				}
			case "nginx", "haproxy":
				if e5 := dm["hrsp_5xx"]; e5 != "" && e5 != "0" {
					parts = append(parts, fmt.Sprintf("%s returning %s 5xx errors — users seeing failures", app.DisplayName, e5))
				}
			case "rabbitmq":
				if q := dm["queue_totals_messages"]; q != "" {
					var qv int
					fmt.Sscanf(q, "%d", &qv)
					if qv > 10000 {
						parts = append(parts, fmt.Sprintf("%s queue backlog %d msgs — async processing falling behind", app.DisplayName, qv))
					}
				}
			}
		}
	}

	// ── Exhaustion warnings ──
	for _, ex := range result.Exhaustions {
		if ex.EstMinutes > 0 && ex.EstMinutes < 120 {
			parts = append(parts, fmt.Sprintf("%s exhaustion in ~%.0fm — action needed before outage", ex.Resource, ex.EstMinutes))
		}
	}

	if len(parts) == 0 {
		return ""
	}
	// Join all parts into a detailed narrative. Keep up to 4 items.
	if len(parts) > 4 {
		parts = parts[:4]
	}
	return strings.Join(parts, ". ")
}
