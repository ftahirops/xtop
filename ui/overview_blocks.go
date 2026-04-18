package ui

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"
	"github.com/ftahirops/xtop/engine"
	"github.com/ftahirops/xtop/model"
	"github.com/ftahirops/xtop/util"
)

// ─── SHARED: TREND SPARKLINE ────────────────────────────────────────────────

func renderTrendBlock(result *model.AnalysisResult, history *engine.History, width int, _ bool) string {
	var sb strings.Builder
	n := history.Len()
	if n < 3 {
		sb.WriteString(titleStyle.Render(" Trend"))
		sb.WriteString(dimStyle.Render("  collecting..."))
		return sb.String()
	}

	oldest := history.Get(0)
	latest := history.Latest()
	durLabel := ""
	if oldest != nil && latest != nil {
		durLabel = fmt.Sprintf(" (%s)", formatDuration(latest.Timestamp.Sub(oldest.Timestamp)))
	}

	// Box inner width: total width - 5 for border chars (` │ ... │`)
	innerW := width - 7
	if innerW < 40 {
		innerW = 40
	}

	title := fmt.Sprintf(" %s ", titleStyle.Render(fmt.Sprintf("Trend%s", durLabel)))
	sb.WriteString(boxTopTitle(title, innerW) + "\n")

	// Sparkline chart width: inner width - label(8) - padding(2) - " now=XXX.X"(~12)
	chartW := innerW - 22
	if chartW < 10 {
		chartW = 10
	}

	// Collect all 16 series from snapshot + rate history
	cpuBusy := make([]float64, n)
	cpuIOWait := make([]float64, n)
	cpuSteal := make([]float64, n)
	cpuPSI := make([]float64, n)

	memUsed := make([]float64, n)
	memPSI := make([]float64, n)
	swapIO := make([]float64, n)
	reclaim := make([]float64, n)

	ioPSI := make([]float64, n)
	ioUtil := make([]float64, n)
	ioAwait := make([]float64, n)
	ioThru := make([]float64, n)

	netThru := make([]float64, n)
	netRetx := make([]float64, n)
	netDrops := make([]float64, n)
	netSoftIRQ := make([]float64, n)

	for i := 0; i < n; i++ {
		s := history.Get(i)
		if s == nil {
			continue
		}

		// PSI (from snapshot directly)
		cpuPSI[i] = s.Global.PSI.CPU.Some.Avg10
		memPSI[i] = s.Global.PSI.Memory.Full.Avg10
		ioPSI[i] = s.Global.PSI.IO.Full.Avg10

		// Memory used %
		if s.Global.Memory.Total > 0 {
			memUsed[i] = float64(s.Global.Memory.Total-s.Global.Memory.Available) / float64(s.Global.Memory.Total) * 100
		}

		// Rate-based metrics
		r := history.GetRate(i)
		if r == nil {
			continue
		}

		cpuBusy[i] = r.CPUBusyPct
		cpuIOWait[i] = r.CPUIOWaitPct
		cpuSteal[i] = r.CPUStealPct

		swapIO[i] = r.SwapInRate + r.SwapOutRate
		reclaim[i] = r.DirectReclaimRate

		// Worst disk util/await/throughput
		for _, d := range r.DiskRates {
			if d.UtilPct > ioUtil[i] {
				ioUtil[i] = d.UtilPct
				ioAwait[i] = d.AvgAwaitMs
			}
			ioThru[i] += d.ReadMBs + d.WriteMBs
		}

		// Network aggregates
		for _, nr := range r.NetRates {
			netThru[i] += nr.RxMBs + nr.TxMBs
			netDrops[i] += nr.RxDropsPS + nr.TxDropsPS
		}
		netRetx[i] = r.RetransRate
		netSoftIRQ[i] = r.CPUSoftIRQPct
	}

	line := func(label string, data []float64, maxV float64) {
		content := fmt.Sprintf("  %s %s", styledPad(dimStyle.Render(label), 8), sparkline(data, chartW, 0, maxV))
		sb.WriteString(boxRow(content, innerW) + "\n")
	}

	section := func(title string) {
		sb.WriteString(boxRow(titleStyle.Render(title), innerW) + "\n")
	}

	section("CPU")
	line("busy", cpuBusy, 100)
	line("iowait", cpuIOWait, 100)
	line("steal", cpuSteal, 100)
	line("PSI", cpuPSI, 50)

	sb.WriteString(boxMid(innerW) + "\n")
	section("Memory")
	line("used", memUsed, 100)
	line("PSI", memPSI, 50)
	line("swap", swapIO, 10)
	line("reclm", reclaim, 1000)

	sb.WriteString(boxMid(innerW) + "\n")
	section("Disk IO")
	line("PSI", ioPSI, 50)
	line("util", ioUtil, 100)
	line("await", ioAwait, 100)
	line("thru", ioThru, 500)

	// Derive network throughput max from link speed
	netThruMax := float64(100) // default 100 MB/s
	if latest != nil {
		for _, iface := range latest.Global.Network {
			if iface.SpeedMbps > 0 {
				// Convert Mbps to MB/s (divide by 8)
				ifaceMaxMBs := float64(iface.SpeedMbps) / 8
				if ifaceMaxMBs > netThruMax {
					netThruMax = ifaceMaxMBs
				}
			}
		}
	}

	sb.WriteString(boxMid(innerW) + "\n")
	section("Network")
	line("thru", netThru, netThruMax)
	line("retx", netRetx, 100)
	line("drops", netDrops, 100)
	line("softirq", netSoftIRQ, 100)

	sb.WriteString(boxBot(innerW) + "\n")

	return sb.String()
}

// ─── SHARED: OWNERS BLOCK ───────────────────────────────────────────────────

func renderOwnersBlock(result *model.AnalysisResult, width int) string {
	var sb strings.Builder

	innerW := width - 7
	if innerW < 40 {
		innerW = 40
	}
	if innerW > 200 {
		innerW = 200
	}
	var lines []string

	renderLine := func(resource string, owners []model.Owner) {
		label := styledPad(headerStyle.Render(resource+":"), colOwLbl+1)
		if len(owners) == 0 {
			lines = append(lines, label+dimStyle.Render("\u2014"))
			return
		}
		// Calculate max name width based on available space
		// Each owner takes ~"name:value | " — fit as many as possible
		maxName := (innerW - 8) / 3 // divide among up to 3 owners
		if maxName < 16 {
			maxName = 16
		}
		if maxName > 40 {
			maxName = 40
		}
		parts := make([]string, 0, 3)
		for i, o := range owners {
			if i >= 3 {
				break
			}
			name := truncate(o.Name, maxName)
			parts = append(parts, valueStyle.Render(name)+dimStyle.Render(":"+o.Value))
		}
		lines = append(lines, label+strings.Join(parts, dimStyle.Render(" | ")))
	}

	if result == nil {
		renderLine("IO", nil)
		renderLine("CPU", nil)
		renderLine("MEM", nil)
		renderLine("NET", nil)
	} else {
		renderLine("IO", result.IOOwners)
		renderLine("CPU", result.CPUOwners)
		renderLine("MEM", result.MemOwners)
		renderLine("NET", result.NetOwners)
	}

	title := fmt.Sprintf(" %s ", titleStyle.Render("Top Resource Owners"))
	sb.WriteString(boxTopTitle(title, innerW) + "\n")
	for _, l := range lines {
		sb.WriteString(boxRow(l, innerW) + "\n")
	}
	sb.WriteString(boxBot(innerW) + "\n")
	return sb.String()
}

// ─── SHARED: RCA BOX ────────────────────────────────────────────────────────

func renderRCABox(result *model.AnalysisResult, width int) string {
	var sb strings.Builder

	innerW := width - 7
	if innerW < 40 {
		innerW = 40
	}
	if innerW > 200 {
		innerW = 200
	}

	title := fmt.Sprintf(" %s ", titleStyle.Render("Root Cause Analysis"))
	sb.WriteString(boxTopTitle(title, innerW) + "\n")

	if result == nil {
		sb.WriteString(boxRow(dimStyle.Render("collecting..."), innerW) + "\n")
		sb.WriteString(boxBot(innerW) + "\n")
		return sb.String()
	}

	switch result.Health {
	case model.HealthOK:
		stableLine := ""
		if result.StableSince > 60 {
			stableLine = "  Stable for " + fmtDuration(result.StableSince)
		}
		sb.WriteString(boxRow(okStyle.Render("\u25cf")+"  No bottleneck detected", innerW) + "\n")
		if stableLine != "" {
			sb.WriteString(boxRow(dimStyle.Render(stableLine), innerW) + "\n")
		}

	case model.HealthInconclusive:
		sb.WriteString(boxRow(orangeStyle.Render("\u25cc")+"  Inconclusive "+dimStyle.Render("\u2014 evidence insufficient"), innerW) + "\n")
		sb.WriteString(boxRow(dimStyle.Render("  Press I to run 10s eBPF deep dive"), innerW) + "\n")

	case model.HealthDegraded, model.HealthCritical:
		sevStyle := warnStyle
		if result.Health == model.HealthCritical {
			sevStyle = critStyle
		}
		// Field width: leave room for label (7 chars) + box padding
		maxField := innerW - 8
		if maxField < 30 {
			maxField = 30
		}

		// --- WHAT: short bottleneck name only ---
		whatStr := result.PrimaryBottleneck
		sb.WriteString(boxRow(dimStyle.Render("WHAT:  ")+sevStyle.Render(truncate(whatStr, maxField)), innerW) + "\n")

		// --- WHY: narrative root cause (human explanation, not raw metrics) ---
		why := ""
		if result.Narrative != nil && result.Narrative.RootCause != "" {
			why = result.Narrative.RootCause
		}
		if why != "" && why != whatStr {
			sb.WriteString(boxRow(dimStyle.Render("WHY:   ")+valueStyle.Render(truncate(why, maxField)), innerW) + "\n")
		}

		// --- WHO: culprit process ---
		culprit := ""
		if result.PrimaryAppName != "" {
			culprit = result.PrimaryAppName
			if result.PrimaryPID > 0 {
				culprit = fmt.Sprintf("%s (PID %d)", result.PrimaryAppName, result.PrimaryPID)
			}
		} else if result.PrimaryProcess != "" {
			culprit = result.PrimaryProcess
			if result.PrimaryPID > 0 {
				culprit = fmt.Sprintf("%s (PID %d)", result.PrimaryProcess, result.PrimaryPID)
			}
		} else if result.PrimaryCulprit != "" && result.PrimaryCulprit != "/" {
			culprit = result.PrimaryCulprit
		}
		if culprit != "" {
			sb.WriteString(boxRow(dimStyle.Render("WHO:   ")+valueStyle.Render(truncate(culprit, maxField)), innerW) + "\n")
		}

		// --- SINCE: duration + confidence (keep short, one line) ---
		sinceStr := ""
		if result.AnomalyStartedAgo > 0 {
			sinceStr = fmtDuration(result.AnomalyStartedAgo) + " ago"
		}
		confStr := fmt.Sprintf("%d%%", result.Confidence)
		sinceLine := dimStyle.Render("SINCE: ") + sevStyle.Render(sinceStr) + dimStyle.Render(" | Conf: ") + sevStyle.Render(confStr)
		if result.Narrative != nil && result.Narrative.Pattern != "" {
			sinceLine += dimStyle.Render(" | ") + dimStyle.Render(truncate(result.Narrative.Pattern, 25))
		}
		sb.WriteString(boxRow(sinceLine, innerW) + "\n")

		// --- Evidence section ---
		if result.Narrative != nil && len(result.Narrative.Evidence) > 0 {
			sb.WriteString(boxRow("", innerW) + "\n")
			secHdr := dimStyle.Render("\u2500\u2500 ") + titleStyle.Render("Evidence") + dimStyle.Render(" "+strings.Repeat("\u2500", innerW-14))
			sb.WriteString(boxRow(secHdr, innerW) + "\n")
			for i, ev := range result.Narrative.Evidence {
				if i >= 4 {
					break
				}
				human := humanizeEvidence(ev)
				sb.WriteString(boxRow(dimStyle.Render("\u25b8 ")+valueStyle.Render(truncate(human, innerW-4)), innerW) + "\n")
			}
		}

		// --- Impact section ---
		if result.Narrative != nil && result.Narrative.Impact != "" {
			sb.WriteString(boxRow("", innerW) + "\n")
			secHdr := dimStyle.Render("\u2500\u2500 ") + titleStyle.Render("Impact") + dimStyle.Render(" "+strings.Repeat("\u2500", innerW-12))
			sb.WriteString(boxRow(secHdr, innerW) + "\n")
			sb.WriteString(boxRow(warnStyle.Render(truncate(result.Narrative.Impact, innerW-2)), innerW) + "\n")
		}

		// --- Timeline section ---
		timeline := buildRCATimeline(result)
		if len(timeline) > 0 {
			sb.WriteString(boxRow("", innerW) + "\n")
			secHdr := dimStyle.Render("\u2500\u2500 ") + titleStyle.Render("Timeline") + dimStyle.Render(" "+strings.Repeat("\u2500", innerW-14))
			sb.WriteString(boxRow(secHdr, innerW) + "\n")
			for _, te := range timeline {
				offset := styledPad(dimStyle.Render(te.Offset), 9)
				marker := te.Style.Render("\u25aa")
				suffix := ""
				if te.Current {
					suffix = dimStyle.Render(" \u2190 CURRENT")
					marker = sevStyle.Render("\u25ab")
				}
				event := humanizeEvidence(te.Event)
				sb.WriteString(boxRow(offset+" "+marker+" "+valueStyle.Render(truncate(event, innerW-16))+suffix, innerW) + "\n")
			}
		}

		// --- Next Steps section ---
		steps := suggestNextSteps(result)
		if len(steps) > 0 {
			sb.WriteString(boxRow("", innerW) + "\n")
			secHdr := dimStyle.Render("\u2500\u2500 ") + titleStyle.Render("Next Steps") + dimStyle.Render(" "+strings.Repeat("\u2500", innerW-16))
			sb.WriteString(boxRow(secHdr, innerW) + "\n")
			for i, step := range steps {
				sb.WriteString(boxRow(dimStyle.Render(fmt.Sprintf("%d. ", i+1))+valueStyle.Render(truncate(step, innerW-6)), innerW) + "\n")
			}
		}
	}

	sb.WriteString(boxBot(innerW) + "\n")
	return sb.String()
}

// timelineEntry represents one event in the visual RCA timeline.
type timelineEntry struct {
	Offset  string         // e.g. "-4m30s", "now"
	Event   string
	Style   lipgloss.Style
	Current bool
}

// buildRCATimeline constructs a visual timeline from temporal chain or narrative evidence.
func buildRCATimeline(result *model.AnalysisResult) []timelineEntry {
	var entries []timelineEntry

	// Prefer structured temporal chain events
	if result.TemporalChain != nil && len(result.TemporalChain.Events) > 0 {
		now := time.Now()
		for _, ev := range result.TemporalChain.Events {
			offset := "-" + fmtDuration(int(now.Sub(ev.FirstSeen).Seconds()))
			if now.Sub(ev.FirstSeen).Seconds() < 3 {
				offset = "now"
			}
			entries = append(entries, timelineEntry{
				Offset:  offset,
				Event:   ev.Label,
				Style:   warnStyle,
				Current: offset == "now",
			})
		}
	} else if result.Narrative != nil && result.Narrative.Temporal != "" {
		// Fall back: parse the temporal summary string (format: "signal (T+0s) -> signal (T+3s)")
		parts := strings.Split(result.Narrative.Temporal, " \u2192 ")
		if len(parts) <= 1 {
			parts = strings.Split(result.Narrative.Temporal, " -> ")
		}
		for i, p := range parts {
			p = strings.TrimSpace(p)
			if p == "" {
				continue
			}
			isCurrent := i == len(parts)-1
			style := warnStyle
			if isCurrent {
				style = critStyle
			}
			entries = append(entries, timelineEntry{
				Offset:  fmt.Sprintf("T+%d", i),
				Event:   p,
				Style:   style,
				Current: isCurrent,
			})
		}
	}

	// If we still have nothing, build from anomaly start + evidence
	if len(entries) == 0 && result.AnomalyStartedAgo > 0 {
		entries = append(entries, timelineEntry{
			Offset: "-" + fmtDuration(result.AnomalyStartedAgo),
			Event:  "Anomaly onset: " + result.PrimaryBottleneck,
			Style:  warnStyle,
		})
		if result.Narrative != nil && len(result.Narrative.Evidence) > 0 {
			entries = append(entries, timelineEntry{
				Offset:  "now",
				Event:   result.Narrative.Evidence[0],
				Style:   critStyle,
				Current: true,
			})
		}
	}

	// Cap at 5 entries
	if len(entries) > 5 {
		entries = entries[len(entries)-5:]
	}
	return entries
}

// suggestNextSteps generates actionable investigation steps based on the bottleneck domain.
func suggestNextSteps(result *model.AnalysisResult) []string {
	if result == nil {
		return nil
	}
	var steps []string
	// Match against exact bottleneck names to avoid substring collisions
	// ("CPU Contention" contains "io" in "content-io-n" which falsely matched IO)
	domain := result.PrimaryBottleneck
	appName := strings.ToLower(result.PrimaryAppName)

	_ = appName
	switch domain {
	case "IO Starvation":
		steps = append(steps, "Press 3 → IO detail (per-device latency, IOPS, queue)")
		steps = append(steps, "Press 8 → Probe results (IO latency histograms)")
		steps = append(steps, "Press I → Run eBPF IO latency deep dive (10s)")

	case "Memory Pressure":
		steps = append(steps, "Press 2 → Memory detail (swap, reclaim, page faults)")
		steps = append(steps, "Press 5 → CGroups (which group is consuming memory)")
		steps = append(steps, "Press I → Run eBPF off-CPU analysis (10s)")

	case "CPU Contention":
		steps = append(steps, "Press 1 → CPU detail (per-process breakdown, throttle)")
		steps = append(steps, "Press 5 → CGroups (which group is throttled)")
		steps = append(steps, "Press I → Run eBPF off-CPU analysis (10s)")

	case "Network Overload":
		steps = append(steps, "Press 4 → Network detail (drops, retransmits, conntrack)")
		steps = append(steps, "Press L → Security (attack detection, port scans)")
		steps = append(steps, "Press I → Run eBPF deep dive (10s)")

	default:
		steps = append(steps, "Press I → Run eBPF deep dive (10s)")
	}

	// Always ensure probe suggestion is present
	hasProbe := false
	for _, s := range steps {
		if strings.Contains(s, "Press I") {
			hasProbe = true
			break
		}
	}
	if !hasProbe {
		steps = append(steps, "Press I to run 10s eBPF deep dive")
	}

	// Limit to 3 steps
	if len(steps) > 3 {
		steps = steps[:3]
	}
	return steps
}

// humanizeEvidence transforms raw engine evidence strings into plain English.
// Input:  "- CPU PSI some=75.2% full=0.0%"
// Output: "CPU pressure: 75.2% of time, tasks stalled waiting for CPU"
func humanizeEvidence(raw string) string {
	s := strings.TrimPrefix(raw, "- ")
	s = strings.TrimSpace(s)
	low := strings.ToLower(s)

	// CPU evidence
	if strings.HasPrefix(low, "cpu psi") {
		if idx := strings.Index(s, "some="); idx >= 0 {
			val := extractNum(s[idx+5:])
			return fmt.Sprintf("CPU pressure: %.0f%% of time, tasks stalled waiting for CPU", val)
		}
	}
	if strings.HasPrefix(low, "cpu busy=") {
		val := extractNum(s[9:])
		return fmt.Sprintf("CPU utilization: %.0f%% (all cores)", val)
	}
	if strings.HasPrefix(low, "runqueue ratio=") {
		if idx := strings.Index(s, "("); idx >= 0 {
			detail := strings.TrimSuffix(s[idx:], ")")
			return fmt.Sprintf("Run queue overloaded: %s tasks competing for cores", strings.TrimPrefix(detail, "("))
		}
		return "Run queue: more tasks than available CPU cores"
	}
	if strings.HasPrefix(low, "cpu steal=") {
		val := extractNum(s[10:])
		return fmt.Sprintf("Hypervisor stealing %.0f%% of CPU time (noisy neighbor)", val)
	}
	if strings.HasPrefix(low, "cpu iowait=") {
		val := extractNum(s[11:])
		return fmt.Sprintf("%.0f%% CPU time waiting on disk IO", val)
	}
	if strings.HasPrefix(low, "ctx switches=") {
		return "High context switch rate: excessive task scheduling"
	}
	if strings.HasPrefix(low, "cgroup throttle=") {
		return "Cgroup CPU limit reached: processes being throttled"
	}
	if strings.HasPrefix(low, "bpf throttle=") {
		return "CPU throttling detected by eBPF sentinel"
	}

	// Memory evidence
	if strings.HasPrefix(low, "mem psi") || strings.HasPrefix(low, "memory psi") {
		if idx := strings.Index(s, "some="); idx >= 0 {
			val := extractNum(s[idx+5:])
			return fmt.Sprintf("Memory pressure: %.0f%% of time, tasks stalled on memory", val)
		}
	}
	if strings.HasPrefix(low, "mem available=") || strings.HasPrefix(low, "avail=") {
		return "Low available memory: system running out of free pages"
	}
	if strings.Contains(low, "swap in=") || strings.Contains(low, "swap out=") {
		return "Active swapping: memory pages moving to/from disk (slow)"
	}
	if strings.Contains(low, "direct reclaim") || strings.Contains(low, "reclaim=") {
		return "Kernel actively reclaiming memory pages (high pressure)"
	}
	if strings.Contains(low, "oom") {
		return "OOM killer active: system ran out of memory"
	}
	if strings.Contains(low, "slab leak") {
		return "Kernel slab memory growing abnormally (possible leak)"
	}

	// IO evidence
	if strings.HasPrefix(low, "io psi") {
		if idx := strings.Index(s, "some="); idx >= 0 {
			val := extractNum(s[idx+5:])
			return fmt.Sprintf("IO pressure: %.0f%% of time, tasks stalled on disk", val)
		}
	}
	if strings.Contains(low, "disk util=") || strings.Contains(low, "utilization=") {
		return "Disk utilization near 100%: IO requests queueing"
	}
	if strings.Contains(low, "disk latency=") || strings.Contains(low, "await=") {
		if idx := strings.Index(low, "="); idx >= 0 {
			val := extractNum(s[idx+1:])
			if val > 0 {
				return fmt.Sprintf("Disk latency: %.0fms per IO operation (normal <5ms)", val)
			}
		}
		return "Elevated disk latency"
	}
	if strings.Contains(low, "d-state=") || strings.Contains(low, "d-state tasks") {
		return "Processes stuck in D-state (uninterruptible sleep waiting for IO)"
	}
	if strings.Contains(low, "queue depth=") || strings.Contains(low, "qdepth=") {
		return "Disk IO queue building up: requests waiting to be served"
	}
	if strings.Contains(low, "dirty pages") || strings.Contains(low, "dirty=") {
		return "Large dirty page cache: pending writes to disk"
	}

	// Network evidence
	if strings.Contains(low, "retrans") {
		return "TCP retransmissions: packets being resent (network quality issue)"
	}
	if strings.Contains(low, "drops") && !strings.Contains(low, "benign") {
		return "Packet drops detected: network buffer overflow or filtering"
	}
	if strings.Contains(low, "conntrack") {
		return "Connection tracking table pressure (firewall state table)"
	}
	if strings.Contains(low, "softirq") {
		return "High kernel network processing overhead (softIRQ)"
	}
	if strings.Contains(low, "tcp reset") {
		return "TCP connections being reset: peer refusing or timing out"
	}

	// Security evidence
	if strings.Contains(low, "lateral movement") {
		return "Lateral movement pattern: unusual outbound connections"
	}
	if strings.Contains(low, "syn flood") || strings.Contains(low, "synflood") {
		return "SYN flood detected: possible DDoS attack"
	}
	if strings.Contains(low, "port scan") || strings.Contains(low, "portscan") {
		return "Port scan detected: reconnaissance activity"
	}
	if strings.Contains(low, "beacon") {
		return "Beacon pattern detected: possible C2 communication"
	}

	// Statistical evidence
	if strings.Contains(low, "deviating") && strings.Contains(low, "sigma") {
		return strings.Replace(s, "- ", "", 1) // already somewhat readable
	}
	if strings.Contains(low, "correlated") {
		return strings.Replace(s, "- ", "", 1)
	}

	// App-specific (already formatted by narrative_apps.go)
	if strings.HasPrefix(s, "[") {
		return s
	}

	// Probe evidence
	if strings.Contains(low, "off-cpu") || strings.Contains(low, "offcpu") {
		return s // already formatted by probe
	}

	// Default: strip leading "- " and return
	return strings.TrimPrefix(s, "- ")
}

// extractNum extracts the first float from a string like "75.2% foo".
func extractNum(s string) float64 {
	s = strings.TrimSpace(s)
	end := 0
	for end < len(s) && (s[end] >= '0' && s[end] <= '9' || s[end] == '.') {
		end++
	}
	if end == 0 {
		return 0
	}
	v, _ := strconv.ParseFloat(s[:end], 64)
	return v
}

// ─── SHARED: CAPACITY BLOCK ─────────────────────────────────────────────────

func renderCapacityBlock(result *model.AnalysisResult, withBars bool, barW int, width int, intermediate ...bool) string {
	isIntermediate := len(intermediate) > 0 && intermediate[0]
	var sb strings.Builder

	innerW := width - 7
	if innerW < 40 {
		innerW = 40
	}
	if innerW > 200 {
		innerW = 200
	}

	title := fmt.Sprintf(" %s ", titleStyle.Render("Capacity Remaining"))

	if result == nil {
		sb.WriteString(boxTopTitle(title, innerW) + "\n")
		sb.WriteString(boxRow(dimStyle.Render("collecting..."), innerW) + "\n")
		sb.WriteString(boxBot(innerW) + "\n")
		return sb.String()
	}

	// Header
	if withBars {
		hdr := fmt.Sprintf("%s %s %s  %s",
			styledPad(dimStyle.Render("Resource"), colKey),
			styledPad("", barW),
			styledPad(dimStyle.Render("Free"), 6),
			dimStyle.Render("Current / Limit"))
		sb.WriteString(boxTopTitle(title, innerW) + "\n")
		sb.WriteString(boxRow(hdr, innerW) + "\n")
	} else {
		sb.WriteString(boxTopTitle(title, innerW) + "\n")
	}

	for _, cap := range result.Capacities {
		style := dimStyle
		if cap.Pct < 15 {
			style = critStyle
		} else if cap.Pct < 30 {
			style = warnStyle
		}

		capLabel := cap.Label
		if isIntermediate {
			switch capLabel {
			case "Conntrack":
				capLabel = "Conntrack (connection tracker)"
			case "Ephemeral ports":
				capLabel = "Ephemeral ports (outbound connections)"
			case "File descriptors":
				capLabel = "File descriptors (open files/sockets)"
			case "MemAvailable":
				capLabel = "Memory available"
			}
		}
		lbl := styledPad(capLabel, colKey)
		var content string
		if withBars {
			limitInfo := ""
			if cap.Current != "" && cap.Limit != "" {
				limitInfo = dimStyle.Render(fmt.Sprintf("  %s / %s", cap.Current, cap.Limit))
			} else if cap.Current != "" {
				limitInfo = dimStyle.Render(fmt.Sprintf("  %s", cap.Current))
			}
			content = fmt.Sprintf("%s %s %s%s",
				lbl,
				capacityBar(cap.Pct, barW),
				style.Render(fmtPct(cap.Pct)),
				limitInfo)
		} else {
			content = fmt.Sprintf("%s %s",
				lbl,
				style.Render(fmtPct(cap.Pct)))
			if cap.Current != "" && cap.Limit != "" {
				content += dimStyle.Render(fmt.Sprintf("  %s / %s", cap.Current, cap.Limit))
			} else if cap.Current != "" {
				content += dimStyle.Render(fmt.Sprintf("  %s", cap.Current))
			}
		}
		sb.WriteString(boxRow(content, innerW) + "\n")
	}
	sb.WriteString(boxBot(innerW) + "\n")
	return sb.String()
}

// capacityBar renders a green/yellow/red bar based on remaining capacity.
func capacityBar(pct float64, width int) string {
	if pct < 0 {
		pct = 0
	}
	if pct > 100 {
		pct = 100
	}
	filled := int(pct / 100 * float64(width))
	if filled > width {
		filled = width
	}
	filledStr := strings.Repeat("█", filled)
	emptyStr := strings.Repeat("░", width-filled)
	style := okStyle
	if pct < 15 {
		style = critStyle
	} else if pct < 30 {
		style = warnStyle
	}
	return style.Render(filledStr) + dimStyle.Render(emptyStr)
}

// ─── SHARED: EXHAUSTION WARNINGS ────────────────────────────────────────────

func renderExhaustionBlock(result *model.AnalysisResult, width int) string {
	var sb strings.Builder

	innerW := width - 7
	if innerW < 40 {
		innerW = 40
	}
	if innerW > 200 {
		innerW = 200
	}

	title := fmt.Sprintf(" %s ", titleStyle.Render("Exhaustion Warnings"))
	sb.WriteString(boxTopTitle(title, innerW) + "\n")
	if result == nil || len(result.Exhaustions) == 0 {
		sb.WriteString(boxRow(dimStyle.Render("none"), innerW) + "\n")
	} else {
		for _, ex := range result.Exhaustions {
			confPct := int(ex.Confidence * 100)
			content := critStyle.Render(fmt.Sprintf("!! %s exhaustion in ~%.0fm", ex.Resource, ex.EstMinutes)) +
				dimStyle.Render(fmt.Sprintf("  (%.0f%%, +%.2f%%/s, conf %d%%)", ex.CurrentPct, ex.TrendPerS, confPct))
			sb.WriteString(boxRow(content, innerW) + "\n")
		}
	}
	sb.WriteString(boxBot(innerW) + "\n")
	return sb.String()
}

// ─── SHARED: WHAT CHANGED BLOCK ─────────────────────────────────────────────

func renderChangesBlock(result *model.AnalysisResult, width int) string {
	var sb strings.Builder

	innerW := width - 7
	if innerW < 40 {
		innerW = 40
	}
	if innerW > 200 {
		innerW = 200
	}

	title := fmt.Sprintf(" %s ", titleStyle.Render("What Changed (30s)"))
	sb.WriteString(boxTopTitle(title, innerW) + "\n")
	if result == nil || len(result.TopChanges) == 0 {
		sb.WriteString(boxRow(dimStyle.Render("no significant changes"), innerW) + "\n")
	} else {
		for _, c := range result.TopChanges {
			arrow := okStyle.Render("\u2193") // ↓
			if c.Rising {
				arrow = critStyle.Render("\u2191") // ↑
			}
			sign := ""
			if c.Rising {
				sign = "+"
			}
			pctStr := fmt.Sprintf("%s%.0f%%", sign, c.DeltaPct)
			style := dimStyle
			absPct := c.DeltaPct
			if absPct < 0 {
				absPct = -absPct
			}
			if absPct > 50 {
				style = critStyle
			} else if absPct > 20 {
				style = warnStyle
			}
			content := fmt.Sprintf(" %s %s %s  now %s",
				arrow,
				styledPad(valueStyle.Render(c.Name), 18),
				styledPad(style.Render(pctStr), 8),
				dimStyle.Render(c.Current))
			sb.WriteString(boxRow(content, innerW) + "\n")
		}
	}
	sb.WriteString(boxBot(innerW) + "\n")
	return sb.String()
}

func renderChangesInline(result *model.AnalysisResult) string {
	var sb strings.Builder
	sb.WriteString(" ")
	sb.WriteString(titleStyle.Render("Changed:"))
	sb.WriteString(" ")

	if result == nil || len(result.TopChanges) == 0 {
		sb.WriteString(dimStyle.Render("no significant changes"))
		sb.WriteString("\n")
		return sb.String()
	}

	parts := []string{}
	for i, c := range result.TopChanges {
		if i >= 5 {
			break
		}
		arrow := "\u2193"
		if c.Rising {
			arrow = "\u2191"
		}
		sign := ""
		if c.Rising {
			sign = "+"
		}
		parts = append(parts, fmt.Sprintf("%s%s %s%.0f%%", arrow, c.Name, sign, c.DeltaPct))
	}
	sb.WriteString(dimStyle.Render(strings.Join(parts, " | ")))
	sb.WriteString("\n")
	return sb.String()
}

// ─── SHARED: SUGGESTED ACTIONS BLOCK ─────────────────────────────────────────

func renderActionsBlock(result *model.AnalysisResult, width int) string {
	var sb strings.Builder

	innerW := width - 7
	if innerW < 40 {
		innerW = 40
	}
	if innerW > 200 {
		innerW = 200
	}

	title := fmt.Sprintf(" %s ", titleStyle.Render("Suggested Actions"))
	sb.WriteString(boxTopTitle(title, innerW) + "\n")
	if result == nil || len(result.Actions) == 0 {
		sb.WriteString(boxRow(dimStyle.Render("no actions — system healthy"), innerW) + "\n")
	} else {
		shown := result.Actions
		if len(shown) > 5 {
			shown = shown[:5]
		}
		maxSummary := innerW - 8 // "│ N. <summary> │"
		if maxSummary < 40 {
			maxSummary = 40
		}
		maxCmd := innerW - 10 // "│    $ <cmd> │"
		if maxCmd < 40 {
			maxCmd = 40
		}
		for i, a := range shown {
			// Word-wrap long summaries across multiple lines
			summary := a.Summary
			if len(summary) <= maxSummary {
				content := fmt.Sprintf(" %s %s", orangeStyle.Render(fmt.Sprintf("%d.", i+1)), summary)
				sb.WriteString(boxRow(content, innerW) + "\n")
			} else {
				// First line with number prefix
				content := fmt.Sprintf(" %s %s", orangeStyle.Render(fmt.Sprintf("%d.", i+1)), summary[:maxSummary])
				sb.WriteString(boxRow(content, innerW) + "\n")
				// Continuation lines indented
				rest := summary[maxSummary:]
				for len(rest) > 0 {
					chunk := rest
					if len(chunk) > maxSummary {
						chunk = rest[:maxSummary]
					}
					sb.WriteString(boxRow("    "+chunk, innerW) + "\n")
					rest = rest[len(chunk):]
				}
			}
			if a.Command != "" {
				cmd := a.Command
				if len(cmd) > maxCmd {
					cmd = cmd[:maxCmd-3] + "..."
				}
				sb.WriteString(boxRow(dimStyle.Render("    $ "+cmd), innerW) + "\n")
			}
		}
	}
	sb.WriteString(boxBot(innerW) + "\n")
	return sb.String()
}

// ─── SHARED: DEGRADATION BLOCK ──────────────────────────────────────────────

func renderDegradationBlock(result *model.AnalysisResult, width int) string {
	if result == nil || len(result.Degradations) == 0 {
		return ""
	}

	var sb strings.Builder

	innerW := width - 7
	if innerW < 40 {
		innerW = 40
	}
	if innerW > 200 {
		innerW = 200
	}

	title := fmt.Sprintf(" %s ", titleStyle.Render("Slow Degradation"))
	sb.WriteString(boxTopTitle(title, innerW) + "\n")
	for _, d := range result.Degradations {
		dur := fmtDuration(d.Duration)
		content := warnStyle.Render(fmt.Sprintf(" %s %s", d.Metric, d.Direction)) +
			dimStyle.Render(fmt.Sprintf("  %.2f %s for %s", d.Rate, d.Unit, dur))
		sb.WriteString(boxRow(content, innerW) + "\n")
	}
	sb.WriteString(boxBot(innerW) + "\n")
	return sb.String()
}

// ─── SHARED: INLINE BLOCKS (fixed-size for layouts C/D) ─────────────────────

// renderRCAInline renders a single-line RCA status. Always produces exactly 1 line.
func renderRCAInline(result *model.AnalysisResult) string {
	var sb strings.Builder
	sb.WriteString(" ")
	sb.WriteString(titleStyle.Render("RCA:"))
	sb.WriteString(" ")

	if result == nil {
		sb.WriteString(dimStyle.Render("collecting..."))
		sb.WriteString("\n")
		return sb.String()
	}

	switch result.Health {
	case model.HealthOK:
		sb.WriteString(okStyle.Render("No bottleneck detected"))

	case model.HealthInconclusive:
		sb.WriteString(orangeStyle.Render("Inconclusive"))
		sb.WriteString(dimStyle.Render(" \u2014 evidence insufficient"))
		sb.WriteString(dimStyle.Render(" | Press I to investigate"))

	case model.HealthDegraded, model.HealthCritical:
		style := warnStyle
		if result.Health == model.HealthCritical {
			style = critStyle
		}

		// Use narrative root cause if available, otherwise fall back to PrimaryBottleneck
		rootCause := result.PrimaryBottleneck
		if result.Narrative != nil && result.Narrative.RootCause != "" {
			rootCause = truncate(result.Narrative.RootCause, 60)
		}
		sb.WriteString(style.Render(rootCause))

		culprit := "\u2014"
		if result.PrimaryAppName != "" {
			culprit = truncate(result.PrimaryAppName, 30)
		} else if result.PrimaryProcess != "" {
			culprit = truncate(result.PrimaryProcess, 24)
		} else if result.PrimaryCulprit != "" && result.PrimaryCulprit != "/" {
			culprit = truncate(result.PrimaryCulprit, 24)
		}
		sb.WriteString(dimStyle.Render(" | Culprit: "))
		sb.WriteString(valueStyle.Render(culprit))
		sb.WriteString(dimStyle.Render(fmt.Sprintf(" | Confidence: %d%%", result.Confidence)))

		if result.AnomalyStartedAgo > 0 {
			sb.WriteString(dimStyle.Render(" | Active: "))
			sb.WriteString(critStyle.Render(fmtDuration(result.AnomalyStartedAgo)))
		}
	}

	sb.WriteString("\n")
	return sb.String()
}

// isBenignSentinelDrop returns true for drop reasons that are normal TCP lifecycle,
// not actual problems. These are excluded from the overview headline.
func isBenignSentinelDrop(reason string) bool {
	return util.IsBenignDropReason(reason)
}

// renderProbeStatusLine renders the sentinel + probe status. Always produces exactly 1 line.
// Pass nil for idle state (no probe engine available yet).
func renderProbeStatusLine(pm probeQuerier, snap *model.Snapshot, intermediate bool) string {
	var sb strings.Builder
	sb.WriteString(" ")

	// Sentinel status
	if snap != nil && snap.Global.Sentinel.Active {
		sb.WriteString(titleStyle.Render("Sentinel:"))
		sb.WriteString(" ")
		sent := snap.Global.Sentinel

		// Calculate real (non-benign) drop rate for severity
		realDropRate := float64(0)
		for _, d := range sent.PktDrops {
			if !d.Benign {
				realDropRate += d.Rate
			}
		}

		// Show key rates with reason breakdown and severity coloring
		var parts []string
		var benignParts []string // shown dim, not alarming
		if sent.PktDropRate > 0 {
			// Find top reason for display
			topReason := ""
			topRate := float64(0)
			allBenign := true
			for _, d := range sent.PktDrops {
				if d.Rate >= 1 {
					if !d.Benign {
						allBenign = false
						if topReason == "" {
							topReason = d.ReasonStr
							topRate = d.Rate
						}
					} else if topReason == "" {
						topReason = d.ReasonStr
						topRate = d.Rate
					}
				}
			}
			dropLabel := fmt.Sprintf("Drops:%.0f/s", sent.PktDropRate)
			if topReason != "" {
				dropLabel += fmt.Sprintf(" [%s:%.0f/s — %s]", topReason, topRate, dropReasonHint(topReason))
			}
			if allBenign {
				benignParts = append(benignParts, dropLabel)
			} else {
				parts = append(parts, dropLabel)
			}
		}
		if sent.TCPResetRate > 0 {
			parts = append(parts, fmt.Sprintf("RSTs:%.0f/s", sent.TCPResetRate))
		}
		if sent.RetransRate > 0 {
			parts = append(parts, fmt.Sprintf("Retrans:%.0f/s", sent.RetransRate))
		}
		if sent.ThrottleRate > 0 {
			parts = append(parts, fmt.Sprintf("Throttle:%.0f/s", sent.ThrottleRate))
		}
		if len(sent.OOMKills) > 0 {
			parts = append(parts, fmt.Sprintf("OOM:%d", len(sent.OOMKills)))
		}

		if len(parts) == 0 && len(benignParts) == 0 {
			sb.WriteString(okStyle.Render("ok"))
		} else {
			// Real problems: color by severity
			if len(parts) > 0 {
				isCrit := realDropRate > 100 || len(sent.OOMKills) > 0
				text := strings.Join(parts, " | ")
				if isCrit {
					sb.WriteString(critStyle.Render(text))
				} else {
					sb.WriteString(warnStyle.Render(text))
				}
			}
			// Benign-only drops: show dim (not alarming)
			if len(benignParts) > 0 {
				if len(parts) > 0 {
					sb.WriteString(dimStyle.Render(" | "))
				}
				sb.WriteString(dimStyle.Render(strings.Join(benignParts, " | ")))
			}
		}
		sb.WriteString(dimStyle.Render(" | "))
	}

	// Probe status
	sb.WriteString(titleStyle.Render("Probe:"))
	sb.WriteString(" ")

	if pm == nil || pm.ProbeState() == 0 {
		sb.WriteString(dimStyle.Render("idle"))
		sb.WriteString(dimStyle.Render(
			" | Press I to run 10s deep dive"))
		sb.WriteString("\n")
		return sb.String()
	}

	switch pm.ProbeState() {
	case 1: // running
		sb.WriteString(orangeStyle.Render("running"))
		sb.WriteString(dimStyle.Render(fmt.Sprintf(
			" (%s) \u2014 %ds left\u2026", pm.ProbePack(), pm.ProbeSecsLeft())))
	case 2: // done
		sb.WriteString(okStyle.Render("done"))
		summary := pm.ProbeSummary()
		if summary != "" {
			sb.WriteString(dimStyle.Render(" | Findings: "))
			sb.WriteString(valueStyle.Render(summary))
		}
	}

	sb.WriteString("\n")
	return sb.String()
}

// dropReasonHint returns a human-friendly explanation for a drop reason string.
func dropReasonHint(reason string) string {
	switch reason {
	case "OTHERHOST":
		return "packets for other VMs, benign"
	case "NO_SOCKET":
		return "no matching socket, connection closed"
	case "NETFILTER_DROP":
		return "dropped by firewall rules"
	case "SOCKET_FILTER":
		return "dropped by socket filter (tcpdump/BPF)"
	case "SOCKET_RCVBUFF":
		return "receive buffer full, app too slow"
	case "SOCKET_BACKLOG":
		return "socket backlog full, app too slow"
	case "PROTO_MEM":
		return "kernel protocol memory exhausted"
	case "TCP_CSUM":
		return "TCP checksum error"
	case "UDP_CSUM":
		return "UDP checksum error"
	case "IP_CSUM":
		return "IP checksum error"
	case "TCP_OVERWINDOW":
		return "packet exceeds TCP window"
	case "TCP_OLD_DATA":
		return "stale retransmit, normal"
	case "TCP_OLD_SEQUENCE":
		return "old sequence number, normal"
	case "TCP_RESET":
		return "connection reset"
	case "TCP_INVALID_SEQUENCE":
		return "unexpected sequence number"
	case "TCP_INVALID_SYN":
		return "malformed SYN packet"
	case "TCP_CLOSE":
		return "connection closing, normal"
	case "TCP_OFOMERGE":
		return "out-of-order merge, normal"
	case "TCP_ZEROWINDOW":
		return "flow control, receiver paused"
	case "TCP_FLAGS":
		return "normal FIN/RST handling"
	case "QDISC_DROP":
		return "queue discipline overflow"
	case "FULL_RING":
		return "NIC ring buffer full"
	case "NOMEM":
		return "out of memory"
	case "CPU_BACKLOG":
		return "CPU processing backlog full"
	case "IP_RPFILTER":
		return "reverse path filter, spoofing protection"
	case "NEIGH_FAILED":
		return "ARP/neighbor resolution failed"
	case "NEIGH_QUEUEFULL":
		return "neighbor queue full"
	default:
		return "kernel drop"
	}
}

// probeQuerier is an interface for querying probe state without importing engine.
type probeQuerier interface {
	ProbeState() int
	ProbePack() string
	ProbeSecsLeft() int
	ProbeSummary() string
}

// renderOwnersInline renders owners with top-3 per resource. 5 lines (title + 4 resource lines).
func renderOwnersInline(result *model.AnalysisResult) string {
	var sb strings.Builder
	sb.WriteString(" ")
	sb.WriteString(titleStyle.Render("Owners:"))
	sb.WriteString("\n")

	renderLine := func(label string, owners []model.Owner) {
		sb.WriteString("  ")
		sb.WriteString(headerStyle.Render(label + ":"))
		sb.WriteString(" ")
		if len(owners) == 0 {
			sb.WriteString(dimStyle.Render("\u2014"))
		} else {
			parts := make([]string, 0, 3)
			for i, o := range owners {
				if i >= 3 {
					break
				}
				name := truncate(o.Name, 24)
				parts = append(parts, valueStyle.Render(name)+dimStyle.Render(":"+o.Value))
			}
			sb.WriteString(strings.Join(parts, dimStyle.Render(" | ")))
		}
		sb.WriteString("\n")
	}

	if result != nil {
		renderLine("IO", result.IOOwners)
		renderLine("CPU", result.CPUOwners)
		renderLine("MEM", result.MemOwners)
		renderLine("NET", result.NetOwners)
	} else {
		renderLine("IO", nil)
		renderLine("CPU", nil)
		renderLine("MEM", nil)
		renderLine("NET", nil)
	}
	return sb.String()
}

// renderCapacityInline renders a single-line capacity summary. Always produces exactly 1 line.
func renderCapacityInline(result *model.AnalysisResult) string {
	var sb strings.Builder
	sb.WriteString(" ")
	sb.WriteString(titleStyle.Render("Capacity:"))
	sb.WriteString(" ")

	if result == nil || len(result.Capacities) == 0 {
		sb.WriteString(dimStyle.Render("collecting..."))
		sb.WriteString("\n")
		return sb.String()
	}

	parts := []string{}
	for _, cap := range result.Capacities {
		style := dimStyle
		if cap.Pct < 15 {
			style = critStyle
		} else if cap.Pct < 30 {
			style = warnStyle
		}
		parts = append(parts, fmt.Sprintf("%s %s", cap.Label, style.Render(fmtPct(cap.Pct))))
	}
	sb.WriteString(strings.Join(parts, dimStyle.Render(" | ")))
	sb.WriteString("\n")
	return sb.String()
}

// ─── SHARED: HELPERS ────────────────────────────────────────────────────────

func psiColor(pct float64) lipgloss.Style {
	switch {
	case pct >= 25:
		return critStyle
	case pct >= 5:
		return warnStyle
	case pct >= 0.5:
		return orangeStyle
	default:
		return okStyle
	}
}

func meterColor(pct float64) lipgloss.Style {
	switch {
	case pct >= 80:
		return critStyle
	case pct >= 50:
		return warnStyle
	default:
		return okStyle
	}
}

func fmtDuration(sec int) string {
	if sec >= 3600 {
		return fmt.Sprintf("%dh%dm", sec/3600, (sec%3600)/60)
	}
	if sec >= 60 {
		return fmt.Sprintf("%dm%ds", sec/60, sec%60)
	}
	return fmt.Sprintf("%ds", sec)
}

// separator renders a horizontal rule.
func separator(width int) string {
	if width < 1 {
		width = 40
	}
	return dimStyle.Render(strings.Repeat("─", width))
}

// renderExplainPanel renders a detailed evidence breakdown for each RCA entry.
func renderExplainPanel(result *model.AnalysisResult, width int) string {
	var sb strings.Builder

	innerW := width - 7
	if innerW < 60 {
		innerW = 60
	}
	if innerW > 200 {
		innerW = 200
	}

	sb.WriteString("\n")
	sb.WriteString(titleStyle.Render(" EXPLAIN VERDICT (press e to close)"))
	sb.WriteString("\n")

	if result == nil || len(result.RCA) == 0 {
		sb.WriteString(boxTop(innerW) + "\n")
		sb.WriteString(boxRow(dimStyle.Render("No analysis data available"), innerW) + "\n")
		sb.WriteString(boxBot(innerW) + "\n")
		return sb.String()
	}

	// Narrative summary box (if available)
	if n := result.Narrative; n != nil {
		sb.WriteString(boxTopTitle(dimStyle.Render(" ROOT CAUSE "), innerW) + "\n")

		rcStyle := warnStyle
		if result.Health == model.HealthCritical {
			rcStyle = critStyle
		}
		sb.WriteString(boxRow(" "+rcStyle.Render(n.RootCause), innerW) + "\n")

		if len(n.Evidence) > 0 {
			sb.WriteString(boxMid(innerW) + "\n")
			sb.WriteString(boxRow(" "+titleStyle.Render("EVIDENCE"), innerW) + "\n")
			for _, ev := range n.Evidence {
				sb.WriteString(boxRow(" "+dimStyle.Render(ev), innerW) + "\n")
			}
		}

		if n.Impact != "" {
			sb.WriteString(boxMid(innerW) + "\n")
			sb.WriteString(boxRow(" "+titleStyle.Render("IMPACT"), innerW) + "\n")
			sb.WriteString(boxRow(" "+warnStyle.Render(n.Impact), innerW) + "\n")
		}

		sb.WriteString(boxBot(innerW) + "\n")
		sb.WriteString("\n")
	}

	// Temporal causality box (if available)
	if tc := result.TemporalChain; tc != nil && len(tc.Events) > 1 {
		sb.WriteString(boxTopTitle(dimStyle.Render(" TEMPORAL CAUSALITY "), innerW) + "\n")

		earliest := tc.Events[0].FirstSeen
		for _, ev := range tc.Events {
			if len(ev.Label) == 0 {
				continue
			}
			offset := ev.FirstSeen.Sub(earliest)
			marker := ""
			if ev.Sequence == 0 {
				marker = "  <-- first signal"
			}
			line := fmt.Sprintf(" T+%ds:  %s%s",
				int(offset.Seconds()),
				truncate(ev.Label, innerW-20),
				marker)
			sb.WriteString(boxRow(dimStyle.Render(line), innerW) + "\n")
		}

		sb.WriteString(boxBot(innerW) + "\n")
		sb.WriteString("\n")
	}

	// Blame / Top Offenders box (if available)
	if len(result.Blame) > 0 {
		sb.WriteString(boxTopTitle(dimStyle.Render(" TOP OFFENDERS "), innerW) + "\n")

		for i, b := range result.Blame {
			var metricParts []string
			for k, v := range b.Metrics {
				metricParts = append(metricParts, k+":"+v)
			}
			displayName := b.Comm
			if b.AppName != "" {
				displayName = b.AppName
			}
			line := fmt.Sprintf(" %d. %s (PID %d) — %s",
				i+1,
				truncate(displayName, 22),
				b.PID,
				strings.Join(metricParts, ", "))
			sb.WriteString(boxRow(dimStyle.Render(line), innerW) + "\n")
		}

		sb.WriteString(boxBot(innerW) + "\n")
		sb.WriteString("\n")
	}

	for _, rca := range result.RCA {
		if rca.Score == 0 && rca.EvidenceGroups == 0 {
			continue
		}

		sb.WriteString(boxTop(innerW) + "\n")

		// Bottleneck header with score
		style := dimStyle
		if rca.Score >= 60 {
			style = critStyle
		} else if rca.Score >= 25 {
			style = warnStyle
		} else if rca.Score > 0 {
			style = orangeStyle
		}
		header := fmt.Sprintf(" %s  Score: %s  Groups: %d/%d",
			style.Render(rca.Bottleneck),
			style.Render(fmt.Sprintf("%d%%", rca.Score)),
			rca.EvidenceGroups, len(rca.Checks))
		sb.WriteString(boxRow(header, innerW) + "\n")

		if rca.TopProcess != "" {
			displayName := rca.TopProcess
			if rca.TopAppName != "" {
				displayName = rca.TopAppName
			}
			culprit := fmt.Sprintf(" Culprit: %s (PID %d)", valueStyle.Render(displayName), rca.TopPID)
			sb.WriteString(boxRow(culprit, innerW) + "\n")
		}

		sb.WriteString(boxMid(innerW) + "\n")

		// Evidence checks with pass/fail, confidence tags
		for _, check := range rca.Checks {
			icon := dimStyle.Render("[ ]")
			if check.Passed {
				icon = okStyle.Render("[x]")
			}
			confTag := ""
			if check.Confidence != "" {
				confTag = dimStyle.Render(fmt.Sprintf(" [%s]", check.Confidence))
			}
			line := fmt.Sprintf(" %s %s %s%s",
				icon,
				styledPad(check.Label, 24),
				dimStyle.Render(check.Value),
				confTag)
			sb.WriteString(boxRow(line, innerW) + "\n")
		}

		sb.WriteString(boxBot(innerW) + "\n")
	}

	return sb.String()
}

// ─── SHARED: PROCESS TABLE ──────────────────────────────────────────────────

// renderProcessTable renders a sorted process table (CPU% descending).
func renderProcessTable(rates *model.RateSnapshot, width, maxRows int) string {
	if rates == nil || len(rates.ProcessRates) == 0 || maxRows <= 0 {
		return ""
	}

	// Sort by CPU% descending (copy to avoid mutating)
	procs := make([]model.ProcessRate, len(rates.ProcessRates))
	copy(procs, rates.ProcessRates)
	sort.Slice(procs, func(i, j int) bool {
		return procs[i].CPUPct > procs[j].CPUPct
	})

	var sb strings.Builder

	// Column widths: PID(7) CPU%(6) MEM%(6) STATE(6) THR(4) RSS(8) IO R/W(16) COMMAND(fill)
	fixedW := 7 + 6 + 6 + 6 + 4 + 8 + 16 + 4 // 4 for spacing
	cmdW := width - fixedW - 2                  // 2 for leading space
	if cmdW < 8 {
		cmdW = 8
	}

	// Header
	hdr := fmt.Sprintf(" %s%s%s%s%s%s%s%s",
		styledPad(dimStyle.Render("PID"), 7),
		styledPad(dimStyle.Render("CPU%"), 6),
		styledPad(dimStyle.Render("MEM%"), 6),
		styledPad(dimStyle.Render("STATE"), 6),
		styledPad(dimStyle.Render("THR"), 4),
		styledPad(dimStyle.Render("RSS"), 8),
		styledPad(dimStyle.Render("IO R/W"), 16),
		dimStyle.Render("COMMAND"))
	sb.WriteString(hdr + "\n")

	// Rows
	n := maxRows
	if n > len(procs) {
		n = len(procs)
	}
	for i := 0; i < n; i++ {
		p := procs[i]

		// CPU% coloring
		cpuStr := fmt.Sprintf("%.1f", p.CPUPct)
		cpuStyled := dimStyle.Render(cpuStr)
		if p.CPUPct > 50 {
			cpuStyled = critStyle.Render(cpuStr)
		} else if p.CPUPct > 20 {
			cpuStyled = warnStyle.Render(cpuStr)
		} else if p.CPUPct > 0.1 {
			cpuStyled = valueStyle.Render(cpuStr)
		}

		// MEM% coloring
		memStr := fmt.Sprintf("%.1f", p.MemPct)
		memStyled := dimStyle.Render(memStr)
		if p.MemPct > 50 {
			memStyled = critStyle.Render(memStr)
		} else if p.MemPct > 20 {
			memStyled = warnStyle.Render(memStr)
		} else if p.MemPct > 0.1 {
			memStyled = valueStyle.Render(memStr)
		}

		// State coloring
		stateStyled := dimStyle.Render(p.State)
		switch p.State {
		case "R":
			stateStyled = okStyle.Render("R")
		case "D":
			stateStyled = critStyle.Render("D")
		}

		// IO R/W
		ioStr := fmt.Sprintf("%.1f/%.1f MB/s", p.ReadMBs, p.WriteMBs)

		// Command
		cmd := p.Comm
		if len(cmd) > cmdW {
			cmd = cmd[:cmdW-3] + "..."
		}

		row := fmt.Sprintf(" %s%s%s%s%s%s%s%s",
			styledPad(dimStyle.Render(fmt.Sprintf("%d", p.PID)), 7),
			styledPad(cpuStyled, 6),
			styledPad(memStyled, 6),
			styledPad(stateStyled, 6),
			styledPad(dimStyle.Render(fmt.Sprintf("%d", p.NumThreads)), 4),
			styledPad(dimStyle.Render(fmtBytes(p.RSS)), 8),
			styledPad(dimStyle.Render(ioStr), 16),
			valueStyle.Render(cmd))
		sb.WriteString(row + "\n")
	}

	return sb.String()
}

// perCoreBusy computes per-core CPU busy % from two consecutive snapshots.
func perCoreBusy(prev, curr *model.Snapshot) []float64 {
	if prev == nil || curr == nil {
		return nil
	}
	prevCPU := prev.Global.CPU.PerCPU
	currCPU := curr.Global.CPU.PerCPU
	n := len(currCPU)
	if len(prevCPU) < n {
		n = len(prevCPU)
	}
	if n == 0 {
		return nil
	}

	pcts := make([]float64, n)
	for i := 0; i < n; i++ {
		prevTotal := prevCPU[i].Total()
		currTotal := currCPU[i].Total()
		// #10: Guard against uint64 underflow on counter reset
		if currTotal < prevTotal {
			continue
		}
		delta := currTotal - prevTotal
		if delta == 0 {
			continue
		}
		if currCPU[i].Idle < prevCPU[i].Idle {
			continue
		}
		idle := currCPU[i].Idle - prevCPU[i].Idle
		if idle > delta {
			continue
		}
		pcts[i] = float64(delta-idle) / float64(delta) * 100
		if pcts[i] < 0 {
			pcts[i] = 0
		}
		if pcts[i] > 100 {
			pcts[i] = 100
		}
	}
	return pcts
}
