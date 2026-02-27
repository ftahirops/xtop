package ui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/ftahirops/xtop/model"
)

// ExplainEntry describes one metric for the explain side panel.
type ExplainEntry struct {
	Metric string // "PSI some avg10"
	Plain  string // "% of time tasks are stuck waiting for CPU"
	Good   string // "< 5%"
	Bad    string // "> 20%"
}

// ── Per-page glossaries ──────────────────────────────────────────────────────

var overviewGlossary = []ExplainEntry{
	{"PSI CPU", "% of time tasks wait for CPU. Like a queue at a checkout.", "< 5%", "> 20%"},
	{"PSI Memory", "% of time tasks wait for memory allocation.", "< 5%", "> 20%"},
	{"PSI IO", "% of time tasks wait for disk reads/writes.", "< 5%", "> 20%"},
	{"Run queue", "Tasks waiting per CPU core. 1x = balanced, >2x = overloaded.", "< 1x cores", "> 2x cores"},
	{"Confidence", "How sure xtop is about its diagnosis. Higher = more evidence.", "> 70%", "< 30%"},
	{"D-state", "Processes stuck waiting for disk. High = IO bottleneck.", "0", "> 5"},
	{"Swap", "Memory overflow to disk. Any swap activity means memory is tight.", "0 MB/s", "> 0"},
	{"Health", "Overall system health assessment: OK, DEGRADED, or CRITICAL.", "OK", "CRITICAL"},
	{"Causal chain", "Path from root cause to visible symptoms.", "n/a", "n/a"},
	{"Blame", "Top processes responsible for the bottleneck.", "n/a", "n/a"},
}

var cpuGlossary = []ExplainEntry{
	{"user%", "Time spent running your applications.", "varies", "n/a"},
	{"sys%", "Time spent in kernel (OS overhead).", "< 20%", "> 40%"},
	{"iowait%", "CPUs idle while waiting for disk. Often misleading \u2014 check PSI instead.", "< 10%", "> 30%"},
	{"steal%", "CPU time stolen by the hypervisor (VMs only). >5% = noisy neighbor.", "< 2%", "> 5%"},
	{"softirq%", "Network/timer interrupt overhead. >10% = potential network saturation.", "< 5%", "> 10%"},
	{"Throttle", "Cgroup CPU limit hit. Container/service is being slowed down.", "0/s", "> 0"},
	{"Load avg", "Average number of runnable + uninterruptible tasks over 1/5/15 min.", "< cores", "> 2x cores"},
	{"Context switch", "Rate of task switches. Very high may indicate contention.", "varies", "> 100k/s"},
	{"nice%", "Time running low-priority (nice'd) processes.", "varies", "n/a"},
	{"irq%", "Time handling hardware interrupts.", "< 1%", "> 5%"},
}

var memGlossary = []ExplainEntry{
	{"Available", "Memory the kernel considers allocatable without swapping.", "> 20% total", "< 10% total"},
	{"Cached", "File data kept in RAM for fast access. Reclaimable if needed.", "varies", "n/a"},
	{"Dirty", "Modified data not yet written to disk. High = IO burst coming.", "< 100 MB", "> 500 MB"},
	{"Swap used", "Data pushed to disk because RAM was full.", "0", "> 0"},
	{"Swap in/out", "Rate of data moving between RAM and swap disk.", "0 MB/s", "> 0"},
	{"Slab", "Kernel internal caches (dentries, inodes). Usually reclaimable.", "varies", "n/a"},
	{"AnonPages", "Memory used by applications (heap, stack). Not backed by files.", "varies", "n/a"},
	{"Writeback", "Data being written to disk right now.", "< 10 MB", "> 100 MB"},
	{"Page fault rate", "Rate of page faults (minor = normal, major = disk fetch).", "varies", "high major"},
	{"OOM kills", "Kernel killed a process to free memory. Always bad.", "0", "> 0"},
}

var ioGlossary = []ExplainEntry{
	{"Read MB/s", "Data read from disk per second.", "varies", "n/a"},
	{"Write MB/s", "Data written to disk per second.", "varies", "n/a"},
	{"IOPS", "IO operations per second (reads + writes).", "varies", "n/a"},
	{"Await (ms)", "Average time for an IO request to complete. Key latency metric.", "< 5ms", "> 20ms"},
	{"Queue depth", "IO requests waiting in the disk queue.", "< 4", "> 16"},
	{"Utilization %", "How busy the device is. 100% = fully saturated.", "< 70%", "> 90%"},
	{"PSI IO", "% of time at least one task is stalled on IO.", "< 5%", "> 20%"},
	{"D-state procs", "Processes in uninterruptible sleep (waiting for IO).", "0", "> 5"},
	{"Dirty pages", "Data in memory waiting to be flushed to disk.", "< 100 MB", "> 500 MB"},
}

var netGlossary = []ExplainEntry{
	{"Rx/Tx MB/s", "Network throughput in/out per second.", "varies", "n/a"},
	{"Rx/Tx PPS", "Packets per second in/out.", "varies", "> 500k (small pkt flood)"},
	{"Drops", "Packets dropped by the kernel. May indicate buffer overflow.", "0", "> 0"},
	{"Errors", "Network interface errors (CRC, framing).", "0", "> 0"},
	{"Retransmits", "TCP segments re-sent. Indicates packet loss or congestion.", "< 0.1%", "> 1%"},
	{"TCP conn", "Active TCP connections (ESTABLISHED, TIME_WAIT, etc.).", "varies", "n/a"},
	{"Conntrack", "Connection tracking table usage (firewall). Near-full = drops.", "< 70%", "> 90%"},
	{"softirq%", "CPU time processing network interrupts.", "< 5%", "> 10%"},
	{"Link util%", "% of link speed being used.", "< 70%", "> 90%"},
}

var probeGlossary = []ExplainEntry{
	{"Off-CPU", "Time threads spend sleeping/blocked (not running). High = contention.", "< 30%", "> 60%"},
	{"IO latency", "Distribution of per-IO completion times from block layer.", "< 5ms p99", "> 50ms p99"},
	{"Lock wait", "Time threads spend waiting for mutexes/locks.", "< 5%", "> 20%"},
	{"TCP retrans", "Per-connection retransmit counts. Identifies lossy paths.", "0", "> 0"},
	{"Run queue lat", "Time tasks wait in the CPU run queue before executing.", "< 10\u00b5s", "> 100\u00b5s"},
	{"Sentinel", "Always-on lightweight probes that detect anomalies.", "active", "errors"},
	{"Watchdog", "Auto-triggered deep probes activated by RCA findings.", "idle", "n/a"},
	{"Deep Dive", "Manual investigation probes. Press I to start.", "idle", "n/a"},
}

var cgroupGlossary = []ExplainEntry{
	{"CPU usage", "CPU time consumed by all tasks in this cgroup.", "varies", "near limit"},
	{"CPU throttle", "Times the cgroup hit its CPU limit and was slowed.", "0", "> 0"},
	{"Memory usage", "RSS + cache used by the cgroup.", "< limit", "near limit"},
	{"Memory limit", "Maximum memory allowed for this cgroup.", "n/a", "n/a"},
	{"IO read/write", "Disk throughput by this cgroup.", "varies", "n/a"},
	{"IO pressure", "PSI IO pressure within this cgroup.", "< 5%", "> 20%"},
}

// glossaryForPage returns the appropriate glossary for the current page.
func glossaryForPage(page Page) []ExplainEntry {
	switch page {
	case PageOverview:
		return overviewGlossary
	case PageCPU:
		return cpuGlossary
	case PageMemory:
		return memGlossary
	case PageIO:
		return ioGlossary
	case PageNetwork:
		return netGlossary
	case PageProbe:
		return probeGlossary
	case PageCgroups:
		return cgroupGlossary
	default:
		return overviewGlossary
	}
}

// pageTitleForExplain returns a short page title for the explain panel header.
func pageTitleForExplain(page Page) string {
	if int(page) < len(pageNames) {
		return pageNames[page]
	}
	return "Metrics"
}

// renderExplainSidePanel renders the explain side panel for the given page.
func renderExplainSidePanel(page Page, result *model.AnalysisResult, width, height, scrollOffset int, focused bool) string {
	glossary := glossaryForPage(page)

	var sb strings.Builder
	innerW := width - 4
	if innerW < 16 {
		innerW = 16
	}

	// Header
	title := fmt.Sprintf(" EXPLAIN: %s ", pageTitleForExplain(page))
	borderStyle := dimStyle
	if focused {
		borderStyle = lipgloss.NewStyle().Foreground(colorCyan)
	}
	sb.WriteString(borderStyle.Render("\u250c"+strings.Repeat("\u2500", 2)) +
		titleStyle.Render(title) +
		borderStyle.Render(strings.Repeat("\u2500", maxInt(innerW+2-2-lipgloss.Width(title), 0))+"\u2510") + "\n")

	// Build all content lines first for scrolling
	var contentLines []string

	for i, entry := range glossary {
		if i > 0 {
			contentLines = append(contentLines, borderStyle.Render("\u2502")+" "+strings.Repeat(" ", innerW)+" "+borderStyle.Render("\u2502"))
		}

		// Metric name in bold cyan
		contentLines = append(contentLines,
			borderStyle.Render("\u2502")+" "+titleStyle.Render(truncate(entry.Metric, innerW))+" "+
				strings.Repeat(" ", maxInt(innerW-lipgloss.Width(entry.Metric), 0))+borderStyle.Render("\u2502"))

		// Plain description — wrapped
		descLines := wrapText(" "+entry.Plain, innerW)
		for _, dl := range descLines {
			padded := dl + strings.Repeat(" ", maxInt(innerW-lipgloss.Width(dl), 0))
			contentLines = append(contentLines,
				borderStyle.Render("\u2502")+" "+dimStyle.Render(padded)+" "+borderStyle.Render("\u2502"))
		}

		// Good/Bad thresholds
		if entry.Good != "n/a" || entry.Bad != "n/a" {
			goodBad := ""
			if entry.Good != "n/a" {
				goodBad += " " + okStyle.Render("Good: "+entry.Good)
			}
			if entry.Bad != "n/a" {
				if goodBad != "" {
					goodBad += "  "
				} else {
					goodBad += " "
				}
				goodBad += critStyle.Render("Bad: "+entry.Bad)
			}
			gbW := lipgloss.Width(goodBad)
			padded := goodBad + strings.Repeat(" ", maxInt(innerW-gbW, 0))
			contentLines = append(contentLines,
				borderStyle.Render("\u2502")+" "+padded+" "+borderStyle.Render("\u2502"))
		}
	}

	// Add RCA summary if available and on overview
	if page == PageOverview && result != nil && result.Narrative != nil && result.Narrative.RootCause != "" {
		contentLines = append(contentLines,
			borderStyle.Render("\u2502")+" "+strings.Repeat(" ", innerW)+" "+borderStyle.Render("\u2502"))
		contentLines = append(contentLines,
			borderStyle.Render("\u2502")+" "+
				styledPad(headerStyle.Render("\u2500\u2500 ROOT CAUSE"), innerW)+" "+
				borderStyle.Render("\u2502"))
		rcLines := wrapText(" "+result.Narrative.RootCause, innerW)
		for _, rl := range rcLines {
			padded := rl + strings.Repeat(" ", maxInt(innerW-lipgloss.Width(rl), 0))
			contentLines = append(contentLines,
				borderStyle.Render("\u2502")+" "+warnStyle.Render(padded)+" "+borderStyle.Render("\u2502"))
		}
	}

	// Apply scroll
	visibleLines := height - 4 // account for header, footer, status
	if visibleLines < 5 {
		visibleLines = 5
	}
	if scrollOffset > len(contentLines)-visibleLines {
		scrollOffset = len(contentLines) - visibleLines
	}
	if scrollOffset < 0 {
		scrollOffset = 0
	}

	end := scrollOffset + visibleLines
	if end > len(contentLines) {
		end = len(contentLines)
	}

	for _, line := range contentLines[scrollOffset:end] {
		sb.WriteString(line + "\n")
	}

	// Scroll indicator
	scrollInfo := ""
	if len(contentLines) > visibleLines {
		pct := 0
		if len(contentLines)-visibleLines > 0 {
			pct = scrollOffset * 100 / (len(contentLines) - visibleLines)
		}
		scrollInfo = fmt.Sprintf(" %d%% ", pct)
	}

	// Footer
	hint := "E:close"
	if focused {
		hint = "\u2191\u2193:scroll Tab:unfocus E:close"
	} else {
		hint = "Tab:focus E:close"
	}
	hintW := lipgloss.Width(hint) + lipgloss.Width(scrollInfo)
	footerDash := maxInt(innerW+2-hintW, 0)
	sb.WriteString(borderStyle.Render("\u2514") +
		dimStyle.Render(scrollInfo) +
		borderStyle.Render(strings.Repeat("\u2500", footerDash)) +
		dimStyle.Render(hint) +
		borderStyle.Render("\u2518") + "\n")

	return sb.String()
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}
