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
	{"CT drops/s", "Conntrack drop rate. Table full — new connections rejected.", "0", "> 0"},
	{"CT insertfail", "Conntrack insert failure rate. Flows denied entry to table.", "0", "> 0"},
	{"CT growth/s", "Net conntrack entries added per second (insert minus delete).", "< 100", "> 1000"},
	{"CT invalid/s", "Packets that don't match any conntrack entry. Protocol violations.", "< 10", "> 100"},
	{"CT restart/s", "Hash table search restarts. Indicates contention or sizing issues.", "< 100", "> 1000"},
	{"CT timeouts", "TCP timeout config from sysctl. ESTABLISHED > 1 day is risky.", "< 1d", "> 1d"},
	{"Age buckets", "Connection TTL distribution. High churn (<10s) vs persistent (>5m).", "balanced", "> 50% short"},
	{"CT states", "Conntrack state distribution (ESTABLISHED, TIME_WAIT, etc.).", "mostly ESTAB", "high CW/TW"},
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

var intelGlossary = []ExplainEntry{
	{"Impact Score", "Weighted composite: CPU 30%, PSI 20%, IO 20%, Mem 20%, Net 10%. Higher = bigger resource hog.", "> 0", "> 70"},
	{"Cross-correlation", "Cause-effect detection across signal domains (CPU→IO, Mem→Swap, etc.).", "none", "high confidence"},
	{"Runtime Module", "Auto-discovered language runtime (JVM, .NET, Python, Node, Go). Zero cost when absent.", "detected", "n/a"},
	{"GC Heap", "Managed heap size after garbage collection (JVM, .NET). Growth = potential memory leak.", "stable", "growing"},
	{"GC Time%", "% of time spent in garbage collection (JVM, .NET). High = throughput loss.", "< 10%", "> 20%"},
	{"hsperfdata", "JVM performance data files in /tmp. Provides GC counts, heap sizes, thread counts.", "present", "n/a"},
	{"GIL-bound", "Python process limited by Global Interpreter Lock. 1 thread + high CPU = likely GIL-bound.", "no", "likely"},
	{"Alloc Rate", ".NET memory allocation rate. Spikes cause GC pressure.", "stable", "spiking"},
	{"SLO Status", "Service level objective pass/fail. Evaluated against live metrics.", "PASS", "FAIL"},
	{"Autopilot", "Safe automated remediation (CPU throttle, process isolation, ionice).", "idle", "active"},
	{"Incidents", "Stored incident records with fingerprinting for pattern detection.", "0", "> 0"},
}

var cgroupGlossary = []ExplainEntry{
	{"CPU usage", "CPU time consumed by all tasks in this cgroup.", "varies", "near limit"},
	{"CPU throttle", "Times the cgroup hit its CPU limit and was slowed.", "0", "> 0"},
	{"Memory usage", "RSS + cache used by the cgroup.", "< limit", "near limit"},
	{"Memory limit", "Maximum memory allowed for this cgroup.", "n/a", "n/a"},
	{"IO read/write", "Disk throughput by this cgroup.", "varies", "n/a"},
	{"IO pressure", "PSI IO pressure within this cgroup.", "< 5%", "> 20%"},
}

var securityGlossary = []ExplainEntry{
	{"SYN Flood", "Massive SYN packet rate overwhelming connection table.", "0", "> 1000 SYN/s"},
	{"Port Scan", "Systematic probing of ports to find running services.", "0 RSTs", "> 100 RSTs"},
	{"DNS Tunneling", "Data exfiltration encoded in DNS query names.", "0% TXT", "> 30% TXT"},
	{"C2 Beacon", "Malware callback to command server at regular intervals.", "none", "low jitter"},
	{"JA3 Fingerprint", "TLS client fingerprint from ClientHello parameters.", "known browser", "unknown/malware"},
	{"Data Exfiltration", "Unauthorized transfer of data to external destination.", "< 10 MB/hr", "> 100 MB/hr"},
	{"Lateral Movement", "Attacker moving between internal hosts after compromise.", "< 5 dests", "> 20 dests"},
	{"TCP Flag Anomaly", "Unusual TCP flag combinations (XMAS, NULL scan, etc.).", "0", "> 0"},
	{"Watchdog Probe", "Auto-triggered deep inspection probe (60-120s burst).", "idle", "active"},
	{"Half-Open Ratio", "% of SYN packets without completed handshake.", "< 10%", "> 50%"},
	{"TXT Ratio", "% of DNS queries using TXT type (high = tunneling).", "< 5%", "> 30%"},
	{"Beacon Jitter", "Regularity of callback intervals (low jitter = suspicious).", "> 20%", "< 5%"},
	{"Failed Auth Rate", "Rate of failed SSH/PAM authentication attempts per second.", "0/s", "> 1/s"},
	{"Brute Force", "Rapid repeated auth failures from same source = password guessing.", "No", "YES"},
	{"SUID Binary", "Executable with set-user-ID bit. New SUID files are suspicious.", "0 new", "> 0 new"},
	{"Reverse Shell", "Shell process with stdin/stdout redirected to a network socket.", "0", "> 0"},
	{"Fileless Process", "Process with deleted or missing executable on disk.", "0", "> 0"},
	{"Ptrace", "Process tracing syscall used for debugging or process injection.", "0", "> 0"},
	{"Module Load", "Kernel module loaded at runtime. Rootkits use this for persistence.", "0", "> 0"},
}

var appsGlossary = []ExplainEntry{
	{"Health Score", "Composite health rating for detected application.", "100", "< 50"},
	{"Deep Metrics", "Protocol-level metrics from connecting to the app.", "enabled", "needs creds"},
	{"Hit Ratio", "Cache hit rate for Redis/Memcached.", "> 90%", "< 80%"},
	{"Evictions", "Keys evicted from cache due to memory pressure.", "0", "> 0"},
	{"Connections", "Active TCP connections to the application port.", "normal", "near limit"},
	{"Workers", "Child/worker processes (Nginx, Apache, HAProxy).", "configured", "fewer than expected"},
	{"Blocked Clients", "Redis clients blocked on BLPOP/BRPOP/WAIT.", "0", "> 0"},
	{"Replication", "Database replication lag or status.", "synced", "lagging/broken"},
	{"Secrets File", "Credentials file at ~/.config/xtop/secrets.json.", "configured", "missing"},
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
	case PageIntel:
		return intelGlossary
	case PageSecurity:
		return securityGlossary
	case PageApps:
		return appsGlossary
	default:
		return nil
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

	if len(glossary) == 0 {
		msg := "No glossary for this page."
		padded := msg + strings.Repeat(" ", maxInt(innerW-lipgloss.Width(msg), 0))
		contentLines = append(contentLines,
			borderStyle.Render("\u2502")+" "+dimStyle.Render(padded)+" "+borderStyle.Render("\u2502"))
	}

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
