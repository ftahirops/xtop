package ui

import (
	"fmt"
	"sort"
	"strings"

	"github.com/ftahirops/xtop/model"
)

// ──────────────────────────────────────────────────────────────────────────────
// Security Page — Collapsible Section Architecture
// ──────────────────────────────────────────────────────────────────────────────

// Security page section constants
const (
	secSecAuth         = 0
	secSecPorts        = 1
	secSecSUID         = 2
	secSecExec         = 3
	secSecPtrace       = 4
	secSecReverseShell = 5
	secSecFileless     = 6
	secSecModLoads     = 7
	secSecSessions     = 8
	secSecThreat       = 9
	secSecAttacks      = 10
	secSecDNS          = 11
	secSecFlows        = 12
	secSecTLS          = 13
	secSecCount        = 14
)

// secSectionNames are the display titles for each collapsible section.
var secSectionNames = [secSecCount]string{
	"SSH / AUTH",
	"NEW LISTENING PORTS",
	"SUID ANOMALIES",
	"PROCESS EXECUTIONS (BPF)",
	"PTRACE DETECTION (BPF)",
	"REVERSE SHELLS",
	"FILELESS PROCESSES",
	"KERNEL MODULE LOADS (BPF)",
	"SESSIONS",
	"NETWORK THREAT OVERVIEW",
	"ATTACK DETECTION (BPF)",
	"DNS INTELLIGENCE (BPF)",
	"FLOW INTELLIGENCE (BPF)",
	"TLS FINGERPRINTS (BPF)",
}

// classifyExecSeverity returns "crit", "warn", or "ok" for a process execution.
func classifyExecSeverity(comm, filename string) string {
	fnLower := strings.ToLower(filename)
	commLower := strings.ToLower(comm)

	// === CRIT: clearly suspicious ===

	// Execution from writable/temp directories
	for _, prefix := range []string{"/tmp/", "/dev/shm/", "/var/tmp/", "/run/shm/"} {
		if strings.HasPrefix(fnLower, prefix) {
			return "crit"
		}
	}
	// Hidden dotfile execution (e.g. /tmp/.xmrig)
	if strings.Contains(filename, "/.") {
		return "crit"
	}
	// Execution from /proc/self/fd/ (process self-exec trick)
	if strings.HasPrefix(filename, "/proc/") {
		return "crit"
	}
	// Known malware/exploit tool names
	for _, kw := range []string{"xmrig", "miner", "payload", "exploit", "reverse",
		"beacon", "mimikatz", "lazagne", "chisel", "ligolo", "sliver", "cobalt"} {
		if strings.Contains(fnLower, kw) || strings.Contains(commLower, kw) {
			return "crit"
		}
	}

	// === WARN: potentially suspicious ===

	warnComms := map[string]bool{
		// Network recon / C2
		"curl": true, "wget": true, "nc": true, "ncat": true, "netcat": true,
		"socat": true, "nmap": true, "masscan": true, "nikto": true,
		// Debuggers / injectors
		"strace": true, "gdb": true, "ltrace": true, "ptrace": true,
		// Credential / key tools
		"ssh-keygen": true, "ssh-agent": true, "ssh-add": true,
		// Encoding / obfuscation
		"base64": true, "xxd": true, "openssl": true,
		// Scripting (unusual as direct exec)
		"python3": true, "python": true, "perl": true, "ruby": true,
		"php": true, "lua": true, "node": true,
		// Recon
		"whoami": true, "id": true, "nslookup": true, "dig": true, "host": true,
		// Priv esc
		"pkexec": true, "su": true,
		// Data exfil
		"scp": true, "rsync": true,
	}
	if warnComms[commLower] {
		return "warn"
	}

	return "ok"
}

// renderSecurityPage renders the security page with collapsible sections.
func renderSecurityPage(snap *model.Snapshot, rates *model.RateSnapshot,
	result *model.AnalysisResult, pm probeQuerier,
	cursor int, expanded [secSecCount]bool,
	width, height int) string {

	var sb strings.Builder
	iw := pageInnerW(width)

	sb.WriteString(titleStyle.Render("SECURITY MONITOR"))
	sb.WriteString("\n")
	sb.WriteString(renderRCAInline(result))
	sb.WriteString(renderProbeStatusLine(pm, snap))
	sb.WriteString("\n")

	sec := snap.Global.Security
	sent := snap.Global.Sentinel

	// === SECURITY STATUS (always visible, not collapsible) ===
	var statusLines []string
	statusLines = append(statusLines, renderHealthBadge(sec.Score)+" "+dimStyle.Render(func() string {
		switch sec.Score {
		case "CRIT":
			return "— security signals detected"
		case "WARN":
			return "— review recommended"
		default:
			return "— no anomalies"
		}
	}()))
	sb.WriteString(boxSection("SECURITY STATUS", statusLines, iw))

	// Summary functions for collapsed headers
	summaryFuncs := [secSecCount]func() string{
		func() string { return secAuthSummary(sec) },
		func() string { return secPortsSummary(sec) },
		func() string { return secSUIDSummary(sec) },
		func() string { return secExecSummary(sent) },
		func() string { return secPtraceSummary(sent) },
		func() string { return secReverseShellSummary(sec) },
		func() string { return secFilelessSummary(snap) },
		func() string { return secModLoadsSummary(sent) },
		func() string { return secSessionsSummary() },
		func() string { return secThreatSummary(sec) },
		func() string { return secAttacksSummary(sent, sec) },
		func() string { return secDNSSummary(sent, sec) },
		func() string { return secFlowsSummary(sent) },
		func() string { return secTLSSummary(sec) },
	}

	// Render functions for expanded content
	renderFuncs := [secSecCount]func() string{
		func() string { return renderSecAuthContent(sec, iw) },
		func() string { return renderSecPortsContent(sec, iw) },
		func() string { return renderSecSUIDContent(sec, iw) },
		func() string { return renderSecExecContent(sent, iw) },
		func() string { return renderSecPtraceContent(sent, iw) },
		func() string { return renderSecReverseShellContent(sec, iw) },
		func() string { return renderSecFilelessContent(snap, iw) },
		func() string { return renderSecModLoadsContent(sent, iw) },
		func() string { return renderSecSessionsContent(iw) },
		func() string { return renderSecThreatContent(sec, iw) },
		func() string { return renderSecAttacksContent(sent, sec, iw) },
		func() string { return renderSecDNSContent(sent, sec, iw) },
		func() string { return renderSecFlowsContent(sent, iw) },
		func() string { return renderSecTLSContent(sec, iw) },
	}

	// Render each section
	for i := 0; i < secSecCount; i++ {
		header := renderNetSectionHeader(secSectionNames[i], summaryFuncs[i](), i == cursor, expanded[i], iw)
		sb.WriteString(header)
		if expanded[i] {
			sb.WriteString(renderFuncs[i]())
		}
	}

	// Key hint line
	sb.WriteString(pageFooter("Tab:section  Enter:expand/collapse  A:all  C:collapse"))

	return sb.String()
}

// ── Summary functions (shown in collapsed header) ────────────────────────────

func secAuthSummary(sec model.SecurityMetrics) string {
	if sec.BruteForce {
		return "BRUTE FORCE active"
	}
	if sec.FailedAuthRate > 1 {
		return fmt.Sprintf("%.1f/s failed auth", sec.FailedAuthRate)
	}
	if sec.FailedAuthTotal > 0 {
		return fmt.Sprintf("%d failed", sec.FailedAuthTotal)
	}
	return "no failures"
}

func secPortsSummary(sec model.SecurityMetrics) string {
	n := len(sec.NewPorts)
	if n == 0 {
		return "none"
	}
	return fmt.Sprintf("%d new port(s)", n)
}

func secSUIDSummary(sec model.SecurityMetrics) string {
	n := len(sec.SUIDAnomalies)
	if n == 0 {
		return "clean"
	}
	return fmt.Sprintf("%d anomaly(ies)", n)
}

func secExecSummary(sent model.SentinelData) string {
	if !sent.Active {
		return "sentinel inactive"
	}
	n := len(sent.ExecEvents)
	if n == 0 {
		return "none"
	}
	// Count suspicious
	var warn, crit int
	for _, e := range sent.ExecEvents {
		sev := classifyExecSeverity(e.Comm, e.Filename)
		if sev == "crit" {
			crit++
		} else if sev == "warn" {
			warn++
		}
	}
	if crit > 0 {
		return fmt.Sprintf("%d CRIT, %d WARN", crit, warn)
	}
	if warn > 0 {
		return fmt.Sprintf("%d WARN", warn)
	}
	return fmt.Sprintf("%d normal", n)
}

func secPtraceSummary(sent model.SentinelData) string {
	if !sent.Active {
		return "sentinel inactive"
	}
	n := len(sent.PtraceEvents)
	if n == 0 {
		return "none"
	}
	return fmt.Sprintf("%d event(s)", n)
}

func secReverseShellSummary(sec model.SecurityMetrics) string {
	n := len(sec.ReverseShells)
	if n == 0 {
		return "none"
	}
	return fmt.Sprintf("%d DETECTED", n)
}

func secFilelessSummary(snap *model.Snapshot) string {
	n := len(snap.Global.FilelessProcs)
	if n == 0 {
		return "none"
	}
	return fmt.Sprintf("%d detected", n)
}

func secModLoadsSummary(sent model.SentinelData) string {
	if !sent.Active {
		return "sentinel inactive"
	}
	n := len(sent.ModLoads)
	if n == 0 {
		return "none"
	}
	return fmt.Sprintf("%d module(s)", n)
}

func secSessionsSummary() string {
	return "n/a"
}

func secThreatSummary(sec model.SecurityMetrics) string {
	ts := sec.ThreatScore
	if ts == "" || ts == "CLEAR" {
		return "all clear"
	}
	return ts
}

func secAttacksSummary(sent model.SentinelData, sec model.SecurityMetrics) string {
	total := len(sent.SynFlood) + len(sent.PortScans) + len(sec.TCPFlagAnomalies)
	if total == 0 {
		return "none"
	}
	var parts []string
	if n := len(sent.SynFlood); n > 0 {
		parts = append(parts, fmt.Sprintf("%d flood", n))
	}
	if n := len(sent.PortScans); n > 0 {
		parts = append(parts, fmt.Sprintf("%d scan", n))
	}
	if n := len(sec.TCPFlagAnomalies); n > 0 {
		parts = append(parts, fmt.Sprintf("%d flag", n))
	}
	return strings.Join(parts, ", ")
}

func secDNSSummary(sent model.SentinelData, sec model.SecurityMetrics) string {
	total := len(sent.DNSAnomaly) + len(sec.DNSTunnelIndicators)
	if total == 0 {
		return "none"
	}
	var parts []string
	if n := len(sent.DNSAnomaly); n > 0 {
		parts = append(parts, fmt.Sprintf("%d anomaly", n))
	}
	if n := len(sec.DNSTunnelIndicators); n > 0 {
		parts = append(parts, fmt.Sprintf("%d tunnel", n))
	}
	return strings.Join(parts, ", ")
}

func secFlowsSummary(sent model.SentinelData) string {
	total := len(sent.FlowRates) + len(sent.OutboundTop)
	if total == 0 {
		return "none"
	}
	var parts []string
	if n := len(sent.FlowRates); n > 0 {
		parts = append(parts, fmt.Sprintf("%d flow", n))
	}
	if n := len(sent.OutboundTop); n > 0 {
		parts = append(parts, fmt.Sprintf("%d outbound", n))
	}
	return strings.Join(parts, ", ")
}

func secTLSSummary(sec model.SecurityMetrics) string {
	n := len(sec.JA3Fingerprints)
	if n == 0 {
		return "inactive"
	}
	// Count known-bad
	var bad int
	for _, j := range sec.JA3Fingerprints {
		known := strings.ToLower(j.Known)
		if known != "" && known != "unknown" && !strings.Contains(known, "ok") &&
			!strings.Contains(known, "chrome") && !strings.Contains(known, "firefox") &&
			!strings.Contains(known, "safari") && !strings.Contains(known, "curl") {
			bad++
		}
	}
	if bad > 0 {
		return fmt.Sprintf("%d fingerprint(s), %d SUSPECT", n, bad)
	}
	return fmt.Sprintf("%d fingerprint(s)", n)
}

// ── Content renderers (shown when section is expanded) ──────────────────────

func renderSecAuthContent(sec model.SecurityMetrics, iw int) string {
	var sb strings.Builder

	rateStr := fmt.Sprintf("%.1f/s", sec.FailedAuthRate)
	if sec.FailedAuthRate > 1 {
		rateStr = critStyle.Render(rateStr)
	} else if sec.FailedAuthRate > 0 {
		rateStr = warnStyle.Render(rateStr)
	} else {
		rateStr = okStyle.Render(rateStr)
	}
	bruteStr := okStyle.Render("No")
	if sec.BruteForce {
		bruteStr = critStyle.Render("YES — active brute force")
	}
	sb.WriteString(fmt.Sprintf("  Failed auth rate: %s   Total: %s   Brute force: %s\n",
		rateStr, valueStyle.Render(fmt.Sprintf("%d", sec.FailedAuthTotal)), bruteStr))

	if len(sec.FailedAuthIPs) > 0 {
		sb.WriteString("\n")
		sb.WriteString(dimStyle.Render("  Source IP              Count") + "\n")
		sb.WriteString(dimStyle.Render("  "+strings.Repeat("─", 35)) + "\n")
		const maxAuthIPs = 10
		shown := sec.FailedAuthIPs
		overflow := 0
		if len(shown) > maxAuthIPs {
			overflow = len(shown) - maxAuthIPs
			shown = shown[:maxAuthIPs]
		}
		for _, ip := range shown {
			sb.WriteString(fmt.Sprintf("  %s %s\n",
				styledPad(valueStyle.Render(ip.IP), 22),
				warnStyle.Render(fmt.Sprintf("%d", ip.Count))))
		}
		if overflow > 0 {
			sb.WriteString(dimStyle.Render(fmt.Sprintf("  ... and %d more", overflow)) + "\n")
		}
	}
	return sb.String()
}

func renderSecPortsContent(sec model.SecurityMetrics, iw int) string {
	var sb strings.Builder
	if len(sec.NewPorts) == 0 {
		sb.WriteString(okStyle.Render("  No new ports since startup") + "\n")
	} else {
		sb.WriteString(dimStyle.Render("  Port     PID    Comm") + "\n")
		sb.WriteString(dimStyle.Render("  "+strings.Repeat("─", 30)) + "\n")
		for _, p := range sec.NewPorts {
			sb.WriteString(fmt.Sprintf("  %s %s %s\n",
				warnStyle.Render(padRight(fmt.Sprintf("%d", p.Port), 8)),
				styledPad(valueStyle.Render(padRight(fmt.Sprintf("%d", p.PID), 6)), 6),
				valueStyle.Render(p.Comm)))
		}
	}
	return sb.String()
}

func renderSecSUIDContent(sec model.SecurityMetrics, iw int) string {
	var sb strings.Builder
	if len(sec.SUIDAnomalies) == 0 {
		sb.WriteString(okStyle.Render("  No new SUID binaries since startup") + "\n")
	} else {
		sb.WriteString(dimStyle.Render("  Path                                           Modified") + "\n")
		sb.WriteString(dimStyle.Render("  "+strings.Repeat("─", 60)) + "\n")
		for _, s := range sec.SUIDAnomalies {
			sb.WriteString(fmt.Sprintf("  %s %s\n",
				critStyle.Render(padRight(s.Path, 48)),
				dimStyle.Render(s.ModTime.Format("2006-01-02 15:04"))))
		}
	}
	return sb.String()
}

func renderSecExecContent(sent model.SentinelData, iw int) string {
	var sb strings.Builder
	if !sent.Active {
		sb.WriteString(dimStyle.Render("  BPF sentinel not active") + "\n")
		return sb.String()
	}
	if len(sent.ExecEvents) == 0 {
		sb.WriteString(okStyle.Render("  No process executions detected") + "\n")
		return sb.String()
	}

	// Classify severity and sort: CRIT first, then WARN, skip OK
	type execRow struct {
		entry model.ExecEventEntry
		sev   string
		tag   string
	}
	var rows []execRow
	var okCount int
	for _, e := range sent.ExecEvents {
		sev := classifyExecSeverity(e.Comm, e.Filename)
		if sev == "ok" {
			okCount++
			continue
		}
		tag := "WARN"
		if sev == "crit" {
			tag = "CRIT"
		}
		rows = append(rows, execRow{entry: e, sev: sev, tag: tag})
	}
	sort.SliceStable(rows, func(i, j int) bool {
		if rows[i].sev != rows[j].sev {
			if rows[i].sev == "crit" {
				return true
			}
			if rows[j].sev == "crit" {
				return false
			}
		}
		return rows[i].entry.Timestamp > rows[j].entry.Timestamp
	})
	if len(rows) == 0 {
		msg := fmt.Sprintf("  No suspicious executions (%d normal events filtered)", okCount)
		sb.WriteString(okStyle.Render(msg) + "\n")
	} else {
		sb.WriteString(dimStyle.Render("  SEV   PID      PPID     UID    COMM             FILENAME                           COUNT") + "\n")
		sb.WriteString(dimStyle.Render("  "+strings.Repeat("─", iw-4)) + "\n")
		limit := 20
		if len(rows) < limit {
			limit = len(rows)
		}
		for _, r := range rows[:limit] {
			e := r.entry
			style := warnStyle
			if r.sev == "crit" {
				style = critStyle
			}
			fn := e.Filename
			if len(fn) > 34 {
				fn = fn[:31] + "..."
			}
			sb.WriteString(fmt.Sprintf("  %s %s %s %s %s %s %s\n",
				styledPad(style.Render(r.tag), 5),
				styledPad(style.Render(fmt.Sprintf("%d", e.PID)), 8),
				styledPad(valueStyle.Render(fmt.Sprintf("%d", e.PPID)), 8),
				styledPad(valueStyle.Render(fmt.Sprintf("%d", e.UID)), 6),
				styledPad(valueStyle.Render(padRight(e.Comm, 16)), 16),
				styledPad(dimStyle.Render(padRight(fn, 34)), 34),
				valueStyle.Render(fmt.Sprintf("%d", e.Count))))
		}
		if okCount > 0 {
			sb.WriteString(dimStyle.Render(fmt.Sprintf("  + %d normal executions filtered", okCount)) + "\n")
		}
	}
	return sb.String()
}

func renderSecPtraceContent(sent model.SentinelData, iw int) string {
	var sb strings.Builder
	if !sent.Active {
		sb.WriteString(dimStyle.Render("  BPF sentinel not active") + "\n")
		return sb.String()
	}
	if len(sent.PtraceEvents) == 0 {
		sb.WriteString(okStyle.Render("  No ptrace activity detected") + "\n")
		return sb.String()
	}
	sb.WriteString(dimStyle.Render("  TRACER PID  TRACER           TARGET PID  TARGET           REQUEST          COUNT") + "\n")
	sb.WriteString(dimStyle.Render("  "+strings.Repeat("─", iw-4)) + "\n")
	for _, p := range sent.PtraceEvents {
		sb.WriteString(fmt.Sprintf("  %s %s %s %s %s %s\n",
			critStyle.Render(padRight(fmt.Sprintf("%d", p.TracerPID), 11)),
			styledPad(critStyle.Render(padRight(p.TracerComm, 16)), 16),
			styledPad(critStyle.Render(padRight(fmt.Sprintf("%d", p.TargetPID), 11)), 11),
			styledPad(valueStyle.Render(padRight(p.TargetComm, 16)), 16),
			styledPad(critStyle.Render(padRight(p.RequestStr, 16)), 16),
			valueStyle.Render(fmt.Sprintf("%d", p.Count))))
	}
	return sb.String()
}

func renderSecReverseShellContent(sec model.SecurityMetrics, iw int) string {
	var sb strings.Builder
	if len(sec.ReverseShells) == 0 {
		sb.WriteString(okStyle.Render("  None detected") + "\n")
		return sb.String()
	}
	sb.WriteString(dimStyle.Render("  PID    Comm             FD0                   FD1") + "\n")
	sb.WriteString(dimStyle.Render("  "+strings.Repeat("─", 70)) + "\n")
	for _, r := range sec.ReverseShells {
		sb.WriteString(fmt.Sprintf("  %s %s %s %s\n",
			critStyle.Render(padRight(fmt.Sprintf("%d", r.PID), 6)),
			styledPad(valueStyle.Render(padRight(r.Comm, 16)), 16),
			styledPad(dimStyle.Render(truncate(r.FD0, 20)), 21),
			dimStyle.Render(truncate(r.FD1, 20))))
	}
	return sb.String()
}

func renderSecFilelessContent(snap *model.Snapshot, iw int) string {
	var sb strings.Builder
	fp := snap.Global.FilelessProcs
	if len(fp) == 0 {
		sb.WriteString(okStyle.Render("  None detected") + "\n")
		return sb.String()
	}
	sb.WriteString(dimStyle.Render("  PID    Comm             ExePath                          Conns  IPs") + "\n")
	sb.WriteString(dimStyle.Render("  "+strings.Repeat("─", iw-4)) + "\n")
	for _, f := range fp {
		sev := warnStyle
		if f.NetConns > 0 {
			sev = critStyle
		}
		ips := strings.Join(f.RemoteIPs, ", ")
		if len(ips) > 30 {
			ips = ips[:27] + "..."
		}
		sb.WriteString(fmt.Sprintf("  %s %s %s %s %s\n",
			sev.Render(padRight(fmt.Sprintf("%d", f.PID), 6)),
			styledPad(valueStyle.Render(padRight(f.Comm, 16)), 16),
			styledPad(dimStyle.Render(truncate(f.ExePath, 32)), 32),
			styledPad(valueStyle.Render(fmt.Sprintf("%d", f.NetConns)), 6),
			dimStyle.Render(ips)))
	}
	return sb.String()
}

func renderSecModLoadsContent(sent model.SentinelData, iw int) string {
	var sb strings.Builder
	if !sent.Active {
		sb.WriteString(dimStyle.Render("  BPF sentinel not active") + "\n")
		return sb.String()
	}
	if len(sent.ModLoads) == 0 {
		sb.WriteString(okStyle.Render("  No module loads detected") + "\n")
		return sb.String()
	}
	sb.WriteString(dimStyle.Render("  MODULE                         COUNT") + "\n")
	sb.WriteString(dimStyle.Render("  "+strings.Repeat("─", 42)) + "\n")
	for _, m := range sent.ModLoads {
		name := m.Name
		if len(name) > 30 {
			name = name[:27] + "..."
		}
		sb.WriteString(fmt.Sprintf("  %s %s\n",
			warnStyle.Render(padRight(name, 30)),
			valueStyle.Render(fmt.Sprintf("%d", m.Count))))
	}
	return sb.String()
}

func renderSecSessionsContent(iw int) string {
	return dimStyle.Render("  Session tracking not yet implemented") + "\n"
}

// ── New Section 9: NETWORK THREAT OVERVIEW ──────────────────────────────────

func renderSecThreatContent(sec model.SecurityMetrics, iw int) string {
	var sb strings.Builder

	ts := sec.ThreatScore
	if ts == "" {
		ts = "CLEAR"
	}

	// Threat status badge
	var badge string
	switch ts {
	case "CLEAR":
		badge = okStyle.Render("CLEAR")
	case "ANOMALY":
		badge = warnStyle.Render("ANOMALY")
	case "THREAT":
		badge = critStyle.Render("THREAT DETECTED")
	default:
		badge = dimStyle.Render(ts)
	}

	sb.WriteString(boxTopTitle(" NETWORK THREAT STATUS ", iw) + "\n")
	sb.WriteString(boxRow(fmt.Sprintf("STATUS: %s", badge), iw) + "\n")

	// Active watchdogs
	if len(sec.ActiveWatchdogs) > 0 {
		wdList := strings.Join(sec.ActiveWatchdogs, ", ")
		sb.WriteString(boxRow(fmt.Sprintf("Active watchdogs: %s", valueStyle.Render(wdList)), iw) + "\n")
	}

	// Quick intel summary
	totalAttacks := len(sec.TCPFlagAnomalies) + len(sec.JA3Fingerprints) + len(sec.BeaconIndicators) + len(sec.DNSTunnelIndicators)
	if totalAttacks > 0 {
		sb.WriteString(boxRow(fmt.Sprintf("Active indicators: %s",
			warnStyle.Render(fmt.Sprintf("%d signal(s)", totalAttacks))), iw) + "\n")
	} else {
		sb.WriteString(boxRow(okStyle.Render("No active threats — all clear"), iw) + "\n")
	}
	sb.WriteString(boxBot(iw) + "\n")

	return sb.String()
}

// ── New Section 10: ATTACK DETECTION (BPF) ──────────────────────────────────

func renderSecAttacksContent(sent model.SentinelData, sec model.SecurityMetrics, iw int) string {
	var sb strings.Builder
	hasData := false

	// SYN Flood table
	if len(sent.SynFlood) > 0 {
		hasData = true
		sb.WriteString(headerStyle.Render("  SYN FLOOD") + "\n")
		sb.WriteString(dimStyle.Render("  Source             SYN/s     Half-Open%  Duration") + "\n")
		sb.WriteString(dimStyle.Render("  "+strings.Repeat("─", 55)) + "\n")
		for _, s := range sent.SynFlood {
			hoStr := fmt.Sprintf("%.1f%%", s.HalfOpenRatio*100)
			if s.HalfOpenRatio > 0.5 {
				hoStr = critStyle.Render(hoStr)
			} else {
				hoStr = warnStyle.Render(hoStr)
			}
			sb.WriteString(fmt.Sprintf("  %s %s %s %s\n",
				styledPad(critStyle.Render(padRight(s.SrcIP, 18)), 18),
				styledPad(critStyle.Render(fmt.Sprintf("%.0f", s.Rate)), 9),
				styledPad(hoStr, 11),
				dimStyle.Render(fmt.Sprintf("%.0fs", float64(s.SynCount)/max64f(s.Rate, 1)))))
		}
		sb.WriteString("\n")
	}

	// Port Scan table
	if len(sent.PortScans) > 0 {
		hasData = true
		sb.WriteString(headerStyle.Render("  PORT SCAN") + "\n")
		sb.WriteString(dimStyle.Render("  Source             RSTs     Ports    Duration") + "\n")
		sb.WriteString(dimStyle.Render("  "+strings.Repeat("─", 55)) + "\n")
		for _, p := range sent.PortScans {
			sb.WriteString(fmt.Sprintf("  %s %s %s %s\n",
				styledPad(warnStyle.Render(padRight(p.SrcIP, 18)), 18),
				styledPad(warnStyle.Render(fmt.Sprintf("%d", p.RSTCount)), 8),
				styledPad(valueStyle.Render(fmt.Sprintf("%d", p.UniquePortBuckets)), 8),
				dimStyle.Render(fmt.Sprintf("%.0fs", p.DurationSec))))
		}
		sb.WriteString("\n")
	}

	// TCP Flag Anomalies
	if len(sec.TCPFlagAnomalies) > 0 {
		hasData = true
		sb.WriteString(headerStyle.Render("  TCP FLAG ANOMALIES") + "\n")
		sb.WriteString(dimStyle.Render("  Source             Flags          Count") + "\n")
		sb.WriteString(dimStyle.Render("  "+strings.Repeat("─", 48)) + "\n")
		for _, f := range sec.TCPFlagAnomalies {
			sb.WriteString(fmt.Sprintf("  %s %s %s\n",
				styledPad(critStyle.Render(padRight(f.SrcIP, 18)), 18),
				styledPad(critStyle.Render(padRight(f.FlagCombo, 14)), 14),
				valueStyle.Render(fmt.Sprintf("%d", f.Count))))
		}
		sb.WriteString("\n")
	}

	if !hasData {
		sb.WriteString(okStyle.Render("  No attack patterns detected") + "\n")
	}

	return sb.String()
}

// ── New Section 11: DNS INTELLIGENCE (BPF) ──────────────────────────────────

func renderSecDNSContent(sent model.SentinelData, sec model.SecurityMetrics, iw int) string {
	var sb strings.Builder
	hasData := false

	// DNS anomalies from sentinel
	if len(sent.DNSAnomaly) > 0 {
		hasData = true
		sb.WriteString(headerStyle.Render("  DNS ANOMALIES") + "\n")
		sb.WriteString(dimStyle.Render("  PID     Comm             Queries/s   Avg Len   Verdict") + "\n")
		sb.WriteString(dimStyle.Render("  "+strings.Repeat("─", 60)) + "\n")
		for _, d := range sent.DNSAnomaly {
			verdict := okStyle.Render("normal")
			if d.QueriesPerSec > 100 || d.AvgQueryLen > 50 {
				verdict = warnStyle.Render("SUSPECT")
			}
			if d.QueriesPerSec > 200 && d.AvgQueryLen > 60 {
				verdict = critStyle.Render("TUNNEL")
			}
			sb.WriteString(fmt.Sprintf("  %s %s %s %s %s\n",
				styledPad(valueStyle.Render(fmt.Sprintf("%d", d.PID)), 7),
				styledPad(valueStyle.Render(padRight(d.Comm, 16)), 16),
				styledPad(valueStyle.Render(fmt.Sprintf("%.1f", d.QueriesPerSec)), 11),
				styledPad(valueStyle.Render(fmt.Sprintf("%d", d.AvgQueryLen)), 9),
				verdict))
		}
		sb.WriteString("\n")
	}

	// DNS tunnel indicators from watchdog
	if len(sec.DNSTunnelIndicators) > 0 {
		hasData = true
		sb.WriteString(headerStyle.Render("  DNS TUNNELING INDICATORS") + "\n")
		sb.WriteString(dimStyle.Render("  PID     Comm             TXT%      Rate/s    Verdict") + "\n")
		sb.WriteString(dimStyle.Render("  "+strings.Repeat("─", 60)) + "\n")
		for _, d := range sec.DNSTunnelIndicators {
			txtPct := d.TXTRatio * 100
			txtStr := fmt.Sprintf("%.0f%%", txtPct)
			if txtPct > 70 {
				txtStr = critStyle.Render(txtStr)
			} else if txtPct > 30 {
				txtStr = warnStyle.Render(txtStr)
			} else {
				txtStr = valueStyle.Render(txtStr)
			}
			verdict := okStyle.Render("normal")
			if txtPct > 70 {
				verdict = critStyle.Render("TUNNEL")
			} else if txtPct > 30 {
				verdict = warnStyle.Render("SUSPECT")
			}
			sb.WriteString(fmt.Sprintf("  %s %s %s %s %s\n",
				styledPad(valueStyle.Render(fmt.Sprintf("%d", d.PID)), 7),
				styledPad(valueStyle.Render(padRight(d.Comm, 16)), 16),
				styledPad(txtStr, 9),
				styledPad(valueStyle.Render(fmt.Sprintf("%.1f", d.QueryRate)), 9),
				verdict))
		}
		sb.WriteString("\n")
	}

	if !hasData {
		sb.WriteString(okStyle.Render("  No DNS anomalies detected") + "\n")
	}

	return sb.String()
}

// ── New Section 12: FLOW INTELLIGENCE (BPF) ─────────────────────────────────

func renderSecFlowsContent(sent model.SentinelData, iw int) string {
	var sb strings.Builder
	hasData := false

	// Outbound volume table
	if len(sent.OutboundTop) > 0 {
		hasData = true
		sb.WriteString(headerStyle.Render("  OUTBOUND VOLUME") + "\n")
		sb.WriteString(dimStyle.Render("  PID     Comm             Dest IP          MB/hr    Pkts/s   Flag") + "\n")
		sb.WriteString(dimStyle.Render("  "+strings.Repeat("─", 72)) + "\n")
		for _, o := range sent.OutboundTop {
			mbHr := float64(o.TotalBytes) / 1024.0 / 1024.0 * 3600.0 / max64f(float64(o.PacketCount), 1)
			// Simpler: use BytesPerSec to compute MB/hr
			mbHrFromRate := o.BytesPerSec * 3600.0 / 1024.0 / 1024.0
			if mbHrFromRate > 0 {
				mbHr = mbHrFromRate
			}
			avgPktSize := max64f(float64(o.TotalBytes)/float64(max64u(o.PacketCount, 1)), 64)
			pktsPerSec := o.BytesPerSec / avgPktSize
			flag := ""
			if mbHr > 100 {
				flag = critStyle.Render("EXFIL")
			} else if mbHr > 10 {
				flag = warnStyle.Render("HIGH")
			}

			sb.WriteString(fmt.Sprintf("  %s %s %s %s %s %s\n",
				styledPad(valueStyle.Render(fmt.Sprintf("%d", o.PID)), 7),
				styledPad(valueStyle.Render(padRight(o.Comm, 16)), 16),
				styledPad(dimStyle.Render(padRight(o.DstIP, 16)), 16),
				styledPad(valueStyle.Render(fmt.Sprintf("%.1f", mbHr)), 8),
				styledPad(valueStyle.Render(fmt.Sprintf("%.0f", pktsPerSec)), 8),
				flag))
		}
		sb.WriteString("\n")
	}

	// Lateral movement (FlowRates with high unique dest counts)
	var lateralEntries []model.FlowRateEntry
	for _, f := range sent.FlowRates {
		if f.UniqueDestCount > 5 {
			lateralEntries = append(lateralEntries, f)
		}
	}
	if len(lateralEntries) > 0 {
		hasData = true
		sb.WriteString(headerStyle.Render("  LATERAL MOVEMENT") + "\n")
		sb.WriteString(dimStyle.Render("  PID     Comm             Unique Dests   Rate/s    Flag") + "\n")
		sb.WriteString(dimStyle.Render("  "+strings.Repeat("─", 60)) + "\n")
		for _, f := range lateralEntries {
			flag := warnStyle.Render("LATERAL")
			if f.UniqueDestCount > 20 {
				flag = critStyle.Render("LATERAL")
			}
			sb.WriteString(fmt.Sprintf("  %s %s %s %s %s\n",
				styledPad(valueStyle.Render(fmt.Sprintf("%d", f.PID)), 7),
				styledPad(valueStyle.Render(padRight(f.Comm, 16)), 16),
				styledPad(warnStyle.Render(fmt.Sprintf("%d", f.UniqueDestCount)), 14),
				styledPad(valueStyle.Render(fmt.Sprintf("%.1f", f.Rate)), 9),
				flag))
		}
		sb.WriteString("\n")
	}

	// Beacon detection (from watchdog)
	// Beacon indicators are in sec.BeaconIndicators but we don't have sec here;
	// we rely on the caller or skip. Actually let me check — sent doesn't have beacons.
	// BeaconIndicators are in SecurityMetrics. We'll handle this in the main render function
	// by passing sec. For now, flow rates are sufficient.

	if !hasData {
		if len(sent.FlowRates) > 0 {
			// Show normal flow rates
			sb.WriteString(dimStyle.Render("  Flow rates detected but no anomalous patterns") + "\n")
		} else {
			sb.WriteString(okStyle.Render("  No flow anomalies detected") + "\n")
		}
	}

	return sb.String()
}

// ── New Section 13: TLS FINGERPRINTS (BPF) ──────────────────────────────────

func renderSecTLSContent(sec model.SecurityMetrics, iw int) string {
	var sb strings.Builder

	// JA3 Fingerprints
	if len(sec.JA3Fingerprints) > 0 {
		sb.WriteString(headerStyle.Render("  JA3 FINGERPRINTS") + "\n")
		sb.WriteString(dimStyle.Render("  JA3 Hash           Count   Sample Src        Match") + "\n")
		sb.WriteString(dimStyle.Render("  "+strings.Repeat("─", 65)) + "\n")
		for _, j := range sec.JA3Fingerprints {
			hash := j.Hash
			if len(hash) > 16 {
				hash = hash[:13] + "..."
			}

			match := j.Known
			if match == "" {
				match = "unknown"
			}
			matchStyle := dimStyle
			knownLower := strings.ToLower(match)
			if strings.Contains(knownLower, "cobalt") || strings.Contains(knownLower, "metasploit") ||
				strings.Contains(knownLower, "sliver") || strings.Contains(knownLower, "empire") {
				matchStyle = critStyle
			} else if strings.Contains(knownLower, "ok") || strings.Contains(knownLower, "chrome") ||
				strings.Contains(knownLower, "firefox") || strings.Contains(knownLower, "safari") ||
				strings.Contains(knownLower, "curl") {
				matchStyle = okStyle
			} else if match != "unknown" {
				matchStyle = warnStyle
			}

			sb.WriteString(fmt.Sprintf("  %s %s %s %s\n",
				styledPad(valueStyle.Render(padRight(hash, 18)), 18),
				styledPad(valueStyle.Render(fmt.Sprintf("%d", j.Count)), 7),
				styledPad(dimStyle.Render(padRight(j.SampleSrc, 17)), 17),
				matchStyle.Render(match)))
		}
		sb.WriteString("\n")
	}

	// Beacon indicators
	if len(sec.BeaconIndicators) > 0 {
		sb.WriteString(headerStyle.Render("  BEACON DETECTION") + "\n")
		sb.WriteString(dimStyle.Render("  PID     Comm          Dest                Interval   Jitter    Flag") + "\n")
		sb.WriteString(dimStyle.Render("  "+strings.Repeat("─", 72)) + "\n")
		for _, b := range sec.BeaconIndicators {
			dest := fmt.Sprintf("%s:%d", b.DstIP, b.DstPort)
			if len(dest) > 18 {
				dest = dest[:15] + "..."
			}
			jitterStr := fmt.Sprintf("%.1f%%", b.Jitter*100)
			flag := ""
			if b.Jitter < 0.05 && b.SampleCount > 5 {
				flag = critStyle.Render("C2")
			} else if b.Jitter < 0.15 {
				flag = warnStyle.Render("SUSPECT")
			}
			sb.WriteString(fmt.Sprintf("  %s %s %s %s %s %s\n",
				styledPad(valueStyle.Render(fmt.Sprintf("%d", b.PID)), 7),
				styledPad(valueStyle.Render(padRight(b.Comm, 13)), 13),
				styledPad(dimStyle.Render(padRight(dest, 19)), 19),
				styledPad(valueStyle.Render(fmt.Sprintf("%.1fs", b.AvgIntervalSec)), 10),
				styledPad(valueStyle.Render(jitterStr), 9),
				flag))
		}
		sb.WriteString("\n")
	}

	if len(sec.JA3Fingerprints) == 0 && len(sec.BeaconIndicators) == 0 {
		sb.WriteString(dimStyle.Render("  TLS fingerprinting inactive — no watchdog data") + "\n")
	}

	return sb.String()
}

// ── Helpers ─────────────────────────────────────────────────────────────────

// max64f returns the larger of two float64 values.
func max64f(a, b float64) float64 {
	if a > b {
		return a
	}
	return b
}

// max64u returns the larger of two uint64 values.
func max64u(a, b uint64) uint64 {
	if a > b {
		return a
	}
	return b
}

// autoExpandSecSection auto-expands sections with anomalous data.
func autoExpandSecSection(snap *model.Snapshot, expanded *[secSecCount]bool) {
	if snap == nil {
		return
	}
	sec := snap.Global.Security
	sent := snap.Global.Sentinel

	// Attacks
	if len(sent.SynFlood) > 0 || len(sent.PortScans) > 0 || len(sec.TCPFlagAnomalies) > 0 {
		expanded[secSecAttacks] = true
	}
	// DNS
	if len(sent.DNSAnomaly) > 0 || len(sec.DNSTunnelIndicators) > 0 {
		expanded[secSecDNS] = true
	}
	// Flows
	if len(sent.FlowRates) > 0 || len(sent.OutboundTop) > 0 {
		expanded[secSecFlows] = true
	}
	// Brute force
	if sec.BruteForce {
		expanded[secSecAuth] = true
	}
	// Reverse shells
	if len(sec.ReverseShells) > 0 {
		expanded[secSecReverseShell] = true
	}
	// TLS anomalies
	if len(sec.BeaconIndicators) > 0 || len(sec.JA3Fingerprints) > 0 {
		expanded[secSecTLS] = true
	}
	// Threat overview
	if sec.ThreatScore != "" && sec.ThreatScore != "CLEAR" {
		expanded[secSecThreat] = true
	}
}
