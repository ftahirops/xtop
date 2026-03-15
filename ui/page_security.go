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

// isProxyProcess returns true for load balancers / reverse proxies that naturally
// connect to many backends and move large volumes of traffic.
func isProxyProcess(comm string) bool {
	switch strings.ToLower(comm) {
	case "haproxy", "nginx", "envoy", "traefik", "caddy", "squid", "varnish",
		"apache2", "httpd", "lighttpd", "pound", "relayd":
		return true
	}
	return false
}

// knownMultiDestVerdict returns a plain-English verdict for processes that are known
// to legitimately connect to many destinations. Returns "" if the process is unknown.
func knownMultiDestVerdict(comm string) string {
	switch strings.ToLower(comm) {
	// Log shippers
	case "rsyslogd", "syslog-ng", "syslogd":
		return "Log forwarder — connects to many hosts to collect/relay logs"
	case "filebeat", "fluentd", "fluent-bit", "logstash", "vector":
		return "Log shipper — sends logs from multiple sources to central store"
	// Monitoring agents
	case "agent", "trace-agent", "process-agent", "datadog-agent":
		return "Monitoring agent (Datadog) — polls metrics from all local services"
	case "telegraf", "collectd", "node_exporter", "prometheus", "grafana-agent",
		"alloy", "otel-collector", "newrelic-infra", "zabbix_agentd":
		return "Monitoring agent — collects metrics from multiple endpoints"
	// System services
	case "unattended-upgr", "unattended-upgrade", "apt", "dpkg", "yum", "dnf", "packagekitd":
		return "Package manager — connects to multiple mirrors for updates"
	case "systemd-resolve", "systemd-resolved", "dnsmasq", "named", "unbound", "coredns":
		return "DNS resolver — resolves queries to many upstream servers"
	// Orchestration / config management
	case "ansible", "puppet", "chef-client", "salt-minion", "consul", "consul-agent":
		return "Config management / service discovery — connects to managed hosts"
	case "kubelet", "kube-proxy", "containerd", "dockerd", "crio":
		return "Container orchestrator — manages containers across the cluster"
	// Backup / sync
	case "rsync", "rclone", "borgbackup", "restic", "bacula-fd":
		return "Backup tool — syncs data to/from multiple storage targets"
	// Databases (replication, cluster gossip)
	case "mysqld", "mariadbd", "postgres", "mongod", "mongos", "redis-server", "redis-sentinel",
		"cassandra", "cqlsh", "cockroach", "etcd", "galera":
		return "Database — cluster replication/gossip connects to multiple peers"
	// Service mesh sidecars
	case "istio-proxy", "linkerd-proxy", "linkerd2-proxy", "consul-connect":
		return "Service mesh sidecar — proxies traffic to multiple service backends"
	// Mail servers
	case "postfix", "sendmail", "exim", "dovecot", "master":
		return "Mail server — delivers mail to many remote MX hosts"
	// CI/CD runners
	case "gitlab-runner", "actions-runner", "jenkins-agent", "buildkitd", "drone-runner":
		return "CI/CD runner — connects to artifact stores, registries, and deploy targets"
	// Media / streaming
	case "ffmpeg", "vlc", "gstreamer", "nginx-rtmp":
		return "Media server — streams to multiple clients/CDN endpoints"
	// MCP / Claude Code (developer tools)
	case "claude", "node", "npx", "claude-code":
		return "Developer tool / MCP server — connects to multiple API endpoints"
	}
	return ""
}

// isKnownOutboundProcess returns true for processes that legitimately send large
// volumes of data to external IPs (SSH, logging, monitoring, backups).
func isKnownOutboundProcess(comm string) bool {
	switch strings.ToLower(comm) {
	case "sshd", "ssh", "scp", "sftp", "rsync", "rclone",
		"filebeat", "fluentd", "fluent-bit", "logstash", "vector",
		"agent", "trace-agent", "process-agent", "datadog-agent",
		"telegraf", "newrelic-infra", "zabbix_agentd", "grafana-agent",
		"alloy", "otel-collector", "collectd", "prometheus",
		"rsyslogd", "syslog-ng", "journald",
		"apt", "yum", "dnf", "wget", "curl",
		"borgbackup", "restic", "bacula-fd",
		"containerd", "dockerd", "kubelet", "crio",
		// Databases (replication traffic)
		"mysqld", "mariadbd", "postgres", "mongod", "mongos",
		"redis-server", "redis-sentinel", "cassandra", "cockroach", "etcd",
		// Service mesh
		"istio-proxy", "linkerd-proxy", "envoy",
		// Mail servers
		"postfix", "sendmail", "exim", "dovecot",
		// CI/CD
		"gitlab-runner", "actions-runner", "jenkins-agent", "buildkitd",
		// Media
		"ffmpeg",
		// Developer tools / MCP
		"claude", "node", "npx", "claude-code":
		return true
	}
	return false
}

// isPrivateIP checks if a formatted "a.b.c.d" IP is RFC1918, link-local, or loopback.
func isPrivateIP(ip string) bool {
	if strings.HasPrefix(ip, "10.") || strings.HasPrefix(ip, "127.") ||
		strings.HasPrefix(ip, "192.168.") || strings.HasPrefix(ip, "169.254.") {
		return true
	}
	// 172.16.0.0/12 → 172.16.x.x through 172.31.x.x
	if strings.HasPrefix(ip, "172.") {
		var second int
		fmt.Sscanf(ip, "172.%d.", &second)
		return second >= 16 && second <= 31
	}
	return false
}

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
	// Combine legacy score with BPF threat score
	effectiveScore := sec.Score
	effectiveMsg := "— no anomalies"
	switch sec.ThreatScore {
	case "THREAT":
		effectiveScore = "CRIT"
		effectiveMsg = "— active threat detected (BPF)"
	case "INVESTIGATING":
		if effectiveScore == "" || effectiveScore == "OK" {
			effectiveScore = "WARN"
		}
		effectiveMsg = "— investigating (watchdog active)"
	case "ANOMALY":
		if effectiveScore == "" || effectiveScore == "OK" {
			effectiveScore = "WARN"
		}
		effectiveMsg = "— anomaly detected (BPF)"
	}
	if effectiveScore == "" {
		effectiveScore = "OK"
	}
	switch sec.Score {
	case "CRIT":
		effectiveScore = "CRIT"
		effectiveMsg = "— security signals detected"
	case "WARN":
		if effectiveScore != "CRIT" {
			effectiveScore = "WARN"
		}
		if sec.ThreatScore == "" || sec.ThreatScore == "CLEAR" {
			effectiveMsg = "— review recommended"
		}
	}
	statusLines = append(statusLines, renderHealthBadge(effectiveScore)+" "+dimStyle.Render(effectiveMsg))
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
		// Check if watchdog is active but hasn't collected yet
		for _, w := range sec.ActiveWatchdogs {
			if w == "tlsfinger" {
				return "investigating..."
			}
		}
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
		if sec.BruteForce {
			sb.WriteString(secContext(
				"Someone is rapidly guessing SSH passwords to break into this server.",
				"sudo apt install fail2ban && sudo systemctl enable --now fail2ban",
				"Automated scanners hit every public SSH server. High rate from one IP = real attack."))
		} else if sec.FailedAuthRate > 0.5 {
			sb.WriteString(secContext(
				"Elevated SSH login failures — could be a slow brute force or misconfigured client.",
				"Review IPs above. Block repeat offenders: sudo ufw deny from <IP>",
				"Users mistyping passwords or old SSH keys can cause low-rate failures."))
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
		sb.WriteString(secContext(
			"A process opened a new network port after xtop started. Could be a backdoor or legitimate service.",
			"Verify: ss -tlnp | grep <port>  — if unexpected, kill the process and investigate.",
			"Restarting services (nginx, sshd) or cron jobs legitimately open ports."))
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
		sb.WriteString(secContext(
			"SUID binaries run with root privileges regardless of who executes them. New ones could be privilege escalation backdoors.",
			"Check: ls -la <path> — if unfamiliar, remove SUID bit: sudo chmod u-s <path>",
			"Package updates (apt/yum) can legitimately create SUID binaries."))
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
		hasCrit := false
		for _, r := range rows {
			if r.sev == "crit" {
				hasCrit = true
				break
			}
		}
		if hasCrit {
			sb.WriteString(secContext(
				"CRIT processes are commonly used in attacks (curl, wget, nc, python as child of web server, etc).",
				"Check parent: cat /proc/<PPID>/cmdline — was this launched by a web shell or cron?",
				"Legitimate automation (ansible, chef, monitoring) also runs these tools."))
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
	sb.WriteString(secContext(
		"ptrace lets one process read/write another's memory — used by debuggers but also by malware to inject code.",
		"If unexpected: sudo kill -9 <TRACER_PID> — then check how it was launched.",
		"Debuggers (gdb, strace), IDEs, and anti-cheat software use ptrace legitimately."))
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
	sb.WriteString(secContext(
		critStyle.Render("ACTIVE COMPROMISE")+" — a shell has stdin/stdout redirected to a network socket. An attacker has remote command execution.",
		"IMMEDIATELY: sudo kill -9 <PID> — then investigate: check auth logs, look for persistence, rotate credentials.",
		""))
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
	hasNet := false
	for _, f := range fp {
		if f.NetConns > 0 {
			hasNet = true
			break
		}
	}
	if hasNet {
		sb.WriteString(secContext(
			critStyle.Render("HIGH RISK")+" — process running from deleted binary AND has network connections. Classic malware evasion technique.",
			"sudo kill -9 <PID> — capture memory dump first if forensics needed: gcore <PID>",
			""))
	} else {
		sb.WriteString(secContext(
			"Process binary was deleted from disk but still running in memory. Could be a software update or malware hiding its tracks.",
			"Check: ls -la /proc/<PID>/exe — if it points to '(deleted)', investigate the original path.",
			"Package updates often delete old binaries while processes still run (e.g., apt upgrade)."))
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
	sb.WriteString(secContext(
		"Kernel modules run with full system privileges. Rootkits load as kernel modules to hide from detection.",
		"Check: lsmod | grep <name> — if unfamiliar: sudo modprobe -r <name> and add to /etc/modprobe.d/blacklist.conf",
		"Hardware drivers, filesystem modules, and Docker/containerd load modules normally."))
	return sb.String()
}

func renderSecSessionsContent(iw int) string {
	return ""
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
		sb.WriteString(secContext(
			"SYN flood overwhelms your server with half-open connections, exhausting resources and blocking real users.",
			"Enable SYN cookies: sudo sysctl -w net.ipv4.tcp_syncookies=1 — block source: sudo iptables -A INPUT -s <IP> -j DROP",
			"High-traffic web servers can show elevated SYN rates during traffic spikes."))
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
		sb.WriteString(secContext(
			"An IP is probing many ports to discover running services — usually reconnaissance before an attack.",
			"Block scanner: sudo iptables -A INPUT -s <IP> -j DROP",
			"Load balancers, CDN health checks, and monitoring tools probe multiple ports legitimately."))
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
		sb.WriteString(secContext(
			"Invalid TCP flag combinations (XMAS, NULL, SYN+FIN) are used for OS fingerprinting and firewall evasion.",
			"Block source: sudo iptables -A INPUT -s <IP> -j DROP",
			"Rarely false — broken network stacks can occasionally produce odd flags."))
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
		hasTunnel := false
		for _, d := range sent.DNSAnomaly {
			verdict := okStyle.Render("normal")
			if d.QueriesPerSec > 500 && d.AvgQueryLen > 80 {
				verdict = warnStyle.Render("SUSPECT")
			}
			if d.QueriesPerSec > 1000 && d.AvgQueryLen > 100 {
				verdict = critStyle.Render("TUNNEL")
				hasTunnel = true
			}
			sb.WriteString(fmt.Sprintf("  %s %s %s %s %s\n",
				styledPad(valueStyle.Render(fmt.Sprintf("%d", d.PID)), 7),
				styledPad(valueStyle.Render(padRight(d.Comm, 16)), 16),
				styledPad(valueStyle.Render(fmt.Sprintf("%.1f", d.QueriesPerSec)), 11),
				styledPad(valueStyle.Render(fmt.Sprintf("%d", d.AvgQueryLen)), 9),
				verdict))
		}
		if hasTunnel {
			sb.WriteString(secContext(
				"Unusually high DNS query rate with long query names — data may be exfiltrated through DNS queries.",
				"Identify: cat /proc/<PID>/cmdline — block: add DNS query length limits in your resolver.",
				"DNS-heavy apps (recursive resolvers, monitoring) can generate high query rates."))
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
		sb.WriteString(secContext(
			"High TXT record ratio indicates DNS tunneling — attackers encode stolen data inside DNS queries to bypass firewalls.",
			"Investigate: tcpdump -i any port 53 -w dns.pcap — then analyze with Wireshark.",
			"DKIM/SPF validation and Let's Encrypt use TXT records legitimately but at low rates."))
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
			mbHr := o.BytesPerSec * 3600.0 / 1024.0 / 1024.0
			avgPktSize := max64f(float64(o.TotalBytes)/float64(max64u(o.PacketCount, 1)), 64)
			pktsPerSec := o.BytesPerSec / avgPktSize
			flag := ""
			if !isPrivateIP(o.DstIP) && !isProxyProcess(o.Comm) && knownMultiDestVerdict(o.Comm) == "" {
				if mbHr > 5000 {
					flag = critStyle.Render("EXFIL")
				} else if mbHr > 500 {
					flag = warnStyle.Render("HIGH")
				}
			}

			sb.WriteString(fmt.Sprintf("  %s %s %s %s %s %s\n",
				styledPad(valueStyle.Render(fmt.Sprintf("%d", o.PID)), 7),
				styledPad(valueStyle.Render(padRight(o.Comm, 16)), 16),
				styledPad(dimStyle.Render(padRight(o.DstIP, 16)), 16),
				styledPad(valueStyle.Render(fmt.Sprintf("%.1f", mbHr)), 8),
				styledPad(valueStyle.Render(fmt.Sprintf("%.0f", pktsPerSec)), 8),
				flag))
		}
		// Build intelligent verdict for outbound traffic
		var unknownHighComms []string
		allRecognized := true
		for _, o := range sent.OutboundTop {
			mbHr2 := o.BytesPerSec * 3600.0 / 1024.0 / 1024.0
			if mbHr2 < 100 || isPrivateIP(o.DstIP) {
				continue
			}
			if !isProxyProcess(o.Comm) && knownMultiDestVerdict(o.Comm) == "" && !isKnownOutboundProcess(o.Comm) {
				allRecognized = false
				found := false
				for _, c := range unknownHighComms {
					if c == o.Comm {
						found = true
						break
					}
				}
				if !found {
					unknownHighComms = append(unknownHighComms, o.Comm)
				}
			}
		}
		sb.WriteString("\n")
		if allRecognized {
			sb.WriteString(okStyle.Render("  ✔ All outbound traffic from recognized services — no exfiltration risk") + "\n")
		} else {
			sb.WriteString(secContext(
				fmt.Sprintf("Unrecognized process(es) with high outbound: %s — verify these are expected.", strings.Join(unknownHighComms, ", ")),
				"",
				""))
		}
		sb.WriteString("\n")
	}

	// Lateral movement (FlowRates with high unique dest counts, deduplicated by PID)
	seenPIDs := make(map[int]bool)
	var lateralEntries []model.FlowRateEntry
	for _, f := range sent.FlowRates {
		if f.UniqueDestCount > 50 && !seenPIDs[f.PID] && !isProxyProcess(f.Comm) {
			seenPIDs[f.PID] = true
			lateralEntries = append(lateralEntries, f)
		}
	}
	if len(lateralEntries) > 0 {
		hasData = true
		sb.WriteString(headerStyle.Render("  LATERAL MOVEMENT") + "\n")
		sb.WriteString(dimStyle.Render("  PID     Comm             Unique Dests   Rate/s    Verdict") + "\n")
		sb.WriteString(dimStyle.Render("  "+strings.Repeat("─", 70)) + "\n")
		unknownCount := 0
		for _, f := range lateralEntries {
			verdict := knownMultiDestVerdict(f.Comm)
			if verdict != "" {
				// Known safe process
				sb.WriteString(fmt.Sprintf("  %s %s %s %s %s\n",
					styledPad(valueStyle.Render(fmt.Sprintf("%d", f.PID)), 7),
					styledPad(valueStyle.Render(padRight(f.Comm, 16)), 16),
					styledPad(dimStyle.Render(fmt.Sprintf("%d", f.UniqueDestCount)), 14),
					styledPad(dimStyle.Render(fmt.Sprintf("%.1f", f.Rate)), 9),
					okStyle.Render("OK")))
				sb.WriteString(dimStyle.Render(fmt.Sprintf("         └─ %s", verdict)) + "\n")
			} else {
				unknownCount++
				flag := warnStyle.Render("INVESTIGATE")
				if f.UniqueDestCount > 200 {
					flag = critStyle.Render("INVESTIGATE")
				}
				sb.WriteString(fmt.Sprintf("  %s %s %s %s %s\n",
					styledPad(warnStyle.Render(fmt.Sprintf("%d", f.PID)), 7),
					styledPad(warnStyle.Render(padRight(f.Comm, 16)), 16),
					styledPad(warnStyle.Render(fmt.Sprintf("%d", f.UniqueDestCount)), 14),
					styledPad(valueStyle.Render(fmt.Sprintf("%.1f", f.Rate)), 9),
					flag))
			}
		}
		if unknownCount == 0 {
			sb.WriteString("\n")
			sb.WriteString(okStyle.Render("  ✔ All processes recognized — no lateral movement threat") + "\n")
		} else {
			sb.WriteString(secContext(
				fmt.Sprintf("%d unknown process(es) connecting to many hosts — could be lateral movement.", unknownCount),
				"Check: cat /proc/<PID>/cmdline — is this a known service or unexpected?",
				""))
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
		hasC2JA3 := false
		for _, j := range sec.JA3Fingerprints {
			kl := strings.ToLower(j.Known)
			if strings.Contains(kl, "cobalt") || strings.Contains(kl, "metasploit") ||
				strings.Contains(kl, "sliver") || strings.Contains(kl, "empire") {
				hasC2JA3 = true
				break
			}
		}
		if hasC2JA3 {
			sb.WriteString(secContext(
				critStyle.Render("KNOWN C2 TOOL FINGERPRINT")+" — TLS handshake matches a known attack framework (CobaltStrike, Metasploit, etc).",
				"URGENT: Block destination IP immediately. Isolate the source host. Begin incident response.",
				""))
		} else {
			sb.WriteString(secContext(
				"JA3 fingerprints identify TLS client implementations. Unknown fingerprints may indicate custom/malicious tools.",
				"Compare with known-good list. Investigate unknown hashes connecting to external IPs.",
				"Legitimate but uncommon TLS libraries (Go, Rust) produce unusual JA3 hashes."))
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
			if b.Jitter < 0.05 && b.SampleCount > 20 && b.AvgIntervalSec > 1 {
				flag = critStyle.Render("C2")
			} else if b.Jitter < 0.15 && b.SampleCount > 10 {
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
		hasC2Beacon := false
		for _, b := range sec.BeaconIndicators {
			if b.Jitter < 0.05 && b.SampleCount > 20 && b.AvgIntervalSec > 1 {
				hasC2Beacon = true
				break
			}
		}
		if hasC2Beacon {
			sb.WriteString(secContext(
				critStyle.Render("C2 BEACON DETECTED")+" — process phones home at regular intervals with low jitter. Classic command-and-control behavior.",
				"URGENT: sudo kill -9 <PID> — block destination IP — begin incident response.",
				""))
		} else {
			sb.WriteString(secContext(
				"Regular outbound connections at fixed intervals may indicate malware checking in with a command server.",
				"Investigate: what is <PID> connecting to? Is that destination expected?",
				"Health checks, NTP, monitoring agents, and apt update produce periodic connections."))
		}
		sb.WriteString("\n")
	}

	if len(sec.JA3Fingerprints) == 0 && len(sec.BeaconIndicators) == 0 {
		active := false
		for _, w := range sec.ActiveWatchdogs {
			if w == "tlsfinger" || w == "beacondetect" {
				active = true
				break
			}
		}
		if active {
			sb.WriteString(warnStyle.Render("  Watchdog active — collecting data...") + "\n")
		} else {
			sb.WriteString(dimStyle.Render("  TLS fingerprinting inactive — no watchdog data") + "\n")
		}
	}

	return sb.String()
}

// ── Context helpers for beginner-friendly explanations ──────────────────────

// secContext renders a "So What?" context block with explanation, actions, and false-positive note.
func secContext(whatItMeans, whatToDo, falsePositive string) string {
	var sb strings.Builder
	sb.WriteString("\n")
	sb.WriteString(dimStyle.Render("  ┌─ So What?") + "\n")
	sb.WriteString(dimStyle.Render("  │ ") + whatItMeans + "\n")
	if whatToDo != "" {
		sb.WriteString(dimStyle.Render("  │") + "\n")
		sb.WriteString(dimStyle.Render("  │ ") + headerStyle.Render("Action:") + " " + whatToDo + "\n")
	}
	if falsePositive != "" {
		sb.WriteString(dimStyle.Render("  │") + "\n")
		sb.WriteString(dimStyle.Render("  │ ") + dimStyle.Render("FP hint: "+falsePositive) + "\n")
	}
	sb.WriteString(dimStyle.Render("  └─") + "\n")
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
	// DNS — only auto-expand when actual anomalies exist
	hasDNSAnomaly := false
	for _, d := range sent.DNSAnomaly {
		if d.QueriesPerSec > 500 && d.AvgQueryLen > 80 {
			hasDNSAnomaly = true
			break
		}
	}
	if hasDNSAnomaly || len(sec.DNSTunnelIndicators) > 0 {
		expanded[secSecDNS] = true
	}
	// Flows — only auto-expand when flagged entries exist
	hasLateral := false
	for _, f := range sent.FlowRates {
		if f.UniqueDestCount > 50 {
			hasLateral = true
			break
		}
	}
	hasHighOutbound := false
	for _, o := range sent.OutboundTop {
		mbHr := o.BytesPerSec * 3600.0 / 1024.0 / 1024.0
		if mbHr > 500 && !isPrivateIP(o.DstIP) {
			hasHighOutbound = true
			break
		}
	}
	if hasLateral || hasHighOutbound {
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
