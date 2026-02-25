package ui

import (
	"fmt"
	"sort"
	"strings"

	"github.com/ftahirops/xtop/model"
)

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

func renderSecurityPage(snap *model.Snapshot, rates *model.RateSnapshot, result *model.AnalysisResult, pm probeQuerier, width, height int) string {
	var sb strings.Builder
	iw := pageInnerW(width)

	sb.WriteString(titleStyle.Render("SECURITY MONITOR"))
	sb.WriteString("\n")
	sb.WriteString(renderRCAInline(result))
	sb.WriteString(renderProbeStatusLine(pm, snap))
	sb.WriteString("\n")

	sec := snap.Global.Security

	// === SECURITY STATUS ===
	var statusLines []string
	switch sec.Score {
	case "CRIT":
		statusLines = append(statusLines, critStyle.Render("CRITICAL")+" "+dimStyle.Render("— security signals detected"))
	case "WARN":
		statusLines = append(statusLines, warnStyle.Render("WARNING")+" "+dimStyle.Render("— review recommended"))
	default:
		statusLines = append(statusLines, okStyle.Render("OK")+" "+dimStyle.Render("— no anomalies"))
	}
	sb.WriteString(boxSection("SECURITY STATUS", statusLines, iw))

	// === SSH / AUTH ===
	var authLines []string
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
	authLines = append(authLines, fmt.Sprintf("  Failed auth rate: %s   Total: %s   Brute force: %s",
		rateStr, valueStyle.Render(fmt.Sprintf("%d", sec.FailedAuthTotal)), bruteStr))

	if len(sec.FailedAuthIPs) > 0 {
		authLines = append(authLines, "")
		authLines = append(authLines, dimStyle.Render("  Source IP              Count"))
		authLines = append(authLines, dimStyle.Render("  "+strings.Repeat("─", 35)))
		for _, ip := range sec.FailedAuthIPs {
			authLines = append(authLines, fmt.Sprintf("  %s %s",
				styledPad(valueStyle.Render(ip.IP), 22),
				warnStyle.Render(fmt.Sprintf("%d", ip.Count))))
		}
	}
	sb.WriteString(boxSection("SSH / AUTH", authLines, iw))

	// === FILELESS PROCESSES ===
	fp := snap.Global.FilelessProcs
	var filelessLines []string
	if len(fp) == 0 {
		filelessLines = append(filelessLines, okStyle.Render("  None detected"))
	} else {
		filelessLines = append(filelessLines, dimStyle.Render("  PID    Comm             ExePath                          Conns  IPs"))
		filelessLines = append(filelessLines, dimStyle.Render("  "+strings.Repeat("─", iw-4)))
		for _, f := range fp {
			sev := warnStyle
			if f.NetConns > 0 {
				sev = critStyle
			}
			ips := strings.Join(f.RemoteIPs, ", ")
			if len(ips) > 30 {
				ips = ips[:27] + "..."
			}
			filelessLines = append(filelessLines, fmt.Sprintf("  %s %s %s %s %s",
				sev.Render(padRight(fmt.Sprintf("%d", f.PID), 6)),
				styledPad(valueStyle.Render(padRight(f.Comm, 16)), 16),
				styledPad(dimStyle.Render(truncate(f.ExePath, 32)), 32),
				styledPad(valueStyle.Render(fmt.Sprintf("%d", f.NetConns)), 6),
				dimStyle.Render(ips)))
		}
	}
	sb.WriteString(boxSection("FILELESS PROCESSES", filelessLines, iw))

	// === NEW LISTENING PORTS ===
	var portLines []string
	if len(sec.NewPorts) == 0 {
		portLines = append(portLines, okStyle.Render("  No new ports since startup"))
	} else {
		portLines = append(portLines, dimStyle.Render("  Port     PID    Comm"))
		portLines = append(portLines, dimStyle.Render("  "+strings.Repeat("─", 30)))
		for _, p := range sec.NewPorts {
			portLines = append(portLines, fmt.Sprintf("  %s %s %s",
				warnStyle.Render(padRight(fmt.Sprintf("%d", p.Port), 8)),
				styledPad(valueStyle.Render(padRight(fmt.Sprintf("%d", p.PID), 6)), 6),
				valueStyle.Render(p.Comm)))
		}
	}
	sb.WriteString(boxSection("NEW LISTENING PORTS", portLines, iw))

	// === SUID ANOMALIES ===
	var suidLines []string
	if len(sec.SUIDAnomalies) == 0 {
		suidLines = append(suidLines, okStyle.Render("  No new SUID binaries since startup"))
	} else {
		suidLines = append(suidLines, dimStyle.Render("  Path                                           Modified"))
		suidLines = append(suidLines, dimStyle.Render("  "+strings.Repeat("─", 60)))
		for _, s := range sec.SUIDAnomalies {
			suidLines = append(suidLines, fmt.Sprintf("  %s %s",
				critStyle.Render(padRight(s.Path, 48)),
				dimStyle.Render(s.ModTime.Format("2006-01-02 15:04"))))
		}
	}
	sb.WriteString(boxSection("SUID ANOMALIES", suidLines, iw))

	// === KERNEL MODULE LOADS (BPF Sentinel) ===
	sent := snap.Global.Sentinel
	if sent.Active {
		var modLines []string
		if len(sent.ModLoads) == 0 {
			modLines = append(modLines, okStyle.Render("  No module loads detected"))
		} else {
			modLines = append(modLines, dimStyle.Render("  MODULE                         COUNT"))
			modLines = append(modLines, dimStyle.Render("  "+strings.Repeat("─", 42)))
			for _, m := range sent.ModLoads {
				name := m.Name
				if len(name) > 30 {
					name = name[:27] + "..."
				}
				modLines = append(modLines, fmt.Sprintf("  %s %s",
					warnStyle.Render(padRight(name, 30)),
					valueStyle.Render(fmt.Sprintf("%d", m.Count))))
			}
		}
		sb.WriteString(boxSection("KERNEL MODULE LOADS (BPF)", modLines, iw))

		// === PROCESS EXECUTIONS (BPF Sentinel) ===
		var execLines []string
		if len(sent.ExecEvents) == 0 {
			execLines = append(execLines, okStyle.Render("  No process executions detected"))
		} else {
			// Classify severity and sort: CRIT first, then WARN, skip OK
			type execRow struct {
				entry model.ExecEventEntry
				sev   string // "crit", "warn", "ok"
				tag   string // display tag
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
			// Sort: crit first, then warn, then by timestamp desc
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
				execLines = append(execLines, okStyle.Render(msg))
			} else {
				execLines = append(execLines, dimStyle.Render("  SEV   PID      PPID     UID    COMM             FILENAME                           COUNT"))
				execLines = append(execLines, dimStyle.Render("  "+strings.Repeat("─", iw-4)))
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
					execLines = append(execLines, fmt.Sprintf("  %s %s %s %s %s %s %s",
						styledPad(style.Render(r.tag), 5),
						styledPad(style.Render(fmt.Sprintf("%d", e.PID)), 8),
						styledPad(valueStyle.Render(fmt.Sprintf("%d", e.PPID)), 8),
						styledPad(valueStyle.Render(fmt.Sprintf("%d", e.UID)), 6),
						styledPad(valueStyle.Render(padRight(e.Comm, 16)), 16),
						styledPad(dimStyle.Render(padRight(fn, 34)), 34),
						valueStyle.Render(fmt.Sprintf("%d", e.Count))))
				}
				if okCount > 0 {
					execLines = append(execLines, dimStyle.Render(
						fmt.Sprintf("  + %d normal executions filtered", okCount)))
				}
			}
		}
		sb.WriteString(boxSection("PROCESS EXECUTIONS (BPF)", execLines, iw))

		// === PTRACE DETECTION (BPF Sentinel) ===
		var ptraceLines []string
		if len(sent.PtraceEvents) == 0 {
			ptraceLines = append(ptraceLines, okStyle.Render("  No ptrace activity detected"))
		} else {
			ptraceLines = append(ptraceLines, dimStyle.Render("  TRACER PID  TRACER           TARGET PID  TARGET           REQUEST          COUNT"))
			ptraceLines = append(ptraceLines, dimStyle.Render("  "+strings.Repeat("─", iw-4)))
			for _, p := range sent.PtraceEvents {
				ptraceLines = append(ptraceLines, fmt.Sprintf("  %s %s %s %s %s %s",
					critStyle.Render(padRight(fmt.Sprintf("%d", p.TracerPID), 11)),
					styledPad(critStyle.Render(padRight(p.TracerComm, 16)), 16),
					styledPad(critStyle.Render(padRight(fmt.Sprintf("%d", p.TargetPID), 11)), 11),
					styledPad(valueStyle.Render(padRight(p.TargetComm, 16)), 16),
					styledPad(critStyle.Render(padRight(p.RequestStr, 16)), 16),
					valueStyle.Render(fmt.Sprintf("%d", p.Count))))
			}
		}
		sb.WriteString(boxSection("PTRACE DETECTION (BPF)", ptraceLines, iw))
	}

	// === REVERSE SHELLS ===
	var rsLines []string
	if len(sec.ReverseShells) == 0 {
		rsLines = append(rsLines, okStyle.Render("  None detected"))
	} else {
		rsLines = append(rsLines, dimStyle.Render("  PID    Comm             FD0                   FD1"))
		rsLines = append(rsLines, dimStyle.Render("  "+strings.Repeat("─", 70)))
		for _, r := range sec.ReverseShells {
			rsLines = append(rsLines, fmt.Sprintf("  %s %s %s %s",
				critStyle.Render(padRight(fmt.Sprintf("%d", r.PID), 6)),
				styledPad(valueStyle.Render(padRight(r.Comm, 16)), 16),
				styledPad(dimStyle.Render(truncate(r.FD0, 20)), 21),
				dimStyle.Render(truncate(r.FD1, 20))))
		}
	}
	sb.WriteString(boxSection("REVERSE SHELLS", rsLines, iw))

	return sb.String()
}
