package ui

import (
	"fmt"
	"strings"

	"github.com/ftahirops/xtop/model"
)

func renderSecurityPage(snap *model.Snapshot, rates *model.RateSnapshot, result *model.AnalysisResult, pm probeQuerier, width, height int) string {
	var sb strings.Builder
	iw := pageInnerW(width)

	sb.WriteString(titleStyle.Render("SECURITY MONITOR"))
	sb.WriteString("\n")
	sb.WriteString(renderRCAInline(result))
	sb.WriteString(renderProbeStatusLine(pm))
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
