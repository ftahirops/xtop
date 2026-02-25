package ui

import (
	"fmt"
	"strings"

	"github.com/ftahirops/xtop/model"
)

func renderServicesPage(snap *model.Snapshot, rates *model.RateSnapshot, result *model.AnalysisResult, pm probeQuerier, width, height int) string {
	var sb strings.Builder
	iw := pageInnerW(width)

	sb.WriteString(titleStyle.Render("SERVICE HEALTH & CERTIFICATES"))
	sb.WriteString("\n")
	sb.WriteString(renderRCAInline(result))
	sb.WriteString(renderProbeStatusLine(pm, snap))
	sb.WriteString("\n")

	probes := snap.Global.HealthChecks.Probes

	// Categorize
	var httpProbes, tcpProbes, certProbes, dnsProbes []model.HealthProbeResult
	healthy, degraded, down := 0, 0, 0

	for _, p := range probes {
		switch p.Status {
		case "OK":
			healthy++
		case "WARN":
			degraded++
		case "CRIT":
			down++
		}

		switch p.ProbeType {
		case "http":
			httpProbes = append(httpProbes, p)
		case "tcp":
			tcpProbes = append(tcpProbes, p)
		case "cert":
			certProbes = append(certProbes, p)
		case "dns":
			dnsProbes = append(dnsProbes, p)
		}
	}

	// === SERVICE STATUS ===
	var statusLines []string
	if len(probes) == 0 {
		statusLines = append(statusLines, dimStyle.Render("  No probes configured (services will be auto-discovered)"))
	} else {
		statusLines = append(statusLines, fmt.Sprintf("  %s healthy   %s degraded   %s down",
			okStyle.Render(fmt.Sprintf("%d", healthy)),
			warnStyle.Render(fmt.Sprintf("%d", degraded)),
			critStyle.Render(fmt.Sprintf("%d", down))))
	}
	sb.WriteString(boxSection("SERVICE STATUS", statusLines, iw))

	// === HTTP PROBES ===
	if len(httpProbes) > 0 {
		var httpLines []string
		httpLines = append(httpLines, fmt.Sprintf("  %s %s %s %s %s %s",
			styledPad(dimStyle.Render("SERVICE"), 12),
			styledPad(dimStyle.Render("URL"), 30),
			styledPad(dimStyle.Render("STATUS"), 8),
			styledPad(dimStyle.Render("CODE"), 6),
			styledPad(dimStyle.Render("LATENCY"), 10),
			dimStyle.Render("CERT EXPIRY")))
		httpLines = append(httpLines, dimStyle.Render("  "+strings.Repeat("─", iw-4)))

		for _, p := range httpProbes {
			statusStr := statusBadge(p.Status)
			codeStr := dimStyle.Render("—")
			if p.StatusCode > 0 {
				codeStr = valueStyle.Render(fmt.Sprintf("%d", p.StatusCode))
			}
			latStr := valueStyle.Render(fmt.Sprintf("%.0fms", p.LatencyMs))
			certStr := dimStyle.Render("—")
			if p.CertDaysLeft >= 0 {
				certStr = certDaysStr(p.CertDaysLeft)
			}

			httpLines = append(httpLines, fmt.Sprintf("  %s %s %s %s %s %s",
				styledPad(valueStyle.Render(padRight(p.Name, 10)), 12),
				styledPad(dimStyle.Render(truncate(p.Target, 28)), 30),
				styledPad(statusStr, 8),
				styledPad(codeStr, 6),
				styledPad(latStr, 10),
				certStr))
		}
		sb.WriteString(boxSection("HTTP PROBES", httpLines, iw))
	}

	// === TCP PROBES ===
	if len(tcpProbes) > 0 {
		var tcpLines []string
		tcpLines = append(tcpLines, fmt.Sprintf("  %s %s %s %s",
			styledPad(dimStyle.Render("SERVICE"), 16),
			styledPad(dimStyle.Render("HOST:PORT"), 24),
			styledPad(dimStyle.Render("STATUS"), 10),
			dimStyle.Render("LATENCY")))
		tcpLines = append(tcpLines, dimStyle.Render("  "+strings.Repeat("─", iw-4)))

		for _, p := range tcpProbes {
			tcpLines = append(tcpLines, fmt.Sprintf("  %s %s %s %s",
				styledPad(valueStyle.Render(padRight(p.Name, 14)), 16),
				styledPad(dimStyle.Render(padRight(p.Target, 22)), 24),
				styledPad(statusBadge(p.Status), 10),
				valueStyle.Render(fmt.Sprintf("%.0fms", p.LatencyMs))))
		}
		sb.WriteString(boxSection("TCP PROBES", tcpLines, iw))
	}

	// === CERTIFICATE EXPIRY ===
	if len(certProbes) > 0 {
		var certLines []string
		certLines = append(certLines, fmt.Sprintf("  %s %s %s %s",
			styledPad(dimStyle.Render("DOMAIN"), 30),
			styledPad(dimStyle.Render("EXPIRES"), 14),
			styledPad(dimStyle.Render("DAYS LEFT"), 12),
			dimStyle.Render("STATUS")))
		certLines = append(certLines, dimStyle.Render("  "+strings.Repeat("─", iw-4)))

		for _, p := range certProbes {
			certLines = append(certLines, fmt.Sprintf("  %s %s %s %s",
				styledPad(valueStyle.Render(padRight(p.Name, 28)), 30),
				styledPad(dimStyle.Render(padRight(p.Detail, 12)), 14),
				styledPad(certDaysStr(p.CertDaysLeft), 12),
				statusBadge(p.Status)))
		}
		sb.WriteString(boxSection("CERTIFICATE EXPIRY", certLines, iw))
	}

	// === DNS RESOLUTION ===
	if len(dnsProbes) > 0 {
		var dnsLines []string
		dnsLines = append(dnsLines, fmt.Sprintf("  %s %s %s",
			styledPad(dimStyle.Render("DOMAIN"), 30),
			styledPad(dimStyle.Render("STATUS"), 10),
			dimStyle.Render("LATENCY")))
		dnsLines = append(dnsLines, dimStyle.Render("  "+strings.Repeat("─", iw-4)))

		for _, p := range dnsProbes {
			dnsLines = append(dnsLines, fmt.Sprintf("  %s %s %s",
				styledPad(valueStyle.Render(padRight(p.Target, 28)), 30),
				styledPad(statusBadge(p.Status), 10),
				valueStyle.Render(fmt.Sprintf("%.0fms", p.LatencyMs))))
		}
		sb.WriteString(boxSection("DNS RESOLUTION", dnsLines, iw))
	}

	// If no probes at all, show hint
	if len(httpProbes) == 0 && len(tcpProbes) == 0 && len(certProbes) == 0 && len(dnsProbes) == 0 {
		var hintLines []string
		hintLines = append(hintLines, dimStyle.Render("  Probes auto-discover from listening ports (5432, 3306, 6379, etc.)"))
		hintLines = append(hintLines, dimStyle.Render("  and web ports (80, 443, 8080, 8443)."))
		hintLines = append(hintLines, dimStyle.Render("  Cert files are scanned from /etc/letsencrypt/live/*/cert.pem"))
		sb.WriteString(boxSection("PROBE DISCOVERY", hintLines, iw))
	}

	return sb.String()
}

func statusBadge(status string) string {
	switch status {
	case "OK":
		return okStyle.Render("OK")
	case "WARN":
		return warnStyle.Render("WARN")
	case "CRIT":
		return critStyle.Render("CRIT")
	default:
		return dimStyle.Render("UNKN")
	}
}

func certDaysStr(days int) string {
	if days < 0 {
		return dimStyle.Render("—")
	}
	s := fmt.Sprintf("%dd", days)
	if days < 7 {
		return critStyle.Render(s)
	}
	if days < 30 {
		return warnStyle.Render(s)
	}
	return okStyle.Render(s)
}
