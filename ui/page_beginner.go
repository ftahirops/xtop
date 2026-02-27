package ui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/ftahirops/xtop/model"
)

// renderOnboarding renders the first-run experience level selection screen.
func renderOnboarding(width, height int) string {
	var sb strings.Builder

	innerW := 52
	if width > 0 && width-7 < innerW {
		innerW = width - 7
		if innerW < 40 {
			innerW = 40
		}
	}

	sb.WriteString("\n")
	sb.WriteString(boxTop(innerW) + "\n")
	sb.WriteString(boxRow("", innerW) + "\n")
	sb.WriteString(boxRow(titleStyle.Render("Welcome to xtop!"), innerW) + "\n")
	sb.WriteString(boxRow("", innerW) + "\n")
	sb.WriteString(boxRow(valueStyle.Render("How would you like to use xtop?"), innerW) + "\n")
	sb.WriteString(boxRow("", innerW) + "\n")
	sb.WriteString(boxMid(innerW) + "\n")
	sb.WriteString(boxRow("", innerW) + "\n")

	sb.WriteString(boxRow(headerStyle.Render("[1]")+" "+valueStyle.Render("Simple Mode"), innerW) + "\n")
	sb.WriteString(boxRow(dimStyle.Render("    Plain-English health summary."), innerW) + "\n")
	sb.WriteString(boxRow(dimStyle.Render("    Best for: developers, managers, anyone"), innerW) + "\n")
	sb.WriteString(boxRow(dimStyle.Render("    new to system monitoring."), innerW) + "\n")
	sb.WriteString(boxRow("", innerW) + "\n")

	sb.WriteString(boxRow(headerStyle.Render("[2]")+" "+valueStyle.Render("Advanced Mode"), innerW) + "\n")
	sb.WriteString(boxRow(dimStyle.Render("    Full metrics dashboard with all pages."), innerW) + "\n")
	sb.WriteString(boxRow(dimStyle.Render("    Best for: ops teams, SREs, sysadmins."), innerW) + "\n")
	sb.WriteString(boxRow("", innerW) + "\n")

	sb.WriteString(boxMid(innerW) + "\n")
	sb.WriteString(boxRow(dimStyle.Render("You can switch anytime with A/B keys."), innerW) + "\n")
	sb.WriteString(boxBot(innerW) + "\n")

	return sb.String()
}

// renderBeginnerPage renders the simplified plain-English overview.
// resolvedAgo > 0 means the RCA result is from a pinned (sticky) finding that has since recovered.
func renderBeginnerPage(snap *model.Snapshot, rates *model.RateSnapshot, result *model.AnalysisResult, resolvedAgo int, width, height int) string {
	if snap == nil {
		return "Collecting first sample..."
	}

	var sb strings.Builder

	innerW := width - 7
	if innerW < 50 {
		innerW = 50
	}
	if innerW > 60 {
		innerW = 60
	}

	// Determine subsystem statuses (always from live data)
	cpuStatus, cpuDesc := beginnerCPUStatus(rates)
	memStatus, memDesc := beginnerMemStatus(snap)
	diskStatus, diskDesc := beginnerDiskStatus(snap, rates)
	netStatus, netDesc := beginnerNetStatus(result)

	healthy := cpuStatus == "OK" && memStatus == "OK" && diskStatus == "OK" && netStatus == "OK"
	// RCA result may be pinned from a recent problem even if live metrics are now OK
	hasRCA := result != nil && result.PrimaryScore > 25

	// SYSTEM HEALTH box
	sb.WriteString(boxTopTitle(dimStyle.Render(" SYSTEM HEALTH "), innerW) + "\n")
	sb.WriteString(boxRow("", innerW) + "\n")

	if healthy && !hasRCA {
		sb.WriteString(boxRow("  "+okStyle.Render("\u2713")+" "+okStyle.Render("Your system is healthy"), innerW) + "\n")
	} else if healthy && hasRCA && resolvedAgo > 0 {
		sb.WriteString(boxRow("  "+okStyle.Render("\u2713")+" "+okStyle.Render("System recovered")+"  "+dimStyle.Render(fmt.Sprintf("(problem ended %ds ago)", resolvedAgo)), innerW) + "\n")
	} else {
		sb.WriteString(boxRow("  "+warnStyle.Render("\u26a0")+" "+warnStyle.Render("Problem Detected"), innerW) + "\n")
	}
	sb.WriteString(boxRow("", innerW) + "\n")

	sb.WriteString(boxRow(beginnerStatusLine("CPU", cpuStatus, cpuDesc, innerW), innerW) + "\n")
	sb.WriteString(boxRow(beginnerStatusLine("Memory", memStatus, memDesc, innerW), innerW) + "\n")
	sb.WriteString(boxRow(beginnerStatusLine("Disk", diskStatus, diskDesc, innerW), innerW) + "\n")
	sb.WriteString(boxRow(beginnerStatusLine("Network", netStatus, netDesc, innerW), innerW) + "\n")
	sb.WriteString(boxRow("", innerW) + "\n")

	// WHAT'S HAPPENING section (show when unhealthy OR when pinned RCA exists)
	if !healthy || hasRCA {
		sb.WriteString(boxMid(innerW) + "\n")
		sb.WriteString(boxRow(" "+titleStyle.Render("WHAT'S HAPPENING"), innerW) + "\n")
		sb.WriteString(boxRow("", innerW) + "\n")

		if result != nil && result.PrimaryProcess != "" && result.PrimaryScore > 0 {
			proc := result.PrimaryProcess
			pid := result.PrimaryPID
			line := fmt.Sprintf("  %q (process %d) is using too much %s",
				proc, pid, strings.ToLower(result.PrimaryBottleneck))
			wrapped := wrapText(line, innerW-2)
			for _, l := range wrapped {
				sb.WriteString(boxRow(valueStyle.Render(l), innerW) + "\n")
			}
		}

		if result != nil && result.Narrative != nil && result.Narrative.RootCause != "" {
			sb.WriteString(boxRow("", innerW) + "\n")
			plain := simplifyNarrative(result.Narrative.RootCause)
			wrapped := wrapText("  "+plain, innerW-2)
			for _, l := range wrapped {
				sb.WriteString(boxRow(dimStyle.Render(l), innerW) + "\n")
			}
		}

		sb.WriteString(boxRow("", innerW) + "\n")

		// WHAT TO DO section
		sb.WriteString(boxMid(innerW) + "\n")
		sb.WriteString(boxRow(" "+titleStyle.Render("WHAT TO DO"), innerW) + "\n")
		sb.WriteString(boxRow("", innerW) + "\n")

		if result != nil && len(result.Actions) > 0 {
			for i, a := range result.Actions {
				if i >= 3 {
					break
				}
				wrapped := wrapText("  "+a.Summary, innerW-2)
				for _, l := range wrapped {
					sb.WriteString(boxRow(dimStyle.Render(l), innerW) + "\n")
				}
			}
		} else {
			sb.WriteString(boxRow(dimStyle.Render("  This may need an expert to investigate."), innerW) + "\n")
			sb.WriteString(boxRow(dimStyle.Render("  Press S to save a report to send them."), innerW) + "\n")
		}

		sb.WriteString(boxRow("", innerW) + "\n")
	}

	sb.WriteString(boxBot(innerW) + "\n")

	// Footer hints
	sb.WriteString("\n")
	sb.WriteString(dimStyle.Render("  Press A to switch to advanced mode  |  Press 1-9 for detail pages  |  S to save report"))
	sb.WriteString("\n")

	return sb.String()
}

func beginnerStatusLine(label, status, desc string, innerW int) string {
	labelW := 10
	styledLabel := styledPad(dimStyle.Render("  "+label), labelW)

	var badge string
	switch status {
	case "OK":
		badge = okStyle.Render("OK")
	case "BUSY", "SLOW", "VERY SLOW", "ALMOST FULL":
		badge = critStyle.Render(status)
	default:
		badge = warnStyle.Render(status)
	}

	if desc != "" {
		maxDesc := innerW - labelW - 14 - 4 // 4 for "— " and padding
		if maxDesc > 0 && len(desc) > maxDesc {
			desc = desc[:maxDesc-1] + "…"
		}
		return styledLabel + styledPad(badge, 14) + dimStyle.Render("\u2014 "+desc)
	}
	return styledLabel + badge
}

func beginnerCPUStatus(rates *model.RateSnapshot) (string, string) {
	if rates == nil {
		return "OK", ""
	}
	pct := rates.CPUBusyPct
	switch {
	case pct > 80:
		return "BUSY", "server is overloaded"
	case pct > 60:
		return "MODERATE", fmt.Sprintf("%.0f%% used", pct)
	default:
		return "OK", fmt.Sprintf("%.0f%% used (plenty of room)", pct)
	}
}

func beginnerMemStatus(snap *model.Snapshot) (string, string) {
	mem := snap.Global.Memory
	if mem.Total == 0 {
		return "OK", ""
	}
	avail := mem.Available
	if avail > mem.Total {
		avail = mem.Total // guard against kernel accounting transients
	}
	usedPct := float64(mem.Total-avail) / float64(mem.Total) * 100
	freeMB := float64(mem.Available) / (1024 * 1024)

	freeStr := fmt.Sprintf("%.1f MB", freeMB)
	if freeMB >= 1024 {
		freeStr = fmt.Sprintf("%.1f GB", freeMB/1024)
	}

	switch {
	case usedPct > 90:
		return "ALMOST FULL", fmt.Sprintf("%.0f%% used (only %s free)", usedPct, freeStr)
	case usedPct > 80:
		return "GETTING FULL", fmt.Sprintf("%.0f%% used (%s free)", usedPct, freeStr)
	default:
		return "OK", fmt.Sprintf("%.0f%% used (%s free)", usedPct, freeStr)
	}
}

func beginnerDiskStatus(snap *model.Snapshot, rates *model.RateSnapshot) (string, string) {
	psiIO := snap.Global.PSI.IO.Some.Avg10

	// Also check disk await from rates
	var maxAwait float64
	if rates != nil {
		for _, d := range rates.DiskRates {
			if d.AvgAwaitMs > maxAwait {
				maxAwait = d.AvgAwaitMs
			}
		}
	}

	switch {
	case psiIO > 20:
		return "VERY SLOW", "heavy IO pressure"
	case psiIO > 5 || maxAwait > 50:
		return "SLOW", "taking long to respond"
	default:
		if maxAwait > 0 {
			return "OK", fmt.Sprintf("fast responses (%.0fms)", maxAwait)
		}
		return "OK", "no issues detected"
	}
}

func beginnerNetStatus(result *model.AnalysisResult) (string, string) {
	if result == nil {
		return "OK", "no issues detected"
	}
	// Check for network-related RCA entries with significant score
	for _, rca := range result.RCA {
		if (strings.Contains(rca.Bottleneck, "Network") || strings.Contains(rca.Bottleneck, "Net")) && rca.Score > 20 {
			return "ISSUES", "network problems detected"
		}
	}
	return "OK", "no issues detected"
}

// simplifyNarrative rewrites RCA narrative into simpler language.
func simplifyNarrative(narrative string) string {
	// Replace technical jargon with plain English
	r := strings.NewReplacer(
		"CPU throttle cascade", "CPU is being limited",
		"cgroup limits saturating run queue", "too many tasks waiting for CPU",
		"memory pressure", "not enough memory",
		"IO stall", "disk is too slow",
		"OOM", "out of memory",
		"D-state", "stuck waiting for disk",
		"run queue", "task queue",
		"PSI", "pressure",
		"softirq", "network overhead",
	)
	return r.Replace(narrative)
}

// wrapText wraps a string to fit within maxW characters.
// Preserves leading whitespace as an indent for continuation lines.
func wrapText(text string, maxW int) []string {
	if maxW <= 0 {
		maxW = 60
	}
	visW := lipgloss.Width(text)
	if visW <= maxW {
		return []string{text}
	}

	// Detect leading indent
	indent := ""
	for _, ch := range text {
		if ch == ' ' {
			indent += " "
		} else {
			break
		}
	}

	words := strings.Fields(text)
	var lines []string
	current := indent
	for _, w := range words {
		test := current
		if test != indent {
			test += " "
		}
		test += w
		if lipgloss.Width(test) > maxW && current != indent {
			lines = append(lines, current)
			current = indent + w
		} else {
			current = test
		}
	}
	if current != "" && current != indent {
		lines = append(lines, current)
	}
	return lines
}
