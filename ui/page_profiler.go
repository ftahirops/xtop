package ui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/ftahirops/xtop/model"
)

func renderProfilerPage(snap *model.Snapshot, cursor int, expanded [6]bool, w, h int) string {
	iw := pageInnerW(w)
	var sb strings.Builder

	if snap == nil || snap.Global.Profile == nil {
		sb.WriteString("\n")
		sb.WriteString(headerStyle.Render("  SYSTEM PROFILER") + "\n\n")
		sb.WriteString(dimStyle.Render("  Collecting system profile... (first scan takes ~60s)") + "\n")
		sb.WriteString(pageFooter("O:refresh"))
		return sb.String()
	}

	prof := snap.Global.Profile

	// Header with overall score
	sb.WriteString("\n")
	scoreStr := fmt.Sprintf("%d/100", prof.OverallScore)
	scoreBadge := profScoreBadge(prof.OverallScore)
	sb.WriteString(headerStyle.Render("  SYSTEM PROFILER") + "    " +
		dimStyle.Render("Score: ") + profScoreStyle(prof.OverallScore).Render(scoreStr) +
		"  " + scoreBadge + "\n")
	sb.WriteString("\n")

	// Identity section
	sb.WriteString(renderProfilerIdentity(snap, prof, iw))
	sb.WriteString("\n")

	// Service census
	sb.WriteString(renderProfilerServices(prof, iw))
	sb.WriteString("\n")

	// Domain sections (collapsible)
	domains := []model.OptDomain{
		model.OptDomainKernel, model.OptDomainNetwork, model.OptDomainMemory,
		model.OptDomainIO, model.OptDomainSecurity, model.OptDomainApps,
	}

	for i, domain := range domains {
		ds := findDomain(prof, domain)
		if ds == nil {
			continue
		}
		selected := cursor == i
		isExpanded := expanded[i]

		summary := profDomainSummary(ds)
		sb.WriteString(renderProfilerSectionHeader(string(domain), summary, ds.Score, selected, isExpanded, iw))

		if isExpanded {
			sb.WriteString(renderProfilerDomainRules(ds, iw))
		}
	}

	sb.WriteString(pageFooter("Tab:section  Enter:expand  A:all  C:collapse"))
	return sb.String()
}

func renderProfilerIdentity(snap *model.Snapshot, prof *model.ServerProfile, iw int) string {
	var sb strings.Builder

	sb.WriteString(titleStyle.Render("  IDENTITY") + "\n")

	role := string(prof.Role)
	if prof.RoleDetail != "" {
		role += " (" + prof.RoleDetail + ")"
	}
	sb.WriteString(fmt.Sprintf("  %s %s\n", dimStyle.Render("Role:"), valueStyle.Render(role)))

	if snap.SysInfo != nil {
		si := snap.SysInfo
		if si.OS != "" {
			sb.WriteString(fmt.Sprintf("  %s %s", dimStyle.Render("OS:"), valueStyle.Render(si.OS)))
			if si.Kernel != "" {
				sb.WriteString(fmt.Sprintf("  %s %s", dimStyle.Render("Kernel:"), valueStyle.Render(si.Kernel)))
			}
			sb.WriteString("\n")
		}
		if si.Virtualization != "" {
			sb.WriteString(fmt.Sprintf("  %s %s", dimStyle.Render("Virt:"), valueStyle.Render(si.Virtualization)))
			if si.CloudProvider != "" {
				sb.WriteString(fmt.Sprintf("  %s %s", dimStyle.Render("Cloud:"), valueStyle.Render(si.CloudProvider)))
			}
			sb.WriteString("\n")
		}
	}

	// Hardware summary
	cpus := snap.Global.CPU.NumCPUs
	ramMB := snap.Global.Memory.Total / (1024 * 1024)
	ramStr := fmt.Sprintf("%.1fG", float64(ramMB)/1024)
	if ramMB > 1024 {
		ramStr = fmt.Sprintf("%.0fG", float64(ramMB)/1024)
	}

	diskCount := 0
	for _, d := range snap.Global.Disks {
		if !isUIPartition(d.Name) {
			diskCount++
		}
	}
	sb.WriteString(fmt.Sprintf("  %s %s  %s %s  %s %d\n",
		dimStyle.Render("CPUs:"), valueStyle.Render(fmt.Sprintf("%d", cpus)),
		dimStyle.Render("RAM:"), valueStyle.Render(ramStr),
		dimStyle.Render("Disks:"), diskCount))

	return sb.String()
}

func renderProfilerServices(prof *model.ServerProfile, iw int) string {
	var sb strings.Builder

	if len(prof.Services) == 0 {
		return ""
	}

	sb.WriteString(titleStyle.Render("  SERVICE CENSUS") + dimStyle.Render(" (by resource usage)") + "\n")

	// Column widths
	cName := 18
	cCPU := 10
	cRAM := 10
	cConn := 8
	cProc := 6

	// Header
	sb.WriteString("  " +
		styledPad(dimStyle.Render("Service"), cName) +
		styledPad(dimStyle.Render("CPU%"), cCPU) +
		styledPad(dimStyle.Render("RAM"), cRAM) +
		styledPad(dimStyle.Render("Conn"), cConn) +
		styledPad(dimStyle.Render("Procs"), cProc) + "\n")

	max := len(prof.Services)
	if max > 10 {
		max = 10
	}
	for _, svc := range prof.Services[:max] {
		name := svc.DisplayName
		if name == "" {
			name = svc.Name
		}
		if len(name) > cName-2 {
			name = name[:cName-2]
		}

		cpuStr := fmt.Sprintf("%.1f%%", svc.CPUPct)
		ramStr := fmtMBUI(svc.RSSMB)
		connStr := "-"
		if svc.Connections > 0 {
			connStr = fmtCountUI(svc.Connections)
		}
		procStr := fmt.Sprintf("%d", svc.Processes)

		sb.WriteString("  " +
			styledPad(valueStyle.Render(name), cName) +
			styledPad(valueStyle.Render(cpuStr), cCPU) +
			styledPad(valueStyle.Render(ramStr), cRAM) +
			styledPad(valueStyle.Render(connStr), cConn) +
			styledPad(dimStyle.Render(procStr), cProc) + "\n")
	}

	return sb.String()
}

func renderProfilerSectionHeader(title, summary string, score int, selected, expanded bool, iw int) string {
	arrow := "\u25b6" // ▶
	if expanded {
		arrow = "\u25bc" // ▼
	}

	scoreStr := fmt.Sprintf("%d/100", score)
	titlePart := fmt.Sprintf("%s %s  %s", arrow, title, scoreStr)

	if selected {
		style := lipgloss.NewStyle().Foreground(lipgloss.Color("14")).Bold(true)
		titlePart = style.Render(titlePart)
	} else {
		titlePart = titleStyle.Render(fmt.Sprintf("%s %s", arrow, title)) + "  " + profScoreStyle(score).Render(scoreStr)
	}

	titleW := lipgloss.Width(titlePart)
	maxSumW := iw - titleW - 4
	if maxSumW < 10 {
		return "  " + titlePart + "\n"
	}
	if lipgloss.Width(summary) > maxSumW {
		runes := []rune(summary)
		if len(runes) > maxSumW-3 {
			summary = string(runes[:maxSumW-3]) + "..."
		}
	}

	gap := iw - titleW - lipgloss.Width(summary) - 4
	if gap < 1 {
		gap = 1
	}
	return "  " + titlePart + strings.Repeat(" ", gap) + dimStyle.Render(summary) + "\n"
}

func renderProfilerDomainRules(ds *model.DomainScore, iw int) string {
	var sb strings.Builder

	if len(ds.Rules) == 0 {
		sb.WriteString("    " + dimStyle.Render("No rules applicable") + "\n")
		return sb.String()
	}

	// Show FAILs first, then WARNs, then PASSes
	ordered := make([]model.AuditRule, 0, len(ds.Rules))
	for _, r := range ds.Rules {
		if r.Status == model.RuleFail {
			ordered = append(ordered, r)
		}
	}
	for _, r := range ds.Rules {
		if r.Status == model.RuleWarn {
			ordered = append(ordered, r)
		}
	}
	for _, r := range ds.Rules {
		if r.Status == model.RulePass {
			ordered = append(ordered, r)
		}
	}

	for _, r := range ordered {
		icon := ""
		var style lipgloss.Style
		switch r.Status {
		case model.RulePass:
			icon = okStyle.Render("✓")
			style = dimStyle
		case model.RuleWarn:
			icon = warnStyle.Render("⚠")
			style = warnStyle
		case model.RuleFail:
			icon = critStyle.Render("✗")
			style = critStyle
		default:
			icon = dimStyle.Render("–")
			style = dimStyle
		}

		// Status line: icon STATUS name = current
		statusLabel := style.Render(r.Status.String())
		sb.WriteString(fmt.Sprintf("    %s %s  %s = %s\n",
			icon, styledPad(statusLabel, 6),
			valueStyle.Render(r.Name),
			valueStyle.Render(r.Current)))

		// Detail lines for non-PASS rules
		if r.Status != model.RulePass {
			sb.WriteString(fmt.Sprintf("           %s %s\n",
				dimStyle.Render("Recommended:"),
				valueStyle.Render(r.Recommended)))
			sb.WriteString(fmt.Sprintf("           %s %s\n",
				dimStyle.Render("Impact:"),
				orangeStyle.Render(r.Impact)))
		}
	}

	sb.WriteString("\n")
	return sb.String()
}

// --- helpers ---

func findDomain(prof *model.ServerProfile, domain model.OptDomain) *model.DomainScore {
	for i := range prof.Domains {
		if prof.Domains[i].Domain == domain {
			return &prof.Domains[i]
		}
	}
	return nil
}

func profDomainSummary(ds *model.DomainScore) string {
	if ds.Issues == 0 {
		return "all checks passed"
	}
	return fmt.Sprintf("%d issues", ds.Issues)
}

func profScoreStyle(score int) lipgloss.Style {
	switch {
	case score >= 80:
		return okStyle
	case score >= 60:
		return warnStyle
	default:
		return critStyle
	}
}

func profScoreBadge(score int) string {
	switch {
	case score >= 80:
		return okStyle.Render("GOOD")
	case score >= 60:
		return warnStyle.Render("NEEDS WORK")
	case score >= 40:
		return orangeStyle.Render("POOR")
	default:
		return critStyle.Render("CRITICAL")
	}
}

func fmtMBUI(mb float64) string {
	if mb >= 1024 {
		return fmt.Sprintf("%.1fG", mb/1024)
	}
	if mb >= 1 {
		return fmt.Sprintf("%.0fM", mb)
	}
	return fmt.Sprintf("%.1fM", mb)
}

func fmtCountUI(n int) string {
	if n >= 1000000 {
		return fmt.Sprintf("%.1fM", float64(n)/1000000)
	}
	if n >= 1000 {
		return fmt.Sprintf("%.1fk", float64(n)/1000)
	}
	return fmt.Sprintf("%d", n)
}

// isUIPartition checks if a disk name is a partition (has a number suffix after letters).
func isUIPartition(name string) bool {
	if strings.HasPrefix(name, "nvme") {
		return strings.Contains(name, "p") && name != strings.TrimRight(name, "0123456789")
	}
	// sda1, vda1 etc
	last := name[len(name)-1]
	return last >= '0' && last <= '9'
}
