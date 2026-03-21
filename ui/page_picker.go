package ui

import (
	"strings"

	"github.com/charmbracelet/lipgloss"
)

type pagePickerEntry struct {
	Page Page
	Key  string
	Name string
	Desc string
}

var pagePickerEntries = []pagePickerEntry{
	{PageOverview, "0", "Overview", "System health dashboard — CPU, Memory, IO, Network at a glance"},
	{PageCPU, "1", "CPU", "CPU utilization, load average, per-process breakdown, throttling"},
	{PageMemory, "2", "Memory", "Memory usage, swap, cache, page faults, VMStat counters"},
	{PageIO, "3", "IO", "Disk IO performance — latency, IOPS, throughput, SMART health"},
	{PageNetwork, "4", "Network", "Network throughput, drops, retransmits, conntrack, ephemeral ports"},
	{PageCgroups, "5", "CGroups", "Control group resource usage — CPU throttle, memory limits, IO"},
	{PageTimeline, "6", "Timeline", "5-minute rolling sparklines for all key metrics"},
	{PageEvents, "7", "Events", "Auto-detected incidents with timestamps, duration, blame"},
	{PageProbe, "8", "Probe", "eBPF deep dive results — off-CPU, IO latency, locks, retransmits"},
	{PageThresholds, "9", "Thresholds", "Live RCA threshold values vs current readings"},
	{PageDiskGuard, "D", "DiskGuard", "Filesystem space monitor with auto-contain"},
	{PageSecurity, "L", "Security", "SSH attacks, listening ports, suspicious processes, eBPF sentinels"},
	{PageDiag, "W", "Diagnostics", "System health checks — FDs, NTP, SSL, Docker, failed units"},
	{PageIntel, "X", "Intel", "Cross-signal correlation, SLO status, runtimes, autopilot"},
	{PageApps, "Y", "Apps", "Application health — MySQL, Redis, Nginx, PostgreSQL, Docker"},
	{PageProfiler, "O", "Profiler", "System optimization audit with domain scores and recommendations"},
	{PageGPU, "U", "GPU", "NVIDIA GPU utilization, VRAM, temperature, power, processes"},
}

// handlePagePicker processes key events when the page picker is open.
func (m *Model) handlePagePicker(key string) Model {
	filtered := m.filteredPickerEntries()

	switch key {
	case "esc", "ctrl+c":
		m.pagePickerActive = false
		return *m
	case "enter":
		if len(filtered) > 0 && m.pagePickerCursor < len(filtered) {
			m.page = filtered[m.pagePickerCursor].Page
			m.scroll = 0
			m.explainScroll = 0
		}
		m.pagePickerActive = false
		return *m
	case "up", "k":
		if m.pagePickerCursor > 0 {
			m.pagePickerCursor--
		}
	case "down", "j":
		if m.pagePickerCursor < len(filtered)-1 {
			m.pagePickerCursor++
		}
	case "backspace":
		if len(m.pagePickerQuery) > 0 {
			m.pagePickerQuery = m.pagePickerQuery[:len(m.pagePickerQuery)-1]
			m.pagePickerCursor = 0
		}
	default:
		if len(key) == 1 && key[0] >= 32 && key[0] <= 126 {
			m.pagePickerQuery += key
			m.pagePickerCursor = 0
		}
	}
	return *m
}

func (m *Model) filteredPickerEntries() []pagePickerEntry {
	if m.pagePickerQuery == "" {
		return pagePickerEntries
	}
	q := strings.ToLower(m.pagePickerQuery)
	var result []pagePickerEntry
	for _, e := range pagePickerEntries {
		if strings.Contains(strings.ToLower(e.Name), q) ||
			strings.Contains(strings.ToLower(e.Desc), q) ||
			strings.Contains(strings.ToLower(e.Key), q) {
			result = append(result, e)
		}
	}
	return result
}

// renderPagePickerOverlay renders the page picker as a centered overlay.
func renderPagePickerOverlay(m *Model, bg string, width, height int) string {
	filtered := m.filteredPickerEntries()

	boxW := 60
	if boxW > width-4 {
		boxW = width - 4
	}
	innerW := boxW - 4

	var sb strings.Builder

	// Title
	sb.WriteString(boxTopTitle(" "+titleStyle.Render("Navigate to Page")+" ", innerW))
	sb.WriteString("\n")

	// Search field
	searchLine := dimStyle.Render("Search: ") + valueStyle.Render(m.pagePickerQuery) + dimStyle.Render("_")
	sb.WriteString(boxRow(searchLine, innerW))
	sb.WriteString("\n")
	sb.WriteString(boxRow("", innerW))
	sb.WriteString("\n")

	// Page list
	maxShow := height - 10
	if maxShow > len(filtered) {
		maxShow = len(filtered)
	}
	if maxShow < 1 {
		maxShow = 1
	}

	// Scroll window
	start := 0
	if m.pagePickerCursor >= maxShow {
		start = m.pagePickerCursor - maxShow + 1
	}
	end := start + maxShow
	if end > len(filtered) {
		end = len(filtered)
	}

	for i := start; i < end; i++ {
		e := filtered[i]
		cursor := "  "
		nameStyle := valueStyle
		descStyle := dimStyle
		if i == m.pagePickerCursor {
			cursor = headerStyle.Render("> ")
			nameStyle = headerStyle
			descStyle = valueStyle
		}

		name := nameStyle.Render(e.Name)
		desc := e.Desc
		// Truncate description to fit
		maxDesc := innerW - lipgloss.Width(name) - 8
		if maxDesc < 10 {
			maxDesc = 10
		}
		if len(desc) > maxDesc {
			desc = desc[:maxDesc-3] + "..."
		}

		line := cursor + styledPad(dimStyle.Render(e.Key), 3) + " " + styledPad(name, 14) + " " + descStyle.Render(desc)
		sb.WriteString(boxRow(line, innerW))
		sb.WriteString("\n")
	}

	if len(filtered) == 0 {
		sb.WriteString(boxRow(dimStyle.Render("  No matching pages"), innerW))
		sb.WriteString("\n")
	}

	sb.WriteString(boxRow("", innerW))
	sb.WriteString("\n")
	sb.WriteString(boxRow(dimStyle.Render("Enter:select  Esc:cancel  ↑↓:navigate  Type to filter"), innerW))
	sb.WriteString("\n")
	sb.WriteString(boxBot(innerW))

	overlay := sb.String()
	overlayLines := strings.Split(overlay, "\n")

	// Center overlay on background
	bgLines := strings.Split(bg, "\n")
	startRow := (height - len(overlayLines)) / 2
	if startRow < 1 {
		startRow = 1
	}
	startCol := (width - boxW) / 2
	if startCol < 0 {
		startCol = 0
	}

	for i, ol := range overlayLines {
		row := startRow + i
		if row >= len(bgLines) {
			break
		}
		bgLine := bgLines[row]
		bgVis := lipgloss.Width(bgLine)
		olVis := lipgloss.Width(ol)

		// Replace the center portion with overlay
		pad := ""
		if startCol > 0 {
			pad = strings.Repeat(" ", startCol)
		}
		trail := ""
		remaining := width - startCol - olVis
		if remaining > 0 {
			trail = strings.Repeat(" ", remaining)
		}
		_ = bgVis // we overwrite the whole line
		bgLines[row] = pad + ol + trail
	}

	return strings.Join(bgLines, "\n")
}
