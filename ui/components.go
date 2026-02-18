package ui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"
)

// Column widths used across all layouts for consistent alignment.
const (
	colName    = 10 // subsystem name: "CPU", "Memory", etc.
	colStat    = 8  // status: "GREEN", "YELLOW", "RED"
	colKey     = 16 // detail key: "Utilization:", "Latency:", etc.
	colVal     = 28 // detail value column
	colOwLbl   = 5  // owner label: "IO", "CPU", "MEM", "NET"
	colOwNam   = 22 // owner name
	maxBoxInner = 55 // max inner width for KV boxes
)

// styledPad pads a styled string to the given visual width using spaces.
// Unlike fmt.Sprintf("%-Xs"), this accounts for ANSI escape codes.
func styledPad(styled string, width int) string {
	visW := lipgloss.Width(styled)
	if visW >= width {
		return styled
	}
	return styled + strings.Repeat(" ", width-visW)
}

// ─── BOX DRAWING HELPERS ─────────────────────────────────────────────────────

// boxTop renders the top border of a rounded box.
// Total visual width = innerW + 5 (1 indent + 1 corner + innerW+2 dashes + 1 corner).
func boxTop(innerW int) string {
	return " " + dimStyle.Render("╭"+strings.Repeat("─", innerW+2)+"╮")
}

// boxBot renders the bottom border of a rounded box.
func boxBot(innerW int) string {
	return " " + dimStyle.Render("╰"+strings.Repeat("─", innerW+2)+"╯")
}

// boxMid renders a horizontal divider inside a box.
func boxMid(innerW int) string {
	return " " + dimStyle.Render("├"+strings.Repeat("─", innerW+2)+"┤")
}

// boxRow renders one content line inside a box, padded to innerW.
func boxRow(content string, innerW int) string {
	visW := lipgloss.Width(content)
	pad := innerW - visW
	if pad < 0 {
		pad = 0
	}
	return " " + dimStyle.Render("│") + " " + content + strings.Repeat(" ", pad) + " " + dimStyle.Render("│")
}

// renderKVBox renders key-value pairs inside a bordered box.
func renderKVBox(details []kv, innerW int) string {
	var sb strings.Builder
	sb.WriteString(boxTop(innerW) + "\n")
	for _, d := range details {
		key := d.Key
		if len(key) > 14 {
			key = key[:14]
		}
		content := fmt.Sprintf("%s %s",
			styledPad(dimStyle.Render(key+":"), colKey),
			valueStyle.Render(d.Val))
		sb.WriteString(boxRow(content, innerW) + "\n")
	}
	sb.WriteString(boxBot(innerW) + "\n")
	return sb.String()
}

// renderKVBoxStyled renders key-value pairs with custom value styling.
func renderKVBoxStyled(details []kv, innerW int, status string) string {
	var sb strings.Builder
	sb.WriteString(boxTop(innerW) + "\n")
	for _, d := range details {
		key := d.Key
		if len(key) > 14 {
			key = key[:14]
		}
		vs := valueStyle
		if status == "RED" && d.Val != "none" && d.Val != "\u2014" && d.Val != "normal" {
			vs = critStyle
		} else if status == "YELLOW" && d.Val != "none" && d.Val != "\u2014" && d.Val != "normal" {
			vs = warnStyle
		}
		content := fmt.Sprintf("%s %s",
			styledPad(dimStyle.Render(key+":"), colKey),
			vs.Render(d.Val))
		sb.WriteString(boxRow(content, innerW) + "\n")
	}
	sb.WriteString(boxBot(innerW) + "\n")
	return sb.String()
}

// bar renders a percentage bar of given width.
func bar(pct float64, width int) string {
	if width < 1 {
		width = 10
	}
	if pct < 0 {
		pct = 0
	}
	if pct > 100 {
		pct = 100
	}
	filled := int(pct / 100 * float64(width))
	if filled > width {
		filled = width
	}
	b := strings.Repeat("█", filled) + strings.Repeat("░", width-filled)
	switch {
	case pct >= 80:
		return critStyle.Render(b)
	case pct >= 50:
		return warnStyle.Render(b)
	default:
		return okStyle.Render(b)
	}
}

// psiBar renders a PSI percentage bar (thresholds are lower than general bars).
func psiBar(pct float64, width int) string {
	if width < 1 {
		width = 10
	}
	if pct > 100 {
		pct = 100
	}
	filled := int(pct / 100 * float64(width))
	if filled > width {
		filled = width
	}
	if filled < 0 {
		filled = 0
	}
	b := strings.Repeat("█", filled) + strings.Repeat("░", width-filled)
	var style lipgloss.Style
	switch {
	case pct >= 25:
		style = critStyle
	case pct >= 5:
		style = warnStyle
	default:
		style = okStyle
	}
	return style.Render(b)
}

func fmtBytes(b uint64) string {
	switch {
	case b >= 1<<30:
		return fmt.Sprintf("%.1fG", float64(b)/(1<<30))
	case b >= 1<<20:
		return fmt.Sprintf("%.1fM", float64(b)/(1<<20))
	case b >= 1<<10:
		return fmt.Sprintf("%.1fK", float64(b)/(1<<10))
	default:
		return fmt.Sprintf("%dB", b)
	}
}

func fmtRate(mbps float64) string {
	if mbps >= 1024 {
		return fmt.Sprintf("%.1f GB/s", mbps/1024)
	}
	if mbps >= 1 {
		return fmt.Sprintf("%.1f MB/s", mbps)
	}
	return fmt.Sprintf("%.0f KB/s", mbps*1024)
}

func fmtPct(v float64) string {
	return fmt.Sprintf("%.1f%%", v)
}

func padRight(s string, width int) string {
	if len(s) >= width {
		if width > 3 {
			return s[:width-3] + "..."
		}
		return s[:width]
	}
	return s + strings.Repeat(" ", width-len(s))
}

// truncate shortens s to maxLen characters with ellipsis if needed.
func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	if maxLen <= 3 {
		return s[:maxLen]
	}
	return s[:maxLen-3] + "..."
}

func padLeft(s string, width int) string {
	if len(s) >= width {
		return s[:width]
	}
	return strings.Repeat(" ", width-len(s)) + s
}

// sparkline renders a simple ASCII sparkline chart (single-line).
func sparkline(data []float64, width int, minVal, maxVal float64) string {
	blocks := []rune{'▁', '▂', '▃', '▄', '▅', '▆', '▇', '█'}
	if maxVal <= minVal {
		maxVal = minVal + 1
	}

	// Resample data to fit width
	var resampled []float64
	if len(data) <= width {
		resampled = data
	} else {
		resampled = make([]float64, width)
		for i := 0; i < width; i++ {
			srcIdx := i * len(data) / width
			if srcIdx >= len(data) {
				srcIdx = len(data) - 1
			}
			resampled[i] = data[srcIdx]
		}
	}

	var sb strings.Builder
	for _, v := range resampled {
		ratio := (v - minVal) / (maxVal - minVal)
		if ratio < 0 {
			ratio = 0
		}
		if ratio > 1 {
			ratio = 1
		}
		idx := int(ratio * float64(len(blocks)-1))
		if idx >= len(blocks) {
			idx = len(blocks) - 1
		}

		switch {
		case ratio > 0.8:
			sb.WriteString(critStyle.Render(string(blocks[idx])))
		case ratio > 0.4:
			sb.WriteString(warnStyle.Render(string(blocks[idx])))
		default:
			sb.WriteString(okStyle.Render(string(blocks[idx])))
		}
	}

	last := float64(0)
	if len(resampled) > 0 {
		last = resampled[len(resampled)-1]
	}
	sb.WriteString(dimStyle.Render(fmt.Sprintf(" now=%.1f", last)))

	return sb.String()
}

// fmtPSI formats a PSI value with color.
func fmtPSI(v float64) string {
	if v >= 10 {
		return critStyle.Render(fmt.Sprintf("%.0f%%", v))
	}
	if v >= 1 {
		return warnStyle.Render(fmt.Sprintf("%.1f%%", v))
	}
	return okStyle.Render(fmt.Sprintf("%.1f%%", v))
}

// healthBadge returns styled health indicator.
// boxSection renders a titled section inside a bordered box.
// title is styled with headerStyle, content lines are rendered as-is inside the box.
func boxSection(title string, lines []string, innerW int) string {
	var sb strings.Builder
	sb.WriteString(boxTop(innerW) + "\n")
	sb.WriteString(boxRow(headerStyle.Render(title), innerW) + "\n")
	sb.WriteString(boxMid(innerW) + "\n")
	for _, line := range lines {
		sb.WriteString(boxRow(line, innerW) + "\n")
	}
	sb.WriteString(boxBot(innerW) + "\n")
	return sb.String()
}

// pageInnerW computes box inner width from terminal width.
func pageInnerW(termWidth int) int {
	w := termWidth - 6
	if w < 60 {
		w = 60
	}
	return w
}

func healthBadge(h fmt.Stringer, score int) string {
	s := h.String()
	switch s {
	case "OK":
		return okStyle.Render("OK")
	case "INCONCLUSIVE":
		return orangeStyle.Render("INCONCLUSIVE")
	case "DEGRADED":
		return warnStyle.Render("DEGRADED")
	case "CRITICAL":
		return critStyle.Render("CRITICAL")
	}
	return s
}
