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

// boxTopTitle renders a top border with a title embedded: ╭──Title──────────╮
func boxTopTitle(title string, innerW int) string {
	titleW := lipgloss.Width(title)
	totalW := innerW + 2
	leftDash := 2
	rightDash := totalW - leftDash - titleW
	if rightDash < 2 {
		rightDash = 2
	}
	return " " + dimStyle.Render("╭"+strings.Repeat("─", leftDash)) +
		title +
		dimStyle.Render(strings.Repeat("─", rightDash)+"╮")
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

func fmtBytesRate(bps float64) string {
	switch {
	case bps >= 1<<30:
		return fmt.Sprintf("%.1f GB/s", bps/(1<<30))
	case bps >= 1<<20:
		return fmt.Sprintf("%.1f MB/s", bps/(1<<20))
	case bps >= 1<<10:
		return fmt.Sprintf("%.1f KB/s", bps/(1<<10))
	default:
		return fmt.Sprintf("%.0f B/s", bps)
	}
}

// #22: Use rune-aware operations for proper UTF-8 handling
func padRight(s string, width int) string {
	runes := []rune(s)
	if len(runes) > width {
		if width > 3 {
			return string(runes[:width-3]) + "..."
		}
		return string(runes[:width])
	}
	return s + strings.Repeat(" ", width-len(runes))
}

// truncate shortens s to maxLen runes with ellipsis if needed.
func truncate(s string, maxLen int) string {
	runes := []rune(s)
	if len(runes) <= maxLen {
		return s
	}
	if maxLen <= 3 {
		return string(runes[:maxLen])
	}
	return string(runes[:maxLen-3]) + "..."
}

// truncateToWidth trims a (possibly ANSI-styled) string to fit within maxW
// visible columns. It iterates runes and stops once lipgloss.Width would exceed
// the limit. This is a best-effort trim — mid-escape truncation is possible but
// the terminal will recover on the next line.
func truncateToWidth(s string, maxW int) string {
	if lipgloss.Width(s) <= maxW {
		return s
	}
	runes := []rune(s)
	for i := len(runes); i > 0; i-- {
		candidate := string(runes[:i])
		if lipgloss.Width(candidate) <= maxW {
			return candidate
		}
	}
	return ""
}

func padLeft(s string, width int) string {
	runes := []rune(s)
	if len(runes) >= width {
		return string(runes[:width])
	}
	return strings.Repeat(" ", width-len(runes)) + s
}

// sparkline renders a simple ASCII sparkline chart (single-line).
func sparkline(data []float64, width int, minVal, maxVal float64) string {
	// #31: Handle empty data gracefully
	if len(data) == 0 {
		return dimStyle.Render(strings.Repeat("░", width) + " no data")
	}

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

	// #41: Batch consecutive chars with same color to reduce Render calls
	var sb strings.Builder
	type colorBand int
	const (
		bandOK   colorBand = 0
		bandWarn colorBand = 1
		bandCrit colorBand = 2
	)
	getBand := func(ratio float64) colorBand {
		if ratio > 0.8 {
			return bandCrit
		}
		if ratio > 0.4 {
			return bandWarn
		}
		return bandOK
	}

	var batch []rune
	prevBand := colorBand(-1)
	flushBatch := func() {
		if len(batch) == 0 {
			return
		}
		s := string(batch)
		switch prevBand {
		case bandCrit:
			sb.WriteString(critStyle.Render(s))
		case bandWarn:
			sb.WriteString(warnStyle.Render(s))
		default:
			sb.WriteString(okStyle.Render(s))
		}
		batch = batch[:0]
	}

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

		band := getBand(ratio)
		if band != prevBand && len(batch) > 0 {
			flushBatch()
		}
		prevBand = band
		batch = append(batch, blocks[idx])
	}
	flushBatch()

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

// pageFooter renders a consistent key-hint footer line.
// pageKeys: page-specific bindings (can be ""). Universal keys always appended.
func pageFooter(pageKeys string) string {
	universal := "N:verdicts  E:explain  j/k:scroll  ?:help  Esc:back  q:quit"
	if pageKeys == "" {
		return "\n" + dimStyle.Render("  "+universal) + "\n"
	}
	return "\n" + dimStyle.Render("  "+pageKeys+"  "+universal) + "\n"
}

// ─── METRIC VERDICT HELPERS ────────────────────────────────────────────────

// metricVerdict returns a styled verdict badge for a numeric value against thresholds.
// warnAt/critAt: thresholds (higher-is-worse). Returns "● OK" / "▲ HIGH" / "▲▲ CRITICAL".
func metricVerdict(val, warnAt, critAt float64) string {
	if val >= critAt {
		return critStyle.Render("▲▲ CRITICAL")
	}
	if val >= warnAt {
		return warnStyle.Render("▲ HIGH")
	}
	return okStyle.Render("● OK")
}

// metricVerdictLow returns verdict where LOWER is worse (e.g., available memory %).
func metricVerdictLow(val, warnBelow, critBelow float64) string {
	if val <= critBelow {
		return critStyle.Render("▼▼ CRITICAL")
	}
	if val <= warnBelow {
		return warnStyle.Render("▼ LOW")
	}
	return okStyle.Render("● OK")
}

// metricVerdictStr returns a one-word verdict string without styling.
func metricVerdictStr(val, warnAt, critAt float64) string {
	if val >= critAt {
		return "CRITICAL"
	}
	if val >= warnAt {
		return "HIGH"
	}
	return "OK"
}

// ─── INLINE ABBREVIATION HELPER ──────────────────────────────────────────────

// abbr formats a metric abbreviation with its expansion on first use.
// intermediate=true shows the expansion, false shows abbreviation only.
func abbr(short, long string, intermediate bool) string {
	if intermediate {
		return short + " (" + long + ")"
	}
	return short
}

// ─── EXPLAIN HINT ────────────────────────────────────────────────────────────

// explainHint returns a subtle hint about the explain panel.
func explainHint() string {
	return dimStyle.Render("  Press E for metric explanations")
}

// ─── PROBE INTERPRETATION ───────────────────────────────────────────────────

// probeInterpretation returns a one-line plain-English verdict for a probe finding.
func probeInterpretOffCPU(comm string, waitPct float64, reason string) string {
	if reason == "" {
		reason = "unknown"
	}
	switch {
	case waitPct >= 50:
		return fmt.Sprintf("%s is severely blocked — spending %.0f%% of time waiting (%s)", comm, waitPct, reason)
	case waitPct >= 30:
		return fmt.Sprintf("%s is frequently blocked — %.0f%% time waiting (%s)", comm, waitPct, reason)
	default:
		return fmt.Sprintf("%s has minor blocking — %.0f%% wait (%s)", comm, waitPct, reason)
	}
}

func probeInterpretIOLat(device string, p95 float64) string {
	switch {
	case p95 >= 50:
		return fmt.Sprintf("%s has very slow IO — 95th percentile latency is %.0fms (severely degraded)", device, p95)
	case p95 >= 20:
		return fmt.Sprintf("%s IO is sluggish — 95th percentile at %.0fms (may cause app slowdowns)", device, p95)
	default:
		return fmt.Sprintf("%s IO is healthy — p95 latency %.1fms", device, p95)
	}
}

func probeInterpretLock(comm string, waitPct float64, lockType string) string {
	switch {
	case waitPct >= 50:
		return fmt.Sprintf("%s has severe lock contention — %.0f%% time waiting for %s", comm, waitPct, lockType)
	case waitPct >= 30:
		return fmt.Sprintf("%s has notable lock contention — %.0f%% on %s", comm, waitPct, lockType)
	default:
		return fmt.Sprintf("%s has minor lock waits — %.0f%% on %s", comm, waitPct, lockType)
	}
}

func probeInterpretRetrans(comm string, retrans int) string {
	switch {
	case retrans >= 100:
		return fmt.Sprintf("%s has severe packet loss — %d retransmits/s (network congestion or faulty link)", comm, retrans)
	case retrans >= 30:
		return fmt.Sprintf("%s is seeing packet loss — %d retransmits/s", comm, retrans)
	default:
		return fmt.Sprintf("%s has minor retransmits — %d/s (normal)", comm, retrans)
	}
}

func probeInterpretRunQLat(comm string, avgUs float64) string {
	switch {
	case avgUs >= 1000:
		return fmt.Sprintf("%s waits %.0fus in CPU queue — tasks are starved for CPU time", comm, avgUs)
	case avgUs >= 100:
		return fmt.Sprintf("%s has moderate CPU queue delay — %.0fus average", comm, avgUs)
	default:
		return fmt.Sprintf("%s has fast CPU scheduling — %.0fus queue wait", comm, avgUs)
	}
}

func probeInterpretConnLat(comm string, avgMs float64, dest string) string {
	switch {
	case avgMs >= 500:
		return fmt.Sprintf("%s takes %.0fms to connect to %s — possible DNS/firewall/routing issue", comm, avgMs, dest)
	case avgMs >= 100:
		return fmt.Sprintf("%s has slow connections to %s — %.0fms average", comm, dest, avgMs)
	default:
		return fmt.Sprintf("%s connects quickly to %s — %.1fms", comm, dest, avgMs)
	}
}

func probeInterpretRTT(dest string, avgMs float64) string {
	switch {
	case avgMs >= 50:
		return fmt.Sprintf("High latency to %s — %.0fms round-trip (remote endpoint or network issue)", dest, avgMs)
	case avgMs >= 10:
		return fmt.Sprintf("Moderate latency to %s — %.0fms round-trip", dest, avgMs)
	default:
		return fmt.Sprintf("Low latency to %s — %.1fms round-trip (healthy)", dest, avgMs)
	}
}

func probeInterpretWBStall(comm string, count int) string {
	return fmt.Sprintf("%s was stalled %d times waiting for dirty pages to flush to disk", comm, count)
}

func probeInterpretPgFault(comm string, majorCount int) string {
	switch {
	case majorCount > 100:
		return fmt.Sprintf("%s triggered %d major page faults — frequently fetching data from disk (memory pressure)", comm, majorCount)
	case majorCount > 10:
		return fmt.Sprintf("%s has %d major page faults — some pages evicted and re-fetched from disk", comm, majorCount)
	default:
		return fmt.Sprintf("%s has %d major faults (normal — mostly minor faults)", comm, majorCount)
	}
}

func probeInterpretSockIO(comm string, dest string, avgWaitMs float64) string {
	switch {
	case avgWaitMs >= 50:
		return fmt.Sprintf("%s waits %.0fms for IO to %s — slow remote endpoint or network", comm, avgWaitMs, dest)
	case avgWaitMs >= 10:
		return fmt.Sprintf("%s has moderate socket wait to %s — %.0fms", comm, dest, avgWaitMs)
	default:
		return fmt.Sprintf("%s has fast socket IO to %s — %.1fms wait", comm, dest, avgWaitMs)
	}
}

// renderHealthBadge returns a styled status badge from a string status.
// Canonical implementation — use everywhere for consistent badge rendering.
func renderHealthBadge(status string) string {
	switch status {
	case "OK":
		return okStyle.Render("OK")
	case "WARN", "WARNING", "DEGRADED":
		return warnStyle.Render(status)
	case "CRIT", "CRITICAL":
		return critStyle.Render(status)
	case "INCONCLUSIVE":
		return orangeStyle.Render("INCONCLUSIVE")
	default:
		return dimStyle.Render(status)
	}
}
