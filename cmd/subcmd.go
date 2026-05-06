package cmd

import (
	"fmt"
	"strings"
	"time"

	"github.com/ftahirops/xtop/api"
	"github.com/ftahirops/xtop/collector"
	"github.com/ftahirops/xtop/engine"
	"github.com/ftahirops/xtop/model"
)

// collectOrQuery returns a snapshot+rates+result for one-shot subcommands
// (xtop why, top, proc). Always uses direct collection — the daemon API
// doesn't expose a full-snapshot endpoint, so the previous "try daemon
// first" path was a no-op that just printed a misleading message.
func collectOrQuery(intervalSec int) (*model.Snapshot, *model.RateSnapshot, *model.AnalysisResult) {
	_ = api.TryConnect // keep the import alive; reserved for future full-snapshot endpoint
	return directCollect(intervalSec)
}

// directCollect runs two engine ticks and returns the second's analysis.
//
// Rate computation needs two samples; we use a short fixed delay between
// them (250 ms) regardless of the operator's --interval. Over 250 ms,
// counter deltas are still well-resolved (jiffies@HZ=1000 → 250 ticks of
// resolution), kernel PSI is still smooth (PSI avg10/avg60 are kernel-side
// averages, tick-interval independent), and the user doesn't wait 3
// seconds for a one-shot answer.
//
// intervalSec is forwarded to the engine ONLY for AlertState calibration
// inside the engine; it does not gate this function's wait time.
func directCollect(intervalSec int) (*model.Snapshot, *model.RateSnapshot, *model.AnalysisResult) {
	if intervalSec <= 0 {
		intervalSec = 3
	}
	// One-shot subcommands run in ModeLean: only the essential collectors
	// (PSI, /proc/stat, processes, key /proc/* files). Skips the heavy
	// rich-mode set (cgroup tree walk, app deep diagnostics, profiler
	// audit, eBPF sentinel) which are pointless for a one-shot question.
	// Cuts the per-tick cost from ~2 s to ~50 ms on a busy host.
	eng := engine.NewEngineMode(60, intervalSec, collector.ModeLean)
	defer eng.Close()
	eng.Tick() // first tick: baseline for rate diff
	time.Sleep(250 * time.Millisecond)
	snap, rates, result := eng.Tick()
	return snap, rates, result
}

// ── Subcommand ANSI rendering helpers ─────────────────────────────────────

// colorByImpact returns an ANSI-colored string based on impact score thresholds.
func colorByImpact(val float64) string {
	switch {
	case val >= 70:
		return fmt.Sprintf("%s%s%.1f%s", B, FBRed, val, R)
	case val >= 40:
		return fmt.Sprintf("%s%.1f%s", FBYel, val, R)
	default:
		return fmt.Sprintf("%s%.1f%s", FBGrn, val, R)
	}
}

// colorByThreshold returns an ANSI-colored float based on warn/crit thresholds.
func colorByThreshold(val, warn, crit float64) string {
	switch {
	case val >= crit:
		return fmt.Sprintf("%s%s%.1f%s", B, FBRed, val, R)
	case val >= warn:
		return fmt.Sprintf("%s%.1f%s", FBYel, val, R)
	default:
		return fmt.Sprintf("%s%.1f%s", FBGrn, val, R)
	}
}

// healthColor returns the ANSI-colored health string.
func healthColor(h model.HealthLevel) string {
	switch h {
	case model.HealthCritical:
		return fmt.Sprintf("%s%s CRITICAL %s", B, BRed, R)
	case model.HealthDegraded:
		return fmt.Sprintf("%s%s DEGRADED %s", B, FBYel, R)
	case model.HealthInconclusive:
		return fmt.Sprintf("%s INCONCLUSIVE %s", FCyn, R)
	default:
		return fmt.Sprintf("%s%s OK %s", B, FBGrn, R)
	}
}

// renderTable renders an ANSI-colored table with headers and rows.
// widths specifies column widths; 0 means auto.
func renderTable(headers []string, rows [][]string, widths []int) string {
	if len(headers) == 0 {
		return ""
	}

	// Auto-compute widths if not provided
	if len(widths) == 0 || len(widths) != len(headers) {
		widths = make([]int, len(headers))
		for i, h := range headers {
			widths[i] = len(h)
		}
		for _, row := range rows {
			for i, cell := range row {
				if i < len(widths) {
					vis := visLen(cell)
					if vis > widths[i] {
						widths[i] = vis
					}
				}
			}
		}
	}

	var sb strings.Builder

	// Header
	sb.WriteString(B)
	for i, h := range headers {
		sb.WriteString(padOrTrunc(h, widths[i]))
		if i < len(headers)-1 {
			sb.WriteString("  ")
		}
	}
	sb.WriteString(R)
	sb.WriteString("\n")

	// Separator
	for i, w := range widths {
		sb.WriteString(strings.Repeat("─", w))
		if i < len(widths)-1 {
			sb.WriteString("──")
		}
	}
	sb.WriteString("\n")

	// Rows
	for _, row := range rows {
		for i, cell := range row {
			if i >= len(widths) {
				break
			}
			sb.WriteString(padStyledOrTrunc(cell, widths[i]))
			if i < len(row)-1 && i < len(widths)-1 {
				sb.WriteString("  ")
			}
		}
		sb.WriteString("\n")
	}

	return sb.String()
}

// visLen returns the visual (non-ANSI) length of a string.
func visLen(s string) int {
	n := 0
	inEsc := false
	for i := 0; i < len(s); i++ {
		if s[i] == '\033' {
			inEsc = true
			continue
		}
		if inEsc {
			if s[i] == 'm' {
				inEsc = false
			}
			continue
		}
		n++
	}
	return n
}

// padOrTrunc pads or truncates a plain string to width.
func padOrTrunc(s string, width int) string {
	if len(s) > width {
		if width > 2 {
			return s[:width-2] + ".."
		}
		return s[:width]
	}
	return s + strings.Repeat(" ", width-len(s))
}

// padStyledOrTrunc pads an ANSI-styled string to visual width.
func padStyledOrTrunc(s string, width int) string {
	vl := visLen(s)
	if vl > width {
		return s // don't truncate styled strings (complex)
	}
	return s + strings.Repeat(" ", width-vl)
}

// subcmdFmtBytes formats bytes to human-readable string.
func subcmdFmtBytes(b uint64) string {
	const (
		kb = 1024
		mb = 1024 * kb
		gb = 1024 * mb
	)
	switch {
	case b >= gb:
		return fmt.Sprintf("%.1fG", float64(b)/float64(gb))
	case b >= mb:
		return fmt.Sprintf("%.1fM", float64(b)/float64(mb))
	case b >= kb:
		return fmt.Sprintf("%.0fK", float64(b)/float64(kb))
	default:
		return fmt.Sprintf("%dB", b)
	}
}

// subcmdTrunc truncates a string with ".." if too long.
func subcmdTrunc(s string, n int) string {
	if len(s) <= n {
		return s
	}
	if n > 2 {
		return s[:n-2] + ".."
	}
	return s[:n]
}
