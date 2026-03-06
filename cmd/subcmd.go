package cmd

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/ftahirops/xtop/api"
	"github.com/ftahirops/xtop/engine"
	"github.com/ftahirops/xtop/model"
)

// collectOrQuery tries daemon API first, falls back to direct 2-tick collection.
func collectOrQuery(intervalSec int) (*model.Snapshot, *model.RateSnapshot, *model.AnalysisResult) {
	// Try daemon API first (instant, no wait)
	client := api.TryConnect()
	if client != nil {
		fmt.Fprintf(os.Stderr, "Connected to daemon API\n")
		// For now, fall through to direct collection since API returns
		// StatusResponse, not full Snapshot/RateSnapshot.
		// TODO: add full snapshot endpoint in API
	}
	return directCollect(intervalSec)
}

// directCollect creates an engine, runs 2 ticks with a sleep between, and returns results.
func directCollect(intervalSec int) (*model.Snapshot, *model.RateSnapshot, *model.AnalysisResult) {
	if intervalSec <= 0 {
		intervalSec = 3
	}
	eng := engine.NewEngine(60, intervalSec)
	defer eng.Close()
	eng.Tick() // first tick: baseline
	time.Sleep(time.Duration(intervalSec) * time.Second)
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
