package ui

import (
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"
)

// areaChart renders a multi-line area chart with Y-axis labels, sub-cell
// resolution using fractional block characters, and per-cell coloring.
//
//	CPU Load %                                          now: 42.0
//	100│
//	 80│          ████
//	 60│        ████████       ██
//	 40│    ████████████████████████
//	 20│████████████████████████████████
//	  0│████████████████████████████████████████
//	   └────────────────────────────────────────
//	   16:30:00                        16:35:00
func areaChart(data []float64, label string, width, height int, minVal, maxVal float64,
	colorFn func(float64, float64) lipgloss.Style, startTime, endTime time.Time) string {

	if height < 2 {
		height = 2
	}
	if maxVal <= minVal {
		maxVal = minVal + 1
	}

	axisW := 4 // e.g. "100│"
	chartW := width - axisW - 1
	if chartW < 10 {
		chartW = 10
	}

	// Resample data to fit chart width
	resampled := resampleData(data, chartW)

	// Sub-block characters for fractional fill within a cell
	subBlocks := []rune{' ', '▁', '▂', '▃', '▄', '▅', '▆', '▇', '█'}

	var sb strings.Builder

	// Title line with current value
	last := float64(0)
	if len(resampled) > 0 {
		last = resampled[len(resampled)-1]
	}
	sb.WriteString(titleStyle.Render(label))
	sb.WriteString(dimStyle.Render(fmt.Sprintf("  now: %.1f", last)))
	sb.WriteString("\n")

	rangeVal := maxVal - minVal

	// Render rows from top to bottom
	for row := height - 1; row >= 0; row-- {
		// Y-axis label
		yVal := minVal + (float64(row+1)/float64(height))*rangeVal
		sb.WriteString(dimStyle.Render(fmt.Sprintf("%3.0f", yVal)))
		sb.WriteString(dimStyle.Render("│"))

		for col := 0; col < len(resampled); col++ {
			val := resampled[col]
			// Normalize value to 0..height scale
			normalized := (val - minVal) / rangeVal * float64(height)

			cellBottom := float64(row)
			cellTop := float64(row + 1)

			var ch rune
			if normalized >= cellTop {
				ch = '█' // fully filled
			} else if normalized <= cellBottom {
				ch = ' ' // empty
			} else {
				// Partial fill
				fraction := normalized - cellBottom
				idx := int(fraction * 8)
				if idx >= len(subBlocks) {
					idx = len(subBlocks) - 1
				}
				if idx < 0 {
					idx = 0
				}
				ch = subBlocks[idx]
			}

			// Color based on value ratio
			ratio := (val - minVal) / rangeVal
			style := colorFn(val, ratio)
			if ch == ' ' {
				sb.WriteRune(' ')
			} else {
				sb.WriteString(style.Render(string(ch)))
			}
		}
		sb.WriteString("\n")
	}

	// X-axis line
	sb.WriteString(dimStyle.Render("   └" + strings.Repeat("─", len(resampled))))
	sb.WriteString("\n")

	// Time labels
	if !startTime.IsZero() && !endTime.IsZero() {
		left := startTime.Format("15:04:05")
		right := endTime.Format("15:04:05")
		gap := len(resampled) - len(left) - len(right) + axisW
		if gap < 1 {
			gap = 1
		}
		sb.WriteString(dimStyle.Render("   " + left + strings.Repeat(" ", gap) + right))
	}

	return sb.String()
}

// resampleData reduces or returns data to fit targetWidth columns.
func resampleData(data []float64, targetWidth int) []float64 {
	if len(data) == 0 {
		return data
	}
	if len(data) <= targetWidth {
		return data
	}
	result := make([]float64, targetWidth)
	for i := 0; i < targetWidth; i++ {
		// Average the bucket of source values that map to this column
		srcStart := i * len(data) / targetWidth
		srcEnd := (i + 1) * len(data) / targetWidth
		if srcEnd > len(data) {
			srcEnd = len(data)
		}
		if srcStart >= srcEnd {
			srcStart = srcEnd - 1
			if srcStart < 0 {
				srcStart = 0
			}
		}
		sum := float64(0)
		count := 0
		for j := srcStart; j < srcEnd; j++ {
			sum += data[j]
			count++
		}
		if count > 0 {
			result[i] = sum / float64(count)
		}
	}
	return result
}

// pctChartColor colors values by percentage (0-100).
func pctChartColor(val, ratio float64) lipgloss.Style {
	switch {
	case val >= 80:
		return critStyle
	case val >= 50:
		return warnStyle
	default:
		return okStyle
	}
}

// psiChartColor colors values by PSI thresholds.
func psiChartColor(val, ratio float64) lipgloss.Style {
	switch {
	case val >= 25:
		return critStyle
	case val >= 5:
		return warnStyle
	case val >= 0.5:
		return orangeStyle
	default:
		return okStyle
	}
}

// autoScale computes a "nice" Y-axis max based on actual data values.
// Returns a rounded-up ceiling that shows data clearly with some headroom.
func autoScale(data []float64, hardMax float64) float64 {
	maxVal := float64(0)
	for _, v := range data {
		if v > maxVal {
			maxVal = v
		}
	}
	if maxVal <= 0 {
		return 5 // minimum scale for all-zero data
	}
	target := maxVal * 1.3 // 30% headroom
	nice := []float64{1, 2, 5, 10, 15, 20, 25, 30, 40, 50, 75, 100}
	for _, n := range nice {
		if target <= n {
			return n
		}
	}
	return hardMax
}

// formatDuration formats a duration as "Xm Ys" or "Xs".
func formatDuration(d time.Duration) string {
	s := int(d.Seconds())
	if s >= 60 {
		return fmt.Sprintf("%dm%ds", s/60, s%60)
	}
	return fmt.Sprintf("%ds", s)
}
