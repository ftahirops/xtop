package ui

import (
	"fmt"
	"sort"
	"strings"

	"github.com/ftahirops/xtop/model"
)

func renderLogsPage(snap *model.Snapshot, rates *model.RateSnapshot, result *model.AnalysisResult, pm probeQuerier, width, height int) string {
	var sb strings.Builder
	iw := pageInnerW(width)

	sb.WriteString(titleStyle.Render("LOG ANALYSIS"))
	sb.WriteString("\n")
	sb.WriteString(renderRCAInline(result))
	sb.WriteString(renderProbeStatusLine(pm))
	sb.WriteString("\n")

	services := snap.Global.Logs.Services

	// === LOG HEALTH ===
	totalErrRate := 0.0
	errServiceCount := 0
	for _, svc := range services {
		totalErrRate += svc.ErrorRate
		if svc.TotalErrors > 0 {
			errServiceCount++
		}
	}

	var healthLines []string
	if len(services) == 0 {
		healthLines = append(healthLines, dimStyle.Render("  No tracked services found (install systemd services to enable)"))
	} else {
		rateStr := fmt.Sprintf("%.2f/s", totalErrRate)
		if totalErrRate > 1 {
			rateStr = critStyle.Render(rateStr)
		} else if totalErrRate > 0 {
			rateStr = warnStyle.Render(rateStr)
		} else {
			rateStr = okStyle.Render(rateStr)
		}
		healthLines = append(healthLines, fmt.Sprintf("  Total error rate: %s   Services with errors: %s / %s",
			rateStr,
			valueStyle.Render(fmt.Sprintf("%d", errServiceCount)),
			dimStyle.Render(fmt.Sprintf("%d tracked", len(services)))))
	}
	sb.WriteString(boxSection("LOG HEALTH", healthLines, iw))

	// === PER-SERVICE LOG RATES ===
	// Sort by error rate descending
	sorted := make([]model.ServiceLogStats, len(services))
	copy(sorted, services)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].ErrorRate > sorted[j].ErrorRate
	})

	var svcLines []string
	if len(sorted) == 0 {
		svcLines = append(svcLines, dimStyle.Render("  No services to display"))
	} else {
		// Header
		svcLines = append(svcLines, fmt.Sprintf("  %s %s %s %s %s %s",
			styledPad(dimStyle.Render("SERVICE"), 16),
			styledPad(dimStyle.Render("ERR/s"), 8),
			styledPad(dimStyle.Render("WARN/s"), 8),
			styledPad(dimStyle.Render("TOTAL"), 8),
			styledPad(dimStyle.Render("SPARKLINE"), 22),
			dimStyle.Render("LAST ERROR")))
		svcLines = append(svcLines, dimStyle.Render("  "+strings.Repeat("─", iw-4)))

		for _, svc := range sorted {
			errRateStr := fmt.Sprintf("%.2f", svc.ErrorRate)
			if svc.ErrorRate > 1 {
				errRateStr = critStyle.Render(errRateStr)
			} else if svc.ErrorRate > 0 {
				errRateStr = warnStyle.Render(errRateStr)
			} else {
				errRateStr = okStyle.Render(errRateStr)
			}

			warnRateStr := fmt.Sprintf("%.2f", svc.WarnRate)
			if svc.WarnRate > 1 {
				warnRateStr = warnStyle.Render(warnRateStr)
			} else {
				warnRateStr = dimStyle.Render(warnRateStr)
			}

			totalStr := fmt.Sprintf("%d", svc.TotalErrors)

			// Sparkline
			maxVal := 0.1
			for _, v := range svc.RateHistory {
				if v > maxVal {
					maxVal = v
				}
			}
			spark := sparkline(svc.RateHistory, 15, 0, maxVal)

			lastErr := svc.LastError
			maxErrLen := iw - 70
			if maxErrLen < 20 {
				maxErrLen = 20
			}
			if len(lastErr) > maxErrLen {
				lastErr = lastErr[:maxErrLen-3] + "..."
			}
			if lastErr == "" {
				lastErr = dimStyle.Render("—")
			} else {
				lastErr = dimStyle.Render(lastErr)
			}

			svcLines = append(svcLines, fmt.Sprintf("  %s %s %s %s %s %s",
				styledPad(valueStyle.Render(padRight(svc.Name, 14)), 16),
				styledPad(errRateStr, 8),
				styledPad(warnRateStr, 8),
				styledPad(valueStyle.Render(padLeft(totalStr, 6)), 8),
				styledPad(spark, 22),
				lastErr))
		}
	}
	sb.WriteString(boxSection("PER-SERVICE LOG RATES", svcLines, iw))

	return sb.String()
}
