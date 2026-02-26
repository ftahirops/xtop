package ui

import (
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"
	"github.com/ftahirops/xtop/engine"
)

func renderTimelinePage(history *engine.History, width, height int) string {
	var sb strings.Builder

	n := history.Len()
	if n < 2 {
		sb.WriteString(titleStyle.Render("TIMELINE"))
		sb.WriteString("\n")
		sb.WriteString(dimStyle.Render("  Need more data (collecting...)"))
		return sb.String()
	}

	// Use all available samples
	maxSamples := n

	// Time range info
	oldest := history.Get(0)
	latest := history.Latest()
	timeRange := ""
	var startTime, endTime time.Time
	if oldest != nil && latest != nil {
		startTime = oldest.Timestamp
		endTime = latest.Timestamp
		dur := endTime.Sub(startTime)
		timeRange = fmt.Sprintf(" (%s, %d samples)",
			formatDuration(dur), maxSamples)
	}
	sb.WriteString(titleStyle.Render("TIMELINE") + dimStyle.Render(timeRange))
	sb.WriteString("\n\n")

	// Gather all data series
	cpuBusy := make([]float64, maxSamples)
	memUsedPct := make([]float64, maxSamples)
	cpuPSI := make([]float64, maxSamples)
	memPSI := make([]float64, maxSamples)
	ioPSI := make([]float64, maxSamples)
	dStates := make([]float64, maxSamples)

	for i := 0; i < maxSamples; i++ {
		s := history.Get(i)
		if s == nil {
			continue
		}

		// Use rate-based CPU busy if available, fallback to load average proxy
		r := history.GetRate(i)
		if r != nil {
			cpuBusy[i] = r.CPUBusyPct
		} else {
			nCPU := s.Global.CPU.NumCPUs
			if nCPU == 0 {
				nCPU = 1
			}
			cpuBusy[i] = s.Global.CPU.LoadAvg.Load1 / float64(nCPU) * 100
			if cpuBusy[i] > 100 {
				cpuBusy[i] = 100
			}
		}

		// Memory used %
		if s.Global.Memory.Total > 0 {
			memUsedPct[i] = float64(s.Global.Memory.Total-s.Global.Memory.Available) / float64(s.Global.Memory.Total) * 100
		}

		cpuPSI[i] = s.Global.PSI.CPU.Some.Avg10
		memPSI[i] = s.Global.PSI.Memory.Full.Avg10
		ioPSI[i] = s.Global.PSI.IO.Full.Avg10

		ds := 0
		for _, p := range s.Processes {
			if p.State == "D" {
				ds++
			}
		}
		dStates[i] = float64(ds)
	}

	// Chart dimensions
	chartH := 6
	chartW := width - 2
	if chartW < 30 {
		chartW = 30
	}

	// Render multi-line area charts with auto-scaled Y-axis
	sb.WriteString(areaChart(cpuBusy, "CPU Load %", chartW, chartH, 0, autoScale(cpuBusy, 100), pctChartColor, startTime, endTime))
	sb.WriteString("\n\n")

	sb.WriteString(areaChart(memUsedPct, "Memory Used %", chartW, chartH, 0, autoScale(memUsedPct, 100), pctChartColor, startTime, endTime))
	sb.WriteString("\n\n")

	sb.WriteString(areaChart(cpuPSI, "CPU PSI (some avg10)", chartW, chartH, 0, autoScale(cpuPSI, 50), psiChartColor, startTime, endTime))
	sb.WriteString("\n\n")

	sb.WriteString(areaChart(ioPSI, "IO PSI (full avg10)", chartW, chartH, 0, autoScale(ioPSI, 50), psiChartColor, startTime, endTime))
	sb.WriteString("\n\n")

	sb.WriteString(areaChart(memPSI, "MEM PSI (full avg10)", chartW, chartH, 0, autoScale(memPSI, 50), psiChartColor, startTime, endTime))
	sb.WriteString("\n\n")

	sb.WriteString(areaChart(dStates, "D-State Tasks", chartW, 4, 0, autoScale(dStates, 20),
		func(val, ratio float64) lipgloss.Style {
			if val >= 5 {
				return critStyle
			}
			if val >= 1 {
				return warnStyle
			}
			return okStyle
		}, startTime, endTime))
	sb.WriteString("\n")

	// OOM event notice — only show if BPF sentinel detected OOM kills this tick
	if latest != nil && latest.Global.Sentinel.Active && len(latest.Global.Sentinel.OOMKills) > 0 {
		sb.WriteString("\n")
		victim := latest.Global.Sentinel.OOMKills[0]
		sb.WriteString(critStyle.Render(fmt.Sprintf("  OOM kill detected: %s (PID %d) killed this tick", victim.VictimComm, victim.VictimPID)))
		sb.WriteString("\n")
	}

	return sb.String()
}

