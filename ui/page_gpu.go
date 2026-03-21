package ui

import (
	"fmt"
	"strings"

	"github.com/ftahirops/xtop/model"
)

func renderGPUPage(snap *model.Snapshot, width, height int) string {
	var sb strings.Builder
	iw := width - 6
	if iw < 40 {
		iw = 40
	}
	if iw > 100 {
		iw = 100
	}

	sb.WriteString(boxSection("GPU MONITORING", nil, iw))

	if snap == nil || !snap.Global.GPU.Available || len(snap.Global.GPU.Devices) == 0 {
		var lines []string
		lines = append(lines, dimStyle.Render("No NVIDIA GPU detected"))
		lines = append(lines, dimStyle.Render("Requires: nvidia-smi in PATH"))
		lines = append(lines, "")
		lines = append(lines, dimStyle.Render("Supported: NVIDIA GPUs with proprietary driver"))
		lines = append(lines, dimStyle.Render("Install: apt install nvidia-driver-XXX"))
		sb.WriteString(boxSection("STATUS", lines, iw))
		sb.WriteString("\n")
		sb.WriteString(pageFooter(""))
		return sb.String()
	}

	for _, dev := range snap.Global.GPU.Devices {
		// GPU header
		title := fmt.Sprintf("GPU %d: %s (driver %s)", dev.Index, dev.Name, dev.Driver)
		var lines []string

		// Utilization
		gpuBar := progressBar(dev.UtilGPU, 30)
		lines = append(lines, fmt.Sprintf("  GPU Util:   %s %.1f%% %s", gpuBar, dev.UtilGPU, metricVerdict(dev.UtilGPU, 70, 90)))

		memBar := progressBar(dev.UtilMem, 30)
		lines = append(lines, fmt.Sprintf("  Mem Ctrl:   %s %.1f%% %s", memBar, dev.UtilMem, metricVerdict(dev.UtilMem, 70, 90)))

		// Memory
		memPct := float64(0)
		if dev.MemTotal > 0 {
			memPct = float64(dev.MemUsed) / float64(dev.MemTotal) * 100
		}
		memBarV := progressBar(memPct, 30)
		lines = append(lines, fmt.Sprintf("  VRAM:       %s %s / %s (%.0f%%) %s",
			memBarV, fmtBytes(dev.MemUsed), fmtBytes(dev.MemTotal), memPct, metricVerdict(memPct, 80, 95)))

		// Temperature
		tempVerdict := metricVerdict(float64(dev.Temperature), 75, 85)
		lines = append(lines, fmt.Sprintf("  Temperature: %d°C %s", dev.Temperature, tempVerdict))

		// Power
		powerPct := float64(0)
		if dev.PowerLimit > 0 {
			powerPct = dev.PowerDraw / dev.PowerLimit * 100
		}
		lines = append(lines, fmt.Sprintf("  Power:       %.0fW / %.0fW (%.0f%%)", dev.PowerDraw, dev.PowerLimit, powerPct))

		// Fan
		if dev.FanSpeed >= 0 {
			lines = append(lines, fmt.Sprintf("  Fan:         %d%%", dev.FanSpeed))
		}

		sb.WriteString(boxSection(title, lines, iw))

		// Processes
		if len(dev.Processes) > 0 {
			var procLines []string
			procLines = append(procLines, dimStyle.Render(fmt.Sprintf("  %7s  %-20s  %10s", "PID", "PROCESS", "GPU MEM")))
			for _, p := range dev.Processes {
				name := p.Name
				if len(name) > 20 {
					name = name[:20]
				}
				procLines = append(procLines, fmt.Sprintf("  %7d  %-20s  %10s", p.PID, name, fmtBytes(p.MemUsed)))
			}
			sb.WriteString(boxSection("GPU PROCESSES", procLines, iw))
		}
	}

	sb.WriteString("\n")
	sb.WriteString(pageFooter(""))
	return sb.String()
}

// progressBar renders a simple text progress bar.
func progressBar(pct float64, width int) string {
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
	bar := strings.Repeat("█", filled) + strings.Repeat("░", width-filled)
	if pct >= 90 {
		return critStyle.Render(bar)
	} else if pct >= 70 {
		return warnStyle.Render(bar)
	}
	return okStyle.Render(bar)
}
