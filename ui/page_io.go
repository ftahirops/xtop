package ui

import (
	"fmt"
	"sort"
	"strings"

	"github.com/ftahirops/xtop/model"
)

func renderIOPage(snap *model.Snapshot, rates *model.RateSnapshot, result *model.AnalysisResult, smartDisks []model.SMARTDisk, pm probeQuerier, width, height int) string {
	var sb strings.Builder
	iw := pageInnerW(width)

	sb.WriteString(titleStyle.Render("IO / DISK SUBSYSTEM"))
	sb.WriteString("\n")
	sb.WriteString(renderRCAInline(result))
	sb.WriteString(renderProbeStatusLine(pm, snap))
	sb.WriteString("\n")

	// === DISK HEALTH (at top — most critical info first, bare metal only) ===
	if snap.SysInfo.Virtualization == "Bare Metal" || snap.SysInfo.Virtualization == "" {
		sb.WriteString(renderDiskHealth(smartDisks, iw))
	}

	psi := snap.Global.PSI.IO

	// === Summary ===
	var sumLines []string
	sumLines = append(sumLines, fmt.Sprintf("IO PSI some/full: %s / %s", fmtPSI(psi.Some.Avg10), fmtPSI(psi.Full.Avg10)))

	dCount := 0
	var dProcs []string
	for _, p := range snap.Processes {
		if p.State == "D" {
			dCount++
			if len(dProcs) < 5 {
				dProcs = append(dProcs, fmt.Sprintf("%s(%d)", p.Comm, p.PID))
			}
		}
	}
	if dCount > 0 {
		sumLines = append(sumLines, warnStyle.Render(fmt.Sprintf("D-state tasks: %d  [%s]", dCount, strings.Join(dProcs, ", "))))
	} else {
		sumLines = append(sumLines, "D-state tasks: 0")
	}
	sb.WriteString(boxSection("SUMMARY", sumLines, iw))

	// === Per-Device Breakdown ===
	var devLines []string
	if rates != nil && len(rates.DiskRates) > 0 {
		devLines = append(devLines, dimStyle.Render(fmt.Sprintf("%-8s %10s %10s %8s %8s %8s %7s %6s",
			"DEVICE", "READ MB/s", "WRITE MB/s", "R IOPS", "W IOPS", "AWAIT", "UTIL%", "QDEP")))

		for _, d := range rates.DiskRates {
			utilBar := styledPad(bar(d.UtilPct, 8), 8)
			row := fmt.Sprintf("%-8s %9.1f %10.1f %8.0f %8.0f %7.1fms %s %5d",
				d.Name, d.ReadMBs, d.WriteMBs, d.ReadIOPS, d.WriteIOPS, d.AvgAwaitMs, utilBar, d.QueueDepth)
			if d.UtilPct > 90 || d.AvgAwaitMs > 50 {
				devLines = append(devLines, critStyle.Render(row))
			} else if d.UtilPct > 70 || d.AvgAwaitMs > 20 {
				devLines = append(devLines, warnStyle.Render(row))
			} else {
				devLines = append(devLines, row)
			}
		}
	} else {
		devLines = append(devLines, dimStyle.Render("(need 2 samples for rates)"))
	}
	sb.WriteString(boxSection("PER-DEVICE BREAKDOWN", devLines, iw))

	// === IO type analysis ===
	var ioLines []string
	if rates != nil && len(rates.DiskRates) > 0 {
		for _, d := range rates.DiskRates {
			totalIOPS := d.ReadIOPS + d.WriteIOPS
			totalMBs := d.ReadMBs + d.WriteMBs
			readPct := float64(0)
			writePct := float64(0)
			if totalIOPS > 0 {
				readPct = d.ReadIOPS / totalIOPS * 100
				writePct = 100 - readPct
			}

			ioLines = append(ioLines, fmt.Sprintf("%s: Read %5.0f%% / Write %5.0f%%  (total: %.1f MB/s, %.0f IOPS)",
				d.Name, readPct, writePct, totalMBs, totalIOPS))

			avgSizeKB := float64(0)
			ioType := "idle"
			if totalIOPS > 0 && totalMBs > 0 {
				avgSizeKB = totalMBs * 1024 / totalIOPS
				ioType = "mixed"
				if avgSizeKB > 64 {
					ioType = "sequential (large IOs)"
				} else if avgSizeKB < 8 {
					ioType = "random (small IOs)"
				}
			}
			ioLines = append(ioLines, fmt.Sprintf("  avg IO size: %.0f KB  pattern: %s", avgSizeKB, ioType))
		}
	} else {
		ioLines = append(ioLines, dimStyle.Render("(collecting...)"))
	}
	sb.WriteString(boxSection("IO TYPE ANALYSIS", ioLines, iw))

	// === Top cgroups by IO ===
	var cgLines []string
	cgLines = append(cgLines, dimStyle.Render(fmt.Sprintf("%-28s %10s %10s", "CGROUP", "READ MB/s", "WRITE MB/s")))

	if rates != nil && len(rates.CgroupRates) > 0 {
		cgs := make([]model.CgroupRate, len(rates.CgroupRates))
		copy(cgs, rates.CgroupRates)
		sort.Slice(cgs, func(i, j int) bool {
			return (cgs[i].IORateMBs + cgs[i].IOWRateMBs) > (cgs[j].IORateMBs + cgs[j].IOWRateMBs)
		})
		for i, cg := range cgs {
			total := cg.IORateMBs + cg.IOWRateMBs
			if i >= 10 || total < 0.001 {
				break
			}
			name := cg.Name
			if len(name) > 28 {
				name = name[:25] + "..."
			}
			cgLines = append(cgLines, fmt.Sprintf("%-28s %9.1f %10.1f", name, cg.IORateMBs, cg.IOWRateMBs))
		}
	} else {
		cgLines = append(cgLines, dimStyle.Render("(collecting...)"))
	}
	sb.WriteString(boxSection("TOP CGROUPS BY IO", cgLines, iw))

	// === Top PIDs by IO ===
	var procLines []string
	procLines = append(procLines, dimStyle.Render(fmt.Sprintf("%7s %-16s %5s %10s %10s", "PID", "COMMAND", "STATE", "READ MB/s", "WRITE MB/s")))

	if rates != nil && len(rates.ProcessRates) > 0 {
		procs := make([]model.ProcessRate, len(rates.ProcessRates))
		copy(procs, rates.ProcessRates)
		sort.Slice(procs, func(i, j int) bool {
			return (procs[i].ReadMBs + procs[i].WriteMBs) > (procs[j].ReadMBs + procs[j].WriteMBs)
		})
		for i, p := range procs {
			total := p.ReadMBs + p.WriteMBs
			if i >= 15 || total < 0.001 {
				break
			}
			comm := p.Comm
			if len(comm) > 16 {
				comm = comm[:13] + "..."
			}
			row := fmt.Sprintf("%7d %-16s %5s %9.2f %10.2f",
				p.PID, comm, p.State, p.ReadMBs, p.WriteMBs)
			if p.State == "D" {
				procLines = append(procLines, warnStyle.Render(row))
			} else {
				procLines = append(procLines, row)
			}
		}
	} else {
		procLines = append(procLines, dimStyle.Render("(collecting...)"))
	}
	sb.WriteString(boxSection("TOP PROCESSES BY IO", procLines, iw))

	sb.WriteString(pageFooter(""))

	return sb.String()
}

// renderDiskHealth renders the DISK HEALTH section with life gauge and failure prediction.
func renderDiskHealth(disks []model.SMARTDisk, iw int) string {
	var lines []string

	if len(disks) == 0 {
		lines = append(lines, dimStyle.Render("No block devices detected"))
		return boxSection("DISK HEALTH", lines, iw)
	}

	// Header
	lines = append(lines, dimStyle.Render(fmt.Sprintf(
		"%-10s %-5s %-8s %-12s %5s %8s %10s  %s",
		"DEVICE", "TYPE", "VERDICT", "LIFE REMAIN", "TEMP", "WRITTEN", "EST. LEFT", "MODEL")))

	for _, d := range disks {
		if d.DiskType == model.DiskTypeVirtual {
			mdl := d.ModelNumber
			if d.ModelFamily != "" {
				mdl = d.ModelFamily + " " + mdl
			}
			if mdl == "" {
				mdl = "virtual disk"
			}
			lines = append(lines, fmt.Sprintf("%-10s %s %s %s",
				d.Name, styledPad(dimStyle.Render("VIRT"), 5),
				styledPad(dimStyle.Render("—"), 8),
				dimStyle.Render("no SMART — "+mdl)))
			continue
		}
		if d.ErrorString != "" {
			lines = append(lines, fmt.Sprintf("%-10s %s", d.Name, dimStyle.Render("error: "+d.ErrorString)))
			continue
		}

		// Type label
		typeStr := styledPad(dimStyle.Render(string(d.DiskType)), 5)

		// Health verdict with color
		verdict := d.HealthVerdict()
		var verdictStyled string
		switch verdict {
		case "OK":
			verdictStyled = styledPad(okStyle.Render("OK"), 8)
		case "WARN":
			verdictStyled = styledPad(warnStyle.Render("WARN"), 8)
		case "WORN":
			verdictStyled = styledPad(warnStyle.Render("WORN"), 8)
		case "CRITICAL":
			verdictStyled = styledPad(critStyle.Render("CRIT"), 8)
		case "FAILING":
			verdictStyled = styledPad(critStyle.Render("FAILING"), 8)
		case "FAIL":
			verdictStyled = styledPad(critStyle.Render("FAIL"), 8)
		default:
			verdictStyled = styledPad(dimStyle.Render(verdict), 8)
		}

		// Life remaining bar + percentage
		lifeBar := renderLifeGauge(d)

		// Temperature
		temp := dimStyle.Render("  n/a")
		if d.Temperature > 0 {
			ts := okStyle
			if d.Temperature >= 70 {
				ts = critStyle
			} else if d.Temperature >= 55 {
				ts = warnStyle
			}
			temp = ts.Render(fmt.Sprintf("%3dC", d.Temperature))
		}

		// Total written
		written := dimStyle.Render("     n/a")
		if d.WriteTBW > 0 {
			if d.WriteTBW >= 1000 {
				written = fmt.Sprintf("%6.1fPB", d.WriteTBW/1024)
			} else if d.WriteTBW >= 1 {
				written = fmt.Sprintf("%6.1fTB", d.WriteTBW)
			} else {
				written = fmt.Sprintf("%5.0fGB", d.WriteTBW*1024)
			}
		}

		// Estimated life remaining
		estLife := renderEstLife(d)

		// Model (truncated)
		mdl := d.ModelNumber
		if len(mdl) > 24 {
			mdl = mdl[:21] + "..."
		}

		lines = append(lines, fmt.Sprintf("%-10s %s %s %s %s %8s %10s  %s",
			d.Name, typeStr, verdictStyled, lifeBar, styledPad(temp, 5), written, estLife, dimStyle.Render(mdl)))

		// Extra detail lines for critical/warning conditions
		details := renderDiskDetails(d)
		for _, detail := range details {
			lines = append(lines, "  "+detail)
		}
	}

	return boxSection("DISK HEALTH", lines, iw)
}

// renderLifeGauge renders a visual life gauge bar with percentage.
func renderLifeGauge(d model.SMARTDisk) string {
	if d.WearLevelPct < 0 {
		// HDD or unknown — show realloc/pending instead
		if d.DiskType == model.DiskTypeSATAHDD {
			if d.ReallocSectors > 0 || d.PendingSectors > 0 {
				return styledPad(warnStyle.Render(fmt.Sprintf("R:%d P:%d", d.ReallocSectors, d.PendingSectors)), 12)
			}
			return styledPad(dimStyle.Render("  no wear  "), 12)
		}
		return styledPad(dimStyle.Render("    n/a    "), 12)
	}

	pct := d.WearLevelPct
	barWidth := 8
	filled := pct * barWidth / 100
	if filled > barWidth {
		filled = barWidth
	}
	if filled < 0 {
		filled = 0
	}

	barStr := strings.Repeat("█", filled) + strings.Repeat("░", barWidth-filled)
	pctStr := fmt.Sprintf("%3d%%", pct)

	combined := barStr + " " + pctStr
	switch {
	case pct <= 10:
		return styledPad(critStyle.Render(combined), 12)
	case pct <= 30:
		return styledPad(warnStyle.Render(combined), 12)
	default:
		return styledPad(okStyle.Render(combined), 12)
	}
}

// renderEstLife renders the estimated remaining life.
func renderEstLife(d model.SMARTDisk) string {
	if d.EstLifeDays < 0 {
		if d.DiskType == model.DiskTypeSATAHDD {
			// HDD: show power-on age instead
			if d.PowerOnHours > 0 {
				years := float64(d.PowerOnHours) / (365.25 * 24)
				if years >= 1 {
					return fmt.Sprintf("age:%.1fy", years)
				}
				return fmt.Sprintf("age:%dd", d.PowerOnHours/24)
			}
		}
		return dimStyle.Render("   n/a")
	}

	if d.EstLifeDays == 0 {
		return critStyle.Render("  EOL!")
	}

	years := float64(d.EstLifeDays) / 365.25
	if years >= 1 {
		s := fmt.Sprintf("~%.1fy", years)
		if years < 1.5 {
			return warnStyle.Render(s)
		}
		return okStyle.Render(s)
	}

	months := float64(d.EstLifeDays) / 30.4
	if months >= 1 {
		s := fmt.Sprintf("~%.0fmo", months)
		if months < 6 {
			return critStyle.Render(s)
		}
		return warnStyle.Render(s)
	}

	return critStyle.Render(fmt.Sprintf("~%dd!", d.EstLifeDays))
}

// renderDiskDetails returns extra detail lines for disks with notable conditions.
func renderDiskDetails(d model.SMARTDisk) []string {
	var details []string

	// NVMe critical warning flags
	if d.CriticalWarning&model.NVMeWarnReliability != 0 {
		details = append(details, critStyle.Render("!! NVMe: reliability degraded — media/internal errors detected"))
	}
	if d.CriticalWarning&model.NVMeWarnReadOnly != 0 {
		details = append(details, critStyle.Render("!! NVMe: drive in READ-ONLY mode — endurance exhausted"))
	}
	if d.CriticalWarning&model.NVMeWarnSpare != 0 {
		details = append(details, critStyle.Render(fmt.Sprintf("!! NVMe: available spare %d%% below threshold %d%%",
			d.AvailableSpare, d.AvailableSpareThreshold)))
	}
	if d.CriticalWarning&model.NVMeWarnTemperature != 0 {
		details = append(details, warnStyle.Render("!! NVMe: temperature above critical composite threshold"))
	}

	// Media errors
	if d.MediaErrors > 0 {
		details = append(details, warnStyle.Render(fmt.Sprintf("   media errors: %d (uncorrectable data integrity errors)", d.MediaErrors)))
	}

	// Unsafe shutdowns
	if d.UnsafeShutdowns > 100 {
		details = append(details, dimStyle.Render(fmt.Sprintf("   unsafe shutdowns: %d", d.UnsafeShutdowns)))
	}

	// Available spare
	if d.AvailableSpare >= 0 && d.AvailableSpare < 50 && d.CriticalWarning&model.NVMeWarnSpare == 0 {
		details = append(details, warnStyle.Render(fmt.Sprintf("   available spare: %d%% (threshold: %d%%)",
			d.AvailableSpare, d.AvailableSpareThreshold)))
	}

	// Reallocated/pending sectors for SATA
	if d.ReallocSectors > 0 {
		style := warnStyle
		if d.ReallocSectors > 100 {
			style = critStyle
		}
		details = append(details, style.Render(fmt.Sprintf("   reallocated sectors: %d", d.ReallocSectors)))
	}
	if d.PendingSectors > 0 {
		details = append(details, critStyle.Render(fmt.Sprintf("   pending sectors: %d (awaiting remap)", d.PendingSectors)))
	}

	// Write rate info
	if d.WriteRateTBPerYear > 0 {
		details = append(details, dimStyle.Render(fmt.Sprintf("   write rate: %.1f TB/year  power-on: %s",
			d.WriteRateTBPerYear, fmtPowerOnHours(d.PowerOnHours))))
	}

	return details
}

func fmtPowerOnHours(hours int) string {
	if hours <= 0 {
		return "n/a"
	}
	years := float64(hours) / (365.25 * 24)
	if years >= 1 {
		return fmt.Sprintf("%.1f years", years)
	}
	days := hours / 24
	if days > 0 {
		return fmt.Sprintf("%d days", days)
	}
	return fmt.Sprintf("%d hours", hours)
}
