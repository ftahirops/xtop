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
	sb.WriteString(renderProbeStatusLine(pm))
	sb.WriteString("\n")

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
			utilBar := bar(d.UtilPct, 8)
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

	// === Raw diskstats ===
	var rawLines []string
	rawLines = append(rawLines, dimStyle.Render(fmt.Sprintf("%-8s %12s %12s %12s %12s %10s %10s",
		"DEVICE", "READS", "WRITES", "SECT_R", "SECT_W", "R_TIME_ms", "W_TIME_ms")))

	for _, d := range snap.Global.Disks {
		rawLines = append(rawLines, fmt.Sprintf("%-8s %12d %12d %12d %12d %10d %10d",
			d.Name, d.ReadsCompleted, d.WritesCompleted, d.SectorsRead, d.SectorsWritten, d.ReadTimeMs, d.WriteTimeMs))
	}
	sb.WriteString(boxSection("RAW DISK COUNTERS (cumulative)", rawLines, iw))

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

	// === SMART Health ===
	var smartLines []string
	if len(smartDisks) > 0 {
		smartLines = append(smartLines, dimStyle.Render(fmt.Sprintf("%-12s %-6s %5s %6s %6s %6s %8s  %s",
			"DEVICE", "HEALTH", "WEAR%", "TEMP", "REALL", "PEND", "PWR_HRS", "MODEL")))

		for _, d := range smartDisks {
			if d.ErrorString != "" {
				smartLines = append(smartLines, fmt.Sprintf("%-12s %s", d.Name, dimStyle.Render("error: "+d.ErrorString)))
				continue
			}

			health := okStyle.Render("OK    ")
			if !d.HealthOK {
				health = critStyle.Render("FAIL  ")
			}

			wear := dimStyle.Render("  n/a")
			if d.WearLevelPct >= 0 {
				wearStyle := okStyle
				if d.WearLevelPct < 20 {
					wearStyle = critStyle
				} else if d.WearLevelPct < 50 {
					wearStyle = warnStyle
				}
				wear = wearStyle.Render(fmt.Sprintf("%4d%%", d.WearLevelPct))
			}

			temp := dimStyle.Render("   n/a")
			if d.Temperature > 0 {
				tempStyle := okStyle
				if d.Temperature >= 70 {
					tempStyle = critStyle
				} else if d.Temperature >= 55 {
					tempStyle = warnStyle
				}
				temp = tempStyle.Render(fmt.Sprintf("%4dC", d.Temperature))
			}

			realloc := fmt.Sprintf("%5d", d.ReallocSectors)
			if d.ReallocSectors > 0 {
				realloc = warnStyle.Render(realloc)
			} else {
				realloc = dimStyle.Render(realloc)
			}

			pending := fmt.Sprintf("%5d", d.PendingSectors)
			if d.PendingSectors > 0 {
				pending = critStyle.Render(pending)
			} else {
				pending = dimStyle.Render(pending)
			}

			pwr := dimStyle.Render(fmt.Sprintf("%7d", d.PowerOnHours))

			mdl := d.ModelNumber
			if len(mdl) > 30 {
				mdl = mdl[:27] + "..."
			}

			smartLines = append(smartLines, fmt.Sprintf("%-12s %s %s %s %s %s %s  %s",
				d.Name, health, wear, temp, realloc, pending, pwr, dimStyle.Render(mdl)))
		}
	} else {
		smartLines = append(smartLines, dimStyle.Render("smartctl not available or no disks detected"))
	}
	sb.WriteString(boxSection("SMART DISK HEALTH", smartLines, iw))

	return sb.String()
}
