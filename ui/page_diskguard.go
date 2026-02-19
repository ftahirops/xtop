package ui

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/ftahirops/xtop/model"
)

func renderDiskGuardPage(snap *model.Snapshot, rates *model.RateSnapshot, result *model.AnalysisResult,
	pm probeQuerier, diskGuardMode string, actionMsg string, frozen map[int]frozenProc, width, height int) string {

	var sb strings.Builder
	iw := pageInnerW(width)

	// Title + DiskGuard state badge
	sb.WriteString(titleStyle.Render("DISKGUARD"))
	sb.WriteString(" ")

	worstState := "OK"
	if result != nil && result.DiskGuardWorst != "" {
		worstState = result.DiskGuardWorst
	}
	switch worstState {
	case "CRIT":
		sb.WriteString(critStyle.Render("[CRIT]"))
	case "WARN":
		sb.WriteString(warnStyle.Render("[WARN]"))
	default:
		sb.WriteString(okStyle.Render("[OK]"))
	}
	sb.WriteString("  ")
	sb.WriteString(dimStyle.Render(fmt.Sprintf("Mode: %s", diskGuardMode)))
	sb.WriteString("\n")

	// RCA inline + probe status
	sb.WriteString(renderRCAInline(result))
	sb.WriteString(renderProbeStatusLine(pm))

	// ALERT BANNER — shown when any mount is growing toward full
	if result != nil {
		for _, mr := range result.DiskGuardMounts {
			if mr.ETASeconds > 0 && mr.GrowthBytesPerSec > 1024 {
				fullAt := time.Now().Add(time.Duration(mr.ETASeconds) * time.Second)
				growthMBs := mr.GrowthBytesPerSec / (1024 * 1024)

				// Trend: increasing / stable / decreasing
				trend := "stable"
				if mr.PrevGrowthBPS > 0 {
					delta := mr.GrowthBytesPerSec - mr.PrevGrowthBPS
					pct := delta / mr.PrevGrowthBPS * 100
					if pct > 5 {
						trend = "increasing"
					} else if pct < -5 {
						trend = "decreasing"
					}
				}

				// Since when
				sinceStr := ""
				if !mr.GrowthStarted.IsZero() {
					dur := time.Since(mr.GrowthStarted)
					sinceStr = fmt.Sprintf(" since %s (%s ago)",
						mr.GrowthStarted.Format("15:04:05"), fmtDuration(int(dur.Seconds())))
				}

				alertStyle := warnStyle
				if mr.State == "CRIT" {
					alertStyle = critStyle
				}

				sb.WriteString("\n")
				sb.WriteString(alertStyle.Render(fmt.Sprintf(
					"  >> DISK %s FULL AT %s — %.1f MB/s growth (%s)%s",
					mr.MountPoint, fullAt.Format("15:04"), growthMBs, trend, sinceStr)))
				sb.WriteString("\n")
			}
		}
	}

	sb.WriteString("\n")

	// Section 1: FILESYSTEM MOUNTS
	var mountLines []string
	hdr := fmt.Sprintf("%s %s %s %s %s %s %s %s %s",
		styledPad(dimStyle.Render("STATE"), 6),
		styledPad(dimStyle.Render("MOUNT"), 20),
		styledPad(dimStyle.Render("FSTYPE"), 8),
		styledPad(dimStyle.Render("USED%"), 18),
		styledPad(dimStyle.Render("FREE"), 10),
		styledPad(dimStyle.Render("INODE%"), 7),
		styledPad(dimStyle.Render("GROWTH/s"), 10),
		styledPad(dimStyle.Render("FULL AT"), 10),
		dimStyle.Render("DEVICE"))
	mountLines = append(mountLines, hdr)

	if result != nil && len(result.DiskGuardMounts) > 0 {
		// Sort: CRIT first, then WARN, then OK
		mounts := make([]model.MountRate, len(result.DiskGuardMounts))
		copy(mounts, result.DiskGuardMounts)
		sort.Slice(mounts, func(i, j int) bool {
			return stateOrder(mounts[i].State) < stateOrder(mounts[j].State)
		})

		for _, mr := range mounts {
			stateStr := okStyle.Render(" OK  ")
			if mr.State == "CRIT" {
				stateStr = critStyle.Render("CRIT ")
			} else if mr.State == "WARN" {
				stateStr = warnStyle.Render("WARN ")
			}

			mountStr := truncate(mr.MountPoint, 19)

			// Used% bar
			usedBar := bar(mr.UsedPct, 10)
			usedPctStr := meterColor(mr.UsedPct).Render(fmt.Sprintf("%.0f%%", mr.UsedPct))
			usedCol := usedBar + " " + usedPctStr

			freeStr := fmtBytes(mr.FreeBytes)

			inodeStr := fmt.Sprintf("%.0f%%", mr.InodeUsedPct)
			if mr.InodeUsedPct > 90 {
				inodeStr = critStyle.Render(inodeStr)
			} else if mr.InodeUsedPct > 70 {
				inodeStr = warnStyle.Render(inodeStr)
			} else {
				inodeStr = dimStyle.Render(inodeStr)
			}

			growthStr := dimStyle.Render("—")
			if mr.GrowthBytesPerSec > 1024 {
				growthStr = fmtRate(mr.GrowthBytesPerSec / (1024 * 1024))
			}

			// FULL AT — show actual clock time when disk will be full
			fullAtStr := dimStyle.Render("—")
			if mr.ETASeconds > 0 && mr.GrowthBytesPerSec > 1024 {
				fullAt := time.Now().Add(time.Duration(mr.ETASeconds) * time.Second)
				if mr.ETASeconds < 1800 {
					fullAtStr = critStyle.Render(fullAt.Format("15:04!"))
				} else if mr.ETASeconds < 7200 {
					fullAtStr = warnStyle.Render(fullAt.Format("15:04"))
				} else if mr.ETASeconds < 86400 {
					fullAtStr = dimStyle.Render(fullAt.Format("15:04"))
				} else {
					fullAtStr = dimStyle.Render(fullAt.Format("Jan 2"))
				}
			}

			devStr := dimStyle.Render(truncate(mr.Device, 20))

			line := fmt.Sprintf("%s %s %s %s %s %s %s %s %s",
				styledPad(stateStr, 6),
				styledPad(mountStr, 20),
				styledPad(dimStyle.Render(mr.FSType), 8),
				styledPad(usedCol, 18),
				styledPad(freeStr, 10),
				styledPad(inodeStr, 7),
				styledPad(growthStr, 10),
				styledPad(fullAtStr, 10),
				devStr)
			mountLines = append(mountLines, line)
		}
	} else {
		mountLines = append(mountLines, dimStyle.Render("  no filesystem data"))
	}
	sb.WriteString(boxSection("FILESYSTEM MOUNTS", mountLines, iw))

	// Section 2: TOP WRITERS (from ProcessRate.WriteMBs)
	var writerLines []string
	writerHdr := fmt.Sprintf("%s %s %s %s %s %s",
		styledPad(dimStyle.Render("PID"), 8),
		styledPad(dimStyle.Render("COMMAND"), 16),
		styledPad(dimStyle.Render("WRITE MB/s"), 12),
		styledPad(dimStyle.Render("READ MB/s"), 12),
		styledPad(dimStyle.Render("STATUS"), 10),
		dimStyle.Render("TARGET FILE"))
	writerLines = append(writerLines, writerHdr)

	// Collect top writers for use in RECOMMENDATIONS
	var topWriters []model.ProcessRate

	if rates != nil && len(rates.ProcessRates) > 0 {
		// Sort by write rate descending
		procs := make([]model.ProcessRate, len(rates.ProcessRates))
		copy(procs, rates.ProcessRates)
		sort.Slice(procs, func(i, j int) bool {
			return procs[i].WriteMBs > procs[j].WriteMBs
		})

		shown := 0
		for _, p := range procs {
			if shown >= 15 {
				break
			}
			if p.WriteMBs < 0.001 && p.ReadMBs < 0.001 {
				// Still show if frozen
				if _, isFrozen := frozen[p.PID]; !isFrozen {
					continue
				}
			}
			targetStr := dimStyle.Render("—")
			if p.WritePath != "" {
				targetStr = truncate(p.WritePath, 50)
			} else if p.ServiceName != "" {
				targetStr = dimStyle.Render(truncate(p.ServiceName, 50))
			}
			statusStr := dimStyle.Render("active")
			if _, isFrozen := frozen[p.PID]; isFrozen {
				statusStr = critStyle.Render("FROZEN")
			}
			line := fmt.Sprintf("%s %s %s %s %s %s",
				styledPad(fmt.Sprintf("%d", p.PID), 8),
				styledPad(truncate(p.Comm, 15), 16),
				styledPad(fmt.Sprintf("%.2f", p.WriteMBs), 12),
				styledPad(fmt.Sprintf("%.2f", p.ReadMBs), 12),
				styledPad(statusStr, 10),
				targetStr)
			writerLines = append(writerLines, line)
			if p.WriteMBs > 0.1 {
				topWriters = append(topWriters, p)
			}
			shown++
		}
		if shown == 0 {
			writerLines = append(writerLines, dimStyle.Render("  no active writers"))
		}
	} else {
		writerLines = append(writerLines, dimStyle.Render("  collecting..."))
	}

	// Also show frozen processes that may no longer be in process rates
	for pid, fp := range frozen {
		found := false
		if rates != nil {
			for _, p := range rates.ProcessRates {
				if p.PID == pid {
					found = true
					break
				}
			}
		}
		if !found {
			dur := time.Since(fp.FrozenAt)
			targetStr := dimStyle.Render("—")
			if fp.WritePath != "" {
				targetStr = truncate(fp.WritePath, 50)
			}
			line := fmt.Sprintf("%s %s %s %s %s %s",
				styledPad(fmt.Sprintf("%d", pid), 8),
				styledPad(truncate(fp.Comm, 15), 16),
				styledPad("0.00", 12),
				styledPad("0.00", 12),
				styledPad(critStyle.Render("FROZEN"), 10),
				targetStr+" "+dimStyle.Render(fmt.Sprintf("(%s)", fmtDuration(int(dur.Seconds())))))
			writerLines = append(writerLines, line)
		}
	}

	sb.WriteString(boxSection("TOP WRITERS", writerLines, iw))

	// Section 3: BIGGEST FILES
	var bigLines []string
	bigHdr := fmt.Sprintf("%s %s %s",
		styledPad(dimStyle.Render("SIZE"), 10),
		styledPad(dimStyle.Render("MODIFIED"), 20),
		dimStyle.Render("FILE"))
	bigLines = append(bigLines, bigHdr)

	if snap != nil && len(snap.Global.BigFiles) > 0 {
		shown := 0
		for _, bf := range snap.Global.BigFiles {
			if shown >= 6 {
				break
			}
			sizeStr := fmtBytes(bf.SizeBytes)
			if bf.SizeBytes > 1024*1024*1024 {
				sizeStr = critStyle.Render(sizeStr)
			} else if bf.SizeBytes > 100*1024*1024 {
				sizeStr = warnStyle.Render(sizeStr)
			}
			modStr := dimStyle.Render(time.Unix(bf.ModTime, 0).Format("Jan 02 15:04"))
			line := fmt.Sprintf("%s %s %s",
				styledPad(sizeStr, 10),
				styledPad(modStr, 20),
				truncate(bf.Path, 80))
			bigLines = append(bigLines, line)
			shown++
		}
	} else {
		bigLines = append(bigLines, dimStyle.Render("  no files > 50MB found"))
	}
	sb.WriteString(boxSection("BIGGEST FILES", bigLines, iw))

	// Section 4: DELETED-BUT-OPEN FILES
	var delLines []string
	delHdr := fmt.Sprintf("%s %s %s %s",
		styledPad(dimStyle.Render("PID"), 8),
		styledPad(dimStyle.Render("COMMAND"), 16),
		styledPad(dimStyle.Render("SIZE"), 10),
		dimStyle.Render("PATH"))
	delLines = append(delLines, delHdr)

	if snap != nil && len(snap.Global.DeletedOpen) > 0 {
		for _, df := range snap.Global.DeletedOpen {
			sizeStr := fmtBytes(df.SizeBytes)
			if df.SizeBytes > 100*1024*1024 {
				sizeStr = critStyle.Render(sizeStr)
			} else if df.SizeBytes > 10*1024*1024 {
				sizeStr = warnStyle.Render(sizeStr)
			}
			pathStr := truncate(df.Path, 50)
			line := fmt.Sprintf("%s %s %s %s",
				styledPad(fmt.Sprintf("%d", df.PID), 8),
				styledPad(truncate(df.Comm, 15), 16),
				styledPad(sizeStr, 10),
				dimStyle.Render(pathStr))
			delLines = append(delLines, line)
		}
	} else {
		delLines = append(delLines, dimStyle.Render("  none detected"))
	}
	sb.WriteString(boxSection("DELETED-BUT-OPEN FILES", delLines, iw))

	// Section 4: RECOMMENDATIONS
	var recLines []string
	if result != nil && worstState != "OK" {
		idx := 1
		for _, mr := range result.DiskGuardMounts {
			if mr.State == "CRIT" {
				recLines = append(recLines, orangeStyle.Render(fmt.Sprintf("%d.", idx))+" "+
					valueStyle.Render(fmt.Sprintf("URGENT: %s is %.0f%% full — free space immediately", mr.MountPoint, mr.UsedPct)))
				idx++
			}
		}
		// Show top writers with their target files
		for _, tw := range topWriters {
			path := tw.WritePath
			if path == "" {
				path = "unknown target"
			}
			recLines = append(recLines, orangeStyle.Render(fmt.Sprintf("%d.", idx))+" "+
				valueStyle.Render(fmt.Sprintf("PID %d (%s) writing %.1f MB/s -> %s", tw.PID, tw.Comm, tw.WriteMBs, path)))
			idx++
		}
		if len(snap.Global.DeletedOpen) > 0 {
			var totalDel uint64
			for _, df := range snap.Global.DeletedOpen {
				totalDel += df.SizeBytes
			}
			if totalDel > 0 {
				recLines = append(recLines, orangeStyle.Render(fmt.Sprintf("%d.", idx))+" "+
					valueStyle.Render(fmt.Sprintf("Restart processes holding %s in deleted files to reclaim space", fmtBytes(totalDel))))
				idx++
			}
		}
	} else if len(topWriters) > 0 {
		idx := 1
		for _, tw := range topWriters {
			path := tw.WritePath
			if path == "" {
				path = "unknown target"
			}
			recLines = append(recLines, dimStyle.Render(fmt.Sprintf("%d.", idx))+" "+
				valueStyle.Render(fmt.Sprintf("PID %d (%s) writing %.1f MB/s -> %s", tw.PID, tw.Comm, tw.WriteMBs, path)))
			idx++
		}
	} else {
		recLines = append(recLines, okStyle.Render("All filesystems healthy — no heavy writers"))
	}
	sb.WriteString(boxSection("RECOMMENDATIONS", recLines, iw))

	// Action message
	if actionMsg != "" {
		sb.WriteString("\n")
		sb.WriteString("  " + orangeStyle.Render(actionMsg))
	}

	// Footer
	sb.WriteString("\n")
	switch diskGuardMode {
	case "Contain":
		extra := ""
		if len(frozen) > 0 {
			extra = fmt.Sprintf("  r: resume %d frozen", len(frozen))
		}
		sb.WriteString(warnStyle.Render("  CONTAIN MODE") +
			dimStyle.Render("  f: freeze top writer"+extra+"  m: cycle mode  b: back"))
	case "Action":
		extra := ""
		if len(frozen) > 0 {
			extra = fmt.Sprintf("  r: resume %d frozen", len(frozen))
		}
		sb.WriteString(critStyle.Render("  ACTION MODE") +
			dimStyle.Render("  x: kill  f: freeze"+extra+"  m: cycle mode  b: back"))
	default:
		sb.WriteString(dimStyle.Render("  m: cycle mode (Monitor/Contain/Action)  j/k: scroll  b: back"))
	}

	return sb.String()
}

func stateOrder(s string) int {
	switch s {
	case "CRIT":
		return 0
	case "WARN":
		return 1
	default:
		return 2
	}
}
