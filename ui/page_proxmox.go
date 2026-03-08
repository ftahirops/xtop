package ui

import (
	"fmt"
	"sort"
	"strings"

	"github.com/ftahirops/xtop/model"
)

func renderProxmoxPage(snap *model.Snapshot, rates *model.RateSnapshot, result *model.AnalysisResult,
	smartDisks []model.SMARTDisk, pm probeQuerier, width, height int) string {

	var sb strings.Builder
	iw := pageInnerW(width)

	pve := snap.Global.Proxmox
	if pve == nil || !pve.IsProxmoxHost {
		sb.WriteString(titleStyle.Render("PROXMOX"))
		sb.WriteString("\n")
		sb.WriteString(dimStyle.Render("  Not a Proxmox host"))
		return sb.String()
	}

	// Title line
	runCount := 0
	stopCount := 0
	totalVCPU := 0
	totalAllocMB := 0
	for _, vm := range pve.VMs {
		if vm.Status == "running" {
			runCount++
		} else {
			stopCount++
		}
		totalVCPU += vm.CoresAlloc
		totalAllocMB += vm.MemAllocMB
	}
	sb.WriteString(titleStyle.Render("PROXMOX HOST"))
	sb.WriteString("  ")
	sb.WriteString(valueStyle.Render(pve.NodeName))
	if pve.PVEVersion != "" && !strings.Contains(pve.PVEVersion, "{") {
		sb.WriteString("  ")
		sb.WriteString(dimStyle.Render("PVE " + truncate(pve.PVEVersion, 20)))
	}
	sb.WriteString("  ")
	sb.WriteString(okStyle.Render(fmt.Sprintf("%d VM running", runCount)))
	if stopCount > 0 {
		sb.WriteString("  ")
		sb.WriteString(dimStyle.Render(fmt.Sprintf("%d stopped", stopCount)))
	}
	sb.WriteString("\n")

	// RCA + probe
	sb.WriteString(renderRCAInline(result))
	sb.WriteString(renderProbeStatusLine(pm, snap))
	sb.WriteString("\n")

	// === HOST OVERVIEW ===
	sb.WriteString(renderPveHostOverview(snap, rates, iw))

	// === HOST NETWORK ===
	sb.WriteString(renderPveHostNetwork(snap, rates, iw))

	// === HOST DISK IO ===
	sb.WriteString(renderPveHostDiskIO(snap, rates, smartDisks, iw))

	// === VM STATUS TABLE ===
	sb.WriteString(renderPveVMTable(pve, iw))

	// === Per-VM details ===
	for _, vm := range pve.VMs {
		if vm.Status != "running" {
			continue
		}
		sb.WriteString(renderPveVMDetail(vm, iw))
	}

	// === STORAGE POOLS ===
	if len(pve.Storage) > 0 {
		sb.WriteString(renderPveStorage(pve.Storage, iw))
	}

	sb.WriteString(pageFooter("j/k:scroll  Z:proxmox"))

	return sb.String()
}

// renderPveHostOverview shows CPU, memory, load, PSI at host level
func renderPveHostOverview(snap *model.Snapshot, rates *model.RateSnapshot, iw int) string {
	var lines []string
	mem := snap.Global.Memory
	cpu := snap.Global.CPU

	// System info line
	sysLine := ""
	if snap.SysInfo != nil {
		sysLine = fmt.Sprintf("Kernel: %s", dimStyle.Render(snap.SysInfo.Hostname))
		if len(snap.SysInfo.IPs) > 0 {
			sysLine += "  IPs: " + dimStyle.Render(strings.Join(snap.SysInfo.IPs, ", "))
		}
	}
	if sysLine != "" {
		lines = append(lines, sysLine)
	}

	// CPU overview
	cpuLine := dimStyle.Render("CPU:   ")
	if rates != nil {
		busyPct := rates.CPUBusyPct
		cpuVal := fmt.Sprintf("%.1f%% busy", busyPct)
		if busyPct > 80 {
			cpuLine += critStyle.Render(cpuVal)
		} else if busyPct > 50 {
			cpuLine += warnStyle.Render(cpuVal)
		} else {
			cpuLine += valueStyle.Render(cpuVal)
		}
		cpuLine += "  " + bar(busyPct, 12)
		cpuLine += dimStyle.Render(fmt.Sprintf("  usr:%.0f%% sys:%.0f%% iow:%.0f%%",
			rates.CPUUserPct, rates.CPUSystemPct, rates.CPUIOWaitPct))
		// Steal — prominent if > 0
		if rates.CPUStealPct > 0 {
			stealStr := fmt.Sprintf("%.1f%%", rates.CPUStealPct)
			cpuLine += "  "
			if rates.CPUStealPct > 5 {
				cpuLine += critStyle.Render("STEAL:" + stealStr)
			} else if rates.CPUStealPct > 1 {
				cpuLine += warnStyle.Render("steal:" + stealStr)
			} else {
				cpuLine += dimStyle.Render("steal:" + stealStr)
			}
		}
	}
	cpuLine += dimStyle.Render(fmt.Sprintf("  %d cores", cpu.NumCPUs))
	lines = append(lines, cpuLine)

	// Load average
	loadLine := dimStyle.Render("Load:  ")
	loadLine += valueStyle.Render(fmt.Sprintf("%.2f %.2f %.2f", cpu.LoadAvg.Load1, cpu.LoadAvg.Load5, cpu.LoadAvg.Load15))
	loadLine += dimStyle.Render(fmt.Sprintf("  (%d running / %d total)", cpu.LoadAvg.Running, cpu.LoadAvg.Total))
	lines = append(lines, loadLine)

	// Memory overview
	totalGB := float64(mem.Total) / (1024 * 1024)
	availGB := float64(mem.Available) / (1024 * 1024)
	usedGB := totalGB - availGB
	usedPct := 0.0
	if totalGB > 0 {
		usedPct = usedGB / totalGB * 100
	}
	memLine := dimStyle.Render("RAM:  ")
	memVal := fmt.Sprintf("%.1fG / %.1fG (%.0f%%)", usedGB, totalGB, usedPct)
	if usedPct > 90 {
		memLine += critStyle.Render(memVal)
	} else if usedPct > 75 {
		memLine += warnStyle.Render(memVal)
	} else {
		memLine += valueStyle.Render(memVal)
	}
	memLine += "  " + bar(usedPct, 15)
	// Buffers/cached
	bufCacheGB := float64(mem.Buffers+mem.Cached) / (1024 * 1024)
	memLine += dimStyle.Render(fmt.Sprintf("  buf/cache: %.1fG", bufCacheGB))
	lines = append(lines, memLine)

	// Swap
	if mem.SwapTotal > 0 {
		swapUsedGB := float64(mem.SwapUsed) / (1024 * 1024)
		swapTotalGB := float64(mem.SwapTotal) / (1024 * 1024)
		swapPct := 0.0
		if swapTotalGB > 0 {
			swapPct = swapUsedGB / swapTotalGB * 100
		}
		swapLine := dimStyle.Render("Swap: ")
		swapVal := fmt.Sprintf("%.1fG / %.1fG (%.0f%%)", swapUsedGB, swapTotalGB, swapPct)
		if swapPct > 50 {
			swapLine += warnStyle.Render(swapVal)
		} else {
			swapLine += valueStyle.Render(swapVal)
		}
		lines = append(lines, swapLine)
	}

	// PSI pressure
	psi := snap.Global.PSI
	if psi.CPU.Some.Avg10 > 0 || psi.Memory.Some.Avg10 > 0 || psi.IO.Some.Avg10 > 0 {
		psiLine := dimStyle.Render("PSI:  ")
		psiLine += dimStyle.Render("cpu=") + psiStr(psi.CPU.Some.Avg10)
		psiLine += dimStyle.Render("  mem=") + psiStr(psi.Memory.Some.Avg10)
		psiLine += dimStyle.Render("  io=") + psiStr(psi.IO.Some.Avg10)
		lines = append(lines, psiLine)
	}

	// VM resource allocation summary
	totalVCPU := 0
	totalAllocMB := 0
	totalBalloonMinMB := 0
	totalDiskGB := 0
	balloonVMs := 0
	for _, vm := range snap.Global.Proxmox.VMs {
		totalVCPU += vm.CoresAlloc * maxInt(vm.SocketsAlloc, 1)
		totalAllocMB += vm.MemAllocMB
		if vm.BalloonOn {
			balloonVMs++
			totalBalloonMinMB += vm.BalloonMinMB
		}
		for _, d := range vm.DiskConfigs {
			if d.SizeGB > 0 && !strings.Contains(d.Path, "iso") && d.Path != "none" {
				totalDiskGB += d.SizeGB
			}
		}
	}

	// vCPU overcommit line
	vcpuLine := dimStyle.Render("vCPU:  ")
	vcpuLine += valueStyle.Render(fmt.Sprintf("%d allocated", totalVCPU))
	vcpuLine += dimStyle.Render(fmt.Sprintf(" / %d physical", cpu.NumCPUs))
	if cpu.NumCPUs > 0 {
		ratio := float64(totalVCPU) / float64(cpu.NumCPUs)
		ratioStr := fmt.Sprintf("%.1f:1", ratio)
		vcpuLine += "  "
		if ratio > 4 {
			vcpuLine += critStyle.Render("overcommit " + ratioStr)
		} else if ratio > 2 {
			vcpuLine += warnStyle.Render("overcommit " + ratioStr)
		} else if ratio > 1 {
			vcpuLine += valueStyle.Render("overcommit " + ratioStr)
		} else {
			vcpuLine += okStyle.Render("no overcommit " + ratioStr)
		}
	}
	lines = append(lines, vcpuLine)

	// Memory allocation line
	memAllocLine := dimStyle.Render("Alloc: ")
	memAllocLine += valueStyle.Render(fmtMB(totalAllocMB))
	memAllocLine += dimStyle.Render(fmt.Sprintf(" / %.1fG physical", totalGB))
	if totalGB > 0 {
		memCommitPct := float64(totalAllocMB) / (totalGB * 1024) * 100
		commitStr := fmt.Sprintf("(%.0f%%)", memCommitPct)
		memAllocLine += " "
		if memCommitPct > 100 {
			memAllocLine += critStyle.Render("overcommit " + commitStr)
		} else if memCommitPct > 85 {
			memAllocLine += warnStyle.Render(commitStr)
		} else {
			memAllocLine += valueStyle.Render(commitStr)
		}
	}
	if totalDiskGB > 0 {
		memAllocLine += "  " + valueStyle.Render(fmt.Sprintf("%dG disk", totalDiskGB))
	}
	lines = append(lines, memAllocLine)

	// Balloon status
	if balloonVMs > 0 {
		balloonLine := dimStyle.Render("Balloon: ")
		balloonLine += valueStyle.Render(fmt.Sprintf("%d/%d VMs", balloonVMs, len(snap.Global.Proxmox.VMs)))
		balloonLine += dimStyle.Render("  min: ") + valueStyle.Render(fmtMB(totalBalloonMinMB))
		balloonLine += dimStyle.Render("  max: ") + valueStyle.Render(fmtMB(totalAllocMB))
		// Show per-VM balloon if any are running
		for _, vm := range snap.Global.Proxmox.VMs {
			if vm.BalloonOn && vm.Status == "running" && vm.MemBalloonMB > 0 {
				pct := float64(vm.MemBalloonMB) / float64(vm.MemAllocMB) * 100
				balloonLine += dimStyle.Render(fmt.Sprintf("  %s:", vm.Name))
				bStr := fmt.Sprintf("%s/%.0f%%", fmtMB(vm.MemBalloonMB), pct)
				if pct > 90 {
					balloonLine += warnStyle.Render(bStr)
				} else {
					balloonLine += valueStyle.Render(bStr)
				}
			}
		}
		lines = append(lines, balloonLine)
	} else {
		lines = append(lines, dimStyle.Render("Balloon: disabled (all VMs use fixed memory)"))
	}

	return boxSection("HOST OVERVIEW", lines, iw)
}

func psiStr(v float64) string {
	return psiColor(v).Render(fmt.Sprintf("%.1f%%", v))
}

// renderPveHostNetwork shows host-level network interfaces and throughput
func renderPveHostNetwork(snap *model.Snapshot, rates *model.RateSnapshot, iw int) string {
	var lines []string

	// Header
	lines = append(lines, fmt.Sprintf("%s %s %s %s %s %s %s",
		styledPad(dimStyle.Render("IFACE"), 12),
		styledPad(dimStyle.Render("STATE"), 6),
		styledPad(dimStyle.Render("SPEED"), 8),
		styledPad(dimStyle.Render("RX MB/s"), 10),
		styledPad(dimStyle.Render("TX MB/s"), 10),
		styledPad(dimStyle.Render("RX pps"), 10),
		dimStyle.Render("ERRORS")))

	// Use rates if available, fall back to raw stats
	type ifRow struct {
		name  string
		state string
		speed int
		rxMBs float64
		txMBs float64
		rxPPS float64
		txPPS float64
		errs  int
	}

	var rows []ifRow
	if rates != nil && len(rates.NetRates) > 0 {
		for _, nr := range rates.NetRates {
			if nr.Name == "lo" || strings.HasPrefix(nr.Name, "veth") {
				continue
			}
			errs := 0
			if nr.RxErrorsPS > 0 || nr.TxErrorsPS > 0 || nr.RxDropsPS > 0 || nr.TxDropsPS > 0 {
				errs = int(nr.RxErrorsPS + nr.TxErrorsPS + nr.RxDropsPS + nr.TxDropsPS)
			}
			rows = append(rows, ifRow{
				name: nr.Name, state: nr.OperState, speed: nr.SpeedMbps,
				rxMBs: nr.RxMBs, txMBs: nr.TxMBs, rxPPS: nr.RxPPS, txPPS: nr.TxPPS,
				errs: errs,
			})
		}
	} else {
		for _, ns := range snap.Global.Network {
			if ns.Name == "lo" || strings.HasPrefix(ns.Name, "veth") {
				continue
			}
			rows = append(rows, ifRow{
				name: ns.Name, state: ns.OperState, speed: ns.SpeedMbps,
			})
		}
	}

	// Sort: physical first (not tap/vmbr), then by name
	sort.Slice(rows, func(i, j int) bool {
		iPhy := !strings.HasPrefix(rows[i].name, "tap") && !strings.HasPrefix(rows[i].name, "vmbr") && !strings.HasPrefix(rows[i].name, "fwbr")
		jPhy := !strings.HasPrefix(rows[j].name, "tap") && !strings.HasPrefix(rows[j].name, "vmbr") && !strings.HasPrefix(rows[j].name, "fwbr")
		if iPhy != jPhy {
			return iPhy
		}
		return rows[i].name < rows[j].name
	})

	for _, r := range rows {
		stateStr := dimStyle.Render("down")
		if r.state == "up" {
			stateStr = okStyle.Render("up")
		}
		speedStr := dimStyle.Render("—")
		if r.speed > 0 {
			if r.speed >= 1000 {
				speedStr = valueStyle.Render(fmt.Sprintf("%dG", r.speed/1000))
			} else {
				speedStr = valueStyle.Render(fmt.Sprintf("%dM", r.speed))
			}
		}
		rxStr := dimStyle.Render("—")
		txStr := dimStyle.Render("—")
		ppsStr := dimStyle.Render("—")
		if r.rxMBs > 0.001 || r.txMBs > 0.001 {
			rxStr = valueStyle.Render(fmt.Sprintf("%.2f", r.rxMBs))
			txStr = valueStyle.Render(fmt.Sprintf("%.2f", r.txMBs))
		}
		if r.rxPPS > 0 || r.txPPS > 0 {
			ppsStr = dimStyle.Render(fmt.Sprintf("%.0f/%.0f", r.rxPPS, r.txPPS))
		}
		errStr := dimStyle.Render("—")
		if r.errs > 0 {
			errStr = warnStyle.Render(fmt.Sprintf("%d/s", r.errs))
		}

		lines = append(lines, fmt.Sprintf("%s %s %s %s %s %s %s",
			styledPad(valueStyle.Render(truncate(r.name, 11)), 12),
			styledPad(stateStr, 6),
			styledPad(speedStr, 8),
			styledPad(rxStr, 10),
			styledPad(txStr, 10),
			styledPad(ppsStr, 10),
			errStr))
	}

	// Totals
	if rates != nil {
		var totalRx, totalTx float64
		for _, nr := range rates.NetRates {
			if nr.Name == "lo" {
				continue
			}
			totalRx += nr.RxMBs
			totalTx += nr.TxMBs
		}
		if totalRx > 0.001 || totalTx > 0.001 {
			lines = append(lines, dimStyle.Render(fmt.Sprintf("  Total throughput: RX %.2f MB/s  TX %.2f MB/s", totalRx, totalTx)))
		}
	}

	// TCP/socket summary
	sock := snap.Global.Sockets
	tcp := snap.Global.TCPStates
	connLine := dimStyle.Render("  Sockets: ")
	connLine += valueStyle.Render(fmt.Sprintf("%d", sock.SocketsUsed))
	connLine += dimStyle.Render("  TCP established: ")
	connLine += valueStyle.Render(fmt.Sprintf("%d", tcp.Established))
	if tcp.TimeWait > 0 {
		connLine += dimStyle.Render("  TIME_WAIT: ")
		if tcp.TimeWait > 5000 {
			connLine += warnStyle.Render(fmt.Sprintf("%d", tcp.TimeWait))
		} else {
			connLine += valueStyle.Render(fmt.Sprintf("%d", tcp.TimeWait))
		}
	}
	ct := snap.Global.Conntrack
	if ct.Max > 0 {
		ctPct := float64(ct.Count) / float64(ct.Max) * 100
		connLine += dimStyle.Render("  Conntrack: ")
		ctStr := fmt.Sprintf("%d/%d (%.0f%%)", ct.Count, ct.Max, ctPct)
		if ctPct > 80 {
			connLine += critStyle.Render(ctStr)
		} else if ctPct > 50 {
			connLine += warnStyle.Render(ctStr)
		} else {
			connLine += valueStyle.Render(ctStr)
		}
	}
	lines = append(lines, connLine)

	return boxSection("HOST NETWORK", lines, iw)
}

// renderPveHostDiskIO shows host-level disk IO and SMART health summary
func renderPveHostDiskIO(snap *model.Snapshot, rates *model.RateSnapshot, smartDisks []model.SMARTDisk, iw int) string {
	var lines []string

	// Disk IO table
	if rates != nil && len(rates.DiskRates) > 0 {
		lines = append(lines, fmt.Sprintf("%s %s %s %s %s %s",
			styledPad(dimStyle.Render("DEVICE"), 10),
			styledPad(dimStyle.Render("READ MB/s"), 12),
			styledPad(dimStyle.Render("WRITE MB/s"), 12),
			styledPad(dimStyle.Render("IOPS R/W"), 14),
			styledPad(dimStyle.Render("UTIL%"), 12),
			dimStyle.Render("AWAIT")))

		for _, dr := range rates.DiskRates {
			// Skip partitions (nvme0n1p1) and device-mapper, show block devices only
			if strings.Contains(dr.Name, "p") && len(dr.Name) > 4 {
				continue
			}
			if strings.HasPrefix(dr.Name, "dm-") || strings.HasPrefix(dr.Name, "loop") {
				continue
			}

			readStr := dimStyle.Render("—")
			writeStr := dimStyle.Render("—")
			if dr.ReadMBs > 0.01 || dr.WriteMBs > 0.01 {
				readStr = valueStyle.Render(fmt.Sprintf("%.2f", dr.ReadMBs))
				writeStr = valueStyle.Render(fmt.Sprintf("%.2f", dr.WriteMBs))
			}

			iopsStr := dimStyle.Render("—")
			if dr.ReadIOPS > 0 || dr.WriteIOPS > 0 {
				iopsStr = valueStyle.Render(fmt.Sprintf("%.0f/%.0f", dr.ReadIOPS, dr.WriteIOPS))
			}

			utilStr := dimStyle.Render("—")
			if dr.UtilPct > 0 {
				utilVal := fmt.Sprintf("%.1f%%", dr.UtilPct)
				if dr.UtilPct > 80 {
					utilStr = critStyle.Render(utilVal) + " " + bar(dr.UtilPct, 6)
				} else if dr.UtilPct > 50 {
					utilStr = warnStyle.Render(utilVal) + " " + bar(dr.UtilPct, 6)
				} else {
					utilStr = valueStyle.Render(utilVal)
				}
			}

			awaitStr := dimStyle.Render("—")
			if dr.AvgAwaitMs > 0 {
				awaitVal := fmt.Sprintf("%.1fms", dr.AvgAwaitMs)
				if dr.AvgAwaitMs > 20 {
					awaitStr = critStyle.Render(awaitVal)
				} else if dr.AvgAwaitMs > 5 {
					awaitStr = warnStyle.Render(awaitVal)
				} else {
					awaitStr = valueStyle.Render(awaitVal)
				}
			}

			lines = append(lines, fmt.Sprintf("%s %s %s %s %s %s",
				styledPad(valueStyle.Render(dr.Name), 10),
				styledPad(readStr, 12),
				styledPad(writeStr, 12),
				styledPad(iopsStr, 14),
				styledPad(utilStr, 12),
				awaitStr))
		}
	}

	// IO PSI
	psi := snap.Global.PSI.IO
	if psi.Some.Avg10 > 0 || psi.Full.Avg10 > 0 {
		ioLine := dimStyle.Render("  IO PSI: some=") + psiStr(psi.Some.Avg10)
		ioLine += dimStyle.Render("  full=") + psiStr(psi.Full.Avg10)
		lines = append(lines, ioLine)
	}

	// SMART health summary (one-liner per disk)
	if len(smartDisks) > 0 {
		lines = append(lines, "")
		lines = append(lines, dimStyle.Render("  SMART Health:"))
		for _, d := range smartDisks {
			if d.DiskType == model.DiskTypeVirtual {
				continue
			}
			if d.ErrorString != "" {
				lines = append(lines, fmt.Sprintf("    %s  %s", valueStyle.Render(d.Name), dimStyle.Render("error: "+d.ErrorString)))
				continue
			}
			verdict := d.HealthVerdict()
			var vStyle string
			switch verdict {
			case "OK":
				vStyle = okStyle.Render("OK")
			case "WARN", "WORN":
				vStyle = warnStyle.Render(verdict)
			case "CRITICAL", "FAILING", "FAIL":
				vStyle = critStyle.Render(verdict)
			default:
				vStyle = dimStyle.Render(verdict)
			}
			detail := ""
			if d.Temperature > 0 {
				detail += fmt.Sprintf(" %d°C", d.Temperature)
			}
			if d.PercentUsed >= 0 {
				detail += fmt.Sprintf(" wear:%d%%", d.PercentUsed)
			} else if d.WearLevelPct >= 0 {
				detail += fmt.Sprintf(" wear:%d%%", d.WearLevelPct)
			}
			if d.PowerOnHours > 0 {
				days := d.PowerOnHours / 24
				detail += fmt.Sprintf(" %dd", days)
			}
			if d.EstLifeDays > 0 {
				detail += fmt.Sprintf(" ~%dd left", d.EstLifeDays)
			}
			lines = append(lines, fmt.Sprintf("    %s  %s  %s%s",
				styledPad(valueStyle.Render(d.Name), 10),
				styledPad(vStyle, 8),
				dimStyle.Render(truncate(d.ModelNumber, 25)),
				dimStyle.Render(detail)))
		}
	}

	// Filesystem summary
	if len(snap.Global.Mounts) > 0 {
		lines = append(lines, "")
		lines = append(lines, fmt.Sprintf("  %s %s %s %s",
			styledPad(dimStyle.Render("MOUNT"), 20),
			styledPad(dimStyle.Render("USED"), 18),
			styledPad(dimStyle.Render("SIZE"), 8),
			dimStyle.Render("FSTYPE")))
		for _, m := range snap.Global.Mounts {
			if m.TotalBytes == 0 {
				continue
			}
			// Skip special filesystems
			if strings.HasPrefix(m.MountPoint, "/snap") || strings.HasPrefix(m.MountPoint, "/boot/efi") {
				continue
			}
			usedPct := float64(m.UsedBytes) / float64(m.TotalBytes) * 100
			usedStr := fmt.Sprintf("%.1fG/%.1fG",
				float64(m.UsedBytes)/(1024*1024*1024),
				float64(m.TotalBytes)/(1024*1024*1024))
			usedCol := bar(usedPct, 8) + " "
			if usedPct > 90 {
				usedCol += critStyle.Render(fmt.Sprintf("%.0f%%", usedPct))
			} else if usedPct > 75 {
				usedCol += warnStyle.Render(fmt.Sprintf("%.0f%%", usedPct))
			} else {
				usedCol += valueStyle.Render(fmt.Sprintf("%.0f%%", usedPct))
			}

			lines = append(lines, fmt.Sprintf("  %s %s %s %s",
				styledPad(valueStyle.Render(truncate(m.MountPoint, 19)), 20),
				styledPad(usedCol, 18),
				styledPad(dimStyle.Render(usedStr), 8),
				dimStyle.Render(m.FSType)))
		}
	}

	return boxSection("HOST DISK & STORAGE", lines, iw)
}

// renderPveVMTable renders the VM status table
func renderPveVMTable(pve *model.ProxmoxMetrics, iw int) string {
	var vmLines []string
	hdr := fmt.Sprintf("%s %s %s %s %s %s %s %s %s",
		styledPad(dimStyle.Render("VMID"), 6),
		styledPad(dimStyle.Render("NAME"), 14),
		styledPad(dimStyle.Render("STATUS"), 9),
		styledPad(dimStyle.Render("CPU%"), 7),
		styledPad(dimStyle.Render("MEM USED"), 12),
		styledPad(dimStyle.Render("IO R/W"), 14),
		styledPad(dimStyle.Render("NET R/T"), 14),
		styledPad(dimStyle.Render("UPTIME"), 10),
		dimStyle.Render("CONFIG"))
	vmLines = append(vmLines, hdr)

	for _, vm := range pve.VMs {
		vmidStr := fmt.Sprintf("%d", vm.VMID)
		nameStr := truncate(vm.Name, 13)

		var statusStyled string
		switch vm.Status {
		case "running":
			statusStyled = styledPad(okStyle.Render("running"), 9)
		case "stopped":
			statusStyled = styledPad(dimStyle.Render("stopped"), 9)
		case "paused":
			statusStyled = styledPad(warnStyle.Render("paused"), 9)
		default:
			statusStyled = styledPad(dimStyle.Render(vm.Status), 9)
		}

		cpuStr := dimStyle.Render("  —  ")
		if vm.Status == "running" {
			cpuFmt := fmt.Sprintf("%.1f%%", vm.CPUPct)
			if vm.CPUPct > 80 {
				cpuStr = critStyle.Render(cpuFmt)
			} else if vm.CPUPct > 50 {
				cpuStr = warnStyle.Render(cpuFmt)
			} else {
				cpuStr = valueStyle.Render(cpuFmt)
			}
		}

		memStr := dimStyle.Render("   —    ")
		if vm.Status == "running" && vm.MemUsedMB > 0 {
			if vm.MemAllocMB > 0 {
				pct := float64(vm.MemUsedMB) / float64(vm.MemAllocMB) * 100
				memFmt := fmt.Sprintf("%s/%s", fmtMB(vm.MemUsedMB), fmtMB(vm.MemAllocMB))
				if pct > 90 {
					memStr = critStyle.Render(memFmt)
				} else if pct > 70 {
					memStr = warnStyle.Render(memFmt)
				} else {
					memStr = valueStyle.Render(memFmt)
				}
			} else {
				memStr = valueStyle.Render(fmtMB(vm.MemUsedMB))
			}
		}

		ioStr := dimStyle.Render("     —      ")
		if vm.Status == "running" && (vm.IOReadMBs > 0.01 || vm.IOWriteMBs > 0.01) {
			ioStr = fmt.Sprintf("R:%.1f W:%.1f", vm.IOReadMBs, vm.IOWriteMBs)
		}

		netStr := dimStyle.Render("     —      ")
		if vm.Status == "running" && (vm.NetRxMBs > 0.001 || vm.NetTxMBs > 0.001) {
			netStr = fmt.Sprintf("R:%.1f T:%.1f", vm.NetRxMBs, vm.NetTxMBs)
		}

		uptimeStr := dimStyle.Render("   —   ")
		if vm.Status == "running" && vm.UptimeSec > 0 {
			uptimeStr = fmtUptime(vm.UptimeSec)
		}

		configParts := []string{}
		if vm.CoresAlloc > 0 {
			configParts = append(configParts, fmt.Sprintf("%dC", vm.CoresAlloc))
		}
		if vm.MemAllocMB > 0 {
			configParts = append(configParts, fmtMB(vm.MemAllocMB))
		}
		for _, d := range vm.DiskConfigs {
			if d.SizeGB > 0 && !strings.Contains(d.Path, "iso") && d.Path != "none" {
				configParts = append(configParts, fmt.Sprintf("%dG", d.SizeGB))
			}
		}
		configStr := dimStyle.Render(strings.Join(configParts, "/"))

		line := fmt.Sprintf("%s %s %s %s %s %s %s %s %s",
			styledPad(valueStyle.Render(vmidStr), 6),
			styledPad(nameStr, 14),
			statusStyled,
			styledPad(cpuStr, 7),
			styledPad(memStr, 12),
			styledPad(ioStr, 14),
			styledPad(netStr, 14),
			styledPad(uptimeStr, 10),
			configStr)
		vmLines = append(vmLines, line)
	}

	if len(pve.VMs) == 0 {
		vmLines = append(vmLines, dimStyle.Render("  no VMs configured"))
	}
	return boxSection("VM STATUS", vmLines, iw)
}

// renderPveVMDetail renders per-VM config and live metrics
func renderPveVMDetail(vm model.ProxmoxVM, iw int) string {
	var detailLines []string

	// Config line
	var cfgParts []string
	vcpu := vm.CoresAlloc * maxInt(vm.SocketsAlloc, 1)
	cfgParts = append(cfgParts, fmt.Sprintf("%d vCPU", vcpu))
	if vm.MemAllocMB > 0 {
		memCfg := fmt.Sprintf("%s RAM", fmtMB(vm.MemAllocMB))
		if vm.BalloonOn {
			memCfg += fmt.Sprintf(" (balloon min:%s)", fmtMB(vm.BalloonMinMB))
		}
		cfgParts = append(cfgParts, memCfg)
	}
	for _, d := range vm.DiskConfigs {
		if d.SizeGB > 0 && !strings.Contains(d.Path, "iso") && d.Path != "none" {
			cacheStr := ""
			if d.Cache != "" {
				cacheStr = " cache=" + d.Cache
			}
			cfgParts = append(cfgParts, fmt.Sprintf("%s %dG%s", d.Bus, d.SizeGB, cacheStr))
		}
	}
	detailLines = append(detailLines,
		dimStyle.Render("Config: ")+valueStyle.Render(strings.Join(cfgParts, ", ")))

	// Network config
	for _, n := range vm.NetConfigs {
		netInfo := fmt.Sprintf("%s=%s bridge=%s", n.Model, n.MAC, n.Bridge)
		if n.Tag > 0 {
			netInfo += fmt.Sprintf(" vlan=%d", n.Tag)
		}
		detailLines = append(detailLines,
			dimStyle.Render("  Net:  ")+dimStyle.Render(netInfo))
	}

	// Disk paths
	for _, d := range vm.DiskConfigs {
		if d.SizeGB > 0 && !strings.Contains(d.Path, "iso") && d.Path != "none" {
			detailLines = append(detailLines,
				dimStyle.Render(fmt.Sprintf("  Disk: %s → %s (%dG)", d.Bus, d.Path, d.SizeGB)))
		}
	}

	// Live metrics
	if vm.CPUPct > 0 || vm.MemUsedMB > 0 {
		metricsLine := fmt.Sprintf("  Live: CPU=%.1f%%  Mem=%s", vm.CPUPct, fmtMB(vm.MemUsedMB))
		if vm.BalloonOn && vm.MemBalloonMB > 0 && vm.MemAllocMB > 0 {
			pct := float64(vm.MemBalloonMB) / float64(vm.MemAllocMB) * 100
			metricsLine += fmt.Sprintf("  Balloon=%s(%.0f%%)", fmtMB(vm.MemBalloonMB), pct)
		}
		metricsLine += fmt.Sprintf("  IO R:%.1f/W:%.1f MB/s  Net RX:%.1f/TX:%.1f MB/s",
			vm.IOReadMBs, vm.IOWriteMBs, vm.NetRxMBs, vm.NetTxMBs)
		detailLines = append(detailLines, valueStyle.Render(metricsLine))
	}

	title := fmt.Sprintf("VM %d — %s", vm.VMID, vm.Name)
	return boxSection(title, detailLines, iw)
}

// renderPveStorage renders the storage pools section
func renderPveStorage(storages []model.ProxmoxStorage, iw int) string {
	var storLines []string
	storHdr := fmt.Sprintf("%s %s %s %s %s %s",
		styledPad(dimStyle.Render("NAME"), 14),
		styledPad(dimStyle.Render("TYPE"), 10),
		styledPad(dimStyle.Render("USED%"), 18),
		styledPad(dimStyle.Render("USED"), 8),
		styledPad(dimStyle.Render("TOTAL"), 8),
		dimStyle.Render("PATH"))
	storLines = append(storLines, storHdr)

	for _, s := range storages {
		usedBar := ""
		usedPctStr := ""
		if s.TotalGB > 0 {
			usedBar = bar(s.UsedPct, 10)
			usedPctStr = meterColor(s.UsedPct).Render(fmt.Sprintf("%.0f%%", s.UsedPct))
		}
		usedCol := usedBar + " " + usedPctStr

		usedStr := dimStyle.Render("  —  ")
		if s.UsedGB > 0 {
			usedStr = fmt.Sprintf("%.1fG", s.UsedGB)
		}
		totalStr := dimStyle.Render("  —  ")
		if s.TotalGB > 0 {
			totalStr = fmt.Sprintf("%.1fG", s.TotalGB)
		}

		line := fmt.Sprintf("%s %s %s %s %s %s",
			styledPad(valueStyle.Render(truncate(s.Name, 13)), 14),
			styledPad(dimStyle.Render(s.Type), 10),
			styledPad(usedCol, 18),
			styledPad(usedStr, 8),
			styledPad(totalStr, 8),
			dimStyle.Render(truncate(s.Path, 40)))
		storLines = append(storLines, line)
	}
	return boxSection("STORAGE POOLS", storLines, iw)
}

func fmtMB(mb int) string {
	if mb >= 1024 {
		return fmt.Sprintf("%.1fG", float64(mb)/1024)
	}
	return fmt.Sprintf("%dM", mb)
}

func fmtUptime(sec int64) string {
	if sec < 60 {
		return fmt.Sprintf("%ds", sec)
	}
	if sec < 3600 {
		return fmt.Sprintf("%dm", sec/60)
	}
	if sec < 86400 {
		return fmt.Sprintf("%.1fh", float64(sec)/3600)
	}
	return fmt.Sprintf("%dd", sec/86400)
}
