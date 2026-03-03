package ui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/ftahirops/xtop/engine"
	"github.com/ftahirops/xtop/model"
)

// Probe page section constants
const (
	probSecOffCPU     = 0
	probSecIOLat      = 1
	probSecLockWait   = 2
	probSecTCPRetrans = 3
	probSecNetThruput = 4
	probSecTCPRTT     = 5
	probSecTCPConnLat = 6
	probSecRunQLat    = 7
	probSecWBStall    = 8
	probSecPgFault    = 9
	probSecSwapEvict  = 10
	probSecSyscall    = 11
	probSecSockIO     = 12
	probSecCount      = 13
)

// renderProbePage renders the full probe investigation page (page 8).
func renderProbePage(pm *engine.ProbeManager, snap *model.Snapshot, width, height int, cursor int, expanded [13]bool) string {
	var sb strings.Builder

	if pm == nil {
		sb.WriteString(titleStyle.Render(" PROBE INVESTIGATION"))
		sb.WriteString("\n\n")
		sb.WriteString(dimStyle.Render("  Probe engine not available."))
		sb.WriteString("\n")
		return sb.String()
	}

	// Sentinel section (always-on)
	if snap != nil && snap.Global.Sentinel.Active {
		sb.WriteString(renderSentinelSection(snap, width))
	}

	state := pm.State()

	switch state {
	case engine.ProbeIdle:
		sb.WriteString(renderProbeIdle(width))
	case engine.ProbeRunning:
		sb.WriteString(renderProbeRunning(pm, width))
	case engine.ProbeDone:
		sb.WriteString(renderProbeDone(pm, width, cursor, expanded))
	}
	sb.WriteString(pageFooter("I:probe  Tab:section  Enter:expand  A:all  C:collapse"))

	return sb.String()
}

// renderSentinelSection renders the always-on sentinel probe data.
func renderSentinelSection(snap *model.Snapshot, width int) string {
	var sb strings.Builder
	sent := snap.Global.Sentinel

	innerW := width - 7
	if innerW < 50 {
		innerW = 50
	}
	if innerW > 90 {
		innerW = 90
	}

	sb.WriteString(titleStyle.Render(" SENTINEL (always-on)"))
	sb.WriteString("\n")
	sb.WriteString(boxTop(innerW) + "\n")

	// Packet drops
	if len(sent.PktDrops) > 0 {
		var parts []string
		for _, d := range sent.PktDrops {
			if len(parts) >= 4 {
				break
			}
			parts = append(parts, fmt.Sprintf("%s:%.0f", d.ReasonStr, d.Rate))
		}
		line := fmt.Sprintf("  %s %s %s",
			styledPad(titleStyle.Render("Pkt Drops:"), 14),
			warnStyle.Render(fmt.Sprintf("%.0f/s", sent.PktDropRate)),
			dimStyle.Render("("+strings.Join(parts, " ")+")"))
		sb.WriteString(boxRow(line, innerW) + "\n")
	} else {
		sb.WriteString(boxRow(fmt.Sprintf("  %s %s",
			styledPad(titleStyle.Render("Pkt Drops:"), 14),
			dimStyle.Render("0/s")), innerW) + "\n")
	}

	// TCP resets
	if len(sent.TCPResets) > 0 {
		top := sent.TCPResets[0]
		line := fmt.Sprintf("  %s %s %s",
			styledPad(titleStyle.Render("TCP RSTs:"), 14),
			warnStyle.Render(fmt.Sprintf("%.0f/s", sent.TCPResetRate)),
			dimStyle.Render(fmt.Sprintf("(%s PID %d: %.0f/s)", top.Comm, top.PID, top.Rate)))
		sb.WriteString(boxRow(line, innerW) + "\n")
	} else {
		sb.WriteString(boxRow(fmt.Sprintf("  %s %s",
			styledPad(titleStyle.Render("TCP RSTs:"), 14),
			dimStyle.Render("0/s")), innerW) + "\n")
	}

	// Retransmits
	if len(sent.Retransmits) > 0 {
		top := sent.Retransmits[0]
		line := fmt.Sprintf("  %s %s %s",
			styledPad(titleStyle.Render("Retrans:"), 14),
			warnStyle.Render(fmt.Sprintf("%.0f/s", sent.RetransRate)),
			dimStyle.Render(fmt.Sprintf("(%s PID %d: %.0f/s)", top.Comm, top.PID, top.Rate)))
		sb.WriteString(boxRow(line, innerW) + "\n")
	} else {
		sb.WriteString(boxRow(fmt.Sprintf("  %s %s",
			styledPad(titleStyle.Render("Retrans:"), 14),
			dimStyle.Render("0/s")), innerW) + "\n")
	}

	// State transitions
	if len(sent.StateChanges) > 0 {
		top := sent.StateChanges[0]
		line := fmt.Sprintf("  %s %s",
			styledPad(titleStyle.Render("State:"), 14),
			dimStyle.Render(fmt.Sprintf("%s\u2192%s: %.1f/s", top.OldStr, top.NewStr, top.Rate)))
		sb.WriteString(boxRow(line, innerW) + "\n")
	}

	// Module loads, OOM, reclaim, throttle
	modStr := fmt.Sprintf("%d loaded", len(sent.ModLoads))
	oomStr := fmt.Sprintf("%d kills", len(sent.OOMKills))
	reclaimStr := fmt.Sprintf("%.0fms", sent.ReclaimStallMs)
	line := fmt.Sprintf("  %s %s",
		styledPad(titleStyle.Render("Misc:"), 14),
		dimStyle.Render(fmt.Sprintf("Modules: %s | OOM: %s | Reclaim: %s", modStr, oomStr, reclaimStr)))
	sb.WriteString(boxRow(line, innerW) + "\n")

	// Throttle
	if len(sent.CgThrottles) > 0 {
		top := sent.CgThrottles[0]
		line := fmt.Sprintf("  %s %s %s",
			styledPad(titleStyle.Render("Throttle:"), 14),
			warnStyle.Render(fmt.Sprintf("%.0f/s", sent.ThrottleRate)),
			dimStyle.Render(fmt.Sprintf("(%s)", top.CgPath)))
		sb.WriteString(boxRow(line, innerW) + "\n")
	}

	sb.WriteString(boxBot(innerW) + "\n\n")
	return sb.String()
}

func renderProbeIdle(width int) string {
	var sb strings.Builder
	sb.WriteString(titleStyle.Render(" PROBE INVESTIGATION"))
	sb.WriteString("\n\n")

	innerW := width - 7
	if innerW < 50 {
		innerW = 50
	}
	if innerW > 80 {
		innerW = 80
	}

	sb.WriteString(boxTop(innerW) + "\n")
	sb.WriteString(boxRow(dimStyle.Render("No probe running. Press I to start an eBPF investigation."), innerW) + "\n")
	sb.WriteString(boxMid(innerW) + "\n")
	sb.WriteString(boxRow(titleStyle.Render("Available probe packs:"), innerW) + "\n")
	sb.WriteString(boxRow(" ", innerW) + "\n")
	sb.WriteString(boxRow(fmt.Sprintf("  %s  %s",
		styledPad(valueStyle.Render("offcpu"), 14),
		dimStyle.Render("Trace off-CPU wait durations per process (reason from /proc wchan) [H]")), innerW) + "\n")
	sb.WriteString(boxRow(fmt.Sprintf("  %s  %s",
		styledPad(valueStyle.Render("iolatency"), 14),
		dimStyle.Render("Block IO latency histograms per device (BPF tracepoint) [H]")), innerW) + "\n")
	sb.WriteString(boxRow(fmt.Sprintf("  %s  %s",
		styledPad(valueStyle.Render("lockwait"), 14),
		dimStyle.Render("Lock contention (futex, rwsem, mutex) (BPF tracepoint) [H]")), innerW) + "\n")
	sb.WriteString(boxRow(fmt.Sprintf("  %s  %s",
		styledPad(valueStyle.Render("tcpretrans"), 14),
		dimStyle.Render("TCP retransmit tracing (PID may be kernel context) [L]")), innerW) + "\n")
	sb.WriteString(boxRow(fmt.Sprintf("  %s  %s",
		styledPad(valueStyle.Render("netthroughput"), 14),
		dimStyle.Render("Per-process TCP send/receive throughput")), innerW) + "\n")
	sb.WriteString(boxRow(fmt.Sprintf("  %s  %s",
		styledPad(valueStyle.Render("tcprtt"), 14),
		dimStyle.Render("TCP RTT per remote endpoint")), innerW) + "\n")
	sb.WriteString(boxRow(fmt.Sprintf("  %s  %s",
		styledPad(valueStyle.Render("tcpconnlat"), 14),
		dimStyle.Render("TCP connection establishment latency")), innerW) + "\n")
	sb.WriteString(boxMid(innerW) + "\n")
	sb.WriteString(boxRow(headerStyle.Render("Press I")+dimStyle.Render(" to auto-detect and run all packs (10s)"), innerW) + "\n")
	sb.WriteString(boxBot(innerW) + "\n")

	return sb.String()
}

func renderProbeRunning(pm *engine.ProbeManager, width int) string {
	var sb strings.Builder
	secsLeft := pm.SecondsLeft()
	pack := pm.Pack()
	elapsed := 10 - secsLeft
	if elapsed < 0 {
		elapsed = 0
	}

	sb.WriteString(titleStyle.Render(fmt.Sprintf(" PROBE INVESTIGATION \u2014 %s (%ds remaining)", pack, secsLeft)))
	sb.WriteString("\n\n")

	// Progress bar
	pct := float64(elapsed) / 10.0 * 100
	barWidth := 40
	filled := int(pct / 100 * float64(barWidth))
	if filled > barWidth {
		filled = barWidth
	}
	barStr := strings.Repeat("\u2588", filled) + strings.Repeat("\u2591", barWidth-filled)
	sb.WriteString(fmt.Sprintf("  %s %s\n",
		orangeStyle.Render(barStr),
		dimStyle.Render(fmt.Sprintf("%.0f%%", pct))))
	sb.WriteString("\n")
	sb.WriteString(dimStyle.Render("  Collecting eBPF samples... please wait."))
	sb.WriteString("\n\n")
	sb.WriteString(dimStyle.Render("  Attached probes: sched_switch, block_rq_issue/complete, futex, tcp_retransmit_skb,"))
	sb.WriteString("\n")
	sb.WriteString(dimStyle.Render("                   tcp_sendmsg, tcp_cleanup_rbuf, tcp_rcv_established, tcp_v4_connect"))
	sb.WriteString("\n")

	return sb.String()
}

// renderProbeSectionHeader renders a collapsible section header for probe results.
func renderProbeSectionHeader(title string, hasData bool, count int, selected, expanded bool) string {
	if !hasData {
		return ""
	}
	arrow := "▶"
	if expanded {
		arrow = "▼"
	}
	countStr := dimStyle.Render(fmt.Sprintf("(%d)", count))
	line := fmt.Sprintf("%s %s %s", arrow, title, countStr)
	if selected {
		return lipgloss.NewStyle().Foreground(colorCyan).Bold(true).Render(line) + "\n"
	}
	return titleStyle.Render(line) + "\n"
}

func renderProbeDone(pm *engine.ProbeManager, width int, cursor int, expanded [13]bool) string {
	var sb strings.Builder
	f := pm.Findings()
	if f == nil {
		sb.WriteString(titleStyle.Render(" PROBE RESULTS"))
		sb.WriteString("\n\n")
		sb.WriteString(dimStyle.Render("  No findings available."))
		return sb.String()
	}

	sb.WriteString(titleStyle.Render(fmt.Sprintf(" PROBE RESULTS (%s) \u2014 %s", f.Duration, f.Pack)))
	sb.WriteString("\n")

	// Summary
	sb.WriteString(fmt.Sprintf(" Bottleneck: %s (RCA confidence +%d%%)\n",
		warnStyle.Render(f.Bottleneck), f.ConfBoost))
	sb.WriteString(fmt.Sprintf(" Top finding: %s\n", valueStyle.Render(f.Summary)))
	sb.WriteString(dimStyle.Render(fmt.Sprintf(" Captured: last %ds window", int(f.Duration.Seconds()))))
	sb.WriteString("\n\n")

	innerW := width - 7
	if innerW < 50 {
		innerW = 50
	}
	if innerW > 90 {
		innerW = 90
	}

	// Off-CPU waiters
	if hdr := renderProbeSectionHeader("Off-CPU (Top waiters)", len(f.OffCPUWaiters) > 0, len(f.OffCPUWaiters), cursor == probSecOffCPU, expanded[probSecOffCPU]); hdr != "" {
		sb.WriteString(hdr)
		if expanded[probSecOffCPU] {
			sb.WriteString(boxTop(innerW) + "\n")
			hdrLine := fmt.Sprintf("  %s %s %s %s %s",
				styledPad(dimStyle.Render("PID"), 8),
				styledPad(dimStyle.Render("CMD"), 14),
				styledPad(dimStyle.Render("WAIT%"), 8),
				styledPad(dimStyle.Render("CONF"), 6),
				dimStyle.Render("REASON"))
			sb.WriteString(boxRow(hdrLine, innerW) + "\n")
			sb.WriteString(boxMid(innerW) + "\n")
			for _, e := range f.OffCPUWaiters {
				ws := valueStyle
				if e.WaitPct >= 50 {
					ws = critStyle
				} else if e.WaitPct >= 30 {
					ws = warnStyle
				}
				confStr := dimStyle.Render("[H]")
				reasonConf := ""
				if e.Reason != "" {
					reasonConf = " " + dimStyle.Render("[M]")
				}
				row := fmt.Sprintf("  %s %s %s %s %s%s",
					styledPad(dimStyle.Render(fmt.Sprintf("%d", e.PID)), 8),
					styledPad(valueStyle.Render(truncate(e.Comm, 12)), 14),
					styledPad(ws.Render(fmt.Sprintf("%.1f%%", e.WaitPct)), 8),
					styledPad(confStr, 6),
					dimStyle.Render(e.Reason), reasonConf)
				sb.WriteString(boxRow(row, innerW) + "\n")
			}
			sb.WriteString(boxBot(innerW) + "\n\n")
		}
	}

	// IO latency
	if hdr := renderProbeSectionHeader("Block IO Latency", len(f.IOLatency) > 0, len(f.IOLatency), cursor == probSecIOLat, expanded[probSecIOLat]); hdr != "" {
		sb.WriteString(hdr)
		if expanded[probSecIOLat] {
			sb.WriteString(boxTop(innerW) + "\n")
			hdrLine := fmt.Sprintf("  %s %s %s %s %s %s",
				styledPad(dimStyle.Render("DEV"), 12),
				styledPad(dimStyle.Render("p50"), 10),
				styledPad(dimStyle.Render("p95"), 10),
				styledPad(dimStyle.Render("p99"), 10),
				styledPad(dimStyle.Render("UTIL"), 8),
				dimStyle.Render("CONF"))
			sb.WriteString(boxRow(hdrLine, innerW) + "\n")
			sb.WriteString(boxMid(innerW) + "\n")
			for _, e := range f.IOLatency {
				p95s := valueStyle
				if e.P95Ms >= 50 {
					p95s = critStyle
				} else if e.P95Ms >= 20 {
					p95s = warnStyle
				}
				p99s := valueStyle
				if e.P99Ms >= 100 {
					p99s = critStyle
				} else if e.P99Ms >= 20 {
					p99s = warnStyle
				}
				row := fmt.Sprintf("  %s %s %s %s %s %s",
					styledPad(valueStyle.Render(truncate(e.Device, 10)), 12),
					styledPad(dimStyle.Render(fmt.Sprintf("%.1fms", e.P50Ms)), 10),
					styledPad(p95s.Render(fmt.Sprintf("%.1fms", e.P95Ms)), 10),
					styledPad(p99s.Render(fmt.Sprintf("%.1fms", e.P99Ms)), 10),
					styledPad(dimStyle.Render(fmt.Sprintf("%.0f%%", e.UtilPct)), 8),
					dimStyle.Render("[H]"))
				sb.WriteString(boxRow(row, innerW) + "\n")
			}
			sb.WriteString(boxBot(innerW) + "\n\n")
		}
	}

	// Lock waits
	if hdr := renderProbeSectionHeader("Lock Waits", len(f.LockWaiters) > 0, len(f.LockWaiters), cursor == probSecLockWait, expanded[probSecLockWait]); hdr != "" {
		sb.WriteString(hdr)
		if expanded[probSecLockWait] {
			sb.WriteString(boxTop(innerW) + "\n")
			hdrLine := fmt.Sprintf("  %s %s %s %s %s", styledPad(dimStyle.Render("PID"), 8), styledPad(dimStyle.Render("CMD"), 14), styledPad(dimStyle.Render("WAIT%"), 8), styledPad(dimStyle.Render("CONF"), 6), dimStyle.Render("LOCK TYPE"))
			sb.WriteString(boxRow(hdrLine, innerW) + "\n")
			sb.WriteString(boxMid(innerW) + "\n")
			for _, e := range f.LockWaiters {
				ws := valueStyle
				isIdle := true
				for _, oc := range f.OffCPUWaiters {
					if oc.PID == e.PID && oc.WaitPct >= 5 { isIdle = false; break }
				}
				if !isIdle {
					if e.WaitPct >= 50 { ws = critStyle } else if e.WaitPct >= 30 { ws = warnStyle }
				} else { ws = dimStyle }
				row := fmt.Sprintf("  %s %s %s %s %s", styledPad(dimStyle.Render(fmt.Sprintf("%d", e.PID)), 8), styledPad(valueStyle.Render(truncate(e.Comm, 12)), 14), styledPad(ws.Render(fmt.Sprintf("%.1f%%", e.WaitPct)), 8), styledPad(dimStyle.Render("[H]"), 6), dimStyle.Render(e.LockType))
				sb.WriteString(boxRow(row, innerW) + "\n")
			}
			sb.WriteString(boxBot(innerW) + "\n\n")
		}
	}

	// TCP retransmits
	if hdr := renderProbeSectionHeader("TCP Retransmits", len(f.TCPRetrans) > 0, len(f.TCPRetrans), cursor == probSecTCPRetrans, expanded[probSecTCPRetrans]); hdr != "" {
		sb.WriteString(hdr)
		if expanded[probSecTCPRetrans] {
			sb.WriteString(boxTop(innerW) + "\n")
			hdrLine := fmt.Sprintf("  %s %s %s %s %s", styledPad(dimStyle.Render("PID"), 8), styledPad(dimStyle.Render("CMD"), 14), styledPad(dimStyle.Render("RETRANS"), 10), styledPad(dimStyle.Render("CONF"), 6), dimStyle.Render("IFACE"))
			sb.WriteString(boxRow(hdrLine, innerW) + "\n")
			sb.WriteString(boxMid(innerW) + "\n")
			for _, e := range f.TCPRetrans {
				rs := valueStyle
				if e.Retrans >= 100 { rs = critStyle } else if e.Retrans >= 30 { rs = warnStyle }
				confStr := dimStyle.Render("[L]")
				if e.PID == 0 { confStr = dimStyle.Render("[--]") }
				row := fmt.Sprintf("  %s %s %s %s %s", styledPad(dimStyle.Render(fmt.Sprintf("%d", e.PID)), 8), styledPad(valueStyle.Render(truncate(e.Comm, 12)), 14), styledPad(rs.Render(fmt.Sprintf("%d/s", e.Retrans)), 10), styledPad(confStr, 6), dimStyle.Render(e.Iface))
				sb.WriteString(boxRow(row, innerW) + "\n")
			}
			sb.WriteString(boxBot(innerW) + "\n\n")
		}
	}

	// Network throughput
	if hdr := renderProbeSectionHeader("Network Throughput", len(f.NetThroughput) > 0, len(f.NetThroughput), cursor == probSecNetThruput, expanded[probSecNetThruput]); hdr != "" {
		sb.WriteString(hdr)
		if expanded[probSecNetThruput] {
			sb.WriteString(boxTop(innerW) + "\n")
			hdrLine := fmt.Sprintf("  %s %s %s %s %s", styledPad(dimStyle.Render("PID"), 8), styledPad(dimStyle.Render("CMD"), 14), styledPad(dimStyle.Render("TX MB/s"), 10), styledPad(dimStyle.Render("RX MB/s"), 10), dimStyle.Render("TOTAL"))
			sb.WriteString(boxRow(hdrLine, innerW) + "\n")
			sb.WriteString(boxMid(innerW) + "\n")
			for _, e := range f.NetThroughput {
				total := e.TxMBs + e.RxMBs
				ts := valueStyle
				if total >= 100 { ts = critStyle } else if total >= 10 { ts = warnStyle }
				row := fmt.Sprintf("  %s %s %s %s %s", styledPad(dimStyle.Render(fmt.Sprintf("%d", e.PID)), 8), styledPad(valueStyle.Render(truncate(e.Comm, 12)), 14), styledPad(dimStyle.Render(fmt.Sprintf("%.1f", e.TxMBs)), 10), styledPad(dimStyle.Render(fmt.Sprintf("%.1f", e.RxMBs)), 10), ts.Render(fmt.Sprintf("%.1f MB/s", total)))
				sb.WriteString(boxRow(row, innerW) + "\n")
			}
			sb.WriteString(boxBot(innerW) + "\n\n")
		}
	}

	// TCP RTT
	if hdr := renderProbeSectionHeader("TCP RTT", len(f.TCPRTT) > 0, len(f.TCPRTT), cursor == probSecTCPRTT, expanded[probSecTCPRTT]); hdr != "" {
		sb.WriteString(hdr)
		if expanded[probSecTCPRTT] {
			sb.WriteString(boxTop(innerW) + "\n")
			hdrLine := fmt.Sprintf("  %s %s %s %s %s %s", styledPad(dimStyle.Render("DEST"), 18), styledPad(dimStyle.Render("AVG"), 10), styledPad(dimStyle.Render("MIN"), 10), styledPad(dimStyle.Render("MAX"), 10), styledPad(dimStyle.Render("SAMPLES"), 8), dimStyle.Render("PROCESS"))
			sb.WriteString(boxRow(hdrLine, innerW) + "\n")
			sb.WriteString(boxMid(innerW) + "\n")
			for _, e := range f.TCPRTT {
				rs := valueStyle
				if e.AvgRTTMs >= 50 { rs = critStyle } else if e.AvgRTTMs >= 10 { rs = warnStyle }
				row := fmt.Sprintf("  %s %s %s %s %s %s", styledPad(dimStyle.Render(truncate(e.DstAddr, 16)), 18), styledPad(rs.Render(fmt.Sprintf("%.1fms", e.AvgRTTMs)), 10), styledPad(dimStyle.Render(fmt.Sprintf("%.1fms", e.MinRTTMs)), 10), styledPad(dimStyle.Render(fmt.Sprintf("%.1fms", e.MaxRTTMs)), 10), styledPad(dimStyle.Render(fmt.Sprintf("%d", e.Samples)), 8), valueStyle.Render(truncate(e.TopComm, 12)))
				sb.WriteString(boxRow(row, innerW) + "\n")
			}
			sb.WriteString(boxBot(innerW) + "\n\n")
		}
	}

	// TCP connect latency
	if hdr := renderProbeSectionHeader("TCP Connect Latency", len(f.TCPConnLat) > 0, len(f.TCPConnLat), cursor == probSecTCPConnLat, expanded[probSecTCPConnLat]); hdr != "" {
		sb.WriteString(hdr)
		if expanded[probSecTCPConnLat] {
			sb.WriteString(boxTop(innerW) + "\n")
			hdrLine := fmt.Sprintf("  %s %s %s %s %s %s", styledPad(dimStyle.Render("PID"), 8), styledPad(dimStyle.Render("CMD"), 14), styledPad(dimStyle.Render("DEST"), 16), styledPad(dimStyle.Render("AVG"), 10), styledPad(dimStyle.Render("MAX"), 10), dimStyle.Render("COUNT"))
			sb.WriteString(boxRow(hdrLine, innerW) + "\n")
			sb.WriteString(boxMid(innerW) + "\n")
			for _, e := range f.TCPConnLat {
				cs := valueStyle
				if e.AvgMs >= 500 { cs = critStyle } else if e.AvgMs >= 100 { cs = warnStyle }
				row := fmt.Sprintf("  %s %s %s %s %s %s", styledPad(dimStyle.Render(fmt.Sprintf("%d", e.PID)), 8), styledPad(valueStyle.Render(truncate(e.Comm, 12)), 14), styledPad(dimStyle.Render(truncate(e.DstAddr, 14)), 16), styledPad(cs.Render(fmt.Sprintf("%.1fms", e.AvgMs)), 10), styledPad(dimStyle.Render(fmt.Sprintf("%.1fms", e.MaxMs)), 10), dimStyle.Render(fmt.Sprintf("%d", e.Count)))
				sb.WriteString(boxRow(row, innerW) + "\n")
			}
			sb.WriteString(boxBot(innerW) + "\n\n")
		}
	}

	// Watchdog: Run Queue Latency
	if hdr := renderProbeSectionHeader("Run Queue Latency (watchdog)", len(f.RunQLat) > 0, len(f.RunQLat), cursor == probSecRunQLat, expanded[probSecRunQLat]); hdr != "" {
		sb.WriteString(hdr)
		if expanded[probSecRunQLat] {
			sb.WriteString(boxTop(innerW) + "\n")
			hdrLine := fmt.Sprintf("  %s %s %s %s %s", styledPad(dimStyle.Render("PID"), 8), styledPad(dimStyle.Render("CMD"), 14), styledPad(dimStyle.Render("AVG"), 10), styledPad(dimStyle.Render("MAX"), 10), dimStyle.Render("COUNT"))
			sb.WriteString(boxRow(hdrLine, innerW) + "\n")
			sb.WriteString(boxMid(innerW) + "\n")
			for _, e := range f.RunQLat {
				rs := valueStyle
				if e.AvgUs >= 1000 { rs = critStyle } else if e.AvgUs >= 100 { rs = warnStyle }
				row := fmt.Sprintf("  %s %s %s %s %s", styledPad(dimStyle.Render(fmt.Sprintf("%d", e.PID)), 8), styledPad(valueStyle.Render(truncate(e.Comm, 12)), 14), styledPad(rs.Render(fmt.Sprintf("%.0fus", e.AvgUs)), 10), styledPad(dimStyle.Render(fmt.Sprintf("%.0fus", e.MaxUs)), 10), dimStyle.Render(fmt.Sprintf("%d", e.Count)))
				sb.WriteString(boxRow(row, innerW) + "\n")
			}
			sb.WriteString(boxBot(innerW) + "\n\n")
		}
	}

	// Watchdog: Writeback Stalls
	if hdr := renderProbeSectionHeader("Writeback Stalls (watchdog)", len(f.WBStall) > 0, len(f.WBStall), cursor == probSecWBStall, expanded[probSecWBStall]); hdr != "" {
		sb.WriteString(hdr)
		if expanded[probSecWBStall] {
			sb.WriteString(boxTop(innerW) + "\n")
			hdrLine := fmt.Sprintf("  %s %s %s %s", styledPad(dimStyle.Render("PID"), 8), styledPad(dimStyle.Render("CMD"), 14), styledPad(dimStyle.Render("STALLS"), 10), dimStyle.Render("PAGES"))
			sb.WriteString(boxRow(hdrLine, innerW) + "\n")
			sb.WriteString(boxMid(innerW) + "\n")
			for _, e := range f.WBStall {
				row := fmt.Sprintf("  %s %s %s %s", styledPad(dimStyle.Render(fmt.Sprintf("%d", e.PID)), 8), styledPad(valueStyle.Render(truncate(e.Comm, 12)), 14), styledPad(warnStyle.Render(fmt.Sprintf("%d", e.Count)), 10), dimStyle.Render(fmt.Sprintf("%d", e.TotalPages)))
				sb.WriteString(boxRow(row, innerW) + "\n")
			}
			sb.WriteString(boxBot(innerW) + "\n\n")
		}
	}

	// Watchdog: Page Fault Latency
	if hdr := renderProbeSectionHeader("Page Fault Latency (watchdog)", len(f.PgFault) > 0, len(f.PgFault), cursor == probSecPgFault, expanded[probSecPgFault]); hdr != "" {
		sb.WriteString(hdr)
		if expanded[probSecPgFault] {
			sb.WriteString(boxTop(innerW) + "\n")
			hdrLine := fmt.Sprintf("  %s %s %s %s %s", styledPad(dimStyle.Render("PID"), 8), styledPad(dimStyle.Render("CMD"), 14), styledPad(dimStyle.Render("AVG"), 10), styledPad(dimStyle.Render("MAJOR"), 8), dimStyle.Render("TOTAL"))
			sb.WriteString(boxRow(hdrLine, innerW) + "\n")
			sb.WriteString(boxMid(innerW) + "\n")
			for _, e := range f.PgFault {
				rs := valueStyle
				if e.MajorCount > 100 { rs = critStyle } else if e.MajorCount > 10 { rs = warnStyle }
				row := fmt.Sprintf("  %s %s %s %s %s", styledPad(dimStyle.Render(fmt.Sprintf("%d", e.PID)), 8), styledPad(valueStyle.Render(truncate(e.Comm, 12)), 14), styledPad(dimStyle.Render(fmt.Sprintf("%.0fus", e.AvgUs)), 10), styledPad(rs.Render(fmt.Sprintf("%d", e.MajorCount)), 8), dimStyle.Render(fmt.Sprintf("%d", e.TotalCount)))
				sb.WriteString(boxRow(row, innerW) + "\n")
			}
			sb.WriteString(boxBot(innerW) + "\n\n")
		}
	}

	// Watchdog: Swap Activity
	if hdr := renderProbeSectionHeader("Swap Activity (watchdog)", len(f.SwapEvict) > 0, len(f.SwapEvict), cursor == probSecSwapEvict, expanded[probSecSwapEvict]); hdr != "" {
		sb.WriteString(hdr)
		if expanded[probSecSwapEvict] {
			sb.WriteString(boxTop(innerW) + "\n")
			hdrLine := fmt.Sprintf("  %s %s %s %s", styledPad(dimStyle.Render("PID"), 8), styledPad(dimStyle.Render("CMD"), 14), styledPad(dimStyle.Render("READ PG"), 10), dimStyle.Render("WRITE PG"))
			sb.WriteString(boxRow(hdrLine, innerW) + "\n")
			sb.WriteString(boxMid(innerW) + "\n")
			for _, e := range f.SwapEvict {
				row := fmt.Sprintf("  %s %s %s %s", styledPad(dimStyle.Render(fmt.Sprintf("%d", e.PID)), 8), styledPad(valueStyle.Render(truncate(e.Comm, 12)), 14), styledPad(warnStyle.Render(fmt.Sprintf("%d", e.ReadPages)), 10), dimStyle.Render(fmt.Sprintf("%d", e.WritePages)))
				sb.WriteString(boxRow(row, innerW) + "\n")
			}
			sb.WriteString(boxBot(innerW) + "\n\n")
		}
	}

	// Watchdog: Syscall Dissection
	if hdr := renderProbeSectionHeader("Syscall Dissection (watchdog)", len(f.SyscallDissect) > 0, len(f.SyscallDissect), cursor == probSecSyscall, expanded[probSecSyscall]); hdr != "" {
		sb.WriteString(hdr)
		if expanded[probSecSyscall] {
			sb.WriteString(boxTop(innerW) + "\n")
			hdrLine := fmt.Sprintf("  %s %s %s", styledPad(dimStyle.Render("PID"), 8), styledPad(dimStyle.Render("CMD"), 14), dimStyle.Render("BREAKDOWN"))
			sb.WriteString(boxRow(hdrLine, innerW) + "\n")
			sb.WriteString(boxMid(innerW) + "\n")
			for _, e := range f.SyscallDissect {
				var parts []string
				for _, g := range e.Breakdown {
					gs := dimStyle
					if g.Group == "lock/sync" && g.TotalPct >= 30 { gs = critStyle } else if g.TotalPct >= 50 { gs = warnStyle }
					parts = append(parts, gs.Render(fmt.Sprintf("%s:%.0f%%", g.Group, g.TotalPct)))
				}
				row := fmt.Sprintf("  %s %s %s", styledPad(dimStyle.Render(fmt.Sprintf("%d", e.PID)), 8), styledPad(valueStyle.Render(truncate(e.Comm, 12)), 14), strings.Join(parts, "  "))
				sb.WriteString(boxRow(row, innerW) + "\n")
			}
			sb.WriteString(boxBot(innerW) + "\n\n")
		}
	}

	// Watchdog: Socket IO Attribution
	if hdr := renderProbeSectionHeader("Socket IO Attribution (watchdog)", len(f.SockIO) > 0, len(f.SockIO), cursor == probSecSockIO, expanded[probSecSockIO]); hdr != "" {
		sb.WriteString(hdr)
		if expanded[probSecSockIO] {
			sb.WriteString(boxTop(innerW) + "\n")
			hdrLine := fmt.Sprintf("  %s %s %s %s %s %s", styledPad(dimStyle.Render("PID"), 8), styledPad(dimStyle.Render("CMD"), 12), styledPad(dimStyle.Render("DEST"), 24), styledPad(dimStyle.Render("TX"), 8), styledPad(dimStyle.Render("RX"), 8), dimStyle.Render("WAIT"))
			sb.WriteString(boxRow(hdrLine, innerW) + "\n")
			sb.WriteString(boxMid(innerW) + "\n")
			for _, e := range f.SockIO {
				dest := e.DstAddr
				if e.Service != "" { dest = fmt.Sprintf("%s (%s)", e.DstAddr, e.Service) }
				ws := dimStyle
				if e.AvgWaitMs >= 50 { ws = critStyle } else if e.AvgWaitMs >= 10 { ws = warnStyle }
				row := fmt.Sprintf("  %s %s %s %s %s %s", styledPad(dimStyle.Render(fmt.Sprintf("%d", e.PID)), 8), styledPad(valueStyle.Render(truncate(e.Comm, 10)), 12), styledPad(dimStyle.Render(truncate(dest, 22)), 24), styledPad(dimStyle.Render(formatProbeBytes(e.TxBytes)), 8), styledPad(dimStyle.Render(formatProbeBytes(e.RxBytes)), 8), ws.Render(fmt.Sprintf("%.0fms", e.AvgWaitMs)))
				sb.WriteString(boxRow(row, innerW) + "\n")
			}
			sb.WriteString(boxBot(innerW) + "\n")
		}
	}

	return sb.String()
}

// formatProbeBytes formats bytes into a human-readable string (KB/MB/GB).
func formatProbeBytes(b uint64) string {
	switch {
	case b >= 1<<30:
		return fmt.Sprintf("%.1fGB", float64(b)/(1<<30))
	case b >= 1<<20:
		return fmt.Sprintf("%.1fMB", float64(b)/(1<<20))
	case b >= 1<<10:
		return fmt.Sprintf("%.1fKB", float64(b)/(1<<10))
	default:
		return fmt.Sprintf("%dB", b)
	}
}
