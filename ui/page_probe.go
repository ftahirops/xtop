package ui

import (
	"fmt"
	"strings"

	"github.com/ftahirops/xtop/engine"
)

// renderProbePage renders the full probe investigation page (page 8).
func renderProbePage(pm *engine.ProbeManager, width, height int) string {
	var sb strings.Builder

	if pm == nil {
		sb.WriteString(titleStyle.Render(" PROBE INVESTIGATION"))
		sb.WriteString("\n\n")
		sb.WriteString(dimStyle.Render("  Probe engine not available."))
		sb.WriteString("\n")
		return sb.String()
	}

	state := pm.State()

	switch state {
	case engine.ProbeIdle:
		sb.WriteString(renderProbeIdle(width))
	case engine.ProbeRunning:
		sb.WriteString(renderProbeRunning(pm, width))
	case engine.ProbeDone:
		sb.WriteString(renderProbeDone(pm, width))
	}

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
		dimStyle.Render("Trace off-CPU wait stacks (futex, IO, sleep)")), innerW) + "\n")
	sb.WriteString(boxRow(fmt.Sprintf("  %s  %s",
		styledPad(valueStyle.Render("iolatency"), 14),
		dimStyle.Render("Block IO latency histograms per device")), innerW) + "\n")
	sb.WriteString(boxRow(fmt.Sprintf("  %s  %s",
		styledPad(valueStyle.Render("lockwait"), 14),
		dimStyle.Render("Lock contention (futex, rwsem, mutex)")), innerW) + "\n")
	sb.WriteString(boxRow(fmt.Sprintf("  %s  %s",
		styledPad(valueStyle.Render("tcpretrans"), 14),
		dimStyle.Render("TCP retransmit tracing per connection")), innerW) + "\n")
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

func renderProbeDone(pm *engine.ProbeManager, width int) string {
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
	sb.WriteString("\n")

	innerW := width - 7
	if innerW < 50 {
		innerW = 50
	}
	if innerW > 90 {
		innerW = 90
	}

	// Off-CPU waiters
	if len(f.OffCPUWaiters) > 0 {
		sb.WriteString(titleStyle.Render(" Off-CPU (Top waiters)"))
		sb.WriteString("\n")
		sb.WriteString(boxTop(innerW) + "\n")
		hdr := fmt.Sprintf("  %s %s %s %s",
			styledPad(dimStyle.Render("PID"), 8),
			styledPad(dimStyle.Render("CMD"), 14),
			styledPad(dimStyle.Render("WAIT%"), 8),
			dimStyle.Render("REASON"))
		sb.WriteString(boxRow(hdr, innerW) + "\n")
		sb.WriteString(boxMid(innerW) + "\n")
		for _, e := range f.OffCPUWaiters {
			ws := valueStyle
			if e.WaitPct >= 50 {
				ws = critStyle
			} else if e.WaitPct >= 30 {
				ws = warnStyle
			}
			row := fmt.Sprintf("  %s %s %s %s",
				styledPad(dimStyle.Render(fmt.Sprintf("%d", e.PID)), 8),
				styledPad(valueStyle.Render(truncate(e.Comm, 12)), 14),
				styledPad(ws.Render(fmt.Sprintf("%.1f%%", e.WaitPct)), 8),
				dimStyle.Render(e.Reason))
			sb.WriteString(boxRow(row, innerW) + "\n")
		}
		sb.WriteString(boxBot(innerW) + "\n\n")
	}

	// IO latency
	if len(f.IOLatency) > 0 {
		sb.WriteString(titleStyle.Render(" Block IO Latency"))
		sb.WriteString("\n")
		sb.WriteString(boxTop(innerW) + "\n")
		hdr := fmt.Sprintf("  %s %s %s %s %s",
			styledPad(dimStyle.Render("DEV"), 12),
			styledPad(dimStyle.Render("p50"), 10),
			styledPad(dimStyle.Render("p95"), 10),
			styledPad(dimStyle.Render("p99"), 10),
			dimStyle.Render("UTIL"))
		sb.WriteString(boxRow(hdr, innerW) + "\n")
		sb.WriteString(boxMid(innerW) + "\n")
		for _, e := range f.IOLatency {
			p95s := valueStyle
			if e.P95Ms >= 50 {
				p95s = critStyle
			} else if e.P95Ms >= 20 {
				p95s = warnStyle
			}
			row := fmt.Sprintf("  %s %s %s %s %s",
				styledPad(valueStyle.Render(truncate(e.Device, 10)), 12),
				styledPad(dimStyle.Render(fmt.Sprintf("%.1fms", e.P50Ms)), 10),
				styledPad(p95s.Render(fmt.Sprintf("%.1fms", e.P95Ms)), 10),
				styledPad(critStyle.Render(fmt.Sprintf("%.1fms", e.P99Ms)), 10),
				dimStyle.Render(fmt.Sprintf("%.0f%%", e.UtilPct)))
			sb.WriteString(boxRow(row, innerW) + "\n")
		}
		sb.WriteString(boxBot(innerW) + "\n\n")
	}

	// Lock waits
	if len(f.LockWaiters) > 0 {
		sb.WriteString(titleStyle.Render(" Lock Waits"))
		sb.WriteString("\n")
		sb.WriteString(boxTop(innerW) + "\n")
		hdr := fmt.Sprintf("  %s %s %s %s",
			styledPad(dimStyle.Render("PID"), 8),
			styledPad(dimStyle.Render("CMD"), 14),
			styledPad(dimStyle.Render("WAIT%"), 8),
			dimStyle.Render("LOCK TYPE"))
		sb.WriteString(boxRow(hdr, innerW) + "\n")
		sb.WriteString(boxMid(innerW) + "\n")
		for _, e := range f.LockWaiters {
			ws := valueStyle
			if e.WaitPct >= 50 {
				ws = critStyle
			} else if e.WaitPct >= 30 {
				ws = warnStyle
			}
			row := fmt.Sprintf("  %s %s %s %s",
				styledPad(dimStyle.Render(fmt.Sprintf("%d", e.PID)), 8),
				styledPad(valueStyle.Render(truncate(e.Comm, 12)), 14),
				styledPad(ws.Render(fmt.Sprintf("%.1f%%", e.WaitPct)), 8),
				dimStyle.Render(e.LockType))
			sb.WriteString(boxRow(row, innerW) + "\n")
		}
		sb.WriteString(boxBot(innerW) + "\n\n")
	}

	// TCP retransmits
	if len(f.TCPRetrans) > 0 {
		sb.WriteString(titleStyle.Render(" TCP Retransmits"))
		sb.WriteString("\n")
		sb.WriteString(boxTop(innerW) + "\n")
		hdr := fmt.Sprintf("  %s %s %s %s",
			styledPad(dimStyle.Render("PID"), 8),
			styledPad(dimStyle.Render("CMD"), 14),
			styledPad(dimStyle.Render("RETRANS"), 10),
			dimStyle.Render("IFACE"))
		sb.WriteString(boxRow(hdr, innerW) + "\n")
		sb.WriteString(boxMid(innerW) + "\n")
		for _, e := range f.TCPRetrans {
			rs := valueStyle
			if e.Retrans >= 100 {
				rs = critStyle
			} else if e.Retrans >= 30 {
				rs = warnStyle
			}
			row := fmt.Sprintf("  %s %s %s %s",
				styledPad(dimStyle.Render(fmt.Sprintf("%d", e.PID)), 8),
				styledPad(valueStyle.Render(truncate(e.Comm, 12)), 14),
				styledPad(rs.Render(fmt.Sprintf("%d/s", e.Retrans)), 10),
				dimStyle.Render(e.Iface))
			sb.WriteString(boxRow(row, innerW) + "\n")
		}
		sb.WriteString(boxBot(innerW) + "\n\n")
	}

	// Network throughput
	if len(f.NetThroughput) > 0 {
		sb.WriteString(titleStyle.Render(" Network Throughput"))
		sb.WriteString("\n")
		sb.WriteString(boxTop(innerW) + "\n")
		hdr := fmt.Sprintf("  %s %s %s %s %s",
			styledPad(dimStyle.Render("PID"), 8),
			styledPad(dimStyle.Render("CMD"), 14),
			styledPad(dimStyle.Render("TX MB/s"), 10),
			styledPad(dimStyle.Render("RX MB/s"), 10),
			dimStyle.Render("TOTAL"))
		sb.WriteString(boxRow(hdr, innerW) + "\n")
		sb.WriteString(boxMid(innerW) + "\n")
		for _, e := range f.NetThroughput {
			total := e.TxMBs + e.RxMBs
			ts := valueStyle
			if total >= 100 {
				ts = critStyle
			} else if total >= 10 {
				ts = warnStyle
			}
			row := fmt.Sprintf("  %s %s %s %s %s",
				styledPad(dimStyle.Render(fmt.Sprintf("%d", e.PID)), 8),
				styledPad(valueStyle.Render(truncate(e.Comm, 12)), 14),
				styledPad(dimStyle.Render(fmt.Sprintf("%.1f", e.TxMBs)), 10),
				styledPad(dimStyle.Render(fmt.Sprintf("%.1f", e.RxMBs)), 10),
				ts.Render(fmt.Sprintf("%.1f MB/s", total)))
			sb.WriteString(boxRow(row, innerW) + "\n")
		}
		sb.WriteString(boxBot(innerW) + "\n\n")
	}

	// TCP RTT
	if len(f.TCPRTT) > 0 {
		sb.WriteString(titleStyle.Render(" TCP RTT"))
		sb.WriteString("\n")
		sb.WriteString(boxTop(innerW) + "\n")
		hdr := fmt.Sprintf("  %s %s %s %s %s %s",
			styledPad(dimStyle.Render("DEST"), 18),
			styledPad(dimStyle.Render("AVG"), 10),
			styledPad(dimStyle.Render("MIN"), 10),
			styledPad(dimStyle.Render("MAX"), 10),
			styledPad(dimStyle.Render("SAMPLES"), 8),
			dimStyle.Render("PROCESS"))
		sb.WriteString(boxRow(hdr, innerW) + "\n")
		sb.WriteString(boxMid(innerW) + "\n")
		for _, e := range f.TCPRTT {
			rs := valueStyle
			if e.AvgRTTMs >= 50 {
				rs = critStyle
			} else if e.AvgRTTMs >= 10 {
				rs = warnStyle
			}
			row := fmt.Sprintf("  %s %s %s %s %s %s",
				styledPad(dimStyle.Render(truncate(e.DstAddr, 16)), 18),
				styledPad(rs.Render(fmt.Sprintf("%.1fms", e.AvgRTTMs)), 10),
				styledPad(dimStyle.Render(fmt.Sprintf("%.1fms", e.MinRTTMs)), 10),
				styledPad(dimStyle.Render(fmt.Sprintf("%.1fms", e.MaxRTTMs)), 10),
				styledPad(dimStyle.Render(fmt.Sprintf("%d", e.Samples)), 8),
				valueStyle.Render(truncate(e.TopComm, 12)))
			sb.WriteString(boxRow(row, innerW) + "\n")
		}
		sb.WriteString(boxBot(innerW) + "\n\n")
	}

	// TCP connect latency
	if len(f.TCPConnLat) > 0 {
		sb.WriteString(titleStyle.Render(" TCP Connect Latency"))
		sb.WriteString("\n")
		sb.WriteString(boxTop(innerW) + "\n")
		hdr := fmt.Sprintf("  %s %s %s %s %s %s",
			styledPad(dimStyle.Render("PID"), 8),
			styledPad(dimStyle.Render("CMD"), 14),
			styledPad(dimStyle.Render("DEST"), 16),
			styledPad(dimStyle.Render("AVG"), 10),
			styledPad(dimStyle.Render("MAX"), 10),
			dimStyle.Render("COUNT"))
		sb.WriteString(boxRow(hdr, innerW) + "\n")
		sb.WriteString(boxMid(innerW) + "\n")
		for _, e := range f.TCPConnLat {
			cs := valueStyle
			if e.AvgMs >= 500 {
				cs = critStyle
			} else if e.AvgMs >= 100 {
				cs = warnStyle
			}
			row := fmt.Sprintf("  %s %s %s %s %s %s",
				styledPad(dimStyle.Render(fmt.Sprintf("%d", e.PID)), 8),
				styledPad(valueStyle.Render(truncate(e.Comm, 12)), 14),
				styledPad(dimStyle.Render(truncate(e.DstAddr, 14)), 16),
				styledPad(cs.Render(fmt.Sprintf("%.1fms", e.AvgMs)), 10),
				styledPad(dimStyle.Render(fmt.Sprintf("%.1fms", e.MaxMs)), 10),
				dimStyle.Render(fmt.Sprintf("%d", e.Count)))
			sb.WriteString(boxRow(row, innerW) + "\n")
		}
		sb.WriteString(boxBot(innerW) + "\n")
	}

	return sb.String()
}
