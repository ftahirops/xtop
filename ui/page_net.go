package ui

import (
	"fmt"
	"sort"
	"strings"

	"github.com/ftahirops/xtop/model"
)

// defaultEphemeralRange is the Linux default ephemeral port range (32768-60999 = 28232 ports).
const defaultEphemeralRange = 28232

func renderNetPage(snap *model.Snapshot, rates *model.RateSnapshot, result *model.AnalysisResult, pm probeQuerier, width, height int) string {
	var sb strings.Builder
	iw := pageInnerW(width)

	sb.WriteString(titleStyle.Render("NETWORK SUBSYSTEM"))
	sb.WriteString("\n")
	sb.WriteString(renderRCAInline(result))
	sb.WriteString(renderProbeStatusLine(pm, snap))
	sb.WriteString("\n")

	tcp := snap.Global.TCP
	udp := snap.Global.UDP
	sock := snap.Global.Sockets
	st := snap.Global.TCPStates
	ct := snap.Global.Conntrack
	si := snap.Global.SoftIRQ

	// === Network Health ===
	netHealth, netIssues := analyzeNetHealth(snap, rates)
	var healthLines []string
	if netHealth == "OK" {
		healthLines = append(healthLines, okStyle.Render("OK")+" "+dimStyle.Render("\u2014 no issues detected"))
	} else if netHealth == "DEGRADED" {
		healthLines = append(healthLines, warnStyle.Render("DEGRADED"))
	} else {
		healthLines = append(healthLines, critStyle.Render("CRITICAL"))
	}
	shown := 3
	if len(netIssues) < shown {
		shown = len(netIssues)
	}
	for i := 0; i < shown; i++ {
		healthLines = append(healthLines, netIssues[i])
	}
	if len(netIssues) > 3 {
		healthLines = append(healthLines, dimStyle.Render(fmt.Sprintf("  (+%d more issues)", len(netIssues)-3)))
	}
	sb.WriteString(boxSection("NETWORK HEALTH", healthLines, iw))

	// === Throughput ===
	var totalRxMBs, totalTxMBs, totalRxPPS, totalTxPPS float64
	var totalRxDrops, totalTxDrops, totalRxErrors, totalTxErrors float64
	retransR := float64(0)
	resetR := float64(0)
	if rates != nil {
		for _, nr := range rates.NetRates {
			totalRxMBs += nr.RxMBs
			totalTxMBs += nr.TxMBs
			totalRxPPS += nr.RxPPS
			totalTxPPS += nr.TxPPS
			totalRxDrops += nr.RxDropsPS
			totalTxDrops += nr.TxDropsPS
			totalRxErrors += nr.RxErrorsPS
			totalTxErrors += nr.TxErrorsPS
		}
		retransR = rates.RetransRate
		resetR = rates.TCPResetRate
	}

	// Find max link speed for throughput context
	maxSpeedMbps := 0
	for _, iface := range snap.Global.Network {
		if iface.SpeedMbps > maxSpeedMbps {
			maxSpeedMbps = iface.SpeedMbps
		}
	}

	var thrLines []string
	rxTxLine := fmt.Sprintf("RX: %s (%s pps)    TX: %s (%s pps)",
		fmtRate(totalRxMBs), fmtPPS(totalRxPPS),
		fmtRate(totalTxMBs), fmtPPS(totalTxPPS))
	if maxSpeedMbps > 0 {
		totalMBs := totalRxMBs + totalTxMBs
		maxMBs := float64(maxSpeedMbps) / 8
		utilPct := totalMBs / maxMBs * 100
		rxTxLine += dimStyle.Render(fmt.Sprintf("    Total: %s / %s (%.1f%%)",
			fmtRate(totalMBs), fmtRate(maxMBs), utilPct))
	}
	thrLines = append(thrLines, rxTxLine)

	dropLine := fmt.Sprintf("Drops: %.0f/s", totalRxDrops+totalTxDrops)
	errLine := fmt.Sprintf("    Errors: %.0f/s", totalRxErrors+totalTxErrors)
	if totalRxDrops+totalTxDrops > 0 || totalRxErrors+totalTxErrors > 0 {
		thrLines = append(thrLines, warnStyle.Render(dropLine+errLine))
	} else {
		thrLines = append(thrLines, dimStyle.Render(dropLine+errLine))
	}
	thrLines = append(thrLines, fmt.Sprintf("Retransmits: %.0f/s    Resets: %.0f/s", retransR, resetR))
	sb.WriteString(boxSection("THROUGHPUT", thrLines, iw))

	// === Connections ===
	eph := snap.Global.EphemeralPorts
	ephRange := eph.RangeHi - eph.RangeLo + 1
	if ephRange <= 0 {
		ephRange = defaultEphemeralRange
	}
	fdMax := snap.Global.FD.Max
	if fdMax == 0 {
		fdMax = 1048576 // fallback
	}

	totalConns := st.Established + st.SynSent + st.SynRecv + st.FinWait1 + st.FinWait2 +
		st.TimeWait + st.Close + st.CloseWait + st.LastAck + st.Listen + st.Closing

	var connLines []string

	// Capacity context line
	ephUsedPct := float64(eph.InUse) / float64(ephRange) * 100
	fdUsedPct := float64(sock.SocketsUsed) / float64(fdMax) * 100
	capLine := fmt.Sprintf("Total: %d    Ephemeral: %d/%d (%.0f%%)    FDs: %d/%d (%.0f%%)",
		totalConns, eph.InUse, ephRange, ephUsedPct, sock.SocketsUsed, fdMax, fdUsedPct)
	connLines = append(connLines, capLine)

	type connState struct {
		name     string
		count    int
		limit    int    // effective limit for this state
		limName  string // what constrains it
		warn     bool
	}

	// Determine smart limits: outbound states are limited by ephemeral ports,
	// listen by FD, TIME_WAIT by ephemeral (holds port, no FD)
	states := []connState{
		{"ESTABLISHED", st.Established, ephRange, "eph", false},
		{"TIME_WAIT", st.TimeWait, ephRange, "eph", false},
		{"CLOSE_WAIT", st.CloseWait, int(fdMax), "fd", false},
		{"SYN_SENT", st.SynSent, ephRange, "eph", false},
		{"SYN_RECV", st.SynRecv, ephRange, "eph", false},
		{"FIN_WAIT1", st.FinWait1, ephRange, "eph", false},
		{"FIN_WAIT2", st.FinWait2, ephRange, "eph", false},
		{"CLOSING", st.Closing, ephRange, "eph", false},
		{"LAST_ACK", st.LastAck, ephRange, "eph", false},
	}

	// Compute warn thresholds relative to limits
	for i := range states {
		s := &states[i]
		if s.limit > 0 {
			pct := float64(s.count) / float64(s.limit) * 100
			if pct > 5 {
				s.warn = true // using significant portion of limit
			}
		}
		// Hard-coded warnings for known-bad states at any count
		switch s.name {
		case "CLOSE_WAIT":
			if s.count > 100 {
				s.warn = true
			}
		case "SYN_SENT":
			if s.count > 50 {
				s.warn = true
			}
		}
	}

	bw := 15
	for _, s := range states {
		pct := float64(0)
		if s.limit > 0 {
			pct = float64(s.count) / float64(s.limit) * 100
		}
		label := fmt.Sprintf("%-12s %5d ", s.name, s.count)
		barStr := miniBar(pct, bw)
		pctStr := fmt.Sprintf(" %5.1f%% of %s", pct, s.limName)
		if pct > 50 {
			connLines = append(connLines, critStyle.Render(label)+barStr+critStyle.Render(pctStr))
		} else if s.warn {
			connLines = append(connLines, warnStyle.Render(label)+barStr+warnStyle.Render(pctStr))
		} else if s.count == 0 {
			connLines = append(connLines, dimStyle.Render(label)+barStr+dimStyle.Render(pctStr))
		} else {
			connLines = append(connLines, label+barStr+dimStyle.Render(pctStr))
		}
	}

	// Smart warnings relative to actual limits
	if ephRange > 0 {
		twEphPct := float64(eph.TimeWaitIn) / float64(ephRange) * 100
		if twEphPct > 50 {
			connLines = append(connLines, critStyle.Render(fmt.Sprintf(
				"  -> TIME_WAIT holds %.0f%% of ephemeral ports (%d/%d) \u2014 EXHAUSTION IMMINENT",
				twEphPct, eph.TimeWaitIn, ephRange)))
		} else if twEphPct > 20 {
			connLines = append(connLines, warnStyle.Render(fmt.Sprintf(
				"  -> TIME_WAIT holds %.0f%% of ephemeral ports (%d/%d) \u2014 consider tcp_tw_reuse",
				twEphPct, eph.TimeWaitIn, ephRange)))
		}
	}
	if st.CloseWait > 20 {
		cwWarn := fmt.Sprintf("  -> %d CLOSE_WAIT \u2014 app not closing connections (FD leak)", st.CloseWait)
		if len(snap.Global.CloseWaitLeakers) > 0 {
			top := snap.Global.CloseWaitLeakers[0]
			cwWarn = fmt.Sprintf("  -> %d CLOSE_WAIT \u2014 %s (PID %d) holds %d, oldest %s",
				st.CloseWait, top.Comm, top.PID, top.Count, fmtAgeSec(top.OldestAge))
		}
		if st.CloseWait > 500 {
			connLines = append(connLines, critStyle.Render(cwWarn))
		} else {
			connLines = append(connLines, warnStyle.Render(cwWarn))
		}
	}
	if st.SynSent > 50 {
		connLines = append(connLines, warnStyle.Render(fmt.Sprintf(
			"  -> %d SYN_SENT \u2014 outbound connection attempts backing up", st.SynSent)))
	}

	connLines = append(connLines, fmt.Sprintf("Sockets: %d   TCP alloc: %d   Orphans: %d   Listening: %d",
		sock.SocketsUsed, sock.TCPAlloc, sock.TCPOrphan, st.Listen))
	if sock.TCPOrphan > 100 {
		connLines = append(connLines, warnStyle.Render(fmt.Sprintf("  -> %d orphaned TCP sockets", sock.TCPOrphan)))
	}
	sb.WriteString(boxSection("CONNECTIONS", connLines, iw))

	// === CLOSE_WAIT Leakers ===
	if st.CloseWait > 10 && len(snap.Global.CloseWaitLeakers) > 0 {
		var cwLines []string
		trend := snap.Global.CloseWaitTrend
		trendStr := "stable"
		if trend.Growing {
			trendStr = fmt.Sprintf("+%.1f/s growing", trend.GrowthRate)
		} else if trend.GrowthRate < -0.5 {
			trendStr = fmt.Sprintf("%.1f/s draining", trend.GrowthRate)
		}
		cwLines = append(cwLines, fmt.Sprintf("Total: %d CLOSE_WAIT  (%s)", st.CloseWait, trendStr))
		cwLines = append(cwLines, dimStyle.Render(fmt.Sprintf("  %-16s %6s %6s  %8s  %8s",
			"PROCESS", "PID", "COUNT", "OLDEST", "NEWEST")))
		for _, lk := range snap.Global.CloseWaitLeakers {
			name := lk.Comm
			if len(name) > 16 {
				name = name[:13] + "..."
			}
			row := fmt.Sprintf("  %-16s %6d %6d  %8s  %8s",
				name, lk.PID, lk.Count, fmtAgeSec(lk.OldestAge), fmtAgeSec(lk.NewestAge))
			if lk.OldestAge > 300 { // > 5 minutes
				cwLines = append(cwLines, critStyle.Render(row))
			} else if lk.Count > 10 {
				cwLines = append(cwLines, warnStyle.Render(row))
			} else {
				cwLines = append(cwLines, row)
			}
		}
		if len(snap.Global.CloseWaitLeakers) > 0 {
			top := snap.Global.CloseWaitLeakers[0]
			cwLines = append(cwLines, warnStyle.Render(fmt.Sprintf(
				"  -> %s (PID %d) not closing connections", top.Comm, top.PID)))
		}
		sb.WriteString(boxSection("CLOSE_WAIT LEAKERS", cwLines, iw))
	}

	// === Ephemeral Ports ===
	if eph.RangeHi > 0 {
		var ephLines []string
		ephPct := float64(eph.InUse) / float64(ephRange) * 100
		ephLines = append(ephLines, fmt.Sprintf("Range: %d\u2013%d (%d available)", eph.RangeLo, eph.RangeHi, ephRange))

		usageLine := fmt.Sprintf("In Use: %d / %d (%.1f%%)  %s %.1f%%",
			eph.InUse, ephRange, ephPct, miniBar(ephPct, 20), ephPct)
		if ephPct > 80 {
			ephLines = append(ephLines, critStyle.Render(usageLine))
		} else if ephPct > 50 {
			ephLines = append(ephLines, warnStyle.Render(usageLine))
		} else {
			ephLines = append(ephLines, usageLine)
		}

		// Per-state breakdown within ephemeral range
		if eph.InUse > 0 {
			ephLines = append(ephLines, dimStyle.Render(fmt.Sprintf(
				"  ESTABLISHED: %-6d  TIME_WAIT: %-6d  CLOSE_WAIT: %-6d  SYN_SENT: %d",
				eph.EstablishedIn, eph.TimeWaitIn, eph.CloseWaitIn, eph.SynSentIn)))

			twPct := float64(eph.TimeWaitIn) / float64(eph.InUse) * 100
			if twPct > 60 {
				ephLines = append(ephLines, warnStyle.Render(fmt.Sprintf(
					"  TIME_WAIT is %.0f%% of in-use \u2014 ports held 60s after close, consider tcp_tw_reuse", twPct)))
			}
		}

		// Top port users (abusers)
		if len(eph.TopUsers) > 0 {
			ephLines = append(ephLines, "")
			ephLines = append(ephLines, dimStyle.Render(fmt.Sprintf(
				"  %-14s %7s %6s  %6s  %10s  %s",
				"PROCESS", "PID", "PORTS", "ESTAB", "CLOSE_WAIT", "% OF EPH")))
			for _, u := range eph.TopUsers {
				portPct := float64(u.Ports) / float64(ephRange) * 100
				portPctStr := fmt.Sprintf("%.1f%%", portPct)
				row := fmt.Sprintf("  %-14s %7d %6d  %6d  %10d  %s",
					truncate(u.Comm, 14), u.PID, u.Ports, u.Established, u.CloseWait, portPctStr)
				if portPct > 20 {
					ephLines = append(ephLines, critStyle.Render(row))
				} else if portPct > 5 {
					ephLines = append(ephLines, warnStyle.Render(row))
				} else {
					ephLines = append(ephLines, row)
				}
			}
		}
		sb.WriteString(boxSection("EPHEMERAL PORTS", ephLines, iw))
	}

	// === Top Remote IPs ===
	if len(snap.Global.TopRemoteIPs) > 0 {
		var remLines []string
		remLines = append(remLines, dimStyle.Render(fmt.Sprintf("%-18s %6s %6s %10s %10s",
			"REMOTE IP", "TOTAL", "ESTAB", "TIME_WAIT", "CLOSE_WAIT")))
		for _, r := range snap.Global.TopRemoteIPs {
			row := fmt.Sprintf("%-18s %6d %6d %10d %10d",
				model.MaskIP(r.IP), r.Connections, r.Established, r.TimeWait, r.CloseWait)
			if r.TimeWait > 500 || r.CloseWait > 50 {
				remLines = append(remLines, warnStyle.Render(row))
			} else {
				remLines = append(remLines, row)
			}
		}
		sb.WriteString(boxSection("TOP REMOTE IPs", remLines, iw))
	}

	// === Interfaces ===
	var ifLines []string
	if rates != nil && len(rates.NetRates) > 0 {
		ifLines = append(ifLines, dimStyle.Render(fmt.Sprintf("%-16s %5s %6s %7s %10s %10s %6s %8s %8s %7s %7s",
			"INTERFACE", "STATE", "SPEED", "TYPE", "RX", "TX", "UTIL%", "RX pps", "TX pps", "Drops", "Errors")))

		for _, nr := range rates.NetRates {
			drops := nr.RxDropsPS + nr.TxDropsPS
			errors := nr.RxErrorsPS + nr.TxErrorsPS

			// Format state with color
			state := nr.OperState
			stateStr := dimStyle.Render(fmt.Sprintf("%-5s", state))
			if state == "up" {
				stateStr = okStyle.Render(fmt.Sprintf("%-5s", "UP"))
			} else if state == "down" {
				stateStr = critStyle.Render(fmt.Sprintf("%-5s", "DOWN"))
			}

			// Format speed
			speedStr := dimStyle.Render(fmt.Sprintf("%6s", "—"))
			if nr.SpeedMbps > 0 {
				if nr.SpeedMbps >= 1000 {
					speedStr = fmt.Sprintf("%4dG", nr.SpeedMbps/1000)
				} else {
					speedStr = fmt.Sprintf("%4dM", nr.SpeedMbps)
				}
				speedStr = fmt.Sprintf("%6s", speedStr)
			}

			// Format utilization
			utilStr := dimStyle.Render(fmt.Sprintf("%6s", "—"))
			if nr.UtilPct >= 0 {
				utilStr = fmt.Sprintf("%5.1f%%", nr.UtilPct)
				if nr.UtilPct > 90 {
					utilStr = critStyle.Render(utilStr)
				} else if nr.UtilPct > 70 {
					utilStr = warnStyle.Render(utilStr)
				}
			}

			// Format type
			ifType := nr.IfType
			if len(ifType) > 7 {
				ifType = ifType[:7]
			}

			name := nr.Name
			if len(name) > 16 {
				name = name[:13] + "..."
			}

			row := fmt.Sprintf("%-16s %s %s %-7s %10s %10s %s %8s %8s %6.0f/s %6.0f/s",
				name, stateStr, speedStr, ifType,
				fmtRate(nr.RxMBs), fmtRate(nr.TxMBs),
				utilStr,
				fmtPPS(nr.RxPPS), fmtPPS(nr.TxPPS),
				drops, errors)
			if drops > 0 || errors > 0 {
				ifLines = append(ifLines, warnStyle.Render(row))
			} else {
				ifLines = append(ifLines, row)
			}

			// Show master annotation for bridge/bond slaves
			if nr.Master != "" {
				note := fmt.Sprintf("  %s slave of %s — traffic counters may be on master",
					dimStyle.Render("└─"), warnStyle.Render(nr.Master))
				ifLines = append(ifLines, note)
			}
		}
	} else {
		for _, n := range snap.Global.Network {
			state := n.OperState
			master := ""
			if n.Master != "" {
				master = fmt.Sprintf(" [slave of %s]", n.Master)
			}
			ifLines = append(ifLines, fmt.Sprintf("%-14s %-5s  RX: %s (%d pkts)  TX: %s (%d pkts)%s",
				n.Name, state, fmtBytes(n.RxBytes), n.RxPackets, fmtBytes(n.TxBytes), n.TxPackets, master))
		}
	}
	sb.WriteString(boxSection("INTERFACES", ifLines, iw))

	// === Protocol Health ===
	var protoLines []string

	// TCP
	protoLines = append(protoLines, titleStyle.Render("TCP"))
	protoLines = append(protoLines, fmt.Sprintf("  Established: %d   Opens: active=%d passive=%d",
		tcp.CurrEstab, tcp.ActiveOpens, tcp.PassiveOpens))

	retransPct := float64(0)
	if tcp.OutSegs > 0 {
		retransPct = float64(tcp.RetransSegs) / float64(tcp.OutSegs) * 100
	}
	retransLine := fmt.Sprintf("  Retransmit rate: %.3f%%", retransPct)
	if retransPct > 1 {
		protoLines = append(protoLines, critStyle.Render(retransLine))
	} else if retransPct > 0.1 {
		protoLines = append(protoLines, warnStyle.Render(retransLine))
	} else {
		protoLines = append(protoLines, retransLine)
	}

	failLine := fmt.Sprintf("  Failures: attempt=%d resets=%d errors=%d rsts=%d",
		tcp.AttemptFails, tcp.EstabResets, tcp.InErrs, tcp.OutRsts)
	if tcp.AttemptFails > 0 || tcp.EstabResets > 0 || tcp.InErrs > 0 {
		protoLines = append(protoLines, warnStyle.Render(failLine))
	} else {
		protoLines = append(protoLines, dimStyle.Render(failLine))
	}

	inSeg := float64(0)
	outSeg := float64(0)
	softRx := float64(0)
	softTx := float64(0)
	if rates != nil {
		inSeg = rates.InSegRate
		outSeg = rates.OutSegRate
		softRx = rates.SoftIRQNetRxRate
		softTx = rates.SoftIRQNetTxRate
	}
	protoLines = append(protoLines, fmt.Sprintf("  Segment rate: in=%.0f/s out=%.0f/s  SoftIRQ: NET_RX=%.0f/s NET_TX=%.0f/s",
		inSeg, outSeg, softRx, softTx))

	// UDP
	protoLines = append(protoLines, "")
	protoLines = append(protoLines, titleStyle.Render("UDP"))
	protoLines = append(protoLines, fmt.Sprintf("  In use: %d   Datagrams: in=%d out=%d",
		sock.UDPInUse, udp.InDatagrams, udp.OutDatagrams))

	if udp.RcvbufErrors > 0 || udp.SndbufErrors > 0 || udp.InErrors > 0 {
		protoLines = append(protoLines, warnStyle.Render(fmt.Sprintf("  Buffer errors: rcv=%d snd=%d  InErrors=%d  NoPorts=%d",
			udp.RcvbufErrors, udp.SndbufErrors, udp.InErrors, udp.NoPorts)))
	} else {
		protoLines = append(protoLines, dimStyle.Render("  No buffer errors"))
	}
	sb.WriteString(boxSection("PROTOCOL HEALTH", protoLines, iw))

	// === Conntrack ===
	var ctLines []string
	if ct.Max > 0 {
		ctPct := float64(ct.Count) / float64(ct.Max) * 100
		ctLines = append(ctLines, fmt.Sprintf("%s %s (%d / %d)",
			bar(ctPct, 20), fmtPct(ctPct), ct.Count, ct.Max))
		dropStr := fmt.Sprintf("Dropped: %d connections", ct.Drop)
		if ct.Drop > 0 {
			ctLines = append(ctLines, critStyle.Render(dropStr))
		} else {
			ctLines = append(ctLines, dimStyle.Render(dropStr))
		}
		if ctPct > 80 {
			ctLines = append(ctLines, critStyle.Render("-> Table > 80% \u2014 risk of dropped connections"))
		}
	} else {
		ctLines = append(ctLines, dimStyle.Render("Conntrack inactive"))
	}
	sb.WriteString(boxSection("CONNTRACK", ctLines, iw))

	// === Top processes by FD usage ===
	if rates != nil && len(rates.ProcessRates) > 0 {
		fdProcs := make([]model.ProcessRate, len(rates.ProcessRates))
		copy(fdProcs, rates.ProcessRates)
		sort.Slice(fdProcs, func(i, j int) bool {
			return fdProcs[i].FDCount > fdProcs[j].FDCount
		})

		var fdLines []string
		fdLines = append(fdLines, dimStyle.Render(fmt.Sprintf("%-20s %6s %8s %10s %6s",
			"PROCESS", "PID", "FDs", "LIMIT", "USED%")))

		shown := 0
		seen := make(map[string]bool)
		for _, p := range fdProcs {
			if shown >= 10 || p.FDCount == 0 {
				break
			}
			if seen[p.Comm] {
				continue
			}
			seen[p.Comm] = true

			name := p.Comm
			if len(name) > 20 {
				name = name[:17] + "..."
			}
			limitStr := "—"
			pctStr := "—"
			if p.FDSoftLimit > 0 {
				limitStr = fmt.Sprintf("%d", p.FDSoftLimit)
				pctStr = fmt.Sprintf("%.1f%%", p.FDPct)
			}
			row := fmt.Sprintf("%-20s %6d %8d %10s %6s",
				name, p.PID, p.FDCount, limitStr, pctStr)
			if p.FDPct > 80 {
				fdLines = append(fdLines, critStyle.Render(row))
			} else if p.FDPct > 50 {
				fdLines = append(fdLines, warnStyle.Render(row))
			} else {
				fdLines = append(fdLines, row)
			}
			shown++
		}
		if shown > 0 {
			sb.WriteString(boxSection("TOP PROCESSES BY FD USAGE", fdLines, iw))
		}
	}

	// === Top consumers ===
	var consLines []string
	if rates != nil && len(rates.ProcessRates) > 0 {
		procs := make([]model.ProcessRate, len(rates.ProcessRates))
		copy(procs, rates.ProcessRates)
		sort.Slice(procs, func(i, j int) bool {
			return (procs[i].ReadMBs + procs[i].WriteMBs) > (procs[j].ReadMBs + procs[j].WriteMBs)
		})

		consLines = append(consLines, dimStyle.Render(fmt.Sprintf("%-20s %6s %10s %10s %10s %s",
			"PROCESS", "PID", "READ", "WRITE", "TOTAL", "CGROUP")))

		shown := 0
		seen := make(map[string]bool)
		for _, p := range procs {
			if shown >= 10 {
				break
			}
			totalIO := p.ReadMBs + p.WriteMBs
			if totalIO < 0.001 {
				break
			}
			key := p.Comm
			if seen[key] {
				continue
			}
			seen[key] = true

			name := p.Comm
			if len(name) > 20 {
				name = name[:17] + "..."
			}
			cg := p.CgroupPath
			if len(cg) > 25 {
				cg = "..." + cg[len(cg)-22:]
			}
			consLines = append(consLines, fmt.Sprintf("%-20s %6d %10s %10s %10s %s",
				name, p.PID, fmtRate(p.ReadMBs), fmtRate(p.WriteMBs), fmtRate(totalIO), cg))
			shown++
		}
		if shown == 0 {
			consLines = append(consLines, dimStyle.Render("No significant IO activity"))
		}
	} else {
		consLines = append(consLines, dimStyle.Render("(collecting rates...)"))
	}
	sb.WriteString(boxSection("TOP CONSUMERS (by process IO)", consLines, iw))

	// === BPF Sentinel Network ===
	sent := snap.Global.Sentinel
	if sent.Active && (sent.PktDropRate > 0 || sent.TCPResetRate > 0 || sent.RetransRate > 0) {
		var bpfLines []string

		// Packet drops by reason
		if sent.PktDropRate > 0 {
			bpfLines = append(bpfLines, warnStyle.Render(fmt.Sprintf("Packet drops: %.0f/s (BPF kfree_skb)", sent.PktDropRate)))
			for _, d := range sent.PktDrops {
				if d.Rate > 0 {
					bpfLines = append(bpfLines, fmt.Sprintf("  %-24s %6.0f/s", d.ReasonStr, d.Rate))
				}
			}
		}

		// TCP resets by PID
		if sent.TCPResetRate > 0 {
			bpfLines = append(bpfLines, warnStyle.Render(fmt.Sprintf("TCP RSTs: %.0f/s (BPF tcp_send_reset)", sent.TCPResetRate)))
			shown := 0
			for _, r := range sent.TCPResets {
				if shown >= 5 || r.Rate <= 0 {
					break
				}
				bpfLines = append(bpfLines, fmt.Sprintf("  %-16s PID %-6d %6.0f/s  dst=%s", r.Comm, r.PID, r.Rate, r.DstStr))
				shown++
			}
		}

		// Always-on retransmit tracking
		if sent.RetransRate > 0 {
			bpfLines = append(bpfLines, warnStyle.Render(fmt.Sprintf("Retransmits: %.0f/s (BPF sentinel)", sent.RetransRate)))
			shown := 0
			for _, r := range sent.Retransmits {
				if shown >= 5 || r.Rate <= 0 {
					break
				}
				bpfLines = append(bpfLines, fmt.Sprintf("  %-16s PID %-6d %6.1f/s  dst=%s", r.Comm, r.PID, r.Rate, r.DstStr))
				shown++
			}
		}

		sb.WriteString(boxSection("BPF SENTINEL NETWORK", bpfLines, iw))
	}

	// === Kernel SoftIRQ ===
	var kernLines []string
	kernLines = append(kernLines, fmt.Sprintf("SoftIRQ totals:  NET_RX=%s  NET_TX=%s  BLOCK=%s",
		fmtLargeNum(si.NET_RX), fmtLargeNum(si.NET_TX), fmtLargeNum(si.BLOCK)))
	softIRQPct := float64(0)
	if rates != nil {
		softIRQPct = rates.CPUSoftIRQPct
	}
	softIRQLine := fmt.Sprintf("CPU SoftIRQ: %5.1f%%", softIRQPct)
	if softIRQPct > 5 {
		kernLines = append(kernLines, warnStyle.Render(softIRQLine+" \u2014 high kernel overhead"))
	} else {
		kernLines = append(kernLines, softIRQLine)
	}
	sb.WriteString(boxSection("KERNEL NETWORK PROCESSING", kernLines, iw))

	return sb.String()
}

// analyzeNetHealth produces a health verdict and list of issue strings.
func analyzeNetHealth(snap *model.Snapshot, rates *model.RateSnapshot) (string, []string) {
	health := "OK"
	var issues []string

	st := snap.Global.TCPStates
	ct := snap.Global.Conntrack
	udp := snap.Global.UDP
	sock := snap.Global.Sockets

	// Retransmits
	if rates != nil && rates.RetransRate > 50 {
		health = "CRITICAL"
		issues = append(issues, critStyle.Render(fmt.Sprintf("!! High retransmit rate: %.0f/s", rates.RetransRate)))
	} else if rates != nil && rates.RetransRate > 10 {
		health = setWorst(health, "DEGRADED")
		issues = append(issues, warnStyle.Render(fmt.Sprintf("!  Elevated retransmits: %.0f/s", rates.RetransRate)))
	}

	// Drops
	if rates != nil {
		var totalDrops float64
		for _, nr := range rates.NetRates {
			totalDrops += nr.RxDropsPS + nr.TxDropsPS
		}
		if totalDrops > 100 {
			health = "CRITICAL"
			issues = append(issues, critStyle.Render(fmt.Sprintf("!! Packet drops: %.0f/s", totalDrops)))
		} else if totalDrops > 0 {
			health = setWorst(health, "DEGRADED")
			issues = append(issues, warnStyle.Render(fmt.Sprintf("!  Packet drops detected: %.0f/s", totalDrops)))
		}
	}

	// TIME_WAIT accumulation
	if st.TimeWait > 5000 {
		health = setWorst(health, "DEGRADED")
		issues = append(issues, warnStyle.Render(fmt.Sprintf("!  TIME_WAIT sockets: %d — port exhaustion risk", st.TimeWait)))
	}

	// CLOSE_WAIT leak
	if st.CloseWait > 500 {
		health = "CRITICAL"
		cwIssue := fmt.Sprintf("!! CLOSE_WAIT: %d — application connection leak", st.CloseWait)
		if len(snap.Global.CloseWaitLeakers) > 0 {
			top := snap.Global.CloseWaitLeakers[0]
			cwIssue = fmt.Sprintf("!! CLOSE_WAIT: %d — %s (PID %d) holds %d, oldest %s",
				st.CloseWait, top.Comm, top.PID, top.Count, fmtAgeSec(top.OldestAge))
		}
		issues = append(issues, critStyle.Render(cwIssue))
	} else if st.CloseWait > 100 {
		health = setWorst(health, "DEGRADED")
		cwIssue := fmt.Sprintf("!  CLOSE_WAIT: %d — application connection leak", st.CloseWait)
		if len(snap.Global.CloseWaitLeakers) > 0 {
			top := snap.Global.CloseWaitLeakers[0]
			cwIssue = fmt.Sprintf("!  CLOSE_WAIT: %d — %s (PID %d) holds %d, oldest %s",
				st.CloseWait, top.Comm, top.PID, top.Count, fmtAgeSec(top.OldestAge))
		}
		issues = append(issues, warnStyle.Render(cwIssue))
	}

	// Conntrack table pressure
	if ct.Max > 0 {
		ctPct := float64(ct.Count) / float64(ct.Max) * 100
		if ctPct > 90 {
			health = "CRITICAL"
			issues = append(issues, critStyle.Render(fmt.Sprintf("!! Conntrack table %.0f%% full — connections will be dropped", ctPct)))
		} else if ctPct > 70 {
			health = setWorst(health, "DEGRADED")
			issues = append(issues, warnStyle.Render(fmt.Sprintf("!  Conntrack table %.0f%% full", ctPct)))
		}
	}

	// UDP buffer errors
	if udp.RcvbufErrors > 0 {
		health = setWorst(health, "DEGRADED")
		issues = append(issues, warnStyle.Render(fmt.Sprintf("!  UDP receive buffer overflows: %d", udp.RcvbufErrors)))
	}

	// Orphan sockets
	if sock.TCPOrphan > 200 {
		health = setWorst(health, "DEGRADED")
		issues = append(issues, warnStyle.Render(fmt.Sprintf("!  Orphaned TCP sockets: %d", sock.TCPOrphan)))
	}

	// BPF sentinel network signals
	sentData := snap.Global.Sentinel
	if sentData.Active {
		if sentData.PktDropRate > 100 {
			health = "CRITICAL"
			issues = append(issues, critStyle.Render(fmt.Sprintf("!! BPF packet drops: %.0f/s (kfree_skb)", sentData.PktDropRate)))
		} else if sentData.PktDropRate > 10 {
			health = setWorst(health, "DEGRADED")
			issues = append(issues, warnStyle.Render(fmt.Sprintf("!  BPF packet drops: %.0f/s", sentData.PktDropRate)))
		}
		if sentData.TCPResetRate > 50 {
			health = "CRITICAL"
			issues = append(issues, critStyle.Render(fmt.Sprintf("!! BPF TCP RSTs: %.0f/s", sentData.TCPResetRate)))
		} else if sentData.TCPResetRate > 5 {
			health = setWorst(health, "DEGRADED")
			issues = append(issues, warnStyle.Render(fmt.Sprintf("!  BPF TCP RSTs: %.0f/s", sentData.TCPResetRate)))
		}
	}

	// SoftIRQ overhead
	if rates != nil && rates.CPUSoftIRQPct > 15 {
		health = setWorst(health, "DEGRADED")
		issues = append(issues, warnStyle.Render(fmt.Sprintf("!  High SoftIRQ CPU: %.1f%%", rates.CPUSoftIRQPct)))
	}

	return health, issues
}

func setWorst(current, candidate string) string {
	order := map[string]int{"OK": 0, "DEGRADED": 1, "CRITICAL": 2}
	if order[candidate] > order[current] {
		return candidate
	}
	return current
}

// miniBar renders a small bar for connection state visualization.
func miniBar(pct float64, width int) string {
	if width < 1 {
		width = 10
	}
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
	b := strings.Repeat("█", filled) + strings.Repeat("░", width-filled)
	return dimStyle.Render(b)
}

// fmtPPS formats packets-per-second for display.
func fmtPPS(pps float64) string {
	if pps >= 1_000_000 {
		return fmt.Sprintf("%.1fM", pps/1_000_000)
	}
	if pps >= 1000 {
		return fmt.Sprintf("%.1fK", pps/1000)
	}
	return fmt.Sprintf("%.0f", pps)
}

// fmtAgeSec formats seconds as a human-readable duration (e.g. "23m", "1h12m", "45s").
func fmtAgeSec(seconds int) string {
	if seconds < 60 {
		return fmt.Sprintf("%ds", seconds)
	}
	if seconds < 3600 {
		return fmt.Sprintf("%dm", seconds/60)
	}
	h := seconds / 3600
	m := (seconds % 3600) / 60
	if m == 0 {
		return fmt.Sprintf("%dh", h)
	}
	return fmt.Sprintf("%dh%dm", h, m)
}

// fmtLargeNum formats large cumulative counters for display.
func fmtLargeNum(n uint64) string {
	if n >= 1_000_000_000 {
		return fmt.Sprintf("%.1fB", float64(n)/1_000_000_000)
	}
	if n >= 1_000_000 {
		return fmt.Sprintf("%.1fM", float64(n)/1_000_000)
	}
	if n >= 1000 {
		return fmt.Sprintf("%.1fK", float64(n)/1000)
	}
	return fmt.Sprintf("%d", n)
}
