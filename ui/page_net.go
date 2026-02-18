package ui

import (
	"fmt"
	"sort"
	"strings"

	"github.com/ftahirops/xtop/model"
)

func renderNetPage(snap *model.Snapshot, rates *model.RateSnapshot, result *model.AnalysisResult, pm probeQuerier, width, height int) string {
	var sb strings.Builder
	iw := pageInnerW(width)

	sb.WriteString(titleStyle.Render("NETWORK SUBSYSTEM"))
	sb.WriteString("\n")
	sb.WriteString(renderRCAInline(result))
	sb.WriteString(renderProbeStatusLine(pm))
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
	for i := 0; i < 3; i++ {
		if i < len(netIssues) {
			healthLines = append(healthLines, netIssues[i])
		}
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

	var thrLines []string
	thrLines = append(thrLines, fmt.Sprintf("RX: %s (%s pps)    TX: %s (%s pps)",
		fmtRate(totalRxMBs), fmtPPS(totalRxPPS),
		fmtRate(totalTxMBs), fmtPPS(totalTxPPS)))

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
	totalConns := st.Established + st.SynSent + st.SynRecv + st.FinWait1 + st.FinWait2 +
		st.TimeWait + st.Close + st.CloseWait + st.LastAck + st.Listen + st.Closing

	var connLines []string
	connLines = append(connLines, fmt.Sprintf("Total: %d    Active: %d    Listening: %d",
		totalConns, st.Established, st.Listen))

	type connState struct {
		name  string
		count int
		warn  bool
	}
	states := []connState{
		{"ESTABLISHED", st.Established, false},
		{"TIME_WAIT", st.TimeWait, st.TimeWait > 1000},
		{"CLOSE_WAIT", st.CloseWait, st.CloseWait > 100},
		{"SYN_SENT", st.SynSent, st.SynSent > 50},
		{"SYN_RECV", st.SynRecv, st.SynRecv > 100},
		{"FIN_WAIT1", st.FinWait1, st.FinWait1 > 50},
		{"FIN_WAIT2", st.FinWait2, st.FinWait2 > 50},
		{"CLOSING", st.Closing, false},
		{"LAST_ACK", st.LastAck, false},
	}

	bw := 15
	for _, s := range states {
		pct := float64(0)
		if totalConns > 0 {
			pct = float64(s.count) / float64(totalConns) * 100
		}
		label := fmt.Sprintf("%-12s %5d ", s.name, s.count)
		barStr := miniBar(pct, bw)
		pctStr := fmt.Sprintf(" %5.1f%%", pct)
		if s.warn {
			connLines = append(connLines, warnStyle.Render(label)+barStr+warnStyle.Render(pctStr))
		} else if s.count == 0 {
			connLines = append(connLines, dimStyle.Render(label)+barStr+dimStyle.Render(pctStr))
		} else {
			connLines = append(connLines, label+barStr+dimStyle.Render(pctStr))
		}
	}

	connWarnings := []string{}
	if st.TimeWait > 1000 {
		connWarnings = append(connWarnings, warnStyle.Render(fmt.Sprintf("  -> %d TIME_WAIT \u2014 possible port exhaustion risk", st.TimeWait)))
	}
	if st.CloseWait > 100 {
		connWarnings = append(connWarnings, warnStyle.Render(fmt.Sprintf("  -> %d CLOSE_WAIT \u2014 app not closing connections", st.CloseWait)))
	}
	if st.SynSent > 50 {
		connWarnings = append(connWarnings, warnStyle.Render(fmt.Sprintf("  -> %d SYN_SENT \u2014 outbound connection attempts backing up", st.SynSent)))
	}
	for _, w := range connWarnings {
		connLines = append(connLines, w)
	}

	connLines = append(connLines, fmt.Sprintf("Sockets in use: %d   TCP alloc: %d   Orphans: %d",
		sock.SocketsUsed, sock.TCPAlloc, sock.TCPOrphan))
	if sock.TCPOrphan > 100 {
		connLines = append(connLines, warnStyle.Render(fmt.Sprintf("  -> %d orphaned TCP sockets", sock.TCPOrphan)))
	}
	sb.WriteString(boxSection("CONNECTIONS", connLines, iw))

	// === Interfaces ===
	var ifLines []string
	if rates != nil && len(rates.NetRates) > 0 {
		ifLines = append(ifLines, dimStyle.Render(fmt.Sprintf("%-16s %5s %6s %7s %10s %10s %8s %8s %7s %7s",
			"INTERFACE", "STATE", "SPEED", "TYPE", "RX", "TX", "RX pps", "TX pps", "Drops", "Errors")))

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

			// Format type
			ifType := nr.IfType
			if len(ifType) > 7 {
				ifType = ifType[:7]
			}

			name := nr.Name
			if len(name) > 16 {
				name = name[:13] + "..."
			}

			row := fmt.Sprintf("%-16s %s %s %-7s %10s %10s %8s %8s %6.0f/s %6.0f/s",
				name, stateStr, speedStr, ifType,
				fmtRate(nr.RxMBs), fmtRate(nr.TxMBs),
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
	if st.CloseWait > 100 {
		health = setWorst(health, "DEGRADED")
		issues = append(issues, warnStyle.Render(fmt.Sprintf("!  CLOSE_WAIT: %d — application connection leak", st.CloseWait)))
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
