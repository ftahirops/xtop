package ui

import (
	"fmt"
	"sort"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/ftahirops/xtop/model"
)

// defaultEphemeralRange is the Linux default ephemeral port range (32768-60999 = 28232 ports).
const defaultEphemeralRange = 28232

// ──────────────────────────────────────────────────────────────────────────────
// Network Page — Collapsible Section Architecture
// ──────────────────────────────────────────────────────────────────────────────

// Network page section constants
const (
	netSecQuality     = 0
	netSecConnections = 1
	netSecConntrack   = 2
	netSecTraffic     = 3
	netSecProcesses   = 4
	netSecTalkers     = 5
	netSecCount       = 6
)

// netSectionNames are the display titles for each collapsible section.
var netSectionNames = [netSecCount]string{
	"NETWORK QUALITY",
	"CONNECTIONS & SOCKETS",
	"CONNTRACK INTELLIGENCE",
	"TRAFFIC & THROUGHPUT",
	"PROCESSES",
	"TOP TALKERS",
}

// renderNetPage renders the network page with collapsible sections.
func renderNetPage(snap *model.Snapshot, rates *model.RateSnapshot,
	result *model.AnalysisResult, pm probeQuerier,
	pinnedSummary string, resolvedAgo int,
	cursor int, expanded [netSecCount]bool, focusMode bool,
	width, height int) string {

	var sb strings.Builder
	iw := pageInnerW(width)

	sb.WriteString(titleStyle.Render("NETWORK SUBSYSTEM"))
	sb.WriteString("\n")

	// RCA Summary box (always visible)
	sb.WriteString(renderNetRCASummary(snap, rates, result, pinnedSummary, resolvedAgo, iw))

	// Network Intelligence Summary (always visible — full correlation engine)
	if pinnedSummary != "" {
		sb.WriteString(pinnedSummary)
		if resolvedAgo > 0 {
			remaining := 60 - resolvedAgo
			if remaining > 0 {
				sb.WriteString(dimStyle.Render(fmt.Sprintf(
					"  Pinned %ds ago \u2014 holding for review (%ds remaining)", resolvedAgo, remaining)) + "\n")
			}
		}
	} else if netHasFindings(snap, rates) {
		sb.WriteString(buildNetIntelligenceSummary(snap, rates, result, iw))
	}

	// Focus mode: only show RCA summary + intelligence + key hint
	if focusMode {
		sb.WriteString(dimStyle.Render("  F:exit focus  C:collapse all  j/k:navigate  Enter:expand") + "\n")
		return sb.String()
	}

	// Summary functions for collapsed headers
	summaryFuncs := [netSecCount]func() string{
		func() string { return netQualitySummary(snap, rates, pm) },
		func() string { return netConnectionsSummary(snap) },
		func() string { return netConntrackSummary(snap) },
		func() string { return netTrafficSummary(snap, rates) },
		func() string { return netProcessesSummary(snap, rates) },
		func() string { return netTalkersSummary(snap) },
	}

	// Render functions for expanded content
	renderFuncs := [netSecCount]func() string{
		func() string { return renderNetQualityContent(snap, rates, pm, iw) },
		func() string { return renderNetConnectionsContent(snap, rates, iw) },
		func() string { return renderConntrackIntelligence(snap, rates, iw) },
		func() string { return renderNetTrafficContent(snap, rates, iw) },
		func() string { return renderNetProcessesContent(snap, rates, iw) },
		func() string { return renderNetTalkersContent(snap, iw) },
	}

	// Render each section
	for i := 0; i < netSecCount; i++ {
		header := renderNetSectionHeader(netSectionNames[i], summaryFuncs[i](), i == cursor, expanded[i], iw)
		sb.WriteString(header)
		if expanded[i] {
			sb.WriteString(renderFuncs[i]())
		}
	}

	// Key hint line
	sb.WriteString(dimStyle.Render("  Tab:section  j/k:scroll  Enter:expand/collapse  A:all  C:collapse  F:focus") + "\n")

	return sb.String()
}

// renderNetSectionHeader renders a collapsible section header line.
func renderNetSectionHeader(title, summary string, selected, expanded bool, iw int) string {
	arrow := "\u25b6" // ▶
	if expanded {
		arrow = "\u25bc" // ▼
	}

	titlePart := fmt.Sprintf("%s %s", arrow, title)

	if selected {
		// Bright cyan + bold for selected
		style := lipgloss.NewStyle().Foreground(lipgloss.Color("14")).Bold(true)
		titlePart = style.Render(titlePart)
	} else {
		titlePart = titleStyle.Render(titlePart)
	}

	titleW := lipgloss.Width(titlePart)

	// Truncate summary to fit
	maxSumW := iw - titleW - 4
	if maxSumW < 10 {
		return titlePart + "\n"
	}
	if lipgloss.Width(summary) > maxSumW {
		// Simple truncation
		runes := []rune(summary)
		if len(runes) > maxSumW-3 {
			summary = string(runes[:maxSumW-3]) + "..."
		}
	}

	gap := 4
	return titlePart + strings.Repeat(" ", gap) + dimStyle.Render(summary) + "\n"
}

// ──────────────────────────────────────────────────────────────────────────────
// RCA Summary Box — always visible at top of network page
// ──────────────────────────────────────────────────────────────────────────────

func renderNetRCASummary(snap *model.Snapshot, rates *model.RateSnapshot,
	result *model.AnalysisResult, pinnedSummary string, resolvedAgo int, iw int) string {

	intel := computeNetIntel(snap, rates, result)

	var lines []string

	// Pinned summary takes priority
	if resolvedAgo > 0 && pinnedSummary != "" {
		remaining := 60 - resolvedAgo
		if remaining > 0 {
			// Show pinned status with decay badge
			lines = append(lines, warnStyle.Render("STATUS: RECOVERED")+
				dimStyle.Render(fmt.Sprintf("  (resolved %ds ago \u2014 %ds remaining)", resolvedAgo, remaining)))
			lines = append(lines, "")
			lines = append(lines, dimStyle.Render("Pinned findings from last incident:"))
			lines = append(lines, dimStyle.Render("  "+intel.primary+" \u2014 "+intel.confidence+" confidence"))
			return boxSection("NETWORK SUMMARY", lines, iw)
		}
	}

	health, _ := analyzeNetHealth(snap, rates)

	// STATUS line
	switch health {
	case "OK":
		lines = append(lines, okStyle.Render("STATUS: OK"))
	case "DEGRADED":
		lines = append(lines, warnStyle.Render("STATUS: DEGRADED"))
	case "CRITICAL":
		lines = append(lines, critStyle.Render("STATUS: CRITICAL"))
	}

	// Advisory for ctSocketMismatch
	if health == "OK" && intel.ctSocketMismatch {
		lines = append(lines, dimStyle.Render("ADVISORY: conntrack state anomaly (low impact)"))
	}

	// CLASSIFICATION lines for DEGRADED/CRITICAL
	if health != "OK" {
		renderV := func(label, sev, reason string) string {
			var vs string
			switch sev {
			case "CRITICAL":
				vs = critStyle.Render(sev)
			case "DEGRADED":
				vs = warnStyle.Render(sev)
			default:
				vs = okStyle.Render(sev)
			}
			line := fmt.Sprintf("  %-12s %s", label+":", vs)
			if reason != "" {
				line += "  \u2014 " + reason
			}
			return line
		}
		lines = append(lines, "")
		lines = append(lines, renderV("NET", intel.netSev, intel.netReason))
		lines = append(lines, renderV("APP", intel.appSev, intel.appReason))
		lines = append(lines, renderV("KERN", intel.kernSev, intel.kernReason))
		if intel.primary != "INCONCLUSIVE" {
			lines = append(lines, fmt.Sprintf("  Primary: %s  Confidence: %s", intel.primary, intel.confidence))
		}
	}

	lines = append(lines, "")

	// KEY SIGNALS checklist
	lines = append(lines, "KEY SIGNALS:")

	// Latency
	if intel.connLatMax <= 50 {
		lines = append(lines, okStyle.Render("  \u2714")+" Latency normal")
	} else {
		lines = append(lines, critStyle.Render("  \u2718")+fmt.Sprintf(" Latency: p95=%.0fms avg=%.0fms", intel.connLatMax, intel.connLatAvg))
	}

	// Packet loss
	if intel.retransRate < 10 && intel.sigDrops < 10 {
		lines = append(lines, okStyle.Render("  \u2714")+" No packet loss")
	} else {
		lines = append(lines, critStyle.Render("  \u2718")+fmt.Sprintf(" Retransmits: %.0f/s  Drops: %.0f/s", intel.retransRate, intel.sigDrops))
	}

	// Socket leaks
	if intel.procCW < 100 {
		lines = append(lines, okStyle.Render("  \u2714")+" No socket leaks")
	} else {
		lines = append(lines, critStyle.Render("  \u2718")+fmt.Sprintf(" CLOSE_WAIT: %d sockets", intel.procCW))
	}

	// Conntrack
	ct := snap.Global.Conntrack
	if ct.Max > 0 {
		if intel.ctUsagePct < 60 {
			lines = append(lines, okStyle.Render("  \u2714")+fmt.Sprintf(" Conntrack usage low (%.0f%%)", intel.ctUsagePct))
		} else {
			lines = append(lines, critStyle.Render("  \u2718")+fmt.Sprintf(" Conntrack usage: %.0f%% (%d/%d)", intel.ctUsagePct, ct.Count, ct.Max))
		}
	} else {
		lines = append(lines, dimStyle.Render("  - Conntrack inactive"))
	}

	lines = append(lines, "")
	lines = append(lines, dimStyle.Render(fmt.Sprintf("Confidence: %s  Sources: %s", intel.confidence, intel.sourcesStr)))

	// Top action for DEGRADED/CRITICAL
	if health != "OK" {
		topAction := netTopAction(snap, rates, intel)
		if topAction != "" {
			lines = append(lines, warnStyle.Render("ACTION: ")+topAction)
		}
	}

	return boxSection("NETWORK SUMMARY", lines, iw)
}

// netTopAction returns the single most important action for the current network state.
func netTopAction(snap *model.Snapshot, rates *model.RateSnapshot, intel netIntelResult) string {
	ct := snap.Global.Conntrack
	switch intel.primary {
	case "APPLICATION":
		if intel.procCW >= 20 && len(snap.Global.CloseWaitLeakers) > 0 {
			top := snap.Global.CloseWaitLeakers[0]
			return fmt.Sprintf("Fix socket leak in %s (PID %d)", top.Comm, top.PID)
		}
	case "NETWORK":
		if intel.retransRate >= 10 {
			return "Check network path: NIC errors, switch congestion, MTU mismatch"
		}
	case "KERNEL":
		if intel.ctInsertFail > 0 || intel.ctUsagePct > 85 {
			return fmt.Sprintf("Increase conntrack max (currently %d)", ct.Max)
		}
	}
	if intel.connLatMax > 200 {
		return fmt.Sprintf("Investigate connect latency: %s \u2192 %s (%.0fms)", intel.connLatComm, intel.connLatDst, intel.connLatMax)
	}
	return ""
}

// ──────────────────────────────────────────────────────────────────────────────
// Collapsed summary line functions — one-liner for each section header
// ──────────────────────────────────────────────────────────────────────────────

func netQualitySummary(snap *model.Snapshot, rates *model.RateSnapshot, pm probeQuerier) string {
	retrans := float64(0)
	var drops float64
	if rates != nil {
		retrans = rates.RetransRate
		for _, nr := range rates.NetRates {
			drops += nr.RxDropsPS + nr.TxDropsPS
		}
	}
	latStr := "OK"
	sent := snap.Global.Sentinel
	if sent.Active {
		for _, cl := range sent.ConnLatency {
			if cl.MaxMs > 50 {
				latStr = fmt.Sprintf("%.0fms", cl.MaxMs)
				break
			}
		}
	}
	return fmt.Sprintf("retrans: %.1f/s  drops: %.0f/s  latency: %s", retrans, drops, latStr)
}

func netConnectionsSummary(snap *model.Snapshot) string {
	st := snap.Global.TCPStates
	return fmt.Sprintf("ESTAB: %d  TW: %d  CW: %d", st.Established, st.TimeWait, st.CloseWait)
}

func netConntrackSummary(snap *model.Snapshot) string {
	ct := snap.Global.Conntrack
	if ct.Max == 0 {
		return "inactive"
	}
	pct := float64(ct.Count) / float64(ct.Max) * 100
	maxStr := fmtLargeNum(uint64(ct.Max))
	return fmt.Sprintf("%.1f%% (%d/%s)", pct, ct.Count, maxStr)
}

func netTrafficSummary(snap *model.Snapshot, rates *model.RateSnapshot) string {
	var rxMBs, txMBs float64
	if rates != nil {
		for _, nr := range rates.NetRates {
			rxMBs += nr.RxMBs
			txMBs += nr.TxMBs
		}
	}
	return fmt.Sprintf("RX: %s  TX: %s", fmtRate(rxMBs), fmtRate(txMBs))
}

func netProcessesSummary(snap *model.Snapshot, rates *model.RateSnapshot) string {
	if rates == nil || len(rates.ProcessRates) == 0 {
		return "no data"
	}
	procs := make([]model.ProcessRate, len(rates.ProcessRates))
	copy(procs, rates.ProcessRates)
	sort.Slice(procs, func(i, j int) bool {
		return procs[i].FDCount > procs[j].FDCount
	})
	if len(procs) > 0 && procs[0].FDCount > 0 {
		fdStr := fmtLargeNum(uint64(procs[0].FDCount))
		return fmt.Sprintf("Top FD: %s (%s)", procs[0].Comm, fdStr)
	}
	return "no significant FD usage"
}

func netTalkersSummary(snap *model.Snapshot) string {
	if len(snap.Global.TopRemoteIPs) == 0 {
		return "no data"
	}
	top := snap.Global.TopRemoteIPs[0]
	s := fmt.Sprintf("%s (%s)", model.MaskIP(top.IP), fmtLargeNum(uint64(top.Connections)))
	if len(snap.Global.TopRemoteIPs) > 1 {
		r2 := snap.Global.TopRemoteIPs[1]
		s += fmt.Sprintf("  %s (%s)", model.MaskIP(r2.IP), fmtLargeNum(uint64(r2.Connections)))
	}
	return s
}

// ──────────────────────────────────────────────────────────────────────────────
// Section content render functions — full expanded content for each section
// ──────────────────────────────────────────────────────────────────────────────

func renderNetQualityContent(snap *model.Snapshot, rates *model.RateSnapshot, pm probeQuerier, iw int) string {
	var sb strings.Builder
	tcp := snap.Global.TCP
	udp := snap.Global.UDP
	sock := snap.Global.Sockets
	sent := snap.Global.Sentinel

	// Retransmit/drop/reset rates
	retransR := float64(0)
	resetR := float64(0)
	var totalRxDrops, totalTxDrops, totalRxErrors, totalTxErrors float64
	if rates != nil {
		for _, nr := range rates.NetRates {
			totalRxDrops += nr.RxDropsPS
			totalTxDrops += nr.TxDropsPS
			totalRxErrors += nr.RxErrorsPS
			totalTxErrors += nr.TxErrorsPS
		}
		retransR = rates.RetransRate
		resetR = rates.TCPResetRate
	}

	var thrLines []string
	dropLine := fmt.Sprintf("Drops: %.0f/s", totalRxDrops+totalTxDrops)
	errLine := fmt.Sprintf("    Errors: %.0f/s", totalRxErrors+totalTxErrors)
	if totalRxDrops+totalTxDrops > 0 || totalRxErrors+totalTxErrors > 0 {
		thrLines = append(thrLines, warnStyle.Render(dropLine+errLine))
	} else {
		thrLines = append(thrLines, dimStyle.Render(dropLine+errLine))
	}
	thrLines = append(thrLines, fmt.Sprintf("Retransmits: %.0f/s    Resets: %.0f/s", retransR, resetR))
	sb.WriteString(boxSection("RETRANSMITS & DROPS", thrLines, iw))

	// Protocol health (TCP)
	var protoLines []string
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

	// BPF Sentinel (drops, resets, retransmits)
	if sent.Active {
		var bpfLines []string
		bpfLines = append(bpfLines, fmt.Sprintf("Packet drops: %.0f/s (BPF kfree_skb)", sent.PktDropRate))
		dropShown := 0
		for _, d := range sent.PktDrops {
			if dropShown >= 3 || d.Rate <= 0 {
				break
			}
			if noiseBPFDropReasons[d.ReasonStr] {
				bpfLines = append(bpfLines, dimStyle.Render(fmt.Sprintf("  %-24s %6.0f/s  (benign)", d.ReasonStr, d.Rate)))
			} else {
				bpfLines = append(bpfLines, warnStyle.Render(fmt.Sprintf("  %-24s %6.0f/s", d.ReasonStr, d.Rate)))
			}
			dropShown++
		}
		bpfLines = padTo(bpfLines, 4)

		bpfLines = append(bpfLines, fmt.Sprintf("TCP RSTs: %.0f/s (BPF tcp_send_reset)", sent.TCPResetRate))
		rstShown := 0
		for _, r := range sent.TCPResets {
			if rstShown >= 3 || r.Rate <= 0 {
				break
			}
			bpfLines = append(bpfLines, fmt.Sprintf("  %-16s PID %-6d %6.0f/s  dst=%s", r.Comm, r.PID, r.Rate, r.DstStr))
			rstShown++
		}
		bpfLines = padTo(bpfLines, 8)

		bpfLines = append(bpfLines, fmt.Sprintf("Retransmits: %.0f/s (BPF sentinel)", sent.RetransRate))
		retShown := 0
		for _, r := range sent.Retransmits {
			if retShown >= 3 || r.Rate <= 0 {
				break
			}
			bpfLines = append(bpfLines, fmt.Sprintf("  %-16s PID %-6d %6.1f/s  dst=%s", r.Comm, r.PID, r.Rate, r.DstStr))
			retShown++
		}
		bpfLines = padTo(bpfLines, 12)
		sb.WriteString(boxSection("BPF SENTINEL NETWORK", bpfLines, iw))
	}

	return sb.String()
}

func renderNetConnectionsContent(snap *model.Snapshot, rates *model.RateSnapshot, iw int) string {
	var sb strings.Builder
	st := snap.Global.TCPStates
	sock := snap.Global.Sockets
	eph := snap.Global.EphemeralPorts

	ephRange := eph.RangeHi - eph.RangeLo + 1
	if ephRange <= 0 {
		ephRange = defaultEphemeralRange
	}
	fdMax := snap.Global.FD.Max
	if fdMax == 0 {
		fdMax = 1048576
	}

	totalConns := st.Established + st.SynSent + st.SynRecv + st.FinWait1 + st.FinWait2 +
		st.TimeWait + st.Close + st.CloseWait + st.LastAck + st.Listen + st.Closing

	var connLines []string
	ephUsedPct := float64(eph.InUse) / float64(ephRange) * 100
	fdUsedPct := float64(sock.SocketsUsed) / float64(fdMax) * 100
	capLine := fmt.Sprintf("Total: %d    Ephemeral: %d/%d (%.0f%%)    FDs: %d/%d (%.0f%%)",
		totalConns, eph.InUse, ephRange, ephUsedPct, sock.SocketsUsed, fdMax, fdUsedPct)
	connLines = append(connLines, capLine)

	type connState struct {
		name    string
		count   int
		limit   int
		limName string
		warn    bool
	}

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

	for i := range states {
		s := &states[i]
		if s.limit > 0 {
			pct := float64(s.count) / float64(s.limit) * 100
			if pct > 5 {
				s.warn = true
			}
		}
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

	// CLOSE_WAIT Leakers
	{
		var cwLines []string
		if st.CloseWait > 10 && len(snap.Global.CloseWaitLeakers) > 0 {
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
			shown := 0
			for _, lk := range snap.Global.CloseWaitLeakers {
				if shown >= 5 {
					break
				}
				name := lk.Comm
				if len(name) > 16 {
					name = name[:13] + "..."
				}
				row := fmt.Sprintf("  %-16s %6d %6d  %8s  %8s",
					name, lk.PID, lk.Count, fmtAgeSec(lk.OldestAge), fmtAgeSec(lk.NewestAge))
				if lk.OldestAge > 300 {
					cwLines = append(cwLines, critStyle.Render(row))
				} else if lk.Count > 10 {
					cwLines = append(cwLines, warnStyle.Render(row))
				} else {
					cwLines = append(cwLines, row)
				}
				shown++
			}
			top := snap.Global.CloseWaitLeakers[0]
			cwLines = append(cwLines, warnStyle.Render(fmt.Sprintf(
				"  -> %s (PID %d) not closing connections", top.Comm, top.PID)))
		} else {
			cwLines = append(cwLines, dimStyle.Render("No significant CLOSE_WAIT leakers"))
		}
		cwLines = padTo(cwLines, 8)
		sb.WriteString(boxSection("CLOSE_WAIT LEAKERS", cwLines, iw))
	}

	// Ephemeral Ports
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

		ephLines = append(ephLines, "")
		ephLines = append(ephLines, dimStyle.Render(fmt.Sprintf(
			"  %-14s %7s %6s  %6s  %10s  %s",
			"PROCESS", "PID", "PORTS", "ESTAB", "CLOSE_WAIT", "% OF EPH")))
		userShown := 0
		for _, u := range eph.TopUsers {
			if userShown >= 5 {
				break
			}
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
			userShown++
		}
		ephLines = padTo(ephLines, 11)
		sb.WriteString(boxSection("EPHEMERAL PORTS", ephLines, iw))
	}

	return sb.String()
}

func renderNetTrafficContent(snap *model.Snapshot, rates *model.RateSnapshot, iw int) string {
	var sb strings.Builder
	si := snap.Global.SoftIRQ

	// Total RX/TX
	var totalRxMBs, totalTxMBs, totalRxPPS, totalTxPPS float64
	if rates != nil {
		for _, nr := range rates.NetRates {
			totalRxMBs += nr.RxMBs
			totalTxMBs += nr.TxMBs
			totalRxPPS += nr.RxPPS
			totalTxPPS += nr.TxPPS
		}
	}

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
	sb.WriteString(boxSection("THROUGHPUT", thrLines, iw))

	// Interfaces
	var ifLines []string
	if rates != nil && len(rates.NetRates) > 0 {
		ifLines = append(ifLines, dimStyle.Render(fmt.Sprintf("%-16s %5s %6s %7s %10s %10s %6s %8s %8s %7s %7s",
			"INTERFACE", "STATE", "SPEED", "TYPE", "RX", "TX", "UTIL%", "RX pps", "TX pps", "Drops", "Errors")))

		for _, nr := range rates.NetRates {
			drops := nr.RxDropsPS + nr.TxDropsPS
			errors := nr.RxErrorsPS + nr.TxErrorsPS

			state := nr.OperState
			stateStr := dimStyle.Render(fmt.Sprintf("%-5s", state))
			if state == "up" {
				stateStr = okStyle.Render(fmt.Sprintf("%-5s", "UP"))
			} else if state == "down" {
				stateStr = critStyle.Render(fmt.Sprintf("%-5s", "DOWN"))
			}

			speedStr := dimStyle.Render(fmt.Sprintf("%6s", "\u2014"))
			if nr.SpeedMbps > 0 {
				if nr.SpeedMbps >= 1000 {
					speedStr = fmt.Sprintf("%4dG", nr.SpeedMbps/1000)
				} else {
					speedStr = fmt.Sprintf("%4dM", nr.SpeedMbps)
				}
				speedStr = fmt.Sprintf("%6s", speedStr)
			}

			utilStr := dimStyle.Render(fmt.Sprintf("%6s", "\u2014"))
			if nr.UtilPct >= 0 {
				utilStr = fmt.Sprintf("%5.1f%%", nr.UtilPct)
				if nr.UtilPct > 90 {
					utilStr = critStyle.Render(utilStr)
				} else if nr.UtilPct > 70 {
					utilStr = warnStyle.Render(utilStr)
				}
			}

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

			if nr.Master != "" {
				note := fmt.Sprintf("  %s slave of %s \u2014 traffic counters may be on master",
					dimStyle.Render("\u2514\u2500"), warnStyle.Render(nr.Master))
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

	// Kernel SoftIRQ
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

func renderNetProcessesContent(snap *model.Snapshot, rates *model.RateSnapshot, iw int) string {
	var sb strings.Builder

	// Top processes by FD usage
	{
		var fdLines []string
		fdLines = append(fdLines, dimStyle.Render(fmt.Sprintf("%-20s %6s %8s %10s %6s",
			"PROCESS", "PID", "FDs", "LIMIT", "USED%")))

		if rates != nil && len(rates.ProcessRates) > 0 {
			fdProcs := make([]model.ProcessRate, len(rates.ProcessRates))
			copy(fdProcs, rates.ProcessRates)
			sort.Slice(fdProcs, func(i, j int) bool {
				return fdProcs[i].FDCount > fdProcs[j].FDCount
			})

			shown := 0
			seen := make(map[string]bool)
			for _, p := range fdProcs {
				if shown >= 5 || p.FDCount == 0 {
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
				limitStr := "\u2014"
				pctStr := "\u2014"
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
		}
		fdLines = padTo(fdLines, 6)
		sb.WriteString(boxSection("TOP PROCESSES BY FD USAGE", fdLines, iw))
	}

	// Top consumers by IO
	{
		var consLines []string
		consLines = append(consLines, dimStyle.Render(fmt.Sprintf("%-20s %6s %10s %10s %10s %s",
			"PROCESS", "PID", "READ", "WRITE", "TOTAL", "CGROUP")))

		if rates != nil && len(rates.ProcessRates) > 0 {
			procs := make([]model.ProcessRate, len(rates.ProcessRates))
			copy(procs, rates.ProcessRates)
			sort.Slice(procs, func(i, j int) bool {
				return (procs[i].ReadMBs + procs[i].WriteMBs) > (procs[j].ReadMBs + procs[j].WriteMBs)
			})

			shown := 0
			seen := make(map[string]bool)
			for _, p := range procs {
				if shown >= 5 {
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
		}
		consLines = padTo(consLines, 6)
		sb.WriteString(boxSection("TOP CONSUMERS (by process IO)", consLines, iw))
	}

	return sb.String()
}

func renderNetTalkersContent(snap *model.Snapshot, iw int) string {
	var remLines []string
	remLines = append(remLines, dimStyle.Render(fmt.Sprintf("%-18s %6s %6s %10s %10s",
		"REMOTE IP", "TOTAL", "ESTAB", "TIME_WAIT", "CLOSE_WAIT")))
	shown := 0
	for _, r := range snap.Global.TopRemoteIPs {
		if shown >= 5 {
			break
		}
		row := fmt.Sprintf("%-18s %6d %6d %10d %10d",
			model.MaskIP(r.IP), r.Connections, r.Established, r.TimeWait, r.CloseWait)
		if r.TimeWait > 500 || r.CloseWait > 50 {
			remLines = append(remLines, warnStyle.Render(row))
		} else {
			remLines = append(remLines, row)
		}
		shown++
	}
	remLines = padTo(remLines, 6)
	return boxSection("TOP REMOTE IPs", remLines, iw)
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

	// Conntrack kernel failure rates
	if rates != nil {
		if rates.ConntrackInsertFailRate > 0 {
			health = "CRITICAL"
			issues = append(issues, critStyle.Render(fmt.Sprintf("!! Conntrack insert failures: %.1f/s — table rejecting flows", rates.ConntrackInsertFailRate)))
		}
		if rates.ConntrackDropRate > 0 {
			if rates.ConntrackDropRate > 10 {
				health = "CRITICAL"
			} else {
				health = setWorst(health, "DEGRADED")
			}
			issues = append(issues, critStyle.Render(fmt.Sprintf("!! Conntrack drops: %.0f/s", rates.ConntrackDropRate)))
		}
		if rates.ConntrackGrowthRate > 1000 {
			health = setWorst(health, "DEGRADED")
			issues = append(issues, warnStyle.Render(fmt.Sprintf("!  Conntrack growth: +%.0f/s", rates.ConntrackGrowthRate)))
		}
		if rates.ConntrackSearchRestartRate > 5000 {
			health = setWorst(health, "DEGRADED")
			issues = append(issues, warnStyle.Render(fmt.Sprintf("!  Conntrack hash contention: %.0f/s search_restart", rates.ConntrackSearchRestartRate)))
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

// padTo pads a string slice to at least n entries with empty lines.
// Prevents UI height jumping when "top N" tables have variable row counts.
func padTo(lines []string, n int) []string {
	for len(lines) < n {
		lines = append(lines, "")
	}
	return lines
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

// renderConntrackIntelligence produces the full conntrack intelligence panel.
func renderConntrackIntelligence(snap *model.Snapshot, rates *model.RateSnapshot, iw int) string {
	ct := snap.Global.Conntrack
	if ct.Max == 0 {
		return boxSection("CONNTRACK INTELLIGENCE", []string{dimStyle.Render("Conntrack inactive")}, iw)
	}

	var lines []string

	// ─── §1 CAPACITY & PRESSURE ───
	lines = append(lines, dimStyle.Render("─── CAPACITY & PRESSURE ───"))
	ctPct := float64(ct.Count) / float64(ct.Max) * 100
	barStr := bar(ctPct, 20)
	capText := fmt.Sprintf(" %.1f%%  (%d / %d)", ctPct, ct.Count, ct.Max)
	if ct.Buckets > 0 {
		capText += fmt.Sprintf("   Buckets: %d", ct.Buckets)
	}
	switch {
	case ctPct > 80:
		lines = append(lines, barStr+critStyle.Render(capText))
	case ctPct > 60:
		lines = append(lines, barStr+warnStyle.Render(capText))
	default:
		lines = append(lines, barStr+capText)
	}

	if rates != nil {
		dropStr := fmt.Sprintf("Drops: %.0f/s", rates.ConntrackDropRate)
		failStr := fmt.Sprintf("InsertFail: %.1f/s", rates.ConntrackInsertFailRate)
		earlyStr := fmt.Sprintf("EarlyDrop: %.0f/s", rates.ConntrackEarlyDropRate)
		failLine := fmt.Sprintf("  %s       %s      %s", dropStr, failStr, earlyStr)
		if rates.ConntrackDropRate > 0 || rates.ConntrackInsertFailRate > 0 {
			lines = append(lines, critStyle.Render(failLine))
		} else {
			lines = append(lines, dimStyle.Render(failLine))
		}

		growthSign := "+"
		if rates.ConntrackGrowthRate < 0 {
			growthSign = ""
		}
		growthLine := fmt.Sprintf("  Growth: %s%.0f/s  (new=%.0f/s  close=%.0f/s)",
			growthSign, rates.ConntrackGrowthRate, rates.ConntrackInsertRate, rates.ConntrackDeleteRate)

		// ETA-to-full
		if rates.ConntrackGrowthRate > 0 && ct.Max > ct.Count {
			etaSec := float64(ct.Max-ct.Count) / rates.ConntrackGrowthRate
			growthLine += fmt.Sprintf("   ETA full: %s", fmtETADuration(etaSec))
		} else {
			growthLine += "   ETA full: stable"
		}
		if rates.ConntrackGrowthRate > 100 {
			lines = append(lines, warnStyle.Render(growthLine))
		} else {
			lines = append(lines, growthLine)
		}
	}

	// ─── §2 STATE DISTRIBUTION (fixed 8 rows — all standard TCP states always shown) ───
	lines = append(lines, "")
	lines = append(lines, dimStyle.Render("─── STATE DISTRIBUTION ───"))

	dissect := snap.Global.ConntrackDissect
	type stateRow struct {
		name  string
		count int
	}

	// Always show all 8 standard states for stable height
	stdStates := []string{"ESTABLISHED", "TIME_WAIT", "CLOSE_WAIT", "SYN_SENT", "SYN_RECV", "FIN_WAIT1", "FIN_WAIT2", "LAST_ACK"}
	stateMap := make(map[string]int)

	if dissect.Available && len(dissect.CTStates) > 0 {
		for state, cnt := range dissect.CTStates {
			stateMap[state] = cnt
		}
	} else {
		st2 := snap.Global.TCPStates
		stateMap["ESTABLISHED"] = st2.Established
		stateMap["TIME_WAIT"] = st2.TimeWait
		stateMap["CLOSE_WAIT"] = st2.CloseWait
		stateMap["SYN_SENT"] = st2.SynSent
		stateMap["SYN_RECV"] = st2.SynRecv
		stateMap["FIN_WAIT1"] = st2.FinWait1
		stateMap["FIN_WAIT2"] = st2.FinWait2
		stateMap["LAST_ACK"] = st2.LastAck
	}

	// Build rows from standard states, sorted by count descending
	var stateRows []stateRow
	for _, name := range stdStates {
		stateRows = append(stateRows, stateRow{name, stateMap[name]})
	}
	sort.Slice(stateRows, func(i, j int) bool {
		return stateRows[i].count > stateRows[j].count
	})

	stateTotal := 0
	for _, sr := range stateRows {
		stateTotal += sr.count
	}
	if stateTotal == 0 {
		stateTotal = 1
	}
	for _, sr := range stateRows {
		pct := float64(sr.count) / float64(stateTotal) * 100
		stBar := miniBar(pct, 20)
		row := fmt.Sprintf("  %-14s %6d  %s %5.1f%%", sr.name, sr.count, stBar, pct)
		if (sr.name == "CLOSE_WAIT" && sr.count > 100) ||
			(sr.name == "TIME_WAIT" && sr.count > 5000) ||
			(sr.name == "SYN_SENT" && sr.count > 50) {
			if sr.name == "CLOSE_WAIT" && sr.count > 500 {
				lines = append(lines, critStyle.Render(row))
			} else {
				lines = append(lines, warnStyle.Render(row))
			}
		} else if sr.count == 0 {
			lines = append(lines, dimStyle.Render(row))
		} else {
			lines = append(lines, row)
		}
	}

	// ─── §3 LIFECYCLE RATES ───
	if rates != nil {
		lines = append(lines, "")
		lines = append(lines, dimStyle.Render("─── LIFECYCLE RATES ───"))
		growthSign := "+"
		if rates.ConntrackGrowthRate < 0 {
			growthSign = ""
		}
		lcLine := fmt.Sprintf("  New: %.0f/s     Close: %.0f/s      Net growth: %s%.0f/s",
			rates.ConntrackInsertRate, rates.ConntrackDeleteRate, growthSign, rates.ConntrackGrowthRate)
		if rates.ConntrackGrowthRate > 100 {
			lines = append(lines, warnStyle.Render(lcLine))
		} else {
			lines = append(lines, lcLine)
		}
		invLine := fmt.Sprintf("  Invalid: %.0f/s   SearchRestart: %.0f/s",
			rates.ConntrackInvalidRate, rates.ConntrackSearchRestartRate)
		if rates.ConntrackSearchRestartRate > 100 {
			lines = append(lines, warnStyle.Render(invLine))
		} else {
			lines = append(lines, invLine)
		}
	}

	// ─── §4 ERROR INDICATORS ───
	if rates != nil {
		var errLines []string
		if rates.ConntrackDropRate > 0 {
			errLines = append(errLines, critStyle.Render(fmt.Sprintf(
				"  !! Conntrack drops: %.0f/s \u2014 table full, connections rejected", rates.ConntrackDropRate)))
		}
		if rates.ConntrackInsertFailRate > 0 {
			errLines = append(errLines, critStyle.Render(fmt.Sprintf(
				"  !! Insert failures: %.1f/s \u2014 new flows being denied", rates.ConntrackInsertFailRate)))
		}
		if rates.ConntrackEarlyDropRate > 0 {
			errLines = append(errLines, warnStyle.Render(fmt.Sprintf(
				"  !  Early drops: %.0f/s \u2014 evicting entries before timeout", rates.ConntrackEarlyDropRate)))
		}
		if rates.ConntrackInvalidRate > 0 {
			errLines = append(errLines, warnStyle.Render(fmt.Sprintf(
				"  !  Invalid packets: %.0f/s \u2014 check routing / LB config", rates.ConntrackInvalidRate)))
		}
		if rates.ConntrackSearchRestartRate > 0 {
			errLines = append(errLines, warnStyle.Render(fmt.Sprintf(
				"  !  Hash contention: %.0f/s \u2014 search_restart spike, check buckets sizing", rates.ConntrackSearchRestartRate)))
		}
		if len(errLines) > 0 {
			lines = append(lines, "")
			lines = append(lines, dimStyle.Render("─── ERROR INDICATORS ───"))
			lines = append(lines, errLines...)
		}
	}

	// ─── §5 TOP TALKERS (fixed 5 rows) ───
	lines = append(lines, "")
	lines = append(lines, dimStyle.Render("─── TOP TALKERS ───"))
	if dissect.Available {
		lines = append(lines, dimStyle.Render(fmt.Sprintf("  %-20s %6s    %-20s %6s",
			"SOURCE IP", "CONNS", "DESTINATION IP", "CONNS")))
		for i := 0; i < 5; i++ {
			srcIP, srcC, dstIP, dstC := "", "", "", ""
			if i < len(dissect.TopSrcIPs) {
				srcIP = model.MaskIP(dissect.TopSrcIPs[i].IP)
				srcC = fmt.Sprintf("%d", dissect.TopSrcIPs[i].Count)
			}
			if i < len(dissect.TopDstIPs) {
				dstIP = model.MaskIP(dissect.TopDstIPs[i].IP)
				dstC = fmt.Sprintf("%d", dissect.TopDstIPs[i].Count)
			}
			lines = append(lines, fmt.Sprintf("  %-20s %6s    %-20s %6s",
				srcIP, srcC, dstIP, dstC))
		}
	} else {
		lines = append(lines, dimStyle.Render(fmt.Sprintf("  %-20s %6s", "REMOTE IP", "CONNS")))
		for i := 0; i < 5; i++ {
			if i < len(snap.Global.TopRemoteIPs) {
				r := snap.Global.TopRemoteIPs[i]
				lines = append(lines, fmt.Sprintf("  %-20s %6d", model.MaskIP(r.IP), r.Connections))
			} else {
				lines = append(lines, "")
			}
		}
	}

	// ─── §6 PROTOCOL SPLIT ───
	if dissect.Available && dissect.TotalParsed > 0 {
		lines = append(lines, "")
		lines = append(lines, dimStyle.Render("─── PROTOCOL SPLIT ───"))
		total := dissect.TotalParsed
		tcpPct := float64(dissect.TCPCount) / float64(total) * 100
		udpPct := float64(dissect.UDPCount) / float64(total) * 100
		icmpPct := float64(dissect.ICMPCount) / float64(total) * 100
		otherPct := float64(dissect.OtherCount) / float64(total) * 100
		protoLine := fmt.Sprintf("  TCP: %d (%.1f%%)  UDP: %d (%.1f%%)  ICMP: %d (%.1f%%)  Other: %d (%.1f%%)",
			dissect.TCPCount, tcpPct, dissect.UDPCount, udpPct,
			dissect.ICMPCount, icmpPct, dissect.OtherCount, otherPct)
		if tcpPct > 95 || udpPct > 95 {
			lines = append(lines, warnStyle.Render(protoLine))
		} else {
			lines = append(lines, protoLine)
		}
	}

	// ─── §7 CONNECTION AGE ───
	if dissect.Available && dissect.TotalParsed > 0 {
		lines = append(lines, "")
		lines = append(lines, dimStyle.Render("─── CONNECTION AGE ───"))
		total := dissect.TotalParsed
		lt10Pct := float64(dissect.AgeLt10s) / float64(total) * 100
		s60Pct := float64(dissect.Age10s60s) / float64(total) * 100
		m5Pct := float64(dissect.Age1m5m) / float64(total) * 100
		gt5Pct := float64(dissect.AgeGt5m) / float64(total) * 100
		ageLine := fmt.Sprintf("  <10s: %d (%.1f%%)  10s-60s: %d (%.1f%%)  1m-5m: %d (%.1f%%)  >5m: %d (%.1f%%)",
			dissect.AgeLt10s, lt10Pct, dissect.Age10s60s, s60Pct,
			dissect.Age1m5m, m5Pct, dissect.AgeGt5m, gt5Pct)
		if lt10Pct > 50 {
			lines = append(lines, warnStyle.Render(ageLine+" \u2014 high churn"))
		} else {
			lines = append(lines, ageLine)
		}
	}

	// ─── §8 TIMEOUT CONFIG ───
	to := snap.Global.ConntrackTimeouts
	if to.Available {
		lines = append(lines, "")
		lines = append(lines, dimStyle.Render("─── TIMEOUT CONFIG ───"))
		estabStr := fmt.Sprintf("%ds", to.Established)
		if to.Established >= 86400 {
			estabStr = fmt.Sprintf("%ds (%dd)", to.Established, to.Established/86400)
		}
		toLine := fmt.Sprintf("  ESTABLISHED: %s  TIME_WAIT: %ds  CLOSE_WAIT: %ds  SYN_SENT: %ds",
			estabStr, to.TimeWait, to.CloseWait, to.SynSent)
		lines = append(lines, toLine)
		if to.Established > 86400 {
			lines = append(lines, warnStyle.Render(fmt.Sprintf(
				"  !! ESTABLISHED timeout=%dd \u2014 reduce to 1-2h for high-churn servers", to.Established/86400)))
		}
	}

	// ─── §9 DIAGNOSIS (fixed 4 rows) ───
	lines = append(lines, "")
	lines = append(lines, dimStyle.Render("─── DIAGNOSIS ───"))
	diagLines := conntrackDiagnosis(snap, rates)
	diagLines = padTo(diagLines, 3) // at least 3 rows for stable height
	lines = append(lines, diagLines...)

	return boxSection("CONNTRACK INTELLIGENCE", lines, iw)
}

// conntrackDiagnosis returns plain-English diagnosis lines + "Run:" suggestions.
func conntrackDiagnosis(snap *model.Snapshot, rates *model.RateSnapshot) []string {
	ct := snap.Global.Conntrack
	dissect := snap.Global.ConntrackDissect
	var ctPct float64
	if ct.Max > 0 {
		ctPct = float64(ct.Count) / float64(ct.Max) * 100
	}

	var result []string

	// Helper for "Run:" command suggestions
	addCmd := func(cmd string) {
		result = append(result, dimStyle.Render("  Run: "+cmd))
	}

	matched := false

	// 1. Table exhaustion
	if rates != nil && (rates.ConntrackInsertFailRate > 0 || (ctPct > 85 && rates.ConntrackGrowthRate > 0)) {
		result = append(result, warnStyle.Render("  Conntrack table pressure: new flows failing. Increase max or reduce churn."))
		addCmd("sysctl net.netfilter.nf_conntrack_max")
		addCmd("sysctl net.netfilter.nf_conntrack_buckets")
		matched = true
	}

	// 2. Churn / no reuse
	if rates != nil && rates.ConntrackGrowthRate > 100 {
		twHigh := false
		if dissect.Available {
			if cnt, ok := dissect.CTStates["TIME_WAIT"]; ok && cnt > 1000 {
				twHigh = true
			}
		} else if snap.Global.TCPStates.TimeWait > 1000 {
			twHigh = true
		}
		if twHigh {
			result = append(result, warnStyle.Render("  High connection churn; check keep-alive, pooling, HAProxy reuse."))
			addCmd("ss -s")
			addCmd("ss -tan state time-wait | wc -l")
			matched = true
		}
	}

	// 3. Socket leak (CLOSE_WAIT) — socket truth: only flag if SOCKET CW is high.
	// Conntrack CW alone does NOT indicate app leak when sockets disagree.
	socketCW := snap.Global.TCPStates.CloseWait
	ctCW := 0
	if dissect.Available {
		ctCW = dissect.CTStates["CLOSE_WAIT"]
	}
	if socketCW > 100 {
		// Real app leak — sockets confirm it
		result = append(result, warnStyle.Render("  Socket CLOSE_WAIT high \u2014 application not closing connections."))
		matched = true
	} else if ctCW > 100 && socketCW < 20 {
		// Conntrack CW high, socket CW low — NOT an app issue
		result = append(result, dimStyle.Render(fmt.Sprintf(
			"  Conntrack CLOSE_WAIT: %d vs socket: %d \u2014 conntrack lifecycle, not app leak.", ctCW, socketCW)))
		matched = true
	}

	// 4. SYN flood/scan
	synCount := 0
	if dissect.Available {
		synCount = dissect.CTStates["SYN_SENT"] + dissect.CTStates["SYN_RECV"]
	} else {
		synCount = snap.Global.TCPStates.SynSent + snap.Global.TCPStates.SynRecv
	}
	if synCount > 50 && rates != nil && rates.ConntrackDropRate > 0 {
		result = append(result, warnStyle.Render("  Handshake backlog pressure; possible scan/flood or upstream packet loss."))
		matched = true
	}

	// 5. Hash contention
	if rates != nil && rates.ConntrackSearchRestartRate > 100 && ctPct < 70 {
		result = append(result, warnStyle.Render("  Conntrack hash contention; consider buckets sizing, check CPU/IRQ balance."))
		addCmd("cat /proc/net/stat/nf_conntrack")
		matched = true
	}

	// 6. Healthy
	if !matched {
		healthLine := fmt.Sprintf("  Stable \u2014 table at %.1f%% with balanced lifecycle.", ctPct)
		result = append(result, okStyle.Render(healthLine))
		if rates != nil && rates.ConntrackGrowthRate > 0 && ct.Max > ct.Count {
			// ETA to 80%
			target80 := float64(ct.Max) * 0.8
			if float64(ct.Count) < target80 {
				etaSec := (target80 - float64(ct.Count)) / rates.ConntrackGrowthRate
				result = append(result, dimStyle.Render(fmt.Sprintf("  Will reach 80%% in %s at current rate.", fmtETADuration(etaSec))))
			}
		}
	}

	return result
}

// fmtETADuration formats seconds into a human-readable "~Xh Ym" or "~Xm" string.
func fmtETADuration(sec float64) string {
	if sec <= 0 {
		return "now"
	}
	if sec < 60 {
		return fmt.Sprintf("~%.0fs", sec)
	}
	if sec < 3600 {
		return fmt.Sprintf("~%.0fm", sec/60)
	}
	h := int(sec / 3600)
	m := int(sec/60) % 60
	if m == 0 {
		return fmt.Sprintf("~%dh", h)
	}
	return fmt.Sprintf("~%dh %dm", h, m)
}

// ──────────────────────────────────────────────────────────────────────────────
// Network Intelligence Correlation Engine
//
// Design principles:
//   1. Separate signal from impact — non-zero ≠ bad, context matters
//   2. One primary incident + supporting symptoms — not "everything is CRITICAL"
//   3. Noise filtering — ignore NO_SOCKET drops, pid_0 retransmits, tiny owners
//   4. Contradiction rules — don't claim NETWORK CRITICAL without corroboration
//   5. Confidence scoring — LOW/MEDIUM/HIGH based on evidence quality
// ──────────────────────────────────────────────────────────────────────────────

// noiseBPFDropReasons are kfree_skb reasons that do not indicate real packet loss.
var noiseBPFDropReasons = map[string]bool{
	"NO_SOCKET":            true,
	"NOT_SPECIFIED":        true,
	"TCP_OLD_DATA":         true,
	"SKB_CONSUMED":         true,
	"TCP_OFO_QUEUE_PRUNE":  true,
}

// sigContrib scores a metric against warn/crit bands, returning 0..weight.
// Returns (score, true) if the signal fired (at WARN or above).
func sigContrib(val, warnThresh, critThresh float64, weight int) (int, bool) {
	if val >= critThresh {
		return weight, true
	}
	if val >= warnThresh {
		return weight / 2, true
	}
	return 0, false
}

// significantDropRate sums BPF sentinel drop rates excluding noise reasons.
func significantDropRate(sent model.SentinelData) float64 {
	var rate float64
	for _, d := range sent.PktDrops {
		if !noiseBPFDropReasons[d.ReasonStr] {
			rate += d.Rate
		}
	}
	return rate
}

// netHasFindings returns true if there are findings worth showing in the intelligence summary.
func netHasFindings(snap *model.Snapshot, rates *model.RateSnapshot) bool {
	health, _ := analyzeNetHealth(snap, rates)
	if health != "OK" {
		return true
	}

	// ESTABLISHED timeout dangerously high (tuning recommendation)
	cto := snap.Global.ConntrackTimeouts
	if cto.Available && cto.Established > 86400 {
		return true
	}

	// CLOSE_WAIT % meaningful — from /proc/net/tcp (real leak signal)
	st := snap.Global.TCPStates
	totalConn := st.Established + st.TimeWait + st.CloseWait + st.SynSent +
		st.SynRecv + st.FinWait1 + st.FinWait2 + st.Closing + st.LastAck
	if totalConn > 0 {
		cwPct := float64(st.CloseWait) / float64(totalConn) * 100
		if cwPct > 2.0 {
			return true
		}
	}

	// Conntrack CLOSE_WAIT high relative to table
	dissect := snap.Global.ConntrackDissect
	ct := snap.Global.Conntrack
	if dissect.Available && ct.Count > 100 {
		if cw, ok := dissect.CTStates["CLOSE_WAIT"]; ok {
			cwPct := float64(cw) / float64(ct.Count) * 100
			if cwPct > 10.0 {
				return true
			}
		}
	}

	// Conntrack at moderate usage
	if ct.Max > 0 && float64(ct.Count)/float64(ct.Max)*100 > 50 {
		return true
	}

	return false
}

// netIntelResult holds all computed network intelligence scoring results.
// Separates computation from rendering so multiple renderers can use the same data.
type netIntelResult struct {
	netScore, appScore, kernScore     int
	netSev, appSev, kernSev           string
	primary, confidence, situationSev string
	netReason, appReason, kernReason  string
	retransRate, sigDrops, connLatMax float64
	connLatAvg                        float64
	connLatComm, connLatDst           string
	connLatPID                        uint32
	connLatIsolated                   bool
	procCW, ctCW                      int
	procCWPct, ctCWPct, ctUsagePct    float64
	ctSocketMismatch, timeoutAdvisory bool
	maxLinkUtil, softIRQPct           float64
	ctInsertFail, ctDropRate          float64
	ctGrowthRate, ctSearchRestart     float64
	twEphPct                          float64
	nicDropsPS, totalBPFDrops         float64
	maxLinkName                       string
	sourcesStr                        string
	blindSpots                        string
}

// computeNetIntel runs Phase 1-3 of the network intelligence engine:
// normalize metrics, score domains, determine primary responsibility and confidence.
func computeNetIntel(snap *model.Snapshot, rates *model.RateSnapshot, result *model.AnalysisResult) netIntelResult {
	var r netIntelResult

	st := snap.Global.TCPStates
	ct := snap.Global.Conntrack
	udp := snap.Global.UDP
	sock := snap.Global.Sockets
	sent := snap.Global.Sentinel
	cwTrend := snap.Global.CloseWaitTrend
	eph := snap.Global.EphemeralPorts
	dissect := snap.Global.ConntrackDissect
	cto := snap.Global.ConntrackTimeouts

	// Phase 1: Normalize metrics
	if rates != nil {
		r.retransRate = rates.RetransRate
	}
	if sent.Active {
		r.sigDrops = significantDropRate(sent)
		r.totalBPFDrops = sent.PktDropRate
	}
	if rates != nil {
		for _, nr := range rates.NetRates {
			r.nicDropsPS += nr.RxDropsPS + nr.TxDropsPS
		}
	}
	if ct.Max > 0 {
		r.ctUsagePct = float64(ct.Count) / float64(ct.Max) * 100
	}
	if rates != nil {
		r.ctInsertFail = rates.ConntrackInsertFailRate
		r.ctDropRate = rates.ConntrackDropRate
		r.ctSearchRestart = rates.ConntrackSearchRestartRate
		r.ctGrowthRate = rates.ConntrackGrowthRate
	}

	r.procCW = st.CloseWait
	if dissect.Available {
		if cw, ok := dissect.CTStates["CLOSE_WAIT"]; ok {
			r.ctCW = cw
		}
	}
	totalConn := st.Established + st.TimeWait + st.CloseWait + st.SynSent +
		st.SynRecv + st.FinWait1 + st.FinWait2 + st.Closing + st.LastAck
	if totalConn > 0 {
		r.procCWPct = float64(r.procCW) / float64(totalConn) * 100
	}
	if ct.Count > 0 {
		r.ctCWPct = float64(r.ctCW) / float64(ct.Count) * 100
	}

	ephRange := eph.RangeHi - eph.RangeLo
	if ephRange <= 0 {
		ephRange = defaultEphemeralRange
	}
	r.twEphPct = float64(st.TimeWait) / float64(ephRange) * 100

	if sent.Active {
		for _, cl := range sent.ConnLatency {
			if cl.MaxMs > r.connLatMax {
				r.connLatMax = cl.MaxMs
				r.connLatComm = cl.Comm
				r.connLatPID = cl.PID
				r.connLatDst = cl.DstStr
				r.connLatAvg = cl.AvgMs
			}
		}
	}

	if rates != nil {
		for _, nr := range rates.NetRates {
			if nr.UtilPct > r.maxLinkUtil && nr.SpeedMbps > 0 {
				r.maxLinkUtil = nr.UtilPct
				r.maxLinkName = nr.Name
			}
		}
	}
	if rates != nil {
		r.softIRQPct = rates.CPUSoftIRQPct
	}

	// Phase 2: Score each domain
	netSignals := 0
	if s, ok := sigContrib(r.retransRate, 10, 100, 35); ok {
		r.netScore += s
		netSignals++
	}
	if s, ok := sigContrib(r.sigDrops+r.nicDropsPS, 10, 100, 25); ok {
		r.netScore += s
		netSignals++
	}
	if s, ok := sigContrib(r.maxLinkUtil, 80, 95, 25); ok {
		r.netScore += s
		netSignals++
	}
	if s, ok := sigContrib(r.connLatMax, 50, 200, 30); ok {
		r.netScore += s
		netSignals++
	}
	r.connLatIsolated = r.connLatMax > 50 && r.retransRate < 10 && r.sigDrops < 10
	if r.netScore >= 70 && r.retransRate < 10 && r.connLatMax < 50 {
		r.netScore = 50
	}

	appSignals := 0
	if s, ok := sigContrib(r.procCWPct, 2, 10, 40); ok {
		r.appScore += s
		appSignals++
	}
	if r.procCW >= 20 && r.ctCWPct > 0 {
		if s, ok := sigContrib(r.ctCWPct, 10, 30, 25); ok {
			r.appScore += s
			appSignals++
		}
	}
	r.ctSocketMismatch = r.ctCWPct > 10 && r.procCW < 20
	if cwTrend.Growing {
		if s, ok := sigContrib(cwTrend.GrowthRate, 10, 50, 25); ok {
			r.appScore += s
			appSignals++
		}
	}
	if s, ok := sigContrib(float64(sock.TCPOrphan), 200, 500, 15); ok {
		r.appScore += s
		appSignals++
	}

	kernSignals := 0
	if s, ok := sigContrib(r.ctUsagePct, 60, 85, 30); ok {
		r.kernScore += s
		kernSignals++
	}
	if s, ok := sigContrib(r.ctInsertFail, 0.5, 1, 40); ok {
		r.kernScore += s
		kernSignals++
	}
	if s, ok := sigContrib(r.ctDropRate, 1, 5, 30); ok {
		r.kernScore += s
		kernSignals++
	}
	if s, ok := sigContrib(r.ctSearchRestart, 10, 200, 20); ok {
		r.kernScore += s
		kernSignals++
	}
	if s, ok := sigContrib(r.softIRQPct, 15, 30, 15); ok {
		r.kernScore += s
		kernSignals++
	}
	if udp.RcvbufErrors > 0 {
		if s, ok := sigContrib(float64(udp.RcvbufErrors), 1, 100, 15); ok {
			r.kernScore += s
			kernSignals++
		}
	}
	r.timeoutAdvisory = cto.Available && cto.Established > 86400
	if r.timeoutAdvisory {
		r.kernScore += 10
		kernSignals++
	}

	// Phase 3: Determine primary responsibility + confidence
	sevFromScore := func(score int) string {
		if score >= 70 {
			return "CRITICAL"
		}
		if score >= 25 {
			return "DEGRADED"
		}
		return "OK"
	}

	r.netSev = sevFromScore(r.netScore)
	r.appSev = sevFromScore(r.appScore)
	r.kernSev = sevFromScore(r.kernScore)

	r.primary = "INCONCLUSIVE"
	primaryScore := 0
	if r.netScore >= 45 && r.netScore >= r.appScore && r.netScore >= r.kernScore {
		r.primary = "NETWORK"
		primaryScore = r.netScore
	} else if r.appScore >= 45 && r.appScore >= r.netScore && r.appScore >= r.kernScore {
		r.primary = "APPLICATION"
		primaryScore = r.appScore
	} else if r.kernScore >= 45 && r.kernScore >= r.netScore && r.kernScore >= r.appScore {
		r.primary = "KERNEL"
		primaryScore = r.kernScore
	} else {
		maxS := r.netScore
		if r.appScore > maxS {
			maxS = r.appScore
		}
		if r.kernScore > maxS {
			maxS = r.kernScore
		}
		primaryScore = maxS
	}

	r.confidence = "LOW"
	primarySignals := 0
	switch r.primary {
	case "NETWORK":
		primarySignals = netSignals
	case "APPLICATION":
		primarySignals = appSignals
	case "KERNEL":
		primarySignals = kernSignals
	}
	if primaryScore >= 70 && primarySignals >= 2 {
		r.confidence = "HIGH"
	} else if primaryScore >= 45 {
		r.confidence = "MEDIUM"
	}
	if r.ctSocketMismatch && r.confidence == "LOW" {
		r.confidence = "MEDIUM"
	}

	overallSev := "OK"
	if r.netSev != "OK" || r.appSev != "OK" || r.kernSev != "OK" {
		overallSev = "DEGRADED"
	}
	if r.netSev == "CRITICAL" || r.appSev == "CRITICAL" || r.kernSev == "CRITICAL" {
		overallSev = "CRITICAL"
	}
	r.situationSev = overallSev
	if r.situationSev == "DEGRADED" && r.confidence == "LOW" {
		r.situationSev = "ADVISORY"
	}
	if r.situationSev == "OK" {
		r.situationSev = "ADVISORY"
	}

	// Build reason strings
	switch {
	case r.retransRate >= 100:
		r.netReason = fmt.Sprintf("%.0f/s retransmits, packet loss confirmed", r.retransRate)
	case r.retransRate >= 10:
		if r.connLatMax < 50 && r.sigDrops < 10 {
			r.netReason = fmt.Sprintf("retransmits slightly above baseline (%.0f/s); no loss/latency \u2192 likely benign", r.retransRate)
		} else {
			r.netReason = fmt.Sprintf("elevated retransmits (%.0f/s) with corroborating signals", r.retransRate)
		}
	case r.sigDrops > 10:
		r.netReason = fmt.Sprintf("significant packet drops (%.0f/s)", r.sigDrops)
	case r.maxLinkUtil > 80:
		r.netReason = fmt.Sprintf("%s at %.0f%% utilization", r.maxLinkName, r.maxLinkUtil)
	case r.connLatMax > 100 || (r.connLatMax > 50 && r.connLatAvg > 20):
		src := fmt.Sprintf("%s \u2192 %s", r.connLatComm, r.connLatDst)
		if r.connLatIsolated {
			r.netReason = fmt.Sprintf("outbound connect latency p95=%.0fms avg=%.0fms (%s) \u2014 no packet loss corroboration", r.connLatMax, r.connLatAvg, src)
		} else {
			r.netReason = fmt.Sprintf("high outbound connect latency p95=%.0fms avg=%.0fms (%s) with corroborating loss", r.connLatMax, r.connLatAvg, src)
		}
	case r.connLatMax > 50:
		r.netReason = fmt.Sprintf("connect latency p95=%.0fms, avg=%.0fms (normal range)", r.connLatMax, r.connLatAvg)
	case r.retransRate > 0 && r.retransRate < 10:
		r.netReason = fmt.Sprintf("minor retransmits (%.0f/s \u2014 normal)", r.retransRate)
	}

	switch {
	case r.procCWPct > 10:
		r.appReason = fmt.Sprintf("socket leak \u2014 %d CLOSE_WAIT (%.0f%% of connections)", r.procCW, r.procCWPct)
	case r.procCWPct > 2:
		r.appReason = fmt.Sprintf("elevated CLOSE_WAIT %d (%.1f%%)", r.procCW, r.procCWPct)
	case r.ctCWPct > 10 && r.procCW < 20:
		r.appReason = fmt.Sprintf("socket CLOSE_WAIT low (%d)", r.procCW)
	case sock.TCPOrphan > 200:
		r.appReason = fmt.Sprintf("%d orphan sockets", sock.TCPOrphan)
	}

	switch {
	case r.ctInsertFail > 1:
		r.kernReason = fmt.Sprintf("conntrack table full \u2014 %.1f/s insert failures", r.ctInsertFail)
	case r.ctInsertFail > 0.5:
		r.kernReason = fmt.Sprintf("conntrack insert failures: %.1f/s", r.ctInsertFail)
	case r.ctDropRate > 5:
		r.kernReason = fmt.Sprintf("conntrack dropping %.0f/s", r.ctDropRate)
	case r.ctDropRate > 1:
		r.kernReason = fmt.Sprintf("conntrack drops: %.1f/s", r.ctDropRate)
	case r.ctSearchRestart > 200:
		r.kernReason = fmt.Sprintf("hash contention %.0f/s search restarts", r.ctSearchRestart)
	case r.softIRQPct > 15:
		r.kernReason = fmt.Sprintf("%.1f%% SoftIRQ overhead", r.softIRQPct)
	case r.timeoutAdvisory:
		if r.ctUsagePct > 50 || r.ctGrowthRate > 10 {
			r.kernReason = fmt.Sprintf("ESTABLISHED timeout %dd (tuning recommended)", cto.Established/86400)
		} else {
			r.kernReason = fmt.Sprintf("ESTABLISHED timeout %dd (tuning optional)", cto.Established/86400)
		}
	case udp.RcvbufErrors > 0:
		r.kernReason = "UDP buffer overflow"
	}

	// Data quality
	var sources []string
	if ct.Max > 0 {
		sources = append(sources, "conntrack \u2713")
	} else {
		sources = append(sources, "conntrack \u2717")
	}
	if dissect.Available {
		sources = append(sources, "ct-dissect \u2713")
	} else {
		sources = append(sources, "ct-dissect \u2717")
	}
	if sent.Active {
		sources = append(sources, "eBPF \u2713")
	} else {
		sources = append(sources, "eBPF \u2717")
	}
	if st.Established > 0 || st.Listen > 0 || st.TimeWait > 0 {
		sources = append(sources, "/proc/net \u2713")
	} else {
		sources = append(sources, "/proc/net \u2717")
	}
	r.sourcesStr = joinStrings(sources, "  ")

	var blind []string
	if !sent.Active {
		blind = append(blind, "no per-PID retransmit attribution")
	}
	if r.procCW < 10 && r.ctCW > 100 {
		blind = append(blind, "conntrack CLOSE_WAIT not PID-attributable")
	}
	r.blindSpots = joinStrings(blind, "; ")

	return r
}

// buildNetIntelligenceSummary produces a production-grade correlated cross-layer network diagnosis.
// Uses weighted domain scoring, noise filtering, contradiction rules, and confidence assessment.
func buildNetIntelligenceSummary(snap *model.Snapshot, rates *model.RateSnapshot, result *model.AnalysisResult, iw int) string {
	intel := computeNetIntel(snap, rates, result)
	var lines []string

	st := snap.Global.TCPStates
	ct := snap.Global.Conntrack
	sent := snap.Global.Sentinel
	cwTrend := snap.Global.CloseWaitTrend
	eph := snap.Global.EphemeralPorts
	dissect := snap.Global.ConntrackDissect
	cto := snap.Global.ConntrackTimeouts

	// Alias fields from intel for readability in existing rendering code
	situationSev := intel.situationSev
	ctSocketMismatch := intel.ctSocketMismatch
	timeoutAdvisory := intel.timeoutAdvisory
	retransRate := intel.retransRate
	sigDrops := intel.sigDrops
	totalBPFDrops := intel.totalBPFDrops
	nicDropsPS := intel.nicDropsPS
	connLatMax := intel.connLatMax
	connLatAvg := intel.connLatAvg
	connLatComm := intel.connLatComm
	connLatPID := intel.connLatPID
	connLatDst := intel.connLatDst
	connLatIsolated := intel.connLatIsolated
	procCW := intel.procCW
	ctCW := intel.ctCW
	procCWPct := intel.procCWPct
	ctCWPct := intel.ctCWPct
	ctUsagePct := intel.ctUsagePct
	ctInsertFail := intel.ctInsertFail
	ctDropRate := intel.ctDropRate
	ctGrowthRate := intel.ctGrowthRate
	ctSearchRestart := intel.ctSearchRestart
	twEphPct := intel.twEphPct
	maxLinkUtil := intel.maxLinkUtil
	maxLinkName := intel.maxLinkName
	softIRQPct := intel.softIRQPct
	primary := intel.primary
	confidence := intel.confidence
	netSev := intel.netSev
	appSev := intel.appSev
	kernSev := intel.kernSev
	netReason := intel.netReason
	appReason := intel.appReason
	kernReason := intel.kernReason

	// ════════════════════════════════════════════════════════════════════════
	// Phase 4: Build output
	// ════════════════════════════════════════════════════════════════════════

	// ─── §1 SITUATION ───
	lines = append(lines, dimStyle.Render("─── SITUATION ───"))

	switch situationSev {
	case "CRITICAL":
		lines = append(lines, critStyle.Render("CRITICAL")+" \u2014 active network failures detected")
	case "DEGRADED":
		lines = append(lines, warnStyle.Render("WARNING")+" \u2014 confirmed network degradation")
	default:
		// Build specific advisory reason
		advReason := "configuration tuning recommended"
		if ctSocketMismatch {
			advReason = "conntrack state anomaly detected (low impact)"
		} else if timeoutAdvisory {
			advReason = "configuration tuning recommended"
		}
		lines = append(lines, dimStyle.Render("ADVISORY")+" \u2014 "+advReason)
	}

	// Build findings — only significant, contextualised signals
	var findings []string

	// Conntrack exhaustion (only if actually pressured)
	if ctInsertFail > 0.5 {
		findings = append(findings, fmt.Sprintf("Conntrack table rejecting new connections: %.1f/s insert failures (%.0f%% full)", ctInsertFail, ctUsagePct))
	} else if ctUsagePct > 60 {
		findings = append(findings, fmt.Sprintf("Conntrack table at %.0f%% capacity (%d/%d)", ctUsagePct, ct.Count, ct.Max))
	}

	// Retransmits — only if above noise floor, with context
	if retransRate >= 10 {
		if connLatMax < 50 && sigDrops < 10 && nicDropsPS < 10 {
			findings = append(findings, fmt.Sprintf("Retransmits: %.0f/s (slightly above baseline; no loss/latency corroboration \u2192 likely benign)", retransRate))
		} else {
			findings = append(findings, fmt.Sprintf("Elevated retransmits: %.0f/s with corroborating loss/latency signals", retransRate))
		}
	} else if retransRate > 0 {
		findings = append(findings, dimStyle.Render(fmt.Sprintf("Retransmits: %.0f/s (normal)", retransRate)))
	}

	// Significant drops — reason-aware
	if sigDrops > 10 {
		findings = append(findings, fmt.Sprintf("Significant packet drops: %.0f/s (noise-filtered from %.0f/s total)", sigDrops, totalBPFDrops))
	} else if totalBPFDrops > 10 && sigDrops < 10 {
		findings = append(findings, dimStyle.Render(fmt.Sprintf("BPF drops: %.0f/s (all noise: NO_SOCKET/NOT_SPECIFIED \u2014 non-impacting)", totalBPFDrops)))
	}

	// CLOSE_WAIT — distinguish source and severity
	if procCWPct > 2 {
		cwFinding := fmt.Sprintf("CLOSE_WAIT: %d sockets (%.1f%% of connections) in /proc/net/tcp", procCW, procCWPct)
		if len(snap.Global.CloseWaitLeakers) > 0 {
			top := snap.Global.CloseWaitLeakers[0]
			totalCW := procCW
			if totalCW == 0 {
				totalCW = 1
			}
			topPct := float64(top.Count) / float64(totalCW) * 100
			if topPct >= 5 {
				cwFinding += fmt.Sprintf(" \u2014 %s (PID %d) owns %.0f%%", top.Comm, top.PID, topPct)
			}
		}
		findings = append(findings, cwFinding)
	} else if ctCWPct > 10 && procCW < 20 {
		// Conntrack vs socket mismatch — NOT an application issue
		findings = append(findings, fmt.Sprintf("Conntrack CLOSE_WAIT: %d (%.0f%% of tracked flows) vs socket CLOSE_WAIT: %d",
			ctCW, ctCWPct, procCW))
		findings = append(findings, dimStyle.Render("  Not an application leak \u2014 conntrack lifecycle / NAT artifact"))
	}

	// TIME_WAIT — only flag if ephemeral usage is meaningful
	if twEphPct > 30 {
		findings = append(findings, fmt.Sprintf("TIME_WAIT: %d sockets (%.0f%% of ephemeral range) \u2014 port exhaustion risk", st.TimeWait, twEphPct))
	} else if st.TimeWait > 0 {
		findings = append(findings, dimStyle.Render(fmt.Sprintf("TIME_WAIT: %d sockets (%.1f%% of ephemeral range \u2014 normal)", st.TimeWait, twEphPct)))
	}

	// Timeout advisory
	if timeoutAdvisory {
		findings = append(findings, fmt.Sprintf("ESTABLISHED timeout: %dd \u2014 stale connections accumulate (recommend 2h)", cto.Established/86400))
	}

	// Link saturation
	if maxLinkUtil > 80 {
		findings = append(findings, fmt.Sprintf("Link saturation: %s at %.0f%% utilization", maxLinkName, maxLinkUtil))
	}

	// SoftIRQ
	if softIRQPct > 15 {
		findings = append(findings, fmt.Sprintf("High SoftIRQ: %.1f%% CPU in kernel network processing", softIRQPct))
	}

	// Hash contention
	if ctSearchRestart > 10 {
		findings = append(findings, fmt.Sprintf("Conntrack hash contention: %.0f/s search restarts", ctSearchRestart))
	}

	for _, f := range findings {
		lines = append(lines, "  \u2022 "+f)
	}

	// ─── §2 CLASSIFICATION ───
	lines = append(lines, "")
	lines = append(lines, dimStyle.Render("─── CLASSIFICATION ───"))

	renderVerdict := func(label, sev, reason string) string {
		var vs string
		switch sev {
		case "CRITICAL":
			vs = critStyle.Render(sev)
		case "DEGRADED":
			vs = warnStyle.Render(sev)
		default:
			vs = okStyle.Render(sev)
		}
		line := fmt.Sprintf("  %-14s %s", label+":", vs)
		if reason != "" {
			line += "  \u2014 " + reason
		}
		return line
	}

	lines = append(lines, renderVerdict("NETWORK", netSev, netReason))
	lines = append(lines, renderVerdict("APPLICATION", appSev, appReason))
	lines = append(lines, renderVerdict("KERNEL", kernSev, kernReason))

	// Primary responsibility
	if primary != "INCONCLUSIVE" && situationSev != "ADVISORY" {
		lines = append(lines, warnStyle.Render(fmt.Sprintf("  Primary responsibility: %s", primary))+
			dimStyle.Render(fmt.Sprintf("   Confidence: %s", confidence)))
	} else if situationSev == "ADVISORY" {
		lines = append(lines, dimStyle.Render(fmt.Sprintf("  Primary: NONE (no active issue)   Confidence: %s", confidence)))
	} else if intel.situationSev != "OK" && intel.situationSev != "ADVISORY" {
		lines = append(lines, dimStyle.Render("  Primary responsibility: INCONCLUSIVE \u2014 no single domain scores high enough"))
	}

	// ─── §3 INSIGHT (conntrack vs socket reconciliation) ───
	if ctSocketMismatch {
		lines = append(lines, "")
		lines = append(lines, dimStyle.Render("─── INSIGHT ───"))
		lines = append(lines, fmt.Sprintf("  Conntrack vs Socket mismatch:"))
		lines = append(lines, fmt.Sprintf("    Conntrack CLOSE_WAIT: %d (%.0f%% of tracked flows)", ctCW, ctCWPct))
		lines = append(lines, fmt.Sprintf("    Socket CLOSE_WAIT:    %d", procCW))
		lines = append(lines, "")
		lines = append(lines, dimStyle.Render("  Conclusion: Not an application leak."))
		lines = append(lines, dimStyle.Render("  These conntrack entries represent completed/closing flows still tracked"))
		lines = append(lines, dimStyle.Render("  by the kernel, not active sockets. Conntrack state persists independently"))
		lines = append(lines, dimStyle.Render("  of socket state, especially with long ESTABLISHED timeouts."))
		// NAT heuristic: if source IPs in conntrack differ from local IPs, NAT likely
		natStatus := "not detected"
		if dissect.Available && len(dissect.TopSrcIPs) > 1 {
			// Multiple distinct source IPs in conntrack suggest NAT/masquerade
			localCount := 0
			for _, src := range dissect.TopSrcIPs {
				if strings.HasPrefix(src.IP, "127.") {
					localCount++
				}
			}
			if localCount == 0 && len(dissect.TopSrcIPs) > 2 {
				natStatus = "likely (multiple non-local source IPs in conntrack)"
			}
		}
		lines = append(lines, dimStyle.Render(fmt.Sprintf("  NAT: %s", natStatus)))
		// Impact statement
		impactParts := []string{}
		if ctUsagePct < 60 {
			impactParts = append(impactParts, "conntrack usage low")
		}
		if ctDropRate == 0 {
			impactParts = append(impactParts, "no drops")
		}
		if ctInsertFail == 0 {
			impactParts = append(impactParts, "no insert failures")
		}
		if len(impactParts) > 0 {
			lines = append(lines, "")
			lines = append(lines, dimStyle.Render(fmt.Sprintf("  Impact: none (%s)", joinStrings(impactParts, ", "))))
		}
	}

	// ─── §4 OWNERSHIP ──
	var ownerLines []string

	// CLOSE_WAIT owners — only show when socket CW is actually high (not conntrack artifact).
	// If socket CW is low and we already explained the mismatch in INSIGHT, don't accuse anyone.
	if procCW >= 20 {
		totalCWForOwnership := procCW
		for i, lk := range snap.Global.CloseWaitLeakers {
			if i >= 3 {
				break
			}
			ownerPct := float64(lk.Count) / float64(totalCWForOwnership) * 100
			if ownerPct < 5 {
				continue
			}
			ownerLines = append(ownerLines, fmt.Sprintf("  %-16s PID %-6d  %d CLOSE_WAIT (%.0f%% of total, oldest: %s)",
				lk.Comm, lk.PID, lk.Count, ownerPct, fmtAgeSec(lk.OldestAge)))
		}
	}

	// Retransmit offenders (BPF) — skip pid 0 (kernel context = noise)
	if sent.Active {
		for i, r := range sent.Retransmits {
			if i >= 3 || r.Rate <= 0 || len(ownerLines) >= 5 {
				break
			}
			if r.PID == 0 {
				continue // kernel context retransmit — not a culprit
			}
			ownerLines = append(ownerLines, fmt.Sprintf("  %-16s PID %-6d  %.0f/s retransmits \u2192 %s",
				r.Comm, r.PID, r.Rate, r.DstStr)+
				dimStyle.Render("  (scheduling-based — may not be socket owner)"))
		}
	}

	// Top conntrack talkers
	if dissect.Available && ct.Count > 100 {
		for i, src := range dissect.TopSrcIPs {
			if i >= 2 || len(ownerLines) >= 5 {
				break
			}
			srcPct := float64(src.Count) / float64(ct.Count) * 100
			if srcPct > 20 {
				ownerLines = append(ownerLines, fmt.Sprintf("  %-16s          %d conntrack entries (%.0f%% of tracked flows)",
					src.IP, src.Count, srcPct))
			}
		}
	}

	// If conntrack CW is high but socket CW is low, the INSIGHT section already explains it.
	// No ownership accusation needed — it's a conntrack artifact, not a process leak.

	if len(ownerLines) > 0 {
		lines = append(lines, "")
		lines = append(lines, dimStyle.Render("─── OWNERSHIP ───"))
		lines = append(lines, ownerLines...)
	}

	// ─── §5 PREDICTIONS ───
	var predLines []string

	// Conntrack ETA to full
	if ct.Max > 0 && ctGrowthRate > 0 {
		remaining := float64(ct.Max) - float64(ct.Count)
		if remaining > 0 {
			etaSec := remaining / ctGrowthRate
			predLines = append(predLines, fmt.Sprintf("  Conntrack table will fill in %s at current growth rate", fmtETADuration(etaSec)))
		}
	}

	// CLOSE_WAIT trajectory
	if cwTrend.Growing && cwTrend.GrowthRate > 10 {
		predLines = append(predLines, fmt.Sprintf("  CLOSE_WAIT growing at +%.0f/s \u2014 active leak", cwTrend.GrowthRate))
	}

	// Ephemeral port exhaustion — only if actually at risk
	if twEphPct > 30 {
		ephRange := eph.RangeHi - eph.RangeLo
		if ephRange <= 0 {
			ephRange = defaultEphemeralRange
		}
		predLines = append(predLines, fmt.Sprintf("  Ephemeral ports: %.0f%% used (%d/%d) \u2014 monitor for exhaustion", twEphPct, eph.InUse, ephRange))
	}

	// Stale accumulation prediction
	if timeoutAdvisory && ctUsagePct > 5 {
		predLines = append(predLines, fmt.Sprintf("  With %dd timeout, stale entries accumulate during sustained traffic (%.0f%% full now)",
			cto.Established/86400, ctUsagePct))
	}

	if len(predLines) > 0 {
		lines = append(lines, "")
		lines = append(lines, dimStyle.Render("─── PREDICTIONS ───"))
		lines = append(lines, predLines...)
	} else {
		lines = append(lines, "")
		lines = append(lines, dimStyle.Render("─── PREDICTIONS ───"))
		lines = append(lines, dimStyle.Render("  No exhaustion risk \u2014 trends stable"))
	}

	// ─── §6 RESOLUTION ───
	lines = append(lines, "")
	lines = append(lines, dimStyle.Render("─── RESOLUTION ───"))

	actionN := 0

	// Actions based on primary responsibility — only accuse app when socket CW confirms
	if (primary == "APPLICATION" || procCWPct > 2) && procCW >= 20 && actionN < 5 {
		actionN++
		if len(snap.Global.CloseWaitLeakers) > 0 {
			top := snap.Global.CloseWaitLeakers[0]
			topPct := float64(top.Count) / float64(procCW) * 100
			if topPct >= 5 {
				lines = append(lines, fmt.Sprintf("  %d. Fix socket leak in %s (PID %d) \u2014 owns %.0f%% of CLOSE_WAIT, oldest %s",
					actionN, top.Comm, top.PID, topPct, fmtAgeSec(top.OldestAge)))
				lines = append(lines, dimStyle.Render("     Application not calling close() after remote peer disconnects"))
			} else {
				lines = append(lines, fmt.Sprintf("  %d. Investigate CLOSE_WAIT distribution \u2014 %d sockets but no single process owns >5%%",
					actionN, procCW))
				lines = append(lines, dimStyle.Render("     May indicate many services with minor leaks or connection pool misconfiguration"))
			}
		}
	}
	// ctCW high + procCW low = conntrack artifact (INSIGHT explains), no app action needed

	if primary == "NETWORK" && actionN < 5 {
		actionN++
		if sent.Active && len(sent.Retransmits) > 0 && sent.Retransmits[0].PID != 0 {
			top := sent.Retransmits[0]
			lines = append(lines, fmt.Sprintf("  %d. Network path issue \u2014 %.0f/s retransmits observed near %s (PID %d) \u2192 %s",
				actionN, top.Rate, top.Comm, top.PID, top.DstStr))
			lines = append(lines, dimStyle.Render("     Attribution is scheduling-based (process on CPU during retransmit, not necessarily socket owner)"))
		} else {
			lines = append(lines, fmt.Sprintf("  %d. Network path degraded \u2014 %.0f retransmits/s, check upstream connectivity",
				actionN, retransRate))
		}
		lines = append(lines, dimStyle.Render("     Likely: NIC errors, switch congestion, MTU mismatch, or upstream packet loss"))
	}

	if primary == "KERNEL" || (ctInsertFail > 0 && actionN < 5) {
		actionN++
		newMax := ct.Max * 2
		if newMax == 0 {
			newMax = 524288
		}
		lines = append(lines, fmt.Sprintf("  %d. Increase conntrack table \u2014 max %d is insufficient", actionN, ct.Max))
		lines = append(lines, dimStyle.Render(fmt.Sprintf("     sysctl -w net.netfilter.nf_conntrack_max=%d", newMax)))
	}

	// Connect latency action — show actual source from BPF
	if connLatMax > 200 && actionN < 5 {
		actionN++
		lines = append(lines, fmt.Sprintf("  %d. Investigate high connect latency: %s (PID %d) \u2192 %s (max %.0fms, avg %.0fms)",
			actionN, connLatComm, connLatPID, connLatDst, connLatMax, connLatAvg))
		if connLatIsolated {
			lines = append(lines, dimStyle.Render("     No packet loss/retransmits corroborate \u2014 likely slow destination or DNS resolution"))
		} else {
			lines = append(lines, dimStyle.Render("     Corroborated by retransmits/drops \u2014 likely real network path issue"))
		}
	}

	// Timeout fix — softer when no pressure
	if timeoutAdvisory && actionN < 5 {
		actionN++
		hasPressure := ctUsagePct > 50 || ctGrowthRate > 10 || ctInsertFail > 0
		if hasPressure {
			lines = append(lines, fmt.Sprintf("  %d. Reduce ESTABLISHED timeout from %dd to 2h", actionN, cto.Established/86400))
			lines = append(lines, dimStyle.Render("     sysctl -w net.netfilter.nf_conntrack_tcp_timeout_established=7200"))
		} else {
			lines = append(lines, fmt.Sprintf("  %d. Optional: reduce ESTABLISHED timeout (%dd \u2192 2h) for high-churn systems", actionN, cto.Established/86400))
			lines = append(lines, dimStyle.Render("     Not required currently (no conntrack pressure detected)"))
			lines = append(lines, dimStyle.Render("     sysctl -w net.netfilter.nf_conntrack_tcp_timeout_established=7200"))
		}
	}

	if actionN == 0 {
		lines = append(lines, dimStyle.Render("  No action required \u2014 system operating within normal parameters"))
	}

	// ─── §7 DATA QUALITY ───
	lines = append(lines, "")
	lines = append(lines, dimStyle.Render("─── DATA QUALITY ───"))

	qualityLine := fmt.Sprintf("  Sources: %s  Confidence: %s", intel.sourcesStr, confidence)
	lines = append(lines, dimStyle.Render(qualityLine))
	if intel.blindSpots != "" {
		lines = append(lines, dimStyle.Render("  Blind spots: "+intel.blindSpots))
	}

	return boxSection("NETWORK INTELLIGENCE SUMMARY", lines, iw)
}

// joinStrings joins a string slice with a separator.
func joinStrings(ss []string, sep string) string {
	result := ""
	for i, s := range ss {
		if i > 0 {
			result += sep
		}
		result += s
	}
	return result
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
