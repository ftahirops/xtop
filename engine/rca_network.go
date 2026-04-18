package engine

import (
	"fmt"
	"net"
	"strings"

	"github.com/ftahirops/xtop/model"
	"github.com/ftahirops/xtop/util"
)

// isPrivateIPStr checks if a formatted IP is RFC1918, link-local, or loopback.
func isPrivateIPStr(ip string) bool {
	if strings.HasPrefix(ip, "10.") || strings.HasPrefix(ip, "127.") ||
		strings.HasPrefix(ip, "192.168.") || strings.HasPrefix(ip, "169.254.") {
		return true
	}
	if strings.HasPrefix(ip, "172.") {
		var second int
		fmt.Sscanf(ip, "172.%d.", &second)
		return second >= 16 && second <= 31
	}
	return false
}

// ---------- Network Score ----------
// Evidence groups: Drops, Retransmits, Conntrack, SoftIRQ, TCP state issues
// isBenignDropReasonStr returns true for drop reasons that are normal TCP lifecycle.
func isBenignDropReasonStr(reason string) bool {
	return util.IsBenignDropReason(reason)
}

// dropReasonImpact returns a human-readable impact description for a BPF drop reason.
func dropReasonImpact(reason string) string {
	switch reason {
	case "NETFILTER_DROP":
		return "firewall rules (iptables/nftables) actively rejecting traffic"
	case "NO_SOCKET":
		return "packets arriving for closed/non-existent connections"
	case "SOCKET_RCVBUFF":
		return "application not reading fast enough — receive buffer full"
	case "PROTO_MEM":
		return "kernel TCP/UDP memory pressure — system under memory stress"
	case "QDISC_DROP":
		return "outbound queue full — network interface congested"
	case "FULL_RING":
		return "NIC ring buffer full — interface can't keep up with packet rate"
	case "NOMEM":
		return "kernel out of memory for network buffers"
	case "IP_OUTNOROUTES":
		return "no route to destination — routing table missing entries"
	case "TCP_CSUM":
		return "TCP checksum mismatch — possible hardware/driver issue"
	case "PKT_TOO_SMALL":
		return "malformed packets — possible attack or driver bug"
	case "SOCKET_BACKLOG":
		return "socket backlog full — application accept() too slow"
	case "NOT_SPECIFIED":
		return "generic kernel drop — no specific reason recorded"
	case "TCP_FLAGS":
		return "normal TCP lifecycle (FIN/RST handling)"
	case "TCP_OLD_DATA":
		return "retransmit arrived after ACK — normal on busy connections"
	case "TCP_ZEROWINDOW":
		return "TCP flow control — receiver window full"
	case "SOCKET_FILTER":
		return "BPF socket filter drop (tcpdump/iptables match)"
	case "SKB_CONSUMED":
		return "packet consumed normally — not an actual drop"
	default:
		return "kernel packet drop"
	}
}

func analyzeNetwork(curr *model.Snapshot, rates *model.RateSnapshot, sp systemProfile) model.RCAEntry {
	r := model.RCAEntry{Bottleneck: BottleneckNetwork}
	if rates == nil {
		return r
	}

	// Compute aggregates
	var totalDrops, totalErrors float64
	for _, nr := range rates.NetRates {
		totalDrops += nr.RxDropsPS + nr.TxDropsPS
		totalErrors += nr.RxErrorsPS + nr.TxErrorsPS
	}
	retransRate := rates.RetransRate

	var conntrackPct float64
	ct := curr.Global.Conntrack
	if ct.Max > 0 {
		conntrackPct = float64(ct.Count) / float64(ct.Max)
	}

	st := curr.Global.TCPStates

	// Ephemeral ports
	eph := curr.Global.EphemeralPorts
	// Guard against corrupt/zero values that would cause underflow or div-by-zero.
	var ephRange int
	if eph.RangeHi > eph.RangeLo {
		ephRange = eph.RangeHi - eph.RangeLo + 1
	}
	var ephPct float64
	if ephRange > 0 {
		ephPct = float64(eph.InUse) / float64(ephRange) * 100
	}

	// --- v2 evidence ---
	var retransRatio float64
	if rates.OutSegRate > 0 {
		retransRatio = retransRate / rates.OutSegRate * 100
	}

	// Retrans confidence: dampen when absolute rate is very low (< 5/s is normal background)
	retransConf := netRetransBaseConf
	if retransRate < netRetransLowRate {
		retransConf = netRetransLowConf
	}

	// Split RX/TX drops for directional attribution
	var totalRxDrops, totalTxDrops float64
	for _, nr := range rates.NetRates {
		totalRxDrops += nr.RxDropsPS
		totalTxDrops += nr.TxDropsPS
	}

	w, c := threshold("net.drops", 1, 100)
	w2, c2 := threshold("net.tcp.retrans", 1, 5)
	w3, c3 := threshold("net.conntrack", 70, 95)
	w4, c4 := threshold("net.softirq", 5, 25)
	r.EvidenceV2 = append(r.EvidenceV2,
		emitEvidence("net.drops", model.DomainNetwork,
			totalDrops, w, c, true, 0.8,
			fmt.Sprintf("net drops=%.0f/s (rx=%.0f tx=%.0f)", totalDrops, totalRxDrops, totalTxDrops), "1s",
			nil, nil),
		emitEvidence("net.tcp.retrans", model.DomainNetwork,
			retransRatio, w2, c2, true, retransConf,
			fmt.Sprintf("retrans=%.0f/s (%.1f%% ratio)", retransRate, retransRatio), "1s",
			nil, nil),
		emitEvidence("net.conntrack", model.DomainNetwork,
			conntrackPct*100, w3, c3, true, 0.9,
			fmt.Sprintf("conntrack=%.0f%% (%d/%d)", conntrackPct*100, ct.Count, ct.Max), "1s",
			nil, nil),
		emitEvidence("net.softirq", model.DomainNetwork,
			rates.CPUSoftIRQPct, w4, c4, false, 0.6,
			fmt.Sprintf("softirq CPU=%.1f%%", rates.CPUSoftIRQPct), "1s",
			nil, nil),
	)

	// Split RX/TX drop evidence for directional diagnosis
	if totalRxDrops > netDropSplitMinRate {
		wRx, cRx := threshold("net.drops.rx", 1, 100)
		r.EvidenceV2 = append(r.EvidenceV2, emitEvidence("net.drops.rx", model.DomainNetwork,
			totalRxDrops, wRx, cRx, true, 0.85,
			fmt.Sprintf("RX drops=%.0f/s (inbound buffer overflow)", totalRxDrops), "1s",
			nil, nil))
	}
	if totalTxDrops > netDropSplitMinRate {
		wTx, cTx := threshold("net.drops.tx", 1, 50)
		r.EvidenceV2 = append(r.EvidenceV2, emitEvidence("net.drops.tx", model.DomainNetwork,
			totalTxDrops, wTx, cTx, true, 0.7,
			fmt.Sprintf("TX drops=%.0f/s (outbound queue full)", totalTxDrops), "1s",
			nil, nil))
	}

	// Split TIME_WAIT and SYN_SENT into separate evidence (different root causes)
	if st.TimeWait > netTimeWaitEvidenceMin {
		wTw, cTw := threshold("net.tcp.timewait", 3000, 15000)
		r.EvidenceV2 = append(r.EvidenceV2, emitEvidence("net.tcp.timewait", model.DomainNetwork,
			float64(st.TimeWait), wTw, cTw, true, 0.6,
			fmt.Sprintf("TIME_WAIT=%d (connection churn)", st.TimeWait), "1s",
			nil, nil))
	}
	if st.SynSent > netSynSentEvidenceMin {
		wSs, cSs := threshold("net.tcp.synsent", 10, 100)
		r.EvidenceV2 = append(r.EvidenceV2, emitEvidence("net.tcp.synsent", model.DomainNetwork,
			float64(st.SynSent), wSs, cSs, true, 0.85,
			fmt.Sprintf("SYN_SENT=%d (upstream unreachable/slow)", st.SynSent), "1s",
			nil, nil))
	}

	// Ephemeral port exhaustion (Gregg USE: Saturation for network stack)
	if ephPct > netEphemeralEvidenceMinPct {
		wEph, cEph := threshold("net.ephemeral", 50, 85)
		r.EvidenceV2 = append(r.EvidenceV2, emitEvidence("net.ephemeral", model.DomainNetwork,
			ephPct, wEph, cEph, true, 0.9,
			fmt.Sprintf("ephemeral ports=%.0f%% (%d/%d)", ephPct, eph.InUse, ephRange), "1s",
			nil, nil))
	}

	// UDP errors (USE: Errors for UDP)
	if rates.UDPErrRate > netUDPErrMinRate {
		wUdp, cUdp := threshold("net.udp.errors", 1, 50)
		r.EvidenceV2 = append(r.EvidenceV2, emitEvidence("net.udp.errors", model.DomainNetwork,
			rates.UDPErrRate, wUdp, cUdp, true, 0.7,
			fmt.Sprintf("UDP errors=%.1f/s (InErrors+RcvbufErrors)", rates.UDPErrRate), "1s",
			nil, nil))
	}

	// TCP resets (connection rejections / aborts — Google SRE: Error signal)
	if rates.TCPResetRate > netTCPResetMinRate {
		wRst, cRst := threshold("net.tcp.resets", 5, 100)
		r.EvidenceV2 = append(r.EvidenceV2, emitEvidence("net.tcp.resets", model.DomainNetwork,
			rates.TCPResetRate, wRst, cRst, true, 0.75,
			fmt.Sprintf("TCP RSTs=%.0f/s", rates.TCPResetRate), "1s",
			nil, nil))
	}

	// TCP connection attempt failures (Google SRE: Error signal)
	if rates.TCPAttemptFailRate > netTCPAttemptFailMinRate {
		wAf, cAf := threshold("net.tcp.attemptfails", 5, 100)
		r.EvidenceV2 = append(r.EvidenceV2, emitEvidence("net.tcp.attemptfails", model.DomainNetwork,
			rates.TCPAttemptFailRate, wAf, cAf, true, 0.8,
			fmt.Sprintf("TCP attempt fails=%.0f/s", rates.TCPAttemptFailRate), "1s",
			nil, nil))
	}

	// Sentinel: BPF-measured packet drops and TCP resets
	if sent := curr.Global.Sentinel; sent.Active {
		if sent.PktDropRate > 0 {
			// Build reason breakdown — only non-benign reasons
			dropDetail := fmt.Sprintf("BPF pkt drops=%.0f/s", sent.PktDropRate)
			var topReasons []string
			var topReason string
			for _, d := range sent.PktDrops {
				if d.Rate < netBPFDropMinRate {
					continue
				}
				if isBenignDropReasonStr(d.ReasonStr) {
					continue
				}
				if topReason == "" {
					topReason = d.ReasonStr
				}
				if len(topReasons) < 3 {
					topReasons = append(topReasons, fmt.Sprintf("%s:%.0f/s", d.ReasonStr, d.Rate))
				}
			}
			if len(topReasons) > 0 {
				dropDetail += " — " + strings.Join(topReasons, ", ")
			}
			if topReason != "" {
				dropDetail += " | " + dropReasonImpact(topReason)
			}
			// Add kernel function where drops happen (the real "where")
			if len(sent.PktDropLocs) > 0 {
				var locParts []string
				for _, loc := range sent.PktDropLocs {
					if len(locParts) >= 2 || loc.Rate < 1 {
						break
					}
					locParts = append(locParts, fmt.Sprintf("%s:%.0f/s", loc.Function, loc.Rate))
				}
				if len(locParts) > 0 {
					dropDetail += " @ " + strings.Join(locParts, ", ")
				}
			}
			// Add protocol breakdown
			if len(sent.PktDropProto) > 0 {
				var protoParts []string
				for _, p := range sent.PktDropProto {
					if p.Rate >= 1 {
						protoParts = append(protoParts, fmt.Sprintf("%s:%.0f/s", p.Proto, p.Rate))
					}
				}
				if len(protoParts) > 0 {
					dropDetail += " proto=" + strings.Join(protoParts, ",")
				}
			}
			r.EvidenceV2 = append(r.EvidenceV2, emitEvidence("net.sentinel.drops", model.DomainNetwork,
				sent.PktDropRate, 1, 100, true, 0.95,
				dropDetail, "1s",
				nil, nil))
		}
		if sent.TCPResetRate > 0 {
			r.EvidenceV2 = append(r.EvidenceV2, emitEvidence("net.sentinel.resets", model.DomainNetwork,
				sent.TCPResetRate, 1, 50, true, 0.95,
				fmt.Sprintf("BPF TCP RSTs=%.0f/s", sent.TCPResetRate), "1s",
				nil, nil))
		}
	}

	// Conntrack kernel failure rates
	w6a, c6a := threshold("net.conntrack.drops", 1, 100)
	w6b, c6b := threshold("net.conntrack.insertfail", 0.1, 10)
	ctGrowth := rates.ConntrackGrowthRate
	if ctGrowth < 0 {
		ctGrowth = 0 // only fire evidence on positive growth
	}
	w6c, c6c := threshold("net.conntrack.growth", 100, 1000)
	w6d, c6d := threshold("net.conntrack.invalid", 10, 500)
	w6e, c6e := threshold("net.conntrack.hashcontention", 100, 5000)
	r.EvidenceV2 = append(r.EvidenceV2,
		emitEvidence("net.conntrack.drops", model.DomainNetwork,
			rates.ConntrackDropRate, w6a, c6a, true, 0.95,
			fmt.Sprintf("conntrack drops=%.0f/s", rates.ConntrackDropRate), "1s",
			nil, nil),
		emitEvidence("net.conntrack.insertfail", model.DomainNetwork,
			rates.ConntrackInsertFailRate, w6b, c6b, true, 0.95,
			fmt.Sprintf("conntrack insert_failed=%.1f/s", rates.ConntrackInsertFailRate), "1s",
			nil, nil),
		emitEvidence("net.conntrack.growth", model.DomainNetwork,
			ctGrowth, w6c, c6c, false, 0.7,
			fmt.Sprintf("conntrack growth=%.0f/s", rates.ConntrackGrowthRate), "1s",
			nil, nil),
		emitEvidence("net.conntrack.invalid", model.DomainNetwork,
			rates.ConntrackInvalidRate, w6d, c6d, false, 0.6,
			fmt.Sprintf("conntrack invalid=%.0f/s", rates.ConntrackInvalidRate), "1s",
			nil, nil),
		emitEvidence("net.conntrack.hashcontention", model.DomainNetwork,
			rates.ConntrackSearchRestartRate, w6e, c6e, false, 0.6,
			fmt.Sprintf("conntrack search_restart=%.0f/s", rates.ConntrackSearchRestartRate), "1s",
			nil, nil),
	)

	// Dedicated CLOSE_WAIT evidence with per-PID attribution
	w6, c6 := threshold("net.closewait", 50, 500)
	cwMsg := fmt.Sprintf("CLOSE_WAIT=%d", st.CloseWait)
	if len(curr.Global.CloseWaitLeakers) > 0 {
		top := curr.Global.CloseWaitLeakers[0]
		cwMsg = fmt.Sprintf("CLOSE_WAIT=%d — %s(PID %d) holds %d, oldest %s",
			st.CloseWait, top.Comm, top.PID, top.Count, fmtAge(top.OldestAge))
	}
	r.EvidenceV2 = append(r.EvidenceV2,
		emitEvidence("net.closewait", model.DomainNetwork,
			float64(st.CloseWait), w6, c6, true, 0.8,
			cwMsg, "1s",
			nil, nil),
	)

	// --- Network security evidence (BPF sentinel) ---
	var maxSynRate float64
	var maxPortBuckets int
	if curr.Global.Sentinel.Active {
		// SYN flood detection
		for _, sf := range curr.Global.Sentinel.SynFlood {
			if sf.Rate > maxSynRate {
				maxSynRate = sf.Rate
			}
		}
		if maxSynRate > 0 {
			ws, cs := threshold("sec.synflood", 100, 1000)
			r.EvidenceV2 = append(r.EvidenceV2, emitEvidence("sec.synflood", model.DomainNetwork,
				maxSynRate, ws, cs, true, 0.9,
				fmt.Sprintf("SYN flood: %.0f SYN/s from single source", maxSynRate), "3s",
				nil, nil))
		}

		// Port scan detection
		for _, ps := range curr.Global.Sentinel.PortScans {
			if ps.UniquePortBuckets > maxPortBuckets {
				maxPortBuckets = ps.UniquePortBuckets
			}
		}
		if maxPortBuckets >= netPortScanMinBuckets {
			ws, cs := threshold("sec.portscan", 15, 40)
			r.EvidenceV2 = append(r.EvidenceV2, emitEvidence("sec.portscan", model.DomainNetwork,
				float64(maxPortBuckets), ws, cs, true, 0.85,
				fmt.Sprintf("Port scan: %d unique port groups from single source", maxPortBuckets), "3s",
				nil, nil))
		}

		// DNS anomaly detection
		maxDNSRate := float64(0)
		for _, dns := range curr.Global.Sentinel.DNSAnomaly {
			if dns.QueriesPerSec > maxDNSRate {
				maxDNSRate = dns.QueriesPerSec
			}
		}
		if maxDNSRate > 0 {
			ws, cs := threshold("sec.dns.anomaly", 50, 200)
			r.EvidenceV2 = append(r.EvidenceV2, emitEvidence("sec.dns.anomaly", model.DomainNetwork,
				maxDNSRate, ws, cs, true, 0.8,
				fmt.Sprintf("DNS anomaly: %.0f queries/s", maxDNSRate), "3s",
				nil, nil))
		}

		// Lateral movement detection
		maxDests := 0
		for _, fr := range curr.Global.Sentinel.FlowRates {
			if fr.UniqueDestCount > maxDests {
				maxDests = fr.UniqueDestCount
			}
		}
		if maxDests >= netLateralMinDests {
			ws, cs := threshold("sec.lateral", 200, 500)
			r.EvidenceV2 = append(r.EvidenceV2, emitEvidence("sec.lateral", model.DomainNetwork,
				float64(maxDests), ws, cs, true, 0.75,
				fmt.Sprintf("Lateral movement: %d unique destinations from single PID", maxDests), "3s",
				nil, nil))
		}

		// Data exfiltration detection — exclude private IPs and known SSH session IPs
		// SSH management traffic to admin IPs is not exfiltration
		sshIPs := make(map[string]bool)
		for _, sess := range curr.Global.Sessions {
			if sess.From == "" || sess.From == "-" {
				continue
			}
			// Strip :port suffix (SSH sessions may include port info)
			ip := sess.From
			if h, _, err := net.SplitHostPort(sess.From); err == nil {
				ip = h
			}
			sshIPs[ip] = true
		}
		maxEgressMBHr := float64(0)
		for _, ob := range curr.Global.Sentinel.OutboundTop {
			if isPrivateIPStr(ob.DstIP) || sshIPs[ob.DstIP] {
				continue
			}
			mbhr := ob.BytesPerSec * 3600 / (1024 * 1024)
			if mbhr > maxEgressMBHr {
				maxEgressMBHr = mbhr
			}
		}
		if maxEgressMBHr > netExfilMinMBHr {
			ws, cs := threshold("sec.outbound.exfil", 500, 5000)
			r.EvidenceV2 = append(r.EvidenceV2, emitEvidence("sec.outbound.exfil", model.DomainNetwork,
				maxEgressMBHr, ws, cs, true, 0.8,
				fmt.Sprintf("Outbound data: %.0f MB/hr to single destination", maxEgressMBHr), "3s",
				nil, nil))
		}
	}

	// Watchdog-derived evidence (from SecurityMetrics)
	// DNS tunneling (from dnsdeep watchdog)
	maxTXTRatio := float64(0)
	for _, dt := range curr.Global.Security.DNSTunnelIndicators {
		if dt.TXTRatio > maxTXTRatio {
			maxTXTRatio = dt.TXTRatio
		}
	}
	if maxTXTRatio > 0 {
		ws, cs := threshold("sec.dns.tunnel", 0.3, 0.7)
		r.EvidenceV2 = append(r.EvidenceV2, emitEvidence("sec.dns.tunnel", model.DomainNetwork,
			maxTXTRatio, ws, cs, true, 0.85,
			fmt.Sprintf("DNS tunneling: %.0f%% TXT queries", maxTXTRatio*100), "60s",
			nil, nil))
	}

	// C2 beacon detection (from beacondetect watchdog)
	minJitter := float64(1.0)
	for _, bi := range curr.Global.Security.BeaconIndicators {
		if bi.Jitter < minJitter && bi.SampleCount >= netBeaconMinSamples {
			minJitter = bi.Jitter
		}
	}
	if minJitter < 1.0 && len(curr.Global.Security.BeaconIndicators) > 0 {
		// Invert: lower jitter = more suspicious = higher value for normalize
		invertedJitter := 1.0 - minJitter
		ws, cs := threshold("sec.beacon", 0.80, 0.95)
		r.EvidenceV2 = append(r.EvidenceV2, emitEvidence("sec.beacon", model.DomainNetwork,
			invertedJitter, ws, cs, true, 0.85,
			fmt.Sprintf("C2 beacon: %.1f%% jitter (regular intervals)", minJitter*100), "120s",
			nil, nil))
	}

	// TCP flag anomalies (from tcpflags watchdog)
	totalFlagCount := uint64(0)
	for _, fa := range curr.Global.Security.TCPFlagAnomalies {
		totalFlagCount += fa.Count
	}
	if totalFlagCount > 0 {
		ws, cs := threshold("sec.tcp.flags", 1, 10)
		r.EvidenceV2 = append(r.EvidenceV2, emitEvidence("sec.tcp.flags", model.DomainNetwork,
			float64(totalFlagCount), ws, cs, true, 0.9,
			fmt.Sprintf("TCP flag anomalies: %d suspicious packets", totalFlagCount), "60s",
			nil, nil))
	}

	// v2 scoring
	v2Score := weightedDomainScore(r.EvidenceV2)
	if !v2TrustGate(r.EvidenceV2) {
		v2Score = 0
	}
	r.Score = int(v2Score)
	hasSecEvidence := false
	for _, e := range r.EvidenceV2 {
		if strings.HasPrefix(e.ID, "sec.") && e.Strength >= evidenceStrengthMin {
			hasSecEvidence = true
			break
		}
	}
	if !hasSecEvidence && totalDrops < netEvDropsMin && retransRate < netRetransLowRate {
		if r.Score > netNoSecMaxScore {
			r.Score = netNoSecMaxScore
		}
	}
	if totalDrops > netEvDropsMin && rates.CPUSoftIRQPct > netEvSoftIRQMin && v2TrustGate(r.EvidenceV2) {
		r.Score += netDropsSoftIRQBonus
	}
	if r.Score < rcaScoreFloor && !hasSecEvidence {
		r.Score = 0
	}
	cap100(&r.Score)
	r.EvidenceGroups = evidenceGroupsFired(r.EvidenceV2, evidenceStrengthMin)
	r.Checks = evidenceToChecks(r.EvidenceV2)

	// Evidence strings
	if totalDrops > netEvDropsMin {
		r.Evidence = append(r.Evidence, fmt.Sprintf("Network drops=%.0f/s", totalDrops))
	}
	if retransRate > netEvRetransMin {
		r.Evidence = append(r.Evidence, fmt.Sprintf("TCP retransmits=%.0f/s", retransRate))
	}
	if conntrackPct > netEvConntrackPctMin {
		r.Evidence = append(r.Evidence, fmt.Sprintf("Conntrack=%.0f%% (%d/%d)", conntrackPct*100, ct.Count, ct.Max))
	}
	if rates.CPUSoftIRQPct > netEvSoftIRQMin {
		r.Evidence = append(r.Evidence, fmt.Sprintf("SoftIRQ CPU=%.1f%%", rates.CPUSoftIRQPct))
	}
	if st.TimeWait > netEvTimeWaitMin {
		r.Evidence = append(r.Evidence, fmt.Sprintf("TIME_WAIT=%d (port exhaustion risk)", st.TimeWait))
	}
	if st.CloseWait > netEvCloseWaitMin {
		cwEvStr := fmt.Sprintf("CLOSE_WAIT=%d (app not closing)", st.CloseWait)
		if len(curr.Global.CloseWaitLeakers) > 0 {
			top := curr.Global.CloseWaitLeakers[0]
			cwEvStr = fmt.Sprintf("CLOSE_WAIT=%d — %s(PID %d) holds %d, oldest %s",
				st.CloseWait, top.Comm, top.PID, top.Count, fmtAge(top.OldestAge))
		}
		r.Evidence = append(r.Evidence, cwEvStr)
	}
	if totalErrors > netEvErrorsMin {
		r.Evidence = append(r.Evidence, fmt.Sprintf("Network errors=%.0f/s", totalErrors))
	}
	if ephPct > netEvEphemeralMin {
		r.Evidence = append(r.Evidence, fmt.Sprintf("Ephemeral ports=%.0f%% (%d/%d)", ephPct, eph.InUse, ephRange))
	}
	if maxSynRate > netEvSynFloodMin {
		r.Evidence = append(r.Evidence, fmt.Sprintf("SYN flood: %.0f/s", maxSynRate))
	}
	if maxPortBuckets > netEvPortScanMin {
		r.Evidence = append(r.Evidence, fmt.Sprintf("Port scan: %d port groups", maxPortBuckets))
	}

	// Chain
	if r.Score > 0 && r.EvidenceGroups >= minEvidenceGroups {
		if retransRate > netEvRetransMin {
			r.Chain = append(r.Chain, fmt.Sprintf("retrans=%.0f/s", retransRate))
		}
		if totalDrops > netEvDropsMin {
			r.Chain = append(r.Chain, fmt.Sprintf("drops=%.0f/s", totalDrops))
		}
		r.Chain = append(r.Chain, "connection quality risk")
	}

	return r
}
