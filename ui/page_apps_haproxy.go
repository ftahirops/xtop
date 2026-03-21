//go:build linux

package ui

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/ftahirops/xtop/model"
)

func renderHAProxyDeepMetrics(app model.AppInstance, iw int) string {
	var sb strings.Builder
	dm := app.DeepMetrics
	thirdW := (iw - 10) / 3
	halfW := (iw - 8) / 2

	// ── Health Checks + Proxy Info (side by side) ───────────────────────
	type hRow struct{ metric, value, status string }
	hRows := []hRow{}
	haAddH := func(name, val, ref string, wT, cT float64, hi bool) {
		if val == "" { return }
		v, _ := strconv.ParseFloat(val, 64)
		st := "OK"
		if hi { if v >= cT { st = "CRIT" } else if v >= wT { st = "WARN" }
		} else { if v <= cT { st = "CRIT" } else if v <= wT { st = "WARN" } }
		d := val; if ref != "" { d = val + "/" + ref }
		hRows = append(hRows, hRow{name, d, st})
	}
	haAddH("Servers Down", dm["servers_down"], dm["servers_total"], 1, 3, true)
	if dm["curr_conn"] != "" && dm["max_conn"] != "" {
		curr, _ := strconv.ParseFloat(dm["curr_conn"], 64)
		max, _ := strconv.ParseFloat(dm["max_conn"], 64)
		if max > 0 {
			pct := curr / max * 100
			st := "OK"; if pct > 90 { st = "CRIT" } else if pct > 75 { st = "WARN" }
			hRows = append(hRows, hRow{"Conn Usage", fmt.Sprintf("%s/%s (%.0f%%)", dm["curr_conn"], dm["max_conn"], pct), st})
		}
	}
	haAddH("Queue", dm["queue_current"], "", 10, 50, true)
	haAddH("5xx Rate%", dm["err_5xx_pct"], "", 1, 5, true)
	haAddH("4xx Rate%", dm["err_4xx_pct"], "", 5, 20, true)
	haAddH("CPU Idle%", dm["idle_pct"], "", 25, 10, false)
	haAddH("Conn Err%", dm["conn_err_pct"], "", 1, 5, true)
	haAddH("Retry%", dm["retry_pct"], "", 1, 5, true)

	infraKVs := []kv{
		{Key: "Role", Val: dm["proxy_role"]},
		{Key: "HTTP FE/BE", Val: haJoin(dm["http_frontends"], dm["http_backends"])},
		{Key: "TCP FE/BE", Val: haJoin(dm["tcp_frontends"], dm["tcp_backends"])},
		{Key: "Servers", Val: haServersLine(dm)},
		{Key: "MaxConn", Val: dm["max_conn"]},
		{Key: "Workers", Val: dm["workers"]},
		{Key: "Ports", Val: dm["listen_ports"]},
		{Key: "Stats", Val: dm["cfg_stats_uri"]},
	}

	sb.WriteString("  " + titleStyle.Render("HEALTH CHECKS") + strings.Repeat(" ", halfW-16) + titleStyle.Render("PROXY & INFRASTRUCTURE") + "\n")
	sb.WriteString(boxTop(iw) + "\n")
	cCheck, cVal := 14, 24
	leftHdr := fmt.Sprintf("  %s %s %s", styledPad(dimStyle.Render("Check"), cCheck), styledPad(dimStyle.Render("Value"), cVal), dimStyle.Render("St"))
	sb.WriteString(boxRow(fmt.Sprintf("%s  %s", styledPad(leftHdr, halfW), dimStyle.Render("Parameter        Value")), iw) + "\n")
	sb.WriteString(boxMid(iw) + "\n")

	maxRows := len(hRows); if len(infraKVs) > maxRows { maxRows = len(infraKVs) }
	for i := 0; i < maxRows; i++ {
		var left, right string
		if i < len(hRows) {
			r := hRows[i]
			badge := okStyle.Render(" OK ")
			if r.status == "WARN" { badge = warnStyle.Render("WARN") } else if r.status == "CRIT" { badge = critStyle.Render("CRIT") }
			left = fmt.Sprintf("  %s %s %s", styledPad(valueStyle.Render(r.metric), cCheck), styledPad(valueStyle.Render(r.value), cVal), badge)
		}
		if i < len(infraKVs) && infraKVs[i].Val != "" {
			right = fmt.Sprintf("  %s %s", styledPad(dimStyle.Render(infraKVs[i].Key+":"), 14), valueStyle.Render(infraKVs[i].Val))
		}
		sb.WriteString(boxRow(fmt.Sprintf("%s%s", styledPad(left, halfW), right), iw) + "\n")
	}
	sb.WriteString(boxBot(iw) + "\n\n")

	// ── Traffic & Throughput (3-column) ──────────────────────────────────
	sb.WriteString("  " + titleStyle.Render("TRAFFIC & THROUGHPUT") + "\n")
	sb.WriteString(boxTop(iw) + "\n")
	haRender3Col(&sb, iw, thirdW, []kv{
		{Key: "In Req/s", Val: haSuffix(dm["fe_req_rate"], "/s")},
		{Key: "Out Req/s", Val: haSuffix(dm["be_req_rate"], "/s")},
		{Key: "Sess Rate", Val: haSuffix(dm["session_rate"], "/s")},
		{Key: "Cur Sess", Val: dm["current_sessions"]},
	}, []kv{
		{Key: "Total In", Val: haFmtNum(dm["fe_req_total"])},
		{Key: "Total Out", Val: haFmtNum(dm["be_req_total"])},
		{Key: "Total Sess", Val: haFmtNum(dm["total_sessions"])},
		{Key: "Max Sess/s", Val: dm["max_sess_rate"]},
	}, []kv{
		{Key: "Bytes In", Val: haFmtBytes(dm["bytes_in"])},
		{Key: "Bytes Out", Val: haFmtBytes(dm["bytes_out"])},
		{Key: "Queue", Val: dm["queue_current"] + "/" + dm["queue_max"]},
		{Key: "Total Conns", Val: haFmtNum(dm["total_connections"])},
		{Key: "Denied Req", Val: haFmtNonZero(dm["total_dreq"])},
		{Key: "Denied Resp", Val: haFmtNonZero(dm["total_dresp"])},
	})
	sb.WriteString(boxBot(iw) + "\n\n")


	// ── BACKENDS ────────────────────────────────────────────────────────
	beCount, _ := strconv.Atoi(dm["be_detail_count"])
	if beCount > 0 {
		// Backend summary line
		beSumm := fmt.Sprintf("%s backends, %s servers (%s up, %s down), %s req/s out, %s 5xx, %s retries",
			dm["backends"], dm["servers_total"], dm["servers_up"], dm["servers_down"],
			dm["be_req_rate"], haFmtNum(dm["http_5xx"]), haFmtNum(dm["retries"]))
		sb.WriteString("  " + titleStyle.Render("BACKENDS") + "  " + dimStyle.Render(beSumm) + "\n")
		sb.WriteString(boxTop(iw) + "\n")

		cName, cAddr, cRate, cRt, cErr, c5, cAbrt, cHp, cChk := 20, 18, 7, 10, 7, 7, 9, 9, 16
		hdr := fmt.Sprintf("  %s%s%s%s%s%s%s%s%s%s",
			styledPad(dimStyle.Render("Backend"), cName),
			styledPad(dimStyle.Render("Endpoint"), cAddr),
			styledPad(dimStyle.Render("Req/s"), cRate),
			styledPad(dimStyle.Render("Response"), cRt),
			styledPad(dimStyle.Render("Err%"), cErr),
			styledPad(dimStyle.Render("5xx"), c5),
			styledPad(dimStyle.Render("Aborts"), cAbrt),
			styledPad(dimStyle.Render("Srv"), cHp),
			styledPad(dimStyle.Render("Health Check"), cChk),
			dimStyle.Render("Health"))
		sb.WriteString(boxRow(hdr, iw) + "\n")
		sb.WriteString(boxMid(iw) + "\n")

		for i := 0; i < beCount; i++ {
			pre := fmt.Sprintf("be_detail_%d_", i)
			name := dm[pre+"name"]
			addr := dm[pre+"addr"]
			rate := dm[pre+"sess_rate"]
			errPct := dm[pre+"err_pct"]
			h5xx := dm[pre+"5xx"]
			cliA := dm[pre+"cli_abrt"]
			srvA := dm[pre+"srv_abrt"]
			srvUp := dm[pre+"servers_up"]
			srvDown := dm[pre+"servers_down"]
			srvTotal := dm[pre+"servers_total"]
			rtime := dm[pre+"rtime"]
			beHealth := dm[pre+"health"]
			checkSt := dm[pre+"check_status"]

			if len(name) > 18 { name = name[:18] }
			if len(addr) > 16 { addr = addr[:16] }

			// Error %
			errStr := "0"
			if errPct != "" && errPct != "0.00" {
				ep, _ := strconv.ParseFloat(errPct, 64)
				if ep > 5 { errStr = critStyle.Render(errPct+"%") } else if ep > 1 { errStr = warnStyle.Render(errPct+"%") } else { errStr = errPct + "%" }
			}

			// Response time colored
			rtStr := rtime + "ms"
			if rt, _ := strconv.Atoi(rtime); rt > 5000 {
				rtStr = critStyle.Render(rtime + "ms")
			} else if rt > 2000 {
				rtStr = warnStyle.Render(rtime + "ms")
			}

			srvLine := srvUp + "/" + srvTotal
			if srvDown != "" && srvDown != "0" { srvLine += " " + critStyle.Render(srvDown+"d") }
			abortLine := haFmtNum(cliA) + "/" + haFmtNum(srvA)

			// Health badge
			var hBadge string
			switch beHealth {
			case "HEALTHY":  hBadge = okStyle.Render("HEALTHY")
			case "DEGRADED": hBadge = warnStyle.Render("DEGRADED")
			case "SLOW":     hBadge = warnStyle.Render("SLOW")
			case "CRITICAL": hBadge = critStyle.Render("CRITICAL")
			case "DOWN":     hBadge = critStyle.Render("DOWN")
			default:         hBadge = dimStyle.Render("?")
			}

			// Health check column
			var chkStr string
			if checkSt == "disabled" || checkSt == "" {
				chkStr = dimStyle.Render("no check")
			} else if strings.Contains(checkSt, "failing") {
				chkStr = critStyle.Render(checkSt)
				if len(checkSt) > 14 { chkStr = critStyle.Render(checkSt[:14]) }
			} else {
				chkStr = okStyle.Render(checkSt)
				if len(checkSt) > 14 { chkStr = okStyle.Render(checkSt[:14]) }
			}

			row := fmt.Sprintf("  %s%s%s%s%s%s%s%s%s%s",
				styledPad(valueStyle.Render(name), cName),
				styledPad(dimStyle.Render(addr), cAddr),
				styledPad(valueStyle.Render(rate+"/s"), cRate),
				styledPad(rtStr, cRt),
				styledPad(errStr, cErr),
				styledPad(haColorVal(haFmtNum(h5xx), "5xx"), c5),
				styledPad(valueStyle.Render(abortLine), cAbrt),
				styledPad(valueStyle.Render(srvLine), cHp),
				styledPad(chkStr, cChk),
				hBadge)
			sb.WriteString(boxRow(row, iw) + "\n")
		}
		sb.WriteString(boxBot(iw) + "\n\n")
	}

	// ── SLOW BACKENDS SPOTLIGHT ─────────────────────────────────────────
	slowBeCount, _ := strconv.Atoi(dm["slow_be_count"])
	if slowBeCount > 0 {
		sb.WriteString("  " + titleStyle.Render("SLOW BACKENDS") + "\n")
		sb.WriteString(boxTop(iw) + "\n")
		cSN, cSA, cSQ, cSC, cSR := 22, 20, 12, 12, 12
		sb.WriteString(boxRow(fmt.Sprintf("  %s%s%s%s%s%s",
			styledPad(dimStyle.Render("Backend"), cSN),
			styledPad(dimStyle.Render("Endpoint"), cSA),
			styledPad(dimStyle.Render("Queue"), cSQ),
			styledPad(dimStyle.Render("Connect"), cSC),
			styledPad(dimStyle.Render("Response"), cSR),
			dimStyle.Render("Total")), iw) + "\n")
		sb.WriteString(boxMid(iw) + "\n")
		for i := 0; i < slowBeCount; i++ {
			pre := fmt.Sprintf("slow_be_%d_", i)
			sName := dm[pre+"name"]
			sAddr := dm[pre+"addr"]
			sQ := dm[pre+"qtime"] + "ms"
			sC := dm[pre+"ctime"] + "ms"
			sR := dm[pre+"rtime"] + "ms"
			sT := dm[pre+"ttime"] + "ms"
			if len(sName) > 20 { sName = sName[:20] }
			if len(sAddr) > 18 { sAddr = sAddr[:18] }
			// Color response time
			rVal := valueStyle.Render(sR)
			if rt, _ := strconv.Atoi(dm[pre+"rtime"]); rt > 5000 {
				rVal = critStyle.Render(sR)
			} else if rt > 2000 {
				rVal = warnStyle.Render(sR)
			}
			row := fmt.Sprintf("  %s%s%s%s%s%s",
				styledPad(valueStyle.Render(sName), cSN),
				styledPad(dimStyle.Render(sAddr), cSA),
				styledPad(valueStyle.Render(sQ), cSQ),
				styledPad(valueStyle.Render(sC), cSC),
				styledPad(rVal, cSR),
				valueStyle.Render(sT))
			sb.WriteString(boxRow(row, iw) + "\n")
		}
		sb.WriteString(boxBot(iw) + "\n\n")
	}

	// ── RETRY & REDISPATCH ANALYSIS ─────────────────────────────────────
	{
		type retryRow struct{ name, retries, wredis, retryPct, reqs string }
		var retryRows []retryRow
		for i := 0; i < beCount; i++ {
			pre := fmt.Sprintf("be_detail_%d_", i)
			retries := dm[pre+"retries"]
			if retries == "" || retries == "0" { continue }
			retryRows = append(retryRows, retryRow{
				name:     dm[pre+"name"],
				retries:  retries,
				wredis:   dm[pre+"wredis"],
				retryPct: dm[pre+"retry_pct"],
				reqs:     dm[pre+"req_total"],
			})
		}
		if len(retryRows) > 0 {
			sb.WriteString("  " + titleStyle.Render("RETRY & REDISPATCH ANALYSIS") + "\n")
			sb.WriteString(boxTop(iw) + "\n")
			cRN, cRR, cRD, cRP := 22, 12, 12, 10
			sb.WriteString(boxRow(fmt.Sprintf("  %s%s%s%s%s",
				styledPad(dimStyle.Render("Backend"), cRN),
				styledPad(dimStyle.Render("Retries"), cRR),
				styledPad(dimStyle.Render("Redispatch"), cRD),
				styledPad(dimStyle.Render("Retry%"), cRP),
				dimStyle.Render("Sessions")), iw) + "\n")
			sb.WriteString(boxMid(iw) + "\n")
			for _, r := range retryRows {
				rName := r.name
				if len(rName) > 20 { rName = rName[:20] }
				row := fmt.Sprintf("  %s%s%s%s%s",
					styledPad(valueStyle.Render(rName), cRN),
					styledPad(valueStyle.Render(haFmtNum(r.retries)), cRR),
					styledPad(valueStyle.Render(haFmtNum(r.wredis)), cRD),
					styledPad(valueStyle.Render(haSuffix(r.retryPct, "%")), cRP),
					valueStyle.Render(haFmtNum(r.reqs)))
				sb.WriteString(boxRow(row, iw) + "\n")
			}
			sb.WriteString(boxBot(iw) + "\n\n")
		}
	}

	// ── PEAK vs CURRENT ─────────────────────────────────────────────────
	if beCount > 0 {
		type peakRow struct{ name, sessCur, sessMax, qCur, qMax string }
		var peakRows []peakRow
		for i := 0; i < beCount; i++ {
			pre := fmt.Sprintf("be_detail_%d_", i)
			scur := dm[pre+"scur"]
			smax := dm[pre+"smax"]
			if scur == "" && smax == "" { continue }
			peakRows = append(peakRows, peakRow{
				name:    dm[pre+"name"],
				sessCur: scur,
				sessMax: smax,
				qCur:    dm[pre+"qcur"],
				qMax:    dm[pre+"qmax"],
			})
		}
		if len(peakRows) > 0 {
			sb.WriteString("  " + titleStyle.Render("PEAK vs CURRENT") + "\n")
			sb.WriteString(boxTop(iw) + "\n")
			cPN, cPS := 22, 20
			sb.WriteString(boxRow(fmt.Sprintf("  %s%s%s",
				styledPad(dimStyle.Render("Backend"), cPN),
				styledPad(dimStyle.Render("Sess Cur/Max"), cPS),
				dimStyle.Render("Queue Cur/Max")), iw) + "\n")
			sb.WriteString(boxMid(iw) + "\n")
			for _, p := range peakRows {
				pName := p.name
				if len(pName) > 20 { pName = pName[:20] }
				sessStr := p.sessCur + "/" + p.sessMax
				qStr := p.qCur + "/" + p.qMax
				row := fmt.Sprintf("  %s%s%s",
					styledPad(valueStyle.Render(pName), cPN),
					styledPad(valueStyle.Render(sessStr), cPS),
					valueStyle.Render(qStr))
				sb.WriteString(boxRow(row, iw) + "\n")
			}
			sb.WriteString(boxBot(iw) + "\n\n")
		}
	}

	// ── CONFIG WARNINGS ─────────────────────────────────────────────────
	cfgWarnCount, _ := strconv.Atoi(dm["config_warning_count"])
	if cfgWarnCount > 0 {
		sb.WriteString("  " + titleStyle.Render("CONFIG WARNINGS") + "\n")
		sb.WriteString(boxTop(iw) + "\n")
		for i := 0; i < cfgWarnCount; i++ {
			w := dm[fmt.Sprintf("config_warning_%d", i)]
			if w == "" { continue }
			sb.WriteString(boxRow("  "+warnStyle.Render("!")+dimStyle.Render(" "+w), iw) + "\n")
		}
		sb.WriteString(boxBot(iw) + "\n\n")
	}

	// ── LAST STATE CHANGES ──────────────────────────────────────────────
	stateChgCount, _ := strconv.Atoi(dm["state_change_count"])
	if stateChgCount > 0 {
		sb.WriteString("  " + titleStyle.Render("LAST STATE CHANGES") + "\n")
		sb.WriteString(boxTop(iw) + "\n")
		cSS, cSB, cSSt := 20, 20, 12
		sb.WriteString(boxRow(fmt.Sprintf("  %s%s%s%s",
			styledPad(dimStyle.Render("Server"), cSS),
			styledPad(dimStyle.Render("Backend"), cSB),
			styledPad(dimStyle.Render("Status"), cSSt),
			dimStyle.Render("Changed Ago")), iw) + "\n")
		sb.WriteString(boxMid(iw) + "\n")
		for i := 0; i < stateChgCount; i++ {
			pre := fmt.Sprintf("state_change_%d_", i)
			srv := dm[pre+"server"]
			be := dm[pre+"backend"]
			status := dm[pre+"status"]
			lastchg := dm[pre+"lastchg"]
			if len(srv) > 18 { srv = srv[:18] }
			if len(be) > 18 { be = be[:18] }
			// Color status
			var stBadge string
			switch status {
			case "UP":   stBadge = okStyle.Render(status)
			case "DOWN": stBadge = critStyle.Render(status)
			default:     stBadge = warnStyle.Render(status)
			}
			row := fmt.Sprintf("  %s%s%s%s",
				styledPad(valueStyle.Render(srv), cSS),
				styledPad(valueStyle.Render(be), cSB),
				styledPad(stBadge, cSSt),
				dimStyle.Render(haFmtDuration(lastchg)))
			sb.WriteString(boxRow(row, iw) + "\n")
		}
		sb.WriteString(boxBot(iw) + "\n\n")
	}

	// ── FRONTENDS ───────────────────────────────────────────────────────
	feCount, _ := strconv.Atoi(dm["fe_detail_count"])
	if feCount > 0 {
		// Frontend summary line
		feTotalReq := dm["total_sessions"]
		fe2xxPctStr, fe5xxPctStr := "", ""
		if tot, _ := strconv.ParseFloat(feTotalReq, 64); tot > 0 {
			v2, _ := strconv.ParseFloat(dm["fe_2xx"], 64)
			v5, _ := strconv.ParseFloat(dm["fe_5xx"], 64)
			fe2xxPctStr = fmt.Sprintf(" (%.1f%%)", v2/tot*100)
			fe5xxPctStr = fmt.Sprintf(" (%.1f%%)", v5/tot*100)
		}
		feSumm := fmt.Sprintf("%s frontends, %s req/s in, %s 2xx%s, %s 5xx%s, %s ereq",
			dm["frontends"], dm["fe_req_rate"], haFmtNum(dm["fe_2xx"]), fe2xxPctStr, haFmtNum(dm["fe_5xx"]), fe5xxPctStr, haFmtNum(dm["fe_ereq"]))
		sb.WriteString("  " + titleStyle.Render("FRONTENDS") + "  " + dimStyle.Render(feSumm) + "\n")
		sb.WriteString(boxTop(iw) + "\n")

		cFN, cFM, cFR, cFRr, cFBi, cFBo, cF2, cF2p, cF5, cF5p := 20, 8, 8, 10, 12, 12, 10, 7, 10, 7
		feHdr := fmt.Sprintf("  %s%s%s%s%s%s%s%s%s%s%s",
			styledPad(dimStyle.Render("Frontend"), cFN),
			styledPad(dimStyle.Render("Mode"), cFM),
			styledPad(dimStyle.Render("Cur"), cFR),
			styledPad(dimStyle.Render("Req/s"), cFRr),
			styledPad(dimStyle.Render("In"), cFBi),
			styledPad(dimStyle.Render("Out"), cFBo),
			styledPad(dimStyle.Render("2xx"), cF2),
			styledPad(dimStyle.Render("2xx%"), cF2p),
			styledPad(dimStyle.Render("5xx"), cF5),
			styledPad(dimStyle.Render("5xx%"), cF5p),
			dimStyle.Render("Health"))
		sb.WriteString(boxRow(feHdr, iw) + "\n")
		sb.WriteString(boxMid(iw) + "\n")

		for i := 0; i < feCount; i++ {
			pre := fmt.Sprintf("fe_detail_%d_", i)
			feName := dm[pre+"name"]
			feMode := dm[pre+"mode"]
			feCur := dm[pre+"scur"]
			feRR := dm[pre+"req_rate"]
			feBin := dm[pre+"bin"]
			feBout := dm[pre+"bout"]
			fe2 := dm[pre+"2xx"]
			fe5 := dm[pre+"5xx"]
			feStot := dm[pre+"stot"]
			feH := dm[pre+"health"]

			if len(feName) > 18 { feName = feName[:18] }

			// Compute percentages
			fe2pct, fe5pct := "—", "—"
			if tot, _ := strconv.ParseFloat(feStot, 64); tot > 0 {
				v2, _ := strconv.ParseFloat(fe2, 64)
				v5, _ := strconv.ParseFloat(fe5, 64)
				fe2pct = fmt.Sprintf("%.1f%%", v2/tot*100)
				fe5pct = fmt.Sprintf("%.1f%%", v5/tot*100)
			}

			var hBadge string
			switch feH {
			case "HEALTHY":  hBadge = okStyle.Render("HEALTHY")
			case "DEGRADED": hBadge = warnStyle.Render("DEGRADED")
			case "CRITICAL": hBadge = critStyle.Render("CRITICAL")
			default:         hBadge = dimStyle.Render(feH)
			}

			// Color 5xx% — red if >1%, yellow if >0.1%
			fe5pctStyled := valueStyle.Render(fe5pct)
			if v5, _ := strconv.ParseFloat(fe5, 64); v5 > 0 {
				if tot, _ := strconv.ParseFloat(feStot, 64); tot > 0 {
					pct := v5 / tot * 100
					if pct > 1 {
						fe5pctStyled = critStyle.Render(fe5pct)
					} else if pct > 0.1 {
						fe5pctStyled = warnStyle.Render(fe5pct)
					}
				}
			}

			row := fmt.Sprintf("  %s%s%s%s%s%s%s%s%s%s%s",
				styledPad(valueStyle.Render(feName), cFN),
				styledPad(valueStyle.Render(feMode), cFM),
				styledPad(valueStyle.Render(feCur), cFR),
				styledPad(valueStyle.Render(feRR+"/s"), cFRr),
				styledPad(valueStyle.Render(haFmtBytes(feBin)), cFBi),
				styledPad(valueStyle.Render(haFmtBytes(feBout)), cFBo),
				styledPad(valueStyle.Render(haFmtNum(fe2)), cF2),
				styledPad(okStyle.Render(fe2pct), cF2p),
				styledPad(haColorVal(haFmtNum(fe5), "5xx"), cF5),
				styledPad(fe5pctStyled, cF5p),
				hBadge)
			sb.WriteString(boxRow(row, iw) + "\n")
		}
		// Source IPs inside frontend box
		inboundIPCount, _ := strconv.Atoi(dm["inbound_ip_count"])
		if inboundIPCount > 0 {
			sb.WriteString(boxMid(iw) + "\n")
			sb.WriteString(boxRow("  "+dimStyle.Render("SOURCE IPs"), iw) + "\n")
			sb.WriteString(boxMid(iw) + "\n")
			cIP, cConns, cFE := 20, 14, 20
			sb.WriteString(boxRow(fmt.Sprintf("  %s%s%s%s",
				styledPad(dimStyle.Render("Source IP"), cIP),
				styledPad(dimStyle.Render("Active Conns"), cConns),
				styledPad(dimStyle.Render("Frontend"), cFE),
				dimStyle.Render("% of Traffic")), iw) + "\n")
			for i := 0; i < inboundIPCount; i++ {
				pre := fmt.Sprintf("inbound_ip_%d_", i)
				ip := dm[pre+"addr"]
				conns := dm[pre+"conns"]
				pct := dm[pre+"pct"]
				fe := dm[pre+"frontend"]
				row := fmt.Sprintf("  %s%s%s%s",
					styledPad(valueStyle.Render(ip), cIP),
					styledPad(valueStyle.Render(conns), cConns),
					styledPad(dimStyle.Render(fe), cFE),
					valueStyle.Render(pct+"%"))
				sb.WriteString(boxRow(row, iw) + "\n")
			}
		}

		// TCP states — frontend (inbound) vs backend (outbound) side by side
		if dm["tcp_total"] != "" {
			sb.WriteString(boxMid(iw) + "\n")
			subHdr := fmt.Sprintf("%s%s",
				styledPad("  "+dimStyle.Render(fmt.Sprintf("INBOUND TCP (clients → HAProxy) [%s]", dm["fe_tcp_total"])), halfW),
				"  "+dimStyle.Render(fmt.Sprintf("OUTBOUND TCP (HAProxy → suppliers) [%s]", dm["be_tcp_total"])))
			sb.WriteString(boxRow(subHdr, iw) + "\n")
			feKVs := []kv{
				{Key: "ESTABLISHED", Val: dm["fe_tcp_established"]},
				{Key: "TIME_WAIT", Val: dm["fe_tcp_time_wait"]},
				{Key: "CLOSE_WAIT", Val: haColorTCPState(dm["fe_tcp_close_wait"], "CLOSE_WAIT")},
				{Key: "FIN_WAIT1", Val: haColorTCPState(dm["fe_tcp_fin_wait1"], "FIN_WAIT")},
				{Key: "FIN_WAIT2", Val: haColorTCPState(dm["fe_tcp_fin_wait2"], "FIN_WAIT")},
				{Key: "SYN_RECV", Val: haColorTCPState(dm["fe_tcp_syn_recv"], "SYN_RECV")},
				{Key: "LAST_ACK", Val: dm["fe_tcp_last_ack"]},
				{Key: "LISTEN", Val: dm["fe_tcp_listen"]},
			}
			beKVs := []kv{
				{Key: "ESTABLISHED", Val: dm["be_tcp_established"]},
				{Key: "TIME_WAIT", Val: dm["be_tcp_time_wait"]},
				{Key: "CLOSE_WAIT", Val: haColorTCPState(dm["be_tcp_close_wait"], "CLOSE_WAIT")},
				{Key: "FIN_WAIT1", Val: haColorTCPState(dm["be_tcp_fin_wait1"], "FIN_WAIT")},
				{Key: "FIN_WAIT2", Val: haColorTCPState(dm["be_tcp_fin_wait2"], "FIN_WAIT")},
				{Key: "SYN_SENT", Val: dm["be_tcp_syn_sent"]},
				{Key: "LAST_ACK", Val: dm["be_tcp_last_ack"]},
			}
			maxR := len(feKVs)
			if len(beKVs) > maxR { maxR = len(beKVs) }
			for i := 0; i < maxR; i++ {
				var left, right string
				if i < len(feKVs) && feKVs[i].Val != "" && feKVs[i].Val != "0" {
					left = fmt.Sprintf("  %s %s", styledPad(dimStyle.Render(feKVs[i].Key+":"), 14), feKVs[i].Val)
				}
				if i < len(beKVs) && beKVs[i].Val != "" && beKVs[i].Val != "0" {
					right = fmt.Sprintf("  %s %s", styledPad(dimStyle.Render(beKVs[i].Key+":"), 14), beKVs[i].Val)
				}
				if left != "" || right != "" {
					sb.WriteString(boxRow(fmt.Sprintf("%s%s", styledPad(left, halfW), right), iw) + "\n")
				}
			}

			// Top IPs per direction
			feIPCount, _ := strconv.Atoi(dm["fe_top_ip_count"])
			beIPCount, _ := strconv.Atoi(dm["be_top_ip_count"])
			if feIPCount > 0 || beIPCount > 0 {
				sb.WriteString(boxMid(iw) + "\n")
				subHdr2 := fmt.Sprintf("%s%s",
					styledPad("  "+dimStyle.Render("TOP INBOUND IPs"), halfW),
					"  "+dimStyle.Render("TOP OUTBOUND IPs"))
				sb.WriteString(boxRow(subHdr2, iw) + "\n")
				maxIP := feIPCount
				if beIPCount > maxIP { maxIP = beIPCount }
				for i := 0; i < maxIP; i++ {
					var left, right string
					if i < feIPCount {
						fePfx := fmt.Sprintf("fe_top_ip_%d_", i)
						left = fmt.Sprintf("  %s %s",
							styledPad(valueStyle.Render(dm[fePfx+"ip"]), 18),
							dimStyle.Render(dm[fePfx+"states"]))
					}
					if i < beIPCount {
						bePfx := fmt.Sprintf("be_top_ip_%d_", i)
						right = fmt.Sprintf("  %s %s",
							styledPad(valueStyle.Render(dm[bePfx+"ip"]), 18),
							dimStyle.Render(dm[bePfx+"states"]))
					}
					if left != "" || right != "" {
						sb.WriteString(boxRow(fmt.Sprintf("%s%s", styledPad(left, halfW), right), iw) + "\n")
					}
				}
			}

			// Connection summary below
			sb.WriteString(boxMid(iw) + "\n")
			summKVs := []kv{
				{Key: "Active Sess", Val: dm["inbound_active_sess"]},
				{Key: "Cli Aborts", Val: haFmtNum(dm["client_aborts"])},
				{Key: "Abort Rate", Val: haSuffix(dm["inbound_abort_pct"], "%")},
			}
			summKVs2 := []kv{
				{Key: "Unique IPs", Val: dm["inbound_total_unique"]},
				{Key: "Total TCP", Val: dm["tcp_total"]},
				{Key: "Ports", Val: dm["listen_ports"]},
			}
			for i := 0; i < len(summKVs); i++ {
				var left, right string
				if summKVs[i].Val != "" {
					left = fmt.Sprintf("  %s %s", styledPad(dimStyle.Render(summKVs[i].Key+":"), 14), valueStyle.Render(summKVs[i].Val))
				}
				if i < len(summKVs2) && summKVs2[i].Val != "" {
					right = fmt.Sprintf("  %s %s", styledPad(dimStyle.Render(summKVs2[i].Key+":"), 14), valueStyle.Render(summKVs2[i].Val))
				}
				sb.WriteString(boxRow(fmt.Sprintf("%s%s", styledPad(left, halfW), right), iw) + "\n")
			}
		}
		sb.WriteString(boxBot(iw) + "\n\n")
	}

	// ── DIAGNOSTICS (unified: all RCA in one place) ─────────────────────
	{
		// Collect all diagnostic items
		type diagItem struct {
			severity string
			title    string
			cause    string
			evidence string
			blame    string
			fix      string
		}
		var diags []diagItem

		// 1) RCA per-backend blame (from collector)
		if dm["rca_summary"] != "" && dm["rca_summary"] != "No significant issues detected" {
			rcaBeCount, _ := strconv.Atoi(dm["rca_backend_count"])
			if rcaBeCount > 0 {
				for i := 0; i < rcaBeCount; i++ {
					line := dm[fmt.Sprintf("rca_backend_%d", i)]
					if line != "" {
						diags = append(diags, diagItem{
							severity: "WARN",
							title:    "Backend: " + line,
						})
					}
				}
			}
			if dm["rca_abort_analysis"] != "" {
				diags = append(diags, diagItem{
					severity: "WARN",
					title:    "Aborts: " + dm["rca_abort_analysis"],
				})
			}
		}

		// 2) Inbound diagnostics (from collector)
		issueCount, _ := strconv.Atoi(dm["inbound_issue_count"])
		for i := 0; i < issueCount; i++ {
			pre := fmt.Sprintf("inbound_issue_%d_", i)
			title := dm[pre+"title"]
			if title == "" { continue }
			diags = append(diags, diagItem{
				severity: dm[pre+"severity"],
				title:    title,
				cause:    dm[pre+"cause"],
				evidence: dm[pre+"evidence"],
				blame:    dm[pre+"blame"],
				fix:      dm[pre+"fix"],
			})
		}

		if len(diags) > 0 {
			sb.WriteString("  " + titleStyle.Render("DIAGNOSTICS") + "  " + dimStyle.Render(fmt.Sprintf("%d issues", len(diags))) + "\n")
			sb.WriteString(boxTop(iw) + "\n")

			// Summary line
			if dm["rca_summary"] != "" && dm["rca_summary"] != "No significant issues detected" {
				sb.WriteString(boxRow("  "+critStyle.Render("SUMMARY: ")+valueStyle.Render(dm["rca_summary"]), iw) + "\n")
				sb.WriteString(boxMid(iw) + "\n")
			}

			for idx, d := range diags {
				if idx > 0 { sb.WriteString(boxMid(iw) + "\n") }

				var sevBadge string
				if d.severity == "CRIT" { sevBadge = critStyle.Render("CRIT") } else { sevBadge = warnStyle.Render("WARN") }
				sb.WriteString(boxRow(fmt.Sprintf("  %s %s  %s",
					warnStyle.Render(fmt.Sprintf("#%d", idx+1)), sevBadge, valueStyle.Render(d.title)), iw) + "\n")

				if d.cause != "" {
					sb.WriteString(boxRow("  "+dimStyle.Render("Cause:")+"    "+dimStyle.Render(d.cause), iw) + "\n")
				}
				if d.evidence != "" {
					sb.WriteString(boxRow("  "+dimStyle.Render("Evidence:")+" "+dimStyle.Render(d.evidence), iw) + "\n")
				}
				if d.blame != "" {
					blameStyled := dimStyle.Render(d.blame)
					if strings.HasPrefix(d.blame, "Our side") || strings.HasPrefix(d.blame, "Configuration") {
						blameStyled = warnStyle.Render(d.blame)
					} else if strings.HasPrefix(d.blame, "External") {
						blameStyled = critStyle.Render(d.blame)
					}
					sb.WriteString(boxRow("  "+dimStyle.Render("Blame:")+"    "+blameStyled, iw) + "\n")
				}
				if d.fix != "" {
					sb.WriteString(boxRow("  "+dimStyle.Render("Fix:")+"      "+dimStyle.Render(d.fix), iw) + "\n")
				}
			}
			sb.WriteString(boxBot(iw) + "\n\n")
		}
	}

	return sb.String()
}

// haRender3Col renders 3 columns of kv pairs in a box (no top/bot borders).
func haRender3Col(sb *strings.Builder, iw, thirdW int, c1, c2, c3 []kv) {
	maxR := len(c1)
	if len(c2) > maxR { maxR = len(c2) }
	if len(c3) > maxR { maxR = len(c3) }
	for i := 0; i < maxR; i++ {
		var s1, s2, s3 string
		if i < len(c1) && c1[i].Val != "" { s1 = fmt.Sprintf("  %s %s", styledPad(dimStyle.Render(c1[i].Key+":"), 12), valueStyle.Render(c1[i].Val)) }
		if i < len(c2) && c2[i].Val != "" { s2 = fmt.Sprintf("  %s %s", styledPad(dimStyle.Render(c2[i].Key+":"), 12), valueStyle.Render(c2[i].Val)) }
		if i < len(c3) && c3[i].Val != "" { s3 = fmt.Sprintf("  %s %s", styledPad(dimStyle.Render(c3[i].Key+":"), 12), valueStyle.Render(c3[i].Val)) }
		sb.WriteString(boxRow(fmt.Sprintf("%s%s%s", styledPad(s1, thirdW), styledPad(s2, thirdW), s3), iw) + "\n")
	}
}

// renderHAProxyHealthIssues shows health issues with per-backend error attribution.
func renderHAProxyHealthIssues(app model.AppInstance, iw int) string {
	dm := app.DeepMetrics
	var sb strings.Builder

	sb.WriteString("  " + titleStyle.Render("HEALTH ISSUES") + "\n")
	sb.WriteString(boxTop(iw) + "\n")

	// Show each issue
	for _, issue := range app.HealthIssues {
		row := "  " + critStyle.Render("\u25cf") + " " + valueStyle.Render(issue)
		sb.WriteString(boxRow(row, iw) + "\n")
	}

	// Per-backend error breakdown — find backends with errors
	type beErr struct {
		name    string
		addr    string
		e5xx    int64
		econ    int64
		retries int64
		cliAbrt int64
		rtime   int64
		reqTot  int64
		health  string
	}
	beCount, _ := strconv.Atoi(dm["be_detail_count"])
	var problemBEs []beErr
	for i := 0; i < beCount; i++ {
		pre := fmt.Sprintf("be_detail_%d_", i)
		e5, _ := strconv.ParseInt(dm[pre+"5xx"], 10, 64)
		ec, _ := strconv.ParseInt(dm[pre+"econ"], 10, 64)
		ret, _ := strconv.ParseInt(dm[pre+"retries"], 10, 64)
		ca, _ := strconv.ParseInt(dm[pre+"cli_abrt"], 10, 64)
		rt, _ := strconv.ParseInt(dm[pre+"rtime"], 10, 64)
		rq, _ := strconv.ParseInt(dm[pre+"req_total"], 10, 64)
		h := dm[pre+"health"]
		if e5 > 0 || ec > 0 || ret > 0 || ca > 100 || h == "DEGRADED" || h == "CRITICAL" || h == "DOWN" || h == "SLOW" {
			problemBEs = append(problemBEs, beErr{
				name: dm[pre+"name"], addr: dm[pre+"addr"],
				e5xx: e5, econ: ec, retries: ret, cliAbrt: ca,
				rtime: rt, reqTot: rq, health: h,
			})
		}
	}

	if len(problemBEs) > 0 {
		sb.WriteString(boxMid(iw) + "\n")
		sb.WriteString(boxRow("  "+titleStyle.Render("ERROR BREAKDOWN BY BACKEND"), iw) + "\n")
		sb.WriteString(boxMid(iw) + "\n")

		cN, cA, c5, cE, cR, cAb, cRt := 20, 18, 10, 10, 9, 12, 9
		hdr := fmt.Sprintf("  %s%s%s%s%s%s%s%s",
			styledPad(dimStyle.Render("Backend"), cN),
			styledPad(dimStyle.Render("Endpoint"), cA),
			styledPad(dimStyle.Render("5xx"), c5),
			styledPad(dimStyle.Render("ConnErr"), cE),
			styledPad(dimStyle.Render("Retries"), cR),
			styledPad(dimStyle.Render("Cli Aborts"), cAb),
			styledPad(dimStyle.Render("Resp ms"), cRt),
			dimStyle.Render("Status"))
		sb.WriteString(boxRow(hdr, iw) + "\n")

		for _, be := range problemBEs {
			name := be.name
			if len(name) > 18 { name = name[:18] }
			addr := be.addr
			if len(addr) > 16 { addr = addr[:16] }

			// 5xx with percentage
			e5str := haFmtNum(fmt.Sprintf("%d", be.e5xx))
			if be.reqTot > 0 && be.e5xx > 0 {
				pct := float64(be.e5xx) / float64(be.reqTot) * 100
				e5str += fmt.Sprintf(" %.1f%%", pct)
				if pct > 1 {
					e5str = critStyle.Render(e5str)
				} else {
					e5str = warnStyle.Render(e5str)
				}
			} else {
				e5str = dimStyle.Render("—")
			}

			ecStr := dimStyle.Render("—")
			if be.econ > 0 { ecStr = critStyle.Render(haFmtNum(fmt.Sprintf("%d", be.econ))) }

			retStr := dimStyle.Render("—")
			if be.retries > 0 { retStr = warnStyle.Render(haFmtNum(fmt.Sprintf("%d", be.retries))) }

			abStr := dimStyle.Render("—")
			if be.cliAbrt > 100 { abStr = warnStyle.Render(haFmtNum(fmt.Sprintf("%d", be.cliAbrt))) }

			rtStr := fmt.Sprintf("%dms", be.rtime)
			if be.rtime > 5000 {
				rtStr = critStyle.Render(rtStr)
			} else if be.rtime > 2000 {
				rtStr = warnStyle.Render(rtStr)
			} else {
				rtStr = valueStyle.Render(rtStr)
			}

			var hBadge string
			switch be.health {
			case "HEALTHY":  hBadge = okStyle.Render("OK")
			case "DEGRADED": hBadge = warnStyle.Render("DEGRADED")
			case "SLOW":     hBadge = warnStyle.Render("SLOW")
			case "CRITICAL": hBadge = critStyle.Render("CRITICAL")
			case "DOWN":     hBadge = critStyle.Render("DOWN")
			default:         hBadge = dimStyle.Render(be.health)
			}

			row := fmt.Sprintf("  %s%s%s%s%s%s%s%s",
				styledPad(valueStyle.Render(name), cN),
				styledPad(dimStyle.Render(addr), cA),
				styledPad(e5str, c5),
				styledPad(ecStr, cE),
				styledPad(retStr, cR),
				styledPad(abStr, cAb),
				styledPad(rtStr, cRt),
				hBadge)
			sb.WriteString(boxRow(row, iw) + "\n")
		}
	}

	// RCA summary — the root cause explanation
	if rca := dm["rca_summary"]; rca != "" && rca != "No significant issues detected" {
		sb.WriteString(boxMid(iw) + "\n")
		sb.WriteString(boxRow("  "+titleStyle.Render("ROOT CAUSE")+"  "+valueStyle.Render(rca), iw) + "\n")
	}

	sb.WriteString(boxBot(iw) + "\n\n")
	return sb.String()
}

// HAProxy UI helpers
func haJoin(a, b string) string {
	if a == "" && b == "" { return "" }
	if a == "" { a = "0" }
	if b == "" { b = "0" }
	return a + " / " + b
}

func haServersLine(dm map[string]string) string {
	up, down, total := dm["servers_up"], dm["servers_down"], dm["servers_total"]
	if total == "" { return "" }
	s := up + " up"
	if down != "" && down != "0" { s += ", " + warnStyle.Render(down+" down") }
	s += " / " + total
	return s
}

func haSuffix(val, suffix string) string {
	if val == "" { return "" }
	return val + suffix
}

func haFmtNum(val string) string {
	if val == "" { return "" }
	v, err := strconv.ParseInt(val, 10, 64)
	if err != nil { return val }
	switch {
	case v >= 1_000_000_000: return fmt.Sprintf("%.1fB", float64(v)/1e9)
	case v >= 1_000_000:     return fmt.Sprintf("%.1fM", float64(v)/1e6)
	case v >= 1_000:         return fmt.Sprintf("%.1fK", float64(v)/1e3)
	default:                 return val
	}
}

func haFmtNumPct(val, pct string) string {
	if val == "" { return "" }
	num := haFmtNum(val)
	if pct == "" || pct == "0.00" { return num }
	return num + " (" + pct + "%)"
}

func haFmtBytes(val string) string {
	if val == "" { return "" }
	v, err := strconv.ParseInt(val, 10, 64)
	if err != nil { return val }
	switch {
	case v >= 1<<40: return fmt.Sprintf("%.1f TB", float64(v)/float64(int64(1)<<40))
	case v >= 1<<30: return fmt.Sprintf("%.1f GB", float64(v)/float64(int64(1)<<30))
	case v >= 1<<20: return fmt.Sprintf("%.1f MB", float64(v)/float64(int64(1)<<20))
	case v >= 1<<10: return fmt.Sprintf("%.1f KB", float64(v)/float64(int64(1)<<10))
	default:         return fmt.Sprintf("%d B", v)
	}
}

func haColorVal(val, key string) string {
	if val == "" || val == "0" { return valueStyle.Render(val) }
	if strings.Contains(key, "5xx") || strings.Contains(key, "Err") { return critStyle.Render(val) }
	if strings.Contains(key, "4xx") || strings.Contains(key, "Abort") { return warnStyle.Render(val) }
	if strings.Contains(key, "2xx") { return okStyle.Render(val) }
	return valueStyle.Render(val)
}

func haFmtDuration(secStr string) string {
	s, err := strconv.ParseInt(secStr, 10, 64)
	if err != nil || secStr == "" { return secStr }
	switch {
	case s < 60:    return fmt.Sprintf("%ds ago", s)
	case s < 3600:  return fmt.Sprintf("%dm ago", s/60)
	case s < 86400: return fmt.Sprintf("%dh ago", s/3600)
	default:        return fmt.Sprintf("%dd ago", s/86400)
	}
}

func haFmtNonZero(val string) string {
	if val == "" || val == "0" { return "" }
	return haFmtNum(val)
}

func haColorTCPState(val, stateType string) string {
	if val == "" || val == "0" {
		return valueStyle.Render("0")
	}
	n, _ := strconv.Atoi(val)
	switch stateType {
	case "CLOSE_WAIT":
		if n > 50 {
			return critStyle.Render(val)
		} else if n > 10 {
			return warnStyle.Render(val)
		}
	case "FIN_WAIT":
		if n > 50 {
			return warnStyle.Render(val)
		}
	case "SYN_RECV":
		if n > 20 {
			return critStyle.Render(val)
		} else if n > 5 {
			return warnStyle.Render(val)
		}
	}
	return valueStyle.Render(val)
}
