//go:build linux

package ui

import (
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/ftahirops/xtop/model"
)

// mongoRate returns "value (rate/s)" or just "value" if no rate.
func mongoRate(dm map[string]string, key string) string {
	v := dm[key]
	if v == "" {
		return ""
	}
	r := dm[key+"_rate"]
	if r == "" || r == "0.0" {
		return v
	}
	// Format rate nicely
	rf, _ := strconv.ParseFloat(r, 64)
	var rs string
	switch {
	case rf >= 1e9:
		rs = fmt.Sprintf("%.1fB", rf/1e9)
	case rf >= 1e6:
		rs = fmt.Sprintf("%.1fM", rf/1e6)
	case rf >= 1e3:
		rs = fmt.Sprintf("%.1fK", rf/1e3)
	case rf >= 1:
		rs = fmt.Sprintf("%.0f", rf)
	default:
		rs = fmt.Sprintf("%.1f", rf)
	}
	return v + " (" + rs + "/s)"
}

func renderMongoDBDeepMetrics(app model.AppInstance, iw int) string {
	var sb strings.Builder
	dm := app.DeepMetrics
	halfW := (iw - 4) / 2
	lw := 18 // label width for compact columns

	// ══════════════════════════════════════════════════════════════════
	// 1. DATABASES & COLLECTIONS — most actionable, shown first
	// ══════════════════════════════════════════════════════════════════
	if dbList := dm["db_list"]; dbList != "" {
		sb.WriteString(renderMongoDBCollections(dm, iw))
	}

	// ══════════════════════════════════════════════════════════════════
	// 2. HEALTH RCA
	// ══════════════════════════════════════════════════════════════════
	type healthRow struct{ metric, value, status, tip string }
	rows := []healthRow{}

	// Cache usage
	if v := dm["cache_usage_pct"]; v != "" {
		pct, _ := strconv.ParseFloat(v, 64)
		st, tip := "OK", ""
		if pct > 95 {
			st, tip = "CRIT", "eviction pressure — increase cacheSizeGB or reduce working set"
		} else if pct > 80 {
			st, tip = "WARN", "cache filling up — monitor eviction rate"
		}
		rows = append(rows, healthRow{"WT Cache", v + "%", st, tip})
	}

	// Cache dirty ratio
	dirtyMB, _ := strconv.ParseFloat(dm["cache_dirty_mb"], 64)
	cacheMB, _ := strconv.ParseFloat(dm["cache_max_mb"], 64)
	if cacheMB > 0 && dirtyMB > 0 {
		dirtyPct := dirtyMB / cacheMB * 100
		st, tip := "OK", ""
		if dirtyPct > 20 {
			st, tip = "CRIT", "write stalls likely — check I/O throughput"
		} else if dirtyPct > 5 {
			st, tip = "WARN", "dirty pages accumulating"
		}
		rows = append(rows, healthRow{"Cache Dirty", fmt.Sprintf("%.1f%%", dirtyPct), st, tip})
	}

	// Connection usage
	connCur, _ := strconv.Atoi(dm["conn_current"])
	connAvail, _ := strconv.Atoi(dm["conn_available"])
	if connAvail > 0 {
		pct := float64(connCur) / float64(connCur+connAvail) * 100
		st, tip := "OK", ""
		if pct > 90 {
			st, tip = "CRIT", "near connection limit — increase maxIncomingConnections or use connection pooling"
		} else if pct > 80 {
			st, tip = "WARN", "connection pool filling"
		}
		rows = append(rows, healthRow{"Connections", fmt.Sprintf("%d/%d (%.0f%%)", connCur, connCur+connAvail, pct), st, tip})
	}

	// Lock queue
	lockQ, _ := strconv.Atoi(dm["lock_queue_total"])
	{
		st, tip := "OK", ""
		if lockQ > 10 {
			st, tip = "CRIT", "severe contention — check slow queries and indexing"
		} else if lockQ > 0 {
			st, tip = "WARN", "lock contention detected"
		}
		rows = append(rows, healthRow{"Lock Queue", fmt.Sprintf("%d", lockQ), st, tip})
	}

	// WT tickets
	readAvail, _ := strconv.Atoi(dm["wt_read_avail"])
	writeAvail, _ := strconv.Atoi(dm["wt_write_avail"])
	readOut, _ := strconv.Atoi(dm["wt_read_out"])
	writeOut, _ := strconv.Atoi(dm["wt_write_out"])
	if readAvail+readOut > 0 {
		st, tip := "OK", ""
		if readAvail < 5 {
			st, tip = "CRIT", "read tickets exhausted — queries queuing"
		} else if readAvail < 20 {
			st, tip = "WARN", "read tickets low"
		}
		rows = append(rows, healthRow{"Read Tickets", fmt.Sprintf("%d avail / %d used", readAvail, readOut), st, tip})
	}
	if writeAvail+writeOut > 0 {
		st, tip := "OK", ""
		if writeAvail < 5 {
			st, tip = "CRIT", "write tickets exhausted — writes queuing"
		} else if writeAvail < 20 {
			st, tip = "WARN", "write tickets low"
		}
		rows = append(rows, healthRow{"Write Tickets", fmt.Sprintf("%d avail / %d used", writeAvail, writeOut), st, tip})
	}

	// Slow ops
	slowOps, _ := strconv.Atoi(dm["slow_ops"])
	if slowOps > 0 {
		st := "WARN"
		tip := "check db.currentOp() and add indexes"
		if slowOps > 10 {
			st, tip = "CRIT", "many slow queries — profile and optimize"
		}
		rows = append(rows, healthRow{"Slow Ops (>5s)", fmt.Sprintf("%d", slowOps), st, tip})
	}

	// Cursors timed out
	curTimeout, _ := strconv.Atoi(dm["cursor_timed_out"])
	if curTimeout > 100 {
		rows = append(rows, healthRow{"Cursor Timeouts", dm["cursor_timed_out"], "WARN", "increase batch size or process faster"})
	}

	// Replication lag
	if lagStr := dm["repl_lag_sec"]; lagStr != "" && lagStr != "0" {
		lag, _ := strconv.Atoi(lagStr)
		st, tip := "WARN", "secondary falling behind"
		if lag > 60 {
			st, tip = "CRIT", "severely behind primary — check oplog size and network"
		}
		rows = append(rows, healthRow{"Replication Lag", lagStr + "s", st, tip})
	}

	// Asserts
	assertReg, _ := strconv.Atoi(dm["assert_regular"])
	assertMsg, _ := strconv.Atoi(dm["assert_msg"])
	assertUser, _ := strconv.Atoi(dm["assert_user"])
	if assertReg > 0 || assertMsg > 0 {
		rows = append(rows, healthRow{"Asserts", fmt.Sprintf("reg:%d msg:%d user:%d", assertReg, assertMsg, assertUser), "WARN", "internal assertion failures detected"})
	} else if assertUser > 10000 {
		rows = append(rows, healthRow{"User Asserts", mongoFmtCount(int64(assertUser)), "WARN", "app-level errors (dupes, validation)"})
	}

	// Global avg latency
	avgReadUs, _ := strconv.Atoi(dm["avg_read_latency_us"])
	avgWriteUs, _ := strconv.Atoi(dm["avg_write_latency_us"])
	if avgReadUs > 0 || avgWriteUs > 0 {
		st, tip := "OK", ""
		if avgReadUs > 10000 || avgWriteUs > 50000 {
			st, tip = "CRIT", "high global latency — check indexes and working set"
		} else if avgReadUs > 1000 || avgWriteUs > 10000 {
			st, tip = "WARN", "latency elevated"
		}
		rows = append(rows, healthRow{"Avg Latency",
			fmt.Sprintf("R:%s W:%s", mongoFmtLatency(int64(avgReadUs)), mongoFmtLatency(int64(avgWriteUs))), st, tip})
	}

	// Collection scans
	collScans, _ := strconv.Atoi(dm["collection_scans"])
	if collScans > 100 {
		st := "WARN"
		tip := "add indexes to avoid full scans"
		if collScans > 10000 {
			st, tip = "CRIT", "excessive collection scans — missing indexes"
		}
		rows = append(rows, healthRow{"Collection Scans", mongoFmtCount(int64(collScans)), st, tip})
	}

	// Scan efficiency (scanned vs returned)
	scannedObj, _ := strconv.ParseFloat(dm["scanned_objects"], 64)
	docReturned, _ := strconv.ParseFloat(dm["doc_returned"], 64)
	if docReturned > 0 && scannedObj > 0 {
		ratio := scannedObj / docReturned
		if ratio > 10 {
			rows = append(rows, healthRow{"Scan Efficiency",
				fmt.Sprintf("%.0f:1 scan/return", ratio), "CRIT", "scanning far more docs than returning — missing indexes"})
		} else if ratio > 2 {
			rows = append(rows, healthRow{"Scan Efficiency",
				fmt.Sprintf("%.1f:1 scan/return", ratio), "WARN", "consider more targeted indexes"})
		}
	}

	// Rejected connections
	rejConns, _ := strconv.Atoi(dm["conn_rejected"])
	if rejConns > 0 {
		rows = append(rows, healthRow{"Rejected Conns", fmt.Sprintf("%d", rejConns), "CRIT", "clients being turned away — increase maxIncomingConnections"})
	}

	// Killed by disconnect
	killedDisc, _ := strconv.Atoi(dm["killed_disconnect"])
	if killedDisc > 1000 {
		rows = append(rows, healthRow{"Client Disconnects", mongoFmtCount(int64(killedDisc)), "WARN", "clients disconnecting mid-query — check timeouts"})
	}

	// Page faults
	pgFaults, _ := strconv.Atoi(dm["page_faults"])
	if pgFaults > 10000 {
		rows = append(rows, healthRow{"Page Faults", dm["page_faults"], "WARN", "working set exceeds RAM — increase cacheSizeGB"})
	}

	// Render health table
	sb.WriteString("  " + titleStyle.Render("HEALTH RCA") + "\n")
	sb.WriteString(boxTop(iw) + "\n")
	cM, cV, cS := 18, 28, 6
	cTip := iw - cM - cV - cS - 10
	if cTip < 10 {
		cTip = 10
	}
	hdr := fmt.Sprintf("  %s %s %s %s",
		styledPad(dimStyle.Render("Check"), cM),
		styledPad(dimStyle.Render("Value"), cV),
		styledPad(dimStyle.Render("Status"), cS),
		dimStyle.Render("Recommendation"))
	sb.WriteString(boxRow(hdr, iw) + "\n")
	sb.WriteString(boxMid(iw) + "\n")
	for _, r := range rows {
		badge := okStyle.Render(" OK ")
		if r.status == "WARN" {
			badge = warnStyle.Render("WARN")
		} else if r.status == "CRIT" {
			badge = critStyle.Render("CRIT")
		}
		tipStr := ""
		if r.tip != "" && r.status != "OK" {
			t := r.tip
			if len(t) > cTip {
				t = t[:cTip-1] + "…"
			}
			tipStr = dimStyle.Render(t)
		}
		row := fmt.Sprintf("  %s %s %s %s",
			styledPad(valueStyle.Render(r.metric), cM),
			styledPad(valueStyle.Render(r.value), cV),
			styledPad(badge, cS),
			tipStr)
		sb.WriteString(boxRow(row, iw) + "\n")
	}
	if len(rows) == 0 {
		sb.WriteString(boxRow("  "+dimStyle.Render("All checks passed"), iw) + "\n")
	}
	sb.WriteString(boxBot(iw) + "\n")

	// ── CONNECTIONS + OPERATIONS (side by side) ────────────────────────
	sb.WriteString("  " + titleStyle.Render("CONNECTIONS") + strings.Repeat(" ", halfW-12) + titleStyle.Render("OPERATIONS (/s)") + "\n")
	sb.WriteString(boxTop(iw) + "\n")
	lCol := []kv{
		{Key: "Current", Val: dm["conn_current"]},
		{Key: "Available", Val: dm["conn_available"]},
		{Key: "Total Created", Val: mongoRate(dm, "conn_total_created")},
		{Key: "Active", Val: dm["conn_active"]},
		{Key: "Rejected", Val: dm["conn_rejected"]},
		{Key: "Active Read", Val: dm["active_readers"]},
		{Key: "Active Write", Val: dm["active_writers"]},
	}
	rCol := []kv{
		{Key: "Queries", Val: mongoRate(dm, "op_query")},
		{Key: "Inserts", Val: mongoRate(dm, "op_insert")},
		{Key: "Updates", Val: mongoRate(dm, "op_update")},
		{Key: "Deletes", Val: mongoRate(dm, "op_delete")},
		{Key: "GetMore", Val: mongoRate(dm, "op_getmore")},
		{Key: "Commands", Val: mongoRate(dm, "op_command")},
		{Key: "Slow (>5s)", Val: dm["slow_ops"]},
	}
	mongoRenderDualCol(&sb, lCol, rCol, iw, halfW, lw)
	sb.WriteString(boxBot(iw) + "\n")

	// ── MEMORY/CACHE + WT ENGINE (side by side) ────────────────────────
	sb.WriteString("  " + titleStyle.Render("MEMORY & CACHE") + strings.Repeat(" ", halfW-15) + titleStyle.Render("WIREDTIGER") + "\n")
	sb.WriteString(boxTop(iw) + "\n")
	lCol = []kv{
		{Key: "Resident MB", Val: dm["mem_resident_mb"]},
		{Key: "Virtual MB", Val: dm["mem_virtual_mb"]},
		{Key: "Cache Used MB", Val: dm["cache_used_mb"]},
		{Key: "Cache Max MB", Val: dm["cache_max_mb"]},
		{Key: "Cache Usage%", Val: dm["cache_usage_pct"]},
		{Key: "Cache Dirty MB", Val: dm["cache_dirty_mb"]},
	}
	rCol = []kv{
		{Key: "Read Tickets", Val: mongoFmtTicket(dm["wt_read_avail"], dm["wt_read_out"])},
		{Key: "Write Tickets", Val: mongoFmtTicket(dm["wt_write_avail"], dm["wt_write_out"])},
		{Key: "Cache Reads", Val: mongoRate(dm, "cache_reads")},
		{Key: "Cache Writes", Val: mongoRate(dm, "cache_writes")},
		{Key: "Page Faults", Val: dm["page_faults"]},
		{Key: "Engine", Val: dm["storage_engine"]},
	}
	mongoRenderDualCol(&sb, lCol, rCol, iw, halfW, lw)
	sb.WriteString(boxBot(iw) + "\n")

	// ── DOCUMENTS + QUERY PERFORMANCE (side by side) ──────────────────
	sb.WriteString("  " + titleStyle.Render("DOCUMENTS & NETWORK (/s)") + strings.Repeat(" ", halfW-24) + titleStyle.Render("QUERY PERFORMANCE") + "\n")
	sb.WriteString(boxTop(iw) + "\n")
	lCol = []kv{
		{Key: "Inserted", Val: mongoRate(dm, "doc_inserted")},
		{Key: "Returned", Val: mongoRate(dm, "doc_returned")},
		{Key: "Updated", Val: mongoRate(dm, "doc_updated")},
		{Key: "Deleted", Val: mongoRate(dm, "doc_deleted")},
		{Key: "Net In", Val: mongoFmtBytes(dm["net_bytes_in"])},
		{Key: "Net Out", Val: mongoFmtBytes(dm["net_bytes_out"])},
		{Key: "Net Requests", Val: mongoRate(dm, "net_num_requests")},
	}
	// Compute avg latencies for display
	avgRdLat := mongoFmtLatency(mongoParseI64(dm["avg_read_latency_us"]))
	avgWrLat := mongoFmtLatency(mongoParseI64(dm["avg_write_latency_us"]))
	rCol = []kv{
		{Key: "Avg Read Lat", Val: avgRdLat},
		{Key: "Avg Write Lat", Val: avgWrLat},
		{Key: "Scanned Keys", Val: mongoRate(dm, "scanned_keys")},
		{Key: "Scanned Objs", Val: mongoRate(dm, "scanned_objects")},
		{Key: "Coll Scans", Val: mongoRate(dm, "collection_scans")},
		{Key: "Open Cursors", Val: dm["cursor_open"]},
		{Key: "Killed(disc)", Val: mongoRate(dm, "killed_disconnect")},
	}
	mongoRenderDualCol(&sb, lCol, rCol, iw, halfW, lw)
	sb.WriteString(boxBot(iw) + "\n")

	// ── LOCKS + REPLICATION (side by side) ─────────────────────────────
	sb.WriteString("  " + titleStyle.Render("LOCKS") + strings.Repeat(" ", halfW-6) + titleStyle.Render("REPLICATION") + "\n")
	sb.WriteString(boxTop(iw) + "\n")
	lCol = []kv{
		{Key: "Queue Total", Val: dm["lock_queue_total"]},
		{Key: "Queue Readers", Val: dm["lock_queue_readers"]},
		{Key: "Queue Writers", Val: dm["lock_queue_writers"]},
		{Key: "Active Ops", Val: dm["current_ops_active"]},
		{Key: "Total Ops", Val: dm["current_ops_total"]},
	}
	rCol = []kv{
		{Key: "Set Name", Val: dm["repl_set"]},
		{Key: "State", Val: dm["repl_state"]},
		{Key: "Members", Val: dm["repl_members"]},
		{Key: "Lag (sec)", Val: dm["repl_lag_sec"]},
	}
	mongoRenderDualCol(&sb, lCol, rCol, iw, halfW, lw)
	sb.WriteString(boxBot(iw) + "\n")

	// ── SLOW QUERIES ──────────────────────────────────────────────────
	if sqJSON := dm["slow_queries"]; sqJSON != "" {
		type slowQ struct {
			Op     string `json:"op"`
			NS     string `json:"ns"`
			Secs   int    `json:"secs"`
			Client string `json:"client"`
			Plan   string `json:"plan"`
			Cmd    string `json:"cmd"`
		}
		var queries []slowQ
		if err := json.Unmarshal([]byte(sqJSON), &queries); err == nil && len(queries) > 0 {
			sb.WriteString("  " + titleStyle.Render(fmt.Sprintf("SLOW QUERIES (%d active >5s)", len(queries))) + "\n")
			sb.WriteString(boxTop(iw) + "\n")
			for i, q := range queries {
				// Header line: duration, operation, namespace, client
				durStyle := warnStyle
				if q.Secs > 30 {
					durStyle = critStyle
				}
				header := fmt.Sprintf("  %s %s %s %s %s",
					durStyle.Render(fmt.Sprintf("[%ds]", q.Secs)),
					dimStyle.Render("op=")+valueStyle.Render(q.Op),
					dimStyle.Render("ns=")+valueStyle.Render(q.NS),
					dimStyle.Render("client=")+valueStyle.Render(q.Client),
					"")
				sb.WriteString(boxRow(header, iw) + "\n")

				// Plan summary — this tells WHY it's slow
				if q.Plan != "" {
					planLine := fmt.Sprintf("    %s %s", dimStyle.Render("plan:"), "")
					if q.Plan == "COLLSCAN" {
						planLine = fmt.Sprintf("    %s %s",
							dimStyle.Render("plan:"),
							critStyle.Render("COLLSCAN")+" "+dimStyle.Render("← MISSING INDEX, full collection scan"))
					} else if strings.HasPrefix(q.Plan, "IXSCAN") {
						planLine = fmt.Sprintf("    %s %s",
							dimStyle.Render("plan:"),
							okStyle.Render(q.Plan))
					} else {
						planLine = fmt.Sprintf("    %s %s",
							dimStyle.Render("plan:"),
							valueStyle.Render(q.Plan))
					}
					sb.WriteString(boxRow(planLine, iw) + "\n")
				}

				// Command snippet
				if q.Cmd != "" {
					cmd := q.Cmd
					maxCmdW := iw - 12
					if len(cmd) > maxCmdW {
						cmd = cmd[:maxCmdW-3] + "..."
					}
					cmdLine := fmt.Sprintf("    %s %s", dimStyle.Render("cmd:"), dimStyle.Render(cmd))
					sb.WriteString(boxRow(cmdLine, iw) + "\n")
				}

				if i < len(queries)-1 {
					sb.WriteString(boxMid(iw) + "\n")
				}
			}
			sb.WriteString(boxBot(iw) + "\n")
		}
	}

	// ── SECURITY & CONFIG AUDIT ────────────────────────────────────────
	sb.WriteString("  " + titleStyle.Render("SECURITY & CONFIGURATION AUDIT") + "\n")
	sb.WriteString(boxTop(iw) + "\n")
	auditLW := 28
	type auditRow struct{ check, value, status, note string }
	audits := []auditRow{}

	// Auth
	authVal := dm["auth_enabled"]
	if authVal == "" {
		authVal = "unknown"
	}
	{
		st, note := "OK", "authentication enforced"
		if authVal == "disabled" || authVal == "unknown" {
			st, note = "CRIT", "ENABLE authorization in mongod.conf"
		}
		audits = append(audits, auditRow{"Authorization", authVal, st, note})
	}

	// Bind IP
	bindIP := dm["bind_ip"]
	if bindIP == "" {
		bindIP = "default"
	}
	{
		st, note := "OK", ""
		if bindIP == "0.0.0.0" || bindIP == "default" {
			st, note = "WARN", "restrict to specific IPs"
		}
		audits = append(audits, auditRow{"Bind IP", bindIP, st, note})
	}

	// TLS
	tlsMode := dm["tls_mode"]
	if tlsMode == "" {
		tlsMode = "disabled"
	}
	{
		st, note := "OK", "encrypted connections"
		if tlsMode == "disabled" || tlsMode == "" {
			st, note = "WARN", "enable TLS for production"
		}
		audits = append(audits, auditRow{"TLS/SSL", tlsMode, st, note})
	}

	// Max connections config
	if maxC := dm["max_connections"]; maxC != "" {
		mc, _ := strconv.Atoi(maxC)
		st, note := "OK", ""
		if mc > 50000 {
			st, note = "WARN", "very high limit — may cause resource exhaustion"
		} else if mc == 0 {
			st, note = "WARN", "no limit set"
		}
		audits = append(audits, auditRow{"Max Connections", maxC, st, note})
	}

	// Cache size config
	if cs := dm["wt_cache_size_gb"]; cs != "" {
		audits = append(audits, auditRow{"Cache Size", cs + " GB", "OK", "explicitly configured"})
	} else {
		audits = append(audits, auditRow{"Cache Size", "auto", "OK", "default: 50% RAM - 1GB"})
	}

	// Journal
	if j := dm["journal_enabled"]; j != "" {
		st := "OK"
		note := "crash recovery enabled"
		if j != "true" && j != "enabled" {
			st, note = "CRIT", "ENABLE journaling for durability"
		}
		audits = append(audits, auditRow{"Journaling", j, st, note})
	}

	for _, a := range audits {
		badge := okStyle.Render(" OK ")
		if a.status == "WARN" {
			badge = warnStyle.Render("WARN")
		} else if a.status == "CRIT" {
			badge = critStyle.Render("CRIT")
		}
		noteStr := ""
		if a.note != "" {
			noteStr = dimStyle.Render(a.note)
		}
		row := fmt.Sprintf("  %s %s %s %s",
			styledPad(dimStyle.Render(a.check+":"), auditLW),
			styledPad(valueStyle.Render(a.value), 16),
			styledPad(badge, 6),
			noteStr)
		sb.WriteString(boxRow(row, iw) + "\n")
	}
	sb.WriteString(boxBot(iw) + "\n")

	// ── INDEX ANALYSIS (per-collection) ───────────────────────────────
	indexRecs := mongoIndexAnalysis(dm)
	if len(indexRecs) > 0 {
		sb.WriteString("  " + titleStyle.Render(fmt.Sprintf("INDEX ANALYSIS (%d issues found)", len(indexRecs))) + "\n")
		sb.WriteString(boxTop(iw) + "\n")
		for i, rec := range indexRecs {
			if i > 0 {
				sb.WriteString(boxMid(iw) + "\n")
			}
			badge := warnStyle.Render("WARN")
			if rec.severity == "CRIT" {
				badge = critStyle.Render("CRIT")
			}
			// Collection name + badge
			sb.WriteString(boxRow(fmt.Sprintf("  %s  %s", badge, critStyle.Render(rec.collection)), iw) + "\n")
			// Problem — plain English
			sb.WriteString(boxRow(fmt.Sprintf("  %s %s", dimStyle.Render("Problem:"), rec.problem), iw) + "\n")
			// Impact — quantified
			if rec.impact != "" {
				sb.WriteString(boxRow(fmt.Sprintf("  %s  %s", dimStyle.Render("Impact:"), warnStyle.Render(rec.impact)), iw) + "\n")
			}
			// Sibling reference
			if rec.sibling != "" {
				sb.WriteString(boxRow(fmt.Sprintf("  %s     %s", dimStyle.Render("Note:"), dimStyle.Render(rec.sibling)), iw) + "\n")
			}
			// Fix command
			if rec.fix != "" {
				sb.WriteString(boxRow(fmt.Sprintf("  %s     %s", dimStyle.Render("Fix:"), valueStyle.Render(rec.fix)), iw) + "\n")
			}
			// Safety note
			if rec.fixNote != "" {
				sb.WriteString(boxRow(fmt.Sprintf("           %s", okStyle.Render(rec.fixNote)), iw) + "\n")
			}
		}
		sb.WriteString(boxBot(iw) + "\n")
	}

	// ── CLIENT CONNECTIONS ────────────────────────────────────────────
	if clientJSON := dm["client_connections"]; clientJSON != "" {
		type clientEntry struct {
			IP    string `json:"ip"`
			Count int    `json:"count"`
		}
		var clients []clientEntry
		if err := json.Unmarshal([]byte(clientJSON), &clients); err == nil && len(clients) > 0 {
			totalConns := 0
			for _, c := range clients {
				totalConns += c.Count
			}
			sb.WriteString("  " + titleStyle.Render(fmt.Sprintf("CLIENT CONNECTIONS (%d total, %d sources)", totalConns, len(clients))) + "\n")
			sb.WriteString(boxTop(iw) + "\n")
			cIP, cCnt, cPct := 20, 8, 8
			hdr := fmt.Sprintf("  %s%s%s%s",
				styledPad(dimStyle.Render("Client IP"), cIP),
				styledPad(dimStyle.Render("Conns"), cCnt),
				styledPad(dimStyle.Render("Share"), cPct),
				dimStyle.Render("Status"))
			sb.WriteString(boxRow(hdr, iw) + "\n")
			sb.WriteString(boxMid(iw) + "\n")
			for _, c := range clients {
				pct := float64(c.Count) / float64(totalConns) * 100
				status := okStyle.Render(" OK ")
				note := ""
				if c.Count > 200 {
					status = critStyle.Render("CRIT")
					note = dimStyle.Render("excessive — reduce maxPoolSize")
				} else if c.Count > 100 {
					status = warnStyle.Render("WARN")
					note = dimStyle.Render("high — review pool settings")
				}
				row := fmt.Sprintf("  %s%s%s%s %s",
					styledPad(valueStyle.Render(c.IP), cIP),
					styledPad(valueStyle.Render(fmt.Sprintf("%d", c.Count)), cCnt),
					styledPad(valueStyle.Render(fmt.Sprintf("%.0f%%", pct)), cPct),
					status, note)
				sb.WriteString(boxRow(row, iw) + "\n")
			}
			sb.WriteString(boxBot(iw) + "\n")
		}
	}

	// ── OPERATION TYPE BREAKDOWN ──────────────────────────────────────
	if opJSON := dm["op_type_breakdown"]; opJSON != "" {
		type opEntry struct {
			Op    string `json:"op"`
			Count int    `json:"count"`
		}
		var ops []opEntry
		if err := json.Unmarshal([]byte(opJSON), &ops); err == nil && len(ops) > 0 {
			// Sort by count desc
			sort.Slice(ops, func(i, j int) bool { return ops[i].Count > ops[j].Count })
			totalOps := 0
			for _, o := range ops {
				totalOps += o.Count
			}
			sb.WriteString("  " + titleStyle.Render("OPERATION BREAKDOWN (currentOp)") + "\n")
			sb.WriteString(boxTop(iw) + "\n")
			for _, o := range ops {
				pct := float64(o.Count) / float64(totalOps) * 100
				label := o.Op
				note := ""
				if o.Op == "hello" {
					note = dimStyle.Render(" ← driver heartbeats (normal, but high count = too many connections)")
				} else if o.Op == "none" {
					note = dimStyle.Render(" ← idle connections waiting for work")
				}
				bar := strings.Repeat("█", int(pct/3))
				row := fmt.Sprintf("  %s %s %s%s",
					styledPad(valueStyle.Render(label), 12),
					styledPad(valueStyle.Render(fmt.Sprintf("%d (%.0f%%)", o.Count, pct)), 16),
					dimStyle.Render(bar), note)
				sb.WriteString(boxRow(row, iw) + "\n")
			}
			sb.WriteString(boxBot(iw) + "\n")
		}
	}

	// ── OPTIMIZATION RECOMMENDATIONS ───────────────────────────────────
	recs := mongoOptimizationRecs(dm)
	if len(recs) > 0 {
		sb.WriteString("  " + titleStyle.Render("OPTIMIZATION RECOMMENDATIONS") + "\n")
		sb.WriteString(boxTop(iw) + "\n")
		for _, rec := range recs {
			badge := warnStyle.Render("▸")
			if rec.severity == "CRIT" {
				badge = critStyle.Render("▸")
			}
			line := fmt.Sprintf("  %s %s", badge, valueStyle.Render(rec.text))
			sb.WriteString(boxRow(line, iw) + "\n")
		}
		sb.WriteString(boxBot(iw) + "\n")
	}

	return sb.String()
}

// renderMongoDBCollections renders the DATABASES & COLLECTIONS section.
func renderMongoDBCollections(dm map[string]string, iw int) string {
	var sb strings.Builder
	dbList := dm["db_list"]
	if dbList == "" {
		return ""
	}
	sb.WriteString("  " + titleStyle.Render("DATABASES & COLLECTIONS") + "\n")

	type collInfo struct {
		Name     string   `json:"name"`
		SizeMB   float64  `json:"size_mb"`
		Docs     int64    `json:"docs"`
		Indexes  int      `json:"indexes"`
		IdxNames []string `json:"idx_names"`
		AvgObj   int      `json:"avg_obj"`
		ROps     int64    `json:"r_ops"`
		RAvgUs   int64    `json:"r_avg_us"`
		WOps     int64    `json:"w_ops"`
		WAvgUs   int64    `json:"w_avg_us"`
		COps     int64    `json:"c_ops"`
		CAvgUs   int64    `json:"c_avg_us"`
		ROpsRate float64  `json:"r_ops_rate"`
		WOpsRate float64  `json:"w_ops_rate"`
	}
	type dbInfo struct {
		Name        string     `json:"name"`
		SizeMB      float64    `json:"size_mb"`
		Collections int        `json:"collections"`
		Indexes     int        `json:"indexes"`
		Colls       []collInfo `json:"colls"`
	}
	var dbs []dbInfo
	if err := json.Unmarshal([]byte(dbList), &dbs); err == nil {
		for _, d := range dbs {
			if (d.Name == "admin" || d.Name == "config" || d.Name == "local") && d.SizeMB < 1 {
				continue
			}
			dbSize := fmt.Sprintf("%.1fMB", d.SizeMB)
			if d.SizeMB >= 1024 {
				dbSize = fmt.Sprintf("%.1fGB", d.SizeMB/1024)
			}
			// Sum DB-level ops and rates
			var dbReads, dbWrites int64
			var dbReadRate, dbWriteRate float64
			for _, c := range d.Colls {
				dbReads += c.ROps
				dbWrites += c.WOps
				dbReadRate += c.ROpsRate
				dbWriteRate += c.WOpsRate
			}
			sb.WriteString(boxTop(iw) + "\n")
			readsVal := mongoFmtRateShort(dbReadRate)
			writesVal := mongoFmtRateShort(dbWriteRate)
			dbTitle := fmt.Sprintf("  %s  %s  %s  %s  %s  %s",
				titleStyle.Render(d.Name),
				dimStyle.Render("Size:")+valueStyle.Render(dbSize),
				dimStyle.Render("Colls:")+valueStyle.Render(fmt.Sprintf("%d", d.Collections)),
				dimStyle.Render("Idx:")+valueStyle.Render(fmt.Sprintf("%d", d.Indexes)),
				dimStyle.Render("Rd/s:")+valueStyle.Render(readsVal),
				dimStyle.Render("Wr/s:")+valueStyle.Render(writesVal))
			sb.WriteString(boxRow(dbTitle, iw) + "\n")

			if len(d.Colls) > 0 {
				sb.WriteString(boxMid(iw) + "\n")
				cN, cSz, cDoc, cRd, cWr, cRL, cWL, cSt := 34, 8, 10, 10, 10, 8, 8, 6
				cReason := iw - cN - cSz - cDoc - cRd - cWr - cRL - cWL - cSt - 8
				if cReason < 10 {
					cReason = 10
				}
				collHdr := fmt.Sprintf("  %s%s%s%s%s%s%s%s%s",
					styledPad(dimStyle.Render("Collection"), cN),
					styledPad(dimStyle.Render("Size"), cSz),
					styledPad(dimStyle.Render("Docs"), cDoc),
					styledPad(dimStyle.Render("Rd/s"), cRd),
					styledPad(dimStyle.Render("Wr/s"), cWr),
					styledPad(dimStyle.Render("R.Avg"), cRL),
					styledPad(dimStyle.Render("W.Avg"), cWL),
					styledPad(dimStyle.Render("Status"), cSt),
					dimStyle.Render("Reason"))
				sb.WriteString(boxRow(collHdr, iw) + "\n")

				for _, c := range d.Colls {
					collSize := mongoFmtSizeMB(c.SizeMB)
					docStr := mongoFmtCount(c.Docs)
					rdStr := mongoFmtRateShort(c.ROpsRate)
					wrStr := mongoFmtRateShort(c.WOpsRate)
					rLatStr := mongoFmtLatency(c.RAvgUs)
					wLatStr := mongoFmtLatency(c.WAvgUs)

					// Determine health + reason + color problem values
					status := "OK"
					reason := ""
					rLatStyled := valueStyle.Render(rLatStr)
					wLatStyled := valueStyle.Render(wLatStr)
					rdStyled := valueStyle.Render(rdStr)
					wrStyled := valueStyle.Render(wrStr)

					// Thresholds: R.Avg normal <1ms, warn >10ms, crit >50ms
					//             W.Avg normal <5ms, warn >10ms, crit >50ms
					if c.WAvgUs > 50000 {
						status = "CRIT"
						reason = fmt.Sprintf("W.Avg %s (>50ms)", wLatStr)
						wLatStyled = critStyle.Render(wLatStr)
					} else if c.RAvgUs > 50000 {
						status = "CRIT"
						reason = fmt.Sprintf("R.Avg %s (>50ms)", rLatStr)
						rLatStyled = critStyle.Render(rLatStr)
					} else if c.WAvgUs > 10000 {
						status = "WARN"
						reason = fmt.Sprintf("W.Avg %s (>10ms)", wLatStr)
						wLatStyled = warnStyle.Render(wLatStr)
					} else if c.RAvgUs > 10000 {
						status = "WARN"
						reason = fmt.Sprintf("R.Avg %s (>10ms)", rLatStr)
						rLatStyled = warnStyle.Render(rLatStr)
					}
					if c.Indexes < 2 && c.Docs > 100000 && c.ROps > 1000 {
						if status == "OK" {
							status = "WARN"
						}
						reason = fmt.Sprintf("only _id index, %s docs", mongoFmtCount(c.Docs))
					}
					// High read rate on large collection
					if c.ROpsRate > 10000 && c.Docs > 1000000 {
						if status == "OK" {
							status = "WARN"
						}
						if reason == "" {
							reason = fmt.Sprintf("%s rd/s on %s docs", rdStr, mongoFmtCount(c.Docs))
						}
						rdStyled = warnStyle.Render(rdStr)
					}

					badge := okStyle.Render(" OK ")
					reasonStyled := ""
					if status == "WARN" {
						badge = warnStyle.Render("WARN")
						reasonStyled = warnStyle.Render(reason)
					} else if status == "CRIT" {
						badge = critStyle.Render("CRIT")
						reasonStyled = critStyle.Render(reason)
					}

					name := c.Name
					if len(name) > cN-2 {
						name = name[:cN-5] + "..."
					}
					row := fmt.Sprintf("  %s%s%s%s%s%s%s%s%s",
						styledPad(valueStyle.Render(name), cN),
						styledPad(valueStyle.Render(collSize), cSz),
						styledPad(valueStyle.Render(docStr), cDoc),
						styledPad(rdStyled, cRd),
						styledPad(wrStyled, cWr),
						styledPad(rLatStyled, cRL),
						styledPad(wLatStyled, cWL),
						styledPad(badge, cSt),
						reasonStyled)
					sb.WriteString(boxRow(row, iw) + "\n")
				}
			}
			sb.WriteString(boxBot(iw) + "\n")
		}
	}
	if totalMB := dm["total_size_mb"]; totalMB != "" {
		t, _ := strconv.ParseFloat(totalMB, 64)
		totalStr := mongoFmtSizeMB(t)
		sb.WriteString(fmt.Sprintf("  %s %s (%s databases)\n",
			dimStyle.Render("Total Storage:"),
			valueStyle.Render(totalStr),
			dm["db_count"]))
	}
	return sb.String()
}

// mongoRenderDualCol renders two kv columns side by side in a box (no top/bot).
func mongoRenderDualCol(sb *strings.Builder, lCol, rCol []kv, iw, halfW, lw int) {
	maxR := len(lCol)
	if len(rCol) > maxR {
		maxR = len(rCol)
	}
	for i := 0; i < maxR; i++ {
		var left, right string
		if i < len(lCol) && lCol[i].Val != "" {
			left = fmt.Sprintf("%s %s",
				styledPad(dimStyle.Render(lCol[i].Key+":"), lw),
				valueStyle.Render(lCol[i].Val))
		}
		if i < len(rCol) && rCol[i].Val != "" {
			right = fmt.Sprintf("%s %s",
				styledPad(dimStyle.Render(rCol[i].Key+":"), lw),
				valueStyle.Render(rCol[i].Val))
		}
		row := fmt.Sprintf("  %s%s", styledPad(left, halfW), right)
		sb.WriteString(boxRow(row, iw) + "\n")
	}
}

// mongoFmtTicket formats available/used ticket pair.
func mongoFmtTicket(avail, used string) string {
	if avail == "" && used == "" {
		return ""
	}
	if avail == "" {
		avail = "—"
	}
	if used == "" {
		used = "—"
	}
	return avail + " / " + used
}

// mongoFmtBytes formats byte count to human readable.
func mongoFmtBytes(s string) string {
	if s == "" {
		return ""
	}
	b, _ := strconv.ParseFloat(s, 64)
	switch {
	case b >= 1e12:
		return fmt.Sprintf("%.1fTB", b/1e12)
	case b >= 1e9:
		return fmt.Sprintf("%.1fGB", b/1e9)
	case b >= 1e6:
		return fmt.Sprintf("%.1fMB", b/1e6)
	case b >= 1e3:
		return fmt.Sprintf("%.1fKB", b/1e3)
	default:
		return fmt.Sprintf("%.0fB", b)
	}
}

// mongoFmtSizeMB formats MB to human readable.
func mongoFmtSizeMB(mb float64) string {
	if mb >= 1024 {
		return fmt.Sprintf("%.1fGB", mb/1024)
	}
	return fmt.Sprintf("%.1fMB", mb)
}

// mongoFmtCount formats large numbers with K/M suffix.
func mongoFmtCount(n int64) string {
	if n >= 1000000000 {
		return fmt.Sprintf("%.1fB", float64(n)/1e9)
	}
	if n >= 1000000 {
		return fmt.Sprintf("%.1fM", float64(n)/1e6)
	}
	if n >= 1000 {
		return fmt.Sprintf("%.1fK", float64(n)/1e3)
	}
	return fmt.Sprintf("%d", n)
}

// mongoFmtOps formats operation count with K/M suffix.
func mongoFmtOps(n int64) string {
	if n == 0 {
		return "0"
	}
	return mongoFmtCount(n)
}

// mongoFmtRateShort formats a rate value compactly for inline display.
func mongoFmtRateShort(r float64) string {
	switch {
	case r >= 1e9:
		return fmt.Sprintf("%.0fB/s", r/1e9)
	case r >= 1e6:
		return fmt.Sprintf("%.0fM/s", r/1e6)
	case r >= 1e3:
		return fmt.Sprintf("%.1fK/s", r/1e3)
	case r >= 1:
		return fmt.Sprintf("%.0f/s", r)
	case r > 0:
		return fmt.Sprintf("%.1f/s", r)
	default:
		return "0"
	}
}

// mongoFmtLatency formats microseconds to human readable.
func mongoFmtLatency(us int64) string {
	if us == 0 {
		return "—"
	}
	if us >= 1000000 {
		return fmt.Sprintf("%.1fs", float64(us)/1e6)
	}
	if us >= 1000 {
		return fmt.Sprintf("%.1fms", float64(us)/1e3)
	}
	return fmt.Sprintf("%dµs", us)
}

// mongoParseI64 parses a string to int64, returns 0 on error.
func mongoParseI64(s string) int64 {
	if s == "" {
		return 0
	}
	v, _ := strconv.ParseInt(s, 10, 64)
	return v
}

type mongoRec struct {
	severity string
	text     string
}

type mongoIndexRec struct {
	severity   string
	collection string // "DB.Collection"
	problem    string // plain English explanation
	impact     string // quantified impact
	fix        string // createIndex() command
	fixNote    string // safety note
	sibling    string // sibling that has the index (if applicable)
}

// mongoIndexAnalysis examines per-collection index data and generates
// specific recommendations with clear problem/impact/fix explanations.
func mongoIndexAnalysis(dm map[string]string) []mongoIndexRec {
	dbList := dm["db_list"]
	if dbList == "" {
		return nil
	}

	type collInfo struct {
		Name     string   `json:"name"`
		SizeMB   float64  `json:"size_mb"`
		Docs     int64    `json:"docs"`
		Indexes  int      `json:"indexes"`
		IdxNames []string `json:"idx_names"`
		ROps     int64    `json:"r_ops"`
		RAvgUs   int64    `json:"r_avg_us"`
		WOps     int64    `json:"w_ops"`
		WAvgUs   int64    `json:"w_avg_us"`
		ROpsRate float64  `json:"r_ops_rate"`
	}
	type dbInfo struct {
		Name  string     `json:"name"`
		Colls []collInfo `json:"colls"`
	}

	var dbs []dbInfo
	if err := json.Unmarshal([]byte(dbList), &dbs); err != nil {
		return nil
	}

	var recs []mongoIndexRec

	for _, d := range dbs {
		if d.Name == "admin" || d.Name == "config" || d.Name == "local" {
			continue
		}

		// Build index map across sibling collections
		siblingIndexes := make(map[string]map[string]bool)
		for _, c := range d.Colls {
			idxSet := make(map[string]bool)
			for _, idx := range c.IdxNames {
				if idx != "_id_" {
					idxSet[idx] = true
				}
			}
			siblingIndexes[c.Name] = idxSet
		}

		for _, c := range d.Colls {
			ns := d.Name + "." + c.Name

			// 1. Large collection with only _id index and significant reads
			if c.Indexes < 2 && c.Docs > 50000 && c.ROps > 100 {
				sev := "WARN"
				if c.ROpsRate > 1000 || c.Docs > 1000000 {
					sev = "CRIT"
				}

				// Find missing indexes from siblings
				var missingIdxs []string
				var siblingName string
				for sibName, sibIdx := range siblingIndexes {
					if sibName == c.Name || !mongoAreSiblings(c.Name, sibName) {
						continue
					}
					for idx := range sibIdx {
						if !siblingIndexes[c.Name][idx] {
							missingIdxs = append(missingIdxs, strings.TrimSuffix(idx, "_1"))
							siblingName = sibName
						}
					}
				}

				docStr := mongoFmtCount(c.Docs)
				if len(missingIdxs) > 0 {
					// Missing sibling index — most actionable finding
					for _, idx := range missingIdxs {
						recs = append(recs, mongoIndexRec{
							severity:   sev,
							collection: ns,
							problem: fmt.Sprintf("No %s index — every query on %s scans all %s documents (full table scan)",
								idx, idx, docStr),
							impact: fmt.Sprintf("Each %s lookup takes ~%.0fms instead of <1ms, wasting CPU on %s reads",
								idx, float64(c.Docs)/500000.0*100, mongoFmtCount(c.ROps)),
							sibling: fmt.Sprintf("Sibling \"%s\" has this index — this collection was likely created without it",
								siblingName),
							fix: fmt.Sprintf("db.getSiblingDB(\"%s\").%s.createIndex({%s: 1})",
								d.Name, c.Name, idx),
							fixNote: "Safe to run in production — builds in background, no downtime",
						})
					}
				} else {
					// No sibling reference, generic "only _id" warning
					recs = append(recs, mongoIndexRec{
						severity:   sev,
						collection: ns,
						problem: fmt.Sprintf("Only _id index on %s docs — any query not using _id scans the entire collection",
							docStr),
						impact: fmt.Sprintf("Full collection scans cause high CPU and slow responses (%s total reads)",
							mongoFmtCount(c.ROps)),
						fix: "Enable profiling to find which fields need indexes: db.setProfilingLevel(1, {slowms: 50})",
						fixNote: "Then check db.system.profile for COLLSCAN queries to identify needed indexes",
					})
				}
			}

			// 2. High read latency with few indexes
			if c.RAvgUs > 5000 && c.Indexes < 3 && c.ROps > 1000 {
				recs = append(recs, mongoIndexRec{
					severity:   "WARN",
					collection: ns,
					problem: fmt.Sprintf("Average read takes %s with only %d index — queries may be scanning too many documents",
						mongoFmtLatency(c.RAvgUs), c.Indexes),
					impact: fmt.Sprintf("Slow reads affect application response time across %s operations",
						mongoFmtCount(c.ROps)),
					fix: fmt.Sprintf("db.getSiblingDB(\"%s\").setProfilingLevel(1, {slowms: 50})",
						d.Name),
					fixNote: "Check db.system.profile to find slow query patterns, then create targeted indexes",
				})
			}

			// 3. Write latency high (only when writes are actually happening)
			if c.WAvgUs > 50000 && c.WOps > 100 {
				recs = append(recs, mongoIndexRec{
					severity:   "CRIT",
					collection: ns,
					problem: fmt.Sprintf("Write operations averaging %s — significantly slower than normal (<10ms)",
						mongoFmtLatency(c.WAvgUs)),
					impact: fmt.Sprintf("Slow writes cause application timeouts and connection pile-ups (%d indexes to update per write)",
						c.Indexes),
					fix: "Check disk I/O with xtop IO page. If indexes > 5, review if all are needed",
					fixNote: "Too many indexes slow every write — each insert/update must update all indexes",
				})
			}
		}
	}

	return recs
}

// mongoAreSiblings checks if two collection names are variants of each other
// (e.g., "Foo" and "Foo_New", "Foo_DAG2" and "Foo_DAG2_New").
func mongoAreSiblings(a, b string) bool {
	if strings.HasSuffix(a, "_New") && strings.TrimSuffix(a, "_New") == b {
		return true
	}
	if strings.HasSuffix(b, "_New") && strings.TrimSuffix(b, "_New") == a {
		return true
	}
	// Also check base name match (strip _New, _DAG2, etc.)
	baseA := a
	baseB := b
	for _, suf := range []string{"_New", "_DAG2_New", "_DAG2"} {
		baseA = strings.TrimSuffix(baseA, suf)
		baseB = strings.TrimSuffix(baseB, suf)
	}
	return baseA == baseB && a != b
}

// mongoOptimizationRecs generates optimization recommendations from metrics.
func mongoOptimizationRecs(dm map[string]string) []mongoRec {
	var recs []mongoRec

	// Cache pressure
	if v := dm["cache_usage_pct"]; v != "" {
		pct, _ := strconv.ParseFloat(v, 64)
		if pct > 95 {
			recs = append(recs, mongoRec{"CRIT", "WT cache critically full — increase storage.wiredTiger.engineConfig.cacheSizeGB"})
		} else if pct > 85 {
			recs = append(recs, mongoRec{"WARN", "WT cache > 85% — consider increasing cacheSizeGB or reducing working set"})
		}
	}

	// Connection pool
	connCur, _ := strconv.Atoi(dm["conn_current"])
	if connCur > 5000 {
		recs = append(recs, mongoRec{"CRIT", fmt.Sprintf("%d connections — implement connection pooling (maxPoolSize in driver)", connCur)})
	} else if connCur > 1000 {
		recs = append(recs, mongoRec{"WARN", fmt.Sprintf("%d connections — consider connection pooling", connCur)})
	}

	// Lock contention
	lockQ, _ := strconv.Atoi(dm["lock_queue_total"])
	if lockQ > 10 {
		recs = append(recs, mongoRec{"CRIT", "Heavy lock contention — review slow queries with db.currentOp(), add missing indexes"})
	}

	// Slow ops
	slowOps, _ := strconv.Atoi(dm["slow_ops"])
	if slowOps > 5 {
		recs = append(recs, mongoRec{"CRIT", fmt.Sprintf("%d slow operations (>5s) — run db.setProfilingLevel(1) and check system.profile", slowOps)})
	} else if slowOps > 0 {
		recs = append(recs, mongoRec{"WARN", "Slow operations detected — check query plans with .explain()"})
	}

	// WT tickets
	readAvail, _ := strconv.Atoi(dm["wt_read_avail"])
	writeAvail, _ := strconv.Atoi(dm["wt_write_avail"])
	if readAvail > 0 && readAvail < 20 {
		recs = append(recs, mongoRec{"WARN", "Read tickets low — increase wiredTigerConcurrentReadTransactions or reduce load"})
	}
	if writeAvail > 0 && writeAvail < 20 {
		recs = append(recs, mongoRec{"WARN", "Write tickets low — increase wiredTigerConcurrentWriteTransactions or reduce write load"})
	}

	// Security
	if dm["auth_enabled"] == "disabled" {
		recs = append(recs, mongoRec{"CRIT", "Authentication DISABLED — set security.authorization: enabled in mongod.conf"})
	}
	if dm["tls_mode"] == "disabled" || dm["tls_mode"] == "" {
		recs = append(recs, mongoRec{"WARN", "TLS disabled — enable net.tls.mode: requireTLS for encrypted connections"})
	}
	if dm["bind_ip"] == "0.0.0.0" {
		recs = append(recs, mongoRec{"WARN", "Bound to all interfaces — restrict net.bindIp to specific addresses"})
	}

	// Replication
	if lagStr := dm["repl_lag_sec"]; lagStr != "" && lagStr != "0" {
		lag, _ := strconv.Atoi(lagStr)
		if lag > 60 {
			recs = append(recs, mongoRec{"CRIT", fmt.Sprintf("Replication lag %ds — increase oplog size (replSetResizeOplog) or check network", lag)})
		}
	}

	// Cursor timeouts
	curTimeout, _ := strconv.Atoi(dm["cursor_timed_out"])
	if curTimeout > 100 {
		recs = append(recs, mongoRec{"WARN", "High cursor timeouts — use noCursorTimeout cautiously or process batches faster"})
	}

	// Collection scans
	collScans, _ := strconv.Atoi(dm["collection_scans"])
	if collScans > 1000 {
		recs = append(recs, mongoRec{"CRIT", fmt.Sprintf("%d collection scans — create indexes for frequent query patterns", collScans)})
	} else if collScans > 100 {
		recs = append(recs, mongoRec{"WARN", fmt.Sprintf("%d collection scans — review queries without index support", collScans)})
	}

	// Scan efficiency
	scannedObj, _ := strconv.ParseFloat(dm["scanned_objects"], 64)
	docReturned, _ := strconv.ParseFloat(dm["doc_returned"], 64)
	if docReturned > 0 && scannedObj/docReturned > 5 {
		recs = append(recs, mongoRec{"WARN", fmt.Sprintf("Scanning %.0fx more docs than returning — create compound indexes matching query filters", scannedObj/docReturned)})
	}

	// High write latency
	avgWrUs, _ := strconv.Atoi(dm["avg_write_latency_us"])
	if avgWrUs > 50000 {
		recs = append(recs, mongoRec{"CRIT", fmt.Sprintf("Avg write latency %s — check disk I/O, journal, and write concern", mongoFmtLatency(int64(avgWrUs)))})
	} else if avgWrUs > 10000 {
		recs = append(recs, mongoRec{"WARN", fmt.Sprintf("Avg write latency %s — consider write concern w:1 or faster storage", mongoFmtLatency(int64(avgWrUs)))})
	}

	// Client disconnects killing ops
	killedDisc, _ := strconv.Atoi(dm["killed_disconnect"])
	if killedDisc > 10000 {
		recs = append(recs, mongoRec{"WARN", fmt.Sprintf("%s operations killed by client disconnect — increase client timeouts", mongoFmtCount(int64(killedDisc)))})
	}

	// No replication on production
	if dm["repl_set"] == "" && connCur > 100 {
		recs = append(recs, mongoRec{"WARN", "Standalone instance with significant traffic — consider replica set for HA"})
	}

	return recs
}
