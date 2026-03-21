//go:build linux

package ui

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/ftahirops/xtop/model"
)

func renderMySQLDeepMetrics(app model.AppInstance, iw int) string {
	var sb strings.Builder
	dm := app.DeepMetrics
	halfW := (iw - 8) / 2

	// ── ACTIVITY (real-time rates) ────────────────────────────────────
	hasActivity := dm["queries_per_sec"] != "" || dm["Bytes_received"] != "" || dm["selects_per_sec"] != ""
	if hasActivity {
		sb.WriteString("  " + titleStyle.Render("ACTIVITY") + "\n")
		sb.WriteString(boxTop(iw) + "\n")
		type actPair struct{ lKey, lVal, rKey, rVal string }
		actRows := []actPair{
			{"Queries/s", dm["queries_per_sec"], "Selects/s", dm["selects_per_sec"]},
			{"Inserts/s", dm["inserts_per_sec"], "Updates/s", dm["updates_per_sec"]},
			{"Deletes/s", dm["deletes_per_sec"], "Commits/s", dm["commits_per_sec"]},
			{"Bytes In", haFmtBytes(dm["bytes_in_per_sec"]) + "/s", "Bytes Out", haFmtBytes(dm["bytes_out_per_sec"]) + "/s"},
		}
		for _, r := range actRows {
			lv := r.lVal; if lv == "/s" { lv = "" }
			rv := r.rVal; if rv == "/s" { rv = "" }
			if lv == "" && rv == "" { continue }
			left := fmt.Sprintf("  %s %s", styledPad(dimStyle.Render(r.lKey+":"), 14), styledPad(valueStyle.Render(lv), halfW-16))
			right := ""
			if rv != "" {
				right = fmt.Sprintf("%s %s", styledPad(dimStyle.Render(r.rKey+":"), 14), valueStyle.Render(rv))
			}
			sb.WriteString(boxRow(left+right, iw) + "\n")
		}
		sb.WriteString(boxBot(iw) + "\n")
	}

	// ── TOP QUERIES ───────────────────────────────────────────────────
	if dm["top_query_count"] != "" {
		cnt, _ := strconv.Atoi(dm["top_query_count"])
		if cnt > 0 {
			sb.WriteString("  " + titleStyle.Render("TOP QUERIES") + "  " + dimStyle.Render(fmt.Sprintf("%d running", cnt)) + "\n")
			sb.WriteString(boxTop(iw) + "\n")
			cID, cUser, cHost, cDB, cTime, cState := 8, 10, 16, 10, 8, 16
			queryW := iw - cID - cUser - cHost - cDB - cTime - cState - 14
			if queryW < 20 { queryW = 20 }
			hdr := fmt.Sprintf("  %s%s%s%s%s%s%s",
				styledPad(dimStyle.Render("ID"), cID),
				styledPad(dimStyle.Render("User"), cUser),
				styledPad(dimStyle.Render("Host"), cHost),
				styledPad(dimStyle.Render("DB"), cDB),
				styledPad(dimStyle.Render("Time"), cTime),
				styledPad(dimStyle.Render("State"), cState),
				dimStyle.Render("Query"))
			sb.WriteString(boxRow(hdr, iw) + "\n")
			sb.WriteString(boxMid(iw) + "\n")
			maxQ := cnt; if maxQ > 5 { maxQ = 5 }
			for i := 0; i < maxQ; i++ {
				pfx := fmt.Sprintf("top_query_%d_", i)
				qID := dm[pfx+"id"]
				qUser := dm[pfx+"user"]
				qHost := dm[pfx+"host"]
				qDB := dm[pfx+"db"]
				qTime := dm[pfx+"time"]
				qState := dm[pfx+"state"]
				qInfo := dm[pfx+"info"]
				if qDB == "" || qDB == "NULL" { qDB = "-" }
				// color time
				timeStyled := valueStyle.Render(qTime + "s")
				if ts, _ := strconv.Atoi(qTime); ts > 30 {
					timeStyled = critStyle.Render(qTime + "s")
				} else if ts > 5 {
					timeStyled = warnStyle.Render(qTime + "s")
				}
				if len(qHost) > cHost-2 { qHost = qHost[:cHost-2] }
				if len(qState) > cState-2 { qState = qState[:cState-2] }
				if len(qInfo) > queryW { qInfo = qInfo[:queryW-3] + "..." }
				row := fmt.Sprintf("  %s%s%s%s%s%s%s",
					styledPad(dimStyle.Render(qID), cID),
					styledPad(valueStyle.Render(qUser), cUser),
					styledPad(valueStyle.Render(qHost), cHost),
					styledPad(dimStyle.Render(qDB), cDB),
					styledPad(timeStyled, cTime),
					styledPad(dimStyle.Render(qState), cState),
					dimStyle.Render(qInfo))
				sb.WriteString(boxRow(row, iw) + "\n")
			}
			sb.WriteString(boxBot(iw) + "\n")
		}
	}

	// ── CONNECTIONS BY HOST ───────────────────────────────────────────
	if dm["conn_host_count"] != "" {
		hostCnt, _ := strconv.Atoi(dm["conn_host_count"])
		if hostCnt > 0 {
			sb.WriteString("  " + titleStyle.Render("CONNECTIONS BY HOST") + "\n")
			sb.WriteString(boxTop(iw) + "\n")
			hdr := fmt.Sprintf("  %s %s %s",
				styledPad(dimStyle.Render("Host"), 22),
				styledPad(dimStyle.Render("Connections"), 14),
				dimStyle.Render("Active"))
			sb.WriteString(boxRow(hdr, iw) + "\n")
			sb.WriteString(boxMid(iw) + "\n")
			maxH := hostCnt; if maxH > 10 { maxH = 10 }
			for i := 0; i < maxH; i++ {
				pfx := fmt.Sprintf("conn_host_%d_", i)
				hHost := dm[pfx+"host"]
				hCount := dm[pfx+"count"]
				hActive := dm[pfx+"active"]
				if hHost == "" { continue }
				if len(hHost) > 21 { hHost = hHost[:21] }
				row := fmt.Sprintf("  %s %s %s",
					styledPad(valueStyle.Render(hHost), 22),
					styledPad(valueStyle.Render(hCount), 14),
					valueStyle.Render(hActive))
				sb.WriteString(boxRow(row, iw) + "\n")
			}
			sb.WriteString(boxBot(iw) + "\n")
		}
	}

	// ── DIAGNOSTICS ───────────────────────────────────────────────────
	type mysqlDiag struct {
		severity string
		title    string
		cause    string
		impact   string
		fix      string
	}
	var diags []mysqlDiag

	// Buffer Pool Hit Ratio
	if dm["buffer_pool_hit_ratio"] != "" {
		ratio, _ := strconv.ParseFloat(dm["buffer_pool_hit_ratio"], 64)
		if ratio < 95 {
			sev := "WARN"
			if ratio < 90 { sev = "CRIT" }
			poolSize := dm["innodb_buffer_pool_size"]
			dataPages := dm["Innodb_buffer_pool_pages_data"]
			totalPages := dm["Innodb_buffer_pool_pages_total"]
			diags = append(diags, mysqlDiag{
				severity: sev,
				title:    fmt.Sprintf("InnoDB buffer pool hit ratio %.1f%% — below optimal (>99%%)", ratio),
				cause:    fmt.Sprintf("Working set exceeds buffer pool. Pool: %s, data pages: %s/%s. Queries are reading from disk instead of memory.", poolSize, dataPages, totalPages),
				impact:   "Disk I/O increases, query latency rises. Every cache miss = random disk read (~5-10ms SSD, ~10-20ms HDD) vs ~0.1ms from memory.",
				fix:      "1) Increase innodb_buffer_pool_size (aim for 70-80%% of RAM). 2) Optimize queries to reduce working set. 3) Add indexes to avoid full table scans.",
			})
		}
	}

	// Slow Queries
	if v, _ := strconv.Atoi(dm["Slow_queries"]); v > 0 {
		sev := "WARN"
		if v > 100 { sev = "CRIT" }
		diags = append(diags, mysqlDiag{
			severity: sev,
			title:    fmt.Sprintf("%s slow queries detected", haFmtNum(dm["Slow_queries"])),
			cause:    "Queries exceeding long_query_time threshold. Common causes: missing indexes, full table scans, unoptimized joins, large result sets.",
			impact:   fmt.Sprintf("Slow queries hold locks longer, block other connections, increase CPU/IO load. Full scans: %s, full joins: %s.", haFmtNum(dm["Select_scan"]), haFmtNum(dm["Select_full_join"])),
			fix:      "1) Enable slow query log: SET GLOBAL slow_query_log=ON. 2) Run EXPLAIN on slow queries. 3) Add missing indexes. 4) Rewrite full joins to use indexed lookups.",
		})
	}

	// Row Lock Waits
	if v, _ := strconv.Atoi(dm["Innodb_row_lock_waits"]); v > 100 {
		sev := "WARN"
		if v > 1000 { sev = "CRIT" }
		avgMs := dm["Innodb_row_lock_time_avg"]
		diags = append(diags, mysqlDiag{
			severity: sev,
			title:    fmt.Sprintf("%s InnoDB row lock waits (avg %sms)", haFmtNum(dm["Innodb_row_lock_waits"]), avgMs),
			cause:    "Multiple transactions competing for the same rows. Long-running transactions hold locks, blocking others.",
			impact:   "Query queuing, increased response times, potential deadlocks. Active threads spike as connections wait for locks.",
			fix:      "1) Keep transactions short — commit early. 2) Access rows in consistent order to prevent deadlocks. 3) Use SELECT ... FOR UPDATE only when necessary. 4) Check for long-running transactions: SHOW ENGINE INNODB STATUS.",
		})
	}

	// Full Table Scans
	if v, _ := strconv.Atoi(dm["Select_scan"]); v > 100000 {
		sev := "WARN"
		if v > 1000000 { sev = "CRIT" }
		diags = append(diags, mysqlDiag{
			severity: sev,
			title:    fmt.Sprintf("%s full table scans — review query plans", haFmtNum(dm["Select_scan"])),
			cause:    "Queries scanning entire tables instead of using indexes. Missing indexes or queries that can't use existing indexes (e.g., functions on indexed columns, OR conditions).",
			impact:   "Each full scan reads every row — CPU and IO waste. Compounds with table size. Causes buffer pool churn, evicting useful cached pages.",
			fix:      "1) EXPLAIN suspect queries — look for 'type: ALL'. 2) Add composite indexes matching WHERE + ORDER BY. 3) Avoid SELECT * — select only needed columns. 4) Use covering indexes for frequent queries.",
		})
	}

	// Deadlocks
	if v, _ := strconv.Atoi(dm["Innodb_deadlocks"]); v > 0 {
		diags = append(diags, mysqlDiag{
			severity: "CRIT",
			title:    fmt.Sprintf("%s InnoDB deadlocks", dm["Innodb_deadlocks"]),
			cause:    "Two or more transactions waiting for each other's locks in a cycle. MySQL automatically kills one transaction (the victim).",
			impact:   "Victim transactions are rolled back — application must retry. If frequent, causes cascading failures and wasted work.",
			fix:      "1) Access tables/rows in the same order in all transactions. 2) Keep transactions short. 3) Use lower isolation level if possible (READ COMMITTED). 4) SHOW ENGINE INNODB STATUS — check LATEST DEADLOCK section.",
		})
	}

	// Connection Usage
	if dm["connection_usage_pct"] != "" {
		pct, _ := strconv.ParseFloat(dm["connection_usage_pct"], 64)
		if pct > 75 {
			sev := "WARN"
			if pct > 90 { sev = "CRIT" }
			diags = append(diags, mysqlDiag{
				severity: sev,
				title:    fmt.Sprintf("Connection usage at %.0f%% (%s/%s)", pct, dm["Threads_connected"], dm["max_connections"]),
				cause:    "Too many open connections. Applications not releasing connections, connection pool misconfigured, or max_connections set too low.",
				impact:   "New connections will be refused when limit is hit. Each connection uses ~1MB RAM (thread stack + buffers). High thread count increases context switching.",
				fix:      fmt.Sprintf("1) Tune application connection pool (max idle, max lifetime). 2) Increase max_connections (current: %s). 3) Kill idle connections: sleeping=%s. 4) Use connection pooling (ProxySQL/MaxScale).", dm["max_connections"], dm["sleeping_connections"]),
			})
		}
	}

	// Thread count high relative to connections
	threads, _ := strconv.Atoi(dm["Threads_connected"])
	running, _ := strconv.Atoi(dm["Threads_running"])
	if threads > 0 && running > 0 && threads > 30 && running < threads/4 {
		conns := app.Connections
		if conns > 0 && threads > conns*3 {
			diags = append(diags, mysqlDiag{
				severity: "WARN",
				title:    fmt.Sprintf("Thread count (%d) high relative to connections (%d)", threads, conns),
				cause:    "Many threads are idle or sleeping. Applications opening connections but not closing them, or connection pool holding too many idle connections.",
				impact:   "Wasted memory (~1MB per thread). Increases mutex contention on thread scheduler. Sleeping threads still hold resources.",
				fix:      "1) Reduce connection pool max-idle setting. 2) Set wait_timeout lower (current default: 28800s = 8h). 3) Use thread_pool plugin for better scaling.",
			})
		}
	}

	// Table Lock Contention
	if dm["table_lock_contention"] != "" {
		pct, _ := strconv.ParseFloat(dm["table_lock_contention"], 64)
		if pct > 1 {
			sev := "WARN"
			if pct > 5 { sev = "CRIT" }
			diags = append(diags, mysqlDiag{
				severity: sev,
				title:    fmt.Sprintf("Table lock contention %.1f%%", pct),
				cause:    fmt.Sprintf("Locks waited: %s vs immediate: %s. MyISAM tables or DDL operations cause table-level locks that block all other operations.", dm["Table_locks_waited"], dm["Table_locks_immediate"]),
				impact:   "All queries on the locked table queue up. Can cascade to connection exhaustion if lock is held long.",
				fix:      "1) Convert MyISAM tables to InnoDB (row-level locking). 2) Avoid long ALTER TABLE during peak hours — use pt-online-schema-change. 3) Keep DDL transactions short.",
			})
		}
	}

	// Replication lag
	if dm["replication_status"] != "" && dm["replication_status"] != "ok" {
		diags = append(diags, mysqlDiag{
			severity: "CRIT",
			title:    "Replication broken — " + dm["replication_status"],
			cause:    fmt.Sprintf("IO Running: %s, SQL Running: %s. Network issues, binary log corruption, or schema drift between master and replica.", dm["Slave_IO_Running"], dm["Slave_SQL_Running"]),
			impact:   "Replica serves stale data. Failover to replica will cause data loss. Read-scaling is compromised.",
			fix:      "1) Check SHOW SLAVE STATUS for Last_Error. 2) Verify network to master. 3) If SQL thread stopped: STOP SLAVE; SET GLOBAL SQL_SLAVE_SKIP_COUNTER=1; START SLAVE (skip one event). 4) If drift: re-provision from backup.",
		})
	} else if dm["Seconds_behind_master"] != "" && dm["Seconds_behind_master"] != "0" {
		lag, _ := strconv.Atoi(dm["Seconds_behind_master"])
		if lag > 5 {
			sev := "WARN"
			if lag > 30 { sev = "CRIT" }
			diags = append(diags, mysqlDiag{
				severity: sev,
				title:    fmt.Sprintf("Replication lag: %ds behind master", lag),
				cause:    "Replica SQL thread can't keep up with master write rate. Single-threaded replication, heavy writes, or slow disk on replica.",
				impact:   fmt.Sprintf("Reads from replica are %ds stale. Failover would lose %ds of data.", lag, lag),
				fix:      "1) Enable parallel replication: slave_parallel_workers > 1. 2) Optimize slow queries on replica. 3) Use faster disk on replica. 4) Reduce master write rate during catch-up.",
			})
		}
	}

	// Render diagnostics if any
	if len(diags) > 0 {
		sb.WriteString("  " + titleStyle.Render("DIAGNOSTICS") + "  " + dimStyle.Render(fmt.Sprintf("%d issues", len(diags))) + "\n")
		sb.WriteString(boxTop(iw) + "\n")
		for idx, d := range diags {
			if idx > 0 { sb.WriteString(boxMid(iw) + "\n") }
			var sevBadge string
			if d.severity == "CRIT" { sevBadge = critStyle.Render("CRIT") } else { sevBadge = warnStyle.Render("WARN") }
			sb.WriteString(boxRow(fmt.Sprintf("  %s %s  %s",
				warnStyle.Render(fmt.Sprintf("#%d", idx+1)), sevBadge, valueStyle.Render(d.title)), iw) + "\n")
			sb.WriteString(boxRow("  "+dimStyle.Render("Cause:")+"   "+dimStyle.Render(d.cause), iw) + "\n")
			sb.WriteString(boxRow("  "+dimStyle.Render("Impact:")+"  "+dimStyle.Render(d.impact), iw) + "\n")
			sb.WriteString(boxRow("  "+dimStyle.Render("Fix:")+"     "+dimStyle.Render(d.fix), iw) + "\n")
		}
		sb.WriteString(boxBot(iw) + "\n")
	}

	// ── HEALTH CHECKS + CONNECTIONS (side by side) ────────────────────
	type hRow struct{ metric, value, status string }
	var hRows []hRow
	mysqlAddH := func(name, val string, wT, cT float64, hi bool) {
		if val == "" { return }
		v, _ := strconv.ParseFloat(val, 64)
		st := "OK"
		if hi { if v >= cT { st = "CRIT" } else if v >= wT { st = "WARN" }
		} else { if v <= cT { st = "CRIT" } else if v <= wT { st = "WARN" } }
		hRows = append(hRows, hRow{name, val, st})
	}
	mysqlAddH("Buffer Pool Hit%", dm["buffer_pool_hit_ratio"]+"%", 95, 90, false)
	mysqlAddH("Conn Usage%", dm["connection_usage_pct"]+"%", 75, 90, true)
	mysqlAddH("Lock Contention%", dm["table_lock_contention"]+"%", 1, 5, true)
	if dm["Slow_queries"] != "" {
		sv, _ := strconv.Atoi(dm["Slow_queries"])
		st := "OK"; if sv > 100 { st = "CRIT" } else if sv > 0 { st = "WARN" }
		hRows = append(hRows, hRow{"Slow Queries", haFmtNum(dm["Slow_queries"]), st})
	}
	if dm["Innodb_deadlocks"] != "" && dm["Innodb_deadlocks"] != "0" {
		hRows = append(hRows, hRow{"Deadlocks", dm["Innodb_deadlocks"], "CRIT"})
	}
	if dm["Innodb_row_lock_waits"] != "" {
		rv, _ := strconv.Atoi(dm["Innodb_row_lock_waits"])
		st := "OK"; if rv > 1000 { st = "CRIT" } else if rv > 100 { st = "WARN" }
		hRows = append(hRows, hRow{"Row Lock Waits", haFmtNum(dm["Innodb_row_lock_waits"]), st})
	}
	if dm["replication_status"] != "" {
		st := "OK"; if dm["replication_status"] != "ok" { st = "CRIT" }
		val := dm["replication_status"]
		if dm["Seconds_behind_master"] != "" && dm["Seconds_behind_master"] != "0" {
			val += " (lag:" + dm["Seconds_behind_master"] + "s)"
			lag, _ := strconv.Atoi(dm["Seconds_behind_master"])
			if lag > 30 { st = "CRIT" } else if lag > 5 { st = "WARN" }
		}
		hRows = append(hRows, hRow{"Replication", val, st})
	}

	// Connection values with status coloring
	mysqlConnColor := func(key, val string) string {
		if val == "" { return "" }
		v, _ := strconv.Atoi(val)
		switch key {
		case "Connected":
			maxC, _ := strconv.Atoi(dm["max_connections"])
			if maxC > 0 {
				pct := float64(v) / float64(maxC) * 100
				if pct > 90 { return critStyle.Render(val) }
				if pct > 75 { return warnStyle.Render(val) }
			}
		case "Running":
			if v > 100 { return critStyle.Render(val) }
			if v > 50 { return warnStyle.Render(val) }
		case "Sleeping":
			if v > 100 { return warnStyle.Render(val) }
		case "Aborted In":
			if v > 100 { return warnStyle.Render(val) }
		case "Aborted Out":
			if v > 100 { return warnStyle.Render(val) }
		}
		return valueStyle.Render(val)
	}

	connKVs := []kv{
		{Key: "Max Conns", Val: dm["max_connections"]},
		{Key: "Connected", Val: dm["Threads_connected"]},
		{Key: "Running", Val: dm["Threads_running"]},
		{Key: "Max Used", Val: dm["Max_used_connections"]},
		{Key: "Active", Val: dm["active_queries"]},
		{Key: "Sleeping", Val: dm["sleeping_connections"]},
		{Key: "Aborted In", Val: dm["Aborted_connects"]},
		{Key: "Aborted Out", Val: dm["Aborted_clients"]},
	}

	sb.WriteString("  " + titleStyle.Render("HEALTH CHECKS") + strings.Repeat(" ", halfW-16) + titleStyle.Render("CONNECTIONS") + "\n")
	sb.WriteString(boxTop(iw) + "\n")
	cCheck, cVal := 18, 22
	leftHdr := fmt.Sprintf("  %s %s %s", styledPad(dimStyle.Render("Check"), cCheck), styledPad(dimStyle.Render("Value"), cVal), dimStyle.Render("St"))
	sb.WriteString(boxRow(fmt.Sprintf("%s  %s", styledPad(leftHdr, halfW), dimStyle.Render("Param          Value")), iw) + "\n")
	sb.WriteString(boxMid(iw) + "\n")
	maxR := len(hRows); if len(connKVs) > maxR { maxR = len(connKVs) }
	for i := 0; i < maxR; i++ {
		var left, right string
		if i < len(hRows) {
			r := hRows[i]
			badge := okStyle.Render(" OK "); if r.status == "WARN" { badge = warnStyle.Render("WARN") } else if r.status == "CRIT" { badge = critStyle.Render("CRIT") }
			left = fmt.Sprintf("  %s %s %s", styledPad(valueStyle.Render(r.metric), cCheck), styledPad(valueStyle.Render(r.value), cVal), badge)
		}
		if i < len(connKVs) && connKVs[i].Val != "" {
			right = fmt.Sprintf("  %s %s", styledPad(dimStyle.Render(connKVs[i].Key+":"), 14), mysqlConnColor(connKVs[i].Key, connKVs[i].Val))
		}
		sb.WriteString(boxRow(fmt.Sprintf("%s%s", styledPad(left, halfW), right), iw) + "\n")
	}
	sb.WriteString(boxBot(iw) + "\n")

	// ── INNODB + QUERY PERFORMANCE (side by side, with status colors) ─
	innoKVs := []kv{
		{Key: "Pool Size", Val: dm["innodb_buffer_pool_size"]},
		{Key: "Hit Ratio", Val: mysqlPctStr(dm["buffer_pool_hit_ratio"])},
		{Key: "Pool Usage", Val: mysqlPctStr(dm["buffer_pool_usage_pct"])},
		{Key: "Pages Data", Val: haFmtNum(dm["Innodb_buffer_pool_pages_data"])},
		{Key: "Pages Dirty", Val: haFmtNum(dm["Innodb_buffer_pool_pages_dirty"])},
		{Key: "Pages Free", Val: haFmtNum(dm["Innodb_buffer_pool_pages_free"])},
		{Key: "Lock Waits", Val: haFmtNum(dm["Innodb_row_lock_waits"])},
		{Key: "Lock Avg ms", Val: dm["Innodb_row_lock_time_avg"]},
		{Key: "Deadlocks", Val: dm["Innodb_deadlocks"]},
		{Key: "Data Reads", Val: haFmtNum(dm["Innodb_data_reads"])},
		{Key: "Data Writes", Val: haFmtNum(dm["Innodb_data_writes"])},
		{Key: "History Len", Val: dm["history_list_length"]},
	}
	queryKVs := []kv{
		{Key: "Questions", Val: haFmtNum(dm["Questions"])},
		{Key: "Slow Queries", Val: haFmtNum(dm["Slow_queries"])},
		{Key: "Full Joins", Val: haFmtNum(dm["Select_full_join"])},
		{Key: "Full Scans", Val: haFmtNum(dm["Select_scan"])},
		{Key: "Sort Merges", Val: haFmtNum(dm["Sort_merge_passes"])},
		{Key: "Tmp Disk %", Val: mysqlPctStr(dm["tmp_disk_table_pct"])},
		{Key: "Tmp Disk Tbl", Val: haFmtNum(dm["Created_tmp_disk_tables"])},
		{Key: "Tmp Tables", Val: haFmtNum(dm["Created_tmp_tables"])},
		{Key: "Rnd Reads", Val: haFmtNum(dm["Handler_read_rnd_next"])},
		{Key: "Open Tables", Val: dm["Open_tables"]},
		{Key: "Opened Tbls", Val: haFmtNum(dm["Opened_tables"])},
		{Key: "Locks Wait", Val: haFmtNum(dm["Table_locks_waited"])},
	}

	sb.WriteString("  " + titleStyle.Render("INNODB ENGINE") + strings.Repeat(" ", halfW-16) + titleStyle.Render("QUERY PERFORMANCE") + "\n")
	sb.WriteString(boxTop(iw) + "\n")
	maxR = len(innoKVs); if len(queryKVs) > maxR { maxR = len(queryKVs) }
	for i := 0; i < maxR; i++ {
		var left, right string
		if i < len(innoKVs) && innoKVs[i].Val != "" {
			left = fmt.Sprintf("  %s %s", styledPad(dimStyle.Render(innoKVs[i].Key+":"), 14), mysqlColorVal(innoKVs[i].Val, innoKVs[i].Key, dm))
		}
		if i < len(queryKVs) && queryKVs[i].Val != "" {
			right = fmt.Sprintf("  %s %s", styledPad(dimStyle.Render(queryKVs[i].Key+":"), 14), mysqlColorVal(queryKVs[i].Val, queryKVs[i].Key, dm))
		}
		if left != "" || right != "" {
			sb.WriteString(boxRow(fmt.Sprintf("%s%s", styledPad(left, halfW), right), iw) + "\n")
		}
	}
	sb.WriteString(boxBot(iw) + "\n")

	// ── REPLICATION + INNODB STATUS (side by side, if present) ────────
	if dm["Slave_IO_Running"] != "" || dm["replication_status"] != "" || dm["pending_reads"] != "" {
		replKVs := []kv{
			{Key: "Status", Val: dm["replication_status"]},
			{Key: "Lag (s)", Val: dm["Seconds_behind_master"]},
			{Key: "IO Thread", Val: dm["Slave_IO_Running"]},
			{Key: "SQL Thread", Val: dm["Slave_SQL_Running"]},
		}
		statusKVs := []kv{
			{Key: "Chkpt Age", Val: dm["checkpoint_age"]},
			{Key: "Pend Reads", Val: dm["pending_reads"]},
			{Key: "Pend Writes", Val: dm["pending_writes"]},
			{Key: "Tier 2", Val: dm["tier2_status"]},
		}

		hasRepl := false
		for _, k := range replKVs { if k.Val != "" { hasRepl = true; break } }
		hasStatus := false
		for _, k := range statusKVs { if k.Val != "" { hasStatus = true; break } }

		if hasRepl || hasStatus {
			lTitle := "REPLICATION"
			if !hasRepl { lTitle = "INNODB STATUS" }
			rTitle := "INNODB STATUS"
			if !hasRepl { rTitle = "" }
			sb.WriteString("  " + titleStyle.Render(lTitle))
			if rTitle != "" { sb.WriteString(strings.Repeat(" ", halfW-len(lTitle)-2) + titleStyle.Render(rTitle)) }
			sb.WriteString("\n")
			sb.WriteString(boxTop(iw) + "\n")
			lKVs := replKVs
			rKVs := statusKVs
			if !hasRepl { lKVs = statusKVs; rKVs = nil }
			maxR = len(lKVs); if rKVs != nil && len(rKVs) > maxR { maxR = len(rKVs) }
			for i := 0; i < maxR; i++ {
				var left, right string
				if i < len(lKVs) && lKVs[i].Val != "" {
					left = fmt.Sprintf("  %s %s", styledPad(dimStyle.Render(lKVs[i].Key+":"), 14), valueStyle.Render(lKVs[i].Val))
				}
				if rKVs != nil && i < len(rKVs) && rKVs[i].Val != "" {
					right = fmt.Sprintf("  %s %s", styledPad(dimStyle.Render(rKVs[i].Key+":"), 14), valueStyle.Render(rKVs[i].Val))
				}
				if left != "" || right != "" {
					sb.WriteString(boxRow(fmt.Sprintf("%s%s", styledPad(left, halfW), right), iw) + "\n")
				}
			}
			sb.WriteString(boxBot(iw) + "\n")
		}
	}

	return sb.String()
}

func mysqlPctStr(val string) string {
	if val == "" { return "" }
	return val + "%"
}

// mysqlColorVal returns a styled value string with threshold-based coloring
// for InnoDB and Query Performance metrics.
func mysqlColorVal(val, key string, dm map[string]string) string {
	if val == "" { return valueStyle.Render(val) }
	// strip % suffix for numeric comparison
	numStr := strings.TrimSuffix(val, "%")
	v, err := strconv.ParseFloat(numStr, 64)
	if err != nil { return valueStyle.Render(val) }
	switch key {
	// InnoDB thresholds
	case "Hit Ratio":
		if v < 90 { return critStyle.Render(val) }
		if v < 95 { return warnStyle.Render(val) }
		return okStyle.Render(val)
	case "Pages Dirty":
		if v > 1000 { return warnStyle.Render(val) }
	case "Lock Waits":
		if v > 1000 { return critStyle.Render(val) }
		if v > 100 { return warnStyle.Render(val) }
	case "Lock Avg ms":
		if v > 100 { return critStyle.Render(val) }
		if v > 50 { return warnStyle.Render(val) }
	case "Deadlocks":
		if v > 0 { return critStyle.Render(val) }
	// Query Performance thresholds
	case "Slow Queries":
		if v > 100 { return critStyle.Render(val) }
		if v > 0 { return warnStyle.Render(val) }
	case "Full Joins":
		if v > 1000 { return warnStyle.Render(val) }
	case "Full Scans":
		if v > 1000000 { return critStyle.Render(val) }
		if v > 100000 { return warnStyle.Render(val) }
	case "Sort Merges":
		if v > 1000 { return warnStyle.Render(val) }
	case "Tmp Disk %":
		if v > 25 { return critStyle.Render(val) }
		if v > 10 { return warnStyle.Render(val) }
	case "Locks Wait":
		if v > 100 { return warnStyle.Render(val) }
	}
	return valueStyle.Render(val)
}
