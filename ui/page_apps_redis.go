//go:build linux

package ui

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/ftahirops/xtop/model"
)

func renderRedisDeepMetrics(app model.AppInstance, iw int) string {
	var sb strings.Builder
	dm := app.DeepMetrics

	// Column widths: 33% health, 67% throughput
	healthW := iw / 3
	tpW := iw - healthW - 4 // gap between columns

	// ── SECTION 1: HEALTH STATUS (33%) | THROUGHPUT & CLIENTS (67%) ──
	sb.WriteString("  " + titleStyle.Render("HEALTH STATUS") + strings.Repeat(" ", healthW-15) + titleStyle.Render("THROUGHPUT & CLIENTS") + "\n")
	sb.WriteString(boxTop(iw) + "\n")

	type healthRow struct {
		metric, value, status string
	}
	var hRows []healthRow

	if dm["memory_usage_pct"] != "" {
		var pct float64
		fmt.Sscanf(dm["memory_usage_pct"], "%f", &pct)
		st := "OK"
		if pct > 90 {
			st = "CRIT"
		} else if pct > 75 {
			st = "WARN"
		}
		hRows = append(hRows, healthRow{"Memory", dm["used_memory_human"] + "/" + dm["maxmemory_human"] + " (" + dm["memory_usage_pct"] + ")", st})
	} else if dm["maxmemory"] == "0" || dm["maxmemory"] == "" {
		hRows = append(hRows, healthRow{"Memory", dm["used_memory_human"] + " (no limit)", "OK"})
	}
	if dm["hit_ratio"] != "" {
		var ratio float64
		fmt.Sscanf(dm["hit_ratio"], "%f", &ratio)
		st := "OK"
		if ratio < 80 {
			st = "CRIT"
		} else if ratio < 90 {
			st = "WARN"
		}
		hRows = append(hRows, healthRow{"Hit Ratio", dm["hit_ratio"], st})
	}
	if ev := dm["evicted_keys"]; ev != "" {
		st := "OK"
		if ev != "0" {
			st = "CRIT"
		}
		hRows = append(hRows, healthRow{"Evictions", ev, st})
	}
	if dm["mem_fragmentation_ratio"] != "" {
		frag, _ := strconv.ParseFloat(dm["mem_fragmentation_ratio"], 64)
		st := "OK"
		if frag > 1.5 || (frag < 1.0 && frag > 0) {
			st = "WARN"
		}
		hRows = append(hRows, healthRow{"Fragmentation", dm["mem_fragmentation_ratio"], st})
	}
	if dm["blocked_clients"] != "" {
		st := "OK"
		b, _ := strconv.Atoi(dm["blocked_clients"])
		if b > 10 {
			st = "CRIT"
		} else if b > 0 {
			st = "WARN"
		}
		hRows = append(hRows, healthRow{"Blocked", dm["blocked_clients"], st})
	}
	{
		st := "OK"
		if dm["rejected_connections"] != "" && dm["rejected_connections"] != "0" {
			st = "CRIT"
		}
		hRows = append(hRows, healthRow{"Rejected", dm["rejected_connections"], st})
	}
	if dm["rdb_last_bgsave_status"] != "" {
		st := "OK"
		if dm["rdb_last_bgsave_status"] != "ok" {
			st = "CRIT"
		}
		hRows = append(hRows, healthRow{"RDB Save", dm["rdb_last_bgsave_status"], st})
	}
	if dm["role"] == "slave" && dm["master_link_status"] != "" {
		st := "OK"
		if dm["master_link_status"] == "down" {
			st = "CRIT"
		}
		hRows = append(hRows, healthRow{"Repl Link", dm["master_link_status"], st})
	}
	// New health indicators
	if p99 := dm["latency_percentiles_usec_p99"]; p99 != "" {
		p99v, _ := strconv.ParseFloat(p99, 64)
		st := "OK"
		label := redisFmtUsec(p99v)
		if p99v > 10000 {
			st = "CRIT"
		} else if p99v > 1000 {
			st = "WARN"
		}
		hRows = append(hRows, healthRow{"P99 Latency", label, st})
	}
	if rssR := dm["rss_overhead_ratio"]; rssR != "" {
		rssv, _ := strconv.ParseFloat(rssR, 64)
		st := "OK"
		if rssv > 2.0 {
			st = "CRIT"
		} else if rssv > 1.5 {
			st = "WARN"
		}
		hRows = append(hRows, healthRow{"RSS Ratio", rssR + "x", st})
	}
	if capPct := dm["client_capacity_pct"]; capPct != "" {
		var cv float64
		fmt.Sscanf(capPct, "%f", &cv)
		st := "OK"
		if cv > 80 {
			st = "CRIT"
		} else if cv > 60 {
			st = "WARN"
		}
		hRows = append(hRows, healthRow{"Client Cap", capPct, st})
	}
	if forkUs := dm["latest_fork_usec"]; forkUs != "" {
		fv, _ := strconv.ParseInt(forkUs, 10, 64)
		st := "OK"
		label := redisFmtUsec(float64(fv))
		if fv > 500000 {
			st = "CRIT"
		} else if fv > 100000 {
			st = "WARN"
		}
		hRows = append(hRows, healthRow{"Fork Time", label, st})
	}
	if dm["slowlog_count"] != "" && dm["slowlog_count"] != "0" {
		st := "WARN"
		hRows = append(hRows, healthRow{"Slow Queries", dm["slowlog_count"] + " recent", st})
	}

	// Throughput items split into 2 sub-columns on right side
	type tpItem struct{ key, val string }
	tpCol1 := []tpItem{
		{"Ops/sec", dm["instantaneous_ops_per_sec"]},
		{"Input", redisFmtKbps(dm["instantaneous_input_kbps"])},
		{"Output", redisFmtKbps(dm["instantaneous_output_kbps"])},
		{"Total Cmds", redisFmtLargeNum(dm["total_commands_processed"])},
		{"Total Conns", redisFmtLargeNum(dm["total_connections_received"])},
		{"Net In", redisFmtNetBytes(dm["total_net_input_bytes"])},
		{"Net Out", redisFmtNetBytes(dm["total_net_output_bytes"])},
	}
	// Add latency to TP col1
	if p50 := dm["latency_percentiles_usec_p50"]; p50 != "" {
		p50v, _ := strconv.ParseFloat(p50, 64)
		tpCol1 = append(tpCol1, tpItem{"Latency p50", redisFmtUsec(p50v)})
	}
	if p99 := dm["latency_percentiles_usec_p99"]; p99 != "" {
		p99v, _ := strconv.ParseFloat(p99, 64)
		tpCol1 = append(tpCol1, tpItem{"Latency p99", redisFmtUsec(p99v)})
	}
	tpCol2 := []tpItem{
		{"Connected", dm["connected_clients"]},
		{"Blocked", dm["blocked_clients"]},
		{"Max Clients", dm["maxclients"]},
		{"Client Cap", dm["client_capacity_pct"]},
		{"Rejected", dm["rejected_connections"]},
		{"CPU Sys", redisFmtSec(dm["used_cpu_sys"])},
		{"CPU User", redisFmtSec(dm["used_cpu_user"])},
	}
	if ps := dm["pubsub_channels"]; ps != "" && ps != "0" {
		tpCol2 = append(tpCol2, tpItem{"PubSub Ch", ps})
	}
	if lf := dm["lazyfree_pending_objects"]; lf != "" && lf != "0" {
		tpCol2 = append(tpCol2, tpItem{"Lazyfree", lf})
	}

	cLabel := 14
	cVal := healthW - cLabel - 10
	if cVal < 10 {
		cVal = 10
	}
	tpHalf := (tpW - 2) / 2
	tpLabel := 13
	tpVal := tpHalf - tpLabel - 2
	if tpVal < 8 {
		tpVal = 8
	}

	maxRows := len(hRows)
	if len(tpCol1) > maxRows {
		maxRows = len(tpCol1)
	}
	if len(tpCol2) > maxRows {
		maxRows = len(tpCol2)
	}

	for i := 0; i < maxRows; i++ {
		// Health column (left 33%)
		var left string
		if i < len(hRows) {
			r := hRows[i]
			var badge string
			switch r.status {
			case "OK":
				badge = okStyle.Render("OK")
			case "WARN":
				badge = warnStyle.Render("WARN")
			case "CRIT":
				badge = critStyle.Render("CRIT")
			}
			left = fmt.Sprintf("%s %s %s",
				styledPad(dimStyle.Render(r.metric+":"), cLabel),
				styledPad(valueStyle.Render(r.value), cVal),
				badge)
		}

		// TP column 1 (middle)
		var mid string
		if i < len(tpCol1) && tpCol1[i].val != "" {
			mid = fmt.Sprintf("%s %s",
				styledPad(dimStyle.Render(tpCol1[i].key+":"), tpLabel),
				styledPad(valueStyle.Render(tpCol1[i].val), tpVal))
		}

		// TP column 2 (right)
		var right string
		if i < len(tpCol2) && tpCol2[i].val != "" {
			right = fmt.Sprintf("%s %s",
				styledPad(dimStyle.Render(tpCol2[i].key+":"), tpLabel),
				valueStyle.Render(tpCol2[i].val))
		}

		row := fmt.Sprintf("  %s %s %s %s %s",
			styledPad(left, healthW),
			dimStyle.Render("│"),
			styledPad(mid, tpHalf),
			dimStyle.Render("│"),
			right)
		sb.WriteString(boxRow(row, iw) + "\n")
	}
	sb.WriteString(boxBot(iw) + "\n")

	// ── SECTION 2: KEYSPACE & COMMANDS (full width, single box) ──
	sb.WriteString("  " + titleStyle.Render("KEYSPACE & COMMANDS") + "\n")
	sb.WriteString(boxTop(iw) + "\n")

	// Parse command stats
	type cmdEntry struct {
		name   string
		calls  int64
		usecPC float64
	}
	var cmds []cmdEntry
	for k, v := range dm {
		if !strings.HasPrefix(k, "cmdstat_") {
			continue
		}
		cmdName := strings.ToUpper(k[8:])
		var calls int64
		var usecPC float64
		for _, part := range strings.Split(v, ",") {
			pair := strings.SplitN(part, "=", 2)
			if len(pair) != 2 {
				continue
			}
			switch pair[0] {
			case "calls":
				calls, _ = strconv.ParseInt(pair[1], 10, 64)
			case "usec_per_call":
				usecPC, _ = strconv.ParseFloat(pair[1], 64)
			}
		}
		if calls > 0 {
			cmds = append(cmds, cmdEntry{name: cmdName, calls: calls, usecPC: usecPC})
		}
	}
	for i := 0; i < len(cmds); i++ {
		for j := i + 1; j < len(cmds); j++ {
			if cmds[j].calls > cmds[i].calls {
				cmds[i], cmds[j] = cmds[j], cmds[i]
			}
		}
	}
	var totalCmdCalls int64
	for _, c := range cmds {
		totalCmdCalls += c.calls
	}

	// DB table header
	dbHdr := fmt.Sprintf("  %s %s %s %s",
		styledPad(dimStyle.Render("DB"), 6),
		styledPad(dimStyle.Render("Keys"), 12),
		styledPad(dimStyle.Render("Expires"), 12),
		dimStyle.Render("Avg TTL"))
	sb.WriteString(boxRow(dbHdr, iw) + "\n")
	sb.WriteString(boxMid(iw) + "\n")

	// DB rows
	totalKeys := 0
	totalExpires := 0
	for i := 0; i <= 15; i++ {
		dbKey := fmt.Sprintf("db%d", i)
		v, ok := dm[dbKey]
		if !ok {
			continue
		}
		keys, expires, ttl := redisParseDBParts(v)
		totalKeys += keys
		totalExpires += expires
		dbRow := fmt.Sprintf("  %s %s %s %s",
			styledPad(valueStyle.Render(dbKey), 6),
			styledPad(valueStyle.Render(redisFmtLargeNum(fmt.Sprintf("%d", keys))), 12),
			styledPad(valueStyle.Render(redisFmtLargeNum(fmt.Sprintf("%d", expires))), 12),
			valueStyle.Render(redisFmtDuration(ttl)))
		sb.WriteString(boxRow(dbRow, iw) + "\n")
	}
	sb.WriteString(boxMid(iw) + "\n")
	totRow := fmt.Sprintf("  %s %s %s",
		styledPad(titleStyle.Render("Total"), 6),
		styledPad(valueStyle.Render(redisFmtLargeNum(fmt.Sprintf("%d", totalKeys))), 12),
		valueStyle.Render(redisFmtLargeNum(fmt.Sprintf("%d", totalExpires))))
	sb.WriteString(boxRow(totRow, iw) + "\n")

	// Key stats inline
	ksItems := []kv{
		{Key: "Hits", Val: redisFmtLargeNum(dm["keyspace_hits"])},
		{Key: "Misses", Val: redisFmtLargeNum(dm["keyspace_misses"])},
		{Key: "Hit Ratio", Val: dm["hit_ratio"]},
		{Key: "Expired", Val: redisFmtLargeNum(dm["expired_keys"])},
		{Key: "Evicted", Val: dm["evicted_keys"]},
	}
	var ksLine string
	for _, item := range ksItems {
		if item.Val == "" {
			continue
		}
		ksLine += fmt.Sprintf("  %s %s", dimStyle.Render(item.Key+":"), valueStyle.Render(item.Val))
	}
	sb.WriteString(boxRow(ksLine, iw) + "\n")

	// Command stats — wide table with each command as a column
	if len(cmds) > 0 {
		sb.WriteString(boxMid(iw) + "\n")

		// Determine how many commands fit per row (2 rows of commands)
		cmdColW := 18
		cmdsPerRow := (iw - 4) / cmdColW
		if cmdsPerRow < 4 {
			cmdsPerRow = 4
		}
		maxShow := cmdsPerRow * 2 // 2 rows
		if maxShow > len(cmds) {
			maxShow = len(cmds)
		}
		if maxShow > 28 {
			maxShow = 28
		}
		topCmds := cmds[:maxShow]

		// Row 1: command names
		for rowStart := 0; rowStart < len(topCmds); rowStart += cmdsPerRow {
			rowEnd := rowStart + cmdsPerRow
			if rowEnd > len(topCmds) {
				rowEnd = len(topCmds)
			}
			chunk := topCmds[rowStart:rowEnd]

			// Command name row
			var nameRow string
			for _, c := range chunk {
				nameRow += styledPad(titleStyle.Render(c.name), cmdColW)
			}
			sb.WriteString(boxRow("  "+nameRow, iw) + "\n")

			// Calls + % row
			var callRow string
			for _, c := range chunk {
				pct := float64(0)
				if totalCmdCalls > 0 {
					pct = float64(c.calls) / float64(totalCmdCalls) * 100
				}
				label := fmt.Sprintf("%s %.0f%%", redisFmtLargeNum(fmt.Sprintf("%d", c.calls)), pct)
				callRow += styledPad(valueStyle.Render(label), cmdColW)
			}
			sb.WriteString(boxRow("  "+callRow, iw) + "\n")

			// Latency row
			var latRow string
			for _, c := range chunk {
				latRow += styledPad(dimStyle.Render(redisFmtUsec(c.usecPC)+"/call"), cmdColW)
			}
			sb.WriteString(boxRow("  "+latRow, iw) + "\n")

			// Spacer between rows (not after last)
			if rowEnd < len(topCmds) {
				sb.WriteString(boxRow("", iw) + "\n")
			}
		}

		// Total commands summary
		sb.WriteString(boxMid(iw) + "\n")
		totalLine := fmt.Sprintf("  %s %s    %s %s    %s %d",
			dimStyle.Render("Total Calls:"), valueStyle.Render(redisFmtLargeNum(fmt.Sprintf("%d", totalCmdCalls))),
			dimStyle.Render("Unique Commands:"), valueStyle.Render(fmt.Sprintf("%d", len(cmds))),
			dimStyle.Render("Showing top:"), maxShow)
		sb.WriteString(boxRow(totalLine, iw) + "\n")
	}
	sb.WriteString(boxBot(iw) + "\n")

	// ── SECTION 3: MEMORY | PERSISTENCE | REPLICATION (full width, 3 cols) ──
	sb.WriteString("  " + titleStyle.Render("MEMORY") + strings.Repeat(" ", iw/3-8) +
		titleStyle.Render("PERSISTENCE") + strings.Repeat(" ", iw/3-13) +
		titleStyle.Render("REPLICATION") + "\n")
	sb.WriteString(boxTop(iw) + "\n")

	col3W := (iw - 8) / 3
	memKVs := []kv{
		{Key: "Used", Val: dm["used_memory_human"]},
		{Key: "RSS", Val: dm["used_memory_rss_human"]},
		{Key: "Peak", Val: dm["used_memory_peak_human"]},
		{Key: "Max", Val: dm["maxmemory_human"]},
		{Key: "Policy", Val: dm["maxmemory_policy"]},
		{Key: "Dataset%", Val: dm["used_memory_dataset_perc"]},
		{Key: "Fragment", Val: dm["mem_fragmentation_ratio"]},
		{Key: "Lua", Val: dm["used_memory_lua_human"]},
		{Key: "RSS Ratio", Val: dm["rss_overhead_ratio"]},
		{Key: "Allocator", Val: dm["mem_allocator"]},
	}
	persKVs := []kv{
		{Key: "RDB", Val: dm["rdb_last_bgsave_status"]},
		{Key: "Save Time", Val: redisFmtSec(dm["rdb_last_bgsave_time_sec"])},
		{Key: "Changes", Val: dm["rdb_changes_since_last_save"]},
		{Key: "AOF", Val: redisYesNo(dm["aof_enabled"])},
		{Key: "Rewrite", Val: dm["aof_last_bgrewrite_status"]},
		{Key: "Fork", Val: redisFmtUsecStr(dm["latest_fork_usec"])},
	}
	if dm["aof_current_size"] != "" {
		aofBytes, _ := strconv.ParseFloat(dm["aof_current_size"], 64)
		if aofBytes > 0 {
			persKVs = append(persKVs, kv{Key: "AOF Size", Val: redisFmtNetBytes(dm["aof_current_size"])})
		}
	}
	replKVs := []kv{
		{Key: "Role", Val: dm["role"]},
		{Key: "Slaves", Val: dm["connected_slaves"]},
	}
	if dm["master_host"] != "" {
		replKVs = append(replKVs,
			kv{Key: "Master", Val: dm["master_host"] + ":" + dm["master_port"]},
			kv{Key: "Link", Val: dm["master_link_status"]},
			kv{Key: "Last IO", Val: redisFmtSec(dm["master_last_io_seconds_ago"])})
	}
	if lagBytes := dm["repl_lag_bytes"]; lagBytes != "" {
		replKVs = append(replKVs, kv{Key: "Lag", Val: redisFmtNetBytes(lagBytes)})
	}
	if backlog := dm["repl_backlog_size"]; backlog != "" {
		replKVs = append(replKVs, kv{Key: "Backlog", Val: redisFmtNetBytes(backlog)})
	}

	maxR3 := len(memKVs)
	if len(persKVs) > maxR3 {
		maxR3 = len(persKVs)
	}
	if len(replKVs) > maxR3 {
		maxR3 = len(replKVs)
	}
	kvLabel := 10
	for i := 0; i < maxR3; i++ {
		var c1, c2, c3 string
		if i < len(memKVs) && memKVs[i].Val != "" {
			c1 = fmt.Sprintf("%s %s", styledPad(dimStyle.Render(memKVs[i].Key+":"), kvLabel), valueStyle.Render(memKVs[i].Val))
		}
		if i < len(persKVs) && persKVs[i].Val != "" {
			c2 = fmt.Sprintf("%s %s", styledPad(dimStyle.Render(persKVs[i].Key+":"), kvLabel), valueStyle.Render(persKVs[i].Val))
		}
		if i < len(replKVs) && replKVs[i].Val != "" {
			c3 = fmt.Sprintf("%s %s", styledPad(dimStyle.Render(replKVs[i].Key+":"), kvLabel), valueStyle.Render(replKVs[i].Val))
		}
		row := fmt.Sprintf("  %s %s %s %s %s",
			styledPad(c1, col3W),
			dimStyle.Render("│"),
			styledPad(c2, col3W),
			dimStyle.Render("│"),
			c3)
		sb.WriteString(boxRow(row, iw) + "\n")
	}
	sb.WriteString(boxBot(iw) + "\n")

	// ── SECTION 4: LATENCY & SLOW LOG (full width) ──
	hasLatency := dm["latency_percentiles_usec_p50"] != "" || dm["slowlog_entries"] != ""
	if hasLatency {
		sb.WriteString("  " + titleStyle.Render("LATENCY & SLOW LOG") + "\n")
		sb.WriteString(boxTop(iw) + "\n")

		// Latency summary row
		var latParts []string
		if p50 := dm["latency_percentiles_usec_p50"]; p50 != "" {
			p50v, _ := strconv.ParseFloat(p50, 64)
			latParts = append(latParts, fmt.Sprintf("%s %s", dimStyle.Render("p50:"), valueStyle.Render(redisFmtUsec(p50v))))
		}
		if p99 := dm["latency_percentiles_usec_p99"]; p99 != "" {
			p99v, _ := strconv.ParseFloat(p99, 64)
			latParts = append(latParts, fmt.Sprintf("%s %s", dimStyle.Render("p99:"), valueStyle.Render(redisFmtUsec(p99v))))
		}
		if p999 := dm["latency_percentiles_usec_p99.9"]; p999 != "" {
			p999v, _ := strconv.ParseFloat(p999, 64)
			latParts = append(latParts, fmt.Sprintf("%s %s", dimStyle.Render("p99.9:"), valueStyle.Render(redisFmtUsec(p999v))))
		}
		if forkUs := dm["latest_fork_usec"]; forkUs != "" {
			fv, _ := strconv.ParseFloat(forkUs, 64)
			latParts = append(latParts, fmt.Sprintf("%s %s", dimStyle.Render("Fork:"), valueStyle.Render(redisFmtUsec(fv))))
		}
		if len(latParts) > 0 {
			sb.WriteString(boxRow("  "+strings.Join(latParts, "    "), iw) + "\n")
		}

		// Slow log entries
		if entries := dm["slowlog_entries"]; entries != "" {
			sb.WriteString(boxMid(iw) + "\n")
			sb.WriteString(boxRow(fmt.Sprintf("  %s %s %s",
				styledPad(dimStyle.Render("TIME"), 10),
				styledPad(dimStyle.Render("DURATION"), 12),
				dimStyle.Render("COMMAND")), iw) + "\n")
			for _, entry := range strings.Split(entries, ";") {
				parts := strings.SplitN(entry, "|", 3)
				if len(parts) == 3 {
					row := fmt.Sprintf("  %s %s %s",
						styledPad(valueStyle.Render(parts[0]), 10),
						styledPad(warnStyle.Render(parts[1]), 12),
						valueStyle.Render(parts[2]))
					sb.WriteString(boxRow(row, iw) + "\n")
				}
			}
		}
		sb.WriteString(boxBot(iw) + "\n")
	}

	// ── SECTION 5: RECOMMENDATIONS (full width) ──
	recCount, _ := strconv.Atoi(dm["rec_count"])
	if recCount > 0 {
		sb.WriteString("  " + titleStyle.Render("RECOMMENDATIONS") + "\n")
		sb.WriteString(boxTop(iw) + "\n")
		for i := 0; i < recCount; i++ {
			rec := dm[fmt.Sprintf("rec_%d", i)]
			if rec == "" {
				continue
			}
			// Split recommendation into action + explanation at first " — "
			prefix := warnStyle.Render(fmt.Sprintf(" %d.", i+1))
			// Wrap long recommendations
			maxRecW := iw - 8
			if len(rec) > maxRecW {
				// First line
				sb.WriteString(boxRow(fmt.Sprintf("  %s %s", prefix, valueStyle.Render(rec[:maxRecW])), iw) + "\n")
				// Continuation lines
				remaining := rec[maxRecW:]
				for len(remaining) > 0 {
					chunk := remaining
					if len(chunk) > maxRecW {
						chunk = remaining[:maxRecW]
					}
					remaining = remaining[len(chunk):]
					sb.WriteString(boxRow(fmt.Sprintf("      %s", dimStyle.Render(chunk)), iw) + "\n")
				}
			} else {
				sb.WriteString(boxRow(fmt.Sprintf("  %s %s", prefix, valueStyle.Render(rec)), iw) + "\n")
			}
		}
		sb.WriteString(boxBot(iw) + "\n")
	}

	return sb.String()
}

// redisParseDBParts returns keys, expires, avg_ttl_ms from a Redis db info string.
func redisParseDBParts(v string) (keys, expires int, ttlMs int64) {
	for _, part := range strings.Split(v, ",") {
		kv := strings.SplitN(part, "=", 2)
		if len(kv) != 2 {
			continue
		}
		switch kv[0] {
		case "keys":
			keys, _ = strconv.Atoi(kv[1])
		case "expires":
			expires, _ = strconv.Atoi(kv[1])
		case "avg_ttl":
			ttlMs, _ = strconv.ParseInt(kv[1], 10, 64)
		}
	}
	return
}

// redisFmtDuration formats milliseconds into human-readable duration.
func redisFmtDuration(ms int64) string {
	if ms <= 0 {
		return "-"
	}
	sec := ms / 1000
	if sec >= 86400 {
		return fmt.Sprintf("%.1fd", float64(sec)/86400)
	}
	if sec >= 3600 {
		return fmt.Sprintf("%.1fh", float64(sec)/3600)
	}
	if sec >= 60 {
		return fmt.Sprintf("%.0fm", float64(sec)/60)
	}
	return fmt.Sprintf("%ds", sec)
}

// redisFmtUsec formats microseconds per call into readable latency.
func redisFmtUsec(usec float64) string {
	if usec >= 1000 {
		return fmt.Sprintf("%.2fms", usec/1000)
	}
	return fmt.Sprintf("%.1fus", usec)
}

func redisParseDB(v string) string {
	parts := strings.Split(v, ",")
	result := []string{}
	for _, p := range parts {
		kv := strings.SplitN(p, "=", 2)
		if len(kv) == 2 {
			switch kv[0] {
			case "keys":
				result = append(result, kv[1]+" keys")
			case "expires":
				result = append(result, kv[1]+" expires")
			case "avg_ttl":
				ttl, _ := strconv.ParseInt(kv[1], 10, 64)
				if ttl > 0 {
					result = append(result, fmt.Sprintf("avg_ttl=%ds", ttl/1000))
				}
			}
		}
	}
	return strings.Join(result, ", ")
}

func redisFmtKbps(s string) string {
	if s == "" {
		return ""
	}
	v, _ := strconv.ParseFloat(s, 64)
	if v >= 1024 {
		return fmt.Sprintf("%.1f MB/s", v/1024)
	}
	return fmt.Sprintf("%.1f KB/s", v)
}

func redisFmtNetBytes(s string) string {
	if s == "" {
		return ""
	}
	v, _ := strconv.ParseFloat(s, 64)
	return appFmtBytesShort(v)
}

func redisFmtLargeNum(s string) string {
	if s == "" {
		return ""
	}
	v, _ := strconv.ParseFloat(s, 64)
	switch {
	case v >= 1e9:
		return fmt.Sprintf("%.1fB", v/1e9)
	case v >= 1e6:
		return fmt.Sprintf("%.1fM", v/1e6)
	case v >= 1e3:
		return fmt.Sprintf("%.1fK", v/1e3)
	default:
		return s
	}
}

func redisYesNo(s string) string {
	if s == "1" {
		return "yes"
	}
	if s == "0" {
		return "no"
	}
	return s
}

func redisFmtUsecStr(s string) string {
	if s == "" {
		return ""
	}
	v, _ := strconv.ParseFloat(s, 64)
	return redisFmtUsec(v)
}

func redisFmtSec(s string) string {
	if s == "" {
		return ""
	}
	v, _ := strconv.ParseFloat(s, 64)
	if v >= 3600 {
		return fmt.Sprintf("%.1fh", v/3600)
	}
	if v >= 60 {
		return fmt.Sprintf("%.1fm", v/60)
	}
	return fmt.Sprintf("%.1fs", v)
}
