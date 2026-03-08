//go:build linux

package ui

import (
	"fmt"
	"sort"
	"strings"

	"github.com/ftahirops/xtop/model"
)

func renderAppsPage(snap *model.Snapshot, selectedIdx int, detailMode bool, width, height int) string {
	var sb strings.Builder
	iw := pageInnerW(width)

	instances := snap.Global.Apps.Instances

	if detailMode && selectedIdx < len(instances) {
		app := instances[selectedIdx]
		if app.AppType == "docker" {
			return renderDockerDetail(app, iw)
		}
		return renderAppsDetail(app, iw)
	}

	// ── List View ──────────────────────────────────────────────────────────

	sb.WriteString(titleStyle.Render("APPS DIAGNOSTICS"))
	sb.WriteString("\n\n")

	if len(instances) == 0 {
		sb.WriteString("\n")
		pad := (iw - 26) / 2
		if pad < 0 {
			pad = 0
		}
		sb.WriteString(strings.Repeat(" ", pad) + dimStyle.Render("No applications detected."))
		sb.WriteString("\n")
		sb.WriteString(pageFooter("Y:Apps"))
		return sb.String()
	}

	// Summary
	issueCount := 0
	for _, a := range instances {
		if len(a.HealthIssues) > 0 {
			issueCount++
		}
	}
	sb.WriteString(fmt.Sprintf("  %s detected   %s with issues\n\n",
		valueStyle.Render(fmt.Sprintf("%d apps", len(instances))),
		warnStyle.Render(fmt.Sprintf("%d", issueCount))))

	// Table
	colNum := 3
	colApp := 18
	colPID := 8
	colPort := 7
	colRSS := 8
	colConn := 7
	colThr := 9
	colHlth := 8

	header := fmt.Sprintf("  %s %s %s %s %s %s %s %s %s",
		styledPad(dimStyle.Render("#"), colNum),
		styledPad(dimStyle.Render("App"), colApp),
		styledPad(dimStyle.Render("PID"), colPID),
		styledPad(dimStyle.Render("Port"), colPort),
		styledPad(dimStyle.Render("RSS"), colRSS),
		styledPad(dimStyle.Render("Conns"), colConn),
		styledPad(dimStyle.Render("Threads"), colThr),
		styledPad(dimStyle.Render("Health"), colHlth),
		dimStyle.Render("Version"))

	sb.WriteString(boxTop(iw) + "\n")
	sb.WriteString(boxRow(header, iw) + "\n")
	sb.WriteString(boxMid(iw) + "\n")

	for i, app := range instances {
		name := app.DisplayName
		if len(name) > colApp-2 {
			name = name[:colApp-2]
		}

		portStr := "—"
		if app.Port > 0 {
			portStr = fmt.Sprintf("%d", app.Port)
		}

		rssStr := appFmtMem(app.RSSMB)
		healthStr := healthScoreStr(app.HealthScore)

		verStr := app.Version
		if verStr == "" {
			verStr = "—"
		}

		row := fmt.Sprintf("  %s %s %s %s %s %s %s %s %s",
			styledPad(dimStyle.Render(fmt.Sprintf("%d", i+1)), colNum),
			styledPad(valueStyle.Render(name), colApp),
			styledPad(valueStyle.Render(fmt.Sprintf("%d", app.PID)), colPID),
			styledPad(valueStyle.Render(portStr), colPort),
			styledPad(valueStyle.Render(rssStr), colRSS),
			styledPad(valueStyle.Render(fmt.Sprintf("%d", app.Connections)), colConn),
			styledPad(valueStyle.Render(fmt.Sprintf("%d", app.Threads)), colThr),
			styledPad(healthStr, colHlth),
			dimStyle.Render(verStr))

		if i == selectedIdx {
			row = titleStyle.Render("> ") + row[2:]
		}

		sb.WriteString(boxRow(row, iw) + "\n")
	}

	sb.WriteString(boxBot(iw) + "\n")
	sb.WriteString(pageFooter("j/k:Navigate  Enter:Details  Y:Apps"))
	return sb.String()
}

// ── Generic App Detail ─────────────────────────────────────────────────

func renderAppsDetail(app model.AppInstance, iw int) string {
	var sb strings.Builder

	sb.WriteString(appDetailHeader(app))

	sb.WriteString(appSection("PROCESS INFO", iw, []kv{
		{Key: "PID", Val: fmt.Sprintf("%d", app.PID)},
		{Key: "Port", Val: appFmtPort(app.Port)},
		{Key: "Uptime", Val: fmtUptime(app.UptimeSec)},
		{Key: "Version", Val: appFmtDash(app.Version)},
		{Key: "Config", Val: app.ConfigPath},
	}))

	sb.WriteString(appSection("RESOURCE USAGE", iw, []kv{
		{Key: "RSS", Val: appFmtMem(app.RSSMB)},
		{Key: "CPU", Val: fmt.Sprintf("%.1f%%", app.CPUPct)},
		{Key: "Threads", Val: fmt.Sprintf("%d", app.Threads)},
		{Key: "File Descriptors", Val: fmt.Sprintf("%d", app.FDs)},
		{Key: "Connections", Val: fmt.Sprintf("%d", app.Connections)},
	}))

	if app.HasDeepMetrics && len(app.DeepMetrics) > 0 {
		sb.WriteString(renderAppDeepMetrics(app, iw))
	}

	if len(app.HealthIssues) > 0 {
		sb.WriteString("  " + titleStyle.Render("HEALTH ISSUES") + "\n")
		sb.WriteString(boxTop(iw) + "\n")
		for _, issue := range app.HealthIssues {
			row := "  " + critStyle.Render("\u25cf") + " " + valueStyle.Render(issue)
			sb.WriteString(boxRow(row, iw) + "\n")
		}
		sb.WriteString(boxBot(iw) + "\n\n")
	}

	if app.NeedsCreds && !app.HasDeepMetrics {
		sb.WriteString("  " + dimStyle.Render("Configure credentials in ~/.config/xtop/secrets.json for deep metrics") + "\n\n")
	}

	sb.WriteString(pageFooter("k:Back  Y:Apps"))
	return sb.String()
}

func renderAppDeepMetrics(app model.AppInstance, iw int) string {
	switch app.AppType {
	case "elasticsearch":
		return renderESDeepMetrics(app, iw)
	default:
		return renderGenericDeepMetrics(app.DeepMetrics, iw)
	}
}

// ── Elasticsearch Detail ───────────────────────────────────────────────

func renderESDeepMetrics(app model.AppInstance, iw int) string {
	var sb strings.Builder
	dm := app.DeepMetrics

	sb.WriteString(appSection("CLUSTER", iw, []kv{
		{Key: "Cluster Name", Val: dm["cluster_name"]},
		{Key: "Status", Val: esColorStatus(dm["status"])},
		{Key: "Nodes", Val: dm["number_of_nodes"]},
		{Key: "Data Nodes", Val: dm["number_of_data_nodes"]},
		{Key: "Lucene", Val: dm["lucene_version"]},
	}))

	sb.WriteString(appSection("SHARDS", iw, []kv{
		{Key: "Active Primary", Val: dm["active_primary_shards"]},
		{Key: "Active Total", Val: dm["active_shards"]},
		{Key: "Unassigned", Val: esColorVal(dm["unassigned_shards"], "0")},
		{Key: "Relocating", Val: dm["relocating_shards"]},
		{Key: "Initializing", Val: dm["initializing_shards"]},
		{Key: "Pending Tasks", Val: dm["number_of_pending_tasks"]},
		{Key: "Active %", Val: dm["active_shards_percent_as_number"]},
	}))

	sb.WriteString(appSection("INDICES", iw, []kv{
		{Key: "Total Indices", Val: dm["total_indices"]},
		{Key: "Green", Val: dm["indices_green"]},
		{Key: "Yellow", Val: esColorVal(dm["indices_yellow"], "0")},
		{Key: "Red", Val: esColorVal(dm["indices_red"], "0")},
		{Key: "Documents", Val: dm["doc_count"]},
		{Key: "Deleted Docs", Val: dm["deleted_docs"]},
		{Key: "Store Size", Val: dm["store_size"]},
		{Key: "Segments", Val: dm["segment_count"]},
		{Key: "Segment Memory", Val: dm["segment_memory"]},
	}))

	sb.WriteString(appSection("JVM & MEMORY", iw, []kv{
		{Key: "Heap Used", Val: dm["jvm_heap_used"]},
		{Key: "Heap Max", Val: dm["jvm_heap_max"]},
		{Key: "Heap Used %", Val: dm["jvm_heap_used_pct"]},
		{Key: "Fielddata Mem", Val: dm["fielddata_memory"]},
		{Key: "Fielddata Evictions", Val: dm["fielddata_evictions"]},
		{Key: "Query Cache Mem", Val: dm["query_cache_memory"]},
		{Key: "Query Cache Hits", Val: dm["query_cache_hits"]},
		{Key: "Query Cache Misses", Val: dm["query_cache_misses"]},
	}))

	// GC — collect all gc_*_count keys
	gcKVs := []kv{}
	for _, name := range []string{"young", "old"} {
		countKey := "gc_" + name + "_count"
		timeKey := "gc_" + name + "_time_ms"
		if dm[countKey] != "" {
			gcKVs = append(gcKVs, kv{Key: capitalize(name) + " Count", Val: dm[countKey]})
			gcKVs = append(gcKVs, kv{Key: capitalize(name) + " Time (ms)", Val: dm[timeKey]})
		}
	}
	if len(gcKVs) == 0 {
		for k, v := range dm {
			if strings.HasPrefix(k, "gc_") && strings.HasSuffix(k, "_count") {
				name := strings.TrimSuffix(strings.TrimPrefix(k, "gc_"), "_count")
				gcKVs = append(gcKVs, kv{Key: name + " Count", Val: v})
				if tv, ok := dm["gc_"+name+"_time_ms"]; ok {
					gcKVs = append(gcKVs, kv{Key: name + " Time (ms)", Val: tv})
				}
			}
		}
	}
	if len(gcKVs) > 0 {
		sb.WriteString(appSection("GARBAGE COLLECTION", iw, gcKVs))
	}

	sb.WriteString(appSection("THROUGHPUT", iw, []kv{
		{Key: "Index Total", Val: dm["index_total"]},
		{Key: "Index Time (ms)", Val: dm["index_time_ms"]},
		{Key: "Search Queries", Val: dm["search_query_total"]},
		{Key: "Search Time (ms)", Val: dm["search_query_time_ms"]},
		{Key: "Merges", Val: dm["merge_total"]},
		{Key: "OS CPU", Val: dm["os_cpu_pct"]},
		{Key: "HTTP Connections", Val: dm["http_current_open"]},
	}))

	return sb.String()
}

func esColorStatus(s string) string {
	switch s {
	case "green":
		return okStyle.Render("GREEN")
	case "yellow":
		return warnStyle.Render("YELLOW")
	case "red":
		return critStyle.Render("RED")
	}
	return s
}

func esColorVal(s, good string) string {
	if s == "" || s == good {
		return s
	}
	return warnStyle.Render(s)
}

func capitalize(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

// ── Docker Detail ──────────────────────────────────────────────────────

func renderDockerDetail(app model.AppInstance, iw int) string {
	var sb strings.Builder

	sb.WriteString(appDetailHeader(app))

	// Daemon Info
	sb.WriteString(appSection("DOCKER DAEMON", iw, []kv{
		{Key: "PID", Val: fmt.Sprintf("%d", app.PID)},
		{Key: "Version", Val: appFmtDash(app.Version)},
		{Key: "Uptime", Val: fmtUptime(app.UptimeSec)},
		{Key: "RSS", Val: appFmtMem(app.RSSMB)},
		{Key: "Threads", Val: fmt.Sprintf("%d", app.Threads)},
		{Key: "File Descriptors", Val: fmt.Sprintf("%d", app.FDs)},
		{Key: "Storage Driver", Val: app.DeepMetrics["Storage Driver"]},
		{Key: "Cgroup Driver", Val: app.DeepMetrics["Cgroup Driver"]},
		{Key: "OS", Val: app.DeepMetrics["OS"]},
		{Key: "Kernel", Val: app.DeepMetrics["Kernel"]},
		{Key: "CPUs", Val: app.DeepMetrics["CPUs"]},
		{Key: "Total Memory", Val: app.DeepMetrics["Total Memory"]},
	}))

	// Container Summary
	sb.WriteString(appSection("CONTAINER SUMMARY", iw, []kv{
		{Key: "Total", Val: app.DeepMetrics["Total Containers"]},
		{Key: "Running", Val: app.DeepMetrics["Running"]},
		{Key: "Stopped", Val: app.DeepMetrics["Stopped"]},
		{Key: "Paused", Val: app.DeepMetrics["Paused"]},
		{Key: "Images", Val: app.DeepMetrics["Images"]},
	}))

	// Per-container table
	if len(app.Containers) > 0 {
		sb.WriteString("  " + titleStyle.Render("CONTAINERS") + "\n")
		sb.WriteString(boxTop(iw) + "\n")

		cName := 22
		cState := 10
		cCPU := 8
		cMem := 24
		cNetRx := 10
		cNetTx := 10
		cBlkR := 10
		cBlkW := 10
		cPIDs := 6

		hdr := fmt.Sprintf("  %s %s %s %s %s %s %s %s %s",
			styledPad(dimStyle.Render("Name"), cName),
			styledPad(dimStyle.Render("State"), cState),
			styledPad(dimStyle.Render("CPU%"), cCPU),
			styledPad(dimStyle.Render("Memory"), cMem),
			styledPad(dimStyle.Render("Net RX"), cNetRx),
			styledPad(dimStyle.Render("Net TX"), cNetTx),
			styledPad(dimStyle.Render("Blk R"), cBlkR),
			styledPad(dimStyle.Render("Blk W"), cBlkW),
			styledPad(dimStyle.Render("PIDs"), cPIDs))
		sb.WriteString(boxRow(hdr, iw) + "\n")
		sb.WriteString(boxMid(iw) + "\n")

		for _, c := range app.Containers {
			name := c.Name
			if len(name) > cName-2 {
				name = name[:cName-2]
			}

			stateStr := c.State
			switch c.State {
			case "running":
				stateStr = okStyle.Render("running")
			case "exited":
				if c.ExitCode != 0 {
					stateStr = critStyle.Render("exited")
				} else {
					stateStr = dimStyle.Render("exited")
				}
			case "paused":
				stateStr = warnStyle.Render("paused")
			default:
				stateStr = dimStyle.Render(c.State)
			}

			cpuStr := "—"
			memStr := "—"
			netRx := "—"
			netTx := "—"
			blkR := "—"
			blkW := "—"
			pidStr := "—"

			if c.State == "running" {
				cpuStr = fmt.Sprintf("%.1f%%", c.CPUPct)
				if c.MemLimitBytes > 0 && c.MemLimitBytes < 1e18 {
					memStr = fmt.Sprintf("%s / %s (%.0f%%)",
						appFmtBytesShort(c.MemUsedBytes),
						appFmtBytesShort(c.MemLimitBytes),
						c.MemPct)
				} else {
					memStr = appFmtBytesShort(c.MemUsedBytes)
				}
				netRx = appFmtBytesShort(c.NetRxBytes)
				netTx = appFmtBytesShort(c.NetTxBytes)
				blkR = appFmtBytesShort(c.BlockRead)
				blkW = appFmtBytesShort(c.BlockWrite)
				pidStr = fmt.Sprintf("%d", c.PIDs)
			}

			row := fmt.Sprintf("  %s %s %s %s %s %s %s %s %s",
				styledPad(valueStyle.Render(name), cName),
				styledPad(stateStr, cState),
				styledPad(valueStyle.Render(cpuStr), cCPU),
				styledPad(valueStyle.Render(memStr), cMem),
				styledPad(valueStyle.Render(netRx), cNetRx),
				styledPad(valueStyle.Render(netTx), cNetTx),
				styledPad(valueStyle.Render(blkR), cBlkR),
				styledPad(valueStyle.Render(blkW), cBlkW),
				styledPad(valueStyle.Render(pidStr), cPIDs))
			sb.WriteString(boxRow(row, iw) + "\n")

			// Detail line: image, health, restarts, status
			details := []string{}
			if c.Image != "" {
				details = append(details, dimStyle.Render("image: ")+valueStyle.Render(c.Image))
			}
			if c.Health != "" && c.Health != "—" {
				hlth := c.Health
				if hlth == "healthy" {
					hlth = okStyle.Render(hlth)
				} else if hlth == "unhealthy" {
					hlth = critStyle.Render(hlth)
				}
				details = append(details, dimStyle.Render("health: ")+hlth)
			}
			if c.RestartCount > 0 {
				details = append(details, dimStyle.Render("restarts: ")+warnStyle.Render(fmt.Sprintf("%d", c.RestartCount)))
			}
			if c.State == "exited" {
				details = append(details, dimStyle.Render("exit: ")+valueStyle.Render(fmt.Sprintf("%d", c.ExitCode)))
			}
			if c.Status != "" {
				details = append(details, dimStyle.Render(c.Status))
			}
			if len(details) > 0 {
				detailRow := "    " + strings.Join(details, "  ")
				sb.WriteString(boxRow(detailRow, iw) + "\n")
			}
		}
		sb.WriteString(boxBot(iw) + "\n\n")
	}

	if len(app.HealthIssues) > 0 {
		sb.WriteString("  " + titleStyle.Render("HEALTH ISSUES") + "\n")
		sb.WriteString(boxTop(iw) + "\n")
		for _, issue := range app.HealthIssues {
			row := "  " + critStyle.Render("\u25cf") + " " + valueStyle.Render(issue)
			sb.WriteString(boxRow(row, iw) + "\n")
		}
		sb.WriteString(boxBot(iw) + "\n\n")
	}

	sb.WriteString(pageFooter("k:Back  Y:Apps"))
	return sb.String()
}

// ── Generic Deep Metrics ───────────────────────────────────────────────

func renderGenericDeepMetrics(dm map[string]string, iw int) string {
	keys := make([]string, 0, len(dm))
	for k := range dm {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	kvs := make([]kv, 0, len(keys))
	for _, k := range keys {
		kvs = append(kvs, kv{Key: k, Val: dm[k]})
	}
	return appSection("DEEP METRICS", iw, kvs)
}

// ── Shared Helpers ─────────────────────────────────────────────────────

func appDetailHeader(app model.AppInstance) string {
	status := "OK"
	if app.HealthScore < 50 {
		status = "CRIT"
	} else if app.HealthScore < 80 {
		status = "WARN"
	}
	return titleStyle.Render(app.DisplayName) + "  " + renderHealthBadge(status) +
		"  " + dimStyle.Render(fmt.Sprintf("(score: %d)", app.HealthScore)) + "\n\n"
}

func appSection(title string, iw int, kvs []kv) string {
	var sb strings.Builder
	sb.WriteString("  " + titleStyle.Render(title) + "\n")
	sb.WriteString(boxTop(iw) + "\n")
	for _, item := range kvs {
		if item.Val == "" {
			continue
		}
		label := item.Key + ":"
		row := fmt.Sprintf("  %s %s", styledPad(dimStyle.Render(label), 22), valueStyle.Render(item.Val))
		sb.WriteString(boxRow(row, iw) + "\n")
	}
	sb.WriteString(boxBot(iw) + "\n\n")
	return sb.String()
}

func appFmtMem(mb float64) string {
	if mb >= 1024 {
		return fmt.Sprintf("%.1fG", mb/1024)
	}
	return fmt.Sprintf("%.0fM", mb)
}

func appFmtPort(port int) string {
	if port > 0 {
		return fmt.Sprintf("%d", port)
	}
	return "—"
}

func appFmtDash(s string) string {
	if s == "" {
		return "—"
	}
	return s
}

func appFmtBytesShort(b float64) string {
	switch {
	case b >= 1e12:
		return fmt.Sprintf("%.1fT", b/1e12)
	case b >= 1e9:
		return fmt.Sprintf("%.1fG", b/1e9)
	case b >= 1e6:
		return fmt.Sprintf("%.1fM", b/1e6)
	case b >= 1e3:
		return fmt.Sprintf("%.1fK", b/1e3)
	default:
		return fmt.Sprintf("%.0fB", b)
	}
}

func healthScoreStr(score int) string {
	s := fmt.Sprintf("%d", score)
	switch {
	case score >= 80:
		return okStyle.Render(s)
	case score >= 50:
		return warnStyle.Render(s)
	default:
		return critStyle.Render(s)
	}
}
