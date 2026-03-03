package ui

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/ftahirops/xtop/engine"
	"github.com/ftahirops/xtop/model"
	"github.com/ftahirops/xtop/store"
)

// ── Intel page collapsible section constants ────────────────────────────────

const (
	intelSecImpact    = 0
	intelSecCorr      = 1
	intelSecRuntimes  = 2
	intelSecSLO       = 3
	intelSecAutopilot = 4
	intelSecIncidents = 5
	intelSecCount     = 6
)

var intelSectionNames = [intelSecCount]string{
	"IMPACT SCORES",
	"CROSS-SIGNAL CORRELATION",
	"RUNTIMES",
	"SLO STATUS",
	"AUTOPILOT",
	"INCIDENTS",
}

// ── Lazy incident store (read-only, opened once) ────────────────────────────

var (
	intelStoreOnce sync.Once
	intelStore     *store.Store
)

func getIntelStore() *store.Store {
	intelStoreOnce.Do(func() {
		home, err := os.UserHomeDir()
		if err != nil {
			return
		}
		dbPath := filepath.Join(home, ".xtop", "incidents.db")
		if _, err := os.Stat(dbPath); err != nil {
			return
		}
		st, err := store.Open(dbPath)
		if err != nil {
			return
		}
		intelStore = st
	})
	return intelStore
}

// ── Main render function ────────────────────────────────────────────────────

func renderIntelPage(
	snap *model.Snapshot,
	rates *model.RateSnapshot,
	result *model.AnalysisResult,
	eng *engine.Engine,
	cursor int, expanded [intelSecCount]bool,
	width, height int,
) string {
	var sb strings.Builder
	iw := pageInnerW(width)

	sb.WriteString(titleStyle.Render("─── INTELLIGENCE ") + dimStyle.Render(strings.Repeat("─", maxInt(iw-17, 0))) + "\n\n")

	// Compute data sources
	scores := engine.ComputeImpactScores(snap, rates, result)
	var corrs []model.CrossCorrelation
	if result != nil {
		corrs = result.CrossCorrelations
	}
	var runtimes model.RuntimeMetrics
	if snap != nil {
		runtimes = snap.Global.Runtimes
	}
	var sloResults []engine.SLOResult
	if eng != nil && len(eng.SLOPolicies) > 0 {
		sloResults = engine.EvaluateSLOs(eng.SLOPolicies, snap, rates, result)
	}
	var ap *engine.Autopilot
	if eng != nil {
		ap = eng.Autopilot
	}

	st := getIntelStore()
	var incidents []store.IncidentRecord
	if st != nil {
		incidents, _ = st.ListIncidents(10, 0)
	}

	// Summary functions
	summaryFuncs := [intelSecCount]func() string{
		func() string { return intelImpactSummary(len(scores)) },
		func() string { return intelCorrSummary(len(corrs)) },
		func() string { return intelRuntimesSummary(runtimes) },
		func() string {
			if len(sloResults) == 0 {
				return "not configured"
			}
			pass := 0
			for _, r := range sloResults {
				if r.Passed {
					pass++
				}
			}
			return intelSLOSummary(pass, len(sloResults))
		},
		func() string { return intelAutopilotSummary(ap) },
		func() string { return intelIncidentsSummary(len(incidents), st) },
	}

	// Render functions
	renderFuncs := [intelSecCount]func() string{
		func() string { return renderIntelImpactContent(scores, iw) },
		func() string { return renderIntelCorrContent(corrs, iw) },
		func() string { return renderIntelRuntimesContent(runtimes, iw) },
		func() string { return renderIntelSLOContent(sloResults, eng, iw) },
		func() string { return renderIntelAutopilotContent(ap, iw) },
		func() string { return renderIntelIncidentsContent(incidents, st, iw) },
	}

	// Render each section
	for i := 0; i < intelSecCount; i++ {
		header := renderNetSectionHeader(intelSectionNames[i], summaryFuncs[i](), i == cursor, expanded[i], iw)
		sb.WriteString(header)
		if expanded[i] {
			sb.WriteString(renderFuncs[i]())
		}
	}

	sb.WriteString(pageFooter("Tab:section  Enter:expand  A:all  C:collapse"))
	return sb.String()
}

// ── Summary functions ───────────────────────────────────────────────────────

func intelImpactSummary(n int) string {
	if n == 0 {
		return "no data"
	}
	return fmt.Sprintf("%d processes scored", n)
}

func intelCorrSummary(n int) string {
	if n == 0 {
		return "none"
	}
	if n == 1 {
		return "1 pair detected"
	}
	return fmt.Sprintf("%d pairs detected", n)
}

func intelRuntimesSummary(runtimes model.RuntimeMetrics) string {
	var activeNames []string
	totalProcs := 0
	for _, entry := range runtimes.Entries {
		if entry.Active && len(entry.Processes) > 0 {
			activeNames = append(activeNames, entry.DisplayName)
			totalProcs += len(entry.Processes)
		}
	}
	if len(activeNames) == 0 {
		return "no runtimes detected"
	}
	return fmt.Sprintf("%s (%d procs)", strings.Join(activeNames, ", "), totalProcs)
}

func intelSLOSummary(pass, total int) string {
	return fmt.Sprintf("%d/%d passing", pass, total)
}

func intelAutopilotSummary(ap *engine.Autopilot) string {
	if ap == nil {
		return "disabled"
	}
	actions := ap.Actions()
	if len(actions) == 0 {
		return "idle"
	}
	return fmt.Sprintf("%d actions", len(actions))
}

func intelIncidentsSummary(n int, st *store.Store) string {
	if st == nil {
		return "no database"
	}
	if n == 0 {
		return "none stored"
	}
	return fmt.Sprintf("%d stored", n)
}

// ── Section content renderers ───────────────────────────────────────────────

func renderIntelImpactContent(scores []model.ImpactScore, iw int) string {
	if len(scores) == 0 {
		return dimStyle.Render("  No process impact data available.") + "\n\n"
	}

	var sb strings.Builder
	sb.WriteString(boxTop(iw) + "\n")

	// Header row
	hdr := fmt.Sprintf("  %s %s %s %s %s %s %s",
		styledPad(dimStyle.Render("RANK"), 6),
		styledPad(dimStyle.Render("PID"), 8),
		styledPad(dimStyle.Render("SERVICE"), 16),
		styledPad(dimStyle.Render("CPU%"), 8),
		styledPad(dimStyle.Render("RSS"), 10),
		styledPad(dimStyle.Render("IO(w)"), 10),
		dimStyle.Render("IMPACT"))
	sb.WriteString(boxRow(hdr, iw) + "\n")
	sb.WriteString(boxMid(iw) + "\n")

	// Show top 15
	n := len(scores)
	if n > 15 {
		n = 15
	}
	for _, s := range scores[:n] {
		name := s.Service
		if name == "" {
			name = s.Comm
		}
		if len(name) > 14 {
			name = name[:14]
		}

		// Impact bar + number
		barLen := int(s.Composite / 100 * 10)
		if barLen > 10 {
			barLen = 10
		}
		bar := strings.Repeat("█", barLen) + strings.Repeat("░", 10-barLen)
		impactStr := fmt.Sprintf("%s %3.0f", bar, s.Composite)

		// Color by score
		style := okStyle
		if s.Composite > 70 {
			style = critStyle
		} else if s.Composite > 40 {
			style = warnStyle
		}

		// RSS formatting
		rssStr := formatBytes(s.RSS)

		// IO write formatting
		ioStr := fmt.Sprintf("%.1f MB/s", s.WriteMBs)

		row := fmt.Sprintf("  %s %s %s %s %s %s %s",
			styledPad(dimStyle.Render(fmt.Sprintf("#%d", s.Rank)), 6),
			styledPad(valueStyle.Render(fmt.Sprintf("%d", s.PID)), 8),
			styledPad(valueStyle.Render(name), 16),
			styledPad(valueStyle.Render(fmt.Sprintf("%.1f", s.CPUSaturation*100)), 8),
			styledPad(valueStyle.Render(rssStr), 10),
			styledPad(dimStyle.Render(ioStr), 10),
			style.Render(impactStr))
		sb.WriteString(boxRow(row, iw) + "\n")

		// Component breakdown
		breakdown := fmt.Sprintf("    CPU=%.2f PSI=%.2f IO=%.2f MEM=%.2f NET=%.2f",
			s.CPUSaturation, s.PSIContrib, s.IOWait, s.MemGrowth, s.NetRetrans)
		if s.NewnessPenalty > 0 {
			breakdown += fmt.Sprintf(" NEW=+%.2f", s.NewnessPenalty)
		}
		sb.WriteString(boxRow(dimStyle.Render(breakdown), iw) + "\n")
	}

	sb.WriteString(boxBot(iw) + "\n\n")
	return sb.String()
}

func renderIntelCorrContent(corrs []model.CrossCorrelation, iw int) string {
	if len(corrs) == 0 {
		return dimStyle.Render("  No cross-domain correlations active.") + "\n\n"
	}

	var sb strings.Builder
	sb.WriteString(boxTop(iw) + "\n")

	for i, c := range corrs {
		confPct := c.Confidence * 100
		style := okStyle
		if confPct > 80 {
			style = critStyle
		} else if confPct > 50 {
			style = warnStyle
		}

		row := fmt.Sprintf("  %s → %s  lead=%.1fs  confidence=%s",
			warnStyle.Render(c.Cause),
			critStyle.Render(c.Effect),
			c.LeadTimeSec,
			style.Render(fmt.Sprintf("%.0f%%", confPct)))
		sb.WriteString(boxRow(row, iw) + "\n")

		if c.Explanation != "" {
			sb.WriteString(boxRow(dimStyle.Render("    "+c.Explanation), iw) + "\n")
		}
		if i < len(corrs)-1 {
			sb.WriteString(boxRow("", iw) + "\n")
		}
	}

	sb.WriteString(boxBot(iw) + "\n\n")
	return sb.String()
}

func renderIntelRuntimesContent(runtimes model.RuntimeMetrics, iw int) string {
	// Count active entries
	hasActive := false
	for _, entry := range runtimes.Entries {
		if entry.Active && len(entry.Processes) > 0 {
			hasActive = true
			break
		}
	}
	if !hasActive {
		return dimStyle.Render("  No runtime processes detected.") + "\n\n"
	}

	var sb strings.Builder

	for _, entry := range runtimes.Entries {
		if !entry.Active || len(entry.Processes) == 0 {
			continue
		}

		// Sub-header for each runtime
		sb.WriteString(fmt.Sprintf("  %s %s\n",
			titleStyle.Render(entry.DisplayName),
			dimStyle.Render(fmt.Sprintf("(%d processes)", len(entry.Processes)))))

		switch entry.Name {
		case "dotnet":
			sb.WriteString(renderDotNetSubTable(entry.Processes, iw))
		case "jvm":
			sb.WriteString(renderJVMSubTable(entry.Processes, iw))
		default:
			sb.WriteString(renderGenericSubTable(entry.Processes, iw))
		}
	}

	return sb.String()
}

func renderDotNetSubTable(procs []model.RuntimeProcessMetrics, iw int) string {
	var sb strings.Builder
	sb.WriteString(boxTop(iw) + "\n")

	hdr := fmt.Sprintf("  %s %s %s %s %s %s %s %s",
		styledPad(dimStyle.Render("PID"), 8),
		styledPad(dimStyle.Render("COMM"), 12),
		styledPad(dimStyle.Render("GC_HEAP"), 10),
		styledPad(dimStyle.Render("GC_TIME%"), 10),
		styledPad(dimStyle.Render("ALLOC_RATE"), 12),
		styledPad(dimStyle.Render("TP_COUNT"), 10),
		styledPad(dimStyle.Render("TP_QUEUE"), 10),
		dimStyle.Render("EXCEPT"))
	sb.WriteString(boxRow(hdr, iw) + "\n")
	sb.WriteString(boxMid(iw) + "\n")

	for _, p := range procs {
		gcStyle := valueStyle
		if p.GCPausePct > 20 {
			gcStyle = critStyle
		} else if p.GCPausePct > 10 {
			gcStyle = warnStyle
		}

		tpQueue := p.Extra["threadpool_queue"]
		tpQueueInt := 0
		fmt.Sscanf(tpQueue, "%d", &tpQueueInt)
		queueStyle := valueStyle
		if tpQueueInt > 100 {
			queueStyle = critStyle
		} else if tpQueueInt > 20 {
			queueStyle = warnStyle
		}

		comm := p.Comm
		if len(comm) > 10 {
			comm = comm[:10]
		}

		row := fmt.Sprintf("  %s %s %s %s %s %s %s %s",
			styledPad(valueStyle.Render(fmt.Sprintf("%d", p.PID)), 8),
			styledPad(valueStyle.Render(comm), 12),
			styledPad(valueStyle.Render(fmt.Sprintf("%.1f MB", p.GCHeapMB)), 10),
			styledPad(gcStyle.Render(fmt.Sprintf("%.1f%%", p.GCPausePct)), 10),
			styledPad(valueStyle.Render(fmt.Sprintf("%.1f MB/s", p.AllocRateMBs)), 12),
			styledPad(valueStyle.Render(p.Extra["threadpool_count"]), 10),
			styledPad(queueStyle.Render(tpQueue), 10),
			dimStyle.Render(p.Extra["exception_count"]))
		sb.WriteString(boxRow(row, iw) + "\n")

		// Second line: requests + working set
		reqPerSec := p.Extra["requests_per_sec"]
		curReq := p.Extra["current_requests"]
		if reqPerSec != "" && reqPerSec != "0.0" {
			detail := fmt.Sprintf("    req/s=%s  current=%s  working_set=%.1f MB",
				reqPerSec, curReq, p.WorkingSetMB)
			sb.WriteString(boxRow(dimStyle.Render(detail), iw) + "\n")
		}
	}

	sb.WriteString(boxBot(iw) + "\n\n")
	return sb.String()
}

func renderJVMSubTable(procs []model.RuntimeProcessMetrics, iw int) string {
	var sb strings.Builder
	sb.WriteString(boxTop(iw) + "\n")

	hdr := fmt.Sprintf("  %s %s %s %s %s %s %s %s",
		styledPad(dimStyle.Render("PID"), 8),
		styledPad(dimStyle.Render("COMM"), 12),
		styledPad(dimStyle.Render("HEAP"), 10),
		styledPad(dimStyle.Render("HEAP_MAX"), 10),
		styledPad(dimStyle.Render("GC_TIME%"), 10),
		styledPad(dimStyle.Render("YOUNG_GC"), 10),
		styledPad(dimStyle.Render("FULL_GC"), 10),
		dimStyle.Render("THREADS"))
	sb.WriteString(boxRow(hdr, iw) + "\n")
	sb.WriteString(boxMid(iw) + "\n")

	for _, p := range procs {
		gcStyle := valueStyle
		if p.GCPausePct > 20 {
			gcStyle = critStyle
		} else if p.GCPausePct > 10 {
			gcStyle = warnStyle
		}

		comm := p.Comm
		if len(comm) > 10 {
			comm = comm[:10]
		}

		heapMax := p.Extra["heap_max_mb"]
		if heapMax == "" {
			heapMax = "-"
		} else {
			heapMax += " MB"
		}

		row := fmt.Sprintf("  %s %s %s %s %s %s %s %s",
			styledPad(valueStyle.Render(fmt.Sprintf("%d", p.PID)), 8),
			styledPad(valueStyle.Render(comm), 12),
			styledPad(valueStyle.Render(fmt.Sprintf("%.1f MB", p.GCHeapMB)), 10),
			styledPad(dimStyle.Render(heapMax), 10),
			styledPad(gcStyle.Render(fmt.Sprintf("%.1f%%", p.GCPausePct)), 10),
			styledPad(valueStyle.Render(p.Extra["young_gc_count"]), 10),
			styledPad(valueStyle.Render(p.Extra["full_gc_count"]), 10),
			valueStyle.Render(fmt.Sprintf("%d", p.ThreadCount)))
		sb.WriteString(boxRow(row, iw) + "\n")

		// Second line: classes + working set
		classLoaded := p.Extra["class_loaded"]
		if classLoaded != "" && classLoaded != "0" {
			detail := fmt.Sprintf("    classes=%s  working_set=%.1f MB", classLoaded, p.WorkingSetMB)
			sb.WriteString(boxRow(dimStyle.Render(detail), iw) + "\n")
		}
	}

	sb.WriteString(boxBot(iw) + "\n\n")
	return sb.String()
}

func renderGenericSubTable(procs []model.RuntimeProcessMetrics, iw int) string {
	var sb strings.Builder
	sb.WriteString(boxTop(iw) + "\n")

	hdr := fmt.Sprintf("  %s %s %s %s %s",
		styledPad(dimStyle.Render("PID"), 8),
		styledPad(dimStyle.Render("COMM"), 16),
		styledPad(dimStyle.Render("RSS"), 12),
		styledPad(dimStyle.Render("THREADS"), 10),
		dimStyle.Render("DETAILS"))
	sb.WriteString(boxRow(hdr, iw) + "\n")
	sb.WriteString(boxMid(iw) + "\n")

	for _, p := range procs {
		comm := p.Comm
		if len(comm) > 14 {
			comm = comm[:14]
		}

		// Build details from Extra map
		var details []string
		for _, key := range []string{"framework", "interpreter", "gil_bound", "heap_limit_mb", "inspect_port", "uv_threadpool_size", "gomaxprocs", "gogc", "gomemlimit"} {
			if v, ok := p.Extra[key]; ok && v != "" {
				details = append(details, fmt.Sprintf("%s=%s", key, v))
			}
		}
		detailStr := strings.Join(details, " ")
		if len(detailStr) > 40 {
			detailStr = detailStr[:40]
		}

		row := fmt.Sprintf("  %s %s %s %s %s",
			styledPad(valueStyle.Render(fmt.Sprintf("%d", p.PID)), 8),
			styledPad(valueStyle.Render(comm), 16),
			styledPad(valueStyle.Render(fmt.Sprintf("%.1f MB", p.WorkingSetMB)), 12),
			styledPad(valueStyle.Render(fmt.Sprintf("%d", p.ThreadCount)), 10),
			dimStyle.Render(detailStr))
		sb.WriteString(boxRow(row, iw) + "\n")
	}

	sb.WriteString(boxBot(iw) + "\n\n")
	return sb.String()
}

func renderIntelSLOContent(results []engine.SLOResult, eng *engine.Engine, iw int) string {
	if eng == nil || len(eng.SLOPolicies) == 0 {
		return dimStyle.Render("  No SLO policies configured. Use --slo flag.") + "\n\n"
	}

	var sb strings.Builder
	sb.WriteString(boxTop(iw) + "\n")

	hdr := fmt.Sprintf("  %s %s %s %s %s",
		styledPad(dimStyle.Render("POLICY"), 20),
		styledPad(dimStyle.Render("METRIC"), 12),
		styledPad(dimStyle.Render("THRESHOLD"), 14),
		styledPad(dimStyle.Render("CURRENT"), 12),
		dimStyle.Render("STATUS"))
	sb.WriteString(boxRow(hdr, iw) + "\n")
	sb.WriteString(boxMid(iw) + "\n")

	for _, r := range results {
		badge := okStyle.Render("PASS")
		if !r.Passed {
			badge = critStyle.Render("FAIL")
		}

		threshStr := fmt.Sprintf("%s %.1f%s", r.Policy.Operator, r.Policy.Threshold, r.Policy.Unit)
		curStyle := valueStyle
		if !r.Passed {
			curStyle = critStyle
		}

		row := fmt.Sprintf("  %s %s %s %s %s",
			styledPad(valueStyle.Render(r.Policy.Name), 20),
			styledPad(dimStyle.Render(r.Policy.Metric), 12),
			styledPad(dimStyle.Render(threshStr), 14),
			styledPad(curStyle.Render(fmt.Sprintf("%.1f%s", r.Current, r.Policy.Unit)), 12),
			badge)
		sb.WriteString(boxRow(row, iw) + "\n")
	}

	sb.WriteString(boxBot(iw) + "\n\n")
	return sb.String()
}

func renderIntelAutopilotContent(ap *engine.Autopilot, iw int) string {
	if ap == nil {
		return dimStyle.Render("  Autopilot disabled. Enable in config.") + "\n\n"
	}

	actions := ap.Actions()

	var sb strings.Builder
	// Status line
	status := okStyle.Render("ENABLED")
	countStr := fmt.Sprintf("%d actions taken", len(actions))
	sb.WriteString(fmt.Sprintf("  Status: %s  %s\n", status, dimStyle.Render(countStr)))

	if len(actions) == 0 {
		sb.WriteString(dimStyle.Render("  No actions taken — system operating normally.") + "\n\n")
		return sb.String()
	}

	sb.WriteString(boxTop(iw) + "\n")

	hdr := fmt.Sprintf("  %s %s %s %s %s",
		styledPad(dimStyle.Render("TYPE"), 18),
		styledPad(dimStyle.Render("TARGET"), 16),
		styledPad(dimStyle.Render("OLD"), 16),
		styledPad(dimStyle.Render("NEW"), 16),
		dimStyle.Render("TIME"))
	sb.WriteString(boxRow(hdr, iw) + "\n")
	sb.WriteString(boxMid(iw) + "\n")

	for _, a := range actions {
		target := a.Cgroup
		if a.PID > 0 {
			target = fmt.Sprintf("PID %d", a.PID)
			if a.Comm != "" {
				target += " (" + a.Comm + ")"
			}
		}
		if len(target) > 14 {
			target = target[:14]
		}

		oldVal := a.OldValue
		if len(oldVal) > 14 {
			oldVal = oldVal[:14]
		}
		newVal := a.NewValue
		if len(newVal) > 14 {
			newVal = newVal[:14]
		}

		row := fmt.Sprintf("  %s %s %s %s %s",
			styledPad(valueStyle.Render(string(a.Type)), 18),
			styledPad(warnStyle.Render(target), 16),
			styledPad(dimStyle.Render(oldVal), 16),
			styledPad(valueStyle.Render(newVal), 16),
			dimStyle.Render(a.Timestamp.Format("15:04:05")))
		sb.WriteString(boxRow(row, iw) + "\n")
	}

	sb.WriteString(boxBot(iw) + "\n\n")
	return sb.String()
}

func renderIntelIncidentsContent(incidents []store.IncidentRecord, st *store.Store, iw int) string {
	if st == nil {
		return dimStyle.Render("  No incident database. Run with --daemon to enable.") + "\n\n"
	}
	if len(incidents) == 0 {
		return dimStyle.Render("  No incidents recorded yet.") + "\n\n"
	}

	var sb strings.Builder
	sb.WriteString(boxTop(iw) + "\n")

	hdr := fmt.Sprintf("  %s %s %s %s %s %s",
		styledPad(dimStyle.Render("TIME"), 20),
		styledPad(dimStyle.Render("DURATION"), 10),
		styledPad(dimStyle.Render("BOTTLENECK"), 14),
		styledPad(dimStyle.Render("SCORE"), 8),
		styledPad(dimStyle.Render("CULPRIT"), 16),
		dimStyle.Render("FINGERPRINT"))
	sb.WriteString(boxRow(hdr, iw) + "\n")
	sb.WriteString(boxMid(iw) + "\n")

	for _, inc := range incidents {
		durStr := formatDurationSec(inc.DurationSec)

		scoreStyle := okStyle
		if inc.PeakScore > 70 {
			scoreStyle = critStyle
		} else if inc.PeakScore > 40 {
			scoreStyle = warnStyle
		}

		culprit := inc.CulpritProcess
		if culprit == "" {
			culprit = "-"
		}
		if len(culprit) > 14 {
			culprit = culprit[:14]
		}

		fp := inc.Fingerprint
		if len(fp) > 12 {
			fp = fp[:12]
		}

		bn := inc.Bottleneck
		if len(bn) > 12 {
			bn = bn[:12]
		}

		row := fmt.Sprintf("  %s %s %s %s %s %s",
			styledPad(dimStyle.Render(inc.StartTime.Format("Jan 02 15:04:05")), 20),
			styledPad(dimStyle.Render(durStr), 10),
			styledPad(warnStyle.Render(bn), 14),
			styledPad(scoreStyle.Render(fmt.Sprintf("%d", inc.PeakScore)), 8),
			styledPad(valueStyle.Render(culprit), 16),
			dimStyle.Render(fp))
		sb.WriteString(boxRow(row, iw) + "\n")
	}

	sb.WriteString(boxBot(iw) + "\n\n")
	return sb.String()
}

// ── Helpers ─────────────────────────────────────────────────────────────────

func formatBytes(b uint64) string {
	switch {
	case b >= 1<<30:
		return fmt.Sprintf("%.1f GB", float64(b)/float64(1<<30))
	case b >= 1<<20:
		return fmt.Sprintf("%.1f MB", float64(b)/float64(1<<20))
	case b >= 1<<10:
		return fmt.Sprintf("%.1f KB", float64(b)/float64(1<<10))
	default:
		return fmt.Sprintf("%d B", b)
	}
}

func formatDurationSec(secs int) string {
	if secs < 60 {
		return fmt.Sprintf("%ds", secs)
	}
	if secs < 3600 {
		return fmt.Sprintf("%dm%ds", secs/60, secs%60)
	}
	return fmt.Sprintf("%dh%dm", secs/3600, (secs%3600)/60)
}
