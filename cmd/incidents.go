package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/ftahirops/xtop/store"
)

// runIncidents implements the `xtop incidents` subcommand.
func runIncidents(args []string) error {
	limit := 20
	fpFilter := ""
	jsonOut := false

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "-n":
			if i+1 < len(args) {
				i++
				fmt.Sscanf(args[i], "%d", &limit)
			}
		case "--fingerprint":
			if i+1 < len(args) {
				i++
				fpFilter = args[i]
			}
		case "--json":
			jsonOut = true
		}
	}

	dbPath := incidentDBPath()
	st, err := store.Open(dbPath)
	if err != nil {
		return fmt.Errorf("cannot open incident database: %w\n(has the daemon been run?)", err)
	}
	defer st.Close()

	var records []store.IncidentRecord
	if fpFilter != "" {
		records, err = st.ListByFingerprint(fpFilter)
	} else {
		records, err = st.ListIncidents(limit, 0)
	}
	if err != nil {
		return fmt.Errorf("query incidents: %w", err)
	}

	if len(records) == 0 {
		fmt.Println("No incidents recorded.")
		return nil
	}

	if jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(records)
	}

	// ANSI table
	fmt.Printf("\n  %sxtop incidents%s — %d records\n\n", B, R, len(records))

	headers := []string{"ID", "TIME", "HEALTH", "BOTTLENECK", "SCORE", "CULPRIT", "DURATION", "FP"}
	widths := []int{20, 19, 10, 20, 5, 16, 8, 16}
	rows := make([][]string, 0, len(records))

	for _, r := range records {
		healthStr := r.PeakHealth
		switch r.PeakHealth {
		case "CRITICAL":
			healthStr = FBRed + r.PeakHealth + R
		case "DEGRADED":
			healthStr = FBYel + r.PeakHealth + R
		}
		dur := "-"
		if r.DurationSec > 0 {
			dur = fmt.Sprintf("%ds", r.DurationSec)
		}
		rows = append(rows, []string{
			subcmdTrunc(r.ID, 20),
			r.StartTime.Format("01-02 15:04:05"),
			healthStr,
			subcmdTrunc(r.Bottleneck, 20),
			fmt.Sprintf("%d", r.PeakScore),
			subcmdTrunc(r.CulpritProcess, 16),
			dur,
			r.Fingerprint,
		})
	}

	fmt.Print(renderTable(headers, rows, widths))
	fmt.Println()
	return nil
}

// runIncident implements the `xtop incident <id>` subcommand.
func runIncident(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: xtop incident <id> [--json] [--md]")
	}

	id := args[0]
	jsonOut := false
	mdOut := false
	for i := 1; i < len(args); i++ {
		switch args[i] {
		case "--json":
			jsonOut = true
		case "--md":
			mdOut = true
		}
	}

	dbPath := incidentDBPath()
	st, err := store.Open(dbPath)
	if err != nil {
		return fmt.Errorf("cannot open incident database: %w", err)
	}
	defer st.Close()

	rec, err := st.GetIncident(id)
	if err != nil {
		return fmt.Errorf("incident %q not found: %w", id, err)
	}

	offenders, _ := st.GetOffenders(id)

	// Fingerprint info
	fpInfo, _ := st.GetFingerprint(rec.Fingerprint)

	if jsonOut {
		data := map[string]interface{}{
			"incident":  rec,
			"offenders": offenders,
		}
		if fpInfo != nil {
			data["fingerprint"] = fpInfo
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(data)
	}

	if mdOut {
		return incidentMarkdown(rec, offenders, fpInfo)
	}

	return incidentANSI(rec, offenders, fpInfo)
}

// incidentANSI renders a full incident report with ANSI colors.
func incidentANSI(rec *store.IncidentRecord, offenders []store.IncidentOffender, fp *store.Fingerprint) error {
	fmt.Println()
	fmt.Printf("  %sxtop incident%s — %s\n\n", B, R, rec.ID)

	healthStr := rec.PeakHealth
	switch rec.PeakHealth {
	case "CRITICAL":
		healthStr = fmt.Sprintf("%s%s CRITICAL %s", B, BRed, R)
	case "DEGRADED":
		healthStr = fmt.Sprintf("%s%s DEGRADED %s", B, FBYel, R)
	}

	fmt.Printf("  %sSUMMARY%s\n", B, R)
	fmt.Printf("    %-16s %s\n", "Health:", healthStr)
	fmt.Printf("    %-16s %s\n", "Bottleneck:", rec.Bottleneck)
	fmt.Printf("    %-16s %d\n", "Peak Score:", rec.PeakScore)
	fmt.Printf("    %-16s %s\n", "Started:", rec.StartTime.Format("2006-01-02 15:04:05"))
	if !rec.EndTime.IsZero() {
		fmt.Printf("    %-16s %s (%ds)\n", "Ended:", rec.EndTime.Format("2006-01-02 15:04:05"), rec.DurationSec)
	} else {
		fmt.Printf("    %-16s %sactive%s\n", "Status:", FBRed, R)
	}
	if rec.CulpritProcess != "" {
		fmt.Printf("    %-16s %s (PID %d)\n", "Culprit:", rec.CulpritProcess, rec.CulpritPID)
	}
	if rec.CausalChain != "" {
		fmt.Printf("    %-16s %s\n", "Causal Chain:", rec.CausalChain)
	}
	fmt.Printf("    %-16s CPU=%.1f%% Mem=%.1f%% IO_PSI=%.1f%%\n",
		"Peak Metrics:", rec.PeakCPU, rec.PeakMem, rec.PeakIOPSI)
	fmt.Printf("    %-16s %s\n", "Fingerprint:", rec.Fingerprint)
	fmt.Println()

	// Fingerprint history
	if fp != nil && fp.Count > 1 {
		fmt.Printf("  %sFINGERPRINT HISTORY%s\n", B, R)
		fmt.Printf("    This pattern has occurred %s%d times%s\n", FBYel, fp.Count, R)
		fmt.Printf("    First seen: %s  Last seen: %s\n",
			fp.FirstSeen.Format("Jan 02 15:04"), fp.LastSeen.Format("Jan 02 15:04"))
		fmt.Printf("    Avg duration: %ds\n", fp.AvgDuration)
		fmt.Println()
	}

	// Offenders
	if len(offenders) > 0 {
		fmt.Printf("  %sOFFENDERS%s\n", B, R)
		for _, o := range offenders {
			svc := o.Comm
			if o.Service != "" {
				svc = o.Service
			}
			fmt.Printf("    PID=%-6d %-16s  impact=%s  CPU=%.1f%%  Mem=%s  IO=%.1fM/s\n",
				o.PID, subcmdTrunc(svc, 16), colorByImpact(o.ImpactScore),
				o.CPUPct, subcmdFmtBytes(o.MemBytes), o.IOMBps)
		}
		fmt.Println()
	}

	// Evidence
	if rec.EvidenceJSON != "" {
		var evidence []string
		if json.Unmarshal([]byte(rec.EvidenceJSON), &evidence) == nil && len(evidence) > 0 {
			fmt.Printf("  %sEVIDENCE%s\n", B, R)
			for _, e := range evidence {
				fmt.Printf("    - %s\n", e)
			}
			fmt.Println()
		}
	}

	return nil
}

// incidentMarkdown renders the incident as Markdown.
func incidentMarkdown(rec *store.IncidentRecord, offenders []store.IncidentOffender, fp *store.Fingerprint) error {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("# Incident %s\n\n", rec.ID))
	sb.WriteString(fmt.Sprintf("**Health:** %s  **Score:** %d\n", rec.PeakHealth, rec.PeakScore))
	sb.WriteString(fmt.Sprintf("**Bottleneck:** %s\n", rec.Bottleneck))
	sb.WriteString(fmt.Sprintf("**Time:** %s", rec.StartTime.Format("2006-01-02 15:04:05")))
	if !rec.EndTime.IsZero() {
		sb.WriteString(fmt.Sprintf(" → %s (%ds)\n", rec.EndTime.Format("15:04:05"), rec.DurationSec))
	} else {
		sb.WriteString(" (active)\n")
	}
	if rec.CulpritProcess != "" {
		sb.WriteString(fmt.Sprintf("**Culprit:** %s (PID %d)\n", rec.CulpritProcess, rec.CulpritPID))
	}
	sb.WriteString(fmt.Sprintf("**Fingerprint:** `%s`\n\n", rec.Fingerprint))

	if fp != nil && fp.Count > 1 {
		sb.WriteString(fmt.Sprintf("## Pattern History\n\nThis pattern has occurred **%d times**. Avg duration: %ds.\n\n", fp.Count, fp.AvgDuration))
	}

	if len(offenders) > 0 {
		sb.WriteString("## Offenders\n\n| PID | Process | Impact | CPU% | Mem | IO |\n|-----|---------|--------|------|-----|----|\n")
		for _, o := range offenders {
			sb.WriteString(fmt.Sprintf("| %d | %s | %.1f | %.1f%% | %s | %.1fM/s |\n",
				o.PID, o.Comm, o.ImpactScore, o.CPUPct, subcmdFmtBytes(o.MemBytes), o.IOMBps))
		}
	}

	sb.WriteString("\n---\n*Generated by xtop*\n")
	fmt.Print(sb.String())
	return nil
}

// incidentDBPath returns the path to the incidents database.
func incidentDBPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return "/tmp/xtop-incidents.db"
	}
	return filepath.Join(home, ".xtop", "incidents.db")
}
