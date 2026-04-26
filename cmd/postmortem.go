package cmd

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/ftahirops/xtop/engine"
	"github.com/ftahirops/xtop/model"
)

// runPostmortem implements `xtop postmortem [id-or-index]` — a rich, ticket-
// shaped report for a single recorded incident. Stitches together:
//
//   - the raw incident record from ~/.xtop/rca-history.jsonl
//   - a timeline (start → peak → resolution) with seasonality info
//   - recurrence stats via FindSimilar
//   - a structured diff vs the last N similar incidents (what's different now)
//   - the best-matching operator runbook (if any live under ~/.xtop/runbooks/)
//
// With no args the subcommand lists recent incidents instead; callers can
// then drill in by incident ID or by "@N" shorthand (1-indexed, newest=@1).
func runPostmortem(args []string) error {
	fs := flag.NewFlagSet("postmortem", flag.ExitOnError)
	var (
		mdOut   = fs.Bool("md", false, "render as markdown (for tickets / PRs)")
		jsonOut = fs.Bool("json", false, "render as a single JSON document")
		limit   = fs.Int("n", 20, "number of incidents to list when no ID is given")
	)
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, `xtop postmortem — structured incident reports

  xtop postmortem                 list recent incidents
  xtop postmortem <incident-id>   full report for one incident
  xtop postmortem @1              shorthand for the most-recent incident
  xtop postmortem @3              the 3rd most-recent
  xtop postmortem <id> --md       markdown output
  xtop postmortem <id> --json     JSON output

Flags:`)
		fs.PrintDefaults()
	}
	// Go's flag.Parse stops at the first non-flag argument, so if the user
	// writes `xtop pm @1 --md`, the `--md` would be treated as positional.
	// Pre-split so flags and positionals are independent.
	var flagArgs, positional []string
	for _, a := range args {
		if strings.HasPrefix(a, "-") {
			flagArgs = append(flagArgs, a)
		} else {
			positional = append(positional, a)
		}
	}
	if err := fs.Parse(flagArgs); err != nil {
		return err
	}

	records, err := loadHistory()
	if err != nil {
		return err
	}
	if len(records) == 0 {
		fmt.Println("No incident history recorded at ~/.xtop/rca-history.jsonl — run xtop for a while and come back.")
		return nil
	}

	target := ""
	if len(positional) > 0 {
		target = positional[0]
	}
	if target == "" {
		return listIncidents(records, *limit)
	}

	rec, err := findIncident(records, target)
	if err != nil {
		return err
	}

	// Extra context: similar past incidents, diff, and a matching runbook.
	similar := findSimilarRecords(records, rec)
	diff := computeRecordDiff(rec, similar)

	// Runbook matching needs an AnalysisResult — synthesize one from the record.
	syn := synthesizeResult(rec)
	lib := engine.NewRunbookLibrary()
	rb := lib.Match(syn)

	report := postmortemReport{
		Incident: rec,
		Similar:  similar,
		Diff:     diff,
		Runbook:  rb,
	}
	if rb != nil {
		full := lib.Lookup(rb.Path)
		if full != nil {
			report.RunbookContent = full.Content
		}
	}

	switch {
	case *jsonOut:
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(report)
	case *mdOut:
		return writeMarkdown(&report)
	default:
		return writeANSI(&report)
	}
}

// ── Types ────────────────────────────────────────────────────────────────────

type postmortemReport struct {
	Incident       *engine.RCAIncident  `json:"incident"`
	Similar        []engine.RCAIncident `json:"similar,omitempty"`
	Diff           *model.IncidentDiff  `json:"diff,omitempty"`
	Runbook        *model.RunbookMatch  `json:"runbook,omitempty"`
	RunbookContent string               `json:"runbook_content,omitempty"`
}

// ── History loading ──────────────────────────────────────────────────────────

func historyPath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".xtop", "rca-history.jsonl")
}

func loadHistory() ([]engine.RCAIncident, error) {
	f, err := os.Open(historyPath())
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("open history: %w", err)
	}
	defer f.Close()

	var out []engine.RCAIncident
	dec := json.NewDecoder(f)
	for dec.More() {
		var r engine.RCAIncident
		if err := dec.Decode(&r); err != nil {
			continue // skip corrupt line
		}
		out = append(out, r)
	}
	// Sort newest first so @1 is always the most recent.
	sort.Slice(out, func(i, j int) bool { return out[i].StartedAt.After(out[j].StartedAt) })
	return out, nil
}

// findIncident resolves an ID or @N shorthand.
func findIncident(records []engine.RCAIncident, target string) (*engine.RCAIncident, error) {
	// @N shorthand (1-indexed, newest first).
	if strings.HasPrefix(target, "@") {
		n, err := strconv.Atoi(target[1:])
		if err != nil || n < 1 {
			return nil, fmt.Errorf("bad shorthand %q — use @1 for newest", target)
		}
		if n > len(records) {
			return nil, fmt.Errorf("only %d incidents in history, @%d is out of range", len(records), n)
		}
		cp := records[n-1]
		return &cp, nil
	}
	// Match by full or prefix ID equality on StartedAt+Signature pair — we
	// don't store an explicit ID, so use a synthetic one (see idFor).
	for i := range records {
		if idFor(&records[i]) == target || strings.HasPrefix(idFor(&records[i]), target) {
			cp := records[i]
			return &cp, nil
		}
	}
	return nil, fmt.Errorf("no incident matched %q; try `xtop postmortem` to list them", target)
}

// idFor builds a stable, human-typeable ID from an incident record. Format:
// YYYYMMDD-HHMM-<first4-of-signature>. Used both for display and for matching.
func idFor(r *engine.RCAIncident) string {
	sigHash := "unknown"
	if r.Signature != "" {
		sh := r.Signature
		// Collapse delimiters into a short slug.
		sh = strings.ReplaceAll(sh, "|", "-")
		sh = strings.ReplaceAll(sh, ",", "")
		sh = strings.ReplaceAll(sh, " ", "")
		if len(sh) > 8 {
			sh = sh[:8]
		}
		sigHash = sh
	}
	return r.StartedAt.UTC().Format("20060102-1504") + "-" + sigHash
}

// ── Listing ──────────────────────────────────────────────────────────────────

func listIncidents(records []engine.RCAIncident, limit int) error {
	if limit <= 0 {
		limit = 20
	}
	if len(records) < limit {
		limit = len(records)
	}
	fmt.Printf("\n  %sxtop postmortem%s — %d most-recent incidents (out of %d recorded)\n\n",
		B, R, limit, len(records))

	headers := []string{"#", "ID", "STARTED", "BOTTLENECK", "SCORE", "DUR", "CULPRIT"}
	widths := []int{3, 22, 19, 14, 5, 8, 20}
	rows := make([][]string, 0, limit)
	for i := 0; i < limit; i++ {
		r := records[i]
		culprit := r.CulpritApp
		if culprit == "" {
			culprit = r.Culprit
		}
		if culprit == "" {
			culprit = "—"
		}
		rows = append(rows, []string{
			fmt.Sprintf("@%d", i+1),
			idFor(&r),
			r.StartedAt.Local().Format("2006-01-02 15:04:05"),
			r.Bottleneck,
			colorByImpact(float64(r.PeakScore)),
			fmtDurationShort(r.DurationSec),
			subcmdTrunc(culprit, 20),
		})
	}
	fmt.Print(renderTable(headers, rows, widths))
	fmt.Println()
	fmt.Printf("  View a full report with: %sxtop postmortem @1%s  (or pass an ID)\n\n", B, R)
	return nil
}

func fmtDurationShort(sec int) string {
	if sec <= 0 {
		return "—"
	}
	if sec < 60 {
		return fmt.Sprintf("%ds", sec)
	}
	if sec < 3600 {
		return fmt.Sprintf("%dm%02ds", sec/60, sec%60)
	}
	return fmt.Sprintf("%dh%02dm", sec/3600, (sec%3600)/60)
}

// ── Similar / diff computation ───────────────────────────────────────────────

func findSimilarRecords(all []engine.RCAIncident, target *engine.RCAIncident) []engine.RCAIncident {
	if target == nil || target.Signature == "" {
		return nil
	}
	var out []engine.RCAIncident
	for _, r := range all {
		if r.Signature == target.Signature && !r.StartedAt.Equal(target.StartedAt) {
			out = append(out, r)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].StartedAt.After(out[j].StartedAt) })
	if len(out) > 10 {
		out = out[:10]
	}
	return out
}

// computeRecordDiff reuses the model.IncidentDiff shape against historical
// records so the postmortem output matches the live UI's "vs history" panel.
func computeRecordDiff(rec *engine.RCAIncident, similar []engine.RCAIncident) *model.IncidentDiff {
	if rec == nil || len(similar) == 0 {
		return nil
	}
	d := &model.IncidentDiff{
		MatchCount:       len(similar),
		CurrentPeakScore: rec.PeakScore,
		CurrentCulprit:   firstNonEmpty(rec.CulpritApp, rec.Culprit),
		CulpritFrequency: make(map[string]int),
	}
	d.LastSeen = similar[0].StartedAt
	d.FirstSeen = similar[len(similar)-1].StartedAt

	scores := make([]int, 0, len(similar))
	durations := make([]int, 0, len(similar))
	refHour := rec.StartedAt.Hour()
	for _, s := range similar {
		scores = append(scores, s.PeakScore)
		if s.DurationSec > 0 {
			durations = append(durations, s.DurationSec)
		}
		c := s.CulpritApp
		if c == "" {
			c = s.Culprit
		}
		if c != "" {
			d.CulpritFrequency[c]++
		}
		if s.StartedAt.Hour() == refHour {
			d.SameHourOfDay++
		}
	}
	d.MaxPeakScore = intsMax(scores)
	d.MedianPeakScore = intsMedian(scores)
	d.MedianDurationSec = intsMedian(durations)
	d.ScoreDeltaFromMedian = d.CurrentPeakScore - d.MedianPeakScore
	for c, n := range d.CulpritFrequency {
		if n > d.TopCulpritCount {
			d.TopCulpritCount, d.TopCulprit = n, c
		}
	}
	if d.CurrentCulprit != "" && d.CurrentCulprit == d.TopCulprit && d.TopCulpritCount >= 2 {
		d.CulpritIsRepeat = true
	}

	// Evidence sets
	curSet := stringSetFromSlice(rec.EvidenceIDs)
	baseSet := make(map[string]bool)
	for _, s := range similar {
		for _, id := range s.EvidenceIDs {
			baseSet[id] = true
		}
	}
	d.NewEvidence = setSubtract(curSet, baseSet)
	d.MissingEvidence = setSubtract(baseSet, curSet)
	return d
}

// synthesizeResult rebuilds a minimal AnalysisResult from a historical record
// so we can reuse the live runbook matcher for post-mortem reports. Only the
// fields the matcher reads are populated.
func synthesizeResult(r *engine.RCAIncident) *model.AnalysisResult {
	ev := make([]model.Evidence, 0, len(r.EvidenceIDs))
	for _, id := range r.EvidenceIDs {
		ev = append(ev, model.Evidence{ID: id, Strength: 0.7})
	}
	return &model.AnalysisResult{
		Health:            model.HealthDegraded,
		PrimaryBottleneck: r.Bottleneck,
		PrimaryScore:      r.PeakScore,
		Confidence:        r.Confidence,
		PrimaryProcess:    r.Culprit,
		PrimaryAppName:    r.CulpritApp,
		RCA: []model.RCAEntry{{
			Bottleneck: r.Bottleneck,
			EvidenceV2: ev,
		}},
	}
}

// ── Rendering ────────────────────────────────────────────────────────────────

func writeANSI(rep *postmortemReport) error {
	r := rep.Incident
	fmt.Println()
	fmt.Printf("  %sxtop postmortem%s — %s\n\n", B, R, idFor(r))

	fmt.Printf("  %sSUMMARY%s\n", B, R)
	fmt.Printf("    %-16s %s\n", "Bottleneck:", r.Bottleneck)
	fmt.Printf("    %-16s %s\n", "Peak Score:", colorByImpact(float64(r.PeakScore)))
	fmt.Printf("    %-16s %d%%\n", "Confidence:", r.Confidence)
	culprit := firstNonEmpty(r.CulpritApp, r.Culprit)
	if culprit != "" {
		fmt.Printf("    %-16s %s\n", "Culprit:", culprit)
	}
	if r.Pattern != "" {
		fmt.Printf("    %-16s %s\n", "Pattern:", r.Pattern)
	}
	if r.Resolution != "" {
		fmt.Printf("    %-16s %s\n", "Resolution:", r.Resolution)
	}
	fmt.Println()

	// Timeline
	fmt.Printf("  %sTIMELINE%s\n", B, R)
	fmt.Printf("    %-16s %s\n", "Started:", r.StartedAt.Local().Format("2006-01-02 15:04:05 MST"))
	if !r.EndedAt.IsZero() {
		fmt.Printf("    %-16s %s\n", "Ended:", r.EndedAt.Local().Format("2006-01-02 15:04:05 MST"))
	}
	if r.DurationSec > 0 {
		fmt.Printf("    %-16s %s\n", "Duration:", fmtDurationShort(r.DurationSec))
	}
	fmt.Printf("    %-16s %s (UTC)\n", "Hour-of-Day:", r.StartedAt.UTC().Format("15:04"))
	fmt.Println()

	// Evidence
	if len(r.Evidence) > 0 || len(r.EvidenceIDs) > 0 {
		fmt.Printf("  %sEVIDENCE AT PEAK%s\n", B, R)
		for _, e := range r.Evidence {
			fmt.Printf("    - %s\n", e)
		}
		if len(r.EvidenceIDs) > 0 {
			fmt.Printf("    %s(firing IDs: %s)%s\n", FCyn, strings.Join(r.EvidenceIDs, ", "), R)
		}
		fmt.Println()
	}
	if r.RootCause != "" {
		fmt.Printf("  %sROOT CAUSE%s\n    %s\n\n", B, R, r.RootCause)
	}

	// Diff vs history
	if rep.Diff != nil {
		renderDiffANSI(rep.Diff, len(rep.Similar))
	}

	// Recent similar — drop-in recurrence view
	if len(rep.Similar) > 0 {
		fmt.Printf("  %sRECENT SIMILAR (%d)%s\n", B, len(rep.Similar), R)
		for i, s := range rep.Similar {
			if i >= 5 {
				fmt.Printf("    … %d more\n", len(rep.Similar)-5)
				break
			}
			culprit := firstNonEmpty(s.CulpritApp, s.Culprit)
			if culprit == "" {
				culprit = "—"
			}
			fmt.Printf("    %s  score=%-3d  dur=%-6s  culprit=%s\n",
				s.StartedAt.Local().Format("01-02 15:04"),
				s.PeakScore, fmtDurationShort(s.DurationSec), culprit)
		}
		fmt.Println()
	}

	// Runbook
	if rep.Runbook != nil {
		fmt.Printf("  %sMATCHING RUNBOOK%s\n", B, R)
		fmt.Printf("    %s %s(score %d)%s\n", rep.Runbook.Name, FCyn, rep.Runbook.Score, R)
		fmt.Printf("    %s\n", rep.Runbook.Path)
		if rep.RunbookContent != "" {
			fmt.Println()
			fmt.Println(indent(rep.RunbookContent, "      "))
		}
		fmt.Println()
	}
	return nil
}

func renderDiffANSI(d *model.IncidentDiff, count int) {
	fmt.Printf("  %sVS HISTORY%s (matched %d past incidents)\n", B, R, count)
	if d.ScoreDeltaFromMedian != 0 {
		var color string
		switch {
		case d.ScoreDeltaFromMedian >= 15:
			color = FBRed
		case d.ScoreDeltaFromMedian <= -15:
			color = FBGrn
		default:
			color = FBYel
		}
		sign := ""
		if d.ScoreDeltaFromMedian > 0 {
			sign = "+"
		}
		fmt.Printf("    %-16s %s%s%d%s pts vs median %d%%\n",
			"Severity:", color, sign, d.ScoreDeltaFromMedian, R, d.MedianPeakScore)
	}
	if d.CulpritIsRepeat {
		fmt.Printf("    %-16s %s (%d/%d incidents)\n",
			"Repeat Culprit:", d.TopCulprit, d.TopCulpritCount, d.MatchCount)
	}
	if len(d.NewEvidence) > 0 {
		fmt.Printf("    %-16s %s\n", "New Signals:", strings.Join(d.NewEvidence, ", "))
	}
	if len(d.MissingEvidence) > 0 {
		fmt.Printf("    %-16s %s\n", "Usually-Firing:", strings.Join(d.MissingEvidence, ", "))
	}
	if d.SameHourOfDay >= 2 && d.MatchCount >= 3 {
		fmt.Printf("    %-16s %d/%d past matches occurred at this hour\n",
			"Time-of-Day:", d.SameHourOfDay, d.MatchCount)
	}
	fmt.Println()
}

func writeMarkdown(rep *postmortemReport) error {
	r := rep.Incident
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("# Post-mortem: %s\n\n", idFor(r)))
	sb.WriteString("## Summary\n\n")
	sb.WriteString(fmt.Sprintf("- **Bottleneck:** %s\n", r.Bottleneck))
	sb.WriteString(fmt.Sprintf("- **Peak score:** %d%%\n", r.PeakScore))
	sb.WriteString(fmt.Sprintf("- **Confidence:** %d%%\n", r.Confidence))
	if culprit := firstNonEmpty(r.CulpritApp, r.Culprit); culprit != "" {
		sb.WriteString(fmt.Sprintf("- **Culprit:** %s\n", culprit))
	}
	if r.Pattern != "" {
		sb.WriteString(fmt.Sprintf("- **Pattern:** %s\n", r.Pattern))
	}
	if r.Resolution != "" {
		sb.WriteString(fmt.Sprintf("- **Resolution:** %s\n", r.Resolution))
	}
	sb.WriteString("\n## Timeline\n\n")
	sb.WriteString(fmt.Sprintf("- Started: `%s`\n", r.StartedAt.Local().Format(time.RFC3339)))
	if !r.EndedAt.IsZero() {
		sb.WriteString(fmt.Sprintf("- Ended: `%s`\n", r.EndedAt.Local().Format(time.RFC3339)))
	}
	if r.DurationSec > 0 {
		sb.WriteString(fmt.Sprintf("- Duration: %s\n", fmtDurationShort(r.DurationSec)))
	}

	if len(r.Evidence) > 0 {
		sb.WriteString("\n## Evidence at peak\n\n")
		for _, e := range r.Evidence {
			sb.WriteString(fmt.Sprintf("- %s\n", e))
		}
	}
	if r.RootCause != "" {
		sb.WriteString(fmt.Sprintf("\n## Root cause\n\n%s\n", r.RootCause))
	}

	if rep.Diff != nil {
		d := rep.Diff
		sb.WriteString(fmt.Sprintf("\n## Vs history (%d prior)\n\n", d.MatchCount))
		if d.ScoreDeltaFromMedian != 0 {
			sign := ""
			if d.ScoreDeltaFromMedian > 0 {
				sign = "+"
			}
			sb.WriteString(fmt.Sprintf("- Severity: **%s%d pts** vs median %d%%\n",
				sign, d.ScoreDeltaFromMedian, d.MedianPeakScore))
		}
		if d.CulpritIsRepeat {
			sb.WriteString(fmt.Sprintf("- Repeat culprit: **%s** (%d/%d)\n",
				d.TopCulprit, d.TopCulpritCount, d.MatchCount))
		}
		if len(d.NewEvidence) > 0 {
			sb.WriteString(fmt.Sprintf("- New signals this time: `%s`\n",
				strings.Join(d.NewEvidence, "`, `")))
		}
		if len(d.MissingEvidence) > 0 {
			sb.WriteString(fmt.Sprintf("- Usually firing but absent: `%s`\n",
				strings.Join(d.MissingEvidence, "`, `")))
		}
		if d.SameHourOfDay >= 2 && d.MatchCount >= 3 {
			sb.WriteString(fmt.Sprintf("- Time-of-day: %d/%d prior matches at this hour\n",
				d.SameHourOfDay, d.MatchCount))
		}
	}

	if rep.Runbook != nil {
		sb.WriteString(fmt.Sprintf("\n## Runbook — %s\n\n", rep.Runbook.Name))
		sb.WriteString(fmt.Sprintf("_Path: `%s` (match score %d)_\n\n",
			rep.Runbook.Path, rep.Runbook.Score))
		if rep.RunbookContent != "" {
			sb.WriteString(rep.RunbookContent)
			sb.WriteString("\n")
		}
	}

	sb.WriteString("\n---\n*Generated by xtop postmortem*\n")
	fmt.Print(sb.String())
	return nil
}

// ── Helpers ──────────────────────────────────────────────────────────────────

func indent(s, prefix string) string {
	var b strings.Builder
	for _, line := range strings.Split(s, "\n") {
		b.WriteString(prefix)
		b.WriteString(line)
		b.WriteString("\n")
	}
	return strings.TrimRight(b.String(), "\n")
}

// firstNonEmpty lives in fleet_view.go — reused here to avoid duplication.

func intsMax(v []int) int {
	m := 0
	for _, x := range v {
		if x > m {
			m = x
		}
	}
	return m
}

func intsMedian(v []int) int {
	if len(v) == 0 {
		return 0
	}
	c := append([]int(nil), v...)
	sort.Ints(c)
	return c[len(c)/2]
}

func stringSetFromSlice(v []string) map[string]bool {
	s := make(map[string]bool, len(v))
	for _, x := range v {
		if x != "" {
			s[x] = true
		}
	}
	return s
}

func setSubtract(a, b map[string]bool) []string {
	var out []string
	for k := range a {
		if !b[k] {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}
