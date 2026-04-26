package cmd

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/ftahirops/xtop/engine"
)

// runBaseline implements `xtop baseline` — manage named "this is normal"
// snapshots of host utilization for later comparison.
//
// Subcommands:
//
//	xtop baseline save   <name>         snapshot current N-day stats
//	xtop baseline list                  show saved baselines
//	xtop baseline compare <name>        diff current stats vs a saved one
//	xtop baseline delete <name>         remove a baseline
//	xtop baseline export <name>         write baseline JSON to stdout (for checking into IaC)
//	xtop baseline import [file]         read a baseline JSON from a file (or stdin)
//
// Baseline files live in ~/.xtop/baselines/<name>.json. They are portable
// JSON — operators can commit them alongside their infra config and copy
// them across hosts when fleet-wide normalization is desired.
func runBaseline(args []string) error {
	if len(args) == 0 {
		return baselineUsage()
	}
	cmd, rest := args[0], args[1:]
	switch cmd {
	case "save":
		return baselineSave(rest)
	case "list", "ls":
		return baselineList(rest)
	case "compare", "cmp", "diff":
		return baselineCompare(rest)
	case "delete", "rm":
		return baselineDelete(rest)
	case "export":
		return baselineExport(rest)
	case "import":
		return baselineImport(rest)
	case "help", "-h", "--help":
		return baselineUsage()
	default:
		fmt.Fprintf(os.Stderr, "xtop baseline: unknown subcommand %q\n\n", cmd)
		return baselineUsage()
	}
}

func baselineUsage() error {
	fmt.Fprintln(os.Stderr, `xtop baseline — save and compare "known-good" utilization snapshots

Baselines capture how a host behaves during a quiet period. Later you can
compare current state to a named baseline after a deploy, config change, or
traffic shift.

Subcommands:
  save    <name>          Snapshot the current N-day stats
  list                    Show saved baselines
  compare <name>          Diff current stats vs a saved baseline
  delete  <name>          Remove a baseline
  export  <name>          Write a baseline to stdout (commit alongside IaC)
  import  [file]          Load a baseline JSON (from file or stdin)

Flags for save / compare:
  --days N                Window of usage-history to summarize (default 7)
  --note "..."            Optional description saved with the baseline

Examples:
  xtop baseline save pre-deploy --note "Quiet Sunday, 4.1.2 branch"
  xtop baseline compare pre-deploy --days 1
  xtop baseline export pre-deploy > pre-deploy.json
  xtop baseline import prod-baseline.json`)
	return nil
}

// ── Storage ──────────────────────────────────────────────────────────────────

type baselineDoc struct {
	Name        string    `json:"name"`
	Note        string    `json:"note,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
	SourceDays  int       `json:"source_days"`
	Minutes     int       `json:"minutes"`
	Coverage    float64   `json:"coverage"`
	WindowStart time.Time `json:"window_start"`
	WindowEnd   time.Time `json:"window_end"`

	CPU       resourceVerdict `json:"cpu"`
	Memory    resourceVerdict `json:"memory"`
	IO        resourceVerdict `json:"io"`
	Load      resourceVerdict `json:"load"`
	NumCPUs   int             `json:"num_cpus,omitempty"`
	MemBytes  uint64          `json:"mem_total_bytes,omitempty"`
}

func baselineDir() string {
	home, _ := os.UserHomeDir()
	d := filepath.Join(home, ".xtop", "baselines")
	_ = os.MkdirAll(d, 0o755)
	return d
}

func baselinePath(name string) (string, error) {
	if name == "" {
		return "", fmt.Errorf("baseline name is required")
	}
	// Guard against path traversal — names must be plain identifiers.
	if strings.ContainsAny(name, "/\\") || name == "." || name == ".." {
		return "", fmt.Errorf("invalid baseline name %q (no slashes or dots)", name)
	}
	return filepath.Join(baselineDir(), name+".json"), nil
}

func loadBaseline(name string) (*baselineDoc, error) {
	path, err := baselinePath(name)
	if err != nil {
		return nil, err
	}
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("baseline %q not found (try `xtop baseline list`)", name)
		}
		return nil, err
	}
	defer f.Close()
	var doc baselineDoc
	if err := json.NewDecoder(f).Decode(&doc); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	return &doc, nil
}

func saveBaseline(doc *baselineDoc) error {
	path, err := baselinePath(doc.Name)
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	f, err := os.Create(tmp)
	if err != nil {
		return err
	}
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	if err := enc.Encode(doc); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	f.Close()
	return os.Rename(tmp, path)
}

// ── Subcommands ──────────────────────────────────────────────────────────────

func baselineSave(args []string) error {
	fs := flag.NewFlagSet("baseline save", flag.ExitOnError)
	days := fs.Int("days", 7, "days of history to summarize")
	note := fs.String("note", "", "optional description")
	_ = fs.Parse(hoistFlags(args))
	name, _ := firstPositional(args)
	if name == "" {
		return fmt.Errorf("usage: xtop baseline save <name> [--days N] [--note \"...\"]")
	}

	rollups, err := loadUsageHistory()
	if err != nil {
		return err
	}
	if len(rollups) == 0 {
		return fmt.Errorf("no usage data in ~/.xtop/usage-history.jsonl — run xtop for a while first")
	}

	cutoff := time.Now().UTC().Add(-time.Duration(*days) * 24 * time.Hour)
	window := filterSince(rollups, cutoff)
	if len(window) == 0 {
		return fmt.Errorf("no rollups within the last %d days", *days)
	}

	// Reuse the cost report's building blocks so "save → compare" is
	// apples-to-apples with `xtop cost`.
	rep := buildCostReport(window, *days)

	doc := &baselineDoc{
		Name:        name,
		Note:        *note,
		CreatedAt:   time.Now().UTC(),
		SourceDays:  *days,
		Minutes:     rep.Minutes,
		Coverage:    rep.Coverage,
		WindowStart: rep.StartedAt,
		WindowEnd:   rep.EndedAt,
		CPU:         rep.CPU,
		Memory:      rep.Memory,
		IO:          rep.IO,
		Load:        rep.Load,
		NumCPUs:     rep.NumCPUs,
		MemBytes:    rep.MemTotalBytes,
	}
	if err := saveBaseline(doc); err != nil {
		return err
	}
	path, _ := baselinePath(name)
	fmt.Printf("Saved baseline %q from %s of data (%.0f%% coverage) → %s\n",
		name, fmtMinutes(doc.Minutes), doc.Coverage*100, path)
	return nil
}

func baselineList(_ []string) error {
	entries, err := os.ReadDir(baselineDir())
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	var docs []*baselineDoc
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		name := strings.TrimSuffix(e.Name(), ".json")
		if doc, err := loadBaseline(name); err == nil {
			docs = append(docs, doc)
		}
	}
	if len(docs) == 0 {
		fmt.Println("No baselines saved yet. Create one with `xtop baseline save <name>`.")
		return nil
	}
	sort.Slice(docs, func(i, j int) bool { return docs[i].CreatedAt.After(docs[j].CreatedAt) })

	fmt.Printf("\n  %sxtop baseline%s — %d saved\n\n", B, R, len(docs))
	headers := []string{"NAME", "CREATED", "WINDOW", "CPU p95/max", "MEM p95/max", "NOTE"}
	widths := []int{22, 19, 8, 14, 14, 30}
	rows := make([][]string, 0, len(docs))
	for _, d := range docs {
		rows = append(rows, []string{
			subcmdTrunc(d.Name, 22),
			d.CreatedAt.Local().Format("2006-01-02 15:04:05"),
			fmt.Sprintf("%dd", d.SourceDays),
			fmt.Sprintf("%.0f%% / %.0f%%", d.CPU.P95Max, d.CPU.MaxMax),
			fmt.Sprintf("%.0f%% / %.0f%%", d.Memory.P95Max, d.Memory.MaxMax),
			subcmdTrunc(d.Note, 30),
		})
	}
	fmt.Print(renderTable(headers, rows, widths))
	fmt.Println()
	return nil
}

func baselineCompare(args []string) error {
	fs := flag.NewFlagSet("baseline compare", flag.ExitOnError)
	days := fs.Int("days", 1, "days of recent history to compare against the baseline")
	jsonOut := fs.Bool("json", false, "JSON output")
	mdOut := fs.Bool("md", false, "markdown output")
	_ = fs.Parse(hoistFlags(args))
	name, _ := firstPositional(args)
	if name == "" {
		return fmt.Errorf("usage: xtop baseline compare <name> [--days N]")
	}

	doc, err := loadBaseline(name)
	if err != nil {
		return err
	}

	rollups, err := loadUsageHistory()
	if err != nil {
		return err
	}
	if len(rollups) == 0 {
		return fmt.Errorf("no usage data to compare against — run xtop for a while first")
	}
	cutoff := time.Now().UTC().Add(-time.Duration(*days) * 24 * time.Hour)
	window := filterSince(rollups, cutoff)
	if len(window) == 0 {
		return fmt.Errorf("no rollups within the last %d days", *days)
	}
	current := buildCostReport(window, *days)

	diffs := compareBaseline(doc, current)

	out := baselineComparison{
		Baseline: doc,
		Current:  current,
		Diffs:    diffs,
		Verdict:  summarizeBaselineVerdict(diffs),
	}
	switch {
	case *jsonOut:
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(out)
	case *mdOut:
		return baselineCompareMD(&out)
	default:
		return baselineCompareANSI(&out)
	}
}

func baselineDelete(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: xtop baseline delete <name>")
	}
	path, err := baselinePath(args[0])
	if err != nil {
		return err
	}
	if err := os.Remove(path); err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("baseline %q not found", args[0])
		}
		return err
	}
	fmt.Printf("Deleted baseline %q\n", args[0])
	return nil
}

func baselineExport(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: xtop baseline export <name>")
	}
	doc, err := loadBaseline(args[0])
	if err != nil {
		return err
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(doc)
}

func baselineImport(args []string) error {
	var src *os.File
	if len(args) == 0 {
		src = os.Stdin
	} else {
		f, err := os.Open(args[0])
		if err != nil {
			return fmt.Errorf("open %s: %w", args[0], err)
		}
		defer f.Close()
		src = f
	}
	var doc baselineDoc
	if err := json.NewDecoder(src).Decode(&doc); err != nil {
		return fmt.Errorf("parse baseline JSON: %w", err)
	}
	if doc.Name == "" {
		return fmt.Errorf("baseline JSON missing `name` field")
	}
	if err := saveBaseline(&doc); err != nil {
		return err
	}
	path, _ := baselinePath(doc.Name)
	fmt.Printf("Imported baseline %q → %s\n", doc.Name, path)
	return nil
}

// ── Comparison ───────────────────────────────────────────────────────────────

type baselineComparison struct {
	Baseline *baselineDoc    `json:"baseline"`
	Current  *costReport     `json:"current"`
	Diffs    []baselineDiff  `json:"diffs"`
	Verdict  string          `json:"verdict"` // "stable" | "degraded" | "improved" | "mixed"
}

// baselineDiff captures the direction and magnitude of a single metric shift.
type baselineDiff struct {
	Metric     string  `json:"metric"`
	BaselineP95 float64 `json:"baseline_p95"`
	CurrentP95  float64 `json:"current_p95"`
	DeltaP95    float64 `json:"delta_p95"`
	DeltaPct    float64 `json:"delta_pct"`
	Direction   string  `json:"direction"` // "up" (higher utilization = worse) or "down"
	Material    bool    `json:"material"`  // true if > ~10 absolute pp OR ≥ 25% relative
}

func compareBaseline(b *baselineDoc, cur *costReport) []baselineDiff {
	out := []baselineDiff{
		cmpDim("cpu",  b.CPU.P95Max,    cur.CPU.P95Max),
		cmpDim("mem",  b.Memory.P95Max, cur.Memory.P95Max),
		cmpDim("io",   b.IO.P95Max,     cur.IO.P95Max),
		cmpDim("load", b.Load.P95Max,   cur.Load.P95Max),
	}
	return out
}

func cmpDim(metric string, baseline, current float64) baselineDiff {
	delta := current - baseline
	pct := 0.0
	if baseline > 0.01 {
		pct = delta / baseline * 100
	}
	direction := "stable"
	if delta > 0.1 {
		direction = "up"
	} else if delta < -0.1 {
		direction = "down"
	}
	material := absf(delta) >= 10 || absf(pct) >= 25
	return baselineDiff{
		Metric:      metric,
		BaselineP95: baseline,
		CurrentP95:  current,
		DeltaP95:    delta,
		DeltaPct:    pct,
		Direction:   direction,
		Material:    material,
	}
}

func summarizeBaselineVerdict(diffs []baselineDiff) string {
	up, down := 0, 0
	for _, d := range diffs {
		if !d.Material {
			continue
		}
		switch d.Direction {
		case "up":
			up++
		case "down":
			down++
		}
	}
	switch {
	case up == 0 && down == 0:
		return "stable"
	case up > 0 && down == 0:
		return "degraded"
	case down > 0 && up == 0:
		return "improved"
	default:
		return "mixed"
	}
}

// ── Rendering ────────────────────────────────────────────────────────────────

func baselineCompareANSI(c *baselineComparison) error {
	fmt.Println()
	fmt.Printf("  %sxtop baseline compare%s — %q\n\n", B, R, c.Baseline.Name)

	fmt.Printf("  %sBASELINE%s    saved %s (%s of %dd data)\n",
		B, R,
		c.Baseline.CreatedAt.Local().Format("2006-01-02 15:04"),
		fmtMinutes(c.Baseline.Minutes),
		c.Baseline.SourceDays)
	if c.Baseline.Note != "" {
		fmt.Printf("              %s\n", c.Baseline.Note)
	}
	fmt.Printf("  %sCURRENT%s     last %dd (%s of %dm samples)\n",
		B, R, c.Current.WindowDays, fmtMinutes(c.Current.Minutes), c.Current.Minutes)
	fmt.Printf("  %sVERDICT%s     %s\n\n", B, R, colorVerdict(c.Verdict))

	fmt.Printf("  %-8s %-12s %-12s %-12s %s\n", "", "baseline", "current", "delta", "flag")
	for _, d := range c.Diffs {
		flag := " "
		if d.Material {
			flag = "*"
		}
		fmt.Printf("  %-8s %-12s %-12s %s  %s\n",
			strings.ToUpper(d.Metric)+" p95",
			fmtMetric(d.Metric, d.BaselineP95),
			fmtMetric(d.Metric, d.CurrentP95),
			colorDelta(d),
			flag)
	}
	fmt.Println()
	if c.Verdict == "degraded" {
		fmt.Printf("  %s* marked metrics moved materially (>=10 pp or >=25%% relative)%s\n\n", FBYel, R)
	}
	return nil
}

func baselineCompareMD(c *baselineComparison) error {
	var sb strings.Builder
	fmt.Fprintf(&sb, "# Baseline comparison — `%s`\n\n", c.Baseline.Name)
	fmt.Fprintf(&sb, "- Baseline saved: %s (%dd source window, %s of samples)\n",
		c.Baseline.CreatedAt.Format(time.RFC3339),
		c.Baseline.SourceDays, fmtMinutes(c.Baseline.Minutes))
	if c.Baseline.Note != "" {
		fmt.Fprintf(&sb, "- Baseline note: %s\n", c.Baseline.Note)
	}
	fmt.Fprintf(&sb, "- Current window: last %d day(s), %s of samples\n",
		c.Current.WindowDays, fmtMinutes(c.Current.Minutes))
	fmt.Fprintf(&sb, "- **Verdict: %s**\n\n", c.Verdict)

	sb.WriteString("| metric | baseline | current | delta | material |\n")
	sb.WriteString("|--------|----------|---------|-------|----------|\n")
	for _, d := range c.Diffs {
		mark := ""
		if d.Material {
			mark = "**yes**"
		}
		fmt.Fprintf(&sb, "| %s p95 | %s | %s | %+.1f (%+.0f%%) | %s |\n",
			strings.ToUpper(d.Metric),
			fmtMetricMD(d.Metric, d.BaselineP95),
			fmtMetricMD(d.Metric, d.CurrentP95),
			d.DeltaP95, d.DeltaPct, mark)
	}
	sb.WriteString("\n---\n*Generated by `xtop baseline compare`*\n")
	fmt.Print(sb.String())
	return nil
}

// ── Formatting ───────────────────────────────────────────────────────────────

func fmtMetric(metric string, v float64) string {
	if metric == "load" {
		return fmt.Sprintf("%.2f", v)
	}
	return fmt.Sprintf("%.0f%%", v)
}

func fmtMetricMD(metric string, v float64) string {
	if metric == "load" {
		return fmt.Sprintf("%.2f", v)
	}
	return fmt.Sprintf("%.0f%%", v)
}

func colorDelta(d baselineDiff) string {
	sign := ""
	if d.DeltaP95 > 0 {
		sign = "+"
	}
	valueStr := ""
	if d.Metric == "load" {
		valueStr = fmt.Sprintf("%s%.2f (%+.0f%%)", sign, d.DeltaP95, d.DeltaPct)
	} else {
		valueStr = fmt.Sprintf("%s%.1fpp (%+.0f%%)", sign, d.DeltaP95, d.DeltaPct)
	}
	// In our convention, "up" means higher utilization — bad.
	if !d.Material {
		return fmt.Sprintf("%s%-12s%s", FDim, valueStr, R)
	}
	switch d.Direction {
	case "up":
		return fmt.Sprintf("%s%s%-12s%s", B, FBRed, valueStr, R)
	case "down":
		return fmt.Sprintf("%s%-12s%s", FBGrn, valueStr, R)
	default:
		return fmt.Sprintf("%-12s", valueStr)
	}
}

func colorVerdict(v string) string {
	switch v {
	case "degraded":
		return fmt.Sprintf("%s%s DEGRADED %s", B, BRed, R)
	case "improved":
		return fmt.Sprintf("%s%s IMPROVED %s", B, FBGrn, R)
	case "mixed":
		return fmt.Sprintf("%s MIXED %s", FBYel, R)
	case "stable":
		return fmt.Sprintf("%s STABLE %s", FBCyn, R)
	}
	return v
}

// ── Small helpers ────────────────────────────────────────────────────────────

func absf(v float64) float64 {
	if v < 0 {
		return -v
	}
	return v
}

// hoistFlags returns a copy of args with positional values removed — used so
// `flag.Parse` works regardless of order (`save <name> --days 7` and
// `save --days 7 <name>` are both accepted).
func hoistFlags(args []string) []string {
	out := make([]string, 0, len(args))
	skip := false
	for _, a := range args {
		if skip {
			out = append(out, a)
			skip = false
			continue
		}
		if strings.HasPrefix(a, "-") {
			out = append(out, a)
			if !strings.Contains(a, "=") {
				skip = true
			}
		}
	}
	return out
}

func firstPositional(args []string) (string, bool) {
	skip := false
	for _, a := range args {
		if skip {
			skip = false
			continue
		}
		if strings.HasPrefix(a, "-") {
			if !strings.Contains(a, "=") {
				skip = true
			}
			continue
		}
		return a, true
	}
	return "", false
}

// FDim constant used by colorDelta — our other subcommands define this too;
// we duplicate here only if it isn't already in scope. Go catches duplicate
// definitions at compile time, so the build fails fast if we collide.
const FDim = "\033[2m"

// Variable used by engine to silence "imported and not used"; keeps the
// import intentional (we pull in engine for UsageRollup/UsageStat types via
// cost.go, not this file).
var _ = engine.UsageStat{}
