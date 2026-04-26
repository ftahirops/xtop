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

// runCost implements `xtop cost` — a VM right-sizing report.
//
// Reads per-minute utilization rollups from ~/.xtop/usage-history.jsonl,
// computes p50/p95/max over the requested window (default: 7 days), and
// produces conservative upsize/downsize hints. Pricing numbers are stated
// as relative percentages rather than dollar amounts — xtop doesn't know
// the operator's cloud provider or reserved-instance terms.
//
// Safety: downsize hints only fire with ≥ 72 h of data and leave ≥ 40 %
// headroom above observed p95. Upsize hints fire when p95 > 70 % OR max > 90 %
// so noisy-neighbour VMs aren't mistaken for genuine saturation.
func runCost(args []string) error {
	fs := flag.NewFlagSet("cost", flag.ExitOnError)
	var (
		days    = fs.Int("days", 7, "days of history to analyze")
		jsonOut = fs.Bool("json", false, "machine-readable JSON output")
		mdOut   = fs.Bool("md", false, "markdown output (for tickets)")
	)
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, `xtop cost — VM right-sizing report

Analyzes per-minute CPU/memory/IO utilization collected by xtop over the last
N days and recommends a conservative right-size action. Data lives in
~/.xtop/usage-history.jsonl and accumulates automatically while xtop runs.

Usage:
  xtop cost              # 7-day report, ANSI
  xtop cost --days 30    # monthly report
  xtop cost --md         # markdown for tickets

Flags:`)
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}

	rollups, err := loadUsageHistory()
	if err != nil {
		return err
	}
	if len(rollups) == 0 {
		fmt.Println("No usage data yet — run xtop for a few hours and come back.")
		fmt.Println("(Looking at ~/.xtop/usage-history.jsonl)")
		return nil
	}

	cutoff := time.Now().UTC().Add(-time.Duration(*days) * 24 * time.Hour)
	windowed := filterSince(rollups, cutoff)
	if len(windowed) == 0 {
		fmt.Printf("No data inside the last %d days.\n", *days)
		return nil
	}

	rep := buildCostReport(windowed, *days)

	switch {
	case *jsonOut:
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(rep)
	case *mdOut:
		return writeCostMarkdown(rep)
	default:
		return writeCostANSI(rep)
	}
}

// ── Data types ───────────────────────────────────────────────────────────────

// costReport is the rendered form — everything the ANSI/markdown/JSON writers
// need without further computation.
type costReport struct {
	WindowDays    int              `json:"window_days"`
	SamplesPerDay float64          `json:"samples_per_day"`
	Minutes       int              `json:"minutes"`
	StartedAt     time.Time        `json:"started_at"`
	EndedAt       time.Time        `json:"ended_at"`
	Coverage      float64          `json:"coverage_ratio"` // 0..1 of expected minutes
	CPU           resourceVerdict  `json:"cpu"`
	Memory        resourceVerdict  `json:"memory"`
	IO            resourceVerdict  `json:"io"`
	Load          resourceVerdict  `json:"load"`
	NumCPUs       int              `json:"num_cpus,omitempty"`
	MemTotalBytes uint64           `json:"mem_total_bytes,omitempty"`
	Action        string           `json:"action"`   // "downsize", "upsize", "hold", "insufficient_data"
	Reasoning     []string         `json:"reasoning"`
	Savings       *savingsEstimate `json:"savings,omitempty"`
}

// resourceVerdict summarizes one dimension: observed utilization + a verdict.
type resourceVerdict struct {
	// Stats computed from the per-minute rollups over the window:
	//   P50Max — median of per-minute MAX values (typical peak-minute)
	//   P95Max — 95th percentile of per-minute MAX values (rare peak-minute)
	//   MaxMax — absolute max (the single worst minute)
	//   AvgAvg — avg of per-minute averages (overall utilization)
	P50Max float64 `json:"p50_max"`
	P95Max float64 `json:"p95_max"`
	MaxMax float64 `json:"max_max"`
	AvgAvg float64 `json:"avg_avg"`
	State  string  `json:"state"` // "hot", "warm", "cold", "idle"
}

type savingsEstimate struct {
	FromTier     string `json:"from_tier"`     // e.g. "8 vCPU"
	ToTier       string `json:"to_tier"`       // e.g. "4 vCPU"
	Dimension    string `json:"dimension"`     // "cpu" | "memory"
	PercentSaved int    `json:"percent_saved"` // relative compute cost reduction
	Rationale    string `json:"rationale"`
}

// ── Loading ──────────────────────────────────────────────────────────────────

func loadUsageHistory() ([]engine.UsageRollup, error) {
	home, _ := os.UserHomeDir()
	path := filepath.Join(home, ".xtop", "usage-history.jsonl")
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	defer f.Close()

	var out []engine.UsageRollup
	dec := json.NewDecoder(f)
	for dec.More() {
		var u engine.UsageRollup
		if err := dec.Decode(&u); err != nil {
			continue
		}
		out = append(out, u)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Minute.Before(out[j].Minute) })
	return out, nil
}

func filterSince(rs []engine.UsageRollup, t time.Time) []engine.UsageRollup {
	out := rs[:0:len(rs)]
	for _, r := range rs {
		if r.Minute.After(t) {
			out = append(out, r)
		}
	}
	return out
}

// ── Report building ──────────────────────────────────────────────────────────

func buildCostReport(rs []engine.UsageRollup, days int) *costReport {
	rep := &costReport{
		WindowDays: days,
		Minutes:    len(rs),
		StartedAt:  rs[0].Minute,
		EndedAt:    rs[len(rs)-1].Minute,
	}
	if days > 0 {
		rep.SamplesPerDay = float64(rep.Minutes) / float64(days)
		expected := float64(days) * 24 * 60
		if expected > 0 {
			rep.Coverage = float64(rep.Minutes) / expected
			if rep.Coverage > 1 {
				rep.Coverage = 1
			}
		}
	}

	// Pull series — per-minute max/p95/avg for each dimension.
	cpuMax := series(rs, func(u engine.UsageRollup) float64 { return u.CPU.Max })
	memMax := series(rs, func(u engine.UsageRollup) float64 { return u.Mem.Max })
	ioMax := series(rs, func(u engine.UsageRollup) float64 { return u.IO.Max })
	loadMax := series(rs, func(u engine.UsageRollup) float64 { return u.LoadRatio.Max })

	cpuAvg := series(rs, func(u engine.UsageRollup) float64 { return u.CPU.Avg })
	memAvg := series(rs, func(u engine.UsageRollup) float64 { return u.Mem.Avg })
	ioAvg := series(rs, func(u engine.UsageRollup) float64 { return u.IO.Avg })
	loadAvg := series(rs, func(u engine.UsageRollup) float64 { return u.LoadRatio.Avg })

	rep.CPU = verdict(cpuMax, cpuAvg, 30, 70, 90)
	rep.Memory = verdict(memMax, memAvg, 40, 75, 95)
	rep.IO = verdict(ioMax, ioAvg, 20, 60, 85)
	rep.Load = verdict(loadMax, loadAvg, 0.5, 1.0, 1.5)

	// Capture latest node size for recommendations.
	last := rs[len(rs)-1]
	rep.NumCPUs = last.NumCPUs
	rep.MemTotalBytes = last.MemTotal

	// Decide on an action + reasoning.
	decideAction(rep)
	return rep
}

func series(rs []engine.UsageRollup, pick func(engine.UsageRollup) float64) []float64 {
	out := make([]float64, len(rs))
	for i, r := range rs {
		out[i] = pick(r)
	}
	return out
}

func verdict(maxes, avgs []float64, coldLimit, warmLimit, hotLimit float64) resourceVerdict {
	sorted := append([]float64(nil), maxes...)
	sort.Float64s(sorted)
	avgSum := 0.0
	for _, v := range avgs {
		avgSum += v
	}
	v := resourceVerdict{
		P50Max: pickPercentile(sorted, 0.50),
		P95Max: pickPercentile(sorted, 0.95),
		MaxMax: pickPercentile(sorted, 1.00),
		AvgAvg: avgSum / float64(len(avgs)),
	}
	switch {
	case v.MaxMax >= hotLimit || v.P95Max >= warmLimit:
		v.State = "hot"
	case v.P95Max >= coldLimit:
		v.State = "warm"
	case v.P95Max >= coldLimit/2:
		v.State = "cold"
	default:
		v.State = "idle"
	}
	return v
}

func pickPercentile(sorted []float64, p float64) float64 {
	if len(sorted) == 0 {
		return 0
	}
	if p >= 1 {
		return sorted[len(sorted)-1]
	}
	if p <= 0 {
		return sorted[0]
	}
	rank := int(float64(len(sorted))*p+0.5) - 1
	if rank < 0 {
		rank = 0
	}
	if rank >= len(sorted) {
		rank = len(sorted) - 1
	}
	return sorted[rank]
}

// decideAction walks the verdicts and fills in rep.Action, rep.Reasoning, and
// optionally rep.Savings. Conservative: only recommends a downsize with at
// least 72 h of data AND a large margin over the observed p95.
func decideAction(rep *costReport) {
	// Enough data?
	if rep.Minutes < 60*72 {
		rep.Action = "insufficient_data"
		rep.Reasoning = append(rep.Reasoning,
			fmt.Sprintf("Only %s of data collected — recommendations need ≥ 72 h.",
				fmtMinutes(rep.Minutes)))
		return
	}

	// Any saturation → upsize wins regardless of other dimensions.
	switch {
	case rep.CPU.State == "hot":
		rep.Action = "upsize"
		rep.Reasoning = append(rep.Reasoning,
			fmt.Sprintf("CPU peak minutes hit %.0f %% (p95 max %.0f %%) — node is CPU-saturated.",
				rep.CPU.MaxMax, rep.CPU.P95Max))
		if rep.NumCPUs > 0 {
			rep.Savings = &savingsEstimate{
				Dimension: "cpu",
				FromTier:  fmt.Sprintf("%d vCPU", rep.NumCPUs),
				ToTier:    fmt.Sprintf("%d vCPU", rep.NumCPUs*2),
				Rationale: "Doubling CPU halves saturation; revisit after 7 days of new data.",
			}
		}
	case rep.Memory.State == "hot":
		rep.Action = "upsize"
		rep.Reasoning = append(rep.Reasoning,
			fmt.Sprintf("Memory p95 max %.0f %% (peak %.0f %%) — swap/reclaim risk imminent.",
				rep.Memory.P95Max, rep.Memory.MaxMax))
	case rep.Load.State == "hot":
		rep.Action = "upsize"
		rep.Reasoning = append(rep.Reasoning,
			fmt.Sprintf("Run-queue ratio peaked at %.2fx — CPU-bound workload.", rep.Load.MaxMax))
	}

	if rep.Action != "" {
		return
	}

	// Downsize candidates — both CPU and memory must be comfortable.
	comfortableCPU := rep.CPU.P95Max < 35 && rep.CPU.MaxMax < 60
	comfortableMem := rep.Memory.P95Max < 45 && rep.Memory.MaxMax < 70

	if comfortableCPU && comfortableMem && rep.NumCPUs >= 2 {
		rep.Action = "downsize"
		newCPU := rep.NumCPUs / 2
		if newCPU < 1 {
			newCPU = 1
		}
		rep.Reasoning = append(rep.Reasoning,
			fmt.Sprintf("CPU: p95 max %.0f %% / peak %.0f %% — headroom above 40 %% is ample.",
				rep.CPU.P95Max, rep.CPU.MaxMax))
		rep.Reasoning = append(rep.Reasoning,
			fmt.Sprintf("Memory: p95 max %.0f %% / peak %.0f %% — fits comfortably after a downsize.",
				rep.Memory.P95Max, rep.Memory.MaxMax))
		rep.Savings = &savingsEstimate{
			Dimension:    "cpu",
			FromTier:     fmt.Sprintf("%d vCPU", rep.NumCPUs),
			ToTier:       fmt.Sprintf("%d vCPU", newCPU),
			PercentSaved: 50,
			Rationale:    "Halving vCPUs typically halves compute cost; physical memory often drops proportionally on cloud instance families.",
		}
		return
	}

	// Narrow downsize — memory way over-provisioned, CPU fine.
	if comfortableMem && rep.Memory.P95Max < 25 && rep.Memory.MaxMax < 50 && rep.MemTotalBytes > 8*1024*1024*1024 {
		rep.Action = "downsize"
		rep.Reasoning = append(rep.Reasoning,
			fmt.Sprintf("Memory p95 max %.0f %% / peak %.0f %% — lots of idle RAM.",
				rep.Memory.P95Max, rep.Memory.MaxMax))
		rep.Savings = &savingsEstimate{
			Dimension:    "memory",
			FromTier:     fmtBytesShort(rep.MemTotalBytes),
			ToTier:       fmtBytesShort(rep.MemTotalBytes / 2),
			PercentSaved: 25,
			Rationale:    "Memory-heavy instance families carry a noticeable premium; consider a balanced size.",
		}
		return
	}

	rep.Action = "hold"
	rep.Reasoning = append(rep.Reasoning, "Utilization is within a healthy range; current sizing looks right.")
}

// ── Rendering ────────────────────────────────────────────────────────────────

func writeCostANSI(rep *costReport) error {
	fmt.Println()
	fmt.Printf("  %sxtop cost%s — %d-day right-sizing report\n\n", B, R, rep.WindowDays)

	fmt.Printf("  %sCOVERAGE%s\n", B, R)
	fmt.Printf("    %-16s %d minutes (%s of data)\n",
		"Samples:", rep.Minutes, fmtMinutes(rep.Minutes))
	fmt.Printf("    %-16s %s → %s\n",
		"Range:", rep.StartedAt.Local().Format("2006-01-02 15:04"),
		rep.EndedAt.Local().Format("2006-01-02 15:04"))
	fmt.Printf("    %-16s %.1f %% of expected minutes\n", "Coverage:", rep.Coverage*100)
	if rep.NumCPUs > 0 {
		fmt.Printf("    %-16s %d vCPU · %s RAM\n",
			"Current size:", rep.NumCPUs, fmtBytesShort(rep.MemTotalBytes))
	}
	fmt.Println()

	fmt.Printf("  %sUTILIZATION%s\n", B, R)
	fmt.Printf("    %-10s %-7s %-10s %-10s %-10s %s\n",
		"", "state", "p50 max", "p95 max", "peak", "avg")
	fmt.Printf("    %-10s %s %s %s %s %s\n",
		"CPU %", colorState(rep.CPU.State),
		fmtPctPadded(rep.CPU.P50Max), fmtPctPadded(rep.CPU.P95Max),
		fmtPctPadded(rep.CPU.MaxMax), fmtPctPadded(rep.CPU.AvgAvg))
	fmt.Printf("    %-10s %s %s %s %s %s\n",
		"Mem %", colorState(rep.Memory.State),
		fmtPctPadded(rep.Memory.P50Max), fmtPctPadded(rep.Memory.P95Max),
		fmtPctPadded(rep.Memory.MaxMax), fmtPctPadded(rep.Memory.AvgAvg))
	fmt.Printf("    %-10s %s %s %s %s %s\n",
		"IO %", colorState(rep.IO.State),
		fmtPctPadded(rep.IO.P50Max), fmtPctPadded(rep.IO.P95Max),
		fmtPctPadded(rep.IO.MaxMax), fmtPctPadded(rep.IO.AvgAvg))
	fmt.Printf("    %-10s %s %-10s %-10s %-10s %s\n",
		"Load/CPU", colorState(rep.Load.State),
		fmtFloat(rep.Load.P50Max), fmtFloat(rep.Load.P95Max),
		fmtFloat(rep.Load.MaxMax), fmtFloat(rep.Load.AvgAvg))
	fmt.Println()

	fmt.Printf("  %sRECOMMENDATION%s  %s\n", B, R, colorAction(rep.Action))
	for _, r := range rep.Reasoning {
		fmt.Printf("    - %s\n", r)
	}
	if rep.Savings != nil {
		fmt.Println()
		fmt.Printf("    %s%s → %s%s", B, rep.Savings.FromTier, rep.Savings.ToTier, R)
		if rep.Savings.PercentSaved > 0 {
			fmt.Printf(" (~%d %% compute cost)", rep.Savings.PercentSaved)
		}
		fmt.Println()
		if rep.Savings.Rationale != "" {
			fmt.Printf("    %s%s%s\n", FCyn, rep.Savings.Rationale, R)
		}
	}
	fmt.Println()
	return nil
}

func writeCostMarkdown(rep *costReport) error {
	var sb strings.Builder
	fmt.Fprintf(&sb, "# xtop cost report — %d-day window\n\n", rep.WindowDays)
	fmt.Fprintf(&sb, "- Samples: %d minutes (%s) · coverage %.1f%%\n",
		rep.Minutes, fmtMinutes(rep.Minutes), rep.Coverage*100)
	fmt.Fprintf(&sb, "- Range: `%s` → `%s`\n",
		rep.StartedAt.Format(time.RFC3339), rep.EndedAt.Format(time.RFC3339))
	if rep.NumCPUs > 0 {
		fmt.Fprintf(&sb, "- Current size: **%d vCPU · %s RAM**\n",
			rep.NumCPUs, fmtBytesShort(rep.MemTotalBytes))
	}

	sb.WriteString("\n## Utilization\n\n")
	sb.WriteString("| dimension | state | p50 max | p95 max | peak | avg |\n")
	sb.WriteString("|-----------|-------|---------|---------|------|-----|\n")
	row := func(name string, v resourceVerdict, pct bool) {
		if pct {
			fmt.Fprintf(&sb, "| %s | %s | %.0f%% | %.0f%% | %.0f%% | %.0f%% |\n",
				name, v.State, v.P50Max, v.P95Max, v.MaxMax, v.AvgAvg)
			return
		}
		fmt.Fprintf(&sb, "| %s | %s | %.2f | %.2f | %.2f | %.2f |\n",
			name, v.State, v.P50Max, v.P95Max, v.MaxMax, v.AvgAvg)
	}
	row("CPU %", rep.CPU, true)
	row("Mem %", rep.Memory, true)
	row("IO %", rep.IO, true)
	row("Load/CPU", rep.Load, false)

	fmt.Fprintf(&sb, "\n## Recommendation: **%s**\n\n", rep.Action)
	for _, r := range rep.Reasoning {
		fmt.Fprintf(&sb, "- %s\n", r)
	}
	if rep.Savings != nil {
		fmt.Fprintf(&sb, "\n**%s → %s**", rep.Savings.FromTier, rep.Savings.ToTier)
		if rep.Savings.PercentSaved > 0 {
			fmt.Fprintf(&sb, " (~%d%% compute cost)", rep.Savings.PercentSaved)
		}
		sb.WriteString("\n")
		if rep.Savings.Rationale != "" {
			fmt.Fprintf(&sb, "\n_%s_\n", rep.Savings.Rationale)
		}
	}
	sb.WriteString("\n---\n*Generated by `xtop cost`*\n")
	fmt.Print(sb.String())
	return nil
}

// ── Formatting helpers ───────────────────────────────────────────────────────

func colorState(state string) string {
	switch state {
	case "hot":
		return fmt.Sprintf("%s%s%-7s%s", B, FBRed, state, R)
	case "warm":
		return fmt.Sprintf("%s%-7s%s", FBYel, state, R)
	case "cold":
		return fmt.Sprintf("%s%-7s%s", FBGrn, state, R)
	case "idle":
		return fmt.Sprintf("%s%-7s%s", FBCyn, state, R)
	}
	return fmt.Sprintf("%-7s", state)
}

func colorAction(action string) string {
	switch action {
	case "upsize":
		return fmt.Sprintf("%s%s UPSIZE %s", B, BRed, R)
	case "downsize":
		return fmt.Sprintf("%s%s DOWNSIZE %s", B, FBGrn, R)
	case "hold":
		return fmt.Sprintf("%s HOLD %s", FBCyn, R)
	case "insufficient_data":
		return fmt.Sprintf("%s INSUFFICIENT DATA %s", FBYel, R)
	}
	return action
}

func fmtPctPadded(v float64) string {
	return fmt.Sprintf("%-10s", fmt.Sprintf("%.0f%%", v))
}

func fmtFloat(v float64) string {
	return fmt.Sprintf("%-10s", fmt.Sprintf("%.2f", v))
}

func fmtMinutes(m int) string {
	switch {
	case m < 60:
		return fmt.Sprintf("%dm", m)
	case m < 60*24:
		return fmt.Sprintf("%dh", m/60)
	default:
		return fmt.Sprintf("%.1fd", float64(m)/60/24)
	}
}

func fmtBytesShort(b uint64) string {
	const (
		kb = 1024
		mb = 1024 * kb
		gb = 1024 * mb
	)
	switch {
	case b >= gb:
		return fmt.Sprintf("%.0f GiB", float64(b)/float64(gb))
	case b >= mb:
		return fmt.Sprintf("%.0f MiB", float64(b)/float64(mb))
	default:
		return fmt.Sprintf("%d B", b)
	}
}
