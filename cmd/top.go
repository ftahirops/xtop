package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"

	"github.com/ftahirops/xtop/engine"
	"github.com/ftahirops/xtop/model"
)

// runTop implements the `xtop top` subcommand.
// Displays an impact-scored process table.
func runTop(args []string) error {
	limit := 20
	sortBy := "impact"
	jsonOut := false
	intervalSec := 3

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "-n":
			if i+1 < len(args) {
				i++
				fmt.Sscanf(args[i], "%d", &limit)
			}
		case "--sort":
			if i+1 < len(args) {
				i++
				sortBy = args[i]
			}
		case "--json":
			jsonOut = true
		case "--interval", "-i":
			if i+1 < len(args) {
				i++
				fmt.Sscanf(args[i], "%d", &intervalSec)
			}
		}
	}

	fmt.Fprintf(os.Stderr, "Collecting metrics (%ds)...\n", intervalSec)
	snap, rates, result := collectOrQuery(intervalSec)

	if snap == nil || rates == nil {
		return fmt.Errorf("failed to collect metrics")
	}

	scores := engine.ComputeImpactScores(snap, rates, result)
	if len(scores) == 0 {
		fmt.Println("No processes with measurable impact.")
		return nil
	}

	// Sort by requested field
	switch sortBy {
	case "cpu":
		sort.Slice(scores, func(i, j int) bool { return scores[i].CPUSaturation > scores[j].CPUSaturation })
	case "mem":
		sort.Slice(scores, func(i, j int) bool { return scores[i].MemGrowth > scores[j].MemGrowth })
	case "io":
		sort.Slice(scores, func(i, j int) bool { return scores[i].IOWait > scores[j].IOWait })
	case "net":
		sort.Slice(scores, func(i, j int) bool { return scores[i].NetRetrans > scores[j].NetRetrans })
	default: // "impact" — already sorted by composite
	}

	// Re-assign ranks after sort
	for i := range scores {
		scores[i].Rank = i + 1
	}

	// Limit
	if len(scores) > limit {
		scores = scores[:limit]
	}

	if jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(scores)
	}

	// Print header
	health := model.HealthOK
	if result != nil {
		health = result.Health
	}
	fmt.Printf("\n  %sxtop top%s — %s  %s\n\n",
		B, R, snap.Timestamp.Format("15:04:05"), healthColor(health))

	// Build table
	headers := []string{"RANK", "PID", "SERVICE", "CPU%", "RSS", "IO(w)", "THREADS", "IMPACT"}
	widths := []int{4, 7, 18, 7, 8, 9, 7, 8}

	rows := make([][]string, 0, len(scores))
	for _, s := range scores {
		svc := s.Comm
		if s.Service != "" {
			svc = s.Service
		}
		svc = subcmdTrunc(svc, 18)

		cpuStr := colorByThreshold(s.CPUPct, tCPUWarn, tCPUCrit)
		ioStr := fmt.Sprintf("%.1fM/s", s.WriteMBs)
		impactStr := colorByImpact(s.Composite)

		rows = append(rows, []string{
			fmt.Sprintf("%d", s.Rank),
			fmt.Sprintf("%d", s.PID),
			svc,
			cpuStr,
			subcmdFmtBytes(s.RSS),
			ioStr,
			fmt.Sprintf("%d", s.Threads),
			impactStr,
		})
	}

	fmt.Print(renderTable(headers, rows, widths))
	fmt.Println()
	return nil
}
