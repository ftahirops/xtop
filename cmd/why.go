package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/ftahirops/xtop/engine"
	"github.com/ftahirops/xtop/model"
)

// runWhy implements the `xtop why` subcommand.
// Collects metrics and displays a concise RCA summary.
func runWhy(args []string) error {
	jsonOut := false
	mdOut := false
	intervalSec := 3

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--json":
			jsonOut = true
		case "--md":
			mdOut = true
		case "--interval", "-i":
			if i+1 < len(args) {
				i++
				fmt.Sscanf(args[i], "%d", &intervalSec)
			}
		}
	}

	snap, rates, result := collectOrQuery(intervalSec)

	if snap == nil || result == nil {
		return fmt.Errorf("failed to collect metrics")
	}

	if jsonOut {
		return whyJSON(snap, rates, result)
	}
	if mdOut {
		return whyMarkdown(snap, rates, result)
	}

	return whyANSI(snap, rates, result)
}

// whyANSI renders the RCA summary with ANSI colors.
func whyANSI(snap *model.Snapshot, rates *model.RateSnapshot, result *model.AnalysisResult) error {
	fmt.Println()
	fmt.Printf("  %sxtop why%s — %s\n", B, R, snap.Timestamp.Format("2006-01-02 15:04:05"))
	fmt.Println()

	// 1. HEALTH
	fmt.Printf("  %sHEALTH:%s  %s  confidence=%d%%\n",
		B, R, healthColor(result.Health), result.Confidence)
	fmt.Println()

	if result.Health == model.HealthOK {
		fmt.Printf("  %s%sSystem healthy. No active incidents.%s\n", B, FBGrn, R)
		fmt.Println()

		// Show top 3 by impact
		scores := engine.ComputeImpactScores(snap, rates, result)
		if len(scores) > 0 {
			fmt.Printf("  %sTop processes by impact:%s\n", D, R)
			n := 3
			if len(scores) < n {
				n = len(scores)
			}
			for i := 0; i < n; i++ {
				s := scores[i]
				svc := s.Comm
				if s.Service != "" {
					svc = s.Service
				}
				fmt.Printf("    %s#%d%s  %-16s  PID=%-6d  CPU=%.1f%%  RSS=%s  impact=%s\n",
					D, s.Rank, R, subcmdTrunc(svc, 16), s.PID,
					s.CPUPct, subcmdFmtBytes(s.RSS), colorByImpact(s.Composite))
			}
		}

		if result.StableSince > 0 {
			fmt.Printf("\n  %sStable for %ds%s\n", D, result.StableSince, R)
		}
		fmt.Println()
		return nil
	}

	// 2. ROOT CAUSE
	rootCause := result.PrimaryBottleneck
	patternName := ""
	if result.Narrative != nil {
		if result.Narrative.RootCause != "" {
			rootCause = result.Narrative.RootCause
		}
		patternName = result.Narrative.Pattern
	}
	fmt.Printf("  %sROOT CAUSE:%s  %s%s%s\n", B, R, FBRed, rootCause, R)
	if patternName != "" {
		fmt.Printf("  %sPattern:%s    %s\n", D, R, patternName)
	}
	if result.PrimaryScore > 0 {
		fmt.Printf("  %sScore:%s      %s\n", D, R, colorByThreshold(float64(result.PrimaryScore), 40, 70))
	}
	fmt.Println()

	// 3. EVIDENCE (top 5)
	if len(result.RCA) > 0 {
		primary := result.RCA[0]
		for _, rca := range result.RCA {
			if rca.Bottleneck == result.PrimaryBottleneck {
				primary = rca
				break
			}
		}

		if len(primary.EvidenceV2) > 0 {
			fmt.Printf("  %sEVIDENCE:%s\n", B, R)
			// Sort by strength descending
			evs := make([]model.Evidence, len(primary.EvidenceV2))
			copy(evs, primary.EvidenceV2)
			sort.Slice(evs, func(i, j int) bool { return evs[i].Strength > evs[j].Strength })
			n := 5
			if len(evs) < n {
				n = len(evs)
			}
			for i := 0; i < n; i++ {
				ev := evs[i]
				icon := FBGrn + "○" + R
				if ev.Strength > 0.5 {
					icon = FBRed + "●" + R
				} else if ev.Strength > 0.2 {
					icon = FBYel + "●" + R
				}
				fmt.Printf("    %s  %s  %s(%.0f%%)%s\n",
					icon, ev.Message, D, ev.Strength*100, R)
			}
			fmt.Println()
		} else if len(primary.Checks) > 0 {
			fmt.Printf("  %sEVIDENCE:%s\n", B, R)
			n := 5
			if len(primary.Checks) < n {
				n = len(primary.Checks)
			}
			for i := 0; i < n; i++ {
				c := primary.Checks[i]
				icon := D + "○" + R
				if c.Passed {
					icon = FBRed + "●" + R
				}
				fmt.Printf("    %s  %s — %s\n", icon, c.Label, c.Value)
			}
			fmt.Println()
		}
	}

	// 4. TOP OFFENDER
	if len(result.Blame) > 0 {
		top := result.Blame[0]
		fmt.Printf("  %sTOP OFFENDER:%s  %s%s%s (PID %d)\n",
			B, R, FBYel, top.Comm, R, top.PID)
		// Show metrics
		var metricParts []string
		for k, v := range top.Metrics {
			metricParts = append(metricParts, fmt.Sprintf("%s=%s", k, v))
		}
		if len(metricParts) > 0 {
			sort.Strings(metricParts)
			fmt.Printf("    %s%s%s\n", D, strings.Join(metricParts, "  "), R)
		}
		if top.CgroupPath != "" {
			fmt.Printf("    %scgroup: %s%s\n", D, top.CgroupPath, R)
		}
		fmt.Println()
	}

	// 5. CAUSAL CHAIN
	if result.CausalChain != "" {
		fmt.Printf("  %sCAUSAL CHAIN:%s\n", B, R)
		parts := strings.Split(result.CausalChain, " -> ")
		for i, p := range parts {
			arrow := "  "
			if i > 0 {
				arrow = "→ "
			}
			fmt.Printf("    %s%s\n", arrow, p)
		}
		fmt.Println()
	} else if result.Narrative != nil && result.Narrative.Temporal != "" {
		fmt.Printf("  %sCAUSAL CHAIN:%s  %s\n\n", B, R, result.Narrative.Temporal)
	}

	// 6. NEXT STEPS
	if len(result.Actions) > 0 {
		fmt.Printf("  %sNEXT STEPS:%s\n", B, R)
		n := 3
		if len(result.Actions) < n {
			n = len(result.Actions)
		}
		for i := 0; i < n; i++ {
			a := result.Actions[i]
			fmt.Printf("    %d. %s\n", i+1, a.Summary)
			if a.Command != "" {
				fmt.Printf("       %s$ %s%s\n", D, a.Command, R)
			}
		}
		fmt.Println()
	}

	return nil
}

// whyJSON outputs the RCA summary as JSON.
func whyJSON(snap *model.Snapshot, rates *model.RateSnapshot, result *model.AnalysisResult) error {
	scores := engine.ComputeImpactScores(snap, rates, result)
	topScores := scores
	if len(topScores) > 5 {
		topScores = topScores[:5]
	}

	out := map[string]interface{}{
		"timestamp":  snap.Timestamp,
		"health":     result.Health.String(),
		"confidence": result.Confidence,
		"bottleneck": result.PrimaryBottleneck,
		"score":      result.PrimaryScore,
	}
	if result.Narrative != nil {
		out["root_cause"] = result.Narrative.RootCause
		out["pattern"] = result.Narrative.Pattern
	}
	if result.CausalChain != "" {
		out["causal_chain"] = result.CausalChain
	}
	if len(result.Blame) > 0 {
		out["top_offender"] = result.Blame[0]
	}
	if len(result.Actions) > 0 {
		n := 3
		if len(result.Actions) < n {
			n = len(result.Actions)
		}
		out["actions"] = result.Actions[:n]
	}
	if len(topScores) > 0 {
		out["top_impact"] = topScores
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}

// whyMarkdown outputs the RCA summary as Markdown.
func whyMarkdown(snap *model.Snapshot, rates *model.RateSnapshot, result *model.AnalysisResult) error {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("# xtop why — %s\n\n", snap.Timestamp.Format("2006-01-02 15:04:05")))
	sb.WriteString(fmt.Sprintf("**Health:** %s (confidence %d%%)\n\n", result.Health, result.Confidence))

	if result.Health == model.HealthOK {
		sb.WriteString("System healthy. No active incidents.\n")
		fmt.Print(sb.String())
		return nil
	}

	rootCause := result.PrimaryBottleneck
	if result.Narrative != nil && result.Narrative.RootCause != "" {
		rootCause = result.Narrative.RootCause
	}
	sb.WriteString(fmt.Sprintf("## Root Cause\n\n%s (score: %d%%)\n\n", rootCause, result.PrimaryScore))

	if result.CausalChain != "" {
		sb.WriteString(fmt.Sprintf("## Causal Chain\n\n%s\n\n", result.CausalChain))
	}

	if len(result.Blame) > 0 {
		top := result.Blame[0]
		sb.WriteString(fmt.Sprintf("## Top Offender\n\n**%s** (PID %d)\n\n", top.Comm, top.PID))
	}

	if len(result.Actions) > 0 {
		sb.WriteString("## Next Steps\n\n")
		n := 3
		if len(result.Actions) < n {
			n = len(result.Actions)
		}
		for i := 0; i < n; i++ {
			a := result.Actions[i]
			sb.WriteString(fmt.Sprintf("%d. %s\n", i+1, a.Summary))
			if a.Command != "" {
				sb.WriteString(fmt.Sprintf("   ```\n   %s\n   ```\n", a.Command))
			}
		}
	}

	sb.WriteString("\n---\n*Generated by xtop*\n")
	fmt.Print(sb.String())
	return nil
}
