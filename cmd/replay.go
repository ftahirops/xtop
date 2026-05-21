package cmd

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/ftahirops/xtop/engine/replay"
)

// runReplay implements `xtop replay [path]`.
//
// Default: scan ~/.xtop/incidents/ and run the harness across the
// whole corpus. Prints per-mechanism agreement (replay determinism)
// and, when labels are present, per-mechanism precision.
//
// With a single file argument: load and replay that frame, print
// side-by-side capture vs replay output for inspection.
func runReplayHarness(args []string) error {
	fs := flag.NewFlagSet("replay", flag.ExitOnError)
	dir := fs.String("dir", "", "corpus directory (default: ~/.xtop/incidents)")
	verbose := fs.Bool("v", false, "print every frame's outcome, not just the rollup")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, `xtop replay — offline RCA verification harness (NEXTGEN Phase 5)

  xtop replay                          replay every captured frame
  xtop replay --dir=/path/to/incidents replay frames from a specific dir
  xtop replay --v                      per-frame detail output
  xtop replay frame.json               replay a single frame file

For each frame, the harness:
  1. loads the captured facts + entity graph from disk
  2. re-runs the verifier with the current gate set
  3. compares the fresh tier output to what was captured
  4. when frames carry an operator label (TP/FP/FN/TN), computes
     per-mechanism precision over the corpus

Per-mechanism precision is the substrate of the NEXTGEN 0.1% FP
target. Without labels, the harness reports determinism only.`)
	}
	if err := fs.Parse(args); err != nil {
		return err
	}

	// Single-file form?
	rest := fs.Args()
	if len(rest) == 1 {
		return runReplaySingle(rest[0])
	}

	d := *dir
	if d == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return fmt.Errorf("could not resolve home: %w", err)
		}
		d = filepath.Join(home, ".xtop", "incidents")
	}

	frames, warnings, err := replay.LoadCorpus(d)
	if err != nil {
		return err
	}
	for _, w := range warnings {
		fmt.Fprintf(os.Stderr, "warning: %s\n", w)
	}

	fmt.Printf("Corpus: %s\n", d)
	fmt.Printf("Loaded %d frames.\n", len(frames))
	if len(frames) == 0 {
		fmt.Println("  (no frames yet — let the engine run on a stressed host first)")
		return nil
	}

	sum := replay.SummarizeCorpus(frames)
	fmt.Printf("\nLabeled frames: %d / %d\n", sum.LabeledFrames, sum.Frames)
	fmt.Printf("Tier flip-flops on replay: %d\n", sum.FlipFlops)
	if sum.FlipFlops > 0 {
		fmt.Println("  ⚠ engine has drifted since these frames were captured;")
		fmt.Println("    either gates were tuned or the engine is non-deterministic.")
	}

	// Per-mechanism rollup
	fmt.Println("\nPer-mechanism rollup:")
	mechs := make([]string, 0, len(sum.PerMechanism))
	for m := range sum.PerMechanism {
		mechs = append(mechs, m)
	}
	sort.Strings(mechs)
	const w = 6
	fmt.Printf("  %-60s  %*s %*s %*s %*s  %s  %s\n",
		"MECHANISM", w, "TP", w, "FP", w, "FN", w, "TN", "PRECISION", "AVG_TIER")
	fmt.Println("  " + dashes(60+ (w*4) + 22))
	for _, m := range mechs {
		st := sum.PerMechanism[m]
		precision := "-"
		if st.TP+st.FP > 0 {
			precision = fmt.Sprintf("%.3f", st.Precision())
		}
		fmt.Printf("  %-60s  %*d %*d %*d %*d  %9s  %.2f\n",
			truncate(m, 60),
			w, st.TP, w, st.FP, w, st.FN, w, st.TN,
			precision, st.AvgTierRank)
	}

	if *verbose {
		fmt.Println("\nPer-frame detail:")
		for _, f := range frames {
			r := replay.Replay(f)
			fmt.Printf("  %s  flipflops=%d  label=%q\n",
				f.CapturedAt.Format("2006-01-02T15:04:05"), r.FlipFlops, f.Label)
			for i, vc := range r.Replayed {
				orig := f.VerifiedCauses[i].Tier
				marker := "="
				if orig != vc.Tier {
					marker = "≠"
				}
				fmt.Printf("    %s  %s → %s  %s\n", marker, orig, vc.Tier, vc.Mechanism)
			}
		}
	}
	return nil
}

func runReplaySingle(path string) error {
	f, err := replay.LoadFrame(path)
	if err != nil {
		return err
	}
	r := replay.Replay(f)
	fmt.Printf("Frame: %s\n", path)
	fmt.Printf("Host: %s   Captured: %s\n", f.HostID, f.CapturedAt.Format("2006-01-02T15:04:05"))
	fmt.Printf("Engine version: %s\n", f.EngineVersion)
	fmt.Printf("Label: %q  %s\n\n", f.Label, f.LabelReason)
	fmt.Printf("FlipFlops on replay: %d\n\n", r.FlipFlops)
	for i, orig := range f.VerifiedCauses {
		fresh := r.Replayed[i]
		marker := "="
		if orig.Tier != fresh.Tier {
			marker = "≠"
		}
		fmt.Printf("  %s  %s\n", marker, orig.Mechanism)
		fmt.Printf("    captured:  %-15s  conf=%d\n", orig.Tier, orig.Confidence)
		fmt.Printf("    replayed:  %-15s  conf=%d\n", fresh.Tier, fresh.Confidence)
		for _, g := range fresh.Gates {
			tag := "pass"
			if !g.Passed {
				tag = "FAIL"
			}
			fmt.Printf("        %s  %-22s  %s\n", tag, g.GateID, g.Reason)
		}
	}
	return nil
}

func dashes(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = '-'
	}
	return string(b)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-3] + "..."
}
