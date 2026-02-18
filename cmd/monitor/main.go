// monitor is a headless version of xtop that prints RCA results to stdout.
package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/ftahirops/xtop/engine"
)

func main() {
	interval := flag.Int("interval", 1, "Collection interval in seconds")
	duration := flag.Int("duration", 60, "How long to run in seconds (0=forever)")
	flag.Parse()

	eng := engine.NewEngine(60)

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

	ticker := time.NewTicker(time.Duration(*interval) * time.Second)
	defer ticker.Stop()

	deadline := time.Time{}
	if *duration > 0 {
		deadline = time.Now().Add(time.Duration(*duration) * time.Second)
	}

	fmt.Println("xtop monitor — headless RCA output")
	fmt.Println(strings.Repeat("=", 80))

	tick := 0
	for {
		select {
		case <-sig:
			fmt.Println("\nStopped.")
			return
		case <-ticker.C:
			if !deadline.IsZero() && time.Now().After(deadline) {
				fmt.Println("\nDuration reached.")
				return
			}
			tick++
			snap, rates, result := eng.Tick()
			if snap == nil {
				continue
			}

			ts := snap.Timestamp.Format("15:04:05")

			// PSI line
			psi := snap.Global.PSI
			psiStr := fmt.Sprintf("PSI cpu=%.1f%% mem=%.1f%% io=%.1f%%",
				psi.CPU.Some.Avg10, psi.Memory.Full.Avg10, psi.IO.Full.Avg10)

			// Load
			load := snap.Global.CPU.LoadAvg
			loadStr := fmt.Sprintf("Load=%.2f/%d", load.Load1, snap.Global.CPU.NumCPUs)

			// Mem
			mem := snap.Global.Memory
			memPct := float64(mem.Total-mem.Available) / float64(mem.Total) * 100
			memStr := fmt.Sprintf("Mem=%.0f%%", memPct)

			// D-state
			dCount := 0
			for _, p := range snap.Processes {
				if p.State == "D" {
					dCount++
				}
			}

			fmt.Printf("[%s] %s | %s | %s | D-state=%d\n",
				ts, psiStr, loadStr, memStr, dCount)

			if result != nil && tick > 1 {
				// Health + anomaly
				fmt.Printf("  HEALTH: %s  Confidence: %d%%", result.Health, result.Confidence)
				if result.PrimaryBottleneck != "" && result.PrimaryScore > 0 {
					fmt.Printf("  PRIMARY: %s [%d%%]", result.PrimaryBottleneck, result.PrimaryScore)
					if result.AnomalyStartedAgo > 0 {
						fmt.Printf("  Started: T-%ds", result.AnomalyStartedAgo)
					}
				}
				fmt.Println()

				// Evidence checks (for primary)
				if result.PrimaryScore > 0 {
					for _, rca := range result.RCA {
						if rca.Bottleneck != result.PrimaryBottleneck {
							continue
						}
						for _, check := range rca.Checks {
							mark := "  -"
							if check.Passed {
								mark = "  +"
							}
							fmt.Printf("  %s %-28s %s\n", mark, check.Label, check.Value)
						}
						fmt.Printf("  Evidence groups: %d/%d\n", rca.EvidenceGroups, len(rca.Checks))
						break
					}
				}

				// Capacities
				for _, cap := range result.Capacities {
					fmt.Printf("    %-18s %5.1f%% left  (%s)\n", cap.Label, cap.Pct, cap.Current)
				}

				// RCA entries with score > 0
				for _, r := range result.RCA {
					if r.Score == 0 {
						continue
					}
					marker := "  "
					if r.Score >= 60 {
						marker = "!!"
					} else if r.Score >= 30 {
						marker = "! "
					}
					fmt.Printf("  %s %-20s score=%3d  (%d groups)", marker, r.Bottleneck, r.Score, r.EvidenceGroups)
					if r.TopProcess != "" {
						fmt.Printf("  top=%s(%d)", r.TopProcess, r.TopPID)
					}
					if r.TopCgroup != "" {
						fmt.Printf("  cg=%s", r.TopCgroup)
					}
					fmt.Println()
					for _, e := range r.Evidence {
						fmt.Printf("       -> %s\n", e)
					}
				}

				// Causal chain
				if result.CausalChain != "" {
					fmt.Printf("  CHAIN: %s\n", result.CausalChain)
				}

				// Warnings
				for _, w := range result.Warnings {
					fmt.Printf("  [%s] %s: %s\n", w.Severity, w.Signal, w.Value)
				}

				// CPU rates
				if rates != nil {
					fmt.Printf("  CPU: busy=%.1f%% user=%.1f%% sys=%.1f%% iowait=%.1f%% steal=%.1f%% softirq=%.1f%%\n",
						rates.CPUBusyPct, rates.CPUUserPct, rates.CPUSystemPct,
						rates.CPUIOWaitPct, rates.CPUStealPct, rates.CPUSoftIRQPct)
				}
			} else if tick > 1 && result == nil {
				fmt.Println("  (healthy — no analysis yet)")
			}
		}
	}
}
