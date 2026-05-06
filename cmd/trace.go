package cmd

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/ftahirops/xtop/collector"
	"github.com/ftahirops/xtop/engine"
)

// runTrace implements `xtop trace` — Phase 3 verification tool.
//
// Modes:
//   xtop trace --once             arm next-tick dump, run one tick, exit
//   xtop trace --watch-confirmed  run continuously, dump every Suspected→Confirmed transition
//
// Output: ~/.xtop/traces/trace-<unix>.json + .md
func runTrace(args []string) error {
	fs := flag.NewFlagSet("trace", flag.ExitOnError)
	var (
		once           = fs.Bool("once", false, "dump the next analysis tick to a trace file, then exit")
		watchConfirmed = fs.Bool("watch-confirmed", false, "run continuously; dump every Suspected→Confirmed transition")
		interval       = fs.Int("interval", 3, "tick interval in seconds (only used with --watch-confirmed)")
	)
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, `xtop trace — full A→Z RCA reasoning to a file

  xtop trace --once
      Run a single analysis tick with full reasoning captured to
      ~/.xtop/traces/trace-<unix>.{json,md}, then exit. Use this to
      audit an isolated event.

  xtop trace --watch-confirmed
      Run continuously. Every time an incident is promoted from Suspected
      to Confirmed, write a trace file. Stop with Ctrl-C.

The .md file is sysadmin-readable: inputs, per-domain evidence with
sustained durations, gate audit (which trust gates passed/failed and why),
runner-up domain with score gap, blame, correlations, final verdict.

The .json file has the same data in a stable schema (xtop.trace.v1).

Flags:`)
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	if !*once && !*watchConfirmed {
		fs.Usage()
		return fmt.Errorf("must specify either --once or --watch-confirmed")
	}

	eng := engine.NewEngine(60, *interval)

	if *once {
		eng.ArmTraceNext()
		// Two ticks: first establishes baseline, second produces analysis.
		_, _, _ = eng.Tick()
		time.Sleep(time.Duration(*interval) * time.Second)
		_, _, _ = eng.Tick()
		fmt.Fprintln(os.Stderr, "trace: complete (check ~/.xtop/traces/)")
		return nil
	}

	// watch-confirmed
	eng.ArmTraceOnConfirmed()
	fmt.Fprintln(os.Stderr, "xtop trace --watch-confirmed: running. Ctrl-C to stop.")
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	t := time.NewTicker(time.Duration(*interval) * time.Second)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			_, _, _ = eng.Tick()
		case <-sigCh:
			fmt.Fprintln(os.Stderr, "trace: stopped")
			return nil
		}
	}
}

// Silence unused import on builds that drop xtop-agent's narrow deps.
var _ = collector.ModeRich
