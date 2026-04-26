// xtop-agent is the headless fleet-agent binary. It runs the engine in
// Lean mode and pushes heartbeats + incidents to a hub, with NO TUI code
// linked in (no Bubbletea, no lipgloss, no app deep-metric modules
// loaded — the TUI carries those dependencies indirectly).
//
// The intent: deploy on every host you want to observe; let the operator
// keep the full xtop binary on their workstation for interactive use.
//
// Why a separate binary instead of a build tag in the existing main:
//   - Linker actually drops unused packages, but only if NO transitive
//     import chain reaches them. The TUI lives in ui/, which cmd/ uses
//     unconditionally, which main.go imports. A separate main with a
//     narrower import graph guarantees the agent binary stays small.
//   - Operator clarity: `xtop-agent` on a server is unambiguous about
//     what's running there, vs `xtop --daemon --fleet-hub` where it's
//     not obvious from `ps` whether a TUI is also linked.
//
// Build:
//   CGO_ENABLED=0 go build -ldflags="-s -w \
//     -X main.Version=$VER" \
//     -o xtop-agent ./cmd/xtop-agent
//
// Run:
//   sudo xtop-agent --hub=http://hub:9898 --token=$TOKEN
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"syscall"
	"time"

	"github.com/ftahirops/xtop/collector"
	"github.com/ftahirops/xtop/engine"
	"github.com/ftahirops/xtop/model"
)

// Version is stamped at build time via -ldflags '-X main.Version=...'.
var Version = "dev"

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "xtop-agent: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	var (
		hubURL   = flag.String("hub", os.Getenv("XTOP_FLEET_HUB"), "Hub URL (also XTOP_FLEET_HUB env). Required.")
		token    = flag.String("token", os.Getenv("XTOP_FLEET_TOKEN"), "Hub auth token (also XTOP_FLEET_TOKEN env).")
		insecure = flag.Bool("insecure", os.Getenv("XTOP_FLEET_INSECURE") == "1", "Skip TLS verification (self-signed hub certs).")
		interval = flag.Int("interval", 10, "Tick interval in seconds. 10s is a good default for agents (hub aggregates).")
		dataDir  = flag.String("datadir", defaultDataDir(), "Where to keep state files (~/.xtop/ by default).")
		version  = flag.Bool("version", false, "Print version and exit.")
	)
	flag.Usage = func() {
		fmt.Fprintln(os.Stderr, `xtop-agent — headless fleet agent (lean mode only)

Pushes heartbeats + incidents to an xtop hub. Runs no TUI; reads
~/.xtop/modules.json for which collectors are active.

Usage:
  xtop-agent --hub=http://hub:9898 --token=TOKEN
  xtop-agent                     (uses XTOP_FLEET_HUB / XTOP_FLEET_TOKEN env)

Flags:`)
		flag.PrintDefaults()
		fmt.Fprintln(os.Stderr, `
Configure module set via:
  xtop modules profile minimal       (uses the full xtop binary as a CLI)
  edit ~/.xtop/modules.json directly`)
	}
	flag.Parse()

	if *version {
		fmt.Printf("xtop-agent %s (lean) · %s/%s · %s\n",
			Version, runtime.GOOS, runtime.GOARCH, runtime.Version())
		return nil
	}

	if *hubURL == "" {
		return fmt.Errorf("--hub is required (or set XTOP_FLEET_HUB)")
	}
	if *token == "" {
		return fmt.Errorf("--token is required (or set XTOP_FLEET_TOKEN)")
	}

	if err := os.MkdirAll(*dataDir, 0o700); err != nil {
		return fmt.Errorf("create data dir: %w", err)
	}

	log.SetFlags(log.LstdFlags)
	log.Printf("xtop-agent %s starting · hub=%s · interval=%ds · mode=lean",
		Version, *hubURL, *interval)

	// Lean engine: 9 essential collectors + module-config-honored
	// optional ones. History capped automatically by Lean mode.
	eng := engine.NewEngineMode(30, *interval, collector.ModeLean)
	defer eng.Close()

	fleetCfg := model.FleetAgentConfig{
		HubURL:             *hubURL,
		Token:              *token,
		InsecureSkipVerify: *insecure,
		QueuePath:          filepath.Join(*dataDir, "fleet-queue.jsonl"),
	}
	if fc := engine.NewFleetClient(fleetCfg); fc != nil {
		eng.AttachFleetClient(fc, Version)
	} else {
		return fmt.Errorf("failed to construct fleet client (check --hub URL)")
	}

	// Signal-driven shutdown. We block in the tick loop; SIGINT / SIGTERM
	// breaks out cleanly so systemd's stop sequence doesn't have to wait
	// for a hard timeout.
	ctx, cancel := context.WithCancel(context.Background())
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		log.Println("xtop-agent: shutdown signal received")
		cancel()
	}()

	tick := time.NewTicker(time.Duration(*interval) * time.Second)
	defer tick.Stop()

	// First tick immediately so the hub sees us within seconds, not
	// after the first interval. The engine itself needs two ticks before
	// it can compute rates — the second one finishes inside the loop.
	eng.Tick()

	for {
		select {
		case <-ctx.Done():
			log.Println("xtop-agent: stopped")
			return nil
		case <-tick.C:
			eng.Tick()
		}
	}
}

func defaultDataDir() string {
	if home, err := os.UserHomeDir(); err == nil {
		return filepath.Join(home, ".xtop")
	}
	return "/var/lib/xtop"
}
