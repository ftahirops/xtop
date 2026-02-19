package cmd

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/ftahirops/xtop/engine"
	"github.com/ftahirops/xtop/model"
	"github.com/ftahirops/xtop/ui"
)

// Version is set at build time via ldflags.
var Version = "0.6.1"

// Config holds CLI configuration.
type Config struct {
	Interval    time.Duration
	HistorySize int
	JSONMode    bool
	MDMode      bool
	WatchMode   bool
	WatchCount  int
	Section     string
	RecordPath  string
	ReplayPath  string
	DaemonMode  bool
	DataDir     string
}

// validSections lists sections available for -watch and -section.
var validSections = []string{"overview", "cpu", "mem", "io", "net", "cgroup", "rca"}

func printUsage() {
	fmt.Fprintf(os.Stderr, `xtop v%s — Incident-first root-cause analysis console for Linux

Usage:
  xtop [OPTIONS] [INTERVAL]

Modes:
  (default)         Interactive TUI (bubbletea, fullscreen)
  -watch            CLI output mode — prints to terminal with auto-refresh
  -json             Single JSON snapshot to stdout, then exit
  -md               Single Markdown incident report to stdout, then exit
  -daemon           Background collector (no TUI, writes events to datadir)
  -version          Print version and exit

Options:
  -interval N       Collection interval in seconds (default: 1)
  -history N        Snapshots to keep in ring buffer (default: 300, ~5 min at 1s)
  -section NAME     Section to display in -watch mode (default: overview)
                    Sections: overview, cpu, mem, io, net, cgroup, rca
  -count N          Number of iterations for -watch mode (0 = infinite, default: 0)
  -datadir PATH     Data directory for daemon mode (default: ~/.xtop/)
  -record FILE      Run TUI while recording snapshots to FILE
  -replay FILE      Replay a recorded file through the TUI

Positional:
  INTERVAL          First positional arg sets interval: xtop 5 = xtop -interval 5

Examples:
  sudo xtop                          Interactive TUI, 1s refresh
  sudo xtop 5                        Interactive TUI, 5s refresh
  sudo xtop -watch                   CLI mode, overview section, 1s refresh
  sudo xtop -watch -section cpu      CLI mode, CPU section only
  sudo xtop -watch -section io 3     CLI mode, IO section, 3s refresh
  sudo xtop -watch -section rca      CLI mode, RCA analysis only
  sudo xtop -watch -count 10         CLI mode, 10 iterations then exit
  sudo xtop -watch -section mem -count 5 -interval 2
  sudo xtop -json | jq '.analysis.Health'
  sudo xtop -md > /tmp/incident.md
  sudo xtop -record /var/log/xtop.wlog
  xtop -replay /var/log/xtop.wlog
  sudo xtop -daemon &                  Background daemon, records events
  sudo xtop -daemon -datadir /var/lib/xtop -interval 2
  xtop -version
`, Version)
}

// Run parses flags and starts the application.
func Run() error {
	var cfg Config
	var intervalSec int
	var showVersion bool

	flag.IntVar(&intervalSec, "interval", 1, "Collection interval in seconds")
	flag.IntVar(&cfg.HistorySize, "history", 300, "Number of snapshots to keep in history (5 min at 1s)")
	flag.BoolVar(&cfg.JSONMode, "json", false, "Output a single JSON snapshot and exit")
	flag.BoolVar(&cfg.MDMode, "md", false, "Output a single Markdown incident report and exit")
	flag.BoolVar(&cfg.WatchMode, "watch", false, "CLI output mode (no TUI, prints to terminal)")
	flag.IntVar(&cfg.WatchCount, "count", 0, "Number of iterations for -watch (0=infinite)")
	flag.StringVar(&cfg.Section, "section", "overview", "Section for -watch mode (overview,cpu,mem,io,net,cgroup,rca)")
	flag.BoolVar(&cfg.DaemonMode, "daemon", false, "Run as background collector (no TUI)")
	flag.StringVar(&cfg.DataDir, "datadir", "", "Data directory for daemon mode (default: ~/.xtop/)")
	flag.StringVar(&cfg.RecordPath, "record", "", "Record snapshots to file for later replay")
	flag.StringVar(&cfg.ReplayPath, "replay", "", "Replay snapshots from a recorded file")
	flag.BoolVar(&showVersion, "version", false, "Print version and exit")

	flag.Usage = printUsage
	flag.Parse()

	// -version
	if showVersion {
		fmt.Printf("xtop v%s\n", Version)
		return nil
	}

	// Support positional arg for interval: `xtop 5` = `xtop --interval 5`
	if args := flag.Args(); len(args) > 0 {
		if n, err := strconv.Atoi(args[0]); err == nil && n > 0 {
			intervalSec = n
		}
	}

	cfg.Interval = time.Duration(intervalSec) * time.Second

	// Validate section
	if cfg.WatchMode {
		valid := false
		for _, s := range validSections {
			if cfg.Section == s {
				valid = true
				break
			}
		}
		if !valid {
			fmt.Fprintf(os.Stderr, "Error: unknown section %q\n", cfg.Section)
			fmt.Fprintf(os.Stderr, "Valid sections: %s\n\n", strings.Join(validSections, ", "))
			printUsage()
			os.Exit(1)
		}
	}

	// Check for root (needed for /proc/*/io)
	if os.Geteuid() != 0 && cfg.ReplayPath == "" {
		fmt.Fprintf(os.Stderr, "Warning: running without root — some metrics (process IO) may be unavailable\n")
	}

	// Resolve default data directory
	if cfg.DataDir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			home = "/tmp"
		}
		cfg.DataDir = filepath.Join(home, ".xtop")
	}

	// --replay mode
	if cfg.ReplayPath != "" {
		return runReplay(cfg)
	}

	// --daemon mode
	if cfg.DaemonMode {
		return engine.RunDaemon(engine.DaemonConfig{
			DataDir:  cfg.DataDir,
			Interval: cfg.Interval,
			History:  cfg.HistorySize,
		})
	}

	// Create engine
	eng := engine.NewEngine(cfg.HistorySize)

	// -version handled above

	// -json mode: single snapshot to stdout
	if cfg.JSONMode {
		return runJSON(eng)
	}

	// -md mode: single markdown incident report to stdout
	if cfg.MDMode {
		return runMarkdown(eng)
	}

	// -watch mode: CLI output to terminal
	if cfg.WatchMode {
		return runWatch(eng, cfg)
	}

	// -record mode: TUI + recording
	if cfg.RecordPath != "" {
		return runRecord(eng, cfg)
	}

	// Normal TUI mode
	model := ui.NewModel(eng, cfg.Interval, cfg.DataDir)
	p := tea.NewProgram(model, tea.WithAltScreen())
	_, err := p.Run()
	return err
}

// runJSON outputs a single snapshot + analysis as JSON and exits.
func runJSON(eng *engine.Engine) error {
	// Collect two snapshots for rate calculation
	eng.Tick()
	time.Sleep(time.Second)
	snap, rates, result := eng.Tick()

	data := map[string]interface{}{
		"timestamp": time.Now().Format(time.RFC3339),
		"snapshot":  snap,
		"rates":     rates,
		"analysis":  result,
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(data)
}

// runMarkdown outputs a markdown incident report to stdout.
func runMarkdown(eng *engine.Engine) error {
	// Collect two snapshots for rate calculation
	eng.Tick()
	time.Sleep(time.Second)
	snap, rates, result := eng.Tick()

	fmt.Println(renderMarkdownReport(snap, rates, result))
	return nil
}

// renderMarkdownReport generates a ticket-friendly markdown incident report.
func renderMarkdownReport(snap *model.Snapshot, rates *model.RateSnapshot, result *model.AnalysisResult) string {
	var sb strings.Builder

	sb.WriteString("# xtop Incident Report\n\n")
	sb.WriteString(fmt.Sprintf("**Timestamp:** %s\n\n", snap.Timestamp.Format(time.RFC3339)))

	// Health
	sb.WriteString("## Health\n\n")
	if result != nil {
		sb.WriteString(fmt.Sprintf("- **Status:** %s\n", result.Health))
		sb.WriteString(fmt.Sprintf("- **Confidence:** %d%%\n", result.Confidence))
		if result.PrimaryBottleneck != "" && result.PrimaryScore > 0 {
			sb.WriteString(fmt.Sprintf("- **Primary Bottleneck:** %s (%d%%)\n", result.PrimaryBottleneck, result.PrimaryScore))
		} else {
			sb.WriteString("- **Primary Bottleneck:** None detected\n")
		}
		if result.PrimaryCulprit != "" {
			sb.WriteString(fmt.Sprintf("- **Culprit:** %s\n", result.PrimaryCulprit))
		}
		if result.PrimaryProcess != "" {
			sb.WriteString(fmt.Sprintf("- **Top Process:** %s (PID %d)\n", result.PrimaryProcess, result.PrimaryPID))
		}
	} else {
		sb.WriteString("- **Status:** OK (insufficient samples)\n")
	}

	// Evidence
	if result != nil && result.PrimaryScore > 0 {
		sb.WriteString("\n## Evidence\n\n")
		for _, rca := range result.RCA {
			if rca.Bottleneck != result.PrimaryBottleneck {
				continue
			}
			sb.WriteString(fmt.Sprintf("**%s** — Score: %d%%, Evidence Groups: %d/%d\n\n",
				rca.Bottleneck, rca.Score, rca.EvidenceGroups, len(rca.Checks)))
			for _, check := range rca.Checks {
				if check.Passed {
					sb.WriteString(fmt.Sprintf("- [x] **%s** — %s\n", check.Label, check.Value))
				} else {
					sb.WriteString(fmt.Sprintf("- [ ] %s — %s\n", check.Label, check.Value))
				}
			}
			break
		}
	}

	// Causal Chain
	if result != nil && result.CausalChain != "" {
		sb.WriteString("\n## Causal Chain\n\n")
		parts := strings.Split(result.CausalChain, " -> ")
		for _, p := range parts {
			sb.WriteString(fmt.Sprintf("1. %s\n", p))
		}
	}

	// Capacity
	if result != nil && len(result.Capacities) > 0 {
		sb.WriteString("\n## Capacity Headroom\n\n")
		sb.WriteString("| Resource | Remaining | Current |\n")
		sb.WriteString("|----------|-----------|----------|\n")
		for _, cap := range result.Capacities {
			sb.WriteString(fmt.Sprintf("| %s | %.1f%% | %s |\n", cap.Label, cap.Pct, cap.Current))
		}
	}

	// System Overview
	sb.WriteString("\n## System Overview\n\n")
	psi := snap.Global.PSI
	sb.WriteString(fmt.Sprintf("- **PSI CPU:** some=%.1f%% full=%.1f%%\n", psi.CPU.Some.Avg10, psi.CPU.Full.Avg10))
	sb.WriteString(fmt.Sprintf("- **PSI Memory:** some=%.1f%% full=%.1f%%\n", psi.Memory.Some.Avg10, psi.Memory.Full.Avg10))
	sb.WriteString(fmt.Sprintf("- **PSI IO:** some=%.1f%% full=%.1f%%\n", psi.IO.Some.Avg10, psi.IO.Full.Avg10))
	sb.WriteString(fmt.Sprintf("- **Load:** %.2f %.2f %.2f (%d CPUs)\n",
		snap.Global.CPU.LoadAvg.Load1, snap.Global.CPU.LoadAvg.Load5,
		snap.Global.CPU.LoadAvg.Load15, snap.Global.CPU.NumCPUs))

	mem := snap.Global.Memory
	memPct := float64(mem.Total-mem.Available) / float64(mem.Total) * 100
	sb.WriteString(fmt.Sprintf("- **Memory:** %.0f%% used (%s available / %s total)\n",
		memPct, fmtBytesSimple(mem.Available), fmtBytesSimple(mem.Total)))

	if rates != nil {
		sb.WriteString(fmt.Sprintf("- **CPU:** busy=%.1f%% user=%.1f%% sys=%.1f%% iowait=%.1f%%\n",
			rates.CPUBusyPct, rates.CPUUserPct, rates.CPUSystemPct, rates.CPUIOWaitPct))
	}

	// Warnings
	if result != nil && len(result.Warnings) > 0 {
		sb.WriteString("\n## Warnings\n\n")
		for _, w := range result.Warnings {
			icon := "info"
			if w.Severity == "crit" {
				icon = "CRITICAL"
			} else if w.Severity == "warn" {
				icon = "WARNING"
			}
			sb.WriteString(fmt.Sprintf("- **[%s]** %s: %s — %s\n", icon, w.Signal, w.Detail, w.Value))
		}
	}

	// Actions
	if result != nil && len(result.Actions) > 0 {
		sb.WriteString("\n## Suggested Actions\n\n")
		for _, a := range result.Actions {
			sb.WriteString(fmt.Sprintf("- %s\n", a.Summary))
			if a.Command != "" {
				sb.WriteString(fmt.Sprintf("  ```\n  %s\n  ```\n", a.Command))
			}
		}
	}

	// All RCA scores
	if result != nil {
		sb.WriteString("\n## All Bottleneck Scores\n\n")
		sb.WriteString("| Bottleneck | Score | Evidence Groups | Top Process |\n")
		sb.WriteString("|------------|-------|-----------------|-------------|\n")
		for _, rca := range result.RCA {
			top := "-"
			if rca.TopProcess != "" {
				top = fmt.Sprintf("%s (%d)", rca.TopProcess, rca.TopPID)
			}
			sb.WriteString(fmt.Sprintf("| %s | %d%% | %d/%d | %s |\n",
				rca.Bottleneck, rca.Score, rca.EvidenceGroups, len(rca.Checks), top))
		}
	}

	sb.WriteString("\n---\n*Generated by [xtop](https://github.com/ftahirops/xtop) — Incident-first node RCA console*\n")
	return sb.String()
}

func fmtBytesSimple(b uint64) string {
	switch {
	case b >= 1<<30:
		return fmt.Sprintf("%.1fG", float64(b)/(1<<30))
	case b >= 1<<20:
		return fmt.Sprintf("%.1fM", float64(b)/(1<<20))
	case b >= 1<<10:
		return fmt.Sprintf("%.1fK", float64(b)/(1<<10))
	default:
		return fmt.Sprintf("%dB", b)
	}
}

// runRecord runs the TUI while also recording snapshots to a file.
func runRecord(eng *engine.Engine, cfg Config) error {
	f, err := os.Create(cfg.RecordPath)
	if err != nil {
		return fmt.Errorf("cannot create record file: %w", err)
	}
	defer f.Close()

	// Wrap the engine to intercept ticks and record
	rec := engine.NewRecorder(eng, f)

	model := ui.NewModel(rec.Engine, cfg.Interval, cfg.DataDir)
	p := tea.NewProgram(model, tea.WithAltScreen())
	_, err = p.Run()
	rec.Close()
	return err
}

// runReplay replays a recorded file through the TUI.
func runReplay(cfg Config) error {
	f, err := os.Open(cfg.ReplayPath)
	if err != nil {
		return fmt.Errorf("cannot open replay file: %w", err)
	}
	defer f.Close()

	player, err := engine.NewPlayer(f, cfg.HistorySize)
	if err != nil {
		return fmt.Errorf("cannot parse replay file: %w", err)
	}

	model := ui.NewModel(player.Engine, cfg.Interval, cfg.DataDir)
	p := tea.NewProgram(model, tea.WithAltScreen())
	_, err = p.Run()
	return err
}
