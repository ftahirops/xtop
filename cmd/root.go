package cmd

import (
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	xtopcfg "github.com/ftahirops/xtop/config"
	"github.com/ftahirops/xtop/engine"
	"github.com/ftahirops/xtop/model"
	"github.com/ftahirops/xtop/ui"
)

// Version is set at build time via ldflags.
var Version = "0.10.6"

// Config holds CLI configuration.
type Config struct {
	Interval     time.Duration
	HistorySize  int
	JSONMode     bool
	MDMode       bool
	WatchMode    bool
	WatchCount   int
	Section      string
	RecordPath   string
	ReplayPath   string
	DaemonMode   bool
	DataDir      string
	PromEnabled  bool
	PromAddr     string
	AlertWebhook string
	AlertCommand string
	// Doctor mode
	DoctorMode    bool
	DiscoverMode  bool
	CronMode     bool
	AlertMode    bool
	// Forensics mode
	ForensicsMode bool
	// Diagnose mode
	DiagnoseMode   bool
	DiagnoseTarget string
	// Shell widget
	ShellInit   string
	TmuxStatus  bool
	CronInstall bool
	// Privacy
	MaskIPs bool
}

// MaskIPs is a global flag accessible from UI and doctor rendering.
var MaskIPsEnabled bool

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
  -doctor           Run comprehensive health check
  -discover         Interactive server discovery and tuning
  -forensics        Retroactive incident analysis from system logs
  -diagnose [SVC]   Per-service deep diagnostics (nginx, mysql, redis, etc.)
  -version          Print version and exit

Doctor Options:
  -cron             Doctor: cron-friendly output (silent if OK)
  -alert            Doctor: send alert on state change
  -cron-install     Print crontab line for automated health checks

Shell Widget:
  -shell-init SHELL Output shell init script (bash or zsh)
  -tmux-status      Output tmux-formatted status segment

Options:
  -interval N       Collection interval in seconds (default: 1)
  -history N        Snapshots to keep in ring buffer (default: 300, ~5 min at 1s)
  -section NAME     Section to display in -watch mode (default: overview)
                    Sections: overview, cpu, mem, io, net, cgroup, rca
  -count N          Number of iterations for -watch mode (0 = infinite, default: 0)
  -datadir PATH     Data directory for daemon mode (default: ~/.xtop/)
  -record FILE      Run TUI while recording snapshots to FILE
  -replay FILE      Replay a recorded file through the TUI
  -prom             Enable Prometheus metrics endpoint
  -prom-addr ADDR   Prometheus listen address (default: :9100)
  -alert-webhook URL  Webhook URL for alert notifications
  -alert-command CMD  Command to execute on alert notifications

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
  sudo xtop -doctor                    Health check report
  sudo xtop -doctor -watch             Doctor with auto-refresh (like top)
  sudo xtop -doctor -watch -interval 5 -count 3
  sudo xtop -doctor -json              Health check as JSON
  sudo xtop -doctor -md                Health check as Markdown
  sudo xtop -doctor -cron              Cron-friendly (silent if OK, exit codes)
  sudo xtop -doctor -alert             Alert on state changes
  sudo xtop -diagnose                   Per-service deep diagnostics
  sudo xtop -diagnose mysql             MySQL-only deep analysis
  sudo xtop -diagnose -json             Diagnostics as JSON
  sudo xtop -diagnose -md               Diagnostics as Markdown
  eval "$(xtop -shell-init bash)"      Shell health widget
  xtop -tmux-status                    Tmux status segment
  xtop -cron-install                   Print crontab line
  xtop -version
`, Version)
}

// Run parses flags and starts the application.
func Run() error {
	var cfg Config
	var intervalSec int
	var showVersion bool

	userCfg := xtopcfg.Load()

	// Apply threshold profile from config
	if userCfg.ThresholdProfile != "" {
		if p, ok := engine.Profiles[userCfg.ThresholdProfile]; ok {
			engine.ActiveProfile = p
		}
	}

	if userCfg.IntervalSec > 0 {
		intervalSec = userCfg.IntervalSec
	} else {
		intervalSec = 1
	}
	historyDefault := userCfg.HistorySize
	if historyDefault <= 0 {
		historyDefault = 300
	}
	sectionDefault := userCfg.Section
	if sectionDefault == "" {
		sectionDefault = "overview"
	}
	promAddrDefault := userCfg.Prometheus.Addr
	if promAddrDefault == "" {
		promAddrDefault = "127.0.0.1:9100"
	}

	flag.IntVar(&intervalSec, "interval", intervalSec, "Collection interval in seconds")
	flag.IntVar(&cfg.HistorySize, "history", historyDefault, "Number of snapshots to keep in history (5 min at 1s)")
	flag.BoolVar(&cfg.JSONMode, "json", false, "Output a single JSON snapshot and exit")
	flag.BoolVar(&cfg.MDMode, "md", false, "Output a single Markdown incident report and exit")
	flag.BoolVar(&cfg.WatchMode, "watch", false, "CLI output mode (no TUI, prints to terminal)")
	flag.IntVar(&cfg.WatchCount, "count", 0, "Number of iterations for -watch (0=infinite)")
	flag.StringVar(&cfg.Section, "section", sectionDefault, "Section for -watch mode (overview,cpu,mem,io,net,cgroup,rca)")
	flag.BoolVar(&cfg.DaemonMode, "daemon", false, "Run as background collector (no TUI)")
	flag.StringVar(&cfg.DataDir, "datadir", "", "Data directory for daemon mode (default: ~/.xtop/)")
	flag.StringVar(&cfg.RecordPath, "record", "", "Record snapshots to file for later replay")
	flag.StringVar(&cfg.ReplayPath, "replay", "", "Replay snapshots from a recorded file")
	flag.BoolVar(&showVersion, "version", false, "Print version and exit")
	flag.BoolVar(&cfg.PromEnabled, "prom", userCfg.Prometheus.Enabled, "Enable Prometheus metrics endpoint")
	flag.StringVar(&cfg.PromAddr, "prom-addr", promAddrDefault, "Prometheus listen address")
	flag.StringVar(&cfg.AlertWebhook, "alert-webhook", userCfg.Alerts.Webhook, "Webhook URL for alert notifications")
	flag.StringVar(&cfg.AlertCommand, "alert-command", userCfg.Alerts.Command, "Command to execute on alert notifications")
	// Doctor flags
	flag.BoolVar(&cfg.DoctorMode, "doctor", false, "Run comprehensive health check")
	flag.BoolVar(&cfg.DiscoverMode, "discover", false, "Interactive server discovery and tuning")
	flag.BoolVar(&cfg.ForensicsMode, "forensics", false, "Retroactive incident analysis from system logs")
	flag.BoolVar(&cfg.DiagnoseMode, "diagnose", false, "Per-service deep diagnostics (nginx, mysql, redis, etc.)")
	flag.BoolVar(&cfg.CronMode, "cron", false, "Doctor: cron-friendly output (silent if OK)")
	flag.BoolVar(&cfg.AlertMode, "alert", false, "Doctor: send alert on state change")
	// Shell widget flags
	flag.StringVar(&cfg.ShellInit, "shell-init", "", "Output shell init script (bash or zsh)")
	flag.BoolVar(&cfg.TmuxStatus, "tmux-status", false, "Output tmux-formatted status segment")
	flag.BoolVar(&cfg.CronInstall, "cron-install", false, "Print crontab line for automated health checks")
	// Privacy
	flag.BoolVar(&cfg.MaskIPs, "mask-ips", false, "Mask IP addresses in output (for demos/screenshots)")

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
	MaskIPsEnabled = cfg.MaskIPs
	model.MaskIPsEnabled = cfg.MaskIPs

	// Resolve default data directory
	if cfg.DataDir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return fmt.Errorf("cannot determine home directory for data dir: %w (use -datadir to specify)", err)
		}
		cfg.DataDir = filepath.Join(home, ".xtop")
	}

	// --- Dispatch modes that don't need root first ---

	// Shell init (doesn't need root)
	if cfg.ShellInit != "" {
		runShellInit(cfg.ShellInit, cfg.DataDir)
		return nil
	}

	// Tmux status (doesn't need root)
	if cfg.TmuxStatus {
		runTmuxStatus(cfg.DataDir)
		return nil
	}

	// Cron install (doesn't need root)
	if cfg.CronInstall {
		runCronInstall()
		return nil
	}

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

	var promStore *engine.MetricsStore
	if cfg.PromEnabled {
		promStore = engine.NewMetricsStore()
		srv := &http.Server{
			Addr:              cfg.PromAddr,
			Handler:           promStore.Handler(),
			ReadHeaderTimeout: 10 * time.Second,
			ReadTimeout:       30 * time.Second,
			WriteTimeout:      30 * time.Second,
			IdleTimeout:       60 * time.Second,
		}
		go func() {
			if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				fmt.Fprintf(os.Stderr, "Prometheus endpoint failed: %v\n", err)
			}
		}()
		fmt.Fprintf(os.Stderr, "Prometheus metrics listening on %s\n", cfg.PromAddr)
	}

	wrapTicker := func(t engine.Ticker) engine.Ticker {
		if promStore != nil {
			return engine.NewInstrumentedTicker(t, promStore)
		}
		return t
	}

	// --replay mode
	if cfg.ReplayPath != "" {
		return runReplay(cfg, wrapTicker)
	}

	// --forensics mode
	if cfg.ForensicsMode {
		return runForensics(cfg)
	}

	// --diagnose mode
	if cfg.DiagnoseMode {
		// Target from positional args when -diagnose is set
		if args := flag.Args(); len(args) > 0 {
			cfg.DiagnoseTarget = args[0]
		}
		return runDiagnose(cfg)
	}

	// --discover mode
	if cfg.DiscoverMode {
		return runDiscover()
	}

	// --doctor mode
	if cfg.DoctorMode {
		if cfg.WatchMode {
			return runDoctorWatch(cfg)
		}
		return runDoctor(cfg)
	}

	// --daemon mode
	if cfg.DaemonMode {
		return engine.RunDaemon(engine.DaemonConfig{
			DataDir:  cfg.DataDir,
			Interval: cfg.Interval,
			History:  cfg.HistorySize,
			Metrics:  promStore,
			Alerts: engine.AlertConfig{
				Webhook:          cfg.AlertWebhook,
				Command:          cfg.AlertCommand,
				Email:            userCfg.Alerts.Email,
				SlackWebhook:     userCfg.Alerts.SlackWebhook,
				TelegramBotToken: userCfg.Alerts.TelegramBotToken,
				TelegramChatID:   userCfg.Alerts.TelegramChatID,
			},
		})
	}

	// Create engine
	eng := engine.NewEngine(cfg.HistorySize)

	// -json mode: single snapshot to stdout
	if cfg.JSONMode {
		return runJSON(wrapTicker(eng), cfg.Interval)
	}

	// -md mode: single markdown incident report to stdout
	if cfg.MDMode {
		return runMarkdown(wrapTicker(eng), cfg.Interval)
	}

	// -watch mode: CLI output to terminal
	if cfg.WatchMode {
		return runWatch(wrapTicker(eng), cfg)
	}

	// -record mode: TUI + recording
	if cfg.RecordPath != "" {
		return runRecord(eng, cfg, wrapTicker)
	}

	// Normal TUI mode
	m := ui.NewModel(wrapTicker(eng), cfg.Interval, cfg.DataDir)
	p := tea.NewProgram(m, tea.WithAltScreen())
	_, err := p.Run()
	return err
}

// runJSON outputs a single snapshot + analysis as JSON and exits.
func runJSON(ticker engine.Ticker, interval time.Duration) error {
	// Collect two snapshots for rate calculation
	ticker.Tick()
	time.Sleep(interval)
	snap, rates, result := ticker.Tick()

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
func runMarkdown(ticker engine.Ticker, interval time.Duration) error {
	// Collect two snapshots for rate calculation
	ticker.Tick()
	time.Sleep(interval)
	snap, rates, result := ticker.Tick()

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
	memPct := float64(0)
	if mem.Total > 0 {
		memPct = float64(mem.Total-mem.Available) / float64(mem.Total) * 100
	}
	sb.WriteString(fmt.Sprintf("- **Memory:** %.0f%% used (%s available / %s total)\n",
		memPct, fmtBytesSimple(mem.Available), fmtBytesSimple(mem.Total)))

	if rates != nil {
		sb.WriteString(fmt.Sprintf("- **CPU:** busy=%.1f%% user=%.1f%% sys=%.1f%% iowait=%.1f%%\n",
			rates.CPUBusyPct, rates.CPUUserPct, rates.CPUSystemPct, rates.CPUIOWaitPct))
	}

	// Collector Errors
	if len(snap.Errors) > 0 {
		sb.WriteString("\n## Collector Errors\n\n")
		for _, e := range snap.Errors {
			sb.WriteString(fmt.Sprintf("- %s\n", e))
		}
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
func runRecord(eng *engine.Engine, cfg Config, wrap func(engine.Ticker) engine.Ticker) error {
	f, err := os.OpenFile(cfg.RecordPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("cannot create record file: %w", err)
	}
	defer f.Close()

	// Wrap the engine to intercept ticks and record
	rec := engine.NewRecorder(eng, f)
	ticker := wrap(rec)

	m := ui.NewModel(ticker, cfg.Interval, cfg.DataDir)
	p := tea.NewProgram(m, tea.WithAltScreen())
	_, err = p.Run()
	rec.Close()
	return err
}

// runReplay replays a recorded file through the TUI.
func runReplay(cfg Config, wrap func(engine.Ticker) engine.Ticker) error {
	f, err := os.Open(cfg.ReplayPath)
	if err != nil {
		return fmt.Errorf("cannot open replay file: %w", err)
	}
	defer f.Close()

	player, err := engine.NewPlayer(f, cfg.HistorySize)
	if err != nil {
		return fmt.Errorf("cannot parse replay file: %w", err)
	}

	m := ui.NewModel(wrap(player), cfg.Interval, cfg.DataDir)
	p := tea.NewProgram(m, tea.WithAltScreen())
	_, err = p.Run()
	return err
}
