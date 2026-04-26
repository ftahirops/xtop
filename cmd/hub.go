package cmd

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/ftahirops/xtop/fleet"
	"github.com/ftahirops/xtop/model"
)

// runHub is the top-level dispatcher for `xtop hub <verb>`. Bare `xtop hub`
// keeps its existing behavior (starts the server). Subverbs route to other
// functions: init (provision), status, token, reset-token.
func runHubDispatcher(args []string) error {
	if len(args) > 0 {
		switch args[0] {
		case "init":
			return runHubInit(args[1:])
		case "status":
			return runHubStatus()
		case "token":
			return runHubPrintToken()
		case "reset-token":
			return runHubResetToken()
		case "help", "-h", "--help":
			printHubDispatcherHelp()
			return nil
		}
	}
	// Default / unknown subverb → run the server (preserves the old contract
	// where `xtop hub --listen=:9898` still works).
	return runHub(args)
}

func printHubDispatcherHelp() {
	fmt.Fprintln(os.Stderr, `xtop hub — fleet aggregator controls

Usage:
  xtop hub                    Start the hub server (reads ~/.xtop/hub.json).
  xtop hub init               One-command provisioning (Postgres + token + systemd + start).
  xtop hub status             systemctl status xtop-hub + /health probe.
  xtop hub token              Print the current auth token (for new agent joins).
  xtop hub reset-token        Rotate the token (invalidates existing agents).

Flags for the server (xtop hub):
  --listen, --postgres, --token, --tls-cert, --tls-key, --config, --print-config`)
}

// runHubStatus prints the service status + a health probe result.
func runHubStatus() error {
	_ = runShell("systemctl status xtop-hub --no-pager 2>&1 | head -12 || true")
	fmt.Println()
	cfg, err := readHubConfigIfExists()
	if err != nil || cfg == nil || cfg.ListenAddr == "" {
		fmt.Println("(no /root/.xtop/hub.json found — can't probe /health)")
		return nil
	}
	url := fmt.Sprintf("http://127.0.0.1%s/health", cfg.ListenAddr)
	fmt.Printf("/health: ")
	if err := pollHealth(url, 2); err != nil {
		fmt.Println("DOWN")
	} else {
		fmt.Println("OK")
	}
	return nil
}

// runHubPrintToken reads the hub config and prints just the token — handy
// for scripts that need to tell new agents where to join.
func runHubPrintToken() error {
	cfg, err := readHubConfigIfExists()
	if err != nil {
		return fmt.Errorf("no hub config found at /root/.xtop/hub.json")
	}
	fmt.Println(cfg.AuthToken)
	return nil
}

// runHubResetToken generates a fresh token, rewrites the config, restarts
// the unit. Any agent not reconfigured will get 401s until its token is
// updated.
func runHubResetToken() error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("reset-token needs root")
	}
	cfg, err := readHubConfigIfExists()
	if err != nil {
		return err
	}
	cfg.AuthToken = randomHex(24)
	if _, err := writeHubConfig(*cfg); err != nil {
		return err
	}
	fmt.Printf("New token: %s\n", cfg.AuthToken)
	fmt.Print("Restarting xtop-hub ... ")
	if err := runShell("systemctl restart xtop-hub"); err != nil {
		fmt.Println("failed")
		return err
	}
	fmt.Println("ok")
	fmt.Println("Every agent must be re-pointed with:  sudo xtop agent init --hub=... --token=" + cfg.AuthToken)
	return nil
}

// runHub implements the `xtop hub` subcommand — starts the central fleet
// aggregator that receives heartbeats/incidents from agents.
func runHub(args []string) error {
	fs := flag.NewFlagSet("hub", flag.ExitOnError)
	var (
		configPath  = fs.String("config", "", "path to hub config JSON (default ~/.xtop/hub.json)")
		listen      = fs.String("listen", "", "listen address (overrides config/env, e.g. :9898)")
		pgDSN       = fs.String("postgres", "", "postgres DSN (overrides config)")
		token       = fs.String("token", "", "auth token (overrides config)")
		tlsCert     = fs.String("tls-cert", "", "TLS certificate file")
		tlsKey      = fs.String("tls-key", "", "TLS key file")
		printConfig = fs.Bool("print-config", false, "print loaded config and exit")
	)
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, `xtop hub — start the central fleet aggregator

Receives heartbeats and incidents from xtop agents, stores them in Postgres
with a SQLite hot cache, and exposes a JSON + SSE API for TUI/web clients.

Usage:
  sudo xtop hub [flags]

Config precedence (highest first):
  1. CLI flags                    (--listen, --postgres, --token, --tls-*)
  2. Environment variables        (XTOP_HUB_LISTEN, XTOP_HUB_POSTGRES, XTOP_HUB_TOKEN,
                                   XTOP_HUB_TLS_CERT, XTOP_HUB_TLS_KEY,
                                   XTOP_HUB_SQLITE_CACHE_PATH)
  3. JSON config file             (~/.xtop/hub.json, or --config <path>)
  4. Built-in defaults            (listen :9898)

Flags:`)
		fs.PrintDefaults()
		fmt.Fprintln(os.Stderr, `
Config file format (~/.xtop/hub.json):
  {
    "listen_addr": ":9898",
    "auth_token": "change-me",
    "postgres_dsn": "postgres://xtop:pw@localhost:5432/xtopfleet?sslmode=disable",
    "sqlite_cache_path": "/var/lib/xtop/hub-cache.sqlite",
    "incident_retention_days": 30,
    "heartbeat_retention_hours": 48
  }`)
	}
	if err := fs.Parse(args); err != nil {
		return err
	}

	cfg, err := loadHubConfig(*configPath)
	if err != nil {
		return err
	}

	// Layer environment variables over the file. CLI flags override both below.
	envOverlay(&cfg)

	if *listen != "" {
		cfg.ListenAddr = *listen
	}
	if *pgDSN != "" {
		cfg.PostgresDSN = *pgDSN
	}
	if *token != "" {
		cfg.AuthToken = *token
	}
	if *tlsCert != "" {
		cfg.TLSCert = *tlsCert
	}
	if *tlsKey != "" {
		cfg.TLSKey = *tlsKey
	}

	if *printConfig {
		out, _ := json.MarshalIndent(cfg, "", "  ")
		fmt.Println(string(out))
		return nil
	}

	if cfg.PostgresDSN == "" {
		return fmt.Errorf("postgres DSN is required: set in %s or pass --postgres", hubConfigPath(*configPath))
	}

	hub, err := fleet.NewHub(cfg)
	if err != nil {
		return fmt.Errorf("hub init: %w", err)
	}
	defer hub.Stop()
	return hub.Start()
}

// envOverlay fills in any missing fields from XTOP_HUB_* environment vars. Only
// empty fields are set — callers that already set a value (e.g. from the JSON
// config file) are preserved. CLI flags override env below in runHub.
func envOverlay(cfg *model.FleetHubConfig) {
	if cfg.ListenAddr == "" {
		cfg.ListenAddr = os.Getenv("XTOP_HUB_LISTEN")
	}
	if cfg.PostgresDSN == "" {
		cfg.PostgresDSN = os.Getenv("XTOP_HUB_POSTGRES")
	}
	if cfg.AuthToken == "" {
		cfg.AuthToken = os.Getenv("XTOP_HUB_TOKEN")
	}
	if cfg.TLSCert == "" {
		cfg.TLSCert = os.Getenv("XTOP_HUB_TLS_CERT")
	}
	if cfg.TLSKey == "" {
		cfg.TLSKey = os.Getenv("XTOP_HUB_TLS_KEY")
	}
	if cfg.SQLiteCachePath == "" {
		cfg.SQLiteCachePath = os.Getenv("XTOP_HUB_SQLITE_CACHE_PATH")
	}
}

func hubConfigPath(explicit string) string {
	if explicit != "" {
		return explicit
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".xtop", "hub.json")
}

func loadHubConfig(explicit string) (model.FleetHubConfig, error) {
	var cfg model.FleetHubConfig
	path := hubConfigPath(explicit)
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) && explicit == "" {
			// No config file — return empty so CLI flags can fill it in.
			return cfg, nil
		}
		return cfg, fmt.Errorf("read %s: %w", path, err)
	}
	if err := json.Unmarshal(b, &cfg); err != nil {
		return cfg, fmt.Errorf("parse %s: %w", path, err)
	}
	return cfg, nil
}
