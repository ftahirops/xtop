package cmd

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/ftahirops/xtop/model"
)

// runAgent is the top-level dispatcher for `xtop agent <verb>`.
func runAgent(args []string) error {
	if len(args) == 0 {
		printAgentUsage()
		return nil
	}
	switch args[0] {
	case "init":
		return runAgentInit(args[1:])
	case "status":
		return runAgentStatus()
	case "help", "-h", "--help":
		printAgentUsage()
		return nil
	default:
		fmt.Fprintf(os.Stderr, "xtop agent: unknown subcommand %q\n\n", args[0])
		printAgentUsage()
		return fmt.Errorf("unknown subcommand")
	}
}

func printAgentUsage() {
	fmt.Fprintln(os.Stderr, `xtop agent — manage a host as an xtop fleet agent

Subcommands:
  init --hub=URL --token=T    Write /etc/xtop/fleet.env + systemd unit, start pushing
  status                      Show agent service status + last hub health probe
  help                        This message`)
}

// ── agent init ───────────────────────────────────────────────────────────────

type agentInitOpts struct {
	hub       string
	token     string
	tags      string
	insecure  bool
	noSystemd bool
	noGuard   bool // --no-guard: skip writing XTOP_GUARD=1 to the env file
}

func runAgentInit(args []string) error {
	opts := parseAgentInitFlags(args)
	if runtime.GOOS != "linux" {
		return fmt.Errorf("xtop agent init is Linux-only")
	}
	if os.Geteuid() != 0 {
		return fmt.Errorf("xtop agent init must run as root (systemd unit install). Try: sudo xtop agent init --hub=... --token=...")
	}
	if opts.hub == "" || opts.token == "" {
		return fmt.Errorf("both --hub and --token are required (see `xtop agent init --help`)")
	}

	fmt.Println("xtop agent init — join this host to the fleet")
	fmt.Println()

	// Quick reachability check — helpful to catch typos before we install.
	fmt.Print("  • Hub reachable ............... ")
	if err := probeHubHealth(opts.hub, opts.token); err != nil {
		fmt.Println("FAILED")
		fmt.Fprintf(os.Stderr, "    %s\n\n", err)
		fmt.Fprintln(os.Stderr, "Continuing anyway — the agent will retry via its offline queue.")
		fmt.Fprintln(os.Stderr, "To abort, Ctrl-C within 3 seconds...")
	} else {
		fmt.Println("ok")
	}

	// Write the environment file systemd loads.
	fmt.Print("  • /etc/xtop/fleet.env ......... ")
	if err := writeAgentEnv(opts); err != nil {
		fmt.Println("failed")
		return err
	}
	fmt.Println("ok")

	// Also persist a fleet.json so the TUI mode (run without systemd) can
	// find the hub info without extra flags.
	fmt.Print("  • ~/.xtop/fleet.json .......... ")
	cfg := model.FleetAgentConfig{
		HubURL:             opts.hub,
		Token:              opts.token,
		InsecureSkipVerify: opts.insecure,
	}
	if opts.tags != "" {
		for _, t := range strings.Split(opts.tags, ",") {
			if t = strings.TrimSpace(t); t != "" {
				cfg.Tags = append(cfg.Tags, t)
			}
		}
	}
	if err := writeAgentConfigFile(cfg); err != nil {
		fmt.Println("failed")
		return err
	}
	fmt.Println("ok")

	if !opts.noSystemd {
		fmt.Print("  • systemd unit installed ...... ")
		if err := writeAgentSystemdUnit(); err != nil {
			fmt.Println("failed")
			return err
		}
		fmt.Println("ok")

		fmt.Print("  • Unit enabled + started ...... ")
		if err := reloadAndStart("xtop-agent"); err != nil {
			fmt.Println("failed")
			return err
		}
		fmt.Println("ok")
	}

	fmt.Println()
	fmt.Println(B + "Agent joined." + R)
	fmt.Printf("  Hub:             %s\n", opts.hub)
	fmt.Printf("  Logs:            journalctl -u xtop-agent -f\n")
	fmt.Printf("  Config:          /etc/xtop/fleet.env + ~/.xtop/fleet.json\n")
	if !opts.noGuard {
		fmt.Printf("  ResourceGuard:   enabled (auto-throttles on host stress; disable via --no-guard)\n")
	}
	fmt.Println()
	fmt.Println("Verify it showed up:")
	fmt.Printf("  curl -sH \"X-XTop-Token: %s\" %s/v1/hosts | jq '.[] | .hostname'\n",
		opts.token, strings.TrimRight(opts.hub, "/"))
	fmt.Println()
	return nil
}

func parseAgentInitFlags(args []string) agentInitOpts {
	var o agentInitOpts
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--hub" && i+1 < len(args):
			i++
			o.hub = args[i]
		case strings.HasPrefix(a, "--hub="):
			o.hub = strings.TrimPrefix(a, "--hub=")
		case a == "--token" && i+1 < len(args):
			i++
			o.token = args[i]
		case strings.HasPrefix(a, "--token="):
			o.token = strings.TrimPrefix(a, "--token=")
		case a == "--tags" && i+1 < len(args):
			i++
			o.tags = args[i]
		case strings.HasPrefix(a, "--tags="):
			o.tags = strings.TrimPrefix(a, "--tags=")
		case a == "--insecure":
			o.insecure = true
		case a == "--no-systemd":
			o.noSystemd = true
		case a == "--no-guard":
			o.noGuard = true
		case a == "-h" || a == "--help":
			fmt.Fprintln(os.Stderr, `xtop agent init — join a host to an existing fleet hub

Usage:
  sudo xtop agent init --hub=URL --token=TOKEN [--tags k=v,k=v] [--insecure] [--no-systemd]

Flags:
  --hub URL       Hub URL (required). Example: http://hub.example:9898
  --token T       Hub auth token (required).
  --tags t1,t2    Comma-separated tags to attach to this agent.
  --insecure      Skip TLS verification (self-signed hub certs).
  --no-systemd    Write configs but don't install/start the unit.
  --no-guard      Disable the ResourceGuard self-throttle (default: on).`)
			os.Exit(0)
		}
	}
	return o
}

// probeHubHealth hits /health with the token. Catches typos early.
func probeHubHealth(hubURL, token string) error {
	hubURL = strings.TrimRight(hubURL, "/")
	req, err := http.NewRequest(http.MethodGet, hubURL+"/health", nil)
	if err != nil {
		return err
	}
	if token != "" {
		req.Header.Set(model.FleetAuthHeader, token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("can't reach %s: %w", hubURL, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("hub returned %d — check URL + token", resp.StatusCode)
	}
	return nil
}

func writeAgentEnv(o agentInitOpts) error {
	dir := "/etc/xtop"
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	var sb strings.Builder
	sb.WriteString("# xtop agent — generated by `xtop agent init`\n")
	fmt.Fprintf(&sb, "XTOP_FLEET_HUB=%s\n", o.hub)
	fmt.Fprintf(&sb, "XTOP_FLEET_TOKEN=%s\n", o.token)
	if o.insecure {
		sb.WriteString("XTOP_FLEET_INSECURE=1\n")
	}
	// Enable the resource guard by default so fresh agents never become
	// the box's biggest consumer. The guard is pure-downside-free at L0 —
	// it costs one /proc/self/stat read per tick — and pure-upside when
	// the host gets stressed. --no-guard opts out for benchmarking.
	if !o.noGuard {
		sb.WriteString("# ResourceGuard: xtop self-throttles when host is stressed.\n")
		sb.WriteString("# Disable with `xtop agent init ... --no-guard` on re-install, or\n")
		sb.WriteString("# comment this line + `systemctl restart xtop-agent`.\n")
		sb.WriteString("XTOP_GUARD=1\n")
	}
	return writeFileAtomic(dir+"/fleet.env", []byte(sb.String()), 0o600)
}

func writeAgentConfigFile(cfg model.FleetAgentConfig) error {
	home, err := os.UserHomeDir()
	if err != nil {
		home = "/root"
	}
	path := filepath.Join(home, ".xtop", "fleet.json")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	if err := enc.Encode(&cfg); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	f.Close()
	return os.Rename(tmp, path)
}

const agentSystemdUnit = `[Unit]
Description=xtop fleet agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
EnvironmentFile=/etc/xtop/fleet.env
ExecStart=/usr/local/bin/xtop --daemon --fleet-hub=${XTOP_FLEET_HUB} --fleet-token=${XTOP_FLEET_TOKEN}
Restart=on-failure
RestartSec=5
StandardOutput=append:/var/log/xtop/agent.log
StandardError=append:/var/log/xtop/agent.log
User=root

[Install]
WantedBy=multi-user.target
`

func writeAgentSystemdUnit() error {
	if err := os.MkdirAll("/var/log/xtop", 0o755); err != nil {
		return err
	}
	return writeFileAtomic("/etc/systemd/system/xtop-agent.service", []byte(agentSystemdUnit), 0o644)
}

func runAgentStatus() error {
	fmt.Println("xtop agent status")
	_ = runShell("systemctl status xtop-agent --no-pager 2>&1 | head -15 || true")
	return nil
}
