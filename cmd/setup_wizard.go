package cmd

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"runtime"
	"strings"

	"github.com/ftahirops/xtop/model"
)

// runSetup is the top-level interactive wizard: `xtop setup`.
// It asks what the host should be — hub, agent, both — and drives the
// full corresponding init flow. The goal is zero manual steps:
//
//   sudo xtop setup
//
// gets the operator from nothing installed to a running hub + dashboard
// URL, or from nothing to an agent pushing to an existing hub.
//
// Design principles:
//
//  - Only asks questions the operator MUST answer (hub URL + token for
//    agent flow; nothing required for hub flow — all generated).
//  - Never destroys existing state silently. If /root/.xtop/hub.json
//    exists, re-init asks "rotate secrets or keep?".
//  - Prints every command it's about to run so ops can audit before
//    hitting enter.
//  - All output stays on stdout; prompts go to stderr so piping into
//    a log preserves the machine-readable lines.
func runSetup(args []string) error {
	if runtime.GOOS != "linux" {
		return fmt.Errorf("xtop setup is Linux-only — on macOS/Windows, run `xtop` directly or use the Docker compose in packaging/hub/")
	}
	if os.Geteuid() != 0 {
		return fmt.Errorf("xtop setup must run as root. Try: sudo xtop setup")
	}

	// Allow wizard short-circuit: `xtop setup hub` / `xtop setup agent`
	// skip the role prompt — handy for scripts.
	role := ""
	for _, a := range args {
		switch a {
		case "hub", "agent", "both":
			role = a
		case "-h", "--help":
			printSetupUsage()
			return nil
		}
	}

	banner()

	reader := bufio.NewReader(os.Stdin)
	if role == "" {
		role = promptRole(reader)
	}

	switch role {
	case "hub":
		return wizardHub(reader)
	case "agent":
		return wizardAgent(reader)
	case "both":
		if err := wizardHub(reader); err != nil {
			return err
		}
		return wizardAgent(reader)
	default:
		return fmt.Errorf("unknown role %q", role)
	}
}

func printSetupUsage() {
	fmt.Fprintln(os.Stderr, `xtop setup — interactive end-to-end wizard

Runs through hub provisioning (Postgres role, token generation, systemd
unit, dashboard URL) AND/OR agent join (hub probe, systemd unit, start).

Usage:
  sudo xtop setup            Asks whether this host is a hub, agent, or both.
  sudo xtop setup hub        Skip prompt, run hub flow directly.
  sudo xtop setup agent      Skip prompt, run agent flow directly.
  sudo xtop setup both       Hub first, then agent pointing at localhost.`)
}

func banner() {
	fmt.Println()
	fmt.Println(B + "  xtop setup — one-command fleet provisioning" + R)
	fmt.Println("  " + FDim + "────────────────────────────────────────────" + R)
	fmt.Println()
}

// ── Role prompt ─────────────────────────────────────────────────────────────

func promptRole(reader *bufio.Reader) string {
	for {
		fmt.Println("  What is this host?")
		fmt.Println("    " + B + "[1]" + R + " Fleet hub — this box receives heartbeats from all agents")
		fmt.Println("    " + B + "[2]" + R + " Agent      — this box pushes to an existing hub")
		fmt.Println("    " + B + "[3]" + R + " Both       — hub here + an agent on the same box")
		fmt.Println("    " + B + "[q]" + R + " Quit")
		fmt.Print("\n  choice [1]: ")

		line, _ := reader.ReadString('\n')
		switch strings.TrimSpace(line) {
		case "", "1", "hub":
			return "hub"
		case "2", "agent":
			return "agent"
		case "3", "both":
			return "both"
		case "q", "quit":
			os.Exit(0)
		}
		fmt.Fprint(os.Stderr, "  (invalid choice, try again)\n\n")
	}
}

// ── Hub flow ────────────────────────────────────────────────────────────────

func wizardHub(reader *bufio.Reader) error {
	fmt.Println(B + "→ Hub setup" + R)
	fmt.Println()

	// Detect existing state — don't wipe a running fleet by mistake.
	existing, _ := readHubConfigIfExists()
	if existing != nil && existing.AuthToken != "" {
		fmt.Println("  " + FBYel + "⚠ Existing hub config found at /root/.xtop/hub.json" + R)
		fmt.Println("  Options:")
		fmt.Println("    " + B + "[k]" + R + " Keep current token + Postgres password (recommended)")
		fmt.Println("    " + B + "[r]" + R + " Rotate secrets (invalidates all existing agent tokens)")
		fmt.Println("    " + B + "[a]" + R + " Abort")
		fmt.Print("\n  choice [k]: ")
		line, _ := reader.ReadString('\n')
		choice := strings.ToLower(strings.TrimSpace(line))
		switch choice {
		case "", "k", "keep":
			// Just re-install unit + restart. No secret change.
			return hubKeepAndRestart(existing)
		case "r", "rotate":
			// Fall through to fresh init (runs with --no flags → regenerates).
		case "a", "abort":
			fmt.Println("  aborted")
			return nil
		}
	}

	// Optional customizations — defaults are fine for 95% of operators.
	fmt.Print("  Listen port [9898]: ")
	port, _ := reader.ReadString('\n')
	port = strings.TrimSpace(port)
	if port == "" {
		port = "9898"
	}
	port = strings.TrimPrefix(port, ":")

	// Interface selection — only prompt when multiple non-loopback IPv4
	// interfaces exist. Default is "all interfaces" (listen on 0.0.0.0)
	// which is what most operators want. Binding to a single interface
	// is useful for security (LAN-only hub) or to avoid listening on
	// container bridges.
	listen := ":" + port
	if chosen := promptListenInterface(reader); chosen != "" {
		listen = chosen + ":" + port
	}

	// Run the existing init path — all of the hard work lives there.
	args := []string{"--listen", listen}
	return runHubInit(args)
}

// promptListenInterface returns the selected IP to bind to, or "" when the
// operator picked "all interfaces" (or there's only one candidate). The
// list is filtered to reachable, non-loopback IPv4 addresses.
func promptListenInterface(reader *bufio.Reader) string {
	ips := detectReachableIPs()
	// Zero interfaces → silent pass-through (binds to all, hub still works
	// on loopback for same-box agents).
	// One interface → no point prompting; "bind all" = "bind that one".
	if len(ips) <= 1 {
		return ""
	}

	fmt.Println()
	fmt.Println("  Multiple interfaces detected. Which should the hub listen on?")
	fmt.Println("    " + B + "[0]" + R + " All interfaces (0.0.0.0) — recommended")
	for i, ip := range ips {
		label := ""
		if ip.Label != "" {
			label = " " + FDim + "(" + ip.Label + ")" + R
		}
		fmt.Printf("    %s[%d]%s %s on %s%s\n", B, i+1, R, ip.IP, ip.Interface, label)
	}
	fmt.Print("\n  choice [0]: ")
	line, _ := reader.ReadString('\n')
	line = strings.TrimSpace(line)
	if line == "" || line == "0" {
		return ""
	}
	// Parse the choice. Out-of-range / non-numeric → fall back to "all".
	for i := range ips {
		if line == fmt.Sprintf("%d", i+1) {
			return ips[i].IP
		}
	}
	fmt.Fprintln(os.Stderr, "  (unknown choice, binding to all interfaces)")
	return ""
}

// hubKeepAndRestart is the "don't change secrets, just reinstall the unit
// and restart" fast-path for a wizard re-run.
func hubKeepAndRestart(existing *model.FleetHubConfig) error {
	fmt.Println("  • Keeping existing token + DSN.")
	fmt.Print("  • Reinstalling systemd unit .... ")
	if err := writeHubSystemdUnit(); err != nil {
		fmt.Println("failed")
		return err
	}
	fmt.Println("ok")
	fmt.Print("  • Restarting xtop-hub .......... ")
	if err := reloadAndStart("xtop-hub"); err != nil {
		fmt.Println("failed")
		return err
	}
	fmt.Println("ok")

	listen := existing.ListenAddr
	if listen == "" {
		listen = ":9898"
	}
	fmt.Print("  • /health probe ................ ")
	if err := pollHealth(fmt.Sprintf("http://127.0.0.1%s/health", listen), 10); err != nil {
		fmt.Println("timeout")
		return err
	}
	fmt.Println("ok")
	printHubInitSuccess(listen, existing.AuthToken, false)
	return nil
}

func readHubConfigIfExists() (*model.FleetHubConfig, error) {
	f, err := os.Open("/root/.xtop/hub.json")
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var c model.FleetHubConfig
	if err := json.NewDecoder(f).Decode(&c); err != nil {
		return nil, err
	}
	return &c, nil
}

// ── Agent flow ──────────────────────────────────────────────────────────────

func wizardAgent(reader *bufio.Reader) error {
	fmt.Println()
	fmt.Println(B + "→ Agent setup" + R)
	fmt.Println()

	// If we just ran the hub flow, the token + URL are known — pull from
	// /root/.xtop/hub.json so the operator doesn't have to paste them.
	defaultHub := ""
	defaultToken := ""
	if cfg, err := readHubConfigIfExists(); err == nil && cfg != nil {
		defaultHub = fmt.Sprintf("http://127.0.0.1%s", cfg.ListenAddr)
		defaultToken = cfg.AuthToken
		fmt.Println("  " + FDim + "Detected local hub — pre-filling values. Enter to accept." + R)
	}

	hub := prompt(reader, "Hub URL", defaultHub)
	if hub == "" {
		return fmt.Errorf("hub URL is required")
	}
	token := prompt(reader, "Hub token", defaultToken)
	if token == "" {
		return fmt.Errorf("token is required")
	}
	tags := prompt(reader, "Tags (comma-separated, optional, e.g. role=db,env=prod)", "")

	fmt.Println()
	// Connectivity pre-check before we install anything.
	fmt.Print("  • Probing hub .................. ")
	if err := probeAgentHub(hub, token); err != nil {
		fmt.Println("FAILED")
		fmt.Printf("    %s\n", err)
		fmt.Print("  Continue anyway? [y/N]: ")
		line, _ := reader.ReadString('\n')
		if strings.ToLower(strings.TrimSpace(line)) != "y" {
			return fmt.Errorf("aborted")
		}
	} else {
		fmt.Println("ok")
	}

	// Hand off to the non-interactive agent init.
	args := []string{"--hub", hub, "--token", token}
	if tags != "" {
		args = append(args, "--tags", tags)
	}
	return runAgentInit(args)
}

func probeAgentHub(hubURL, token string) error {
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
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("hub returned %d (check URL + token)", resp.StatusCode)
	}
	return nil
}

// prompt asks a question and returns the trimmed answer, or the default
// when the operator just hits Enter.
func prompt(reader *bufio.Reader, label, def string) string {
	if def != "" {
		fmt.Printf("  %s [%s]: ", label, shortenForPrompt(def))
	} else {
		fmt.Printf("  %s: ", label)
	}
	line, _ := reader.ReadString('\n')
	line = strings.TrimSpace(line)
	if line == "" {
		return def
	}
	return line
}

// shortenForPrompt masks long values (tokens) so they don't scroll the
// terminal. Keeps the first 10 chars + ellipsis.
func shortenForPrompt(v string) string {
	if len(v) > 20 {
		return v[:10] + "…"
	}
	return v
}
