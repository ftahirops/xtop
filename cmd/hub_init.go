package cmd

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/ftahirops/xtop/model"
)

// runHubInit implements `xtop hub init` — one-command hub provisioning.
//
// What it does (in order, each step is idempotent):
//
//  1. Sanity-check: Linux + root + systemd. Non-Linux exits early with
//     instructions; non-root suggests `sudo`.
//  2. Ensure Postgres is installed and reachable on localhost:5432. If not,
//     print distro-specific install hints and exit (we don't `apt install`
//     for the operator — too invasive without explicit consent).
//  3. Generate random auth token + Postgres password.
//  4. Create the `xtop` role + `xtopfleet` database (idempotent — existing
//     role/db is fine; we update only the password to match the fresh value
//     unless --keep-db-password is given).
//  5. Write /root/.xtop/hub.json (0600).
//  6. Write /etc/systemd/system/xtop-hub.service, reload systemd, enable +
//     start the unit.
//  7. Sanity-check: poll /health for up to 10 seconds. If it doesn't come
//     up, show the journalctl tail and exit non-zero.
//  8. Print the agent join command with the full token and web URL.
//
// Flags let operators split this: --skip-db lets them bring their own PG;
// --no-systemd skips unit creation (for BYO init systems); --listen /
// --postgres / --token override generated values.
func runHubInit(args []string) error {
	opts := parseHubInitFlags(args)
	if err := preflightHubInit(opts); err != nil {
		return err
	}

	if runtime.GOOS != "linux" {
		return fmt.Errorf("xtop hub init is Linux-only (this is %s). On macOS/Windows, run the Docker compose in packaging/hub/ instead", runtime.GOOS)
	}
	if os.Geteuid() != 0 {
		return fmt.Errorf("xtop hub init must run as root (writes /etc/systemd/system + creates Postgres role). Try: sudo xtop hub init")
	}

	fmt.Println("xtop hub init — one-command fleet aggregator setup")
	fmt.Println()

	// ── Step 1: Postgres availability ─────────────────────────────────────
	if !opts.skipDB {
		fmt.Print("  • Postgres presence ........... ")
		if err := ensurePostgresReachable(); err != nil {
			fmt.Println("missing")
			printPostgresInstallHelp()
			return err
		}
		fmt.Println("ok")
	}

	// ── Step 2: generate secrets if not provided ──────────────────────────
	token := opts.token
	if token == "" {
		token = randomHex(24)
	}
	pgPass := opts.pgPassword
	if pgPass == "" {
		pgPass = randomHex(16)
	}
	listen := opts.listen
	if listen == "" {
		listen = fmt.Sprintf(":%d", model.FleetDefaultPort)
	}
	postgresDSN := opts.postgresDSN
	if postgresDSN == "" {
		postgresDSN = fmt.Sprintf("postgres://xtop:%s@127.0.0.1:5432/xtopfleet?sslmode=disable", pgPass)
	}

	// ── Step 3: Postgres role + database ──────────────────────────────────
	if !opts.skipDB {
		fmt.Print("  • Postgres role + database .... ")
		if err := ensurePostgresRoleAndDB("xtop", pgPass, "xtopfleet"); err != nil {
			fmt.Println("failed")
			return fmt.Errorf("postgres provisioning: %w", err)
		}
		fmt.Println("ok")
	}

	// ── Step 4: hub config ───────────────────────────────────────────────
	fmt.Print("  • Hub config written .......... ")
	cfgPath, err := writeHubConfig(model.FleetHubConfig{
		ListenAddr:  listen,
		AuthToken:   token,
		PostgresDSN: postgresDSN,
	})
	if err != nil {
		fmt.Println("failed")
		return err
	}
	fmt.Printf("%s\n", cfgPath)

	// ── Step 5: systemd unit ─────────────────────────────────────────────
	if !opts.noSystemd {
		fmt.Print("  • systemd unit installed ...... ")
		if err := writeHubSystemdUnit(); err != nil {
			fmt.Println("failed")
			return err
		}
		fmt.Println("ok")

		fmt.Print("  • Unit enabled + started ...... ")
		if err := reloadAndStart("xtop-hub"); err != nil {
			fmt.Println("failed")
			return err
		}
		fmt.Println("ok")

		// Health poll
		fmt.Print("  • /health probe ............... ")
		healthURL := fmt.Sprintf("http://127.0.0.1%s/health", listen)
		if err := pollHealth(healthURL, 10); err != nil {
			fmt.Println("timeout")
			fmt.Fprintln(os.Stderr, "\nHub didn't come up cleanly. Tail of the unit log:")
			_ = runShell("journalctl -u xtop-hub --no-pager -n 20")
			return err
		}
		fmt.Println("ok")
	}

	// ── Step 6: print next-steps summary ─────────────────────────────────
	printHubInitSuccess(listen, token, opts.noSystemd)
	return nil
}

// ── Flags ────────────────────────────────────────────────────────────────────

type hubInitOpts struct {
	skipDB      bool
	noSystemd   bool
	listen      string
	postgresDSN string
	token       string
	pgPassword  string
}

func parseHubInitFlags(args []string) hubInitOpts {
	var o hubInitOpts
	// Simple hand-rolled flag loop to keep the main runHub's flagset untouched.
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--skip-db":
			o.skipDB = true
		case a == "--no-systemd":
			o.noSystemd = true
		case a == "--listen" && i+1 < len(args):
			i++
			o.listen = args[i]
		case strings.HasPrefix(a, "--listen="):
			o.listen = strings.TrimPrefix(a, "--listen=")
		case a == "--postgres" && i+1 < len(args):
			i++
			o.postgresDSN = args[i]
		case strings.HasPrefix(a, "--postgres="):
			o.postgresDSN = strings.TrimPrefix(a, "--postgres=")
		case a == "--token" && i+1 < len(args):
			i++
			o.token = args[i]
		case strings.HasPrefix(a, "--token="):
			o.token = strings.TrimPrefix(a, "--token=")
		case a == "-h" || a == "--help":
			printHubInitUsage()
			os.Exit(0)
		}
	}
	return o
}

func printHubInitUsage() {
	fmt.Fprintln(os.Stderr, `xtop hub init — one-command fleet hub provisioning

Creates Postgres role+db, writes /root/.xtop/hub.json with a random auth
token, installs /etc/systemd/system/xtop-hub.service, enables + starts it,
and prints the join command you give to every agent.

Usage:
  sudo xtop hub init [flags]

Flags:
  --skip-db                 Don't touch Postgres (assume operator provisioned it).
  --no-systemd              Don't write/enable a systemd unit (config only).
  --listen :PORT            Override listen addr (default :9898).
  --postgres <DSN>          Use this DSN instead of generating a local one.
  --token <T>               Use this token instead of generating a random one.
  --help                    Show this help.

Re-running is safe: existing role/db are kept, existing systemd unit is
overwritten with the fresh token, service is restarted.`)
}

// ── Preflight ────────────────────────────────────────────────────────────────

// preflightHubInit catches avoidable failure modes early so the operator
// doesn't half-provision a host.
func preflightHubInit(opts hubInitOpts) error {
	// Reject empty token-only overrides — CLI-provided tokens must be
	// non-trivial so ops don't end up with "--token=x" by accident.
	if opts.token != "" && len(opts.token) < 16 {
		return fmt.Errorf("--token must be at least 16 chars; got %d", len(opts.token))
	}
	// --no-systemd implies the operator will start the hub manually, but the
	// config file still gets written. That's fine.
	// --skip-db implies the operator supplied a DSN via --postgres OR an
	// env var they expect runHub to pick up later.
	if opts.skipDB && opts.postgresDSN == "" {
		fmt.Fprintln(os.Stderr, "note: --skip-db without --postgres means you must set XTOP_HUB_POSTGRES before starting the hub")
	}
	return nil
}

// ── Postgres plumbing ────────────────────────────────────────────────────────

// ensurePostgresReachable returns nil only when `psql` is on PATH AND the
// local socket / 127.0.0.1:5432 accepts a connection. We don't discriminate
// between socket vs tcp — either works for the hub's typical DSN.
func ensurePostgresReachable() error {
	if _, err := exec.LookPath("psql"); err != nil {
		return fmt.Errorf("psql not on PATH; install postgresql-client + postgresql server first")
	}
	// Quick TCP probe — catches the "installed but not running" case.
	conn, err := net.Dial("tcp", "127.0.0.1:5432")
	if err != nil {
		return fmt.Errorf("no Postgres on 127.0.0.1:5432: %w", err)
	}
	_ = conn.Close()
	return nil
}

func printPostgresInstallHelp() {
	fmt.Fprint(os.Stderr, `
Postgres isn't installed (or isn't running on 127.0.0.1:5432).

Debian / Ubuntu:
  sudo apt install -y postgresql
  sudo systemctl enable --now postgresql

Fedora / Rocky / RHEL:
  sudo dnf install -y postgresql-server postgresql-contrib
  sudo postgresql-setup --initdb
  sudo systemctl enable --now postgresql

Arch:
  sudo pacman -S postgresql
  sudo -u postgres initdb -D /var/lib/postgres/data
  sudo systemctl enable --now postgresql

Docker (no system install):
  docker run -d --name xtop-pg -p 127.0.0.1:5432:5432 \
    -e POSTGRES_USER=xtop -e POSTGRES_PASSWORD=<secret> \
    -e POSTGRES_DB=xtopfleet postgres:16-alpine

Then re-run:  sudo xtop hub init
`)
}

// ensurePostgresRoleAndDB runs idempotent SQL via `sudo -u postgres psql`.
// The logic: CREATE ROLE if missing, then ALTER to set the fresh password
// every time so we don't stash a stale password in the config.
func ensurePostgresRoleAndDB(role, password, database string) error {
	// Using psql + heredoc so we don't have to depend on pgx at init time.
	// DO blocks guarantee idempotency without pre-SELECTs.
	sql := fmt.Sprintf(`
DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = %[1]s) THEN
        CREATE ROLE %[2]s LOGIN PASSWORD %[3]s;
    ELSE
        ALTER ROLE %[2]s WITH PASSWORD %[3]s;
    END IF;
END
$$;
SELECT 'CREATE DATABASE %[4]s OWNER %[2]s' WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = %[5]s)\gexec
GRANT ALL PRIVILEGES ON DATABASE %[4]s TO %[2]s;
`,
		sqlLiteral(role),        // [1] role name as string literal for WHERE clause
		sqlIdent(role),          // [2] role name as SQL identifier
		sqlLiteral(password),    // [3] password literal
		sqlIdent(database),      // [4] database name as identifier (for CREATE DATABASE / GRANT)
		sqlLiteral(database),    // [5] database name as string literal (for WHERE)
	)
	cmd := exec.Command("sudo", "-u", "postgres", "psql", "-v", "ON_ERROR_STOP=1")
	cmd.Stdin = strings.NewReader(sql)
	cmd.Stdout = nil
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("psql: %w", err)
	}
	return nil
}

// sqlIdent quotes an identifier for safe use in DDL (CREATE DATABASE "x").
// We only accept [A-Za-z0-9_] names here — all role/db names we construct
// are hard-coded to "xtop" / "xtopfleet", so this is just defense in depth.
func sqlIdent(name string) string {
	if !isSimpleIdent(name) {
		panic("refusing to use non-simple SQL identifier: " + name)
	}
	return "\"" + name + "\""
}

// sqlLiteral returns a string literal — caller uses it where SQL expects
// a quoted string constant (WHERE rolname = 'xtop', etc.).
func sqlLiteral(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "''") + "'"
}

func isSimpleIdent(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z') && !(r >= 'A' && r <= 'Z') &&
			!(r >= '0' && r <= '9') && r != '_' {
			return false
		}
	}
	return true
}

// ── Config + systemd ─────────────────────────────────────────────────────────

func writeHubConfig(cfg model.FleetHubConfig) (string, error) {
	if cfg.IncidentRetentionDays == 0 {
		cfg.IncidentRetentionDays = 30
	}
	if cfg.HeartbeatRetentionHours == 0 {
		cfg.HeartbeatRetentionHours = 48
	}
	path := "/root/.xtop/hub.json"
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return "", err
	}
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return "", err
	}
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	if err := enc.Encode(&cfg); err != nil {
		f.Close()
		os.Remove(tmp)
		return "", err
	}
	f.Close()
	if err := os.Chmod(tmp, 0o600); err != nil {
		os.Remove(tmp)
		return "", err
	}
	if err := os.Rename(tmp, path); err != nil {
		return "", err
	}
	return path, nil
}

const hubSystemdUnit = `[Unit]
Description=xtop fleet hub
After=network-online.target postgresql.service
Wants=postgresql.service network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/xtop hub
Restart=on-failure
RestartSec=5
StandardOutput=append:/var/log/xtop/hub.log
StandardError=append:/var/log/xtop/hub.log
# The hub opens /root/.xtop/hub.json which contains a shared secret — keep
# its own reads/writes private to root. It binds a network port; no other
# elevated capabilities required.
User=root

[Install]
WantedBy=multi-user.target
`

func writeHubSystemdUnit() error {
	// Ensure log directory exists so StandardOutput=append doesn't block
	// the unit from starting on a fresh host.
	if err := os.MkdirAll("/var/log/xtop", 0o755); err != nil {
		return err
	}
	return writeFileAtomic("/etc/systemd/system/xtop-hub.service", []byte(hubSystemdUnit), 0o644)
}

// reloadAndStart daemon-reloads systemd, enables + starts (or restarts) the
// given unit. Called from both hub and agent init.
func reloadAndStart(unit string) error {
	if err := runShell("systemctl daemon-reload"); err != nil {
		return err
	}
	if err := runShell("systemctl enable " + unit); err != nil {
		return err
	}
	// restart so re-runs pick up config changes without a stop+start dance.
	return runShell("systemctl restart " + unit)
}

// ── Success summary ─────────────────────────────────────────────────────────

func printHubInitSuccess(listen, token string, noSystemd bool) {
	port, boundIP := splitListen(listen)

	// Gather + split candidate IPs into "primary" (LAN/WAN/wifi/VPN) and
	// "local-only" (docker / libvirt / container bridges). Primary IPs are
	// what agents on other hosts will use; local-only only make sense for
	// same-box agents, so we still print them but behind a dim divider.
	var primary, local []reachableIP
	if boundIP != "" {
		primary = []reachableIP{{Interface: "(bound)", IP: boundIP, Label: "explicit"}}
	} else {
		for _, r := range detectReachableIPs() {
			switch r.Label {
			case "container", "libvirt":
				local = append(local, r)
			default:
				primary = append(primary, r)
			}
		}
	}

	// Pick a single "primary URL" for the compact summary block. Prefer a
	// WAN address (only one typically exists) so the dashboard link is the
	// publicly-reachable one. Falls back to the first LAN, then loopback.
	pickURL := func() string {
		for _, r := range primary {
			if r.Label == "wan" {
				return "http://" + r.IP + ":" + port
			}
		}
		if len(primary) > 0 {
			return "http://" + primary[0].IP + ":" + port
		}
		return "http://127.0.0.1:" + port
	}
	primaryURL := pickURL()

	fmt.Println()
	fmt.Println(B + "xtop hub is live." + R)
	fmt.Println()
	fmt.Printf("  Web dashboard:   %s%s/%s\n", FBCyn, primaryURL, R)
	fmt.Printf("  Health:          curl %s/health\n", primaryURL)
	fmt.Printf("  Config:          /root/.xtop/hub.json  (token inside, chmod 600)\n")
	if !noSystemd {
		fmt.Printf("  Unit status:     systemctl status xtop-hub\n")
		fmt.Printf("  Logs:            journalctl -u xtop-hub -f   or   tail -f /var/log/xtop/hub.log\n")
	}

	// ── Ready-to-run agent commands ─────────────────────────────────────
	// This is the last thing on screen so operators can copy-paste the
	// bottom of their terminal. Each candidate gets a complete, bolded,
	// one-shot install command.
	fmt.Println()
	fmt.Println(B + "━━━━━━━━━━━━  AGENT INSTALL  ━━━━━━━━━━━━" + R)
	fmt.Println("Pick the URL your agent can reach, then paste the full command on that agent:")
	fmt.Println()

	if len(primary) == 0 && len(local) == 0 {
		fmt.Printf("  %ssudo xtop agent init --hub=http://127.0.0.1:%s --token=%s%s\n",
			B, port, token, R)
		fmt.Println()
		fmt.Println("  (no non-loopback IPv4 detected; bind explicitly with --listen=IP:PORT if needed)")
		return
	}

	for _, r := range primary {
		fmt.Println(dimStyle("  # " + r.Interface + "  " + r.Label + "  →  " + r.IP))
		fmt.Printf("  %ssudo xtop agent init --hub=http://%s:%s --token=%s%s\n\n",
			B, r.IP, port, token, R)
	}
	if len(local) > 0 {
		fmt.Println(dimStyle("  ─── container / libvirt bridges (same-host agents only) ───"))
		for _, r := range local {
			fmt.Println(dimStyle("  # " + r.Interface + "  " + r.Label + "  →  " + r.IP))
			fmt.Printf("  %ssudo xtop agent init --hub=http://%s:%s --token=%s%s\n\n",
				B, r.IP, port, token, R)
		}
	}
}

// dimStyle wraps a string in the existing FDim/R envelope for readability —
// lets us keep this file stdlib-fmt-only without pulling the lipgloss
// helper from ui/.
func dimStyle(s string) string { return FDim + s + R }

// splitListen parses listen strings like ":9898" or "10.0.0.5:9898" into
// (port, bound-ip). bound-ip is "" when listening on all interfaces.
func splitListen(listen string) (port, ip string) {
	listen = strings.TrimSpace(listen)
	if listen == "" {
		return fmt.Sprintf("%d", model.FleetDefaultPort), ""
	}
	if strings.HasPrefix(listen, ":") {
		return strings.TrimPrefix(listen, ":"), ""
	}
	// "ip:port" form
	host, p, err := net.SplitHostPort(listen)
	if err != nil {
		return fmt.Sprintf("%d", model.FleetDefaultPort), ""
	}
	return p, host
}

// reachableIP is one candidate address the hub can be reached on. The name
// is the interface name (eth0 / enX3 / wg0 / …); operators scanning the
// join list can pick the interface that matches their fleet topology.
type reachableIP struct {
	Interface string
	IP        string
	Label     string // short hint: "LAN", "WAN", "Wireguard", "Docker" …
}

// detectReachableIPs enumerates every up, non-loopback IPv4 address on this
// host. Docker/libvirt/Kubernetes bridge interfaces are included but
// labeled so the operator can tell LAN from overlay. Returns empty slice
// only when the box genuinely has no non-loopback IPv4 — the wizard falls
// back to the hostname display in that edge case.
func detectReachableIPs() []reachableIP {
	var out []reachableIP
	ifaces, err := net.Interfaces()
	if err != nil {
		return out
	}
	for _, ifi := range ifaces {
		// Skip interfaces that aren't operationally up. Point-to-point
		// links kept up but with no carrier will report FlagUp but no
		// addresses — that case is filtered below by the addr loop.
		if ifi.Flags&net.FlagUp == 0 || ifi.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := ifi.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			ip, _, err := net.ParseCIDR(a.String())
			if err != nil {
				continue
			}
			if ip.IsLoopback() || ip.IsLinkLocalUnicast() {
				continue
			}
			if ip.To4() == nil { // IPv4 only — join URLs with bare IPv6 need brackets
				continue
			}
			out = append(out, reachableIP{
				Interface: ifi.Name,
				IP:        ip.String(),
				Label:     classifyInterface(ifi.Name, ip),
			})
		}
	}
	return out
}

// classifyInterface returns a one-word hint for the join-command list. The
// logic is conservative — we're not trying to be clever; we just want the
// operator to instantly tell LAN from a Docker bridge.
func classifyInterface(name string, ip net.IP) string {
	low := strings.ToLower(name)
	switch {
	case strings.HasPrefix(low, "docker"),
		strings.HasPrefix(low, "br-"),
		strings.HasPrefix(low, "veth"),
		strings.HasPrefix(low, "cni"),
		strings.HasPrefix(low, "flannel"),
		strings.HasPrefix(low, "cali"),
		strings.HasPrefix(low, "weave"):
		return "container"
	case strings.HasPrefix(low, "wg"):
		return "wireguard"
	case strings.HasPrefix(low, "tun"), strings.HasPrefix(low, "tap"):
		return "vpn"
	case strings.HasPrefix(low, "virbr"), strings.HasPrefix(low, "vnet"):
		return "libvirt"
	case strings.HasPrefix(low, "wl"):
		return "wifi"
	}
	// For physical-ish interfaces (eth*, ens*, enX*, en0…) label by
	// address class. RFC1918 is almost always the LAN; public addresses
	// are the WAN.
	if ip.IsPrivate() {
		return "lan"
	}
	return "wan"
}

// ── Tiny utilities ──────────────────────────────────────────────────────────

func randomHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "change-me-" + fmt.Sprintf("%x", os.Getpid())
	}
	return hex.EncodeToString(b)
}

func writeFileAtomic(path string, data []byte, mode os.FileMode) error {
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	f.Close()
	return os.Rename(tmp, path)
}

func runShell(cmd string) error {
	c := exec.Command("sh", "-c", cmd)
	c.Stdout = os.Stdout
	c.Stderr = os.Stderr
	return c.Run()
}
