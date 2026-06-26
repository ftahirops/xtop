# AGENTS.md — xtop

Linux-only Go project. Single module (`github.com/ftahirops/xtop`), Go 1.25.

## Build

```bash
# Main binary (full TUI + hub + fleet)
CGO_ENABLED=0 go build -ldflags="-s -w -X github.com/ftahirops/xtop/cmd.Version=0.46.0" -o xtop .

# Fleet agent (lean, no Bubbletea/lipgloss/app modules — ~14 MB)
CGO_ENABLED=0 go build -ldflags="-s -w -X main.Version=0.46.0" -o xtop-agent ./cmd/xtop-agent
```

- **Always `CGO_ENABLED=0`** — expected everywhere (docs, PKGBUILD, README).
- Many files use `//go:build linux`; building on non-Linux produces stubs.

## Version bumps

Update **all** of these together — they drift easily:
1. `cmd/root.go` — `var Version = "X.Y.Z"`
2. `packaging/archlinux/PKGBUILD` — `pkgver=X.Y.Z`
3. `packaging/xtop_X.Y.Z-1_amd64/DEBIAN/control` — `Version:` field
4. README / docs examples that hardcode version in build commands

## Test & verify

```bash
go test ./...
go vet ./...
```

- Standard Go tests only; no custom test harness.
- Integration / live RCA test (requires **root** + Go toolchain):
  ```bash
  sudo bash tests/rca_live_test.sh
  ```
- There is no CI, Makefile, or linter config — `go vet ./...` is the gate.

## Packaging workflow

1. Build binaries and place into `packaging/xtop_X.Y.Z-1_amd64/usr/local/bin/`
2. Update `DEBIAN/control` version
3. `dpkg-deb --build packaging/xtop_X.Y.Z-1_amd64`
4. RPM: `packaging/rpm-build.sh [VERSION]` (converts deb with `alien`)

## Architecture notes

| Directory | Purpose |
|---|---|
| `cmd/` | CLI flags, subcommands, TUI bootstrap. `root.go` is the main entry. |
| `collector/` | `/proc`, `/sys`, cgroup, eBPF, app-protocol parsers. Heavy on Linux-specific code. |
| `engine/` | RCA scoring, anomaly detection, narratives, forecasting, fleet client. |
| `ui/` | Bubbletea TUI pages and layouts. |
| `model/` | Shared structs (`Snapshot`, `AnalysisResult`, metrics). |
| `fleet/` | Hub HTTP API + web dashboard. |
| `identity/` | Service discovery (MySQL, Redis, Docker, K8s, etc.). |
| `api/` | Small HTTP client/server helpers. |
| `store/` | Persistence layer. |
| `packaging/hub/` | Docker Compose for fleet hub (Postgres + hub container). |

### Multiple entry points

- `main.go` → full `xtop` binary
- `cmd/xtop-agent/main.go` → headless fleet agent (smaller import graph by design)
- `cmd/monitor/main.go` → daemon mode entry

### eBPF

- Uses `cilium/ebpf` (pure Go, no CGo, no clang at runtime).
- Generated BPF ELFs live in `collector/ebpf/` (`*_bpfel.go`). Do not hand-edit.

## Repo conventions

- No issue tracker automation, no pre-commit hooks, no `.github/workflows/`.
- `WHYTOP_ANALYSIS.md` and `.opencode/` are in `.gitignore` — agent workspace noise.
- `demos/` contains root-requiring stress scripts for live testing RCA.

## Journal RCA feature

xtop classifies systemd journal errors into structured findings at two tiers:

| Tier | Where | What |
|---|---|---|
| Tier-2 (collector) | `collector/journal/` → `model.Snapshot.Global.Logs.Services[].Findings` | Per-service `[]model.JournalFinding` produced by `journal.Classify()` |
| Tier-1 (engine) | `engine/journal_tier1.go` → `model.AnalysisResult.JournalFindings` | Aggregated `[]model.DiagFinding{Category:"logs"}` injected into the RCA chain |
| TUI surface | `ui/page_diag.go` (Service Diagnostics page) | Journal findings rendered per service with severity badge, label, count, sample |

### Signature taxonomy

| Signature | Severity | Triggers |
|---|---|---|
| `crash_restart_loop` | CRIT | "main process exited", "start request repeated too quickly" |
| `oom_killed` | CRIT | "out of memory: killed process", "oom-kill" |
| `segfault_panic` | CRIT | "segfault at", "panic:", "fatal error:" |
| `resource_exhaustion` | WARN | "too many open files", "no space left", "pool exhausted" |
| `dependency_failure` | WARN | "connection refused", "timeout connecting", "tls handshake" |
| `config_auth_error` | WARN | "permission denied", "invalid configuration", "failed to bind" |
| `error_rate_spike` | WARN | high-priority log count > 3× baseline rate |

### `--journal-rca` flag

`--journal-rca=critical|all|off` (default: `critical`) — controls which tiers report findings:
- `critical`: only Tier-1 crit findings promote to the RCA chain
- `all`: warn-level findings are also promoted
- `off`: journal analysis disabled

### Dashboard note

Journal findings do not yet flow through the fleet heartbeat/incident payload (`model.FleetHeartbeat`, `model.FleetIncident`). Surfacing them in the fleet web dashboard requires extending those structs — deferred to a follow-up task.

## Logging convention

| Package | Logger |
|---|---|
| `fleet/` | `log/slog` (stdlib, no extra deps). Default handler set to `slog.NewTextHandler(os.Stderr, nil)` at service startup. |
| `engine/daemon.go` | `log/slog` — same convention, set at `RunDaemon` entry. |
| `collector/`, `engine/` (non-daemon) | stdlib `log` for now — do not churn these to avoid noisy diffs. |

New log lines in `fleet/` and `engine/daemon.go` must use `slog`; existing `log.Printf` calls elsewhere are left as-is until a dedicated cleanup pass.
