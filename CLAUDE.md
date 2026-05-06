# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

See also `AGENTS.md` — it is authoritative for build/version/packaging mechanics. This file complements it with the architecture orientation Claude needs to be productive quickly.

## Project shape

- Linux-only Go project, single module `github.com/ftahirops/xtop`, Go 1.25.
- `xtop` is a Linux performance console with an RCA engine — it identifies *why* a system is slow, not just *what* is slow. Bubbletea TUI + collectors over `/proc`, `/sys`, cgroups, eBPF, and app-protocol parsers.
- Most files are `//go:build linux`; on non-Linux you get stubs. Always build with `CGO_ENABLED=0`.

## Build / test / vet

```bash
# Main binary
CGO_ENABLED=0 go build -ldflags="-s -w -X github.com/ftahirops/xtop/cmd.Version=X.Y.Z" -o xtop .

# Lean fleet agent (intentionally smaller import graph — no Bubbletea/lipgloss)
CGO_ENABLED=0 go build -ldflags="-s -w -X main.Version=X.Y.Z" -o xtop-agent ./cmd/xtop-agent

go test ./...
go vet ./...                # the only lint gate; no CI, no Makefile
sudo bash tests/rca_live_test.sh   # integration RCA test, requires root
```

Run a single test: `go test ./engine -run TestRCAScoring -v`

## Version bumps drift easily — update together

1. `cmd/root.go` → `var Version = "X.Y.Z"`
2. `packaging/archlinux/PKGBUILD` → `pkgver=X.Y.Z`
3. `packaging/xtop_X.Y.Z-1_amd64/DEBIAN/control` → `Version:`
4. README and any docs with hardcoded version in build commands

Packaging: place binaries in `packaging/xtop_X.Y.Z-1_amd64/usr/local/bin/`, then `dpkg-deb --build ...`. RPM via `packaging/rpm-build.sh [VERSION]` (uses `alien`).

## Architecture (the parts that span multiple files)

| Dir | Role |
|---|---|
| `cmd/` | CLI flags, subcommands, TUI bootstrap. `root.go` is main entry. |
| `collector/` | `/proc`, `/sys`, cgroup, eBPF, app-protocol parsers — Linux-specific. |
| `engine/` | RCA scoring, anomaly detection, narratives, forecasting, fleet client. |
| `ui/` | Bubbletea TUI pages and layouts (17 pages, 6 overview layouts). |
| `model/` | Shared structs: `Snapshot`, `AnalysisResult`, metrics. |
| `fleet/` | Hub HTTP API + web dashboard at `:9898`. |
| `identity/` | Service discovery (MySQL, Redis, Docker, K8s, ELK, JVM, Node, …). |
| `store/` | Persistence. |
| `packaging/hub/` | Docker Compose for fleet hub (Postgres + hub container). |

### Three entry points

- `main.go` → full `xtop` TUI binary
- `cmd/xtop-agent/main.go` → headless fleet agent (kept lean by deliberately not importing `ui/` etc.)
- `cmd/monitor/main.go` → daemon mode

When adding code, be careful not to import heavy packages (Bubbletea, lipgloss, `ui/`) into paths reachable from `xtop-agent` — that bloat is what the split is preventing.

### Data flow

`collector/` produces a `model.Snapshot` per tick → `engine/` scores it into an `AnalysisResult` (bottlenecks, evidence checks, narrative, blame, forecasts) → `ui/` renders, or `fleet/` ships it to the hub. RCA is the product; collectors and UI are means to an end.

### eBPF

Uses `cilium/ebpf` (pure Go, no CGo, no clang at runtime). Generated BPF ELFs are checked in as `collector/ebpf/*_bpfel.go` — **do not hand-edit**; regenerate from the C sources.

## Repo conventions

- No CI, no GitHub workflows, no pre-commit hooks, no linter config beyond `go vet`.
- `WHYTOP_ANALYSIS.md` and `.opencode/` are gitignored agent scratch — ignore them.
- `demos/` contains root-requiring stress scripts used to live-test the RCA engine.
- Collector startup is concurrent and resource-throttled (Resource Guardian); when adding a collector, respect the skip-on-pressure pattern and avoid blocking subprocesses without timeouts (see `SecurityCollector`'s 2s `w` timeout for precedent).
