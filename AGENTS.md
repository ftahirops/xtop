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
