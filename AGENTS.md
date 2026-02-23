# Repository Guidelines

## Project Structure & Module Organization
- `main.go` boots the application and wires the CLI.
- `cmd/` contains CLI commands (`root.go`, `monitor/`, `watch.go`).
- `collector/` gathers system signals (CPU, memory, disk, network, PSI, eBPF, cgroup, etc.).
- `engine/` runs analysis, scoring, anomaly detection, and event logging.
- `model/` defines shared data structures (metrics, snapshots, events).
- `ui/` holds TUI layouts, pages, and styling.
- `demos/` provides incident simulation scripts for manual testing.
- `packaging/` includes packaging assets (e.g., .deb metadata).
- `xtop` is a built binary (do not edit; regenerate via build).

## Build, Test, and Development Commands
- `go build -ldflags="-s -w" -o xtop .` builds the optimized binary in the repo root.
- `go build ./...` verifies all packages compile.
- `go vet ./...` runs Go’s static analyzer.
- `sudo xtop` runs the full TUI (root recommended for `/proc/*/io` and eBPF).
- `sudo xtop -watch` runs CLI mode without TUI.
- `sudo xtop -json | jq` outputs JSON for scripting.

## Coding Style & Naming Conventions
- Follow standard Go formatting (`gofmt -w`), and keep imports grouped by `gofmt`.
- Package names are short and lowercase (`engine`, `collector`).
- Files use lowercase names with underscores for pages and features (e.g., `page_diskguard.go`).
- Types and exported identifiers use `CamelCase`; unexported use `camelCase`.

## Testing Guidelines
- No `_test.go` files or test framework are currently present.
- If adding tests, use Go’s `testing` package and run `go test ./...`.
- Keep tests close to implementation (same package) and name files `*_test.go`.

## Commit & Pull Request Guidelines
- Recent commit messages follow a release style: `xtop v0.6.1 — Security fixes, bug fixes, and trigger-based scanning`.
- For feature work, use a concise summary and a short rationale.
- PRs should include: purpose, affected areas (e.g., `collector/`, `ui/`), and how you validated changes (`go build ./...`, `go vet ./...`, manual run commands).

## Security & Configuration Tips
- Root is recommended to access full `/proc` data and run eBPF probes.
- PSI and eBPF features require a Linux kernel with BTF and `/sys/kernel/btf/vmlinux`.
