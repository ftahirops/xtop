# xtop Engine TODO Triage

Tracked items sourced from `// TODO` / `// FIXME` markers in `engine/`.
Each entry below corresponds to one source comment; the originals are kept in place.

| ID | File:Line | Description |
|----|-----------|-------------|
| TODO-1a | engine/baseline_persist.go:9 | Bridge in-memory Welford stores (app baselines + drift detector) to SQLite so baseline state survives restart |
| TODO-1b | engine/daemon.go:134 | Load persisted Welford state for app baselines + drift detector on daemon startup |
| TODO-1c | engine/baseline_app.go:46 | Persist per-app Welford trackers to `~/.xtop/store.db` so app baselines survive restart |
| TODO-1d | engine/baseline_app.go:130 | Persist baselines to SQLite (`store/`) so they survive process restart |
| TODO-drift | engine/drift.go:37 | Persist config drift detector state to `~/.xtop/store.db` so drift history survives restart |
| TODO-4 | engine/probes.go:99 | Implement minimum-viable eBPF-backed probe set (probe the host for `bpftrace` first, then fall back) |
| TODO-5 | engine/fleet_client.go:572 | Populate recorder lifecycle state from the result-echo of recorder state |
| TODO-6 | engine/trace.go:197 | Implement "what can this trace rule out?" OTel-trace reasoning block |

## Notes

- TODO-1a/1b/1c/1d are all facets of the same work item: persisting in-memory statistical
  state (Welford online mean/variance trackers) to SQLite so the adaptive baseline survives
  daemon restarts.  Implement as a single unit in `store/`.
- TODO-drift is a companion to the above: the `ConfigDriftDetector` also needs a persistent
  store so it can detect drift across restarts, not just within a single session.
- TODO-4 (eBPF probes) is gated on availability of `bpftrace` or a compatible eBPF loader;
  it should probe at startup and degrade gracefully when unavailable.
- TODO-5 and TODO-6 are independent of each other and of the baseline work.
