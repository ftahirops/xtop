package model

import "time"

// ─── Fleet protocol — wire types shared by agent and hub ─────────────────────
//
// Design goals:
//   - Heartbeat is small (~500 bytes) so agents can push it every tick cheaply.
//   - Incident payload is richer — sent once per incident, not per tick.
//   - All timestamps are UTC RFC3339 for cross-timezone correctness.
//   - All types are JSON-serializable directly (no custom marshalers).

// FleetHeartbeat is the small per-tick payload from agent → hub.
// Sent every collection tick (default 3s). ~500 bytes per host.
type FleetHeartbeat struct {
	// Identity
	Hostname string   `json:"hostname"`
	AgentID  string   `json:"agent_id"` // stable UUID persisted in ~/.xtop/agent-id
	Tags     []string `json:"tags,omitempty"`

	// Versions
	AgentVersion string `json:"agent_version"`
	Kernel       string `json:"kernel,omitempty"`
	OS           string `json:"os,omitempty"`

	// Timestamp
	Timestamp time.Time `json:"timestamp"`

	// Health summary
	Health           HealthLevel `json:"health"`
	PrimaryBottleneck string     `json:"primary_bottleneck,omitempty"`
	PrimaryScore     int         `json:"primary_score"`
	Confidence       int         `json:"confidence"`

	// Top culprit (if any)
	CulpritProcess string `json:"culprit_process,omitempty"`
	CulpritPID     int    `json:"culprit_pid,omitempty"`
	CulpritApp     string `json:"culprit_app,omitempty"`

	// Compact metric summary (for fleet-wide sparklines on hub)
	CPUBusyPct    float64 `json:"cpu_busy_pct"`
	MemUsedPct    float64 `json:"mem_used_pct"`
	IOWorstUtil   float64 `json:"io_worst_util"`
	LoadAvg1      float64 `json:"load_avg_1"`
	NumCPUs       int     `json:"num_cpus"`
	MemTotalBytes uint64  `json:"mem_total_bytes"`

	// Incident cross-ref (set when this tick is part of an ongoing incident)
	ActiveIncidentID string `json:"active_incident_id,omitempty"`

	// Self-resource reporting — xtop's own footprint on the agent host.
	// The web dashboard renders these inline on the host card so operators
	// can verify at a glance that the observability tool isn't competing
	// with the workload it's observing. Zero-valued when the guardian is
	// disabled (XTOP_GUARD off) — UIs should hide the row in that case.
	XtopOwnCPUPct  float64 `json:"xtop_cpu_pct,omitempty"`
	XtopOwnRSSMB   float64 `json:"xtop_rss_mb,omitempty"`
	XtopGuardLevel int     `json:"xtop_guard_level,omitempty"`
	XtopMode       string  `json:"xtop_mode,omitempty"` // "lean" or "rich"
}

// FleetIncident is the richer payload sent once when an incident starts
// (and again when it changes — e.g., bottleneck domain flips, or confidence jumps).
// Typical size: 5-30 KB depending on evidence + process list.
type FleetIncident struct {
	// Identity (same as heartbeat)
	Hostname string `json:"hostname"`
	AgentID  string `json:"agent_id"`

	// Incident ID — stable across status updates of the same incident.
	// Format: "{hostname}-{unix_sec_start}-{short_signature_hash}"
	IncidentID string `json:"incident_id"`

	// Timestamps
	StartedAt   time.Time  `json:"started_at"`
	ResolvedAt  *time.Time `json:"resolved_at,omitempty"` // nil while active
	Timestamp   time.Time  `json:"timestamp"`              // when this payload was generated

	// Core diagnosis
	Bottleneck string `json:"bottleneck"`
	PeakScore  int    `json:"peak_score"`
	Confidence int    `json:"confidence"`
	Health     HealthLevel `json:"health"`
	Pattern    string `json:"pattern,omitempty"`

	// Culprit
	Culprit    string `json:"culprit,omitempty"`
	CulpritPID int    `json:"culprit_pid,omitempty"`
	CulpritApp string `json:"culprit_app,omitempty"`

	// Narrative
	RootCause string   `json:"root_cause,omitempty"`
	Evidence  []string `json:"evidence,omitempty"`
	Impact    string   `json:"impact,omitempty"`

	// Signature — stable hash of (bottleneck + top-3 evidence IDs) for
	// cross-incident similarity matching.
	Signature string `json:"signature"`

	// Context at incident peak: top 10 CPU/memory/IO processes.
	// Smaller than full snapshot but enough for drill-down.
	TopProcesses []FleetProcess `json:"top_processes,omitempty"`

	// Raw evidence list for hub-side re-analysis (optional — only sent if
	// FleetClient.IncludeRawEvidence is set).
	RawEvidence []Evidence `json:"raw_evidence,omitempty"`

	// Structured diff vs prior similar incidents on this host. Nil when this
	// signature hasn't been seen before. Lets hub UIs show "this is worse/milder
	// than usual" and "new signals firing" without recomputing.
	Diff *IncidentDiff `json:"diff,omitempty"`

	// Update type — lets hub distinguish new incidents from updates
	UpdateType IncidentUpdateType `json:"update_type"`
}

// IncidentUpdateType signals what kind of update the hub is receiving.
type IncidentUpdateType string

const (
	IncidentStarted    IncidentUpdateType = "started"
	IncidentUpdated    IncidentUpdateType = "updated"    // confidence/score changed, same bottleneck
	IncidentEscalated  IncidentUpdateType = "escalated"  // bottleneck changed while incident still active
	IncidentResolved   IncidentUpdateType = "resolved"   // health returned to OK
)

// FleetProcess is a lightweight process record for fleet-wide incident context.
type FleetProcess struct {
	PID    int     `json:"pid"`
	Comm   string  `json:"comm"`
	CPUPct float64 `json:"cpu_pct"`
	RSS    uint64  `json:"rss"`
	State  string  `json:"state,omitempty"`
}

// FleetHost is the hub-side state for a single agent.
// This is what the TUI / web UI reads to render the fleet table.
type FleetHost struct {
	Hostname     string    `json:"hostname"`
	AgentID      string    `json:"agent_id"`
	Tags         []string  `json:"tags,omitempty"`
	AgentVersion string    `json:"agent_version"`
	Kernel       string    `json:"kernel,omitempty"`
	OS           string    `json:"os,omitempty"`

	// Connection liveness
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
	Status    HostStatus `json:"status"` // live / stale / expired

	// Latest health snapshot (from last heartbeat)
	Health            HealthLevel `json:"health"`
	PrimaryBottleneck string      `json:"primary_bottleneck,omitempty"`
	PrimaryScore      int         `json:"primary_score"`
	Confidence        int         `json:"confidence"`
	CulpritProcess    string      `json:"culprit_process,omitempty"`
	CulpritApp        string      `json:"culprit_app,omitempty"`

	// Latest metrics
	CPUBusyPct  float64 `json:"cpu_busy_pct"`
	MemUsedPct  float64 `json:"mem_used_pct"`
	IOWorstUtil float64 `json:"io_worst_util"`
	LoadAvg1    float64 `json:"load_avg_1"`
	NumCPUs     int     `json:"num_cpus"`

	// Active incident, if any
	ActiveIncidentID string `json:"active_incident_id,omitempty"`

	// Mirrored self-resource fields (latest known) so UIs can show xtop's
	// own footprint per host without joining against heartbeats.
	XtopOwnCPUPct  float64 `json:"xtop_cpu_pct,omitempty"`
	XtopOwnRSSMB   float64 `json:"xtop_rss_mb,omitempty"`
	XtopGuardLevel int     `json:"xtop_guard_level,omitempty"`
	XtopMode       string  `json:"xtop_mode,omitempty"`
}

// HostStatus reflects the liveness of an agent relative to its expected interval.
type HostStatus string

const (
	HostStatusLive    HostStatus = "live"    // seen within 3× interval
	HostStatusStale   HostStatus = "stale"   // seen >3× interval ago, <10min
	HostStatusExpired HostStatus = "expired" // >10min since last seen
)

// ─── Protocol endpoints (documentation / constants) ──────────────────────────

const (
	// POST: agent → hub, per tick
	FleetEndpointHeartbeat = "/v1/heartbeat"

	// POST: agent → hub, on incident start / update / resolve
	FleetEndpointIncident = "/v1/incident"

	// GET: UI / agent → hub, list all known hosts
	FleetEndpointHosts = "/v1/hosts"

	// GET: UI → hub, get one host's latest state
	FleetEndpointHost = "/v1/host/" // + hostname

	// GET: UI → hub, list recent incidents across fleet
	FleetEndpointIncidents = "/v1/incidents"

	// GET: UI → hub, stream events (SSE)
	FleetEndpointStream = "/v1/stream"

	// Auth header — agent sends its token here
	FleetAuthHeader = "X-XTop-Token"

	// Default hub listen port. Chosen to avoid collisions with common services
	// (Prometheus 9100, Elasticsearch 9200, Grafana 3000). Override at runtime
	// with `xtop hub --listen=:NNNN` or `XTOP_HUB_LISTEN=:NNNN`.
	FleetDefaultPort = 9898
)

// FleetHubConfig holds the hub-side configuration (loaded from ~/.xtop/hub.json).
type FleetHubConfig struct {
	ListenAddr string `json:"listen_addr"` // default ":9200"
	TLSCert    string `json:"tls_cert,omitempty"`
	TLSKey     string `json:"tls_key,omitempty"`
	AuthToken  string `json:"auth_token"` // shared secret for all agents

	// Postgres connection (e.g. "postgres://xtop:pw@localhost/xtopfleet")
	PostgresDSN string `json:"postgres_dsn"`

	// SQLite hot cache path (default ~/.xtop/hub-cache.sqlite)
	SQLiteCachePath string `json:"sqlite_cache_path,omitempty"`

	// Retention (default 30d)
	IncidentRetentionDays int `json:"incident_retention_days,omitempty"`
	HeartbeatRetentionHours int `json:"heartbeat_retention_hours,omitempty"`
}

// FleetAgentConfig holds the agent-side fleet config (loaded from ~/.xtop/fleet.json
// or via --fleet-hub / --fleet-token flags).
type FleetAgentConfig struct {
	HubURL       string   `json:"hub_url"`       // e.g. "https://hub.example:9200"
	Token        string   `json:"token"`         // auth token
	Tags         []string `json:"tags,omitempty"`
	QueuePath    string   `json:"queue_path,omitempty"` // offline queue, default ~/.xtop/fleet-queue.jsonl
	MaxQueueSize int      `json:"max_queue_size,omitempty"` // default 10_000
	// InsecureSkipVerify allows self-signed certs for the hub (default true for
	// first-run ease; flip off in prod).
	InsecureSkipVerify bool `json:"insecure_skip_verify,omitempty"`
}
