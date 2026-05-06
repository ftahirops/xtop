package model

import "time"

// Snapshot holds a point-in-time system state.
type Snapshot struct {
	HostID           string    // unique identifier for this host (hostname or user-configured)
	Timestamp        time.Time
	Global           GlobalMetrics
	Cgroups          []CgroupMetrics
	Processes        []ProcessMetrics
	SysInfo          *SysInfo
	Errors           []string
	CollectionHealth *CollectionHealth
}

// HealthLevel represents overall system health.
type HealthLevel int

const (
	HealthOK            HealthLevel = 0
	HealthInconclusive  HealthLevel = 1
	HealthDegraded      HealthLevel = 2
	HealthCritical      HealthLevel = 3
)

func (h HealthLevel) String() string {
	switch h {
	case HealthOK:
		return "OK"
	case HealthInconclusive:
		return "INCONCLUSIVE"
	case HealthDegraded:
		return "DEGRADED"
	case HealthCritical:
		return "CRITICAL"
	}
	return "UNKNOWN"
}

// HostIncident holds cross-host correlation data for a single peer host.
type HostIncident struct {
	HostID            string
	Health            HealthLevel
	PrimaryBottleneck string
	PrimaryScore      int
	Timestamp         time.Time
	EvidenceIDs       []string
}

// Warning represents an early-warning signal.
type Warning struct {
	Severity string // "info", "warn", "crit"
	Signal   string // short label
	Detail   string // explanation
	Value    string // current value string
}

// Action is a suggested remediation.
type Action struct {
	Summary string
	Command string // optional runnable command
}

// Capacity represents headroom for one resource.
type Capacity struct {
	Label   string
	Pct     float64 // % remaining (0-100)
	Current string  // current value string
	Limit   string  // limit/max string
}

// Owner represents a top resource consumer.
type Owner struct {
	Name    string
	CgPath  string
	PID     int
	Pct     float64 // share of total
	Value   string
}

// MountRate holds computed per-filesystem rates.
type MountRate struct {
	MountPoint        string
	Device            string
	FSType            string
	TotalBytes        uint64
	UsedPct           float64
	FreePct           float64
	FreeBytes         uint64
	InodeUsedPct      float64
	GrowthBytesPerSec float64   // EWMA-smoothed
	PrevGrowthBPS     float64   // previous tick's smoothed rate (for trend detection)
	ETASeconds        float64   // seconds until full (-1 = not growing)
	GrowthStarted     time.Time // when sustained growth first detected
	State             string    // "OK", "WARN", "CRIT"
}

// DiskRate holds computed per-device rates.
type DiskRate struct {
	Name         string
	ReadMBs      float64
	WriteMBs     float64
	ReadIOPS     float64
	WriteIOPS    float64
	AvgAwaitMs   float64
	UtilPct      float64
	QueueDepth   uint64
}

// NetRate holds computed per-interface rates.
type NetRate struct {
	Name       string
	RxMBs      float64
	TxMBs      float64
	RxPPS      float64
	TxPPS      float64
	RxDropsPS  float64
	TxDropsPS  float64
	RxErrorsPS float64
	TxErrorsPS float64

	// Metadata (passed through from NetworkStats)
	OperState string // "up", "down", "unknown"
	SpeedMbps int    // -1 if unknown
	Master    string // bridge/bond master name
	IfType    string // "physical", "bridge", "bond", "veth", etc.

	// Computed
	UtilPct float64 // link utilization % ((RxMBs+TxMBs)*8*1024/SpeedMbps*100), -1 if unknown
}

// CgroupRate holds computed per-cgroup rates.
type CgroupRate struct {
	Path         string
	Name         string
	CPUPct       float64
	ThrottlePct  float64
	MemPct       float64
	IORateMBs    float64
	IOWRateMBs   float64
	OOMKillDelta uint64 // OOM kills since last tick (delta, not cumulative)
}

// ProcessRate holds computed per-process rates.
type ProcessRate struct {
	PID          int
	Comm         string
	State        string
	CgroupPath   string
	ServiceName  string // resolved from cgroup: k8s pod, systemd unit, or docker container
	CPUPct       float64
	MemPct       float64
	ReadMBs      float64
	WriteMBs     float64
	FaultRate    float64
	MajFaultRate float64
	CtxSwitchRate float64
	RSS          uint64
	VmSwap       uint64
	NumThreads   int
	FDCount      int
	FDSoftLimit  uint64
	FDPct        float64 // FDCount / FDSoftLimit * 100
	WritePath    string  // primary file being written to (resolved from /proc/PID/fd)
}

// RateSnapshot holds all computed rates between two snapshots.
type RateSnapshot struct {
	DeltaSec float64

	// CPU pcts
	CPUBusyPct    float64
	CPUUserPct    float64
	CPUSystemPct  float64
	CPUIOWaitPct  float64
	CPUSoftIRQPct float64
	CPUIRQPct     float64
	CPUStealPct   float64
	CPUNicePct    float64

	// Scheduling
	CtxSwitchRate float64 // total estimated

	// Memory rates (pages/s → MB/s)
	SwapInRate        float64 // MB/s
	SwapOutRate       float64
	PgFaultRate       float64 // pages/s
	MajFaultRate      float64
	DirectReclaimRate float64 // pages/s
	KswapdRate        float64
	OOMKillDelta      uint64  // OOM kills since last tick (delta, not cumulative)
	AllocStallRate    float64 // alloc stalls/s from VMStat.AllocStall delta
	SUnreclaimDelta   int64   // SUnreclaim change in bytes (slab leak detection)

	// Disks
	DiskRates  []DiskRate
	MountRates []MountRate

	// Network
	NetRates     []NetRate
	RetransRate  float64
	InSegRate    float64
	OutSegRate   float64
	TCPResetRate       float64
	TCPAttemptFailRate float64 // TCP connection attempt failures/s from /proc/net/snmp
	TCPResetRateAgg    float64 // aggregate TCP reset rate from /proc/net/snmp (EstabResets)

	// UDP
	UDPInRate    float64
	UDPOutRate   float64
	UDPErrRate   float64

	// Conntrack rates
	ConntrackInsertRate        float64
	ConntrackInsertFailRate    float64 // insert_failed/s — table full indicator
	ConntrackDeleteRate        float64
	ConntrackDropRate          float64
	ConntrackEarlyDropRate     float64 // forced evictions/s
	ConntrackInvalidRate       float64
	ConntrackSearchRestartRate float64 // hash contention/s
	ConntrackGrowthRate        float64 // insert - delete (net change)

	// SoftIRQ rates
	SoftIRQNetRxRate float64
	SoftIRQNetTxRate float64
	SoftIRQBlockRate float64

	// Cgroups
	CgroupRates []CgroupRate

	// Processes
	ProcessRates []ProcessRate
}

// WatchdogState holds auto-trigger state from the watchdog.
type WatchdogState struct {
	Active bool
	Domain string
}

// CollectionHealth tracks the health of individual collectors in a collection cycle.
type CollectionHealth struct {
	Total        int
	Succeeded    int
	Failed       int
	AvgLatencyMs float64
}

// AnalysisResult is the full output of one analysis cycle.
type AnalysisResult struct {
	Health     HealthLevel
	Confidence int // 0-100

	// Primary diagnosis
	PrimaryBottleneck string
	PrimaryScore      int
	PrimaryEvidence   []string
	PrimaryChain      []string
	PrimaryCulprit    string
	PrimaryPID        int
	PrimaryProcess    string
	PrimaryAppName    string // resolved app name for primary culprit

	// Sustained pressure tracking
	Sustained      bool // true if pressure persisted >10 ticks
	SustainedTicks int  // number of recent ticks with elevated pressure

	// Next risk (early warning)
	NextRisk string

	// All RCA results ranked
	RCA []RCAEntry

	// Capacity headroom
	Capacities []Capacity

	// Top owners per subsystem
	CPUOwners []Owner
	MemOwners []Owner
	IOOwners  []Owner
	NetOwners []Owner

	// Warnings
	Warnings []Warning

	// Suggested actions
	Actions []Action

	// Causal chain
	CausalChain string
	CausalDAG   *CausalDAG // structured causal chain (nil = not computed)

	// Anomaly tracking
	AnomalyStartedAgo  int    // seconds since primary bottleneck first appeared (0=not active)
	AnomalyTrigger     string // which signal first crossed threshold
	CulpritSinceAgo    int    // seconds since culprit became top consumer

	// Deployment correlation: process that started near anomaly onset
	RecentDeploy     string // e.g. "node server.js"
	RecentDeployPID  int    // PID of recently deployed process
	RecentDeployAge  int    // seconds since the process started

	// Hidden latency detection (metrics look fine but threads are waiting)
	HiddenLatency     bool   // true if hidden latency detected
	HiddenLatencyDesc string // human-readable explanation
	HiddenLatencyPct  float64 // estimated off-CPU wait percentage
	HiddenLatencyComm string  // top waiting process

	// Stability tracking
	StableSince      int     // seconds system has been continuously OK (0=not stable)
	BiggestChange    string  // description of biggest metric change in last 30s
	BiggestChangePct float64 // magnitude of the biggest change
	TopChanges       []MetricChange // top N biggest changes for "what changed?" display

	// Predictive exhaustion
	Exhaustions []ExhaustionPrediction

	// Slow degradation warnings
	Degradations []DegradationWarning

	// CLOSE_WAIT leaker data (for actions access)
	CloseWaitLeakers []CloseWaitLeaker

	// DiskGuard
	DiskGuardMounts []MountRate
	DiskGuardWorst  string // worst state across all mounts: "OK", "WARN", "CRIT"
	DiskGuardMode   string // "Monitor", "Contain", "Action"

	// Watchdog auto-trigger state
	Watchdog WatchdogState

	// System identity
	SysInfo *SysInfo

	// Narrative engine output
	Narrative *Narrative

	// Temporal causality chain
	TemporalChain *TemporalChain

	// Cross-signal correlation
	CrossCorrelations []CrossCorrelation

	// Blame attribution
	Blame []BlameEntry

	// Statistical intelligence (v0.31.0)
	BaselineAnomalies []BaselineAnomaly   // Evidence deviating from learned baseline
	Correlations      []MetricCorrelation // Discovered metric correlations
	ZScoreAnomalies   []ZScoreAnomaly     // Statistically unusual values vs recent window
	ProcessAnomalies  []ProcessAnomaly    // Processes deviating from learned profile
	AppAnomalies      []AppBehaviorAnomaly `json:"app_anomalies,omitempty"` // Phase 4: per-app baseline deviations
	ProbeResults      []ProbeResult        `json:"probe_results,omitempty"` // Phase 6: active investigation captures

	// Lifecycle echo from the incident recorder. Populated each tick by the
	// engine after IncidentRecorder.Record so downstream consumers (fleet
	// client, trace dump) don't need to plumb the recorder through.
	// IncidentState is one of "" (no incident), "suspected", "confirmed", "resolved".
	IncidentState       string    `json:"incident_state,omitempty"`
	IncidentConfirmedAt time.Time `json:"incident_confirmed_at,omitempty"`
	GoldenSignals     *GoldenSignalSummary // Approximated Golden Signal metrics

	// USE Method checklist (v0.36.6)
	USEChecks []USECheck `json:"use_checks,omitempty"`

	// Change detection (v0.36.6)
	Changes []SystemChange `json:"changes,omitempty"`

	// Impact quantification (v0.36.6)
	ImpactSummary string `json:"impact_summary,omitempty"`

	// Historical context — short human-readable summary from past similar incidents.
	HistoryContext string `json:"history_context,omitempty"`

	// IncidentDiff is a structured comparison of the current incident against
	// the last N similar ones (same signature). Nil if no prior matches exist.
	IncidentDiff *IncidentDiff `json:"incident_diff,omitempty"`

	// Runbook is the best-matching operator runbook for this incident (if any
	// were loaded from ~/.xtop/runbooks/). The engine populates this field;
	// the UI reads it to show a "see runbook: <name>" hint and can load the
	// full content via the engine's RunbookLibrary.Lookup(path).
	Runbook *RunbookMatch `json:"runbook,omitempty"`

	// Guard reports what the resource guard decided this tick (level, skip
	// flags, reason). Populated only when XTOP_GUARD=1. Nil otherwise so
	// status lines cleanly hide the indicator when it's off.
	Guard *GuardStatus `json:"guard,omitempty"`

	// TraceSamples are OpenTelemetry trace summaries that overlap the current
	// incident window, loaded by the engine's TraceCorrelator from a simple
	// JSONL feed. xtop never speaks OTLP directly — any existing OTel pipeline
	// can be pointed at ~/.xtop/otel-samples.jsonl to enable correlation.
	TraceSamples []TraceSample `json:"trace_samples,omitempty"`

	// LogExcerpts are notable lines pulled from app log files during an
	// incident. The engine's log tailer scans a small set of well-known paths
	// (nginx/apache error logs, mysql/postgres logs, systemd journal of the
	// culprit unit), filters for severity keywords, and attaches the top
	// matches here so the UI can show "the RCA says mysql, and here's what
	// mysql's error.log said at the same moment."
	LogExcerpts []LogExcerpt `json:"log_excerpts,omitempty"`

	// Set when UI is showing a pinned result after recovery (sticky RCA).
	// Value is seconds since health returned to OK. 0 = live incident.
	PinnedResolvedSec int `json:"pinned_resolved_sec,omitempty"`

	// Baseline readiness: 0.0 = all metrics warming up, 1.0 = fully ready
	BaselineReadiness float64 `json:"baseline_readiness,omitempty"`

	// Forecast warning from Holt-Winters trend prediction
	ForecastWarning string `json:"forecast_warning,omitempty"` // e.g. "Memory will hit 95% in ~45s at current rate"

	// Cross-host correlation: related incidents on other hosts
	CrossHostCorrelation string `json:"cross_host_correlation,omitempty"` // e.g. "Host db-server also reports IO bottleneck (score 78)"
}

// USECheck represents one USE method check for a resource (Utilization, Saturation, Errors).
type USECheck struct {
	Resource    string  // "CPU", "Memory", "Disk sda", "Network"
	Utilization float64 // percentage (0-100)
	Saturation  float64 // queue length or pressure
	Errors      float64 // error count/rate
	UtilStatus  string  // "ok", "warn", "crit"
	SatStatus   string
	ErrStatus   string
	UtilDetail  string // "25.3% busy"
	SatDetail   string // "runqueue 2/6 (33%)"
	ErrDetail   string // "0 errors"
}

// SystemChange represents a detected change on the system between ticks.
type SystemChange struct {
	Type   string    `json:"type"`   // "new_process", "stopped_process", "package_install", "package_upgrade"
	Detail string    `json:"detail"`
	When   time.Time `json:"when"`
}

// MetricChange represents a notable metric delta for the "what changed?" engine.
type MetricChange struct {
	Name    string  // e.g. "mysql IO"
	Delta   float64 // absolute change value
	DeltaPct float64 // percentage change
	Current string  // current value string
	Unit    string  // e.g. "%", "MB/s", "/s"
	Rising  bool    // true if increasing, false if decreasing
	ZScore  float64 // statistical significance (0 = not computed)
}

// DegradationWarning describes a slow, sustained trend.
type DegradationWarning struct {
	Metric    string  // e.g. "IO latency", "Memory reclaim"
	Direction string  // "rising", "falling"
	Duration  int     // seconds the trend has persisted
	Rate      float64 // change per minute
	Unit      string  // e.g. "ms/min", "%/min"
}

// ExhaustionPrediction estimates when a resource will be exhausted.
type ExhaustionPrediction struct {
	Resource   string  // "FD", "Memory", "Swap", "Conntrack"
	CurrentPct float64 // current usage percent
	TrendPerS  float64 // percentage-point change per second (positive = growing)
	EstMinutes float64 // estimated minutes to exhaustion (-1 = not trending)
	Confidence float64 // 0.0–1.0 confidence in the prediction (based on trend quality)
}

// EvidenceCheck is a single signal check with pass/fail.
type EvidenceCheck struct {
	Group      string  // evidence group name (e.g. "PSI", "D-state", "Disk latency")
	Label      string  // human-readable check (e.g. "IO PSI full avg10=0.12")
	Passed     bool    // did this signal fire?
	Value      string  // current value for display
	Confidence string  // "H" = BPF tracepoint, "M" = /proc counter, "L" = heuristic/derived
	Source     string  // "procfs", "sysfs", "bpf", "derived"
	Strength   float64 // 0.0-1.0 signal strength
}

// SysInfo holds host identity information (collected once).
type SysInfo struct {
	Hostname       string
	IPs            []string
	Virtualization string // "Bare Metal", "VM (KVM)", "VM (VMware)", "Container (Docker)", etc.
	CloudProvider  string // "AWS", "Hetzner", "DigitalOcean", "GCP", "Azure", etc.
	Kernel         string // kernel version
	OS             string // OS name from /etc/os-release
	Arch           string // architecture
	CPUModel       string // CPU model name
}

// RCAEntry holds one bottleneck analysis result.
type RCAEntry struct {
	Bottleneck     string
	Score          int
	EvidenceGroups int // how many independent evidence groups fired
	TopCgroup      string
	TopProcess     string
	TopPID         int
	TopAppName     string // resolved app name from identity (empty = use TopProcess)
	Evidence       []string
	Checks         []EvidenceCheck // structured evidence with pass/fail
	Chain          []string
	EvidenceV2     []Evidence      // v2 evidence objects (parallel to legacy Checks)
	DomainConf     float64         // v2 domain confidence 0..0.98
}

// Domain represents a resource domain for v2 evidence.
type Domain string

const (
	DomainCPU     Domain = "cpu"
	DomainMemory  Domain = "memory"
	DomainIO      Domain = "io"
	DomainNetwork Domain = "network"
)

// Severity represents evidence severity level.
type Severity string

const (
	SeverityInfo Severity = "info"
	SeverityWarn Severity = "warn"
	SeverityCrit Severity = "crit"
)

// OwnerAttribution identifies a resource consumer associated with evidence.
type OwnerAttribution struct {
	Kind       string  // "cgroup", "service", "pid"
	ID         string  // cgroup path, service name, or "pid:1234"
	Share      float64 // 0..1 fraction of observed load
	Confidence float64 // 0..1
}

// Evidence is a v2 structured evidence object with smooth scoring.
type Evidence struct {
	ID         string            // e.g. "io.psi.some", "mem.available.low"
	Message    string            // human-readable description
	Window     string            // time window e.g. "avg10", "1s"
	Domain     Domain            // resource domain
	Severity   Severity          // severity level
	Strength   float64           // 0..1 normalized signal strength
	Confidence float64           // 0..1 measurement confidence
	Value      float64           // raw measured value
	Threshold  float64           // critical threshold
	Measured   bool              // true if from direct measurement (BPF/counter)
	Owners     []OwnerAttribution
	Tags       map[string]string // e.g. "weight": "psi", "device": "sda"

	// Sustained-duration tracking (Phase 1: verdict discipline).
	// FirstSeenAt is the wall-clock time this evidence ID first fired in the
	// current incident; zero value means "first-tick onset".
	// SustainedForSec is now() - FirstSeenAt at the moment the verdict is built.
	// Stamped by stampSustainedDurations() in engine, using History.signalOnsets.
	FirstSeenAt     time.Time `json:"first_seen_at,omitempty"`
	SustainedForSec float64   `json:"sustained_for_sec,omitempty"`
}

// CausalNodeType identifies a node's role in the causal DAG.
type CausalNodeType string

const (
	CausalRootCause    CausalNodeType = "root_cause"
	CausalIntermediate CausalNodeType = "intermediate"
	CausalSymptom      CausalNodeType = "symptom"
)

// CausalNode is a node in the causal DAG.
type CausalNode struct {
	ID          string
	Label       string
	Type        CausalNodeType
	Domain      Domain
	EvidenceIDs []string
}

// CausalEdge is a directed edge in the causal DAG.
type CausalEdge struct {
	From   string
	To     string
	Rule   string
	Weight float64
}

// CausalDAG represents a directed acyclic graph of causal relationships.
type CausalDAG struct {
	Nodes       []CausalNode
	Edges       []CausalEdge
	LinearChain string // human-readable "→"-joined string
}

// Narrative is the human-readable root cause explanation produced by the narrative engine.
type Narrative struct {
	RootCause  string   // e.g. "CPU throttle cascade — cgroup limits saturating run queue"
	Evidence   []string // top 3-4 evidence lines with values
	Impact     string   // e.g. "CPU stall 42%; disk latency +120ms"
	Confidence int
	Pattern    string // matched pattern name (empty if none)
	Temporal   string // temporal chain summary
}

// TemporalChain tracks the order in which signals fired to establish causality.
type TemporalChain struct {
	Events     []TemporalEvent
	Summary    string // e.g. "retransmits (T+0s) → drops (T+3s) → threads blocked (T+12s)"
	FirstMover string // evidence ID that fired first
}

// TemporalEvent is a single signal onset in the temporal chain.
type TemporalEvent struct {
	EvidenceID string
	Label      string
	FirstSeen  time.Time
	Sequence   int
}

// CrossCorrelation describes a detected cause-effect relationship between two
// signals across different domains (e.g., memory reclaim causing IO latency).
type CrossCorrelation struct {
	Cause       string  `json:"cause"`        // evidence ID of the leading signal
	Effect      string  `json:"effect"`       // evidence ID of the lagging signal
	LeadTimeSec float64 `json:"lead_time_sec"` // seconds the cause preceded the effect
	Confidence  float64 `json:"confidence"`   // 0-1 confidence in the correlation
	Explanation string  `json:"explanation"`  // human-readable description
	LeadSamples int     `json:"lead_samples,omitempty"` // lag in samples where cross-correlation peaks (positive = cause leads)
	LaggedR     float64 `json:"lagged_r,omitempty"`     // Pearson R at the best lag
}

// BlameEntry identifies a top offending process or cgroup for the current bottleneck.
type BlameEntry struct {
	Comm       string
	AppName    string // resolved app name from identity
	PID        int
	CgroupPath string
	Metrics    map[string]string // "cpu" → "45.2%", "io" → "12 MB/s"
	ImpactPct  float64
}

// BaselineAnomaly represents an evidence value that deviates from its learned EWMA baseline.
type BaselineAnomaly struct {
	EvidenceID string  // e.g. "cpu.busy"
	Value      float64 // current value
	Baseline   float64 // EWMA mean
	StdDev     float64 // sqrt(EWMA variance)
	ZScore     float64 // (value - mean) / stddev
	Sigma      float64 // how many sigma above baseline
}

// MetricCorrelation represents a discovered Pearson correlation between two metrics.
type MetricCorrelation struct {
	MetricA     string  // evidence ID A
	MetricB     string  // evidence ID B
	Coefficient float64 // Pearson R (-1 to +1)
	Samples     int64   // number of samples
	Strength    string  // "strong"/"moderate"/"weak"
}

// ZScoreAnomaly represents a value that is statistically unusual vs recent history.
type ZScoreAnomaly struct {
	EvidenceID string  // e.g. "cpu.busy"
	Value      float64 // current value
	WindowMean float64 // mean over sliding window
	WindowStd  float64 // stddev over sliding window
	ZScore     float64 // (value - mean) / std
}

// ProcessAnomaly represents a process whose resource usage deviates from its learned profile.
type ProcessAnomaly struct {
	PID      int
	Comm     string
	Metric   string  // "cpu_pct", "rss_mb", "io_mbs"
	Current  float64
	Baseline float64
	StdDev   float64
	Sigma    float64
}

// ProbeResult is the captured output of one Phase 6 active investigation.
// Probes are short, read-only shell or eBPF commands run on demand to
// disambiguate Suspected→Confirmed transitions; results are attached to the
// next trace dump for forensic inspection.
type ProbeResult struct {
	Name      string    `json:"name"`        // probe class, e.g. "top_cpu_processes"
	EvidenceID string   `json:"evidence_id"` // evidence ID that triggered this probe
	StartedAt time.Time `json:"started_at"`
	DurationMs int      `json:"duration_ms"`
	ExitCode  int       `json:"exit_code"`
	Output    string    `json:"output"`     // stdout (truncated to 64 KB)
	Stderr    string    `json:"stderr,omitempty"`
	Truncated bool      `json:"truncated,omitempty"`
	Error     string    `json:"error,omitempty"`
}

// AppBehaviorAnomaly is a per-app baseline deviation, anchored on cgroup +
// hour-of-week so "Postgres is busy at 09:00 Monday" is normal but "Postgres
// is busy at 03:00 Sunday" is flagged. Phase 4: per-app baselines.
type AppBehaviorAnomaly struct {
	AppName        string  `json:"app_name"`
	CgroupPath     string  `json:"cgroup_path,omitempty"`
	Metric         string  `json:"metric"`         // "cpu_pct", "rss_mb"
	Current        float64 `json:"current"`
	HourBaseline   float64 `json:"hour_baseline"`  // mean for this hour-of-week
	HourStdDev     float64 `json:"hour_stddev"`
	Sigma          float64 `json:"sigma"`
	HourOfWeek     int     `json:"hour_of_week"`   // 0..167 (mon 00:00 = 0)
	Note           string  `json:"note,omitempty"` // e.g. "frozen-during-incident", "cold-start"
}

// SaturationDetail breaks down saturation into individual components.
type SaturationDetail struct {
	ConntrackPct  float64 // conntrack table usage % (0-100)
	EphemeralPct  float64 // ephemeral port usage % (0-100)
	RunqueueRatio float64 // load1 / nCPUs (0-1, clamped)
	PSIMax        float64 // max PSI stall across domains (0-1, normalized from %)
}

// GoldenSignalSummary approximates Google SRE Golden Signals from /proc data.
type GoldenSignalSummary struct {
	// Latency proxies
	DiskLatencyMs float64 // worst disk await
	TCPRTTMs      float64 // smoothed TCP RTT (if BPF available)
	PSIStallPct   float64 // max PSI stall across domains
	// Traffic proxies
	TCPSegmentsPerSec float64 // in + out segments
	NetBytesPerSec    float64 // total interface throughput
	ConnAcceptRate    float64 // passive opens / sec
	// Error proxies
	ErrorRate float64 // drops + retrans + resets + OOM combined rate
	// Saturation proxies
	SaturationPct       float64          // max of: conntrack%, ephemeral%, runqueue ratio, PSI
	SaturationBreakdown SaturationDetail // per-component saturation detail
}

// TraceSample is one OpenTelemetry trace summary correlated with an incident.
// The engine reads a simple JSONL feed at ~/.xtop/otel-samples.jsonl — an
// operator can produce it from their existing OTel collector via a
// processor that emits just these fields. Fields are intentionally minimal:
// everything needed to link to the full trace in whatever UI the operator
// already uses (Jaeger/Tempo/etc) plus enough context to display inline.
type TraceSample struct {
	TraceID     string    `json:"trace_id"`
	SpanID      string    `json:"span_id,omitempty"`
	Service     string    `json:"service,omitempty"`
	Operation   string    `json:"operation,omitempty"`
	DurationMs  float64   `json:"duration_ms"`
	StatusCode  string    `json:"status_code,omitempty"` // "OK", "ERROR", "UNSET"
	StatusError string    `json:"status_error,omitempty"`
	StartTime   time.Time `json:"start_time"`
	URL         string    `json:"url,omitempty"` // optional deep-link into Jaeger/Tempo
}

// LogExcerpt is one notable line from an application log file, correlated
// with a live incident. The engine fills these in when an incident is active
// and the culprit matches a known app — so operators see the database's own
// "ERROR: slow query" line beside xtop's "mysqld is the culprit" verdict.
type LogExcerpt struct {
	App       string    `json:"app"`                 // e.g. "mysql", "nginx"
	Path      string    `json:"path"`                // source file
	Line      string    `json:"line"`                // the matched line (trimmed)
	Severity  string    `json:"severity,omitempty"`  // "ERROR", "WARN", "SLOW", "FATAL", "OOM"
	Timestamp time.Time `json:"timestamp,omitempty"` // best-effort parse; zero if unparseable
}

// GuardStatus is the per-tick report from the engine's ResourceGuard. The
// UI reads this to show a compact status strip when xtop is self-throttling:
// "[GUARD L2: host load 4.1x] skipping log-tailer, traces, watchdog".
type GuardStatus struct {
	Level         int     `json:"level"` // 0 none, 1 caution, 2 degraded, 3 minimal
	Reason        string  `json:"reason,omitempty"`
	IntervalSec   int     `json:"interval_sec"`
	OwnCPUPct     float64 `json:"own_cpu_pct"`
	HostLoadRatio float64 `json:"host_load_ratio"`
	Skipped       []string `json:"skipped,omitempty"` // human-readable list of what was skipped
}

// RunbookMatch is the lightweight reference to a matched runbook file. The
// full markdown body stays in the engine's in-memory library and on disk —
// only the preview + path + score travel with AnalysisResult so the payload
// stays small and fleet-serializable.
type RunbookMatch struct {
	Name    string `json:"name"`
	Path    string `json:"path"`
	Score   int    `json:"score"`
	Preview string `json:"preview,omitempty"`
}

// IncidentDiff is a structured comparison of the current incident against
// recent similar ones. Populated by the engine's IncidentRecorder when at
// least one past incident shares the same signature.
//
// What the fields mean:
//   - MatchCount / FirstSeen / LastSeen: how often and how long we've seen this.
//   - MedianPeakScore / MaxPeakScore: baseline severity; compare with current.
//   - CurrentPeakScore / ScoreDeltaFromMedian: is THIS incident worse than usual?
//   - MedianDurationSec: how long these typically last — sets expectations.
//   - CulpritFrequency: "mysqld was the culprit 4/5 times" signals a repeat offender.
//   - NewEvidence / MissingEvidence: evidence IDs firing now that weren't in prior
//     incidents (or vice versa) — the most actionable signal: "this time it's
//     different because X is also firing."
//   - SameHourOfDay: count of past occurrences in the same hour-of-day — hints
//     at scheduled causes (backups, cron jobs).
//   - DriftHint: plain-English one-liner the UI can show inline.
type IncidentDiff struct {
	MatchCount            int       `json:"match_count"`
	FirstSeen             time.Time `json:"first_seen,omitempty"`
	LastSeen              time.Time `json:"last_seen,omitempty"`
	MedianPeakScore       int       `json:"median_peak_score,omitempty"`
	MaxPeakScore          int       `json:"max_peak_score,omitempty"`
	CurrentPeakScore      int       `json:"current_peak_score,omitempty"`
	ScoreDeltaFromMedian  int       `json:"score_delta_from_median,omitempty"`
	MedianDurationSec     int       `json:"median_duration_sec,omitempty"`
	CulpritFrequency      map[string]int `json:"culprit_frequency,omitempty"`
	TopCulprit            string    `json:"top_culprit,omitempty"`
	TopCulpritCount       int       `json:"top_culprit_count,omitempty"`
	CurrentCulprit        string    `json:"current_culprit,omitempty"`
	CulpritIsRepeat       bool      `json:"culprit_is_repeat,omitempty"`
	NewEvidence           []string  `json:"new_evidence,omitempty"`
	MissingEvidence       []string  `json:"missing_evidence,omitempty"`
	SameHourOfDay         int       `json:"same_hour_of_day,omitempty"`
	DriftHint             string    `json:"drift_hint,omitempty"`
}
