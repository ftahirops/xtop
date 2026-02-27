package model

import "time"

// Snapshot holds a point-in-time system state.
type Snapshot struct {
	Timestamp time.Time
	Global    GlobalMetrics
	Cgroups   []CgroupMetrics
	Processes []ProcessMetrics
	SysInfo   *SysInfo
	Errors    []string
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
	SwapInRate      float64 // MB/s
	SwapOutRate     float64
	PgFaultRate     float64 // pages/s
	MajFaultRate    float64
	DirectReclaimRate float64 // pages/s
	KswapdRate      float64
	OOMKillDelta    uint64  // OOM kills since last tick (delta, not cumulative)

	// Disks
	DiskRates  []DiskRate
	MountRates []MountRate

	// Network
	NetRates     []NetRate
	RetransRate  float64
	InSegRate    float64
	OutSegRate   float64
	TCPResetRate float64

	// UDP
	UDPInRate    float64
	UDPOutRate   float64
	UDPErrRate   float64

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

	// Blame attribution
	Blame []BlameEntry
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
}

// RCAEntry holds one bottleneck analysis result.
type RCAEntry struct {
	Bottleneck     string
	Score          int
	EvidenceGroups int // how many independent evidence groups fired
	TopCgroup      string
	TopProcess     string
	TopPID         int
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

// BlameEntry identifies a top offending process or cgroup for the current bottleneck.
type BlameEntry struct {
	Comm       string
	PID        int
	CgroupPath string
	Metrics    map[string]string // "cpu" → "45.2%", "io" → "12 MB/s"
	ImpactPct  float64
}
