package model

import "time"

// Snapshot holds a point-in-time system state.
type Snapshot struct {
	Timestamp time.Time
	Global    GlobalMetrics
	Cgroups   []CgroupMetrics
	Processes []ProcessMetrics
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
}

// ProcessRate holds computed per-process rates.
type ProcessRate struct {
	PID          int
	Comm         string
	State        string
	CgroupPath   string
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

	// Disks
	DiskRates []DiskRate

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

	// Anomaly tracking
	AnomalyStartedAgo  int    // seconds since primary bottleneck first appeared (0=not active)
	AnomalyTrigger     string // which signal first crossed threshold
	CulpritSinceAgo    int    // seconds since culprit became top consumer

	// Stability tracking
	StableSince int    // seconds system has been continuously OK (0=not stable)
	BiggestChange string // description of biggest metric change in last 30s
	BiggestChangePct float64 // magnitude of the biggest change

	// Predictive exhaustion
	Exhaustions []ExhaustionPrediction
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
	Group   string // evidence group name (e.g. "PSI", "D-state", "Disk latency")
	Label   string // human-readable check (e.g. "IO PSI full avg10=0.12")
	Passed  bool   // did this signal fire?
	Value   string // current value for display
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
}
