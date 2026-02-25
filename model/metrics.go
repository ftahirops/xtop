package model

import "time"

// MaskIPsEnabled controls whether IP addresses are masked in output.
var MaskIPsEnabled bool

// MaskIP replaces an IP with x.x.x.x when masking is enabled.
func MaskIP(ip string) string {
	if !MaskIPsEnabled {
		return ip
	}
	return "x.x.x.x"
}

// MaskIPs replaces all IPs in a slice when masking is enabled.
func MaskIPs(ips []string) []string {
	if !MaskIPsEnabled {
		return ips
	}
	out := make([]string, len(ips))
	for i := range ips {
		out[i] = "x.x.x.x"
	}
	return out
}

// PSILine holds one line of PSI data (some or full).
type PSILine struct {
	Avg10  float64
	Avg60  float64
	Avg300 float64
	Total  uint64 // cumulative microseconds
}

// PSIResource holds PSI data for one resource (cpu, memory, or io).
type PSIResource struct {
	Some PSILine
	Full PSILine // cpu has no "full" line
}

// PSIMetrics holds all PSI data.
type PSIMetrics struct {
	CPU    PSIResource
	Memory PSIResource
	IO     PSIResource
}

// CPUTimes holds CPU time counters from /proc/stat (in jiffies/ticks).
type CPUTimes struct {
	User      uint64
	Nice      uint64
	System    uint64
	Idle      uint64
	IOWait    uint64
	IRQ       uint64
	SoftIRQ   uint64
	Steal     uint64
	Guest     uint64
	GuestNice uint64
}

// Total returns total jiffies.
func (c CPUTimes) Total() uint64 {
	return c.User + c.Nice + c.System + c.Idle + c.IOWait +
		c.IRQ + c.SoftIRQ + c.Steal + c.Guest + c.GuestNice
}

// Active returns non-idle jiffies.
func (c CPUTimes) Active() uint64 {
	return c.Total() - c.Idle - c.IOWait
}

// LoadAvg holds /proc/loadavg data.
type LoadAvg struct {
	Load1   float64
	Load5   float64
	Load15  float64
	Running uint64
	Total   uint64
}

// CPUMetrics holds all CPU-related metrics.
type CPUMetrics struct {
	Total   CPUTimes
	PerCPU  []CPUTimes
	LoadAvg LoadAvg
	NumCPUs int
}

// MemoryMetrics holds /proc/meminfo data.
type MemoryMetrics struct {
	Total          uint64
	Free           uint64
	Available      uint64
	Buffers        uint64
	Cached         uint64
	SwapTotal      uint64
	SwapFree       uint64
	SwapUsed       uint64
	SwapCached     uint64
	Dirty          uint64
	Writeback      uint64
	Slab           uint64
	SReclaimable   uint64
	SUnreclaim     uint64
	AnonPages      uint64
	Mapped         uint64
	Shmem          uint64
	KernelStack    uint64
	PageTables     uint64
	Bounce         uint64
	HugePages_Total uint64
	HugePages_Free  uint64
	HugepageSize    uint64
	DirectMap4k     uint64
	DirectMap2M     uint64
	DirectMap1G     uint64
	Mlocked         uint64
	Active          uint64
	Inactive        uint64
	ActiveAnon      uint64
	InactiveAnon    uint64
	ActiveFile      uint64
	InactiveFile    uint64
	Unevictable     uint64
	VmallocTotal    uint64
	VmallocUsed     uint64
}

// VMStatMetrics holds selected /proc/vmstat counters.
type VMStatMetrics struct {
	PgFault         uint64
	PgMajFault      uint64
	PgPgIn          uint64
	PgPgOut         uint64
	PswpIn          uint64
	PswpOut         uint64
	PgStealDirect   uint64
	PgStealKswapd   uint64
	PgScanDirect    uint64
	PgScanKswapd    uint64
	AllocStall      uint64
	CompactStall    uint64
	OOMKill         uint64
	NrDirtied       uint64
	NrWritten       uint64
	ThpFaultAlloc   uint64
	ThpCollapseAlloc uint64
}

// DiskStats holds per-device IO counters from /proc/diskstats.
type DiskStats struct {
	Name            string
	ReadsCompleted  uint64
	ReadsMerged     uint64
	SectorsRead     uint64
	ReadTimeMs      uint64
	WritesCompleted uint64
	WritesMerged    uint64
	SectorsWritten  uint64
	WriteTimeMs     uint64
	IOsInProgress   uint64
	IOTimeMs        uint64
	WeightedIOMs    uint64
	// Extended (kernel 4.18+)
	DiscardsCompleted uint64
	DiscardTimeMs     uint64
	FlushesCompleted  uint64
	FlushTimeMs       uint64
}

// MountStats holds per-filesystem stats from statfs(2).
type MountStats struct {
	MountPoint  string
	Device      string
	FSType      string
	TotalBytes  uint64
	FreeBytes   uint64
	AvailBytes  uint64 // available to non-root (statvfs f_bavail)
	UsedBytes   uint64
	TotalInodes uint64
	FreeInodes  uint64
	UsedInodes  uint64
}

// BigFile represents a large file found on disk.
type BigFile struct {
	Path      string
	Dir       string
	SizeBytes uint64
	ModTime   int64 // unix timestamp
}

// DeletedOpenFile represents a file that was deleted but is still held open.
type DeletedOpenFile struct {
	PID       int
	Comm      string
	FD        int
	Path      string
	SizeBytes uint64
}

// FilelessProcess represents a process running from memory with no on-disk binary.
type FilelessProcess struct {
	PID       int
	Comm      string
	ExePath   string   // readlink result, e.g. "/memfd:payload (deleted)"
	IsMemFD   bool     // /memfd: prefix
	IsDeleted bool     // (deleted) suffix, not memfd
	NetConns  int      // ESTABLISHED + SYN_SENT outbound connections
	RemoteIPs []string // up to 5 unique remote IPs
	RSS       uint64   // resident memory, for context
}

// NetworkStats holds per-interface counters from /proc/net/dev
// plus metadata from /sys/class/net/.
type NetworkStats struct {
	Name      string
	RxBytes   uint64
	RxPackets uint64
	RxErrors  uint64
	RxDrops   uint64
	RxFifo    uint64
	RxFrame   uint64
	TxBytes   uint64
	TxPackets uint64
	TxErrors  uint64
	TxDrops   uint64
	TxFifo    uint64
	TxColls   uint64
	TxCarrier uint64

	// Metadata from /sys/class/net/
	OperState string // "up", "down", "unknown"
	SpeedMbps int    // link speed in Mbps (-1 if unknown)
	Master    string // bridge/bond master interface name (empty if none)
	IfType    string // "physical", "bridge", "bond", "veth", "vlan", "tunnel", "virtual"
}

// TCPMetrics holds TCP-level counters from /proc/net/snmp.
type TCPMetrics struct {
	RetransSegs  uint64
	InSegs       uint64
	OutSegs      uint64
	ActiveOpens  uint64
	PassiveOpens uint64
	CurrEstab    uint64
	AttemptFails uint64
	EstabResets  uint64
	InErrs       uint64
	OutRsts      uint64
}

// UDPMetrics holds UDP counters from /proc/net/snmp.
type UDPMetrics struct {
	InDatagrams  uint64
	OutDatagrams uint64
	InErrors     uint64
	NoPorts      uint64
	RcvbufErrors uint64
	SndbufErrors uint64
}

// SocketStats holds socket counts from /proc/net/sockstat.
type SocketStats struct {
	SocketsUsed int
	TCPInUse    int
	TCPOrphan   int
	TCPTimeWait int
	TCPAlloc    int
	TCPMem      int // pages
	UDPInUse    int
	UDPMem      int
	RawInUse    int
	FragInUse   int
	FragMem     int
}

// TCPConnState holds counts per TCP state from /proc/net/tcp.
type TCPConnState struct {
	Established int
	SynSent     int
	SynRecv     int
	FinWait1    int
	FinWait2    int
	TimeWait    int
	Close       int
	CloseWait   int
	LastAck     int
	Listen      int
	Closing     int
}

// SoftIRQStats holds per-type softirq counts from /proc/softirqs.
type SoftIRQStats struct {
	HI       uint64
	TIMER    uint64
	NET_TX   uint64
	NET_RX   uint64
	BLOCK    uint64
	IRQ_POLL uint64
	TASKLET  uint64
	SCHED    uint64
	HRTIMER  uint64
	RCU      uint64
}

// ConntrackStats holds conntrack data.
type ConntrackStats struct {
	Count   uint64
	Max     uint64
	Found   uint64
	Invalid uint64
	Insert  uint64
	Delete  uint64
	Drop    uint64
}

// FDStats holds file descriptor usage.
type FDStats struct {
	Allocated uint64
	Max       uint64
}

// EphemeralPorts holds ephemeral port usage data.
type EphemeralPorts struct {
	RangeLo       int // from /proc/sys/net/ipv4/ip_local_port_range
	RangeHi       int
	InUse         int // count of connections with local port in ephemeral range
	TimeWaitIn    int // TIME_WAIT specifically in ephemeral range
	EstablishedIn int // ESTABLISHED in ephemeral range
	CloseWaitIn   int // CLOSE_WAIT in ephemeral range
	SynSentIn     int // SYN_SENT in ephemeral range
	TopUsers      []PortUser
}

// PortUser holds per-process ephemeral port consumption.
type PortUser struct {
	PID         int
	Comm        string
	Ports       int // total ephemeral ports held
	Established int
	TimeWait    int // note: TIME_WAIT usually has inode 0, so this tracks indirect attribution
	CloseWait   int
}

// RemoteIPStats holds aggregated connection counts per remote IP.
type RemoteIPStats struct {
	IP          string
	Connections int
	Established int
	TimeWait    int
	CloseWait   int
}

// CloseWaitLeaker holds per-PID CLOSE_WAIT socket attribution.
type CloseWaitLeaker struct {
	PID        int
	Comm       string
	Count      int      // CW sockets held
	OldestAge  int      // seconds
	NewestAge  int      // seconds
	TopRemotes []string // up to 3 remote IPs
}

// CloseWaitTrend holds CLOSE_WAIT growth trend data.
type CloseWaitTrend struct {
	Current    int
	GrowthRate float64 // sockets/sec EWMA
	Growing    bool
}

// ActiveSession represents a currently logged-in user.
type ActiveSession struct {
	User    string
	TTY     string
	From    string
	LoginAt string
	Idle    string
	Command string
}

// FailedAuthSource holds a source IP and its failed authentication count.
type FailedAuthSource struct {
	IP    string
	Count int
}

// NewListeningPort holds a newly detected listening port.
type NewListeningPort struct {
	Port  int
	PID   int
	Comm  string
	Since time.Time
}

// SUIDBinary holds a SUID binary detected on the filesystem.
type SUIDBinary struct {
	Path    string
	Owner   string
	ModTime time.Time
}

// ReverseShellProc holds a candidate reverse shell process.
type ReverseShellProc struct {
	PID      int
	Comm     string
	RemoteIP string
	FD0      string
	FD1      string
}

// SecurityMetrics holds real-time security signal data.
type SecurityMetrics struct {
	FailedAuthRate  float64
	FailedAuthTotal int
	FailedAuthIPs   []FailedAuthSource
	NewPorts        []NewListeningPort
	SUIDAnomalies   []SUIDBinary
	ReverseShells   []ReverseShellProc
	BruteForce      bool
	Score           string // "OK", "WARN", "CRIT"
}

// ServiceLogStats holds per-service log error/warning stats.
type ServiceLogStats struct {
	Name        string
	Unit        string
	ErrorRate   float64
	WarnRate    float64
	TotalErrors int
	TotalWarns  int
	LastError   string
	RateHistory []float64 // ring buffer, 60 entries for sparkline
}

// LogMetrics holds log analysis data for tracked services.
type LogMetrics struct {
	Services []ServiceLogStats
}

// HealthProbeResult holds the result of one health probe.
type HealthProbeResult struct {
	Name         string
	ProbeType    string // "http", "tcp", "dns", "cert"
	Target       string // URL, host:port, or domain
	Status       string // "OK", "WARN", "CRIT", "UNKNOWN"
	LatencyMs    float64
	StatusCode   int // HTTP only
	Detail       string
	LastCheck    time.Time
	CertDaysLeft int // -1 if N/A
}

// HealthCheckMetrics holds active health probe results.
type HealthCheckMetrics struct {
	Probes []HealthProbeResult
}

// DiagSeverity represents the severity of a diagnostic finding.
type DiagSeverity string

const (
	DiagOK   DiagSeverity = "ok"
	DiagInfo DiagSeverity = "info"
	DiagWarn DiagSeverity = "warn"
	DiagCrit DiagSeverity = "crit"
)

// DiagFinding holds a single diagnostic finding for a service.
type DiagFinding struct {
	Severity DiagSeverity
	Category string // "config", "performance", "replication", "memory", "connections"
	Summary  string
	Detail   string
	Advice   string
}

// ServiceDiag holds diagnostic results for one service.
type ServiceDiag struct {
	Name      string
	Available bool
	Findings  []DiagFinding
	WorstSev  DiagSeverity
	LastCheck time.Time
	Metrics   map[string]string // key metrics for TUI display
}

// DiagMetrics holds diagnostics for all detected services.
type DiagMetrics struct {
	Services []ServiceDiag
}

// SentinelData holds always-on eBPF sentinel probe data.
type SentinelData struct {
	Active    bool
	AttachErr string

	// Network sentinels
	PktDrops     []PktDropEntry
	TCPResets    []TCPResetEntry
	StateChanges []SockStateEntry

	// Sentinel-promoted existing probes
	Retransmits []SentinelRetransEntry
	ConnLatency []SentinelConnLatEntry

	// Security
	ModLoads     []ModLoadEntry
	ExecEvents   []ExecEventEntry
	PtraceEvents []PtraceEventEntry

	// Memory
	OOMKills      []OOMKillEntry
	DirectReclaim []DirectReclaimEntry

	// CPU
	CgThrottles []CgThrottleEntry

	// Aggregate rates (computed from deltas)
	PktDropRate    float64
	TCPResetRate   float64
	RetransRate    float64
	ReclaimStallMs float64
	ThrottleRate   float64
}

// PktDropEntry holds a BPF-traced packet drop reason and count.
type PktDropEntry struct {
	Reason    uint32
	ReasonStr string
	Count     uint64
	Rate      float64
}

// TCPResetEntry holds a BPF-traced TCP RST event per PID.
type TCPResetEntry struct {
	PID    uint32
	Comm   string
	Count  uint64
	Rate   float64
	DstStr string
}

// SockStateEntry holds a BPF-traced TCP state transition count.
type SockStateEntry struct {
	OldState uint16
	NewState uint16
	OldStr   string
	NewStr   string
	Count    uint64
	Rate     float64
}

// SentinelRetransEntry holds always-on BPF TCP retransmit data per PID.
type SentinelRetransEntry struct {
	PID    uint32
	Comm   string
	Count  uint32
	Rate   float64
	DstStr string
}

// SentinelConnLatEntry holds always-on BPF TCP connect latency per PID.
type SentinelConnLatEntry struct {
	PID    uint32
	Comm   string
	Count  uint32
	AvgMs  float64
	MaxMs  float64
	DstStr string
}

// ModLoadEntry holds a BPF-traced kernel module load event.
type ModLoadEntry struct {
	Name      string
	Timestamp int64
	Count     uint64
}

// OOMKillEntry holds a BPF-traced OOM kill event.
type OOMKillEntry struct {
	VictimPID  uint32
	VictimComm string
	TotalVM    uint64
	AnonRSS    uint64
	Timestamp  int64
}

// DirectReclaimEntry holds a BPF-traced direct reclaim stall per PID.
type DirectReclaimEntry struct {
	PID     uint32
	Comm    string
	StallNs uint64
	Count   uint32
}

// CgThrottleEntry holds a BPF-traced cgroup CPU throttle event.
type CgThrottleEntry struct {
	CgID   uint64
	CgPath string
	Count  uint64
	Rate   float64
}

// ExecEventEntry holds a BPF-traced process execution event.
type ExecEventEntry struct {
	PID       uint32
	PPID      uint32
	UID       uint32
	Comm      string
	Filename  string
	Count     uint64
	Timestamp int64
}

// PtraceEventEntry holds a BPF-traced ptrace syscall event.
type PtraceEventEntry struct {
	TracerPID  uint32
	TracerComm string
	TargetPID  uint32
	TargetComm string
	Request    uint64
	RequestStr string
	Count      uint64
	Timestamp  int64
}

// GlobalMetrics is the full system-wide metric snapshot.
type GlobalMetrics struct {
	PSI            PSIMetrics
	CPU            CPUMetrics
	Memory         MemoryMetrics
	VMStat         VMStatMetrics
	Disks          []DiskStats
	Network        []NetworkStats
	TCP            TCPMetrics
	UDP            UDPMetrics
	Sockets        SocketStats
	TCPStates      TCPConnState
	SoftIRQ        SoftIRQStats
	Conntrack      ConntrackStats
	FD             FDStats
	EphemeralPorts EphemeralPorts
	TopRemoteIPs     []RemoteIPStats
	CloseWaitLeakers []CloseWaitLeaker
	CloseWaitTrend   CloseWaitTrend
	Mounts           []MountStats
	DeletedOpen    []DeletedOpenFile
	BigFiles       []BigFile
	FilelessProcs  []FilelessProcess
	Security       SecurityMetrics
	Logs           LogMetrics
	HealthChecks   HealthCheckMetrics
	Sessions       []ActiveSession
	Diagnostics    DiagMetrics
	Sentinel       SentinelData
}

// CgroupMetrics holds metrics for a single cgroup.
type CgroupMetrics struct {
	Path string
	Name string // leaf name for display

	// CPU
	UsageUsec     uint64
	UserUsec      uint64
	SystemUsec    uint64
	ThrottledUsec uint64
	NrThrottled   uint64
	NrPeriods     uint64

	// Memory
	MemCurrent uint64
	MemLimit   uint64 // max or high, whichever is set
	MemSwap    uint64
	OOMKills   uint64
	PgFault    uint64
	PgMajFault uint64

	// IO (aggregated across devices)
	IORBytes uint64
	IOWBytes uint64
	IORIOs   uint64
	IOWIOs   uint64

	// PIDs
	PIDCount uint64
	PIDLimit uint64
}

// ProcessMetrics holds metrics for a single process.
type ProcessMetrics struct {
	PID        int
	Comm       string
	State      string
	PPID       int
	CgroupPath string

	// CPU (in ticks)
	UTime      uint64
	STime      uint64
	NumThreads int
	Processor  int

	// Memory (in bytes)
	RSS       uint64
	VmSize    uint64
	VmSwap    uint64
	MinFault  uint64
	MajFault  uint64

	// IO (in bytes)
	ReadBytes  uint64
	WriteBytes uint64
	SyscR      uint64
	SyscW      uint64

	// Context switches
	VoluntaryCtxSwitches    uint64
	NonVoluntaryCtxSwitches uint64

	// File descriptors
	FDCount     int    // count of open FDs from /proc/PID/fd
	FDSoftLimit uint64 // soft limit from /proc/PID/limits

	// Start time (clock ticks since boot, from /proc/PID/stat field 22)
	StartTimeTicks uint64
}
