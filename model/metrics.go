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
	Count         uint64
	Max           uint64
	Buckets       uint64 // hash table buckets (ideal max ~= buckets * 4)
	Found         uint64
	Invalid       uint64
	Insert        uint64
	InsertFailed  uint64 // failed inserts (table full)
	Delete        uint64
	Drop          uint64
	EarlyDrop     uint64 // evicted before timeout
	SearchRestart uint64 // hash contention / CPU pressure
}

// ConntrackDissection holds parsed /proc/net/nf_conntrack data.
type ConntrackDissection struct {
	Available   bool
	TCPCount    int
	UDPCount    int
	ICMPCount   int
	OtherCount  int
	AgeLt10s    int // TTL remaining < 10s
	Age10s60s   int // 10s-60s
	Age1m5m     int // 1m-5m
	AgeGt5m     int // >= 5m
	TopSrcIPs   []ConntrackIPCount
	TopDstIPs   []ConntrackIPCount
	CTStates    map[string]int // "ESTABLISHED" -> count
	TotalParsed int
}

// ConntrackIPCount holds an IP address and its connection count.
type ConntrackIPCount struct {
	IP    string
	Count int
}

// ConntrackTimeouts holds TCP timeout values from sysctl.
type ConntrackTimeouts struct {
	Available   bool
	Established int // default 432000 (5 days!)
	TimeWait    int // default 120
	Close       int
	CloseWait   int
	SynSent     int
	SynRecv     int
	FinWait     int
	LastAck     int
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

	// Network security watchdog results
	TCPFlagAnomalies    []TCPFlagAnomaly    `json:"tcp_flag_anomalies,omitempty"`
	DNSTunnelIndicators []DNSTunnelIndicator `json:"dns_tunnel_indicators,omitempty"`
	JA3Fingerprints     []JA3Entry          `json:"ja3_fingerprints,omitempty"`
	BeaconIndicators    []BeaconIndicator   `json:"beacon_indicators,omitempty"`
	ThreatScore         string              `json:"threat_score"`
	ActiveWatchdogs     []string            `json:"active_watchdogs,omitempty"`
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

	// Network security sentinels
	SynFlood    []SynFloodEntry   `json:"syn_flood,omitempty"`
	PortScans   []PortScanEntry   `json:"port_scans,omitempty"`
	DNSAnomaly  []DNSAnomalyEntry `json:"dns_anomaly,omitempty"`
	FlowRates   []FlowRateEntry   `json:"flow_rates,omitempty"`
	OutboundTop []OutboundEntry   `json:"outbound_top,omitempty"`

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

// --- Network Security Intelligence types ---

// SynFloodEntry holds BPF-detected SYN flood indicators per source IP.
type SynFloodEntry struct {
	SrcIP         string  `json:"src_ip"`
	SynCount      uint64  `json:"syn_count"`
	SynAckRetrans uint64  `json:"synack_retrans"`
	HalfOpenRatio float64 `json:"half_open_ratio"`
	Rate          float64 `json:"rate"`
}

// PortScanEntry holds BPF-detected port scan indicators per source IP.
type PortScanEntry struct {
	SrcIP             string  `json:"src_ip"`
	RSTCount          uint64  `json:"rst_count"`
	UniquePortBuckets int     `json:"unique_port_buckets"`
	DurationSec       float64 `json:"duration_sec"`
	Rate              float64 `json:"rate"`
}

// DNSAnomalyEntry holds BPF-detected DNS anomaly indicators per process.
type DNSAnomalyEntry struct {
	PID            int     `json:"pid"`
	Comm           string  `json:"comm"`
	QueryCount     uint64  `json:"query_count"`
	AvgQueryLen    int     `json:"avg_query_len"`
	TotalRespBytes uint64  `json:"total_resp_bytes"`
	QueriesPerSec  float64 `json:"queries_per_sec"`
}

// FlowRateEntry holds BPF-detected connection flow rate data per process/destination.
type FlowRateEntry struct {
	PID             int     `json:"pid"`
	Comm            string  `json:"comm"`
	DstIP           string  `json:"dst_ip"`
	ConnectCount    uint64  `json:"connect_count"`
	CloseCount      uint64  `json:"close_count"`
	UniqueDestCount int     `json:"unique_dest_count"`
	Rate            float64 `json:"rate"`
}

// OutboundEntry holds BPF-detected top outbound data transfer per process/destination.
type OutboundEntry struct {
	PID         int     `json:"pid"`
	Comm        string  `json:"comm"`
	DstIP       string  `json:"dst_ip"`
	TotalBytes  uint64  `json:"total_bytes"`
	PacketCount uint64  `json:"packet_count"`
	BytesPerSec float64 `json:"bytes_per_sec"`
}

// TCPFlagAnomaly holds BPF-detected unusual TCP flag combinations.
type TCPFlagAnomaly struct {
	SrcIP     string `json:"src_ip"`
	FlagCombo string `json:"flag_combo"`
	Count     uint64 `json:"count"`
}

// DNSTunnelIndicator holds BPF-detected DNS tunneling indicators per process.
type DNSTunnelIndicator struct {
	PID         int     `json:"pid,omitempty"`
	Comm        string  `json:"comm,omitempty"`
	SrcIP       string  `json:"src_ip,omitempty"`
	DomainHash  string  `json:"domain_hash,omitempty"`
	TXTRatio    float64 `json:"txt_ratio"`
	AvgQueryLen int     `json:"avg_query_len"`
	QueryRate   float64 `json:"query_rate,omitempty"`
}

// JA3Entry holds a TLS JA3 fingerprint hash and its occurrence data.
type JA3Entry struct {
	Hash      string `json:"hash"`
	Count     uint64 `json:"count"`
	SampleSrc string `json:"sample_src"`
	SampleDst string `json:"sample_dst"`
	Known     string `json:"known"`
}

// BeaconIndicator holds BPF-detected C2 beacon-like periodic connection indicators.
type BeaconIndicator struct {
	PID            int     `json:"pid"`
	Comm           string  `json:"comm"`
	DstIP          string  `json:"dst_ip"`
	DstPort        uint16  `json:"dst_port"`
	AvgIntervalSec float64 `json:"avg_interval_sec"`
	Jitter         float64 `json:"jitter"`
	SampleCount    int     `json:"sample_count"`
}

// DotNetProcessMetrics holds .NET Core runtime metrics for a single process.
type DotNetProcessMetrics struct {
	PID              int     `json:"pid"`
	Comm             string  `json:"comm"`
	GCHeapSizeMB     float64 `json:"gc_heap_size_mb"`
	Gen0GCCount      uint64  `json:"gen0_gc_count"`
	Gen1GCCount      uint64  `json:"gen1_gc_count"`
	Gen2GCCount      uint64  `json:"gen2_gc_count"`
	TimeInGCPct      float64 `json:"time_in_gc_pct"`
	AllocRateMBs     float64 `json:"alloc_rate_mbs"`
	ThreadPoolCount  int     `json:"threadpool_count"`
	ThreadPoolQueue  int     `json:"threadpool_queue"`
	ExceptionCount   uint64  `json:"exception_count"`
	MonitorLockCount uint64  `json:"monitor_lock_count"`
	WorkingSetMB     float64 `json:"working_set_mb"`
	RequestsPerSec   float64 `json:"requests_per_sec"`
	CurrentRequests  int     `json:"current_requests"`
}

// RuntimeProcessMetrics holds metrics for a single process detected by a language runtime module.
type RuntimeProcessMetrics struct {
	PID          int               `json:"pid"`
	Comm         string            `json:"comm"`
	Runtime      string            `json:"runtime"` // "jvm", "dotnet", "python", "node", "go"
	WorkingSetMB float64           `json:"working_set_mb"`
	ThreadCount  int               `json:"thread_count"`
	GCHeapMB     float64           `json:"gc_heap_mb,omitempty"`
	GCPausePct   float64           `json:"gc_pause_pct,omitempty"`
	GCCount      uint64            `json:"gc_count,omitempty"`
	AllocRateMBs float64           `json:"alloc_rate_mbs,omitempty"`
	Extra        map[string]string `json:"extra,omitempty"`
}

// RuntimeEntry represents one detected language runtime and its processes.
type RuntimeEntry struct {
	Name        string                  `json:"name"`         // "jvm", "dotnet", etc.
	DisplayName string                  `json:"display_name"` // "JVM", ".NET", etc.
	Active      bool                    `json:"active"`
	Processes   []RuntimeProcessMetrics `json:"processes"`
}

// RuntimeMetrics holds all detected language runtime data.
type RuntimeMetrics struct {
	Entries []RuntimeEntry `json:"entries,omitempty"`
}

// AppIdentity holds the resolved application identity for a process.
type AppIdentity struct {
	PID           int
	Comm          string // raw comm from /proc/PID/stat
	AppName       string // resolved application name ("Elasticsearch")
	AppVersion    string // version if detectable
	BinaryPath    string // /proc/PID/exe target
	Cmdline       string // full cmdline (truncated to 256 chars)
	ServiceUnit   string // systemd unit name
	ContainerID   string // container ID prefix (12 chars)
	ParentComm    string // parent process comm
	ParentPID     int
	CgroupPath    string
	DisplayName   string // pre-formatted: "Elasticsearch [java, elasticsearch.service]"
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
	Conntrack         ConntrackStats
	ConntrackDissect  ConntrackDissection
	ConntrackTimeouts ConntrackTimeouts
	FD                FDStats
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
	DotNet         []DotNetProcessMetrics
	Runtimes       RuntimeMetrics
	AppIdentities  map[int]AppIdentity // PID → resolved identity
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
