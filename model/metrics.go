package model

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

// GlobalMetrics is the full system-wide metric snapshot.
type GlobalMetrics struct {
	PSI       PSIMetrics
	CPU       CPUMetrics
	Memory    MemoryMetrics
	VMStat    VMStatMetrics
	Disks     []DiskStats
	Network   []NetworkStats
	TCP       TCPMetrics
	UDP       UDPMetrics
	Sockets   SocketStats
	TCPStates TCPConnState
	SoftIRQ   SoftIRQStats
	Conntrack ConntrackStats
	FD        FDStats
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
}
