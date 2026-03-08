package model

// ProxmoxMetrics holds Proxmox VE host-level data.
type ProxmoxMetrics struct {
	IsProxmoxHost bool
	NodeName      string
	PVEVersion    string
	VMs           []ProxmoxVM
	Storage       []ProxmoxStorage

	// HA and cluster-level features
	HAEnabled   bool
	HAResources []ProxmoxHAResource
	Replication []ProxmoxReplication
	Firewall    ProxmoxFirewall
}

// ProxmoxVM represents a single QEMU/KVM virtual machine.
type ProxmoxVM struct {
	VMID   int
	Name   string
	Status string // "running", "stopped", "paused"
	PID    int    // KVM process PID (0 if stopped)

	// Config (from .conf) — basic resources
	CoresAlloc   int
	SocketsAlloc int // CPU sockets
	MemAllocMB   int
	BalloonMinMB int // balloon minimum (0 = ballooning disabled)
	BalloonOn    bool
	DiskConfigs  []ProxmoxDiskConf
	NetConfigs   []ProxmoxNetConf

	// Config (from .conf) — advanced settings
	CPULimit     float64  // cpulimit (0=unlimited)
	CPUUnits     int      // cpuunits (1024=default)
	NUMA         bool     // NUMA topology enabled
	Machine      string   // q35, i440fx
	BIOS         string   // seabios, ovmf
	Protection   bool     // prevent accidental removal
	StartupOrder string   // startup: order=1,up=30
	Description  string   // VM description/notes
	SnapCount    int      // number of snapshots
	Features     string   // features field (e.g. "fuse=1,nesting=1")
	HostPCI      []string // PCI passthrough devices

	// Live metrics (from cgroups + /proc) — CPU
	CPUPct              float64 // current CPU% of total host
	CPUUserPct          float64 // user-space CPU%
	CPUSysPct           float64 // kernel-space CPU%
	CPUThrottledPeriods uint64  // number of throttled periods
	CPUThrottledPct     float64 // percentage of time throttled

	// Live metrics — memory
	MemUsedMB    int    // current RSS
	MemBalloonMB int    // actual memory after ballooning (from cgroup limit or QMP)
	MemPeakMB    int    // peak RSS watermark
	MemSwapMB    int    // swap usage
	MemLimitMB   int    // memory.max in MB (0=unlimited)
	MemHighMB    int    // memory.high in MB (0=unlimited)
	MemOOMKills  uint64 // total OOM kills
	MemOOMEvents uint64 // total OOM events (attempts)

	// Live metrics — PSI (per-VM pressure stall info, avg10)
	PSICPUSome float64
	PSIMemSome float64
	PSIIOSome  float64

	// Live metrics — IO and network
	IOReadMBs  float64
	IOWriteMBs float64
	NetRxMBs   float64
	NetTxMBs   float64

	// Live metrics — cgroup resource controls
	PIDCount    int    // current number of processes
	PIDLimit    int    // pids.max
	IOMaxBps    string // io.max limit if set
	CPUWeight   int    // cpu.weight
	CPUMaxQuota string // cpu.max (e.g. "200000 100000")

	// Live metrics — misc
	UptimeSec int64

	// Computed health
	HealthScore  int      // 0-100 composite health score
	HealthIssues []string // detected issue descriptions
}

// ProxmoxDiskConf holds VM disk configuration.
type ProxmoxDiskConf struct {
	Bus    string // "scsi0", "ide2", "virtio0"
	Path   string // "local-lvm:vm-100-disk-0", "/var/lib/vz/..."
	SizeGB int
	Cache  string // "none", "writeback", etc.
}

// ProxmoxNetConf holds VM network configuration.
type ProxmoxNetConf struct {
	ID     string // "net0"
	Model  string // "virtio", "e1000"
	MAC    string
	Bridge string // "vmbr0"
	Tag    int    // VLAN tag (0=none)
}

// ProxmoxStorage holds storage pool info.
type ProxmoxStorage struct {
	Name    string
	Type    string  // "lvmthin", "dir", "nfs", "zfspool"
	Path    string  // mount path or VG/LV
	TotalGB float64
	UsedGB  float64
	AvailGB float64
	UsedPct float64
}

// ProxmoxHAResource represents an HA-managed VM or container.
type ProxmoxHAResource struct {
	VMID         int
	State        string // "started", "stopped", "error", "fence"
	Group        string // HA group name
	MaxRestart   int    // max restart attempts before giving up
	MaxRelocate  int    // max relocate attempts before giving up
}

// ProxmoxReplication holds replication job status for a VM.
type ProxmoxReplication struct {
	VMID     int
	Target   string // target node name
	Schedule string // cron-style schedule (e.g. "*/15")
	LastSync string // timestamp of last successful sync
	Status   string // "ok", "error", "syncing"
}

// ProxmoxFirewall holds cluster and per-VM firewall state.
type ProxmoxFirewall struct {
	ClusterEnabled bool         // whether cluster-level firewall is active
	VMFirewalls    map[int]bool // VMID → firewall enabled
}
