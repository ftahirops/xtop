package model

// ProxmoxMetrics holds Proxmox VE host-level data.
type ProxmoxMetrics struct {
	IsProxmoxHost bool
	NodeName      string
	PVEVersion    string
	VMs           []ProxmoxVM
	Storage       []ProxmoxStorage
}

// ProxmoxVM represents a single QEMU/KVM virtual machine.
type ProxmoxVM struct {
	VMID   int
	Name   string
	Status string // "running", "stopped", "paused"
	PID    int    // KVM process PID (0 if stopped)

	// Config (from .conf)
	CoresAlloc  int
	MemAllocMB  int
	DiskConfigs []ProxmoxDiskConf
	NetConfigs  []ProxmoxNetConf

	// Live metrics (from cgroups + /proc)
	CPUPct     float64 // current CPU% of total host
	MemUsedMB  int     // current RSS
	IOReadMBs  float64
	IOWriteMBs float64
	NetRxMBs   float64
	NetTxMBs   float64
	UptimeSec  int64
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
	Name      string
	Type      string // "lvmthin", "dir", "nfs", "zfspool"
	Path      string // mount path or VG/LV
	TotalGB   float64
	UsedGB    float64
	AvailGB   float64
	UsedPct   float64
}
