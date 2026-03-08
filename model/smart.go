package model

// DiskType classifies the physical drive interface.
type DiskType string

const (
	DiskTypeNVMe    DiskType = "NVMe"
	DiskTypeSATASSD DiskType = "SSD"
	DiskTypeSATAHDD DiskType = "HDD"
	DiskTypeSCSI    DiskType = "SCSI"
	DiskTypeVirtual DiskType = "VIRT"
	DiskTypeUnknown DiskType = "???"
)

// SMARTDisk holds SMART health data for a single disk.
type SMARTDisk struct {
	Device      string // e.g., "/dev/sda", "/dev/nvme0n1"
	Name        string // short name: "sda", "nvme0n1"
	ModelFamily string
	ModelNumber string
	SerialNum   string
	DiskType    DiskType

	// Core health
	HealthOK    bool // SMART overall health passed
	Temperature int  // Celsius
	PowerOnHours int

	// Wear / endurance (NVMe + SSD)
	WearLevelPct  int // % life remaining (100=new, 0=dead, -1=unknown)
	PercentUsed   int // % endurance consumed (NVMe: 0=new, 100=EOL, -1=unknown)

	// NVMe-specific health indicators
	AvailableSpare          int // % spare capacity remaining (NVMe only, -1=unknown)
	AvailableSpareThreshold int // vendor-set minimum spare % (NVMe only, -1=unknown)
	CriticalWarning         uint8 // NVMe critical_warning bitmap
	MediaErrors             uint64 // NVMe media and data integrity errors
	UnsafeShutdowns         uint64

	// Write endurance data
	DataUnitsWritten uint64 // NVMe: each unit = 512KB (1000 × 512B sectors)
	TotalBytesWritten uint64 // computed: total bytes written (all disk types)
	TotalBytesRead    uint64

	// SATA-specific
	ReallocSectors int // reallocated sector count
	PendingSectors int // current pending sector count

	// Life estimation (computed)
	EstLifeDays       int     // estimated days of remaining life (-1=unknown)
	WriteTBW          float64 // total terabytes written
	WriteRateTBPerYear float64 // write rate in TB/year (from total_written / power_on_hours)

	// Source of data
	Source      string // "nvme_ioctl", "sata_ioctl", "smartctl"
	ErrorString string // non-empty if collection failed
}

// NVMeCriticalWarning bitmap constants.
const (
	NVMeWarnSpare       = 1 << 0 // available spare below threshold
	NVMeWarnTemperature = 1 << 1 // temperature above critical threshold
	NVMeWarnReliability = 1 << 2 // reliability degraded (media/internal errors)
	NVMeWarnReadOnly    = 1 << 3 // media placed in read-only mode
	NVMeWarnBackup      = 1 << 4 // volatile memory backup device failed
)

// HealthVerdict returns a human-readable health status.
func (d *SMARTDisk) HealthVerdict() string {
	if d.DiskType == DiskTypeVirtual {
		return "VIRT"
	}
	if d.ErrorString != "" {
		return "ERROR"
	}
	if !d.HealthOK {
		return "FAIL"
	}
	if d.CriticalWarning&NVMeWarnReliability != 0 || d.CriticalWarning&NVMeWarnReadOnly != 0 {
		return "FAILING"
	}
	if d.CriticalWarning&NVMeWarnSpare != 0 {
		return "CRITICAL"
	}
	if d.PercentUsed >= 90 || (d.WearLevelPct >= 0 && d.WearLevelPct <= 10) {
		return "CRITICAL"
	}
	if d.ReallocSectors > 100 || d.PendingSectors > 10 {
		return "CRITICAL"
	}
	if d.PercentUsed >= 70 || (d.WearLevelPct >= 0 && d.WearLevelPct <= 30) {
		return "WORN"
	}
	if d.ReallocSectors > 0 || d.PendingSectors > 0 {
		return "WARN"
	}
	if d.MediaErrors > 0 {
		return "WARN"
	}
	return "OK"
}
