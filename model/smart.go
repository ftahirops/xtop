package model

// SMARTDisk holds SMART health data for a single disk.
type SMARTDisk struct {
	Device          string  // e.g., "/dev/sda", "/dev/nvme0n1"
	Name            string  // short name: "sda", "nvme0n1"
	ModelFamily     string
	ModelNumber     string
	HealthOK        bool    // SMART overall health passed
	Temperature     int     // Celsius
	WearLevelPct    int     // % life remaining (NVMe/SSD only, -1 if unknown)
	ReallocSectors  int     // reallocated sector count
	PendingSectors  int     // current pending sector count
	PowerOnHours    int
	ErrorString     string  // non-empty if smartctl failed
}
