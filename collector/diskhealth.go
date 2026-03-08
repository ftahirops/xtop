//go:build linux

package collector

import (
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"

	"github.com/ftahirops/xtop/model"
)

// ── NVMe SMART via ioctl ────────────────────────────────────────────────────

// nvmePassthruCmd matches struct nvme_passthru_cmd from <linux/nvme_ioctl.h>.
type nvmePassthruCmd struct {
	Opcode      uint8
	Flags       uint8
	Rsvd1       uint16
	Nsid        uint32
	Cdw2        uint32
	Cdw3        uint32
	Metadata    uint64
	Addr        uint64
	MetadataLen uint32
	DataLen     uint32
	Cdw10       uint32
	Cdw11       uint32
	Cdw12       uint32
	Cdw13       uint32
	Cdw14       uint32
	Cdw15       uint32
	TimeoutMs   uint32
	Result      uint32
}

const (
	nvmeAdminGetLogPage = 0x02  // Get Log Page opcode
	nvmeLogSMART        = 0x02  // SMART / Health Information log
	nvmeIOCTLAdminCmd   = 0xC0484E41 // _IOWR('N', 0x41, 72) on x86_64
)

// nvmeSMARTLog is the 512-byte SMART/Health Information Log (NVMe spec 5.14.1.2).
type nvmeSMARTLog struct {
	CriticalWarning         uint8
	Temperature             [2]uint8 // Kelvin, little-endian uint16
	AvailableSpare          uint8
	AvailableSpareThreshold uint8
	PercentageUsed          uint8
	EndurGrpCritWarnSummary uint8
	Reserved7               [25]uint8
	DataUnitsRead           [16]uint8 // uint128 LE, each unit = 1000 × 512B
	DataUnitsWritten        [16]uint8 // uint128 LE
	HostReadCmds            [16]uint8 // uint128 LE
	HostWriteCmds           [16]uint8 // uint128 LE
	CtrlBusyTime            [16]uint8 // uint128 LE (minutes)
	PowerCycles             [16]uint8 // uint128 LE
	PowerOnHours            [16]uint8 // uint128 LE
	UnsafeShutdowns         [16]uint8 // uint128 LE
	MediaErrors             [16]uint8 // uint128 LE
	NumErrLogEntries        [16]uint8 // uint128 LE
	WarnCompTempTime        uint32    // minutes
	CritCompTempTime        uint32    // minutes
	TempSensors             [8]uint16
	ThermalMgmtTemp1Trans   uint32
	ThermalMgmtTemp2Trans   uint32
	ThermalMgmtTemp1Total   uint32
	ThermalMgmtTemp2Total   uint32
}

// readUint128Low reads the low 64 bits of a 128-bit LE integer (high bits always 0 in practice).
func readUint128Low(b [16]uint8) uint64 {
	return binary.LittleEndian.Uint64(b[:8])
}

// collectNVMeHealth reads SMART data for all NVMe devices via ioctl.
func collectNVMeHealth() []model.SMARTDisk {
	// Discover NVMe controller character devices (/dev/nvme0, /dev/nvme1, ...)
	matches, _ := filepath.Glob("/dev/nvme[0-9]*")
	if len(matches) == 0 {
		return nil
	}

	// Filter to only controller devices (/dev/nvme0, /dev/nvme1), not namespaces (/dev/nvme0n1)
	var controllers []string
	for _, m := range matches {
		base := filepath.Base(m) // "nvme0", "nvme0n1", etc.
		// Controllers are "nvme" + digits only; namespaces contain "n" after the digits
		if strings.ContainsAny(base[4:], "npP") {
			continue // skip namespaces like nvme0n1, nvme0n1p1
		}
		controllers = append(controllers, m)
	}

	var disks []model.SMARTDisk
	for _, ctrl := range controllers {
		disk := readNVMeSMART(ctrl)
		if disk.Name != "" {
			disks = append(disks, disk)
		}
	}
	return disks
}

func readNVMeSMART(ctrlDev string) (disk model.SMARTDisk) {
	// Recover from any panic in unsafe ioctl code
	defer func() {
		if r := recover(); r != nil {
			disk.ErrorString = fmt.Sprintf("panic: %v", r)
		}
	}()

	// Find the namespace block devices for this controller (e.g., nvme0n1)
	ctrlName := filepath.Base(ctrlDev) // "nvme0"
	nsMatches, _ := filepath.Glob("/sys/block/" + ctrlName + "n*")
	blockName := ctrlName + "n1" // default
	if len(nsMatches) > 0 {
		blockName = filepath.Base(nsMatches[0])
	}

	disk = model.SMARTDisk{
		Device:                  ctrlDev,
		Name:                    blockName,
		DiskType:                model.DiskTypeNVMe,
		WearLevelPct:            -1,
		PercentUsed:             -1,
		AvailableSpare:          -1,
		AvailableSpareThreshold: -1,
		EstLifeDays:             -1,
		Source:                  "nvme_ioctl",
	}

	// Read model from sysfs
	if m, err := os.ReadFile("/sys/class/nvme/" + ctrlName + "/model"); err == nil {
		disk.ModelNumber = strings.TrimSpace(string(m))
	}
	if s, err := os.ReadFile("/sys/class/nvme/" + ctrlName + "/serial"); err == nil {
		disk.SerialNum = strings.TrimSpace(string(s))
	}

	// Open controller character device
	fd, err := syscall.Open(ctrlDev, syscall.O_RDONLY, 0)
	if err != nil {
		disk.ErrorString = fmt.Sprintf("open %s: %v", ctrlDev, err)
		return disk
	}
	defer syscall.Close(fd)

	// Issue GET LOG PAGE for SMART/Health log (log ID 0x02)
	var logBuf [512]byte
	cmd := nvmePassthruCmd{
		Opcode:    nvmeAdminGetLogPage,
		Nsid:      0xFFFFFFFF, // global
		Addr:      uint64(uintptr(unsafe.Pointer(&logBuf[0]))),
		DataLen:   512,
		Cdw10:     uint32((127 << 16) | nvmeLogSMART), // numdw=127 (512/4-1) | log_id
		TimeoutMs: 5000,
	}

	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd),
		uintptr(nvmeIOCTLAdminCmd), uintptr(unsafe.Pointer(&cmd)))
	if errno != 0 {
		disk.ErrorString = fmt.Sprintf("ioctl SMART: %v", errno)
		return disk
	}

	// Parse the SMART log — only copy the struct size, not the full 512-byte buffer
	var log nvmeSMARTLog
	logSize := unsafe.Sizeof(log)
	copy((*[512]byte)(unsafe.Pointer(&log))[:logSize], logBuf[:logSize])

	disk.HealthOK = true
	disk.CriticalWarning = log.CriticalWarning
	if log.CriticalWarning != 0 {
		disk.HealthOK = false
	}

	// Temperature in Kelvin → Celsius
	tempK := int(binary.LittleEndian.Uint16(log.Temperature[:]))
	if tempK > 0 {
		disk.Temperature = tempK - 273
	}

	disk.AvailableSpare = int(log.AvailableSpare)
	disk.AvailableSpareThreshold = int(log.AvailableSpareThreshold)
	disk.PercentUsed = int(log.PercentageUsed)
	if disk.PercentUsed >= 0 && disk.PercentUsed <= 100 {
		disk.WearLevelPct = 100 - disk.PercentUsed
	}

	disk.DataUnitsWritten = readUint128Low(log.DataUnitsWritten)
	disk.MediaErrors = readUint128Low(log.MediaErrors)
	disk.UnsafeShutdowns = readUint128Low(log.UnsafeShutdowns)
	disk.PowerOnHours = int(readUint128Low(log.PowerOnHours))

	// Compute total bytes written: units × 1000 × 512 bytes
	disk.TotalBytesWritten = disk.DataUnitsWritten * 1000 * 512
	disk.TotalBytesRead = readUint128Low(log.DataUnitsRead) * 1000 * 512

	// Compute TBW and write rate
	disk.WriteTBW = float64(disk.TotalBytesWritten) / (1024.0 * 1024 * 1024 * 1024)
	if disk.PowerOnHours > 0 {
		hoursPerYear := 365.25 * 24
		disk.WriteRateTBPerYear = disk.WriteTBW / (float64(disk.PowerOnHours) / hoursPerYear)
	}

	// Estimate remaining life
	computeEstLife(&disk)

	return disk
}

// ── SATA SMART via ioctl ────────────────────────────────────────────────────

const (
	hdioSmartCmd      = 0x031f // HDIO_DRIVE_CMD
	winSmart          = 0xB0   // ATA SMART command
	smartReadValues   = 0xD0   // read attribute values
	smartCylLo        = 0x4F
	smartCylHi        = 0xC2
)

// collectSATAHealth reads SMART attributes for SATA drives via HDIO ioctl.
func collectSATAHealth() []model.SMARTDisk {
	matches, _ := filepath.Glob("/sys/block/sd[a-z]*")
	if len(matches) == 0 {
		return nil
	}

	var disks []model.SMARTDisk
	for _, sysPath := range matches {
		name := filepath.Base(sysPath)
		if isVirtualDisk(sysPath) {
			disks = append(disks, virtualDiskEntry(name, sysPath))
			continue
		}
		disk := readSATASMART(name, sysPath)
		if disk.Name != "" {
			disks = append(disks, disk)
		}
	}
	return disks
}

func isVirtualDisk(sysPath string) bool {
	vendor, _ := os.ReadFile(sysPath + "/device/vendor")
	v := strings.TrimSpace(strings.ToUpper(string(vendor)))
	switch {
	case strings.Contains(v, "QEMU"), strings.Contains(v, "VMWARE"),
		strings.Contains(v, "XEN"), strings.Contains(v, "VBOX"),
		strings.Contains(v, "VIRTIO"), strings.Contains(v, "GOOGLE"),
		strings.Contains(v, "MSFT"), strings.Contains(v, "RED HAT"):
		return true
	}
	return false
}

func readSATASMART(name, sysPath string) (disk model.SMARTDisk) {
	// Recover from any panic in unsafe ioctl code
	defer func() {
		if r := recover(); r != nil {
			disk.ErrorString = fmt.Sprintf("panic: %v", r)
		}
	}()

	disk = model.SMARTDisk{
		Device:                  "/dev/" + name,
		Name:                    name,
		WearLevelPct:            -1,
		PercentUsed:             -1,
		AvailableSpare:          -1,
		AvailableSpareThreshold: -1,
		EstLifeDays:             -1,
		Source:                  "sata_ioctl",
	}

	// Determine disk type from rotational flag
	rotData, err := os.ReadFile(sysPath + "/queue/rotational")
	if err == nil {
		if strings.TrimSpace(string(rotData)) == "0" {
			disk.DiskType = model.DiskTypeSATASSD
		} else {
			disk.DiskType = model.DiskTypeSATAHDD
		}
	} else {
		disk.DiskType = model.DiskTypeUnknown
	}

	// Read model from sysfs
	if m, err := os.ReadFile(sysPath + "/device/model"); err == nil {
		disk.ModelNumber = strings.TrimSpace(string(m))
	}

	// Open block device
	fd, err := syscall.Open("/dev/"+name, syscall.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		disk.ErrorString = fmt.Sprintf("open /dev/%s: %v", name, err)
		return disk
	}
	defer syscall.Close(fd)

	// HDIO_DRIVE_CMD: 4-byte header + 512-byte data
	var buf [4 + 512]byte
	buf[0] = winSmart    // command
	buf[1] = smartReadValues // feature
	buf[2] = 1           // sector count
	buf[3] = 0           // unused

	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd),
		uintptr(hdioSmartCmd), uintptr(unsafe.Pointer(&buf[0])))
	if errno != 0 {
		// SATA SMART ioctl failed — try SCSI passthrough or mark as unsupported
		disk.ErrorString = fmt.Sprintf("SMART ioctl: %v", errno)
		return disk
	}

	// Parse SMART attribute table
	// 30 attributes × 12 bytes each, starting at offset 2 in the 512-byte data
	data := buf[4:] // skip 4-byte header
	disk.HealthOK = true

	for i := 0; i < 30; i++ {
		offset := 2 + i*12
		if offset+12 > len(data) {
			break
		}
		attrID := data[offset]
		if attrID == 0 {
			continue
		}
		normalizedVal := int(data[offset+3])
		rawVal := int(binary.LittleEndian.Uint32(data[offset+5 : offset+9]))
		rawVal48 := binary.LittleEndian.Uint64(append(data[offset+5:offset+11], 0, 0))

		switch attrID {
		case 5: // Reallocated_Sector_Ct
			disk.ReallocSectors = rawVal
		case 9: // Power_On_Hours
			disk.PowerOnHours = rawVal
		case 177: // Wear_Leveling_Count (Samsung, etc.)
			if normalizedVal > 0 && normalizedVal <= 100 {
				disk.WearLevelPct = normalizedVal
				disk.PercentUsed = 100 - normalizedVal
			}
		case 194: // Temperature_Celsius
			disk.Temperature = rawVal & 0xFF // low byte is current temp
		case 197: // Current_Pending_Sector
			disk.PendingSectors = rawVal
		case 231: // SSD_Life_Left
			if normalizedVal > 0 && normalizedVal <= 100 {
				disk.WearLevelPct = normalizedVal
				disk.PercentUsed = 100 - normalizedVal
			}
		case 233: // Media_Wearout_Indicator (Intel SSDs)
			if normalizedVal > 0 && normalizedVal <= 100 && disk.WearLevelPct < 0 {
				disk.WearLevelPct = normalizedVal
				disk.PercentUsed = 100 - normalizedVal
			}
		case 241: // Total_LBAs_Written
			disk.TotalBytesWritten = uint64(rawVal48) * 512 // LBAs to bytes
		case 242: // Total_LBAs_Read
			disk.TotalBytesRead = uint64(rawVal48) * 512
		}
	}

	// Compute TBW and write rate
	if disk.TotalBytesWritten > 0 {
		disk.WriteTBW = float64(disk.TotalBytesWritten) / (1024.0 * 1024 * 1024 * 1024)
	}
	if disk.PowerOnHours > 0 && disk.WriteTBW > 0 {
		hoursPerYear := 365.25 * 24
		disk.WriteRateTBPerYear = disk.WriteTBW / (float64(disk.PowerOnHours) / hoursPerYear)
	}

	computeEstLife(&disk)

	return disk
}

// virtualDiskEntry creates a placeholder entry for a virtual disk.
func virtualDiskEntry(name, sysPath string) model.SMARTDisk {
	disk := model.SMARTDisk{
		Device:                  "/dev/" + name,
		Name:                    name,
		DiskType:                model.DiskTypeVirtual,
		WearLevelPct:            -1,
		PercentUsed:             -1,
		AvailableSpare:          -1,
		AvailableSpareThreshold: -1,
		EstLifeDays:             -1,
		Source:                  "virtual",
	}
	if m, err := os.ReadFile(sysPath + "/device/model"); err == nil {
		disk.ModelNumber = strings.TrimSpace(string(m))
	}
	if v, err := os.ReadFile(sysPath + "/device/vendor"); err == nil {
		disk.ModelFamily = strings.TrimSpace(string(v))
	}
	disk.HealthOK = true
	return disk
}

// collectVirtualDisks detects paravirtual block devices (xvd*, vd*) that don't
// match the sd[a-z]* or nvme patterns.
func collectVirtualDisks() []model.SMARTDisk {
	var disks []model.SMARTDisk
	for _, pattern := range []string{"/sys/block/xvd[a-z]*", "/sys/block/vd[a-z]*"} {
		matches, _ := filepath.Glob(pattern)
		for _, sysPath := range matches {
			name := filepath.Base(sysPath)
			disks = append(disks, virtualDiskEntry(name, sysPath))
		}
	}
	return disks
}

// ── Life estimation ─────────────────────────────────────────────────────────

func computeEstLife(disk *model.SMARTDisk) {
	// Need both wear percentage and write rate to extrapolate
	pctUsed := disk.PercentUsed
	if pctUsed < 0 {
		return
	}
	if pctUsed >= 100 {
		disk.EstLifeDays = 0
		return
	}

	remaining := 100 - pctUsed
	if disk.PowerOnHours <= 0 || pctUsed <= 0 {
		return
	}

	// Wear rate: pctUsed / powerOnHours = % consumed per hour
	wearRatePerHour := float64(pctUsed) / float64(disk.PowerOnHours)
	if wearRatePerHour <= 0 {
		return
	}

	// Estimated hours remaining = remaining% / rate
	estHoursLeft := float64(remaining) / wearRatePerHour
	disk.EstLifeDays = int(estHoursLeft / 24)
}

// ── Unified collector ───────────────────────────────────────────────────────

// CollectDiskHealth gathers disk health from all available sources (NVMe ioctl, SATA ioctl).
func CollectDiskHealth() []model.SMARTDisk {
	var all []model.SMARTDisk

	// NVMe devices via direct ioctl (no smartctl needed)
	nvme := collectNVMeHealth()
	all = append(all, nvme...)

	// SATA devices via HDIO ioctl
	sata := collectSATAHealth()
	all = append(all, sata...)

	// Paravirtual devices (xvd*, vd*) — no SMART, just show them
	virt := collectVirtualDisks()
	all = append(all, virt...)

	return all
}
