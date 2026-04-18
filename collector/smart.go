package collector

import (
	"context"
	"encoding/json"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/ftahirops/xtop/model"
)

// SMARTCollector runs disk health collection periodically and caches results.
// It tries direct kernel ioctls first (NVMe, SATA), then falls back to smartctl.
type SMARTCollector struct {
	mu       sync.RWMutex
	disks    []model.SMARTDisk
	lastRun  time.Time
	interval time.Duration
}

// NewSMARTCollector creates a collector that refreshes every interval.
func NewSMARTCollector(interval time.Duration) *SMARTCollector {
	return &SMARTCollector{interval: interval}
}

// Get returns cached disk health data, triggering async refresh if stale.
func (s *SMARTCollector) Get() []model.SMARTDisk {
	s.mu.RLock()
	disks := s.disks
	s.mu.RUnlock()

	// Trigger async refresh in background (non-blocking)
	s.mu.Lock()
	stale := time.Since(s.lastRun) >= s.interval || len(s.disks) == 0
	s.mu.Unlock()

	if stale {
		go func() {
			data := s.collect()
			s.mu.Lock()
			s.disks = data
			s.lastRun = time.Now()
			s.mu.Unlock()
		}()
	}

	return disks
}

func (s *SMARTCollector) collect() []model.SMARTDisk {
	// Track which devices were already covered by ioctl
	covered := make(map[string]bool)

	// Layer 1: Direct ioctl (no external tools needed)
	ioctlDisks := CollectDiskHealth()
	for _, d := range ioctlDisks {
		covered[d.Name] = true
		// Also mark controller name as covered (e.g., "nvme0" for "nvme0n1")
		covered[d.Device] = true
		base := filepath.Base(d.Device)
		covered[base] = true
	}

	// Layer 2: smartctl fallback for any devices not covered
	smartctlDisks := collectSMARTctl()
	for _, d := range smartctlDisks {
		if !covered[d.Name] && !covered[d.Device] {
			ioctlDisks = append(ioctlDisks, d)
		}
	}

	return ioctlDisks
}

// ── smartctl fallback ───────────────────────────────────────────────────────

// smartctlJSON is the relevant subset of smartctl --json output.
type smartctlJSON struct {
	Device struct {
		Name     string `json:"name"`
		InfoName string `json:"info_name"`
		Type     string `json:"type"`
		Protocol string `json:"protocol"`
	} `json:"device"`
	ModelFamily string `json:"model_family"`
	ModelName   string `json:"model_name"`
	SerialNumber string `json:"serial_number"`
	SmartStatus struct {
		Passed bool `json:"passed"`
	} `json:"smart_status"`
	Temperature struct {
		Current int `json:"current"`
	} `json:"temperature"`
	PowerOnTime struct {
		Hours int `json:"hours"`
	} `json:"power_on_time"`
	ATASmartAttributes struct {
		Table []struct {
			ID    int    `json:"id"`
			Name  string `json:"name"`
			Value int    `json:"value"`
			Raw   struct {
				Value int    `json:"value"`
				Str   string `json:"string"`
			} `json:"raw"`
		} `json:"table"`
	} `json:"ata_smart_attributes"`
	NVMeSmartHealthLog struct {
		PercentageUsed        int `json:"percentage_used"`
		Temperature           int `json:"temperature"`
		AvailableSpare        int `json:"available_spare"`
		AvailableSpareThreshold int `json:"available_spare_threshold"`
		MediaErrors           int `json:"media_errors"`
		DataUnitsWritten      int `json:"data_units_written"`
		DataUnitsRead         int `json:"data_units_read"`
		PowerOnHours          int `json:"power_on_hours"`
		UnsafeShutdowns       int `json:"unsafe_shutdowns"`
		CriticalWarning       int `json:"critical_warning"`
	} `json:"nvme_smart_health_information_log"`
}

func collectSMARTctl() []model.SMARTDisk {
	path, err := exec.LookPath("smartctl")
	if err != nil {
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	scanOut, err := exec.CommandContext(ctx, path, "--scan", "--json").Output()
	if err != nil {
		return nil
	}

	var scanResult struct {
		Devices []struct {
			Name     string `json:"name"`
			InfoName string `json:"info_name"`
			Type     string `json:"type"`
		} `json:"devices"`
	}
	if err := json.Unmarshal(scanOut, &scanResult); err != nil {
		return nil
	}

	var disks []model.SMARTDisk
	for _, dev := range scanResult.Devices {
		disk := querySMARTDevice(path, dev.Name, dev.Type)
		if disk.Name != "" {
			disks = append(disks, disk)
		}
	}
	return disks
}

func querySMARTDevice(smartctlPath, device, devType string) model.SMARTDisk {
	disk := model.SMARTDisk{
		Device:                  device,
		WearLevelPct:            -1,
		PercentUsed:             -1,
		AvailableSpare:          -1,
		AvailableSpareThreshold: -1,
		EstLifeDays:             -1,
		Source:                  "smartctl",
	}

	parts := strings.Split(device, "/")
	disk.Name = parts[len(parts)-1]

	args := []string{"-a", "--json", device}
	if devType != "" {
		args = []string{"-a", "--json", "-d", devType, device}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, smartctlPath, args...).Output()
	if err != nil {
		if len(out) == 0 {
			disk.ErrorString = err.Error()
			return disk
		}
	}

	var data smartctlJSON
	if err := json.Unmarshal(out, &data); err != nil {
		disk.ErrorString = "parse error"
		return disk
	}

	disk.HealthOK = data.SmartStatus.Passed
	disk.ModelFamily = data.ModelFamily
	disk.ModelNumber = data.ModelName
	disk.SerialNum = data.SerialNumber
	disk.Temperature = data.Temperature.Current
	disk.PowerOnHours = data.PowerOnTime.Hours

	// Classify disk type
	switch {
	case strings.Contains(strings.ToLower(data.Device.Protocol), "nvme"):
		disk.DiskType = model.DiskTypeNVMe
	case strings.Contains(strings.ToLower(data.Device.Type), "scsi"):
		disk.DiskType = model.DiskTypeSCSI
	default:
		disk.DiskType = model.DiskTypeUnknown
	}

	// NVMe specific
	nvme := data.NVMeSmartHealthLog
	if nvme.PercentageUsed > 0 || nvme.Temperature > 0 || nvme.AvailableSpare > 0 {
		disk.DiskType = model.DiskTypeNVMe
		disk.PercentUsed = nvme.PercentageUsed
		if disk.PercentUsed >= 0 && disk.PercentUsed <= 100 {
			disk.WearLevelPct = 100 - disk.PercentUsed
		}
		disk.AvailableSpare = nvme.AvailableSpare
		disk.AvailableSpareThreshold = nvme.AvailableSpareThreshold
		disk.CriticalWarning = uint8(nvme.CriticalWarning)
		disk.MediaErrors = uint64(nvme.MediaErrors)
		disk.UnsafeShutdowns = uint64(nvme.UnsafeShutdowns)
		disk.DataUnitsWritten = uint64(nvme.DataUnitsWritten)
		disk.TotalBytesWritten = disk.DataUnitsWritten * 1000 * 512
		disk.TotalBytesRead = uint64(nvme.DataUnitsRead) * 1000 * 512
		if disk.Temperature == 0 {
			disk.Temperature = nvme.Temperature
		}
		if nvme.PowerOnHours > 0 {
			disk.PowerOnHours = nvme.PowerOnHours
		}
	}

	// ATA SMART attributes
	for _, attr := range data.ATASmartAttributes.Table {
		switch attr.ID {
		case 5:
			disk.ReallocSectors = attr.Raw.Value
		case 9:
			if disk.PowerOnHours == 0 {
				disk.PowerOnHours = attr.Raw.Value
			}
		case 177, 231:
			if attr.Value > 0 && attr.Value <= 100 {
				disk.WearLevelPct = attr.Value
				disk.PercentUsed = 100 - attr.Value
				if disk.DiskType == model.DiskTypeUnknown {
					disk.DiskType = model.DiskTypeSATASSD
				}
			}
		case 233:
			if attr.Value > 0 && attr.Value <= 100 && disk.WearLevelPct < 0 {
				disk.WearLevelPct = attr.Value
				disk.PercentUsed = 100 - attr.Value
				if disk.DiskType == model.DiskTypeUnknown {
					disk.DiskType = model.DiskTypeSATASSD
				}
			}
		case 194:
			if disk.Temperature == 0 {
				disk.Temperature = attr.Raw.Value & 0xFF
			}
		case 197:
			disk.PendingSectors = attr.Raw.Value
		case 241:
			disk.TotalBytesWritten = uint64(attr.Raw.Value) * 512
		case 242:
			disk.TotalBytesRead = uint64(attr.Raw.Value) * 512
		}
	}

	// Classify HDD if no SSD attributes found and type still unknown
	if disk.DiskType == model.DiskTypeUnknown && disk.WearLevelPct < 0 {
		disk.DiskType = model.DiskTypeSATAHDD
	}

	// Compute write stats
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
