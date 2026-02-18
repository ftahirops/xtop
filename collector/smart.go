package collector

import (
	"encoding/json"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/ftahirops/xtop/model"
)

// SMARTCollector runs smartctl periodically and caches results.
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

// Get returns cached SMART data, refreshing if stale.
func (s *SMARTCollector) Get() []model.SMARTDisk {
	s.mu.RLock()
	if time.Since(s.lastRun) < s.interval && len(s.disks) > 0 {
		disks := s.disks
		s.mu.RUnlock()
		return disks
	}
	s.mu.RUnlock()

	// Need to refresh
	s.mu.Lock()
	defer s.mu.Unlock()

	// Double-check after acquiring write lock
	if time.Since(s.lastRun) < s.interval && len(s.disks) > 0 {
		return s.disks
	}

	s.disks = collectSMART()
	s.lastRun = time.Now()
	return s.disks
}

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
				Value int `json:"value"`
			} `json:"raw"`
		} `json:"table"`
	} `json:"ata_smart_attributes"`
	NVMeSmartHealthLog struct {
		PercentageUsed int `json:"percentage_used"`
		Temperature    int `json:"temperature"`
	} `json:"nvme_smart_health_information_log"`
}

func collectSMART() []model.SMARTDisk {
	// Check if smartctl exists
	path, err := exec.LookPath("smartctl")
	if err != nil {
		return nil
	}

	// Scan for devices
	scanOut, err := exec.Command(path, "--scan", "--json").Output()
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
		Device:       device,
		WearLevelPct: -1,
	}

	// Extract short name: /dev/sda -> sda, /dev/nvme0n1 -> nvme0n1
	parts := strings.Split(device, "/")
	disk.Name = parts[len(parts)-1]

	args := []string{"-a", "--json", device}
	if devType != "" {
		args = []string{"-a", "--json", "-d", devType, device}
	}

	out, err := exec.Command(smartctlPath, args...).Output()
	if err != nil {
		// smartctl returns non-zero for many non-error reasons
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
	disk.Temperature = data.Temperature.Current
	disk.PowerOnHours = data.PowerOnTime.Hours

	// NVMe specific
	if data.NVMeSmartHealthLog.PercentageUsed > 0 || data.NVMeSmartHealthLog.Temperature > 0 {
		disk.WearLevelPct = 100 - data.NVMeSmartHealthLog.PercentageUsed
		if disk.Temperature == 0 {
			disk.Temperature = data.NVMeSmartHealthLog.Temperature
		}
	}

	// ATA SMART attributes
	for _, attr := range data.ATASmartAttributes.Table {
		switch attr.ID {
		case 5: // Reallocated_Sector_Ct
			disk.ReallocSectors = attr.Raw.Value
		case 197: // Current_Pending_Sector
			disk.PendingSectors = attr.Raw.Value
		case 177, 231: // Wear_Leveling_Count / SSD_Life_Left
			if attr.Value > 0 && attr.Value <= 100 {
				disk.WearLevelPct = attr.Value
			}
		case 194: // Temperature_Celsius
			if disk.Temperature == 0 {
				disk.Temperature = attr.Raw.Value
			}
		}
	}

	return disk
}
