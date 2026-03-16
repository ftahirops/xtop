//go:build linux

package profiler

import (
	"fmt"
	"strings"

	"github.com/ftahirops/xtop/model"
	"github.com/ftahirops/xtop/util"
)

func auditIO(role model.ServerRole, snap *model.Snapshot) []model.AuditRule {
	var result []model.AuditRule

	// Check IO scheduler per disk
	for _, disk := range snap.Global.Disks {
		name := disk.Name
		// Skip partitions (sda1, nvme0n1p1)
		if isPartition(name) {
			continue
		}

		schedulerPath := fmt.Sprintf("/sys/block/%s/queue/scheduler", name)
		schedulerRaw, err := util.ReadFileString(schedulerPath)
		if err != nil {
			continue
		}
		currentSched := extractBracketValue(strings.TrimSpace(schedulerRaw))

		isNVMe := strings.HasPrefix(name, "nvme")
		recommended := "mq-deadline"
		if isNVMe {
			recommended = "none"
		}

		status := model.RulePass
		if isNVMe && currentSched != "none" {
			status = model.RuleFail
		} else if !isNVMe && currentSched != "mq-deadline" && currentSched != "deadline" {
			if role == model.RoleDatabase && currentSched == "cfq" {
				status = model.RuleFail
			} else {
				status = model.RuleWarn
			}
		}

		schedFix := ""
		if status != model.RulePass {
			schedFix = fmt.Sprintf("echo %s > /sys/block/%s/queue/scheduler", recommended, name)
		}
		result = append(result, model.AuditRule{
			Domain:      model.OptDomainIO,
			Name:        fmt.Sprintf("io_scheduler[%s]", name),
			Description: fmt.Sprintf("IO scheduler for %s", name),
			Current:     currentSched,
			Recommended: recommended,
			Impact:      "Suboptimal IO ordering increases latency",
			Fix:         schedFix,
			Status:      status,
			Weight:      8,
		})

		// Check readahead
		raPath := fmt.Sprintf("/sys/block/%s/queue/read_ahead_kb", name)
		raStr, err := util.ReadFileString(raPath)
		if err == nil {
			ra := parseUint(strings.TrimSpace(raStr))
			recRA := uint64(256)
			if role == model.RoleDatabase {
				recRA = 256
			}
			if isNVMe {
				recRA = 128
			}

			status := model.RulePass
			raFix := ""
			if ra > recRA*4 {
				status = model.RuleWarn
				raFix = fmt.Sprintf("echo %d > /sys/block/%s/queue/read_ahead_kb", recRA, name)
			}
			result = append(result, model.AuditRule{
				Domain:      model.OptDomainIO,
				Name:        fmt.Sprintf("readahead[%s]", name),
				Description: fmt.Sprintf("Read-ahead buffer for %s (KB)", name),
				Current:     fmt.Sprintf("%d", ra),
				Recommended: fmt.Sprintf("<=%d", recRA),
				Impact:      "Excessive readahead wastes page cache on random IO workloads",
				Fix:         raFix,
				Status:      status,
				Weight:      3,
			})
		}

		// Check nr_requests
		nrPath := fmt.Sprintf("/sys/block/%s/queue/nr_requests", name)
		nrStr, err := util.ReadFileString(nrPath)
		if err == nil {
			nr := parseUint(strings.TrimSpace(nrStr))
			if nr < 256 && (role == model.RoleDatabase || role == model.RoleWebHosting) {
				result = append(result, model.AuditRule{
					Domain:      model.OptDomainIO,
					Name:        fmt.Sprintf("nr_requests[%s]", name),
					Description: fmt.Sprintf("IO queue depth for %s", name),
					Current:     fmt.Sprintf("%d", nr),
					Recommended: ">=256",
					Impact:      "IO queue bottleneck under heavy concurrent access",
					Fix:         fmt.Sprintf("echo 256 > /sys/block/%s/queue/nr_requests", name),
					Status:      model.RuleWarn,
					Weight:      5,
				})
			}
		}
	}

	// Check mount options — read /proc/mounts once for all mounts
	mountData, err := util.ReadFileString("/proc/mounts")
	if err == nil {
		for _, mount := range snap.Global.Mounts {
			if mount.MountPoint == "/" || mount.MountPoint == "/var" || mount.MountPoint == "/home" {
				result = append(result, checkMountOptions(mount, mountData)...)
			}
		}
	}

	return result
}

func checkMountOptions(mount model.MountStats, mountData string) []model.AuditRule {
	var result []model.AuditRule

	for _, line := range strings.Split(mountData, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 4 || fields[1] != mount.MountPoint {
			continue
		}
		opts := fields[3]

		if !strings.Contains(opts, "noatime") && !strings.Contains(opts, "relatime") {
			result = append(result, model.AuditRule{
				Domain:      model.OptDomainIO,
				Name:        fmt.Sprintf("mount_atime[%s]", mount.MountPoint),
				Description: fmt.Sprintf("Access time updates on %s", mount.MountPoint),
				Current:     "atime (full access time tracking)",
				Recommended: "noatime or relatime",
				Impact:      "Extra write IO for every file read",
				Fix:         fmt.Sprintf("Add 'noatime' to mount options in /etc/fstab and run 'mount -o remount,noatime %s'", mount.MountPoint),
				Status:      model.RuleWarn,
				Weight:      5,
			})
		}

		if strings.Contains(opts, "barrier=0") || strings.Contains(opts, "nobarrier") {
			result = append(result, model.AuditRule{
				Domain:      model.OptDomainIO,
				Name:        fmt.Sprintf("mount_barrier[%s]", mount.MountPoint),
				Description: fmt.Sprintf("Write barriers on %s", mount.MountPoint),
				Current:     "disabled (nobarrier)",
				Recommended: "enabled (default) unless battery-backed RAID",
				Impact:      "Data corruption risk on power failure",
				Status:      model.RuleWarn,
				Weight:      8,
			})
		}
		break
	}

	return result
}

// isPartition uses string-based heuristics to detect partitions.
// NVMe: nvme0n1p1 has "p" followed by digits after the base device.
// SCSI/virtio: sda1, vda1 end with digits after letters.
func isPartition(name string) bool {
	if len(name) == 0 {
		return false
	}
	if strings.HasPrefix(name, "nvme") {
		// nvme0n1 = disk, nvme0n1p1 = partition
		// Find "n<digits>" then check for "p<digits>" after
		idx := strings.LastIndex(name, "p")
		if idx <= 0 {
			return false
		}
		// Everything after 'p' must be digits
		after := name[idx+1:]
		if len(after) == 0 {
			return false
		}
		for _, c := range after {
			if c < '0' || c > '9' {
				return false
			}
		}
		return true
	}
	// sda1, vda1, xvda1 — last char is a digit
	last := name[len(name)-1]
	return last >= '0' && last <= '9'
}
