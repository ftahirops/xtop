package collector

import (
	"strings"
	"syscall"

	"github.com/ftahirops/xtop/model"
	"github.com/ftahirops/xtop/util"
)

// pseudoFS lists filesystem types to skip (not real block-backed filesystems).
var pseudoFS = map[string]bool{
	"sysfs": true, "proc": true, "devtmpfs": true, "tmpfs": true,
	"cgroup": true, "cgroup2": true, "debugfs": true, "tracefs": true,
	"securityfs": true, "hugetlbfs": true, "mqueue": true, "fusectl": true,
	"configfs": true, "pstore": true, "bpf": true, "ramfs": true,
	"rpc_pipefs": true, "nsfs": true, "autofs": true, "efivarfs": true,
	"squashfs": true, "iso9660": true, "devpts": true, "overlay": true,
}

// FilesystemCollector reads /proc/mounts and calls statfs per real mount.
type FilesystemCollector struct{}

func (f *FilesystemCollector) Name() string { return "filesystem" }

func (f *FilesystemCollector) Collect(snap *model.Snapshot) error {
	lines, err := util.ReadFileLines("/proc/mounts")
	if err != nil {
		return err
	}

	seen := make(map[string]bool) // deduplicate by device
	var mounts []model.MountStats

	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		dev := fields[0]
		mountPoint := fields[1]
		fsType := fields[2]

		if pseudoFS[fsType] {
			continue
		}
		// Skip non-device mounts
		if !strings.HasPrefix(dev, "/") {
			continue
		}
		if seen[dev] {
			continue
		}
		seen[dev] = true

		var stat syscall.Statfs_t
		if err := syscall.Statfs(mountPoint, &stat); err != nil {
			continue
		}

		bsize := uint64(stat.Bsize)
		totalBytes := stat.Blocks * bsize
		freeBytes := stat.Bfree * bsize
		availBytes := stat.Bavail * bsize
		usedBytes := totalBytes - freeBytes

		ms := model.MountStats{
			MountPoint:  mountPoint,
			Device:      dev,
			FSType:      fsType,
			TotalBytes:  totalBytes,
			FreeBytes:   freeBytes,
			AvailBytes:  availBytes,
			UsedBytes:   usedBytes,
			TotalInodes: stat.Files,
			FreeInodes:  stat.Ffree,
			UsedInodes:  stat.Files - stat.Ffree,
		}
		mounts = append(mounts, ms)
	}

	snap.Global.Mounts = mounts
	return nil
}
