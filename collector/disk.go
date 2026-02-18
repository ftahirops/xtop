package collector

import (
	"fmt"
	"strings"

	"github.com/ftahirops/xtop/model"
	"github.com/ftahirops/xtop/util"
)

// DiskCollector reads /proc/diskstats.
type DiskCollector struct{}

func (d *DiskCollector) Name() string { return "disk" }

func (d *DiskCollector) Collect(snap *model.Snapshot) error {
	lines, err := util.ReadFileLines("/proc/diskstats")
	if err != nil {
		return fmt.Errorf("read /proc/diskstats: %w", err)
	}

	var disks []model.DiskStats
	for _, line := range lines {
		ds, ok := parseDiskstatLine(line)
		if !ok {
			continue
		}
		// Skip partitions (keep whole devices): heuristic: no trailing digit or is a known device pattern
		if isWholeDisk(ds.Name) {
			disks = append(disks, ds)
		}
	}
	snap.Global.Disks = disks
	return nil
}

// parseDiskstatLine parses a line from /proc/diskstats.
// Format: major minor name reads_completed reads_merged sectors_read read_time
//         writes_completed writes_merged sectors_written write_time ios_in_progress io_time weighted_io_time
func parseDiskstatLine(line string) (model.DiskStats, bool) {
	fields := strings.Fields(line)
	if len(fields) < 14 {
		return model.DiskStats{}, false
	}
	name := fields[2]
	return model.DiskStats{
		Name:            name,
		ReadsCompleted:  util.ParseUint64(fields[3]),
		ReadsMerged:     util.ParseUint64(fields[4]),
		SectorsRead:     util.ParseUint64(fields[5]),
		ReadTimeMs:      util.ParseUint64(fields[6]),
		WritesCompleted: util.ParseUint64(fields[7]),
		WritesMerged:    util.ParseUint64(fields[8]),
		SectorsWritten:  util.ParseUint64(fields[9]),
		WriteTimeMs:     util.ParseUint64(fields[10]),
		IOsInProgress:   util.ParseUint64(fields[11]),
		IOTimeMs:        util.ParseUint64(fields[12]),
		WeightedIOMs:    util.ParseUint64(fields[13]),
	}, true
}

// isWholeDisk returns true if the name looks like a whole disk device (not a partition).
func isWholeDisk(name string) bool {
	// Include sd*, vd*, nvme*n* (but not nvme*n*p*), dm-*, loop*
	if strings.HasPrefix(name, "loop") {
		return false
	}
	// NVMe: nvme0n1 is a disk, nvme0n1p1 is a partition
	if strings.HasPrefix(name, "nvme") {
		return !strings.Contains(name[4:], "p")
	}
	// sd*, vd*, xvd*: disk has no trailing digit after letter
	for _, prefix := range []string{"sd", "vd", "xvd", "hd"} {
		if strings.HasPrefix(name, prefix) {
			suffix := name[len(prefix):]
			if len(suffix) == 1 && suffix[0] >= 'a' && suffix[0] <= 'z' {
				return true
			}
			return false
		}
	}
	// dm-* devices
	if strings.HasPrefix(name, "dm-") {
		return true
	}
	return false
}
