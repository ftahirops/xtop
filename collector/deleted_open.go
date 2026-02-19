package collector

import (
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/ftahirops/xtop/model"
)

// DeletedOpenCollector scans /proc/*/fd/* for deleted-but-open files.
type DeletedOpenCollector struct {
	MaxFiles int // max results to return
}

func (d *DeletedOpenCollector) Name() string { return "deleted_open" }

func (d *DeletedOpenCollector) Collect(snap *model.Snapshot) error {
	maxFiles := d.MaxFiles
	if maxFiles <= 0 {
		maxFiles = 20
	}

	procEntries, err := os.ReadDir("/proc")
	if err != nil {
		return err
	}

	var results []model.DeletedOpenFile
	pidsScanned := 0
	maxPIDs := 50

	for _, entry := range procEntries {
		if pidsScanned >= maxPIDs {
			break
		}
		if !entry.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(entry.Name())
		if err != nil || pid <= 0 {
			continue
		}
		pidsScanned++

		fdDir := filepath.Join("/proc", entry.Name(), "fd")
		fdEntries, err := os.ReadDir(fdDir)
		if err != nil {
			continue
		}

		comm := readComm(pid)

		for _, fdEntry := range fdEntries {
			fdNum, err := strconv.Atoi(fdEntry.Name())
			if err != nil {
				continue
			}

			linkPath := filepath.Join(fdDir, fdEntry.Name())
			target, err := os.Readlink(linkPath)
			if err != nil {
				continue
			}

			if !strings.HasSuffix(target, " (deleted)") {
				continue
			}

			// Get size from stat on the fd
			var sizeBytes uint64
			info, err := os.Stat(linkPath)
			if err == nil {
				sizeBytes = uint64(info.Size())
			}

			results = append(results, model.DeletedOpenFile{
				PID:       pid,
				Comm:      comm,
				FD:        fdNum,
				Path:      strings.TrimSuffix(target, " (deleted)"),
				SizeBytes: sizeBytes,
			})
		}
	}

	// Sort by size descending
	sort.Slice(results, func(i, j int) bool {
		return results[i].SizeBytes > results[j].SizeBytes
	})

	if len(results) > maxFiles {
		results = results[:maxFiles]
	}

	snap.Global.DeletedOpen = results
	return nil
}

func readComm(pid int) string {
	data, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "comm"))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}
