package collector

import (
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ftahirops/xtop/model"
)

// DeletedOpenCollector scans /proc/*/fd/* for deleted-but-open files.
// Time-gated: rescans every 30 seconds or when triggered by disk pressure.
type DeletedOpenCollector struct {
	MaxFiles int

	mu        sync.Mutex
	cache     []model.DeletedOpenFile
	lastScan  time.Time
	triggered bool
}

const deletedOpenScanInterval = 30 * time.Second

func (d *DeletedOpenCollector) Name() string { return "deleted_open" }

// Trigger forces a rescan on the next Collect call.
func (d *DeletedOpenCollector) Trigger() {
	d.mu.Lock()
	d.triggered = true
	d.mu.Unlock()
}

func (d *DeletedOpenCollector) Collect(snap *model.Snapshot) error {
	d.mu.Lock()
	needScan := d.triggered || time.Since(d.lastScan) >= deletedOpenScanInterval
	d.triggered = false
	d.mu.Unlock()

	if !needScan {
		d.mu.Lock()
		snap.Global.DeletedOpen = d.cache
		d.mu.Unlock()
		return nil
	}

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

	sort.Slice(results, func(i, j int) bool {
		return results[i].SizeBytes > results[j].SizeBytes
	})

	if len(results) > maxFiles {
		results = results[:maxFiles]
	}

	d.mu.Lock()
	d.cache = results
	d.lastScan = time.Now()
	d.mu.Unlock()

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
