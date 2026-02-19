package collector

import (
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/ftahirops/xtop/model"
)

// BigFileCollector scans common directories for large files.
// Uses time-gated + trigger-based scanning to avoid constant IO:
//   - Normal: rescan every 60 seconds
//   - Triggered: rescan immediately when disk pressure detected (WARN/CRIT mount)
//   - Cache: reuse last results between scans
type BigFileCollector struct {
	MaxFiles  int    // max results to keep (default 10)
	MinSize   uint64 // minimum file size in bytes (default 50MB)

	mu        sync.Mutex
	cache     []model.BigFile
	lastScan  time.Time
	triggered bool // set externally when disk pressure detected
}

func (b *BigFileCollector) Name() string { return "bigfiles" }

// Trigger forces a rescan on the next Collect call.
func (b *BigFileCollector) Trigger() {
	b.mu.Lock()
	b.triggered = true
	b.mu.Unlock()
}

const (
	bigFileScanInterval = 60 * time.Second // normal rescan interval
)

// scanDirs are the directories most likely to contain large/growing files.
var scanDirs = []string{
	"/tmp",
	"/var/log",
	"/var/lib",
	"/var/cache",
	"/var/spool",
	"/home",
	"/root",
	"/opt",
	"/srv",
}

func (b *BigFileCollector) Collect(snap *model.Snapshot) error {
	b.mu.Lock()
	needScan := b.triggered || time.Since(b.lastScan) >= bigFileScanInterval
	b.triggered = false
	b.mu.Unlock()

	if !needScan {
		// Return cached results
		b.mu.Lock()
		snap.Global.BigFiles = b.cache
		b.mu.Unlock()
		return nil
	}

	maxFiles := b.MaxFiles
	if maxFiles <= 0 {
		maxFiles = 10
	}
	minSize := b.MinSize
	if minSize == 0 {
		minSize = 50 * 1024 * 1024 // 50MB
	}

	var files []model.BigFile
	budget := 3000 // max stat() calls per scan

	for _, dir := range scanDirs {
		if budget <= 0 {
			break
		}
		budget = walkDir(dir, minSize, &files, budget, 0)
	}

	// Sort by size descending
	sort.Slice(files, func(i, j int) bool {
		return files[i].SizeBytes > files[j].SizeBytes
	})

	if len(files) > maxFiles {
		files = files[:maxFiles]
	}

	// Update cache
	b.mu.Lock()
	b.cache = files
	b.lastScan = time.Now()
	b.mu.Unlock()

	snap.Global.BigFiles = files
	return nil
}

// walkDir walks a directory tree collecting large files, with a depth limit and budget.
func walkDir(dir string, minSize uint64, files *[]model.BigFile, budget int, depth int) int {
	if budget <= 0 || depth > 5 {
		return budget
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		return budget
	}

	for _, e := range entries {
		if budget <= 0 {
			break
		}

		name := e.Name()
		if len(name) == 0 {
			continue
		}
		// Skip hidden dirs
		if name[0] == '.' {
			continue
		}

		fullPath := filepath.Join(dir, name)

		if e.IsDir() {
			switch fullPath {
			case "/var/lib/docker/overlay2", "/var/lib/containerd":
				continue
			}
			budget = walkDir(fullPath, minSize, files, budget, depth+1)
			continue
		}

		// Regular file — stat it
		budget--
		info, err := e.Info()
		if err != nil {
			continue
		}

		size := uint64(info.Size())
		if size >= minSize {
			*files = append(*files, model.BigFile{
				Path:      fullPath,
				Dir:       dir,
				SizeBytes: size,
				ModTime:   info.ModTime().Unix(),
			})
		}
	}

	return budget
}
