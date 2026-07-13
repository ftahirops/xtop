package collector

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
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
	cache        []model.BigFile
	cacheDirs    []model.BigDir
	cachePartial bool
	lastScan  time.Time
	triggered bool // set externally when disk pressure detected
	firstRun  bool // true = skip expensive scan on first tick; set false after first Collect
}

// dirAgg accumulates a directory subtree's recursive total during the walk.
type dirAgg struct {
	bytes uint64
	files int
	depth int
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
	// Skip expensive full-directory walk on first tick
	if b.firstRun {
		b.firstRun = false
		snap.Global.BigDirsPartial = b.cachePartial
		b.mu.Unlock()
		snap.Global.BigFiles = b.cache
		snap.Global.BigDirs = b.cacheDirs
		return nil
	}
	b.mu.Unlock()

	if !needScan {
		// Return cached results
		b.mu.Lock()
		snap.Global.BigFiles = b.cache
		snap.Global.BigDirs = b.cacheDirs
		snap.Global.BigDirsPartial = b.cachePartial
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
	dirs := make(map[string]*dirAgg)
	budget := 3000 // max stat() calls per scan

	for _, dir := range scanDirs {
		if budget <= 0 {
			break
		}
		budget, _, _ = walkDir(dir, minSize, &files, dirs, budget, 0)
	}

	// Sort by size descending
	sort.Slice(files, func(i, j int) bool {
		return files[i].SizeBytes > files[j].SizeBytes
	})

	if len(files) > maxFiles {
		files = files[:maxFiles]
	}

	// Roll the per-directory totals up into the top disjoint subtrees.
	bigDirs := topDirs(dirs, minSize, maxFiles)
	// Budget exhausted mid-walk → the directory totals are lower bounds, not
	// authoritative du output. Surface that so the UI can say so.
	partial := budget <= 0

	// Update cache
	b.mu.Lock()
	b.cache = files
	b.cacheDirs = bigDirs
	b.cachePartial = partial
	b.lastScan = time.Now()
	b.mu.Unlock()

	snap.Global.BigFiles = files
	snap.Global.BigDirs = bigDirs
	snap.Global.BigDirsPartial = partial
	return nil
}

// topDirs selects the largest non-nested directory subtrees from the walk.
// Candidates below the scan roots (depth >= 1) that meet minSize are ranked by
// recursive size; a directory is skipped if an already-selected directory is
// one of its ancestors, so the result lists disjoint hot spots (e.g. show
// /var/lib/docker/volumes rather than both it and its parent).
func topDirs(dirs map[string]*dirAgg, minSize uint64, max int) []model.BigDir {
	type cand struct {
		path string
		agg  *dirAgg
	}
	cands := make([]cand, 0, len(dirs))
	for p, a := range dirs {
		if a.depth >= 1 && a.bytes >= minSize {
			cands = append(cands, cand{p, a})
		}
	}
	sort.Slice(cands, func(i, j int) bool {
		return cands[i].agg.bytes > cands[j].agg.bytes
	})

	var out []model.BigDir
	var picked []string
	for _, c := range cands {
		if len(out) >= max {
			break
		}
		nested := false
		for _, p := range picked {
			if strings.HasPrefix(c.path, p+"/") {
				nested = true
				break
			}
		}
		if nested {
			continue
		}
		picked = append(picked, c.path)
		out = append(out, model.BigDir{
			Path:      c.path,
			SizeBytes: c.agg.bytes,
			FileCount: c.agg.files,
		})
	}
	return out
}

// walkDir walks a directory tree collecting large files, with a depth limit and
// budget. It also records each directory's recursive size into dirs (du-style)
// and returns the remaining budget plus this subtree's total bytes and file count.
func walkDir(dir string, minSize uint64, files *[]model.BigFile, dirs map[string]*dirAgg, budget, depth int) (int, uint64, int) {
	if budget <= 0 || depth > 5 {
		return budget, 0, 0
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		return budget, 0, 0
	}

	var subtreeBytes uint64
	var subtreeFiles int

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
			var childBytes uint64
			var childFiles int
			budget, childBytes, childFiles = walkDir(fullPath, minSize, files, dirs, budget, depth+1)
			subtreeBytes += childBytes
			subtreeFiles += childFiles
			continue
		}

		// Regular file — stat it
		budget--
		info, err := e.Info()
		if err != nil {
			continue
		}

		size := uint64(info.Size())
		subtreeBytes += size
		subtreeFiles++
		if size >= minSize {
			*files = append(*files, model.BigFile{
				Path:      fullPath,
				Dir:       dir,
				SizeBytes: size,
				ModTime:   info.ModTime().Unix(),
			})
		}
	}

	dirs[dir] = &dirAgg{bytes: subtreeBytes, files: subtreeFiles, depth: depth}
	return budget, subtreeBytes, subtreeFiles
}
