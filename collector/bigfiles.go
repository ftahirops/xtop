package collector

import (
	"os"
	"path/filepath"
	"sort"

	"github.com/ftahirops/xtop/model"
)

// BigFileCollector scans common directories for large files.
type BigFileCollector struct {
	MaxFiles  int    // max results to keep (default 10)
	MinSize   uint64 // minimum file size in bytes (default 50MB)
}

func (b *BigFileCollector) Name() string { return "bigfiles" }

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
	maxFiles := b.MaxFiles
	if maxFiles <= 0 {
		maxFiles = 10
	}
	minSize := b.MinSize
	if minSize == 0 {
		minSize = 50 * 1024 * 1024 // 50MB
	}

	var files []model.BigFile
	budget := 3000 // max stat() calls per tick

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
		// Skip hidden dirs and known uninteresting ones
		if name[0] == '.' && len(name) > 1 {
			continue
		}

		fullPath := filepath.Join(dir, name)

		if e.IsDir() {
			// Skip pseudo-filesystems mounted under scanned dirs
			switch fullPath {
			case "/var/lib/docker/overlay2", "/var/lib/containerd":
				// Skip container overlays — too deep and mostly layers
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
