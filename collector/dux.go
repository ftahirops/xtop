//go:build linux

package collector

import (
	"context"
	"encoding/json"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/ftahirops/xtop/model"
)

// DuxCollector reads the dux live filesystem index (https://github.com/ftahirops/dux)
// when the `dux` CLI is installed. dux maintains a persistent, fanotify-updated
// SQLite index of the whole filesystem, so it answers "top directories", "top
// files", and — uniquely — "what grew in the last N minutes" instantly and
// exactly, where the built-in BigFileCollector walker is budget-bounded and
// blind to growth. Integration is via `dux ... --json` subprocess calls (3s
// timeout each): no schema coupling, no extra Go dependencies, and the
// collector is a silent no-op when dux is absent.
type DuxCollector struct {
	mu        sync.Mutex
	cacheOK   bool
	cacheDirs []model.BigDir
	cacheFile []model.BigFile
	cacheGrow []model.GrowthEntry
	lastScan  time.Time
	triggered bool
	missing   bool      // dux not in PATH — checked once, rechecked hourly
	checkedAt time.Time // when `missing` was last evaluated
}

func (d *DuxCollector) Name() string { return "dux" }

// Trigger forces a refresh on the next Collect (wired to disk WARN/CRIT,
// like the bigfiles collector).
func (d *DuxCollector) Trigger() {
	d.mu.Lock()
	d.triggered = true
	d.mu.Unlock()
}

const (
	duxRefreshInterval = 60 * time.Second
	duxGrowthWindow    = "15m"
	duxTopLimit        = "12"
	duxCmdTimeout      = 3 * time.Second
)

// duxRow is one entry of `dux top --json` output.
type duxRow struct {
	Bytes  uint64 `json:"bytes"`
	Inodes int    `json:"inodes"`
	Kind   string `json:"kind"`
	Mtime  int64  `json:"mtime"`
	Path   string `json:"path"`
}

func parseDuxRows(data []byte) ([]duxRow, error) {
	var rows []duxRow
	if err := json.Unmarshal(data, &rows); err != nil {
		return nil, err
	}
	return rows, nil
}

// duxDirsFromRows converts top-dirs rows, dropping the root "/" row (it is
// "everything on the filesystem" — noise in a hot-spots list).
func duxDirsFromRows(rows []duxRow) []model.BigDir {
	out := make([]model.BigDir, 0, len(rows))
	for _, r := range rows {
		if r.Path == "/" {
			continue
		}
		out = append(out, model.BigDir{
			Path:      r.Path,
			SizeBytes: r.Bytes,
			FileCount: r.Inodes,
		})
	}
	return out
}

func duxFilesFromRows(rows []duxRow) []model.BigFile {
	out := make([]model.BigFile, 0, len(rows))
	for _, r := range rows {
		out = append(out, model.BigFile{
			Path:      r.Path,
			SizeBytes: r.Bytes,
			ModTime:   r.Mtime,
		})
	}
	return out
}

// parseDuxGrowth parses `dux growth --json`, dropping "inode:NNN" rows —
// entries whose path the index could not resolve (nothing actionable to show).
func parseDuxGrowth(data []byte) ([]model.GrowthEntry, error) {
	var raw []struct {
		DeltaBytes int64  `json:"delta_bytes"`
		Path       string `json:"path"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, err
	}
	out := make([]model.GrowthEntry, 0, len(raw))
	for _, r := range raw {
		if strings.HasPrefix(r.Path, "inode:") {
			continue
		}
		out = append(out, model.GrowthEntry{Path: r.Path, DeltaBytes: r.DeltaBytes})
	}
	return out, nil
}

func runDux(args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), duxCmdTimeout)
	defer cancel()
	return exec.CommandContext(ctx, "dux", args...).Output()
}

func (d *DuxCollector) Collect(snap *model.Snapshot) error {
	d.mu.Lock()
	// Availability: LookPath once, re-check hourly (dux may get installed later).
	if d.checkedAt.IsZero() || time.Since(d.checkedAt) > time.Hour {
		_, err := exec.LookPath("dux")
		d.missing = err != nil
		d.checkedAt = time.Now()
	}
	if d.missing {
		d.mu.Unlock()
		return nil // silent no-op: the built-in walker remains the source
	}
	needScan := d.triggered || time.Since(d.lastScan) >= duxRefreshInterval
	d.triggered = false
	if !needScan {
		snap.Global.DuxOK = d.cacheOK
		snap.Global.DuxDirs = d.cacheDirs
		snap.Global.DuxFiles = d.cacheFile
		snap.Global.DuxGrowth = d.cacheGrow
		d.mu.Unlock()
		return nil
	}
	d.mu.Unlock()

	var (
		dirs   []model.BigDir
		files  []model.BigFile
		growth []model.GrowthEntry
		ok     = true
	)
	if out, err := runDux("top", "--dirs", "--limit", duxTopLimit, "--json"); err == nil {
		if rows, perr := parseDuxRows(out); perr == nil {
			dirs = duxDirsFromRows(rows)
		} else {
			ok = false
		}
	} else {
		ok = false
	}
	if out, err := runDux("top", "--files", "--limit", duxTopLimit, "--json"); err == nil {
		if rows, perr := parseDuxRows(out); perr == nil {
			files = duxFilesFromRows(rows)
		} else {
			ok = false
		}
	} else {
		ok = false
	}
	if out, err := runDux("growth", "--since", duxGrowthWindow, "--limit", duxTopLimit, "--json"); err == nil {
		if g, perr := parseDuxGrowth(out); perr == nil {
			growth = g
		}
		// growth failing alone doesn't invalidate the top data
	}
	// A run with no usable data at all → not OK (e.g. index missing/corrupt);
	// the UI then falls back to the built-in walker sections.
	if len(dirs) == 0 && len(files) == 0 {
		ok = false
	}

	d.mu.Lock()
	d.cacheOK = ok
	d.cacheDirs = dirs
	d.cacheFile = files
	d.cacheGrow = growth
	d.lastScan = time.Now()
	d.mu.Unlock()

	snap.Global.DuxOK = ok
	snap.Global.DuxDirs = dirs
	snap.Global.DuxFiles = files
	snap.Global.DuxGrowth = growth
	return nil
}

// MaxMsPerTick declares the cost envelope for the Resource Guardian: three
// short subprocess calls at most once per minute; the cached path is ~0ms.
func (d *DuxCollector) MaxMsPerTick() int { return 100 }
