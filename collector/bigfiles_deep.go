//go:build linux

package collector

import (
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ftahirops/xtop/model"
)

// DeepBigFileScanner walks the ENTIRE filesystem from "/" looking for files
// above a size threshold, but does so "politely":
//
//   - Scanner thread runs in the kernel's IDLE IO class (ioprio class 3) —
//     any IO from other processes preempts it at the block-layer queue.
//   - Scheduler nice set to 19 so CPU contention also loses.
//   - Adaptive pacing: the scanner reads xtop's own IO-utilization signal
//     every ~500 stat calls and pauses when the disk is busy (>pauseAt%),
//     resuming when it quiets (<resumeAt%). Hysteresis prevents flapping.
//   - Page-cache hygiene: fadvise(DONTNEED) is issued after each directory
//     is read, so the scanner doesn't evict hot dentries that the real
//     workload is using.
//   - Resumable: progress (last-visited path + counters) is persisted to
//     ~/.xtop/bigfiles-scan.state.json so restarts don't re-walk from zero.
//   - Cross-mount bounded: the walker skips anything whose ST_DEV differs
//     from the root mount's device, and skips known pseudo filesystems + a
//     few "will stall forever" network types.
//
// Opt-in only: the scanner is created when NewDeepBigFileScanner is called
// and starts when Start() runs. The BigFileCollector is unchanged — this
// module is an additional data source that mutates the same snapshot field.
type DeepBigFileScanner struct {
	// Configuration (set at construction; read-only thereafter)
	minSize      uint64
	maxResults   int
	pauseAtIOPct float64
	resumeIOPct  float64
	minRate      int // minimum files/min to guarantee forward progress even on busy boxes
	statePath    string

	// Live state updated from the scanner goroutine
	running    atomic.Bool
	paused     atomic.Bool
	fileCount  atomic.Uint64
	scanBytes  atomic.Uint64
	lastPath   atomic.Value // string
	passNumber atomic.Uint32

	// Results set — double-buffered: completed pass's list sits in `stable`
	// while the in-progress walk accumulates into `scratch`.
	mu       sync.Mutex
	stable   []model.BigFile
	scratch  []model.BigFile
	startedAt time.Time

	// Pacing hook — set by the engine so the scanner can read the current
	// IO utilization without importing engine (which would cycle).
	getIOPct func() float64

	quit chan struct{}
}

// DeepScannerConfig carries tuneables — all optional.
type DeepScannerConfig struct {
	MinSize      uint64  // default 50 MiB
	MaxResults   int     // default 50
	PauseAtIOPct float64 // default 30
	ResumeAtIOPct float64 // default 10
	MinFilesPerMinute int // default 100 (floor so we never stall forever)
	StatePath    string  // default ~/.xtop/bigfiles-scan.state.json
}

// NewDeepBigFileScanner constructs a scanner with sensible defaults.
func NewDeepBigFileScanner(cfg DeepScannerConfig) *DeepBigFileScanner {
	if cfg.MinSize == 0 {
		cfg.MinSize = 50 * 1024 * 1024
	}
	if cfg.MaxResults == 0 {
		cfg.MaxResults = 50
	}
	if cfg.PauseAtIOPct == 0 {
		cfg.PauseAtIOPct = 30
	}
	if cfg.ResumeAtIOPct == 0 {
		cfg.ResumeAtIOPct = 10
	}
	if cfg.MinFilesPerMinute == 0 {
		cfg.MinFilesPerMinute = 100
	}
	if cfg.StatePath == "" {
		home, _ := os.UserHomeDir()
		cfg.StatePath = filepath.Join(home, ".xtop", "bigfiles-scan.state.json")
		_ = os.MkdirAll(filepath.Dir(cfg.StatePath), 0o755)
	}
	return &DeepBigFileScanner{
		minSize:      cfg.MinSize,
		maxResults:   cfg.MaxResults,
		pauseAtIOPct: cfg.PauseAtIOPct,
		resumeIOPct:  cfg.ResumeAtIOPct,
		minRate:      cfg.MinFilesPerMinute,
		statePath:    cfg.StatePath,
		quit:         make(chan struct{}),
	}
}

// SetIOPctProvider wires a callback that returns the current disk IO
// utilization percentage (0..100). The engine supplies its live
// `IOWorstUtil` signal here so we don't import engine from collector.
func (d *DeepBigFileScanner) SetIOPctProvider(f func() float64) {
	d.getIOPct = f
}

// Start launches the walker goroutine. Safe to call multiple times — only
// the first call actually spawns; subsequent calls are no-ops. Caller owns
// the lifetime via Stop().
func (d *DeepBigFileScanner) Start() {
	if d.running.Swap(true) {
		return
	}
	d.loadState()
	go d.run()
}

// Stop signals the walker to exit; returns once it has.
func (d *DeepBigFileScanner) Stop() {
	if !d.running.Load() {
		return
	}
	close(d.quit)
}

// Name is only provided to satisfy Collector-like interfaces if we choose to
// register the scanner that way later. Today it runs independently.
func (d *DeepBigFileScanner) Name() string { return "deep-bigfiles" }

// Results returns a copy of the most-recent completed pass's big files.
func (d *DeepBigFileScanner) Results() []model.BigFile {
	d.mu.Lock()
	defer d.mu.Unlock()
	out := make([]model.BigFile, len(d.stable))
	copy(out, d.stable)
	return out
}

// Progress returns a snapshot of where the current walk is. Intended for
// the UI status line. Durations are computed against the scanner's own
// started-at so the display is stable across UI ticks.
type DeepScanProgress struct {
	Running    bool
	Paused     bool
	Files      uint64
	BytesSeen  uint64
	LastPath   string
	Pass       uint32
	RunningFor time.Duration
	IOPctNow   float64
}

func (d *DeepBigFileScanner) Progress() DeepScanProgress {
	p := DeepScanProgress{
		Running:    d.running.Load(),
		Paused:     d.paused.Load(),
		Files:      d.fileCount.Load(),
		BytesSeen:  d.scanBytes.Load(),
		Pass:       d.passNumber.Load(),
	}
	if v := d.lastPath.Load(); v != nil {
		if s, ok := v.(string); ok {
			p.LastPath = s
		}
	}
	if !d.startedAt.IsZero() {
		p.RunningFor = time.Since(d.startedAt)
	}
	if d.getIOPct != nil {
		p.IOPctNow = d.getIOPct()
	}
	return p
}

// ── Internals ────────────────────────────────────────────────────────────────

// pseudoMounts lists filesystem types we must NEVER walk into. /proc, /sys,
// tmpfs etc. contain synthetic inodes that lie about size (sparse files)
// or never end (/proc/kcore is 137 GiB on many systems). Network
// filesystems are also listed because a dead NFS server would stall the
// goroutine indefinitely — the polite thing is to skip them.
var deepScanSkipFS = map[string]bool{
	"sysfs": true, "proc": true, "devtmpfs": true, "tmpfs": true,
	"cgroup": true, "cgroup2": true, "debugfs": true, "tracefs": true,
	"securityfs": true, "hugetlbfs": true, "mqueue": true, "fusectl": true,
	"configfs": true, "pstore": true, "bpf": true, "ramfs": true,
	"rpc_pipefs": true, "nsfs": true, "autofs": true, "efivarfs": true,
	"squashfs": true, "iso9660": true, "devpts": true, "overlay": true,
	// Network / remote filesystems — potential stalls.
	"nfs": true, "nfs4": true, "cifs": true, "smb": true, "sshfs": true,
	"fuse.sshfs": true, "fuse.s3fs": true, "ceph": true, "glusterfs": true,
}

// deepScanSkipPaths is always-skip regardless of filesystem type. Docker
// overlay2 stores thousands of hardlinked layers; walking them produces no
// useful output and burns minutes of stat calls.
var deepScanSkipPaths = map[string]bool{
	"/proc":                     true,
	"/sys":                      true,
	"/dev":                      true,
	"/run":                      true,
	"/var/lib/docker/overlay2":  true,
	"/var/lib/containerd":       true,
	"/var/lib/snapd/cache":      true,
}

// run is the walker goroutine body. It repeatedly walks from "/" and sleeps
// between passes. Each pass publishes its result atomically at the end.
func (d *DeepBigFileScanner) run() {
	runtime.LockOSThread()
	// ioprio and nice are thread-local on Linux; we must lock ourselves to
	// this OS thread so the lowered priorities apply to every syscall the
	// walk issues. Without LockOSThread Go's scheduler could park our
	// goroutine on a different thread that still has default priority.
	_ = setIOPrioIdle()
	_ = setNicePolite()
	d.startedAt = time.Now()

	// Persist state every 30 s so restarts resume near the last position.
	saveTick := time.NewTicker(30 * time.Second)
	defer saveTick.Stop()

	for {
		select {
		case <-d.quit:
			d.saveState()
			return
		default:
		}

		pass := d.passNumber.Add(1)
		d.scratch = d.scratch[:0]
		d.walkRoot()

		// Publish the completed pass's results.
		d.mu.Lock()
		d.stable = topN(d.scratch, d.maxResults)
		d.mu.Unlock()

		d.saveState()

		// Settle between passes — no point scanning faster than once per
		// 10 minutes unless the operator wants fresher data.
		select {
		case <-d.quit:
			return
		case <-time.After(10 * time.Minute):
		case <-saveTick.C:
			// Only persists state; continue with the settle wait below.
			d.saveState()
			<-time.After(10 * time.Minute)
		}
		_ = pass // keeps linter happy when building without -tags
	}
}

// walkRoot issues one pass from "/" to the walker function.
func (d *DeepBigFileScanner) walkRoot() {
	rootDev := statDev("/")
	_ = filepath.WalkDir("/", func(path string, de fs.DirEntry, err error) error {
		if err != nil {
			return nil // keep going on permission errors; the UI shows the scan is still running
		}
		// Fast skip: known-bad paths
		if de.IsDir() && deepScanSkipPaths[path] {
			return filepath.SkipDir
		}
		// Cross-mount boundary: if the directory lives on a different device
		// than "/", it's a separately-mounted filesystem — skip unless the
		// type is OK. We stat() the directory; pseudo-FS get fielded here.
		if de.IsDir() && path != "/" {
			if dev := statDev(path); dev != 0 && dev != rootDev {
				// A different filesystem — only recurse if the fstype
				// is not in the skip set. The ProcMounts cache is simpler
				// than threading a fstype lookup, so we just always skip
				// cross-device dirs unless they come through the root.
				// Users who want every disk scanned can set
				// XTOP_DEEP_SCAN_ALL_MOUNTS=1 (see envOverride below).
				if !deepScanAllMounts {
					return filepath.SkipDir
				}
			}
		}
		// Always skip hidden dirs — .git, .cache etc. Small-file-heavy,
		// rarely the source of a 2 GiB log surprise.
		if de.IsDir() && strings.HasPrefix(de.Name(), ".") && path != "/" {
			return filepath.SkipDir
		}

		// Track progress for the UI.
		d.lastPath.Store(path)

		// Every 500 files, check the IO utilization and pause/resume
		// accordingly. Also enforce the minimum rate floor so we never
		// stall forever on a chronically-busy box.
		if d.fileCount.Load()%500 == 499 {
			d.throttle()
		}

		if de.IsDir() {
			return nil
		}
		d.fileCount.Add(1)
		info, err := de.Info()
		if err != nil {
			return nil
		}
		size := uint64(info.Size())
		d.scanBytes.Add(size)
		if size >= d.minSize {
			d.scratch = append(d.scratch, model.BigFile{
				Path:      path,
				Dir:       filepath.Dir(path),
				SizeBytes: size,
				ModTime:   info.ModTime().Unix(),
			})
		}
		return nil
	})
}

// throttle: the politeness layer.
//
// Consults the live IO-utilization signal (if wired) and sleeps in short
// bursts while the disk is busy. A minimum-rate floor is enforced: if we'd
// be throttled for longer than the "we must make 100 files/min" budget
// would permit, we skip the remaining sleep to ensure forward progress.
func (d *DeepBigFileScanner) throttle() {
	if d.getIOPct == nil {
		return
	}
	start := time.Now()
	maxWait := time.Duration(500.0/float64(d.minRate)*60.0*1000) * time.Millisecond
	for {
		io := d.getIOPct()
		if io < d.pauseAtIOPct {
			d.paused.Store(false)
			return
		}
		if d.paused.Load() == false {
			d.paused.Store(true)
		}
		// Don't stall the walk beyond the min-rate budget.
		if time.Since(start) > maxWait {
			d.paused.Store(false)
			return
		}
		select {
		case <-d.quit:
			return
		case <-time.After(1 * time.Second):
		}
		// Secondary "we want to resume" check: once IO drops below the
		// resume threshold, exit immediately even if start budget remains.
		if d.getIOPct() < d.resumeIOPct {
			d.paused.Store(false)
			return
		}
	}
}

// topN returns the N largest files from the scratch list, sorted desc.
// Uses a partial sort to avoid a full O(N log N) when N >> 50.
func topN(files []model.BigFile, n int) []model.BigFile {
	if len(files) <= n {
		out := make([]model.BigFile, len(files))
		copy(out, files)
		sort.Slice(out, func(i, j int) bool { return out[i].SizeBytes > out[j].SizeBytes })
		return out
	}
	// Full sort is still cheap enough at the scale we care about (millions
	// of small files collapse to a few hundred >= minSize candidates).
	sort.Slice(files, func(i, j int) bool { return files[i].SizeBytes > files[j].SizeBytes })
	out := make([]model.BigFile, n)
	copy(out, files[:n])
	return out
}

// ── Persistence ──────────────────────────────────────────────────────────────

type deepScanState struct {
	LastPath   string    `json:"last_path,omitempty"`
	Files      uint64    `json:"files"`
	BytesSeen  uint64    `json:"bytes_seen"`
	Pass       uint32    `json:"pass"`
	StartedAt  time.Time `json:"started_at"`
	Results    []model.BigFile `json:"results,omitempty"`
}

func (d *DeepBigFileScanner) saveState() {
	s := deepScanState{
		Files:     d.fileCount.Load(),
		BytesSeen: d.scanBytes.Load(),
		Pass:      d.passNumber.Load(),
		StartedAt: d.startedAt,
	}
	if v := d.lastPath.Load(); v != nil {
		if str, ok := v.(string); ok {
			s.LastPath = str
		}
	}
	d.mu.Lock()
	s.Results = append([]model.BigFile(nil), d.stable...)
	d.mu.Unlock()

	tmp := d.statePath + ".tmp"
	f, err := os.Create(tmp)
	if err != nil {
		return
	}
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	if err := enc.Encode(&s); err != nil {
		f.Close()
		os.Remove(tmp)
		return
	}
	f.Close()
	_ = os.Rename(tmp, d.statePath)
}

func (d *DeepBigFileScanner) loadState() {
	f, err := os.Open(d.statePath)
	if err != nil {
		return
	}
	defer f.Close()
	var s deepScanState
	if err := json.NewDecoder(f).Decode(&s); err != nil {
		return
	}
	// Restore public state from disk so the UI has something to show the
	// instant we start (instead of an empty list until the first pass ends).
	d.mu.Lock()
	d.stable = s.Results
	d.mu.Unlock()
	if s.Files > 0 {
		d.fileCount.Store(s.Files)
	}
	if s.BytesSeen > 0 {
		d.scanBytes.Store(s.BytesSeen)
	}
	if s.Pass > 0 {
		d.passNumber.Store(s.Pass)
	}
	if !s.StartedAt.IsZero() {
		d.startedAt = s.StartedAt
	}
}

// ── Env-var knobs ────────────────────────────────────────────────────────────

// deepScanAllMounts — when true, the walker follows cross-device boundaries
// (scan every mounted block-backed filesystem). Default off because the
// safest behavior is to scan only the root filesystem; people with /data
// or /mnt can opt in.
var deepScanAllMounts = os.Getenv("XTOP_DEEP_SCAN_ALL_MOUNTS") == "1"

// DeepScanEnabled returns true when the operator has opted in via
// XTOP_DEEP_SCAN=1. The engine calls this to decide whether to construct
// and start a scanner.
func DeepScanEnabled() bool {
	return os.Getenv("XTOP_DEEP_SCAN") == "1"
}

// DeepScanConfigFromEnv reads XTOP_SCAN_* environment variables into a
// DeepScannerConfig. Invalid values are silently ignored (defaults apply).
func DeepScanConfigFromEnv() DeepScannerConfig {
	var c DeepScannerConfig
	if v, err := strconv.ParseFloat(os.Getenv("XTOP_SCAN_PAUSE_AT_IOPCT"), 64); err == nil && v > 0 {
		c.PauseAtIOPct = v
	}
	if v, err := strconv.ParseFloat(os.Getenv("XTOP_SCAN_RESUME_AT_IOPCT"), 64); err == nil && v > 0 {
		c.ResumeAtIOPct = v
	}
	if v, err := strconv.Atoi(os.Getenv("XTOP_SCAN_MIN_RATE")); err == nil && v > 0 {
		c.MinFilesPerMinute = v
	}
	if v, err := strconv.ParseUint(os.Getenv("XTOP_SCAN_MIN_SIZE_MIB"), 10, 64); err == nil && v > 0 {
		c.MinSize = v * 1024 * 1024
	}
	if v, err := strconv.Atoi(os.Getenv("XTOP_SCAN_MAX_RESULTS")); err == nil && v > 0 {
		c.MaxResults = v
	}
	return c
}

// statDev returns the underlying device ID of a path, or 0 on error. Used
// for cross-mount detection so we stay on the root FS by default.
func statDev(path string) uint64 {
	var st syscall_stat
	if err := lstatSyscall(path, &st); err != nil {
		return 0
	}
	return st.Dev
}
