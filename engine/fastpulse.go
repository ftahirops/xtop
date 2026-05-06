//go:build linux

package engine

import (
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

// FastPulse is a sub-second sampler for PSI. It complements xtop's tick-based
// collector (default 3s) by tracking the wall-clock onset of pressure events
// at ~500ms resolution. The output is consumed by stampSustainedDurations to
// give per-evidence SustainedForSec values that the trust gates can rely on.
//
// Design: one goroutine, one read loop, no allocations on the hot path beyond
// the parser. The cost target is <1ms per pulse; on a healthy host this whole
// loop costs ~30ms of CPU per minute.
//
// Disabled if XTOP_FASTPULSE=0. We never ship a no-op stub on non-Linux —
// PSI is Linux-only, and xtop is Linux-only, so the build tag is enough.
type FastPulse struct {
	mu sync.RWMutex

	// firstAboveAt[id] = wall-clock time the signal first crossed threshold
	// in the *current* above-threshold streak. Cleared when the value drops
	// back below threshold. Reading SustainedAbove returns now()-firstAboveAt.
	firstAboveAt map[string]time.Time

	// latestVal[id] = most recent sample value
	latestVal  map[string]float64
	latestSeen map[string]time.Time

	// thresholds[id] = above-threshold cutoff; signal-specific.
	thresholds map[string]float64

	interval time.Duration
	quit     chan struct{}
	started  bool
}

// fastPulseThresholds matches the avg10 cutoffs used elsewhere in the engine.
// Keep these in sync with cpuEvPSISomeMin / memEvPSISomeMin / ioEvPSISomeMin.
var fastPulseThresholds = map[string]float64{
	"cpu.psi": 5.0,
	"mem.psi": 5.0,
	"io.psi":  5.0,
}

// NewFastPulse builds a stopped FastPulse. Start() launches the loop.
// intervalMs <= 0 defaults to 500ms.
func NewFastPulse(intervalMs int) *FastPulse {
	if intervalMs <= 0 {
		intervalMs = 500
	}
	thresholds := make(map[string]float64, len(fastPulseThresholds))
	for k, v := range fastPulseThresholds {
		thresholds[k] = v
	}
	return &FastPulse{
		firstAboveAt: make(map[string]time.Time),
		latestVal:    make(map[string]float64),
		latestSeen:   make(map[string]time.Time),
		thresholds:   thresholds,
		interval:     time.Duration(intervalMs) * time.Millisecond,
		quit:         make(chan struct{}),
	}
}

// Start launches the pulse goroutine. Idempotent.
func (fp *FastPulse) Start() {
	if fp == nil {
		return
	}
	fp.mu.Lock()
	if fp.started {
		fp.mu.Unlock()
		return
	}
	fp.started = true
	fp.mu.Unlock()
	go fp.loop()
}

// Stop signals the goroutine to exit. Safe to call multiple times.
func (fp *FastPulse) Stop() {
	if fp == nil {
		return
	}
	fp.mu.Lock()
	defer fp.mu.Unlock()
	if !fp.started {
		return
	}
	fp.started = false
	close(fp.quit)
	fp.quit = make(chan struct{})
}

func (fp *FastPulse) loop() {
	// Try kernel-event-driven mode first (Linux PSI poll(2)). If it works,
	// the kernel wakes us instantly on threshold crossings. If it doesn't
	// (no permission, kernel <4.20, or trigger write rejected), fall back
	// to the legacy ticker.
	if fp.tryPollLoop() {
		return
	}
	fp.legacyTickerLoop()
}

// legacyTickerLoop is the polling fallback: read PSI files every fp.interval.
func (fp *FastPulse) legacyTickerLoop() {
	t := time.NewTicker(fp.interval)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			fp.sample()
		case <-fp.quit:
			return
		}
	}
}

// psiPollFile holds an open PSI file with a registered threshold trigger.
type psiPollFile struct {
	id       string // "cpu.psi" / "mem.psi" / "io.psi"
	path     string
	fd       int
}

// tryPollLoop attempts to register PSI threshold triggers and poll on them.
// Returns false if any setup step fails — caller falls back to ticker.
//
// Kernel API (https://www.kernel.org/doc/html/latest/accounting/psi.html):
//   1. open /proc/pressure/<resource> O_RDWR | O_NONBLOCK
//   2. write a trigger spec, e.g. "some 50000 1000000" =
//      "wake when 'some' stall accumulates ≥50 ms within any 1 s window".
//   3. poll() the fd; POLLPRI fires on each threshold crossing.
//
// When the kernel wakes us, we sample(); we also wake on a periodic timeout
// so streaks reset cleanly when pressure drops back below threshold.
func (fp *FastPulse) tryPollLoop() bool {
	type trigger struct {
		id   string
		path string
		spec string
	}
	triggers := []trigger{
		// "some 50000 1000000" — wake when ≥50 ms of stall within 1 s window.
		// Equivalent to ~5% PSI avg10 — same threshold the legacy sampler uses.
		{"cpu.psi", "/proc/pressure/cpu", "some 50000 1000000"},
		{"mem.psi", "/proc/pressure/memory", "some 50000 1000000"},
		{"io.psi", "/proc/pressure/io", "some 50000 1000000"},
	}

	var opened []psiPollFile
	for _, t := range triggers {
		fd, err := unix.Open(t.path, unix.O_RDWR|unix.O_NONBLOCK, 0)
		if err != nil {
			closePollFiles(opened)
			return false
		}
		// Write the trigger spec. The kernel parses it and rejects malformed
		// specs (or rejects the write entirely if PSI triggers are disabled).
		if _, err := unix.Write(fd, []byte(t.spec)); err != nil {
			unix.Close(fd)
			closePollFiles(opened)
			return false
		}
		opened = append(opened, psiPollFile{id: t.id, path: t.path, fd: fd})
	}

	go fp.runPollLoop(opened)
	return true
}

func closePollFiles(files []psiPollFile) {
	for _, f := range files {
		unix.Close(f.fd)
	}
}

// runPollLoop blocks on poll(2) for any registered PSI fd. POLLPRI = threshold
// crossed. We also use a fp.interval-sized timeout so streaks naturally reset
// when pressure drops (poll won't fire on dropping edges, only crossings).
func (fp *FastPulse) runPollLoop(files []psiPollFile) {
	defer closePollFiles(files)

	// Build pollfd array. Watch POLLPRI (priority/exception data — what PSI
	// uses for threshold crossings) plus POLLERR for cleanup safety.
	pfds := make([]unix.PollFd, len(files))
	for i, f := range files {
		pfds[i].Fd = int32(f.fd)
		pfds[i].Events = unix.POLLPRI | unix.POLLERR
	}
	timeoutMs := int(fp.interval / time.Millisecond)
	if timeoutMs <= 0 {
		timeoutMs = 500
	}

	for {
		select {
		case <-fp.quit:
			return
		default:
		}

		// Poll with timeout. We always sample after returning regardless of
		// which fds fired — the streak-reset path needs the periodic read.
		_, err := unix.Poll(pfds, timeoutMs)
		if err != nil && err != unix.EINTR {
			// Unexpected poll error — drop to ticker fallback so we don't
			// silently stop sampling.
			fp.legacyTickerLoop()
			return
		}
		fp.sample()
		// Clear revents for next iteration (Go's Poll doesn't auto-reset).
		for i := range pfds {
			pfds[i].Revents = 0
		}
	}
}

func (fp *FastPulse) sample() {
	now := time.Now()

	// CPU PSI (some/avg10)
	if v, ok := readPSIAvg10("/proc/pressure/cpu"); ok {
		fp.observe("cpu.psi", v, now)
	}
	if v, ok := readPSIAvg10("/proc/pressure/memory"); ok {
		fp.observe("mem.psi", v, now)
	}
	if v, ok := readPSIAvg10("/proc/pressure/io"); ok {
		fp.observe("io.psi", v, now)
	}
}

// observe records a sample. Above-threshold samples extend the streak;
// below-threshold samples end it.
func (fp *FastPulse) observe(id string, val float64, now time.Time) {
	fp.mu.Lock()
	defer fp.mu.Unlock()

	fp.latestVal[id] = val
	fp.latestSeen[id] = now

	threshold := fp.thresholds[id]
	if val >= threshold {
		if _, streaking := fp.firstAboveAt[id]; !streaking {
			fp.firstAboveAt[id] = now
		}
	} else {
		delete(fp.firstAboveAt, id)
	}
}

// SustainedAbove returns how long the signal has been continuously above its
// configured threshold, with sub-second precision. The second return is false
// if there is no current streak (signal is below threshold or never seen).
func (fp *FastPulse) SustainedAbove(id string) (time.Duration, bool) {
	if fp == nil {
		return 0, false
	}
	fp.mu.RLock()
	defer fp.mu.RUnlock()
	t, ok := fp.firstAboveAt[id]
	if !ok {
		return 0, false
	}
	return time.Since(t), true
}

// Latest returns the most recent sample for an id, with the age since it was
// taken. ok=false if never observed.
func (fp *FastPulse) Latest(id string) (val float64, age time.Duration, ok bool) {
	if fp == nil {
		return 0, 0, false
	}
	fp.mu.RLock()
	defer fp.mu.RUnlock()
	v, ok1 := fp.latestVal[id]
	t, ok2 := fp.latestSeen[id]
	if !ok1 || !ok2 {
		return 0, 0, false
	}
	return v, time.Since(t), true
}

// readPSIAvg10 reads the "some avg10=..." field from a PSI file. Returns
// (0, false) on any parse failure — PSI is best-effort here, the slow path
// (collector PSICollector) remains authoritative for tick-time analysis.
func readPSIAvg10(path string) (float64, bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, false
	}
	for _, line := range strings.Split(string(data), "\n") {
		if !strings.HasPrefix(line, "some ") {
			continue
		}
		// "some avg10=X.YY avg60=... avg300=... total=..."
		for _, field := range strings.Fields(line) {
			if !strings.HasPrefix(field, "avg10=") {
				continue
			}
			v, err := strconv.ParseFloat(strings.TrimPrefix(field, "avg10="), 64)
			if err != nil {
				return 0, false
			}
			return v, true
		}
	}
	return 0, false
}
