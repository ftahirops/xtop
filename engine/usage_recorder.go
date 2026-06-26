package engine

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

// UsageRecorder appends a compact per-minute utilization rollup to
// ~/.xtop/usage-history.jsonl. Over time this becomes the data source for
// right-sizing recommendations (see `xtop cost`).
//
// Each rollup line is ~150 bytes, so a minute's data for 90 days lands at
// ~20 MB even in the worst case — modest but still too large to keep in
// memory, hence the streaming file format.
//
// Lock ordering (must be respected to avoid deadlock):
//
//	r.mu → (release) → r.fileMu
//
// r.mu guards in-memory state (samples, currentMin, lastPruneAt).
// r.fileMu guards ALL disk IO on r.path (both the append in writeFlush and
// the read-modify-write in prune). The two mutexes are NEVER held at the same
// time: prepareFlushLocked runs under r.mu and produces serialised bytes;
// writeFlush takes only fileMu after r.mu has been released. prune also
// snapshots config under r.mu, releases r.mu, then takes fileMu.
type UsageRecorder struct {
	mu          sync.Mutex
	fileMu      sync.Mutex // guards all disk IO on r.path; see lock-ordering comment above
	path        string
	currentMin  time.Time
	samples     []usageSample // samples inside the current minute
	retainDays  int
	lastPruneAt time.Time
}

// usageSample is an in-memory per-tick sample. Only the aggregated form ever
// hits disk.
type usageSample struct {
	CPU      float64
	Mem      float64
	IO       float64
	LoadRatio float64 // load1 / NumCPUs
}

// UsageRollup is one minute of aggregated usage, persisted as a JSON line.
// Fields are tagged so `xtop cost` and hub ingestion can round-trip them.
type UsageRollup struct {
	Minute    time.Time `json:"minute"`
	Samples   int       `json:"samples"`
	CPU       UsageStat `json:"cpu"`
	Mem       UsageStat `json:"mem"`
	IO        UsageStat `json:"io"`
	LoadRatio UsageStat `json:"load_ratio"`
	NumCPUs   int       `json:"num_cpus,omitempty"`
	MemTotal  uint64    `json:"mem_total_bytes,omitempty"`
}

// UsageStat holds summary statistics for one metric across a minute.
type UsageStat struct {
	Max float64 `json:"max"`
	P95 float64 `json:"p95"`
	P50 float64 `json:"p50"`
	Avg float64 `json:"avg"`
}

// NewUsageRecorder opens (or creates) the rollup file under ~/.xtop/.
func NewUsageRecorder() *UsageRecorder {
	home, _ := os.UserHomeDir()
	dir := filepath.Join(home, ".xtop")
	_ = os.MkdirAll(dir, 0o755)
	return &UsageRecorder{
		path:       filepath.Join(dir, "usage-history.jsonl"),
		retainDays: 90,
	}
}

// Observe takes one tick's aggregate numbers. Cheap: samples are accumulated
// in memory until the minute rolls over, at which point a single line is
// flushed to disk.
//
// r.mu is released before any file IO so the Tick goroutine never blocks on
// prune's disk read-modify-write.
func (r *UsageRecorder) Observe(cpuPct, memPct, ioPct, load1 float64, numCPUs int, memTotal uint64) {
	if r == nil {
		return
	}
	r.mu.Lock()

	now := time.Now().UTC().Truncate(time.Minute)
	if r.currentMin.IsZero() {
		r.currentMin = now
	}

	// If the minute has rolled over, prepare the rollup bytes under r.mu
	// (clears r.samples) but do not write to disk yet.
	var payload []byte
	if !now.Equal(r.currentMin) {
		payload, _ = r.prepareFlushLocked(numCPUs, memTotal)
		r.currentMin = now
	}

	loadRatio := 0.0
	if numCPUs > 0 {
		loadRatio = load1 / float64(numCPUs)
	}
	r.samples = append(r.samples, usageSample{
		CPU: cpuPct, Mem: memPct, IO: ioPct, LoadRatio: loadRatio,
	})

	// Hourly pruning check — note the flag, fire goroutine after mu release.
	shouldPrune := time.Since(r.lastPruneAt) > time.Hour
	if shouldPrune {
		r.lastPruneAt = time.Now()
	}

	r.mu.Unlock() // ← r.mu released; all file IO below holds only fileMu

	if payload != nil {
		r.writeFlush(payload) // acquires fileMu only
	}
	if shouldPrune {
		go r.prune() // background: don't block Tick
	}
}

// Flush forces the current in-memory window to disk. Called on shutdown.
// r.mu is released before file IO.
func (r *UsageRecorder) Flush(numCPUs int, memTotal uint64) {
	if r == nil {
		return
	}
	r.mu.Lock()
	payload, _ := r.prepareFlushLocked(numCPUs, memTotal)
	r.mu.Unlock() // ← r.mu released before file IO

	if payload != nil {
		r.writeFlush(payload)
	}
}

// prepareFlushLocked computes p95/p50/max/avg for the current minute, marshals
// the rollup to JSON, clears r.samples, and returns the bytes to write.
// Caller must hold r.mu. Does NOT touch the file.
func (r *UsageRecorder) prepareFlushLocked(numCPUs int, memTotal uint64) ([]byte, bool) {
	if len(r.samples) == 0 || r.currentMin.IsZero() {
		r.samples = nil
		return nil, false
	}
	roll := UsageRollup{
		Minute:   r.currentMin,
		Samples:  len(r.samples),
		NumCPUs:  numCPUs,
		MemTotal: memTotal,
	}
	roll.CPU = summarize(extract(r.samples, func(s usageSample) float64 { return s.CPU }))
	roll.Mem = summarize(extract(r.samples, func(s usageSample) float64 { return s.Mem }))
	roll.IO = summarize(extract(r.samples, func(s usageSample) float64 { return s.IO }))
	roll.LoadRatio = summarize(extract(r.samples, func(s usageSample) float64 { return s.LoadRatio }))

	r.samples = nil // clear in-memory state while still under r.mu

	data, err := json.Marshal(&roll)
	if err != nil {
		return nil, false
	}
	return append(data, '\n'), true
}

// writeFlush appends a pre-serialised rollup line to the file.
// Caller must NOT hold r.mu. Acquires fileMu only.
func (r *UsageRecorder) writeFlush(payload []byte) {
	r.fileMu.Lock()
	defer r.fileMu.Unlock()
	f, err := os.OpenFile(r.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return
	}
	_, _ = f.Write(payload)
	f.Close()
}

// prune drops any rollup lines older than retainDays. Runs in its own goroutine.
//
// Lock ordering: prune snapshots r.path and r.retainDays under r.mu, then
// releases r.mu BEFORE acquiring r.fileMu. It never holds r.mu while holding
// r.fileMu, preserving the r.mu → r.fileMu ordering established by flushLocked.
func (r *UsageRecorder) prune() {
	// Snapshot immutable-ish config under r.mu, then release before file IO.
	r.mu.Lock()
	path := r.path
	retainDays := r.retainDays
	r.mu.Unlock()

	cutoff := time.Now().UTC().Add(-time.Duration(retainDays) * 24 * time.Hour)

	// All file IO is serialized with flushLocked via fileMu.
	r.fileMu.Lock()
	defer r.fileMu.Unlock()

	f, err := os.Open(path)
	if err != nil {
		return
	}
	var kept []UsageRollup
	dec := json.NewDecoder(f)
	for dec.More() {
		var u UsageRollup
		if err := dec.Decode(&u); err != nil {
			continue
		}
		if u.Minute.After(cutoff) {
			kept = append(kept, u)
		}
	}
	f.Close()

	// If all records expired, truncate the file so stale data isn't left on disk.
	if len(kept) == 0 {
		_ = os.Truncate(path, 0)
		return
	}
	tmp := path + ".tmp"
	out, err := os.Create(tmp)
	if err != nil {
		return
	}
	enc := json.NewEncoder(out)
	for i := range kept {
		if err := enc.Encode(&kept[i]); err != nil {
			out.Close()
			os.Remove(tmp)
			return
		}
	}
	out.Close()
	_ = os.Rename(tmp, path)
}

// ── Stats helpers ────────────────────────────────────────────────────────────

func extract(samples []usageSample, pick func(usageSample) float64) []float64 {
	out := make([]float64, len(samples))
	for i, s := range samples {
		out[i] = pick(s)
	}
	return out
}

func summarize(v []float64) UsageStat {
	if len(v) == 0 {
		return UsageStat{}
	}
	sorted := append([]float64(nil), v...)
	sort.Float64s(sorted)
	sum := 0.0
	for _, x := range sorted {
		sum += x
	}
	return UsageStat{
		Max: sorted[len(sorted)-1],
		P95: percentile(sorted, 0.95),
		P50: percentile(sorted, 0.50),
		Avg: sum / float64(len(sorted)),
	}
}

// percentile over an already-sorted slice, using nearest-rank (no interpolation).
func percentile(sorted []float64, p float64) float64 {
	if len(sorted) == 0 {
		return 0
	}
	if p <= 0 {
		return sorted[0]
	}
	if p >= 1 {
		return sorted[len(sorted)-1]
	}
	rank := int(float64(len(sorted))*p + 0.5) - 1
	if rank < 0 {
		rank = 0
	}
	if rank >= len(sorted) {
		rank = len(sorted) - 1
	}
	return sorted[rank]
}
