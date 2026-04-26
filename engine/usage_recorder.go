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
type UsageRecorder struct {
	mu          sync.Mutex
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
func (r *UsageRecorder) Observe(cpuPct, memPct, ioPct, load1 float64, numCPUs int, memTotal uint64) {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()

	now := time.Now().UTC().Truncate(time.Minute)
	if r.currentMin.IsZero() {
		r.currentMin = now
	}
	if !now.Equal(r.currentMin) {
		r.flushLocked(numCPUs, memTotal)
		r.currentMin = now
	}
	loadRatio := 0.0
	if numCPUs > 0 {
		loadRatio = load1 / float64(numCPUs)
	}
	r.samples = append(r.samples, usageSample{
		CPU: cpuPct, Mem: memPct, IO: ioPct, LoadRatio: loadRatio,
	})

	// Hourly pruning check — cheap, only actual disk work when stale data exists.
	if time.Since(r.lastPruneAt) > time.Hour {
		r.lastPruneAt = time.Now()
		go r.prune() // background: don't block Tick
	}
}

// Flush forces the current in-memory window to disk. Called on shutdown.
func (r *UsageRecorder) Flush(numCPUs int, memTotal uint64) {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.flushLocked(numCPUs, memTotal)
}

// flushLocked computes p95/p50/max/avg for the current minute and appends the
// rollup line. Caller must hold r.mu.
func (r *UsageRecorder) flushLocked(numCPUs int, memTotal uint64) {
	if len(r.samples) == 0 || r.currentMin.IsZero() {
		r.samples = nil
		return
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

	f, err := os.OpenFile(r.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		r.samples = nil
		return
	}
	defer f.Close()
	if data, err := json.Marshal(&roll); err == nil {
		_, _ = f.Write(data)
		_, _ = f.Write([]byte("\n"))
	}
	r.samples = nil
}

// prune drops any rollup lines older than retainDays. Safe to run in a
// goroutine; the file is append-only so we rewrite atomically.
func (r *UsageRecorder) prune() {
	cutoff := time.Now().UTC().Add(-time.Duration(r.retainDays) * 24 * time.Hour)
	f, err := os.Open(r.path)
	if err != nil {
		return
	}
	defer f.Close()
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
	// Only rewrite if pruning would actually remove something.
	if len(kept) == 0 {
		return
	}
	tmp := r.path + ".tmp"
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
	_ = os.Rename(tmp, r.path)
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
