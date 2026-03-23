package engine

import (
	"sort"
	"sync"
	"time"

	"github.com/ftahirops/xtop/model"
)

// ProcessSnapshot records the top CPU/IO/Memory consumers at one point in time.
type ProcessSnapshot struct {
	Timestamp time.Time
	TopCPU    []ProcessEntry // top 10 by CPU%
	TopIO     []ProcessEntry // top 10 by IO MB/s
	TopMem    []ProcessEntry // top 10 by RSS
}

// ProcessEntry is a lightweight record of one process at one point in time.
type ProcessEntry struct {
	PID    int
	Comm   string
	CPUPct float64
	IOMBs  float64 // read + write MB/s
	RSS    uint64
	State  string
}

// ProcessHistory maintains a ring buffer of process snapshots for temporal culprit analysis.
// Stores the last N ticks worth of top process data (~5 min at 3s interval).
type ProcessHistory struct {
	mu   sync.RWMutex
	buf  []ProcessSnapshot
	head int
	size int
	cap  int
}

// NewProcessHistory creates a process history buffer.
func NewProcessHistory(capacity int) *ProcessHistory {
	if capacity <= 0 {
		capacity = 100 // ~5 min at 3s interval
	}
	return &ProcessHistory{
		buf: make([]ProcessSnapshot, capacity),
		cap: capacity,
	}
}

// Record stores the top processes from the current tick.
func (ph *ProcessHistory) Record(rates *model.RateSnapshot) {
	if rates == nil || len(rates.ProcessRates) == 0 {
		return
	}

	snap := ProcessSnapshot{
		Timestamp: time.Now(),
	}

	// Sort by CPU% for top CPU consumers
	sorted := make([]model.ProcessRate, len(rates.ProcessRates))
	copy(sorted, rates.ProcessRates)

	sort.Slice(sorted, func(i, j int) bool { return sorted[i].CPUPct > sorted[j].CPUPct })
	for i := 0; i < len(sorted) && i < 10; i++ {
		p := sorted[i]
		if p.CPUPct <= 0 {
			break
		}
		snap.TopCPU = append(snap.TopCPU, ProcessEntry{
			PID: p.PID, Comm: p.Comm, CPUPct: p.CPUPct,
			IOMBs: p.ReadMBs + p.WriteMBs, RSS: p.RSS, State: p.State,
		})
	}

	// Sort by IO for top IO consumers
	sort.Slice(sorted, func(i, j int) bool {
		return (sorted[i].ReadMBs + sorted[i].WriteMBs) > (sorted[j].ReadMBs + sorted[j].WriteMBs)
	})
	for i := 0; i < len(sorted) && i < 10; i++ {
		p := sorted[i]
		io := p.ReadMBs + p.WriteMBs
		if io <= 0 {
			break
		}
		snap.TopIO = append(snap.TopIO, ProcessEntry{
			PID: p.PID, Comm: p.Comm, CPUPct: p.CPUPct,
			IOMBs: io, RSS: p.RSS, State: p.State,
		})
	}

	// Sort by RSS for top memory consumers
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].RSS > sorted[j].RSS })
	for i := 0; i < len(sorted) && i < 10; i++ {
		p := sorted[i]
		if p.RSS == 0 {
			break
		}
		snap.TopMem = append(snap.TopMem, ProcessEntry{
			PID: p.PID, Comm: p.Comm, CPUPct: p.CPUPct,
			IOMBs: p.ReadMBs + p.WriteMBs, RSS: p.RSS, State: p.State,
		})
	}

	ph.mu.Lock()
	ph.buf[ph.head] = snap
	ph.head = (ph.head + 1) % ph.cap
	if ph.size < ph.cap {
		ph.size++
	}
	ph.mu.Unlock()
}

// FindCPUCulprit looks back through process history to find the process that
// has been consistently in the top CPU consumers. This finds the ROOT CAUSE
// (the process that started consuming CPU first), not just whoever is on top
// at the current moment.
func (ph *ProcessHistory) FindCPUCulprit() (comm string, pid int, appearances int) {
	ph.mu.RLock()
	defer ph.mu.RUnlock()

	if ph.size == 0 {
		return "", 0, 0
	}

	// Count appearances in top-3 CPU over last N ticks
	type candidate struct {
		pid         int
		comm        string
		appearances int
		totalCPU    float64
		firstSeen   int // tick index (0 = oldest)
	}
	counts := make(map[int]*candidate)

	lookback := ph.size
	if lookback > 30 {
		lookback = 30 // last ~90s at 3s interval
	}

	for i := 0; i < lookback; i++ {
		idx := (ph.head - 1 - i + ph.cap) % ph.cap
		snap := ph.buf[idx]
		top := 3
		if top > len(snap.TopCPU) {
			top = len(snap.TopCPU)
		}
		for j := 0; j < top; j++ {
			p := snap.TopCPU[j]
			if isSelfProcess(p.Comm) || isKernelThread(p.Comm) {
				continue
			}
			c, ok := counts[p.PID]
			if !ok {
				c = &candidate{pid: p.PID, comm: p.Comm, firstSeen: i}
				counts[p.PID] = c
			}
			c.appearances++
			c.totalCPU += p.CPUPct
		}
	}

	// Pick the process with most consistent appearances, breaking ties by total CPU
	var best *candidate
	for _, c := range counts {
		if best == nil || c.appearances > best.appearances ||
			(c.appearances == best.appearances && c.totalCPU > best.totalCPU) {
			best = c
		}
	}

	if best == nil {
		return "", 0, 0
	}
	return best.comm, best.pid, best.appearances
}

// FindIOCulprit looks back to find the process consistently generating the most IO.
func (ph *ProcessHistory) FindIOCulprit() (comm string, pid int, appearances int) {
	ph.mu.RLock()
	defer ph.mu.RUnlock()

	if ph.size == 0 {
		return "", 0, 0
	}

	type candidate struct {
		pid         int
		comm        string
		appearances int
		totalIO     float64
	}
	counts := make(map[int]*candidate)

	lookback := ph.size
	if lookback > 30 {
		lookback = 30
	}

	for i := 0; i < lookback; i++ {
		idx := (ph.head - 1 - i + ph.cap) % ph.cap
		snap := ph.buf[idx]
		top := 3
		if top > len(snap.TopIO) {
			top = len(snap.TopIO)
		}
		for j := 0; j < top; j++ {
			p := snap.TopIO[j]
			if isSelfProcess(p.Comm) || isKernelThread(p.Comm) {
				continue
			}
			c, ok := counts[p.PID]
			if !ok {
				c = &candidate{pid: p.PID, comm: p.Comm}
				counts[p.PID] = c
			}
			c.appearances++
			c.totalIO += p.IOMBs
		}
	}

	var best *candidate
	for _, c := range counts {
		if best == nil || c.appearances > best.appearances ||
			(c.appearances == best.appearances && c.totalIO > best.totalIO) {
			best = c
		}
	}

	if best == nil {
		return "", 0, 0
	}
	return best.comm, best.pid, best.appearances
}

// FindMemCulprit looks back to find the process consistently using the most memory.
func (ph *ProcessHistory) FindMemCulprit() (comm string, pid int, appearances int) {
	ph.mu.RLock()
	defer ph.mu.RUnlock()

	if ph.size == 0 {
		return "", 0, 0
	}

	type candidate struct {
		pid         int
		comm        string
		appearances int
		maxRSS      uint64
	}
	counts := make(map[int]*candidate)

	lookback := ph.size
	if lookback > 30 {
		lookback = 30
	}

	for i := 0; i < lookback; i++ {
		idx := (ph.head - 1 - i + ph.cap) % ph.cap
		snap := ph.buf[idx]
		top := 3
		if top > len(snap.TopMem) {
			top = len(snap.TopMem)
		}
		for j := 0; j < top; j++ {
			p := snap.TopMem[j]
			if isSelfProcess(p.Comm) || isKernelThread(p.Comm) {
				continue
			}
			c, ok := counts[p.PID]
			if !ok {
				c = &candidate{pid: p.PID, comm: p.Comm}
				counts[p.PID] = c
			}
			c.appearances++
			if p.RSS > c.maxRSS {
				c.maxRSS = p.RSS
			}
		}
	}

	var best *candidate
	for _, c := range counts {
		if best == nil || c.appearances > best.appearances ||
			(c.appearances == best.appearances && c.maxRSS > best.maxRSS) {
			best = c
		}
	}

	if best == nil {
		return "", 0, 0
	}
	return best.comm, best.pid, best.appearances
}
