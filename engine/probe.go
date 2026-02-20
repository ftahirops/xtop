package engine

import (
	"fmt"
	"sync"
	"time"

	bpf "github.com/ftahirops/xtop/collector/ebpf"
)

// ProbeState represents the lifecycle of a probe session.
type ProbeState int

const (
	ProbeIdle    ProbeState = 0
	ProbeRunning ProbeState = 1
	ProbeDone    ProbeState = 2
)

func (s ProbeState) String() string {
	switch s {
	case ProbeIdle:
		return "idle"
	case ProbeRunning:
		return "running"
	case ProbeDone:
		return "done"
	}
	return "unknown"
}

// ─── Finding entry types ────────────────────────────────────────────────────

// OffCPUEntry holds off-CPU time attribution for one process.
type OffCPUEntry struct {
	PID     int
	Comm    string
	WaitPct float64
	Reason  string
}

// IOLatEntry holds block IO latency for one device.
type IOLatEntry struct {
	Device  string
	P50Ms   float64
	P95Ms   float64
	P99Ms   float64
	UtilPct float64
}

// LockEntry holds lock contention for one process.
type LockEntry struct {
	PID      int
	Comm     string
	WaitPct  float64
	LockType string
}

// TCPRetransEntry holds TCP retransmit attribution for one process.
type TCPRetransEntry struct {
	PID     int
	Comm    string
	Retrans int // per second
	Iface   string
}

// NetThroughputEntry holds per-process TCP throughput.
type NetThroughputEntry struct {
	PID   int
	Comm  string
	TxMBs float64
	RxMBs float64
}

// TCPRTTEntry holds RTT data for one remote endpoint.
type TCPRTTEntry struct {
	DstAddr  string
	AvgRTTMs float64
	MinRTTMs float64
	MaxRTTMs float64
	Samples  int
	TopComm  string
}

// TCPConnLatEntry holds TCP connection establishment latency.
type TCPConnLatEntry struct {
	PID     int
	Comm    string
	DstAddr string
	AvgMs   float64
	MaxMs   float64
	Count   int
}

// ProbeFindings holds the output of a probe session.
type ProbeFindings struct {
	StartTime     time.Time
	Duration      time.Duration
	Pack          string // "auto", "offcpu", "iolatency", etc.
	Bottleneck    string // which RCA bottleneck this reinforces
	ConfBoost     int    // how much to boost RCA confidence
	Summary       string // one-line summary for overview
	OffCPUWaiters []OffCPUEntry
	IOLatency     []IOLatEntry
	LockWaiters   []LockEntry
	TCPRetrans    []TCPRetransEntry
	NetThroughput []NetThroughputEntry
	TCPRTT        []TCPRTTEntry
	TCPConnLat    []TCPConnLatEntry
}

// ─── ProbeManager ───────────────────────────────────────────────────────────

// ProbeManager manages the lifecycle of a probe session.
type ProbeManager struct {
	mu       sync.RWMutex
	state    ProbeState
	start    time.Time
	duration time.Duration
	pack     string
	findings *ProbeFindings
	doneAt   time.Time
	expiry   time.Duration
}

// NewProbeManager creates a new probe manager.
func NewProbeManager() *ProbeManager {
	return &ProbeManager{
		state:  ProbeIdle,
		expiry: 60 * time.Second,
	}
}

// Start initiates a probe session. Returns error if already running.
func (pm *ProbeManager) Start(pack string) error {
	pm.mu.Lock()
	if pm.state == ProbeRunning {
		pm.mu.Unlock()
		return fmt.Errorf("probe already running")
	}
	pm.state = ProbeRunning
	start := time.Now()
	duration := 10 * time.Second
	pm.start = start
	pm.duration = duration
	pm.pack = pack
	pm.findings = nil
	pm.doneAt = time.Time{}
	pm.mu.Unlock()

	// Capture local copies to avoid reading pm fields without lock in goroutine
	go pm.runProbe(start, duration, pack)
	return nil
}

// runProbe executes the eBPF probe collection in a goroutine.
func (pm *ProbeManager) runProbe(start time.Time, duration time.Duration, pack string) {
	results, err := bpf.RunProbe(duration)

	pm.mu.Lock()
	defer pm.mu.Unlock()

	if err != nil {
		pm.findings = &ProbeFindings{
			StartTime: start,
			Duration:  duration,
			Pack:      pack,
			Summary:   "Error: " + err.Error(),
		}
	} else {
		pm.findings = convertResults(results, start, duration, pack)
	}
	pm.state = ProbeDone
	pm.doneAt = time.Now()
}

// convertResults transforms raw eBPF results into ProbeFindings.
func convertResults(r *bpf.ProbeResults, start time.Time, duration time.Duration, pack string) *ProbeFindings {
	durationNs := float64(duration.Nanoseconds())
	durationSec := duration.Seconds()

	f := &ProbeFindings{
		StartTime: start,
		Duration:  duration,
		Pack:      pack,
	}

	// Convert off-CPU results
	for _, oc := range r.OffCPU {
		f.OffCPUWaiters = append(f.OffCPUWaiters, OffCPUEntry{
			PID:     int(oc.PID),
			Comm:    oc.Comm,
			WaitPct: float64(oc.TotalNs) / durationNs * 100,
			Reason:  oc.Reason,
		})
	}

	// Convert IO latency results (already per-device)
	for _, io := range r.IOLatency {
		utilPct := float64(io.TotalNs) / durationNs * 100
		if utilPct > 100 {
			utilPct = 100
		}
		f.IOLatency = append(f.IOLatency, IOLatEntry{
			Device:  io.DevName,
			P50Ms:   float64(io.P50Ns) / 1e6,
			P95Ms:   float64(io.P95Ns) / 1e6,
			P99Ms:   float64(io.P99Ns) / 1e6,
			UtilPct: utilPct,
		})
	}

	// Convert lock wait results
	for _, lw := range r.LockWait {
		f.LockWaiters = append(f.LockWaiters, LockEntry{
			PID:      int(lw.PID),
			Comm:     lw.Comm,
			WaitPct:  float64(lw.TotalWaitNs) / durationNs * 100,
			LockType: "futex",
		})
	}

	// Convert TCP retrans results
	for _, tr := range r.TCPRetrans {
		retransPerSec := int(float64(tr.Count) / durationSec)
		if retransPerSec < 1 && tr.Count > 0 {
			retransPerSec = 1
		}
		comm := tr.Comm
		if tr.PID == 0 {
			comm = "kernel (unattributed)"
		}
		f.TCPRetrans = append(f.TCPRetrans, TCPRetransEntry{
			PID:     int(tr.PID),
			Comm:    comm,
			Retrans: retransPerSec,
			Iface:   tr.DstStr,
		})
	}

	// Convert net throughput results
	for _, nt := range r.NetThroughput {
		f.NetThroughput = append(f.NetThroughput, NetThroughputEntry{
			PID:   int(nt.PID),
			Comm:  nt.Comm,
			TxMBs: float64(nt.TxBytes) / (1024 * 1024) / durationSec,
			RxMBs: float64(nt.RxBytes) / (1024 * 1024) / durationSec,
		})
	}

	// Convert TCP RTT results
	for _, rt := range r.TCPRTT {
		if rt.Count == 0 {
			continue
		}
		avgUs := float64(rt.SumUs) / float64(rt.Count)
		f.TCPRTT = append(f.TCPRTT, TCPRTTEntry{
			DstAddr:  rt.DstStr,
			AvgRTTMs: avgUs / 1000.0,
			MinRTTMs: float64(rt.MinUs) / 1000.0,
			MaxRTTMs: float64(rt.MaxUs) / 1000.0,
			Samples:  int(rt.Count),
			TopComm:  rt.LastComm,
		})
	}

	// Convert TCP connect latency results
	for _, cl := range r.TCPConnLat {
		if cl.Count == 0 {
			continue
		}
		avgNs := float64(cl.TotalNs) / float64(cl.Count)
		f.TCPConnLat = append(f.TCPConnLat, TCPConnLatEntry{
			PID:     int(cl.PID),
			Comm:    cl.Comm,
			DstAddr: cl.DstStr,
			AvgMs:   avgNs / 1e6,
			MaxMs:   float64(cl.MaxNs) / 1e6,
			Count:   int(cl.Count),
		})
	}

	// Determine dominant bottleneck from findings
	f.Bottleneck, f.ConfBoost = classifyBottleneck(f)

	// Generate summary
	f.Summary = generateSummary(f)

	return f
}

// classifyBottleneck determines which bottleneck the probe findings reinforce.
func classifyBottleneck(f *ProbeFindings) (string, int) {
	var ioScore, cpuScore, lockScore, netScore float64

	// IO score: based on p95 latency
	for _, e := range f.IOLatency {
		if e.P95Ms > 20 {
			ioScore += e.P95Ms
		}
	}

	// CPU/Off-CPU score: based on total off-CPU wait
	for _, e := range f.OffCPUWaiters {
		cpuScore += e.WaitPct
	}

	// Lock score: based on futex wait
	for _, e := range f.LockWaiters {
		lockScore += e.WaitPct
	}

	// Network score: based on retransmits + high RTT + connect latency
	for _, e := range f.TCPRetrans {
		netScore += float64(e.Retrans)
	}
	for _, e := range f.TCPRTT {
		if e.AvgRTTMs > 10 {
			netScore += e.AvgRTTMs / 10
		}
	}
	for _, e := range f.TCPConnLat {
		if e.AvgMs > 100 {
			netScore += e.AvgMs / 100
		}
	}

	// Pick the dominant signal
	type scored struct {
		name  string
		score float64
	}
	signals := []scored{
		{BottleneckIO, ioScore},
		{BottleneckCPU, cpuScore},
		{BottleneckCPU, lockScore}, // lock contention → CPU contention
		{BottleneckNetwork, netScore},
	}

	best := signals[0]
	for _, s := range signals[1:] {
		if s.score > best.score {
			best = s
		}
	}

	if best.score == 0 {
		return "None", 0
	}

	// Confidence boost: 5-25% depending on signal strength
	boost := 5
	if best.score > 50 {
		boost = 15
	}
	if best.score > 100 {
		boost = 25
	}

	return best.name, boost
}

// generateSummary creates a one-line summary of the most notable findings.
func generateSummary(f *ProbeFindings) string {
	var parts []string

	if len(f.OffCPUWaiters) > 0 {
		top := f.OffCPUWaiters[0]
		parts = append(parts, fmt.Sprintf("OffCPU: %s %.0f%%", top.Comm, top.WaitPct))
	}
	if len(f.IOLatency) > 0 {
		top := f.IOLatency[0]
		parts = append(parts, fmt.Sprintf("IO p95 %.1fms on %s", top.P95Ms, top.Device))
	}
	if len(f.LockWaiters) > 0 {
		top := f.LockWaiters[0]
		parts = append(parts, fmt.Sprintf("Lock: %s %.0f%%", top.Comm, top.WaitPct))
	}
	if len(f.TCPRetrans) > 0 {
		top := f.TCPRetrans[0]
		parts = append(parts, fmt.Sprintf("Retrans: %d/s", top.Retrans))
	}
	if len(f.NetThroughput) > 0 {
		top := f.NetThroughput[0]
		parts = append(parts, fmt.Sprintf("Net: %s tx=%.1f rx=%.1f MB/s", top.Comm, top.TxMBs, top.RxMBs))
	}
	if len(f.TCPRTT) > 0 {
		top := f.TCPRTT[0]
		parts = append(parts, fmt.Sprintf("RTT: %s avg=%.1fms", top.DstAddr, top.AvgRTTMs))
	}
	if len(f.TCPConnLat) > 0 {
		top := f.TCPConnLat[0]
		parts = append(parts, fmt.Sprintf("ConnLat: %s avg=%.1fms", top.Comm, top.AvgMs))
	}

	if len(parts) == 0 {
		return "No significant findings"
	}

	summary := parts[0]
	for _, p := range parts[1:] {
		if len(summary)+len(p)+3 > 80 {
			break
		}
		summary += " | " + p
	}
	return summary
}

// State returns the current probe state.
func (pm *ProbeManager) State() ProbeState {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	return pm.state
}

// Findings returns the probe findings (nil if not done).
func (pm *ProbeManager) Findings() *ProbeFindings {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	return pm.findings
}

// SecondsLeft returns seconds remaining if running, 0 otherwise.
func (pm *ProbeManager) SecondsLeft() int {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	if pm.state != ProbeRunning {
		return 0
	}
	left := pm.duration - time.Since(pm.start)
	if left < 0 {
		return 0
	}
	return int(left.Seconds())
}

// Pack returns the current pack name.
func (pm *ProbeManager) Pack() string {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	return pm.pack
}

// Tick checks for state transitions. Called each UI tick (~1s).
// The Running→Done transition is handled by the goroutine.
// This only handles Done→Idle expiry.
func (pm *ProbeManager) Tick() {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	if pm.state == ProbeDone && time.Since(pm.doneAt) >= pm.expiry {
		pm.state = ProbeIdle
		pm.findings = nil
	}
}

// ─── probeQuerier interface (for UI) ────────────────────────────────────────

// ProbeState implements probeQuerier for the UI.
func (pm *ProbeManager) ProbeState() int {
	return int(pm.State())
}

// ProbePack implements probeQuerier.
func (pm *ProbeManager) ProbePack() string {
	return pm.Pack()
}

// ProbeSecsLeft implements probeQuerier.
func (pm *ProbeManager) ProbeSecsLeft() int {
	return pm.SecondsLeft()
}

// ProbeSummary implements probeQuerier.
func (pm *ProbeManager) ProbeSummary() string {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	if pm.findings != nil {
		return pm.findings.Summary
	}
	return ""
}
