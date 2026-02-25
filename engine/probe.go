package engine

import (
	"fmt"
	"os"
	"sort"
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

// RunQLatEntry holds run queue latency for one process (watchdog probe).
type RunQLatEntry struct {
	PID   int
	Comm  string
	AvgUs float64
	MaxUs float64
	Count int
}

// WBStallEntry holds writeback stall data for one process (watchdog probe).
type WBStallEntry struct {
	PID        int
	Comm       string
	Count      int
	TotalPages int64
}

// PgFaultEntry holds page fault latency for one process (watchdog probe).
type PgFaultEntry struct {
	PID        int
	Comm       string
	AvgUs      float64
	MajorCount int
	TotalCount int
}

// SwapEvictEntry holds swap activity for one process (watchdog probe).
type SwapEvictEntry struct {
	PID        int
	Comm       string
	ReadPages  uint64
	WritePages uint64
}

// SyscallDissectEntry holds per-PID syscall time breakdown (watchdog probe).
type SyscallDissectEntry struct {
	PID       int
	Comm      string
	Breakdown []SyscallGroupTime // sorted by TotalPct desc
	TotalNs   uint64
}

// SyscallGroupTime holds time spent in one syscall group for a PID.
type SyscallGroupTime struct {
	Group    string  // "read", "write", "lock/sync", "poll", "sleep", "mmap", "open/close", "other"
	TotalNs  uint64
	Count    uint32
	MaxNs    uint32
	TotalPct float64 // % of this PID's total syscall time
}

// SockIOEntry holds per-PID per-connection TCP IO data (watchdog probe).
type SockIOEntry struct {
	PID       int
	Comm      string
	DstAddr   string  // "10.0.0.5:5432"
	Service   string  // "postgres"
	TxBytes   uint64
	RxBytes   uint64
	AvgWaitMs float64
	MaxWaitMs float64
	RecvCount int
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

	// Watchdog probe findings
	RunQLat        []RunQLatEntry
	WBStall        []WBStallEntry
	PgFault        []PgFaultEntry
	SwapEvict      []SwapEvictEntry
	SyscallDissect []SyscallDissectEntry
	SockIO         []SockIOEntry
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

// StartDomain initiates a watchdog-triggered domain-specific probe session.
func (pm *ProbeManager) StartDomain(domain string) error {
	pm.mu.Lock()
	if pm.state == ProbeRunning {
		pm.mu.Unlock()
		return fmt.Errorf("probe already running")
	}
	pm.state = ProbeRunning
	start := time.Now()
	duration := 30 * time.Second
	pm.start = start
	pm.duration = duration
	pm.pack = "watchdog:" + domain
	pm.findings = nil
	pm.doneAt = time.Time{}
	pm.mu.Unlock()

	go pm.runDomainProbe(start, duration, domain)
	return nil
}

// runDomainProbe executes domain-specific eBPF probes in a goroutine.
func (pm *ProbeManager) runDomainProbe(start time.Time, duration time.Duration, domain string) {
	results, err := bpf.RunProbeCtxDomain(duration, domain)

	pm.mu.Lock()
	defer pm.mu.Unlock()

	pack := "watchdog:" + domain
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

	// Convert watchdog: run queue latency
	for _, rq := range r.RunQLat {
		if rq.Count == 0 {
			continue
		}
		avgUs := float64(rq.TotalNs) / float64(rq.Count) / 1000
		maxUs := float64(rq.MaxNs) / 1000
		f.RunQLat = append(f.RunQLat, RunQLatEntry{
			PID:   int(rq.PID),
			Comm:  rq.Comm,
			AvgUs: avgUs,
			MaxUs: maxUs,
			Count: int(rq.Count),
		})
	}

	// Convert watchdog: writeback stalls
	for _, wb := range r.WBStall {
		f.WBStall = append(f.WBStall, WBStallEntry{
			PID:        int(wb.PID),
			Comm:       readCommProbe(wb.PID),
			Count:      int(wb.Count),
			TotalPages: int64(wb.TotalPages),
		})
	}

	// Convert watchdog: page fault latency
	for _, pf := range r.PgFault {
		if pf.Count == 0 {
			continue
		}
		avgUs := float64(pf.TotalNs) / float64(pf.Count) / 1000
		f.PgFault = append(f.PgFault, PgFaultEntry{
			PID:        int(pf.PID),
			Comm:       readCommProbe(pf.PID),
			AvgUs:      avgUs,
			MajorCount: int(pf.MajorCount),
			TotalCount: int(pf.Count),
		})
	}

	// Convert watchdog: swap activity
	for _, se := range r.SwapEvict {
		f.SwapEvict = append(f.SwapEvict, SwapEvictEntry{
			PID:        int(se.PID),
			Comm:       readCommProbe(se.PID),
			ReadPages:  se.ReadPages,
			WritePages: se.WritePages,
		})
	}

	// Convert watchdog: syscall dissection — group by PID, then by syscall group
	if len(r.SyscallDissect) > 0 {
		type pidAgg struct {
			comm    string
			totalNs uint64
			groups  map[string]*SyscallGroupTime
		}
		pidMap := make(map[uint32]*pidAgg)
		for _, sc := range r.SyscallDissect {
			agg, ok := pidMap[sc.PID]
			if !ok {
				agg = &pidAgg{
					comm:   sc.Comm,
					groups: make(map[string]*SyscallGroupTime),
				}
				pidMap[sc.PID] = agg
			}
			_, group := bpf.ResolveSyscall(sc.SyscallNr)
			agg.totalNs += sc.TotalNs
			g, ok := agg.groups[group]
			if !ok {
				g = &SyscallGroupTime{Group: group}
				agg.groups[group] = g
			}
			g.TotalNs += sc.TotalNs
			g.Count += sc.Count
			if sc.MaxNs > g.MaxNs {
				g.MaxNs = sc.MaxNs
			}
		}
		for pid, agg := range pidMap {
			if agg.totalNs == 0 {
				continue
			}
			entry := SyscallDissectEntry{
				PID:     int(pid),
				Comm:    agg.comm,
				TotalNs: agg.totalNs,
			}
			for _, g := range agg.groups {
				g.TotalPct = float64(g.TotalNs) / float64(agg.totalNs) * 100
				if g.TotalPct < 1 {
					continue // hide groups < 1%
				}
				entry.Breakdown = append(entry.Breakdown, *g)
			}
			sort.Slice(entry.Breakdown, func(i, j int) bool {
				return entry.Breakdown[i].TotalPct > entry.Breakdown[j].TotalPct
			})
			f.SyscallDissect = append(f.SyscallDissect, entry)
		}
		sort.Slice(f.SyscallDissect, func(i, j int) bool {
			return f.SyscallDissect[i].TotalNs > f.SyscallDissect[j].TotalNs
		})
		if len(f.SyscallDissect) > 10 {
			f.SyscallDissect = f.SyscallDissect[:10]
		}
	}

	// Convert watchdog: socket IO attribution
	for _, sio := range r.SockIO {
		var avgWaitMs, maxWaitMs float64
		if sio.RecvCount > 0 {
			avgWaitMs = float64(sio.RecvWaitNs) / float64(sio.RecvCount) / 1e6
			maxWaitMs = float64(sio.MaxRecvNs) / 1e6
		}
		svc := bpf.WellKnownPort(sio.DstPort)
		f.SockIO = append(f.SockIO, SockIOEntry{
			PID:       int(sio.PID),
			Comm:      sio.Comm,
			DstAddr:   sio.DstStr,
			Service:   svc,
			TxBytes:   sio.TxBytes,
			RxBytes:   sio.RxBytes,
			AvgWaitMs: avgWaitMs,
			MaxWaitMs: maxWaitMs,
			RecvCount: int(sio.RecvCount),
		})
	}

	// Determine dominant bottleneck from findings
	f.Bottleneck, f.ConfBoost = classifyBottleneck(f)

	// Generate summary
	f.Summary = generateSummary(f)

	return f
}

// readCommProbe reads /proc/PID/comm for a process name (best-effort).
func readCommProbe(pid uint32) string {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid))
	if err != nil {
		return fmt.Sprintf("pid_%d", pid)
	}
	s := string(data)
	if i := len(s) - 1; i >= 0 && s[i] == '\n' {
		s = s[:i]
	}
	return s
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

	// Network score: based on retransmits + high RTT + connect latency + socket IO wait
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
	for _, e := range f.SockIO {
		if e.AvgWaitMs > 10 {
			netScore += e.AvgWaitMs / 10
		}
	}

	// Syscall dissect: boost lock or IO score based on dominant groups
	for _, e := range f.SyscallDissect {
		for _, g := range e.Breakdown {
			if g.Group == "lock/sync" && g.TotalPct > 30 {
				lockScore += g.TotalPct
			}
			if (g.Group == "read" || g.Group == "write") && g.TotalPct > 30 {
				ioScore += g.TotalPct
			}
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
	if len(f.RunQLat) > 0 {
		top := f.RunQLat[0]
		parts = append(parts, fmt.Sprintf("RunQLat: %s avg=%.0fus", top.Comm, top.AvgUs))
	}
	if len(f.WBStall) > 0 {
		top := f.WBStall[0]
		parts = append(parts, fmt.Sprintf("WB: %s %d stalls", top.Comm, top.Count))
	}
	if len(f.PgFault) > 0 {
		top := f.PgFault[0]
		parts = append(parts, fmt.Sprintf("PgFault: %s avg=%.0fus (%d major)", top.Comm, top.AvgUs, top.MajorCount))
	}
	if len(f.SwapEvict) > 0 {
		top := f.SwapEvict[0]
		parts = append(parts, fmt.Sprintf("Swap: %s r=%d w=%d pages", top.Comm, top.ReadPages, top.WritePages))
	}
	if len(f.SyscallDissect) > 0 {
		top := f.SyscallDissect[0]
		if len(top.Breakdown) > 0 {
			parts = append(parts, fmt.Sprintf("Syscall: %s %.0f%% %s", top.Comm, top.Breakdown[0].TotalPct, top.Breakdown[0].Group))
		}
	}
	if len(f.SockIO) > 0 {
		top := f.SockIO[0]
		svc := top.DstAddr
		if top.Service != "" {
			svc = top.Service
		}
		parts = append(parts, fmt.Sprintf("SockIO: %s->%s avg=%.0fms", top.Comm, svc, top.AvgWaitMs))
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
