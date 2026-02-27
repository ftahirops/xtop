//go:build 386 || amd64

package ebpf

import (
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/ftahirops/xtop/model"
)

// SentinelManager implements collector.Collector for always-on sentinel probes.
type SentinelManager struct {
	mu        sync.Mutex
	attached  bool
	attachErr string

	// Sentinel probe handles (nil if attach failed)
	kfreeskb      *kfreeskbProbe
	tcpreset      *tcpresetProbe
	sockstate     *sockstateProbe
	modload       *modloadProbe
	oomkill       *oomkillProbe
	directreclaim *directreclaimProbe
	cgthrottle    *cgthrottleProbe
	tcpretrans    *tcpretransProbe
	tcpconnlat    *tcpconnlatProbe
	execsnoop     *execsnoopProbe
	ptracedetect  *ptracedetectProbe

	// Previous values for delta computation
	prevDrops    map[uint32]uint64
	prevResets   map[uint32]uint64
	prevStates   map[uint32]uint64 // packed oldstate<<16|newstate
	prevRetrans  map[uint32]uint32
	prevThrottle map[uint64]uint64
	lastRead     time.Time

	// Event history buffers (retained across collection cycles)
	execHistory   []model.ExecEventEntry
	ptraceHistory []model.PtraceEventEntry
	selfPID       uint32

	// Count how many probes attached successfully
	attachedCount int
	totalCount    int
}

// NewSentinelManager creates a new sentinel manager.
func NewSentinelManager() *SentinelManager {
	return &SentinelManager{
		prevDrops:    make(map[uint32]uint64),
		prevResets:   make(map[uint32]uint64),
		prevStates:   make(map[uint32]uint64),
		prevRetrans:  make(map[uint32]uint32),
		prevThrottle: make(map[uint64]uint64),
		selfPID:      uint32(os.Getpid()),
		totalCount:   11,
	}
}

// Name implements collector.Collector.
func (s *SentinelManager) Name() string { return "sentinel" }

// Collect implements collector.Collector. On first call, attaches all sentinel
// probes (best-effort). On each subsequent call, reads BPF maps and populates
// snap.Global.Sentinel with delta-computed rates.
func (s *SentinelManager) Collect(snap *model.Snapshot) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Lazy attach on first call
	if !s.attached {
		s.attach()
		s.attached = true
		s.lastRead = time.Now()
		snap.Global.Sentinel.Active = s.attachedCount > 0
		snap.Global.Sentinel.AttachErr = s.attachErr
		return nil
	}

	now := time.Now()
	elapsed := now.Sub(s.lastRead).Seconds()
	if elapsed < 0.1 {
		elapsed = 1.0
	}
	s.lastRead = now

	sent := &snap.Global.Sentinel
	sent.Active = s.attachedCount > 0
	sent.AttachErr = s.attachErr

	// Read packet drops
	if s.kfreeskb != nil {
		results, err := s.kfreeskb.read()
		if err == nil {
			var totalDropRate float64
			for _, r := range results {
				prev := s.prevDrops[r.Reason]
				delta := r.Count - prev
				rate := float64(delta) / elapsed
				s.prevDrops[r.Reason] = r.Count
				if delta > 0 {
					sent.PktDrops = append(sent.PktDrops, model.PktDropEntry{
						Reason:    r.Reason,
						ReasonStr: dropReasonString(r.Reason),
						Count:     r.Count,
						Rate:      rate,
					})
					// Only count concerning drop reasons in the headline total.
					// Benign reasons (normal TCP lifecycle, flow control, socket filters)
					// are still tracked per-reason but excluded from the alarm rate.
					if !isBenignDropReason(r.Reason) {
						totalDropRate += rate
					}
				}
			}
			sent.PktDropRate = totalDropRate
			sort.Slice(sent.PktDrops, func(i, j int) bool {
				return sent.PktDrops[i].Rate > sent.PktDrops[j].Rate
			})
			if len(sent.PktDrops) > 20 {
				sent.PktDrops = sent.PktDrops[:20]
			}
		}
	}

	// Read TCP resets
	if s.tcpreset != nil {
		results, err := s.tcpreset.read()
		if err == nil {
			var totalResetRate float64
			for _, r := range results {
				prev := s.prevResets[r.PID]
				delta := r.Count - prev
				rate := float64(delta) / elapsed
				s.prevResets[r.PID] = r.Count
				if delta > 0 {
					sent.TCPResets = append(sent.TCPResets, model.TCPResetEntry{
						PID:    r.PID,
						Comm:   r.Comm,
						Count:  r.Count,
						Rate:   rate,
						DstStr: r.DstStr,
					})
					totalResetRate += rate
				}
			}
			sent.TCPResetRate = totalResetRate
			sort.Slice(sent.TCPResets, func(i, j int) bool {
				return sent.TCPResets[i].Rate > sent.TCPResets[j].Rate
			})
			if len(sent.TCPResets) > 10 {
				sent.TCPResets = sent.TCPResets[:10]
			}
		}
	}

	// Read socket state transitions
	if s.sockstate != nil {
		results, err := s.sockstate.read()
		if err == nil {
			for _, r := range results {
				key := uint32(r.OldState)<<16 | uint32(r.NewState)
				prev := s.prevStates[key]
				delta := r.Count - prev
				rate := float64(delta) / elapsed
				s.prevStates[key] = r.Count
				if delta > 0 {
					sent.StateChanges = append(sent.StateChanges, model.SockStateEntry{
						OldState: r.OldState,
						NewState: r.NewState,
						OldStr:   tcpStateName(r.OldState),
						NewStr:   tcpStateName(r.NewState),
						Count:    r.Count,
						Rate:     rate,
					})
				}
			}
			sort.Slice(sent.StateChanges, func(i, j int) bool {
				return sent.StateChanges[i].Rate > sent.StateChanges[j].Rate
			})
			if len(sent.StateChanges) > 20 {
				sent.StateChanges = sent.StateChanges[:20]
			}
		}
	}

	// Read sentinel retransmits
	if s.tcpretrans != nil {
		results, err := s.tcpretrans.read()
		if err == nil {
			var totalRetransRate float64
			for _, r := range results {
				prev := s.prevRetrans[r.PID]
				delta := r.Count - prev
				rate := float64(delta) / elapsed
				s.prevRetrans[r.PID] = r.Count
				if delta > 0 {
					sent.Retransmits = append(sent.Retransmits, model.SentinelRetransEntry{
						PID:    r.PID,
						Comm:   r.Comm,
						Count:  r.Count,
						Rate:   float32toRate(rate),
						DstStr: r.DstStr,
					})
					totalRetransRate += rate
				}
			}
			sent.RetransRate = totalRetransRate
			sort.Slice(sent.Retransmits, func(i, j int) bool {
				return sent.Retransmits[i].Rate > sent.Retransmits[j].Rate
			})
			if len(sent.Retransmits) > 10 {
				sent.Retransmits = sent.Retransmits[:10]
			}
		}
	}

	// Read sentinel connect latency
	if s.tcpconnlat != nil {
		results, err := s.tcpconnlat.read()
		if err == nil {
			for _, r := range results {
				if r.Count == 0 {
					continue
				}
				avgNs := float64(r.TotalNs) / float64(r.Count)
				sent.ConnLatency = append(sent.ConnLatency, model.SentinelConnLatEntry{
					PID:    r.PID,
					Comm:   r.Comm,
					Count:  r.Count,
					AvgMs:  avgNs / 1e6,
					MaxMs:  float64(r.MaxNs) / 1e6,
					DstStr: r.DstStr,
				})
			}
			sort.Slice(sent.ConnLatency, func(i, j int) bool {
				return sent.ConnLatency[i].AvgMs > sent.ConnLatency[j].AvgMs
			})
			if len(sent.ConnLatency) > 10 {
				sent.ConnLatency = sent.ConnLatency[:10]
			}
		}
	}

	// Read module loads (event-like: read and clear)
	if s.modload != nil {
		results, _ := s.modload.readAndClear()
		for _, r := range results {
			sent.ModLoads = append(sent.ModLoads, model.ModLoadEntry{
				Name:      r.Name,
				Timestamp: int64(r.Ts),
				Count:     r.Count,
			})
		}
		if len(sent.ModLoads) > 20 {
			sent.ModLoads = sent.ModLoads[:20]
		}
	}

	// Read OOM kills (event-like: read and clear)
	if s.oomkill != nil {
		results, _ := s.oomkill.readAndClear()
		for _, r := range results {
			comm := readComm(r.VictimPID)
			if comm == fmt.Sprintf("pid_%d", r.VictimPID) {
				comm = "killed"
			}
			sent.OOMKills = append(sent.OOMKills, model.OOMKillEntry{
				VictimPID:  r.VictimPID,
				VictimComm: comm,
				TotalVM:    r.TotalVM,
				AnonRSS:    r.AnonRSS,
				Timestamp:  int64(r.Ts),
			})
		}
		if len(sent.OOMKills) > 20 {
			sent.OOMKills = sent.OOMKills[:20]
		}
	}

	// Read direct reclaim stalls
	if s.directreclaim != nil {
		results, err := s.directreclaim.read()
		if err == nil {
			var totalStallMs float64
			for _, r := range results {
				stallMs := float64(r.StallNs) / 1e6
				totalStallMs += stallMs
				sent.DirectReclaim = append(sent.DirectReclaim, model.DirectReclaimEntry{
					PID:     r.PID,
					Comm:    readComm(r.PID),
					StallNs: r.StallNs,
					Count:   r.Count,
				})
			}
			sent.ReclaimStallMs = totalStallMs
			sort.Slice(sent.DirectReclaim, func(i, j int) bool {
				return sent.DirectReclaim[i].StallNs > sent.DirectReclaim[j].StallNs
			})
			if len(sent.DirectReclaim) > 10 {
				sent.DirectReclaim = sent.DirectReclaim[:10]
			}
		}
	}

	// Read cgroup throttle events
	if s.cgthrottle != nil {
		results, err := s.cgthrottle.read()
		if err == nil {
			var totalThrottleRate float64
			for _, r := range results {
				prev := s.prevThrottle[r.CgID]
				delta := r.Count - prev
				rate := float64(delta) / elapsed
				s.prevThrottle[r.CgID] = r.Count
				if delta > 0 {
					cgPath := resolveCgroupID(r.CgID)
					sent.CgThrottles = append(sent.CgThrottles, model.CgThrottleEntry{
						CgID:   r.CgID,
						CgPath: cgPath,
						Count:  r.Count,
						Rate:   rate,
					})
					totalThrottleRate += rate
				}
			}
			sent.ThrottleRate = totalThrottleRate
			sort.Slice(sent.CgThrottles, func(i, j int) bool {
				return sent.CgThrottles[i].Rate > sent.CgThrottles[j].Rate
			})
			if len(sent.CgThrottles) > 10 {
				sent.CgThrottles = sent.CgThrottles[:10]
			}
		}
	}

	// Read exec events — accumulate into history buffer
	if s.execsnoop != nil {
		results, _ := s.execsnoop.readAndClear()
		for _, r := range results {
			// Skip xtop's own children (w, journalctl, etc.)
			if r.PPID == s.selfPID || r.PID == s.selfPID {
				continue
			}
			s.execHistory = append([]model.ExecEventEntry{{
				PID:       r.PID,
				PPID:      r.PPID,
				UID:       r.UID,
				Comm:      r.Comm,
				Filename:  r.Filename,
				Count:     r.Count,
				Timestamp: int64(r.Ts),
			}}, s.execHistory...)
		}
		// Keep most recent 50 events
		if len(s.execHistory) > 50 {
			s.execHistory = s.execHistory[:50]
		}
		sent.ExecEvents = s.execHistory
	}

	// Read ptrace events — accumulate into history buffer
	if s.ptracedetect != nil {
		results, _ := s.ptracedetect.readAndClear()
		for _, r := range results {
			targetComm := readComm(r.TargetPID)
			s.ptraceHistory = append([]model.PtraceEventEntry{{
				TracerPID:  r.TracerPID,
				TracerComm: r.TracerComm,
				TargetPID:  r.TargetPID,
				TargetComm: targetComm,
				Request:    r.Request,
				RequestStr: ptraceRequestName(r.Request),
				Count:      r.Count,
				Timestamp:  int64(r.Ts),
			}}, s.ptraceHistory...)
		}
		if len(s.ptraceHistory) > 20 {
			s.ptraceHistory = s.ptraceHistory[:20]
		}
		sent.PtraceEvents = s.ptraceHistory
	}

	return nil
}

// Close detaches all sentinel probes.
func (s *SentinelManager) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.kfreeskb != nil {
		s.kfreeskb.close()
	}
	if s.tcpreset != nil {
		s.tcpreset.close()
	}
	if s.sockstate != nil {
		s.sockstate.close()
	}
	if s.modload != nil {
		s.modload.close()
	}
	if s.oomkill != nil {
		s.oomkill.close()
	}
	if s.directreclaim != nil {
		s.directreclaim.close()
	}
	if s.cgthrottle != nil {
		s.cgthrottle.close()
	}
	if s.tcpretrans != nil {
		s.tcpretrans.close()
	}
	if s.tcpconnlat != nil {
		s.tcpconnlat.close()
	}
	if s.execsnoop != nil {
		s.execsnoop.close()
	}
	if s.ptracedetect != nil {
		s.ptracedetect.close()
	}
}

// AttachedCount returns how many sentinel probes attached successfully.
func (s *SentinelManager) AttachedCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.attachedCount
}

// TotalCount returns the total number of sentinel probes.
func (s *SentinelManager) TotalCount() int { return s.totalCount }

// attach tries to attach all sentinel probes, best-effort.
func (s *SentinelManager) attach() {
	// Only attach if BTF + root available
	cap := Detect()
	if !cap.Available {
		s.attachErr = cap.Reason
		return
	}

	var errs []string

	if p, err := attachKfreeSkb(); err != nil {
		errs = append(errs, "kfreeskb: "+err.Error())
	} else {
		s.kfreeskb = p
		s.attachedCount++
	}

	if p, err := attachTCPReset(); err != nil {
		errs = append(errs, "tcpreset: "+err.Error())
	} else {
		s.tcpreset = p
		s.attachedCount++
	}

	if p, err := attachSockState(); err != nil {
		errs = append(errs, "sockstate: "+err.Error())
	} else {
		s.sockstate = p
		s.attachedCount++
	}

	if p, err := attachModLoad(); err != nil {
		errs = append(errs, "modload: "+err.Error())
	} else {
		s.modload = p
		s.attachedCount++
	}

	if p, err := attachOOMKill(); err != nil {
		errs = append(errs, "oomkill: "+err.Error())
	} else {
		s.oomkill = p
		s.attachedCount++
	}

	if p, err := attachDirectReclaim(); err != nil {
		errs = append(errs, "directreclaim: "+err.Error())
	} else {
		s.directreclaim = p
		s.attachedCount++
	}

	if p, err := attachCgThrottle(); err != nil {
		errs = append(errs, "cgthrottle: "+err.Error())
	} else {
		s.cgthrottle = p
		s.attachedCount++
	}

	if p, err := attachTCPRetrans(); err != nil {
		errs = append(errs, "tcpretrans: "+err.Error())
	} else {
		s.tcpretrans = p
		s.attachedCount++
	}

	if p, err := attachTCPConnLat(); err != nil {
		errs = append(errs, "tcpconnlat: "+err.Error())
	} else {
		s.tcpconnlat = p
		s.attachedCount++
	}

	if p, err := attachExecSnoop(); err != nil {
		errs = append(errs, "execsnoop: "+err.Error())
	} else {
		s.execsnoop = p
		s.attachedCount++
	}

	if p, err := attachPtraceDetect(); err != nil {
		errs = append(errs, "ptracedetect: "+err.Error())
	} else {
		s.ptracedetect = p
		s.attachedCount++
	}

	if len(errs) > 0 {
		s.attachErr = strings.Join(errs, "; ")
	}
}

// float32toRate is a helper to truncate excessive precision.
func float32toRate(f float64) float64 {
	if f < 0 {
		return 0
	}
	return f
}

// resolveCgroupID attempts to resolve a cgroup ID to a path.
func resolveCgroupID(cgID uint64) string {
	// Best-effort: read /proc/self/cgroup to identify the mount, then
	// search /sys/fs/cgroup. For efficiency, we fall back to the numeric ID.
	path := fmt.Sprintf("/sys/fs/cgroup")
	entries, err := os.ReadDir(path)
	if err != nil {
		return fmt.Sprintf("cgid:%d", cgID)
	}
	return findCgroupByID(path, entries, cgID, 0)
}

// findCgroupByID recursively searches for a cgroup with the given ID.
func findCgroupByID(base string, entries []os.DirEntry, target uint64, depth int) string {
	if depth > 4 {
		return fmt.Sprintf("cgid:%d", target)
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		name := e.Name()
		if strings.HasPrefix(name, ".") {
			continue
		}
		sub := base + "/" + name
		// Read cgroup.id if available
		data, err := os.ReadFile(sub + "/cgroup.id")
		if err == nil {
			idStr := strings.TrimSpace(string(data))
			var id uint64
			if _, err := fmt.Sscanf(idStr, "%d", &id); err == nil && id == target {
				// Return path relative to /sys/fs/cgroup
				rel := strings.TrimPrefix(sub, "/sys/fs/cgroup")
				if rel == "" {
					rel = "/"
				}
				return rel
			}
		}
		// Recurse into subdirectories
		subEntries, err := os.ReadDir(sub)
		if err != nil {
			continue
		}
		if found := findCgroupByID(sub, subEntries, target, depth+1); !strings.HasPrefix(found, "cgid:") {
			return found
		}
	}
	return fmt.Sprintf("cgid:%d", target)
}
