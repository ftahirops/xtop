//go:build 386 || amd64

package ebpf

import (
	"context"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"
)

// ProbeResults holds the aggregated output from all eBPF probe packs.
type ProbeResults struct {
	Duration      time.Duration
	OffCPU        []OffCPUResult
	IOLatency     []IOLatDeviceResult
	LockWait      []LockWaitResult
	TCPRetrans    []TCPRetransResult
	NetThroughput []NetThroughputResult
	TCPRTT        []TCPRTTResult
	TCPConnLat    []TCPConnLatResult
	Errors        []string
}

// RunProbe attaches all available eBPF probes, collects data for the given
// duration, reads the BPF maps, and returns the results. It is safe to call
// from a goroutine. Each pack is best-effort: if one fails to attach, others
// still run. Use RunProbeCtx for cancellation support.
func RunProbe(duration time.Duration) (*ProbeResults, error) {
	return RunProbeCtx(context.Background(), duration)
}

// RunProbeCtx is like RunProbe but supports cancellation via context.
func RunProbeCtx(ctx context.Context, duration time.Duration) (*ProbeResults, error) {
	cap := Detect()
	if !cap.Available {
		return nil, fmt.Errorf("eBPF not available: %s", cap.Reason)
	}

	selfPID := uint32(os.Getpid())
	durationNs := uint64(duration.Nanoseconds())

	results := &ProbeResults{Duration: duration}

	type packEntry struct {
		name   string
		reader func() error
		closer func()
	}
	var packs []packEntry

	// Attach off-CPU
	oc, err := attachOffCPU()
	if err != nil {
		results.Errors = append(results.Errors, "offcpu: "+err.Error())
	} else {
		packs = append(packs, packEntry{
			name: "offcpu",
			reader: func() error {
				r, err := oc.read()
				if err != nil {
					return err
				}
				r = filterOffCPU(r, selfPID, durationNs)
				sort.Slice(r, func(i, j int) bool { return r[i].TotalNs > r[j].TotalNs })
				if len(r) > 10 {
					r = r[:10]
				}
				results.OffCPU = r
				return nil
			},
			closer: oc.close,
		})
	}

	// Attach IO latency
	io, err := attachIOLatency()
	if err != nil {
		results.Errors = append(results.Errors, "iolatency: "+err.Error())
	} else {
		packs = append(packs, packEntry{
			name: "iolatency",
			reader: func() error {
				perPID, err := io.read()
				if err != nil {
					return err
				}
				// Filter self from per-PID before aggregating
				filtered := perPID[:0]
				for _, r := range perPID {
					if r.PID != selfPID {
						filtered = append(filtered, r)
					}
				}
				devResults := aggregateByDevice(filtered)
				sort.Slice(devResults, func(i, j int) bool { return devResults[i].P95Ns > devResults[j].P95Ns })
				results.IOLatency = devResults
				return nil
			},
			closer: io.close,
		})
	}

	// Attach lock wait
	lw, err := attachLockWait()
	if err != nil {
		results.Errors = append(results.Errors, "lockwait: "+err.Error())
	} else {
		packs = append(packs, packEntry{
			name: "lockwait",
			reader: func() error {
				r, err := lw.read()
				if err != nil {
					return err
				}
				r = filterLockWait(r, selfPID, durationNs)
				sort.Slice(r, func(i, j int) bool { return r[i].TotalWaitNs > r[j].TotalWaitNs })
				if len(r) > 10 {
					r = r[:10]
				}
				results.LockWait = r
				return nil
			},
			closer: lw.close,
		})
	}

	// Attach TCP retrans
	tr, err := attachTCPRetrans()
	if err != nil {
		results.Errors = append(results.Errors, "tcpretrans: "+err.Error())
	} else {
		packs = append(packs, packEntry{
			name: "tcpretrans",
			reader: func() error {
				r, err := tr.read()
				if err != nil {
					return err
				}
				// Filter self
				filtered := r[:0]
				for _, e := range r {
					if e.PID != selfPID {
						filtered = append(filtered, e)
					}
				}
				sort.Slice(filtered, func(i, j int) bool { return filtered[i].Count > filtered[j].Count })
				if len(filtered) > 10 {
					filtered = filtered[:10]
				}
				results.TCPRetrans = filtered
				return nil
			},
			closer: tr.close,
		})
	}

	// Attach net throughput
	nt, err := attachNetThroughput()
	if err != nil {
		results.Errors = append(results.Errors, "netthroughput: "+err.Error())
	} else {
		packs = append(packs, packEntry{
			name: "netthroughput",
			reader: func() error {
				r, err := nt.read()
				if err != nil {
					return err
				}
				// Filter self
				filtered := r[:0]
				for _, e := range r {
					if e.PID != selfPID {
						filtered = append(filtered, e)
					}
				}
				sort.Slice(filtered, func(i, j int) bool {
					return (filtered[i].TxBytes + filtered[i].RxBytes) > (filtered[j].TxBytes + filtered[j].RxBytes)
				})
				if len(filtered) > 10 {
					filtered = filtered[:10]
				}
				results.NetThroughput = filtered
				return nil
			},
			closer: nt.close,
		})
	}

	// Attach TCP RTT
	rtt, err := attachTCPRTT()
	if err != nil {
		results.Errors = append(results.Errors, "tcprtt: "+err.Error())
	} else {
		packs = append(packs, packEntry{
			name: "tcprtt",
			reader: func() error {
				r, err := rtt.read()
				if err != nil {
					return err
				}
				// Sort by average RTT descending
				sort.Slice(r, func(i, j int) bool {
					avgI := float64(r[i].SumUs) / float64(r[i].Count)
					avgJ := float64(r[j].SumUs) / float64(r[j].Count)
					return avgI > avgJ
				})
				if len(r) > 10 {
					r = r[:10]
				}
				results.TCPRTT = r
				return nil
			},
			closer: rtt.close,
		})
	}

	// Attach TCP connect latency
	cl, err := attachTCPConnLat()
	if err != nil {
		results.Errors = append(results.Errors, "tcpconnlat: "+err.Error())
	} else {
		packs = append(packs, packEntry{
			name: "tcpconnlat",
			reader: func() error {
				r, err := cl.read()
				if err != nil {
					return err
				}
				// Filter self
				filtered := r[:0]
				for _, e := range r {
					if e.PID != selfPID {
						filtered = append(filtered, e)
					}
				}
				// Sort by average latency descending
				sort.Slice(filtered, func(i, j int) bool {
					avgI := float64(filtered[i].TotalNs) / float64(filtered[i].Count)
					avgJ := float64(filtered[j].TotalNs) / float64(filtered[j].Count)
					return avgI > avgJ
				})
				if len(filtered) > 10 {
					filtered = filtered[:10]
				}
				results.TCPConnLat = filtered
				return nil
			},
			closer: cl.close,
		})
	}

	if len(packs) == 0 {
		return nil, fmt.Errorf("no probes attached: %v", results.Errors)
	}

	// #15: Collect data for the duration, cancellable via context
	select {
	case <-time.After(duration):
	case <-ctx.Done():
		// Close probes and return early on cancellation
		for _, p := range packs {
			p.closer()
		}
		return nil, ctx.Err()
	}

	// Read all maps
	for _, p := range packs {
		if err := p.reader(); err != nil {
			results.Errors = append(results.Errors, p.name+" read: "+err.Error())
		}
	}

	// Close all probes
	for _, p := range packs {
		p.closer()
	}

	return results, nil
}

// filterOffCPU removes noise from off-CPU results:
//   - Self PID
//   - Kernel threads (pid < 100, or known kernel worker names)
//   - Idle daemons: >90% off-CPU with fewer than 100 context switches means
//     the process wakes up on timers and sleeps immediately — not contention.
//     Real contention produces frequent short waits (count >> 100).
func filterOffCPU(raw []OffCPUResult, selfPID uint32, durationNs uint64) []OffCPUResult {
	var out []OffCPUResult
	for _, r := range raw {
		if r.PID == selfPID {
			continue
		}
		if r.PID < 100 {
			continue
		}
		if isKernelWorker(r.Comm) {
			continue
		}
		// Fewer than 10 context switches = too few data points / idle process.
		if r.Count < 10 {
			continue
		}
		// Idle daemon filter: high off-CPU% with low switch count = timer-driven
		// idle process (e.g. psimon waking every 100ms, sshd keepalive).
		// Real contention: hundreds/thousands of switches in 10s.
		pct := float64(r.TotalNs) / float64(durationNs) * 100
		if pct > 90 && r.Count < 100 {
			continue
		}
		out = append(out, r)
	}
	return out
}

// filterLockWait removes noise from lock contention results:
//   - Self PID
//   - Idle futex waits: futex is used for all synchronization, including normal
//     event loops (epoll→futex, pthread_cond_wait). Real lock contention has
//     many short waits. Idle event waits have few long waits.
//   - Filter: avg wait > 200ms AND count < 100 → idle/event wait, not contention.
func filterLockWait(raw []LockWaitResult, selfPID uint32, durationNs uint64) []LockWaitResult {
	var out []LockWaitResult
	for _, r := range raw {
		if r.PID == selfPID {
			continue
		}
		if r.PID < 100 {
			continue
		}
		avgWaitMs := float64(r.TotalWaitNs) / float64(r.Count) / 1e6
		// Long average + low count = sleeping on condvar/event, not lock contention.
		// Real mutex contention = many short waits (us-to-low-ms range).
		// Idle Go runtime / event loops = few waits averaging 100ms+.
		if avgWaitMs > 100 && r.Count < 100 {
			continue
		}
		// Skip entries with negligible total wait (< 0.1% of probe duration)
		pct := float64(r.TotalWaitNs) / float64(durationNs) * 100
		if pct < 0.1 {
			continue
		}
		out = append(out, r)
	}
	return out
}

// isKernelWorker returns true for known kernel thread names that aren't useful.
func isKernelWorker(comm string) bool {
	if strings.HasPrefix(comm, "kworker/") {
		return true
	}
	switch comm {
	case "rcu_preempt", "rcu_sched", "rcu_bh", "ksoftirqd", "kcompactd0",
		"migration", "idle", "kthreadd", "khungtaskd", "oom_reaper",
		"writeback", "kblockd", "kswapd0", "kauditd", "khugepaged",
		"watchdog", "netns", "rcu_gp", "rcu_par_gp", "slub_flushwq",
		"charger_manager", "devfreq_wq", "kdevtmpfs", "inet_frag_wq":
		return true
	}
	// kworker variants, irq handlers, etc.
	if strings.HasPrefix(comm, "irq/") || strings.HasPrefix(comm, "ksoftirqd/") ||
		strings.HasPrefix(comm, "migration/") || strings.HasPrefix(comm, "watchdog/") ||
		strings.HasPrefix(comm, "cpuhp/") || strings.HasPrefix(comm, "idle/") {
		return true
	}
	return false
}
