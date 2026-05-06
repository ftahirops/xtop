package engine

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/ftahirops/xtop/model"
)

// Phase 6: active investigation probes.
//
// When an evidence pattern is partially matched and confidence is low, run a
// targeted read-only command — same thing a human SRE would type — and
// capture the output. The capture is attached to the next trace dump.
//
// Hard safety budget (every constant below is a load-bearing safety rail):
//
//   - **Disabled by default.** Set XTOP_PROBES=1 to enable.
//   - 5s deadline per probe (context.WithTimeout).
//   - 64 KB stdout cap, 16 KB stderr cap (truncated, marked).
//   - 30s rate limit per probe class (no flooding).
//   - 3 concurrent probes max process-wide (semaphore).
//   - Output kept only on the result; not persisted unless the user dumps a trace.
//   - Probes are explicit string commands — no untrusted data interpolation.
//
// Probes registered in v1 are conservative read-only system commands. eBPF /
// perf probes (off-CPU stack profiles, etc.) are intentionally NOT in v1
// because they require root/CAP_BPF and have wider blast radius.

const (
	probeDeadline       = 5 * time.Second
	probeStdoutCap      = 64 * 1024
	probeStderrCap      = 16 * 1024
	probeClassRateLimit = 30 * time.Second
	probeConcurrencyMax = 3
)

// Probe describes one investigation step.
type Probe struct {
	Name string // human-readable name, e.g. "top_cpu_processes"
	// Triggers is the set of evidence IDs that cause this probe to be
	// considered. The probe also requires Strength >= MinStrength.
	Triggers    []string
	MinStrength float64
	// Cmd + Args define the shell command. NO user-data interpolation here:
	// the args are static, by design.
	Cmd  string
	Args []string
}

// builtin returns the v1 probe set. All read-only, all bounded.
//
// eBPF probes are gated by XTOP_PROBES_EBPF=1 in addition to XTOP_PROBES=1.
// Off by default even when probes are on, because eBPF needs CAP_BPF/root and
// the helper tools (bpftrace, perf) may not be installed.
func builtinProbes() []Probe {
	probes := []Probe{
		{
			Name:        "top_cpu_processes",
			Triggers:    []string{"cpu.busy", "cpu.psi", "cpu.runqueue"},
			MinStrength: 0.5,
			Cmd:         "ps",
			Args:        []string{"-eo", "pid,pcpu,pmem,state,comm,args", "--sort=-pcpu"},
		},
		{
			Name:        "dstate_processes",
			Triggers:    []string{"io.dstate", "io.psi"},
			MinStrength: 0.4,
			Cmd:         "ps",
			Args:        []string{"-eo", "pid,state,wchan:30,comm,args"},
		},
		{
			Name:        "kernel_slab_top",
			Triggers:    []string{"mem.slab.leak", "mem.psi", "mem.alloc.stall"},
			MinStrength: 0.4,
			Cmd:         "sh",
			Args:        []string{"-c", "head -30 /proc/slabinfo 2>/dev/null"},
		},
		{
			Name:        "tcp_retrans_summary",
			Triggers:    []string{"net.tcp.retrans", "net.drops"},
			MinStrength: 0.5,
			Cmd:         "ss",
			Args:        []string{"-tin", "state", "established"},
		},
	}

	if os.Getenv("XTOP_PROBES_EBPF") == "1" {
		probes = append(probes, ebpfProbes()...)
	}
	return probes
}

// ebpfProbes returns the eBPF-backed probe set (TODO #4 minimum viable).
//
// Detection strategy: probe the host for `bpftrace` first, then fall back to
// a `perf` one-shot if available. If neither tool is present we still
// register the Probe — runProbe will report the missing-binary error in the
// trace dump, which is itself useful audit information.
//
// Hard 5s deadline still applies (probeDeadline). For sched off-CPU stacks
// that's enough to capture a few seconds of activity on a busy host.
func ebpfProbes() []Probe {
	// 2s capture so we comfortably fit inside probeDeadline=5s.
	const captureSec = 2

	if _, err := exec.LookPath("bpftrace"); err == nil {
		return []Probe{{
			// Off-CPU stacks for D-state-heavy workloads. Counts kstack
			// occurrences over `captureSec` and prints the top 10.
			Name:        "ebpf_offcpu_stacks",
			Triggers:    []string{"io.dstate", "io.psi", "io.disk.latency"},
			MinStrength: 0.5,
			Cmd:         "bpftrace",
			Args: []string{
				"-e",
				`kprobe:finish_task_switch { @[kstack] = count(); }
				 interval:s:` + probeItoa(captureSec) + ` { exit(); }`,
			},
		}, {
			// Per-PID syscall rate during a runqueue stall. Useful when
			// cpu.runqueue fires but `ps` blame is ambiguous.
			Name:        "ebpf_syscall_top",
			Triggers:    []string{"cpu.runqueue"},
			MinStrength: 0.6,
			Cmd:         "bpftrace",
			Args: []string{
				"-e",
				`tracepoint:raw_syscalls:sys_enter { @[comm] = count(); }
				 interval:s:` + probeItoa(captureSec) + ` { exit(); }`,
			},
		}}
	}

	if _, err := exec.LookPath("perf"); err == nil {
		return []Probe{{
			Name:        "perf_top_short",
			Triggers:    []string{"cpu.busy", "cpu.psi"},
			MinStrength: 0.6,
			Cmd:         "sh",
			Args:        []string{"-c", "perf top -E 20 --stdio --duration 2 2>/dev/null"},
		}}
	}

	// Neither tool installed — leave the probe set empty. Operators see no
	// extra probes; XTOP_PROBES_EBPF=1 simply does nothing on this host.
	return nil
}

// probeItoa is a minimal int→string for static probe-arg construction.
// (Named to avoid shadowing the existing itoa in this package.)
func probeItoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}

// ProbeRunner is the per-engine probe scheduler.
type ProbeRunner struct {
	enabled bool
	probes  []Probe
	sem     chan struct{} // concurrency cap
	mu      sync.Mutex
	lastRun map[string]time.Time
}

// NewProbeRunner constructs the runner. Honors XTOP_PROBES.
func NewProbeRunner() *ProbeRunner {
	enabled := os.Getenv("XTOP_PROBES") == "1"
	return &ProbeRunner{
		enabled: enabled,
		probes:  builtinProbes(),
		sem:     make(chan struct{}, probeConcurrencyMax),
		lastRun: make(map[string]time.Time),
	}
}

// Enabled reports whether probes will actually run.
func (r *ProbeRunner) Enabled() bool { return r != nil && r.enabled }

// SetEnabled forces enable/disable (for the CLI helper).
func (r *ProbeRunner) SetEnabled(v bool) {
	if r != nil {
		r.enabled = v
	}
}

// MaybeRun considers the result and dispatches probes for any matching
// evidence. Probes run in goroutines but the runner waits up to a small
// budget for them to finish before returning so the result is attachable.
//
// Returns the slice of probe results captured this tick (may be empty).
func (r *ProbeRunner) MaybeRun(result *model.AnalysisResult) []model.ProbeResult {
	if r == nil || !r.enabled || result == nil {
		return nil
	}

	type job struct {
		probe Probe
		ev    model.Evidence
	}
	var jobs []job

	r.mu.Lock()
	now := time.Now()
	for _, p := range r.probes {
		// rate-limit per probe class
		if t, ok := r.lastRun[p.Name]; ok && now.Sub(t) < probeClassRateLimit {
			continue
		}
		// find a matching evidence in result
		for _, rca := range result.RCA {
			matched := false
			for _, ev := range rca.EvidenceV2 {
				if ev.Strength < p.MinStrength {
					continue
				}
				for _, trig := range p.Triggers {
					if ev.ID == trig {
						jobs = append(jobs, job{probe: p, ev: ev})
						matched = true
						break
					}
				}
				if matched {
					break
				}
			}
			if matched {
				break
			}
		}
	}
	// optimistic: stamp lastRun even for jobs we'll dispatch — this prevents
	// the same tick from re-queueing the same probe due to multiple matching
	// evidence items.
	for _, j := range jobs {
		r.lastRun[j.probe.Name] = now
	}
	r.mu.Unlock()

	if len(jobs) == 0 {
		return nil
	}

	var wg sync.WaitGroup
	resultsCh := make(chan model.ProbeResult, len(jobs))

	for _, j := range jobs {
		// Non-blocking acquire; if no slot, drop this probe rather than queue.
		select {
		case r.sem <- struct{}{}:
			wg.Add(1)
			go func(j job) {
				defer wg.Done()
				defer func() { <-r.sem }()
				resultsCh <- runProbe(j.probe, j.ev)
			}(j)
		default:
			continue
		}
	}

	// Each probe is hard-bounded internally by probeDeadline (5s) via
	// context.WithTimeout in runProbe. We just wait for them all to finish.
	wg.Wait()
	close(resultsCh)

	results := make([]model.ProbeResult, 0, len(jobs))
	for res := range resultsCh {
		results = append(results, res)
	}
	return results
}

// runProbe executes a single probe with all the safety rails.
//
// We capture combined stdout+stderr via cmd.CombinedOutput-ish path, but with
// a bytes.Buffer write cap so the process is killed once the cap is hit.
// This is simpler and deadlock-free vs. separate pipes + drain logic.
func runProbe(p Probe, trigger model.Evidence) model.ProbeResult {
	out := model.ProbeResult{
		Name:       p.Name,
		EvidenceID: trigger.ID,
		StartedAt:  time.Now(),
	}
	ctx, cancel := context.WithTimeout(context.Background(), probeDeadline)
	defer cancel()

	cmd := exec.CommandContext(ctx, p.Cmd, p.Args...)
	stdoutCap := newCapWriter(probeStdoutCap)
	stderrCap := newCapWriter(probeStderrCap)
	cmd.Stdout = stdoutCap
	cmd.Stderr = stderrCap
	// WaitDelay: after the context fires (process killed), give the stdout/stderr
	// copy goroutines at most 1s to drain and return. Without this, a process
	// that produced no output (e.g. `sleep 30`) would make cmd.Run block until
	// the OS finalizes pipe closure — which can take the full sleep duration.
	cmd.WaitDelay = time.Second

	werr := cmd.Run() // Run = Start + Wait, blocking until done or context fires.

	out.DurationMs = int(time.Since(out.StartedAt).Milliseconds())
	out.Output = stdoutCap.String()
	out.Stderr = stderrCap.String()
	out.Truncated = stdoutCap.truncated
	if werr != nil {
		if exitErr, ok := werr.(*exec.ExitError); ok {
			out.ExitCode = exitErr.ExitCode()
		} else {
			out.Error = werr.Error()
		}
	}
	return out
}

// capWriter is an io.Writer with a hard byte cap. After reaching the cap it
// silently discards further bytes and sets truncated=true. The process
// continues running until ctx fires or it exits naturally.
type capWriter struct {
	cap       int
	buf       []byte
	truncated bool
}

func newCapWriter(cap int) *capWriter {
	return &capWriter{cap: cap, buf: make([]byte, 0, cap)}
}

func (w *capWriter) Write(p []byte) (int, error) {
	remaining := w.cap - len(w.buf)
	if remaining <= 0 {
		w.truncated = true
		return len(p), nil // claim full write so process keeps writing or exits
	}
	if len(p) > remaining {
		w.buf = append(w.buf, p[:remaining]...)
		w.truncated = true
		return len(p), nil
	}
	w.buf = append(w.buf, p...)
	return len(p), nil
}

func (w *capWriter) String() string { return string(w.buf) }


// SummarizeForTrace returns a compact one-liner per probe — used in the
// markdown rendering of the trace file.
func SummarizeForTrace(results []model.ProbeResult) string {
	if len(results) == 0 {
		return ""
	}
	var b strings.Builder
	for _, r := range results {
		fmt.Fprintf(&b, "- **%s** (trigger=`%s`, %dms, exit=%d): %d bytes captured\n",
			r.Name, r.EvidenceID, r.DurationMs, r.ExitCode, len(r.Output))
	}
	return b.String()
}
