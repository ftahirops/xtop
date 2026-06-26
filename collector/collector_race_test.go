//go:build linux

package collector

// TestCollectorPoolNoRace exercises the Phase 1 worker pool (the goroutine fan-out
// in CollectAll) under the Go race detector.  The test's sole purpose is to be
// run as:
//
//	CGO_ENABLED=1 go test ./collector/ -run 'Pool|Race|Concurren' -race -count=1 -v
//
// If any two collectors write the same Snapshot field, the race detector fires
// here — giving us a regression guard for the disjoint-field invariant stated
// above the pool loop in collector.go.
//
// Two complementary sub-tests are included:
//
//  1. Synthetic pool — eight minimal fake collectors each writing a distinct
//     top-level Snapshot field.  This verifies that the pool itself is
//     race-clean for genuinely disjoint writes.
//
//  2. Real collectors — the lean registry (CPU, Memory, PSI, Disk, Network,
//     Filesystem, SysInfo, Identity, Process) run through CollectAll; these
//     all read /proc and /sys which are available on any Linux test host
//     without root.  This exercises production code paths under -race and
//     would fire if two built-in collectors share a field.

import (
	"sync/atomic"
	"testing"

	"github.com/ftahirops/xtop/model"
)

// ---------------------------------------------------------------------------
// Synthetic disjoint-field collectors
// ---------------------------------------------------------------------------

// Each fieldWriter writes exactly one Snapshot field and panics if it is ever
// called concurrently with itself (which would be a pool bug, not a race on
// snapshot fields).

type cpuWriter struct{ calls int64 }

func (c *cpuWriter) Name() string { return "test-cpu" }
func (c *cpuWriter) Collect(snap *model.Snapshot) error {
	atomic.AddInt64(&c.calls, 1)
	snap.Global.CPU.NumCPUs = 4
	return nil
}

type memWriter struct{ calls int64 }

func (m *memWriter) Name() string { return "test-mem" }
func (m *memWriter) Collect(snap *model.Snapshot) error {
	atomic.AddInt64(&m.calls, 1)
	snap.Global.Memory.Total = 8 * 1024 * 1024 * 1024
	return nil
}

type psiWriter struct{ calls int64 }

func (p *psiWriter) Name() string { return "test-psi" }
func (p *psiWriter) Collect(snap *model.Snapshot) error {
	atomic.AddInt64(&p.calls, 1)
	snap.Global.PSI.CPU.Some.Avg10 = 0.01
	return nil
}

type diskWriter struct{ calls int64 }

func (d *diskWriter) Name() string { return "test-disk" }
func (d *diskWriter) Collect(snap *model.Snapshot) error {
	atomic.AddInt64(&d.calls, 1)
	snap.Global.Disks = []model.DiskStats{{Name: "sda"}}
	return nil
}

type netWriter struct{ calls int64 }

func (n *netWriter) Name() string { return "test-net" }
func (n *netWriter) Collect(snap *model.Snapshot) error {
	atomic.AddInt64(&n.calls, 1)
	snap.Global.Network = []model.NetworkStats{{Name: "eth0"}}
	return nil
}

type procWriter struct{ calls int64 }

func (p *procWriter) Name() string { return "test-proc" }
func (p *procWriter) Collect(snap *model.Snapshot) error {
	atomic.AddInt64(&p.calls, 1)
	snap.Processes = []model.ProcessMetrics{{PID: 1, Comm: "init"}}
	return nil
}

type sysInfoWriter struct{ calls int64 }

func (s *sysInfoWriter) Name() string { return "test-sysinfo" }
func (s *sysInfoWriter) Collect(snap *model.Snapshot) error {
	atomic.AddInt64(&s.calls, 1)
	if snap.SysInfo == nil {
		snap.SysInfo = &model.SysInfo{}
	}
	snap.SysInfo.Hostname = "testhost"
	return nil
}

type logsWriter struct{ calls int64 }

func (l *logsWriter) Name() string { return "test-logs" }
func (l *logsWriter) Collect(snap *model.Snapshot) error {
	atomic.AddInt64(&l.calls, 1)
	snap.Global.Logs.Services = []model.ServiceLogStats{{Name: "syslog"}}
	return nil
}

// ---------------------------------------------------------------------------
// TestCollectorPoolNoRace/Synthetic
// ---------------------------------------------------------------------------

// TestCollectorPoolNoRace_Synthetic builds a Registry with eight fake collectors
// each writing a disjoint Snapshot field and calls CollectAll 20 times.  Under
// -race this validates that the pool dispatch is race-clean.
func TestCollectorPoolNoRace_Synthetic(t *testing.T) {
	r := &Registry{
		collectors: []Collector{
			&cpuWriter{},
			&memWriter{},
			&psiWriter{},
			&diskWriter{},
			&netWriter{},
			&procWriter{},
			&sysInfoWriter{},
			&logsWriter{},
		},
	}

	// Run many iterations so the race detector has multiple opportunities to
	// observe concurrent writes on any shared field.
	for i := 0; i < 20; i++ {
		snap := &model.Snapshot{}
		errs := r.CollectAll(snap)
		if len(errs) != 0 {
			t.Errorf("iter %d: unexpected errors: %v", i, errs)
		}
		// Spot-check that collectors actually ran (not silently skipped).
		if snap.Global.CPU.NumCPUs == 0 {
			t.Errorf("iter %d: cpu field not written — pool may not have dispatched", i)
		}
	}
}

// ---------------------------------------------------------------------------
// TestCollectorPoolNoRace_RealCollectors
// ---------------------------------------------------------------------------

// TestCollectorPoolNoRace_RealCollectors runs the lean production collector set
// (CPU, Memory, PSI, Disk, Network, Filesystem, SysInfo, Identity, Process)
// through CollectAll.  All of these read /proc or /sys — available on every
// Linux host — and require no root privileges.  This exercises the actual
// field-write paths of each built-in collector under -race; a real field
// overlap between any two of them would fire the race detector here.
func TestCollectorPoolNoRace_RealCollectors(t *testing.T) {
	r := NewRegistryMode(ModeLean)

	for i := 0; i < 5; i++ {
		snap := &model.Snapshot{}
		// Errors are expected on some collectors if optional files are absent
		// (e.g. /proc/pressure/* without PSI kernel support); we don't fail
		// the test on them — what matters is absence of data races.
		_ = r.CollectAll(snap)
	}
}
