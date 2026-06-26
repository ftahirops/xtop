//go:build 386 || amd64

package ebpf

// Pure userspace tests for percentilesFromSlots64 and aggregateByDevice.
// No kernel, no BTF, no root required.

import (
	"testing"
)

// ─── percentilesFromSlots64 ───────────────────────────────────────────────────

func TestPercentilesFromSlots64_Zero(t *testing.T) {
	// Total=0 → all percentiles should be 0.
	p50, p95, p99 := percentilesFromSlots64(make([]uint64, 16), 0)
	if p50 != 0 || p95 != 0 || p99 != 0 {
		t.Errorf("expected all-zero on empty histogram; got p50=%d p95=%d p99=%d", p50, p95, p99)
	}
}

func TestPercentilesFromSlots64_AllInSlot0(t *testing.T) {
	// All 100 events land in slot 0 (1–2µs range).
	// Midpoint calculation: (lo+hi)/2 * 1000 ns. For slot 0:
	//   lo=1, hi=2 → (1+2)/2 = 1 (integer division) → 1000 ns.
	slots := make([]uint64, 16)
	slots[0] = 100
	p50, p95, p99 := percentilesFromSlots64(slots, 100)
	// All three percentiles must resolve to slot 0's midpoint (1000ns).
	if p50 != 1000 {
		t.Errorf("p50=%d, want 1000ns (slot 0 midpoint)", p50)
	}
	if p95 != 1000 {
		t.Errorf("p95=%d, want 1000ns", p95)
	}
	if p99 != 1000 {
		t.Errorf("p99=%d, want 1000ns", p99)
	}
}

func TestPercentilesFromSlots64_Ascending(t *testing.T) {
	// Distribute counts so p50 < p95 < p99.
	// slot 0 (1-2µs): 60 events → covers p50
	// slot 2 (4-8µs): 35 events → covers p95
	// slot 4 (16-32µs): 5 events → covers p99
	slots := make([]uint64, 16)
	slots[0] = 60
	slots[2] = 35
	slots[4] = 5
	total := uint64(100)
	p50, p95, p99 := percentilesFromSlots64(slots, total)

	// p50 must resolve to slot 0 (cumul=60 ≥ 50)
	// p95 must resolve to slot 2 (cumul=95 ≥ 95)
	// p99 must resolve to slot 4 (cumul=100 ≥ 99)
	if p50 >= p95 {
		t.Errorf("p50 (%d) should be < p95 (%d)", p50, p95)
	}
	if p95 >= p99 {
		t.Errorf("p95 (%d) should be < p99 (%d)", p95, p99)
	}
}

func TestPercentilesFromSlots64_Slot0Midpoint(t *testing.T) {
	// Slot i covers [2^i, 2^(i+1)) µs. Midpoint = (2^i + 2^(i+1))/2 µs.
	// Then convert to ns (×1000).
	//
	// Slot 3: [8, 16) µs → midpoint = (8+16)/2 = 12µs = 12000ns
	slots := make([]uint64, 16)
	slots[3] = 100
	p50, _, _ := percentilesFromSlots64(slots, 100)
	if p50 != 12000 {
		t.Errorf("slot 3 midpoint: p50=%d, want 12000ns", p50)
	}
}

func TestPercentilesFromSlots64_HighSlot(t *testing.T) {
	// Slot 15: [32768, 65536) µs → midpoint = 49152µs = 49152000ns
	slots := make([]uint64, 16)
	slots[15] = 100
	p50, p95, p99 := percentilesFromSlots64(slots, 100)
	if p50 != 49152000 {
		t.Errorf("slot 15 p50=%d, want 49152000ns", p50)
	}
	if p50 != p95 || p95 != p99 {
		t.Errorf("all percentiles should be equal when one slot; p50=%d p95=%d p99=%d", p50, p95, p99)
	}
}

// ─── aggregateByDevice ────────────────────────────────────────────────────────

func TestAggregateByDevice_Empty(t *testing.T) {
	results := aggregateByDevice(nil)
	if len(results) != 0 {
		t.Errorf("expected empty result for nil input; got %d", len(results))
	}
}

func TestAggregateByDevice_SingleDevice(t *testing.T) {
	// Two PIDs on the same dev; totals should sum.
	slots := [16]uint32{}
	slots[2] = 50 // all counts in slot 2
	perPID := []IOLatResult{
		{PID: 1, Comm: "proc1", Dev: 42, DevName: "sda", TotalNs: 1000, Count: 50, Slots: slots},
		{PID: 2, Comm: "proc2", Dev: 42, DevName: "sda", TotalNs: 2000, Count: 50, Slots: slots},
	}
	res := aggregateByDevice(perPID)
	if len(res) != 1 {
		t.Fatalf("expected 1 device; got %d", len(res))
	}
	if res[0].TotalNs != 3000 {
		t.Errorf("TotalNs: %d, want 3000", res[0].TotalNs)
	}
	if res[0].Count != 100 {
		t.Errorf("Count: %d, want 100", res[0].Count)
	}
	// All counts in slot 2 → p50 = slot 2 midpoint = (4+8)/2 µs * 1000 = 6000ns
	if res[0].P50Ns != 6000 {
		t.Errorf("P50Ns: %d, want 6000", res[0].P50Ns)
	}
}

func TestAggregateByDevice_TwoDevices(t *testing.T) {
	// Two different devs — result should have two entries.
	slots := [16]uint32{}
	slots[0] = 10
	perPID := []IOLatResult{
		{PID: 1, Dev: 1, DevName: "sda", TotalNs: 100, Count: 10, Slots: slots},
		{PID: 2, Dev: 2, DevName: "sdb", TotalNs: 200, Count: 10, Slots: slots},
	}
	res := aggregateByDevice(perPID)
	if len(res) != 2 {
		t.Errorf("expected 2 devices; got %d", len(res))
	}
}

func TestAggregateByDevice_SkipsZeroCount(t *testing.T) {
	// IOLatResult with Count=0 should be excluded before aggregation
	// (the read() function already excludes them, but verify that a
	// zero-count result in the slice doesn't corrupt aggregation).
	slots := [16]uint32{}
	slots[1] = 20
	perPID := []IOLatResult{
		{PID: 1, Dev: 5, DevName: "nvme0", TotalNs: 500, Count: 20, Slots: slots},
	}
	res := aggregateByDevice(perPID)
	if len(res) != 1 {
		t.Fatalf("expected 1 device; got %d", len(res))
	}
	if res[0].Count != 20 {
		t.Errorf("Count: %d, want 20", res[0].Count)
	}
}
