//go:build 386 || amd64

package ebpf

import (
	"fmt"
	"os"
	"strings"

	"github.com/cilium/ebpf/link"
)

type iolatencyProbe struct {
	objs  iolatencyObjects
	links []link.Link
}

// IOLatResult holds raw IO latency data for one PID.
type IOLatResult struct {
	PID     uint32
	Comm    string
	Dev     uint32
	DevName string
	TotalNs uint64
	MaxNs   uint64
	Count   uint32
	Slots   [16]uint32
}

// IOLatDeviceResult holds aggregated IO latency per device.
type IOLatDeviceResult struct {
	DevName string
	P50Ns   uint64
	P95Ns   uint64
	P99Ns   uint64
	TotalNs uint64
	Count   uint32
}

func attachIOLatency() (*iolatencyProbe, error) {
	var objs iolatencyObjects
	if err := loadIolatencyObjects(&objs, nil); err != nil {
		return nil, fmt.Errorf("load iolatency: %w", err)
	}

	l1, err := link.Tracepoint("block", "block_rq_issue", objs.HandleBlockRqIssue, nil)
	if err != nil {
		objs.Close()
		return nil, fmt.Errorf("attach block_rq_issue: %w", err)
	}

	l2, err := link.Tracepoint("block", "block_rq_complete", objs.HandleBlockRqComplete, nil)
	if err != nil {
		l1.Close()
		objs.Close()
		return nil, fmt.Errorf("attach block_rq_complete: %w", err)
	}

	return &iolatencyProbe{objs: objs, links: []link.Link{l1, l2}}, nil
}

func (p *iolatencyProbe) read() ([]IOLatResult, error) {
	var results []IOLatResult
	var pid uint32
	var val iolatencyIolatVal

	iter := p.objs.IolatHist.Iterate()
	for iter.Next(&pid, &val) {
		if val.Count == 0 {
			continue
		}
		results = append(results, IOLatResult{
			PID:     pid,
			Comm:    readComm(pid),
			Dev:     val.Dev,
			DevName: devName(val.Dev),
			TotalNs: val.TotalNs,
			MaxNs:   val.MaxNs,
			Count:   val.Count,
			Slots:   val.Slots,
		})
	}
	if err := iter.Err(); err != nil {
		return results, fmt.Errorf("iterate iolat map: %w", err)
	}
	return results, nil
}

// aggregateByDevice groups per-PID IO data into per-device results.
func aggregateByDevice(perPID []IOLatResult) []IOLatDeviceResult {
	type devAgg struct {
		name    string
		totalNs uint64
		count   uint32
		slots   [16]uint64
	}
	byDev := make(map[uint32]*devAgg)

	for _, r := range perPID {
		a, ok := byDev[r.Dev]
		if !ok {
			a = &devAgg{name: r.DevName}
			byDev[r.Dev] = a
		}
		a.totalNs += r.TotalNs
		a.count += r.Count
		for i, s := range r.Slots {
			a.slots[i] += uint64(s)
		}
	}

	var results []IOLatDeviceResult
	for _, a := range byDev {
		p50, p95, p99 := percentilesFromSlots64(a.slots[:], uint64(a.count))
		results = append(results, IOLatDeviceResult{
			DevName: a.name,
			P50Ns:   p50,
			P95Ns:   p95,
			P99Ns:   p99,
			TotalNs: a.totalNs,
			Count:   a.count,
		})
	}
	return results
}

func (p *iolatencyProbe) close() {
	for _, l := range p.links {
		l.Close()
	}
	p.objs.Close()
}

// percentilesFromSlots64 computes p50, p95, p99 from a log2 histogram.
// Slot i covers latencies in the range [2^i, 2^(i+1)) microseconds.
func percentilesFromSlots64(slots []uint64, total uint64) (p50, p95, p99 uint64) {
	if total == 0 {
		return 0, 0, 0
	}
	targets := [3]uint64{
		(total + 1) / 2,  // p50
		total*95/100 + 1, // p95
		total*99/100 + 1, // p99
	}
	var results [3]uint64
	var cumul uint64
	found := 0
	for i, count := range slots {
		cumul += count
		for found < 3 && cumul >= targets[found] {
			// Midpoint of bucket [2^i, 2^(i+1)) in microseconds, then convert to ns
			lo := uint64(1) << uint(i)
			hi := lo << 1
			results[found] = (lo + hi) / 2 * 1000 // us → ns
			found++
		}
		if found >= 3 {
			break
		}
	}
	return results[0], results[1], results[2]
}

// devName converts a kernel MKDEV-format dev_t to a human-readable name.
func devName(dev uint32) string {
	if dev == 0 {
		return "unknown"
	}
	// Kernel internal MKDEV: MAJOR = dev >> 20, MINOR = dev & 0xfffff
	major := dev >> 20
	minor := dev & 0xfffff

	// Try dm name
	data, err := os.ReadFile(fmt.Sprintf("/sys/dev/block/%d:%d/dm/name", major, minor))
	if err == nil {
		return "dm-" + strings.TrimSpace(string(data))
	}
	// Try uevent for DEVNAME
	data, err = os.ReadFile(fmt.Sprintf("/sys/dev/block/%d:%d/uevent", major, minor))
	if err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			if strings.HasPrefix(line, "DEVNAME=") {
				return strings.TrimPrefix(line, "DEVNAME=")
			}
		}
	}
	return fmt.Sprintf("%d:%d", major, minor)
}
