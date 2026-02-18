//go:build 386 || amd64

package ebpf

import (
	"fmt"
	"os"
	"strings"

	"github.com/cilium/ebpf/link"
)

type offcpuProbe struct {
	objs  offcpuObjects
	links []link.Link
}

// OffCPUResult holds raw off-CPU data for one process.
type OffCPUResult struct {
	PID     uint32
	Comm    string
	TotalNs uint64
	Count   uint32
	Reason  string
}

func attachOffCPU() (*offcpuProbe, error) {
	var objs offcpuObjects
	if err := loadOffcpuObjects(&objs, nil); err != nil {
		return nil, fmt.Errorf("load offcpu: %w", err)
	}

	l, err := link.AttachRawTracepoint(link.RawTracepointOptions{
		Name:    "sched_switch",
		Program: objs.HandleSchedSwitch,
	})
	if err != nil {
		objs.Close()
		return nil, fmt.Errorf("attach sched_switch: %w", err)
	}

	return &offcpuProbe{objs: objs, links: []link.Link{l}}, nil
}

func (p *offcpuProbe) read() ([]OffCPUResult, error) {
	var results []OffCPUResult
	var pid uint32
	var val offcpuOffcpuVal

	iter := p.objs.OffcpuAccum.Iterate()
	for iter.Next(&pid, &val) {
		if val.TotalNs == 0 {
			continue
		}
		results = append(results, OffCPUResult{
			PID:     pid,
			Comm:    readComm(pid),
			TotalNs: val.TotalNs,
			Count:   val.Count,
			Reason:  readWchan(pid),
		})
	}
	if err := iter.Err(); err != nil {
		return results, fmt.Errorf("iterate offcpu map: %w", err)
	}
	return results, nil
}

func (p *offcpuProbe) close() {
	for _, l := range p.links {
		l.Close()
	}
	p.objs.Close()
}

// readComm reads /proc/PID/comm for a process name.
func readComm(pid uint32) string {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid))
	if err != nil {
		return fmt.Sprintf("pid_%d", pid)
	}
	return strings.TrimSpace(string(data))
}

// readWchan reads /proc/PID/wchan for the wait channel classification.
func readWchan(pid uint32) string {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/wchan", pid))
	if err != nil {
		return "unknown"
	}
	wchan := strings.TrimSpace(string(data))
	if wchan == "" || wchan == "0" {
		return "running"
	}
	switch {
	case strings.Contains(wchan, "futex"):
		return "futex lock"
	case strings.Contains(wchan, "epoll"):
		return "epoll wait"
	case strings.Contains(wchan, "poll"):
		return "poll wait"
	case strings.Contains(wchan, "sleep"), strings.Contains(wchan, "hrtimer"):
		return "nanosleep"
	case strings.Contains(wchan, "io"), strings.Contains(wchan, "blk"):
		return "disk io"
	case strings.Contains(wchan, "pipe"):
		return "pipe wait"
	case strings.Contains(wchan, "socket"), strings.Contains(wchan, "tcp"), strings.Contains(wchan, "inet"):
		return "network"
	case strings.Contains(wchan, "wait"):
		return "wait"
	default:
		return wchan
	}
}
