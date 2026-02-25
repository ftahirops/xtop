//go:build 386 || amd64

package ebpf

import (
	"fmt"

	"github.com/cilium/ebpf/link"
)

type runqlatProbe struct {
	objs  runqlatObjects
	links []link.Link
}

// RunQLatResult holds run queue latency data for one PID.
type RunQLatResult struct {
	PID     uint32
	Comm    string
	TotalNs uint64
	Count   uint32
	MaxNs   uint32
}

func attachRunQLat() (*runqlatProbe, error) {
	var objs runqlatObjects
	if err := loadRunqlatObjects(&objs, nil); err != nil {
		return nil, fmt.Errorf("load runqlat: %w", err)
	}

	l1, err := link.Tracepoint("sched", "sched_wakeup", objs.HandleSchedWakeup, nil)
	if err != nil {
		objs.Close()
		return nil, fmt.Errorf("attach sched_wakeup: %w", err)
	}

	l2, err := link.AttachRawTracepoint(link.RawTracepointOptions{
		Name:    "sched_switch",
		Program: objs.HandleSchedSwitchRqlat,
	})
	if err != nil {
		l1.Close()
		objs.Close()
		return nil, fmt.Errorf("attach sched_switch (runqlat): %w", err)
	}

	return &runqlatProbe{objs: objs, links: []link.Link{l1, l2}}, nil
}

func (p *runqlatProbe) read() ([]RunQLatResult, error) {
	var results []RunQLatResult
	var pid uint32
	var val runqlatRqlatVal

	iter := p.objs.RqlatAccum.Iterate()
	for iter.Next(&pid, &val) {
		if val.Count == 0 {
			continue
		}
		results = append(results, RunQLatResult{
			PID:     pid,
			Comm:    readComm(pid),
			TotalNs: val.TotalNs,
			Count:   val.Count,
			MaxNs:   val.MaxNs,
		})
	}
	if err := iter.Err(); err != nil {
		return results, fmt.Errorf("iterate rqlat_accum map: %w", err)
	}
	return results, nil
}

func (p *runqlatProbe) close() {
	for _, l := range p.links {
		l.Close()
	}
	p.objs.Close()
}
