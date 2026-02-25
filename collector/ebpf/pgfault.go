//go:build 386 || amd64

package ebpf

import (
	"fmt"

	"github.com/cilium/ebpf/link"
)

type pgfaultProbe struct {
	objs  pgfaultObjects
	links []link.Link
}

// PgFaultResult holds page fault latency data for one PID.
type PgFaultResult struct {
	PID        uint32
	TotalNs    uint64
	Count      uint32
	MajorCount uint32
}

func attachPgFault() (*pgfaultProbe, error) {
	var objs pgfaultObjects
	if err := loadPgfaultObjects(&objs, nil); err != nil {
		return nil, fmt.Errorf("load pgfault: %w", err)
	}

	l1, err := link.Kprobe("handle_mm_fault", objs.HandleFaultEnter, nil)
	if err != nil {
		objs.Close()
		return nil, fmt.Errorf("attach handle_mm_fault: %w", err)
	}

	l2, err := link.Kretprobe("handle_mm_fault", objs.HandleFaultExit, nil)
	if err != nil {
		l1.Close()
		objs.Close()
		return nil, fmt.Errorf("attach handle_mm_fault kretprobe: %w", err)
	}

	return &pgfaultProbe{objs: objs, links: []link.Link{l1, l2}}, nil
}

func (p *pgfaultProbe) read() ([]PgFaultResult, error) {
	var results []PgFaultResult
	var pid uint32
	var val pgfaultPgfaultVal

	iter := p.objs.PgfaultAccum.Iterate()
	for iter.Next(&pid, &val) {
		if val.Count == 0 {
			continue
		}
		results = append(results, PgFaultResult{
			PID:        pid,
			TotalNs:    val.TotalNs,
			Count:      val.Count,
			MajorCount: val.MajorCount,
		})
	}
	if err := iter.Err(); err != nil {
		return results, fmt.Errorf("iterate pgfault_accum map: %w", err)
	}
	return results, nil
}

func (p *pgfaultProbe) close() {
	for _, l := range p.links {
		l.Close()
	}
	p.objs.Close()
}
