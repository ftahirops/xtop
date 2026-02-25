//go:build 386 || amd64

package ebpf

import (
	"fmt"

	"github.com/cilium/ebpf/link"
)

type directreclaimProbe struct {
	objs  directreclaimObjects
	links []link.Link
}

// DirectReclaimResult holds direct reclaim stall data for one PID.
type DirectReclaimResult struct {
	PID     uint32
	StallNs uint64
	Count   uint32
}

func attachDirectReclaim() (*directreclaimProbe, error) {
	var objs directreclaimObjects
	if err := loadDirectreclaimObjects(&objs, nil); err != nil {
		return nil, fmt.Errorf("load directreclaim: %w", err)
	}

	l1, err := link.Tracepoint("vmscan", "mm_vmscan_direct_reclaim_begin", objs.HandleReclaimBegin, nil)
	if err != nil {
		objs.Close()
		return nil, fmt.Errorf("attach mm_vmscan_direct_reclaim_begin: %w", err)
	}

	l2, err := link.Tracepoint("vmscan", "mm_vmscan_direct_reclaim_end", objs.HandleReclaimEnd, nil)
	if err != nil {
		l1.Close()
		objs.Close()
		return nil, fmt.Errorf("attach mm_vmscan_direct_reclaim_end: %w", err)
	}

	return &directreclaimProbe{objs: objs, links: []link.Link{l1, l2}}, nil
}

func (p *directreclaimProbe) read() ([]DirectReclaimResult, error) {
	var results []DirectReclaimResult
	var pid uint32
	var val directreclaimReclaimVal

	iter := p.objs.ReclaimAccum.Iterate()
	for iter.Next(&pid, &val) {
		if val.Count == 0 {
			continue
		}
		results = append(results, DirectReclaimResult{
			PID:     pid,
			StallNs: val.StallNs,
			Count:   val.Count,
		})
	}
	if err := iter.Err(); err != nil {
		return results, fmt.Errorf("iterate reclaim_accum map: %w", err)
	}
	return results, nil
}

func (p *directreclaimProbe) close() {
	for _, l := range p.links {
		l.Close()
	}
	p.objs.Close()
}
