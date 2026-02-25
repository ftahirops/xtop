//go:build 386 || amd64

package ebpf

import (
	"fmt"

	"github.com/cilium/ebpf/link"
)

type wbstallProbe struct {
	objs  wbstallObjects
	links []link.Link
}

// WBStallResult holds writeback wait data for one PID.
type WBStallResult struct {
	PID        uint32
	Count      uint64
	TotalPages uint64
}

func attachWBStall() (*wbstallProbe, error) {
	var objs wbstallObjects
	if err := loadWbstallObjects(&objs, nil); err != nil {
		return nil, fmt.Errorf("load wbstall: %w", err)
	}

	l, err := link.Tracepoint("writeback", "writeback_wait", objs.HandleWritebackWait, nil)
	if err != nil {
		objs.Close()
		return nil, fmt.Errorf("attach writeback_wait: %w", err)
	}

	return &wbstallProbe{objs: objs, links: []link.Link{l}}, nil
}

func (p *wbstallProbe) read() ([]WBStallResult, error) {
	var results []WBStallResult
	var pid uint32
	var val wbstallWbVal

	iter := p.objs.WbAccum.Iterate()
	for iter.Next(&pid, &val) {
		if val.Count == 0 {
			continue
		}
		results = append(results, WBStallResult{
			PID:        pid,
			Count:      val.Count,
			TotalPages: val.TotalPages,
		})
	}
	if err := iter.Err(); err != nil {
		return results, fmt.Errorf("iterate wb_accum map: %w", err)
	}
	return results, nil
}

func (p *wbstallProbe) close() {
	for _, l := range p.links {
		l.Close()
	}
	p.objs.Close()
}
