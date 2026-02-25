//go:build 386 || amd64

package ebpf

import (
	"fmt"

	"github.com/cilium/ebpf/link"
)

type swapevictProbe struct {
	objs  swapevictObjects
	links []link.Link
}

// SwapEvictResult holds swap IO data for one PID.
type SwapEvictResult struct {
	PID        uint32
	ReadPages  uint64
	WritePages uint64
}

func attachSwapEvict() (*swapevictProbe, error) {
	var objs swapevictObjects
	if err := loadSwapevictObjects(&objs, nil); err != nil {
		return nil, fmt.Errorf("load swapevict: %w", err)
	}

	l1, err := link.Kprobe("swap_readpage", objs.HandleSwapReadpage, nil)
	if err != nil {
		objs.Close()
		return nil, fmt.Errorf("attach swap_readpage: %w", err)
	}

	l2, err := link.Kprobe("swap_writepage", objs.HandleSwapWritepage, nil)
	if err != nil {
		l1.Close()
		objs.Close()
		return nil, fmt.Errorf("attach swap_writepage: %w", err)
	}

	return &swapevictProbe{objs: objs, links: []link.Link{l1, l2}}, nil
}

func (p *swapevictProbe) read() ([]SwapEvictResult, error) {
	var results []SwapEvictResult
	var pid uint32
	var val swapevictSwapVal

	iter := p.objs.SwapAccum.Iterate()
	for iter.Next(&pid, &val) {
		if val.ReadPages == 0 && val.WritePages == 0 {
			continue
		}
		results = append(results, SwapEvictResult{
			PID:        pid,
			ReadPages:  val.ReadPages,
			WritePages: val.WritePages,
		})
	}
	if err := iter.Err(); err != nil {
		return results, fmt.Errorf("iterate swap_accum map: %w", err)
	}
	return results, nil
}

func (p *swapevictProbe) close() {
	for _, l := range p.links {
		l.Close()
	}
	p.objs.Close()
}
