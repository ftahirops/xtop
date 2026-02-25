//go:build 386 || amd64

package ebpf

import (
	"fmt"

	"github.com/cilium/ebpf/link"
)

type cgthrottleProbe struct {
	objs  cgthrottleObjects
	links []link.Link
}

// CgThrottleResult holds cgroup CPU throttle event data.
type CgThrottleResult struct {
	CgID  uint64
	Count uint64
}

func attachCgThrottle() (*cgthrottleProbe, error) {
	var objs cgthrottleObjects
	if err := loadCgthrottleObjects(&objs, nil); err != nil {
		return nil, fmt.Errorf("load cgthrottle: %w", err)
	}

	l, err := link.Kprobe("throttle_cfs_rq", objs.HandleThrottleCfsRq, nil)
	if err != nil {
		objs.Close()
		return nil, fmt.Errorf("attach throttle_cfs_rq: %w", err)
	}

	return &cgthrottleProbe{objs: objs, links: []link.Link{l}}, nil
}

func (p *cgthrottleProbe) read() ([]CgThrottleResult, error) {
	var results []CgThrottleResult
	var cgid uint64
	var val cgthrottleThrottleVal

	iter := p.objs.ThrottleAccum.Iterate()
	for iter.Next(&cgid, &val) {
		if val.Count == 0 {
			continue
		}
		results = append(results, CgThrottleResult{
			CgID:  cgid,
			Count: val.Count,
		})
	}
	if err := iter.Err(); err != nil {
		return results, fmt.Errorf("iterate throttle_accum map: %w", err)
	}
	return results, nil
}

func (p *cgthrottleProbe) close() {
	for _, l := range p.links {
		l.Close()
	}
	p.objs.Close()
}
