//go:build 386 || amd64

package ebpf

import (
	"fmt"

	"github.com/cilium/ebpf/link"
)

type oomkillProbe struct {
	objs  oomkillObjects
	links []link.Link
}

// OOMKillResult holds an OOM kill event.
type OOMKillResult struct {
	VictimPID uint32
	Ts        uint64
	TotalVM   uint64
	AnonRSS   uint64
}

func attachOOMKill() (*oomkillProbe, error) {
	var objs oomkillObjects
	if err := loadOomkillObjects(&objs, nil); err != nil {
		return nil, fmt.Errorf("load oomkill: %w", err)
	}

	l, err := link.Tracepoint("oom", "mark_victim", objs.HandleMarkVictim, nil)
	if err != nil {
		objs.Close()
		return nil, fmt.Errorf("attach mark_victim: %w", err)
	}

	return &oomkillProbe{objs: objs, links: []link.Link{l}}, nil
}

func (p *oomkillProbe) read() ([]OOMKillResult, error) {
	var results []OOMKillResult
	var pid uint32
	var val oomkillOomVal

	iter := p.objs.OomAccum.Iterate()
	for iter.Next(&pid, &val) {
		results = append(results, OOMKillResult{
			VictimPID: pid,
			Ts:        val.Ts,
			TotalVM:   val.TotalVm,
			AnonRSS:   val.AnonRss,
		})
	}
	if err := iter.Err(); err != nil {
		return results, fmt.Errorf("iterate oom_accum map: %w", err)
	}
	return results, nil
}

// readAndClear reads OOM events and deletes them from the map (event-like).
func (p *oomkillProbe) readAndClear() ([]OOMKillResult, error) {
	results, err := p.read()
	if err != nil {
		return results, err
	}
	for _, r := range results {
		pid := r.VictimPID
		_ = p.objs.OomAccum.Delete(&pid)
	}
	return results, nil
}

func (p *oomkillProbe) close() {
	for _, l := range p.links {
		l.Close()
	}
	p.objs.Close()
}
