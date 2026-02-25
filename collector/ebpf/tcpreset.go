//go:build 386 || amd64

package ebpf

import (
	"fmt"

	"github.com/cilium/ebpf/link"
)

type tcpresetProbe struct {
	objs  tcpresetObjects
	links []link.Link
}

// TCPResetResult holds TCP RST event data for one PID.
type TCPResetResult struct {
	PID       uint32
	Comm      string
	Count     uint64
	LastDaddr uint32
	LastDport uint16
	DstStr    string
}

func attachTCPReset() (*tcpresetProbe, error) {
	var objs tcpresetObjects
	if err := loadTcpresetObjects(&objs, nil); err != nil {
		return nil, fmt.Errorf("load tcpreset: %w", err)
	}

	l, err := link.Kprobe("tcp_send_reset", objs.HandleTcpSendReset, nil)
	if err != nil {
		objs.Close()
		return nil, fmt.Errorf("attach tcp_send_reset: %w", err)
	}

	return &tcpresetProbe{objs: objs, links: []link.Link{l}}, nil
}

func (p *tcpresetProbe) read() ([]TCPResetResult, error) {
	var results []TCPResetResult
	var pid uint32
	var val tcpresetResetVal

	iter := p.objs.ResetAccum.Iterate()
	for iter.Next(&pid, &val) {
		if val.Count == 0 {
			continue
		}
		results = append(results, TCPResetResult{
			PID:       pid,
			Comm:      readComm(pid),
			Count:     val.Count,
			LastDaddr: val.LastDaddr,
			LastDport: val.LastDport,
			DstStr:    formatIPv4Port(val.LastDaddr, val.LastDport),
		})
	}
	if err := iter.Err(); err != nil {
		return results, fmt.Errorf("iterate reset_accum map: %w", err)
	}
	return results, nil
}

func (p *tcpresetProbe) close() {
	for _, l := range p.links {
		l.Close()
	}
	p.objs.Close()
}
