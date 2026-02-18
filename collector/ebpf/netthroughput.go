//go:build 386 || amd64

package ebpf

import (
	"fmt"

	"github.com/cilium/ebpf/link"
)

type netthroughputProbe struct {
	objs  netthroughputObjects
	links []link.Link
}

// NetThroughputResult holds per-PID TCP send/receive data.
type NetThroughputResult struct {
	PID     uint32
	Comm    string
	TxBytes uint64
	RxBytes uint64
}

func attachNetThroughput() (*netthroughputProbe, error) {
	var objs netthroughputObjects
	if err := loadNetthroughputObjects(&objs, nil); err != nil {
		return nil, fmt.Errorf("load netthroughput: %w", err)
	}

	l1, err := link.Kprobe("tcp_sendmsg", objs.HandleTcpSendmsg, nil)
	if err != nil {
		objs.Close()
		return nil, fmt.Errorf("attach tcp_sendmsg: %w", err)
	}

	l2, err := link.Kprobe("tcp_cleanup_rbuf", objs.HandleTcpCleanupRbuf, nil)
	if err != nil {
		l1.Close()
		objs.Close()
		return nil, fmt.Errorf("attach tcp_cleanup_rbuf: %w", err)
	}

	return &netthroughputProbe{objs: objs, links: []link.Link{l1, l2}}, nil
}

func (p *netthroughputProbe) read() ([]NetThroughputResult, error) {
	var results []NetThroughputResult
	var pid uint32
	var val netthroughputNetVal

	iter := p.objs.NetAccum.Iterate()
	for iter.Next(&pid, &val) {
		if val.TxBytes == 0 && val.RxBytes == 0 {
			continue
		}
		results = append(results, NetThroughputResult{
			PID:     pid,
			Comm:    readComm(pid),
			TxBytes: val.TxBytes,
			RxBytes: val.RxBytes,
		})
	}
	if err := iter.Err(); err != nil {
		return results, fmt.Errorf("iterate net_accum map: %w", err)
	}
	return results, nil
}

func (p *netthroughputProbe) close() {
	for _, l := range p.links {
		l.Close()
	}
	p.objs.Close()
}
