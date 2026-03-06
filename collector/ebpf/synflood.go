//go:build 386 || amd64

package ebpf

import (
	"fmt"

	"github.com/cilium/ebpf/link"
	"github.com/ftahirops/xtop/model"
)

type synfloodProbe struct {
	objs  synfloodObjects
	links []link.Link
}

func attachSynFlood() (*synfloodProbe, error) {
	var objs synfloodObjects
	if err := loadSynfloodObjects(&objs, nil); err != nil {
		return nil, fmt.Errorf("load synflood: %w", err)
	}

	l1, err := link.Kprobe("tcp_conn_request", objs.HandleTcpConnRequest, nil)
	if err != nil {
		objs.Close()
		return nil, fmt.Errorf("attach tcp_conn_request: %w", err)
	}

	l2, err := link.Kprobe("tcp_retransmit_synack", objs.HandleTcpRetransmitSynack, nil)
	if err != nil {
		l1.Close()
		objs.Close()
		return nil, fmt.Errorf("attach tcp_retransmit_synack: %w", err)
	}

	return &synfloodProbe{objs: objs, links: []link.Link{l1, l2}}, nil
}

func (p *synfloodProbe) read() ([]model.SynFloodEntry, error) {
	var results []model.SynFloodEntry
	var srcIP uint32
	var val synfloodSynVal

	iter := p.objs.SynAccum.Iterate()
	for iter.Next(&srcIP, &val) {
		if val.SynCount == 0 && val.SynackRetrans == 0 {
			continue
		}
		// Skip loopback (127.0.0.0/8) — not a real SYN flood source
		if isLoopback(srcIP) {
			continue
		}
		var ratio float64
		if val.SynCount > 0 {
			ratio = float64(val.SynackRetrans) / float64(val.SynCount)
		}
		results = append(results, model.SynFloodEntry{
			SrcIP:         formatIPv4(srcIP),
			SynCount:      val.SynCount,
			SynAckRetrans: val.SynackRetrans,
			HalfOpenRatio: ratio,
		})
	}
	if err := iter.Err(); err != nil {
		return results, fmt.Errorf("iterate syn_accum map: %w", err)
	}
	return results, nil
}

func (p *synfloodProbe) close() {
	for _, l := range p.links {
		l.Close()
	}
	p.objs.Close()
}
