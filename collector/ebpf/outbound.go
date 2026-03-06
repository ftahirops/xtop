//go:build 386 || amd64

package ebpf

import (
	"fmt"
	"sort"

	"github.com/cilium/ebpf/link"
	"github.com/ftahirops/xtop/model"
)

type outboundProbe struct {
	objs  outboundObjects
	links []link.Link
}

func attachOutbound() (*outboundProbe, error) {
	var objs outboundObjects
	if err := loadOutboundObjects(&objs, nil); err != nil {
		return nil, fmt.Errorf("load outbound: %w", err)
	}

	l, err := link.Kprobe("tcp_sendmsg", objs.HandleTcpSendmsgEgress, nil)
	if err != nil {
		objs.Close()
		return nil, fmt.Errorf("attach tcp_sendmsg: %w", err)
	}

	return &outboundProbe{objs: objs, links: []link.Link{l}}, nil
}

func (p *outboundProbe) read() ([]model.OutboundEntry, error) {
	var results []model.OutboundEntry
	var key outboundEgressKey
	var val outboundEgressVal

	iter := p.objs.EgressAccum.Iterate()
	for iter.Next(&key, &val) {
		if val.TotalBytes == 0 {
			continue
		}
		// Skip loopback destinations (127.0.0.0/8) — not exfiltration
		if isLoopback(key.Daddr) {
			continue
		}
		results = append(results, model.OutboundEntry{
			PID:         int(key.Pid),
			Comm:        readComm(key.Pid),
			DstIP:       formatIPv4(key.Daddr),
			TotalBytes:  val.TotalBytes,
			PacketCount: val.PacketCount,
		})
	}
	if err := iter.Err(); err != nil {
		return results, fmt.Errorf("iterate egress_accum map: %w", err)
	}

	// Sort by TotalBytes descending and keep top 20
	sort.Slice(results, func(i, j int) bool {
		return results[i].TotalBytes > results[j].TotalBytes
	})
	if len(results) > 20 {
		results = results[:20]
	}

	return results, nil
}

func (p *outboundProbe) close() {
	for _, l := range p.links {
		l.Close()
	}
	p.objs.Close()
}
