//go:build 386 || amd64

package ebpf

import (
	"fmt"

	"github.com/cilium/ebpf/link"
	"github.com/ftahirops/xtop/model"
)

type dnsmonProbe struct {
	objs  dnsmonObjects
	links []link.Link
}

func attachDNSMon() (*dnsmonProbe, error) {
	var objs dnsmonObjects
	if err := loadDnsmonObjects(&objs, nil); err != nil {
		return nil, fmt.Errorf("load dnsmon: %w", err)
	}

	l1, err := link.Kprobe("udp_sendmsg", objs.HandleUdpSendmsg, nil)
	if err != nil {
		objs.Close()
		return nil, fmt.Errorf("attach udp_sendmsg: %w", err)
	}

	l2, err := link.Kprobe("udp_recvmsg", objs.HandleUdpRecvmsg, nil)
	if err != nil {
		l1.Close()
		objs.Close()
		return nil, fmt.Errorf("attach udp_recvmsg: %w", err)
	}

	return &dnsmonProbe{objs: objs, links: []link.Link{l1, l2}}, nil
}

func (p *dnsmonProbe) read() ([]model.DNSAnomalyEntry, error) {
	var results []model.DNSAnomalyEntry
	var pid uint32
	var val dnsmonDnsVal

	iter := p.objs.DnsAccum.Iterate()
	for iter.Next(&pid, &val) {
		if val.QueryCount == 0 {
			continue
		}
		avgQueryLen := 0
		if val.QueryCount > 0 {
			avgQueryLen = int(val.TotalQueryBytes / val.QueryCount)
		}
		results = append(results, model.DNSAnomalyEntry{
			PID:            int(pid),
			Comm:           readComm(pid),
			QueryCount:     val.QueryCount,
			AvgQueryLen:    avgQueryLen,
			TotalRespBytes: val.TotalRespBytes,
		})
	}
	if err := iter.Err(); err != nil {
		return results, fmt.Errorf("iterate dns_accum map: %w", err)
	}
	return results, nil
}

func (p *dnsmonProbe) close() {
	for _, l := range p.links {
		l.Close()
	}
	p.objs.Close()
}
