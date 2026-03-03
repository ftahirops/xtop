//go:build 386 || amd64

package ebpf

import (
	"fmt"
	"net"

	ciliumebpf "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/ftahirops/xtop/model"
)

type dnsdeepProbe struct {
	objs  dnsdeepObjects
	links []link.Link
}

// attachDNSDeep attaches the TC ingress classifier for deep DNS payload inspection.
// ifaceName is the network interface to attach to (e.g. "eth0").
func attachDNSDeep(ifaceName string) (*dnsdeepProbe, error) {
	var objs dnsdeepObjects
	if err := loadDnsdeepObjects(&objs, nil); err != nil {
		return nil, fmt.Errorf("load dnsdeep: %w", err)
	}

	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		objs.Close()
		return nil, fmt.Errorf("lookup interface %s: %w", ifaceName, err)
	}

	l, err := link.AttachTCX(link.TCXOptions{
		Interface: iface.Index,
		Program:   objs.HandleDnsdeep,
		Attach:    ciliumebpf.AttachTCXIngress,
	})
	if err != nil {
		objs.Close()
		return nil, fmt.Errorf("attach tcx ingress on %s: %w", ifaceName, err)
	}

	return &dnsdeepProbe{objs: objs, links: []link.Link{l}}, nil
}

func (p *dnsdeepProbe) read() ([]model.DNSTunnelIndicator, error) {
	var results []model.DNSTunnelIndicator
	var saddr uint32
	var val dnsdeepDnsDeepVal

	iter := p.objs.DnsDeep.Iterate()
	for iter.Next(&saddr, &val) {
		if val.TotalQueries == 0 {
			continue
		}
		var txtRatio float64
		if val.TotalQueries > 0 {
			txtRatio = float64(val.TxtQueries) / float64(val.TotalQueries)
		}
		avgQueryLen := 0
		if val.TotalQueries > 0 {
			avgQueryLen = int(val.TotalQueryBytes / val.TotalQueries)
		}
		results = append(results, model.DNSTunnelIndicator{
			DomainHash:  formatIPv4(saddr), // keyed by source IP in this probe
			TXTRatio:    txtRatio,
			AvgQueryLen: avgQueryLen,
		})
	}
	if err := iter.Err(); err != nil {
		return results, fmt.Errorf("iterate dns_deep map: %w", err)
	}
	return results, nil
}

func (p *dnsdeepProbe) close() {
	for _, l := range p.links {
		l.Close()
	}
	p.objs.Close()
}
