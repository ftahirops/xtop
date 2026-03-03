//go:build 386 || amd64

package ebpf

import (
	"fmt"
	"net"

	ciliumebpf "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/ftahirops/xtop/model"
)

type tlsfingerProbe struct {
	objs  tlsfingerObjects
	links []link.Link
}

// knownJA3 maps FNV-1a hash strings to known tool/client names.
// Populated at runtime; starts empty.
var knownJA3 = map[string]string{}

// attachTLSFinger attaches the TC ingress classifier for TLS JA3 fingerprinting.
// ifaceName is the network interface to attach to (e.g. "eth0").
func attachTLSFinger(ifaceName string) (*tlsfingerProbe, error) {
	var objs tlsfingerObjects
	if err := loadTlsfingerObjects(&objs, nil); err != nil {
		return nil, fmt.Errorf("load tlsfinger: %w", err)
	}

	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		objs.Close()
		return nil, fmt.Errorf("lookup interface %s: %w", ifaceName, err)
	}

	l, err := link.AttachTCX(link.TCXOptions{
		Interface: iface.Index,
		Program:   objs.HandleTlsfinger,
		Attach:    ciliumebpf.AttachTCXIngress,
	})
	if err != nil {
		objs.Close()
		return nil, fmt.Errorf("attach tcx ingress on %s: %w", ifaceName, err)
	}

	return &tlsfingerProbe{objs: objs, links: []link.Link{l}}, nil
}

func (p *tlsfingerProbe) read() ([]model.JA3Entry, error) {
	var results []model.JA3Entry
	var hash uint32
	var val tlsfingerJa3Val

	iter := p.objs.Ja3Accum.Iterate()
	for iter.Next(&hash, &val) {
		if val.Count == 0 {
			continue
		}
		hashStr := fmt.Sprintf("%08x", hash)
		known := knownJA3[hashStr]
		results = append(results, model.JA3Entry{
			Hash:      hashStr,
			Count:     val.Count,
			SampleSrc: formatIPv4(val.SampleSaddr),
			SampleDst: formatIPv4(val.SampleDaddr),
			Known:     known,
		})
	}
	if err := iter.Err(); err != nil {
		return results, fmt.Errorf("iterate ja3_accum map: %w", err)
	}
	return results, nil
}

func (p *tlsfingerProbe) close() {
	for _, l := range p.links {
		l.Close()
	}
	p.objs.Close()
}
