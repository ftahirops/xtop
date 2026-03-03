//go:build 386 || amd64

package ebpf

import (
	"fmt"
	"net"

	ciliumebpf "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/ftahirops/xtop/model"
)

type tcpflagsProbe struct {
	objs  tcpflagsObjects
	links []link.Link
}

// attachTCPFlags attaches the TC ingress classifier for anomalous TCP flag detection.
// ifaceName is the network interface to attach to (e.g. "eth0").
func attachTCPFlags(ifaceName string) (*tcpflagsProbe, error) {
	var objs tcpflagsObjects
	if err := loadTcpflagsObjects(&objs, nil); err != nil {
		return nil, fmt.Errorf("load tcpflags: %w", err)
	}

	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		objs.Close()
		return nil, fmt.Errorf("lookup interface %s: %w", ifaceName, err)
	}

	l, err := link.AttachTCX(link.TCXOptions{
		Interface: iface.Index,
		Program:   objs.HandleTcpflags,
		Attach:    ciliumebpf.AttachTCXIngress,
	})
	if err != nil {
		objs.Close()
		return nil, fmt.Errorf("attach tcx ingress on %s: %w", ifaceName, err)
	}

	return &tcpflagsProbe{objs: objs, links: []link.Link{l}}, nil
}

func (p *tcpflagsProbe) read() ([]model.TCPFlagAnomaly, error) {
	var results []model.TCPFlagAnomaly
	var key tcpflagsFlagsKey
	var val tcpflagsFlagsVal

	iter := p.objs.FlagsAccum.Iterate()
	for iter.Next(&key, &val) {
		if val.Count == 0 {
			continue
		}
		results = append(results, model.TCPFlagAnomaly{
			SrcIP:     formatIPv4(key.Saddr),
			FlagCombo: flagName(key.Flags),
			Count:     val.Count,
		})
	}
	if err := iter.Err(); err != nil {
		return results, fmt.Errorf("iterate flags_accum map: %w", err)
	}
	return results, nil
}

func (p *tcpflagsProbe) close() {
	for _, l := range p.links {
		l.Close()
	}
	p.objs.Close()
}

// flagName returns a human-readable name for TCP flag combinations.
func flagName(flags uint8) string {
	switch {
	case flags == 0x00:
		return "NULL"
	case flags&0x29 == 0x29: // FIN+PSH+URG
		return "XMAS"
	case flags&0x03 == 0x03: // SYN+FIN
		return "SYN+FIN"
	case flags&0x01 != 0 && flags&0x10 == 0: // FIN without ACK
		return "FIN-no-ACK"
	default:
		return fmt.Sprintf("0x%02x", flags)
	}
}
