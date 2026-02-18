//go:build 386 || amd64

package ebpf

import (
	"fmt"

	"github.com/cilium/ebpf/link"
)

type tcpretransProbe struct {
	objs  tcpretransObjects
	links []link.Link
}

// TCPRetransResult holds raw TCP retransmit data for one process.
type TCPRetransResult struct {
	PID       uint32
	Comm      string
	Count     uint32
	LastSport uint16
	LastDport uint16
	LastDaddr uint32
	DstStr    string // formatted "ip:port"
}

func attachTCPRetrans() (*tcpretransProbe, error) {
	var objs tcpretransObjects
	if err := loadTcpretransObjects(&objs, nil); err != nil {
		return nil, fmt.Errorf("load tcpretrans: %w", err)
	}

	l, err := link.Tracepoint("tcp", "tcp_retransmit_skb", objs.HandleTcpRetransmit, nil)
	if err != nil {
		objs.Close()
		return nil, fmt.Errorf("attach tcp_retransmit_skb: %w", err)
	}

	return &tcpretransProbe{objs: objs, links: []link.Link{l}}, nil
}

func (p *tcpretransProbe) read() ([]TCPRetransResult, error) {
	var results []TCPRetransResult
	var pid uint32
	var val tcpretransRetransVal

	iter := p.objs.RetransAccum.Iterate()
	for iter.Next(&pid, &val) {
		if val.Count == 0 {
			continue
		}
		results = append(results, TCPRetransResult{
			PID:       pid,
			Comm:      readComm(pid),
			Count:     val.Count,
			LastSport: val.LastSport,
			LastDport: val.LastDport,
			LastDaddr: val.LastDaddr,
			DstStr:    formatIPv4Port(val.LastDaddr, val.LastDport),
		})
	}
	if err := iter.Err(); err != nil {
		return results, fmt.Errorf("iterate retrans map: %w", err)
	}
	return results, nil
}

func (p *tcpretransProbe) close() {
	for _, l := range p.links {
		l.Close()
	}
	p.objs.Close()
}

// formatIPv4Port formats a BPF-captured IPv4 address and port as "a.b.c.d:port".
// The address bytes are stored in memory order from bpf_probe_read_kernel of __u8[4],
// which on x86 little-endian means byte[0] is the lowest byte of the uint32.
// Network byte order: byte[0]=MSB of IP. After read into uint32 LE: byte[0]=LSB.
// So addr&0xff = first octet of the IP address.
func formatIPv4Port(addr uint32, port uint16) string {
	return fmt.Sprintf("%d.%d.%d.%d:%d",
		addr&0xff, (addr>>8)&0xff, (addr>>16)&0xff, (addr>>24)&0xff, port)
}
