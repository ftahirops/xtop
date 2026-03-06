//go:build 386 || amd64

package ebpf

import (
	"fmt"

	"github.com/cilium/ebpf/link"
)

type tcpconnlatProbe struct {
	objs  tcpconnlatObjects
	links []link.Link
}

// TCPConnLatResult holds TCP connect latency data for one process.
type TCPConnLatResult struct {
	PID     uint32
	Comm    string
	TotalNs uint64
	Count   uint32
	MaxNs   uint32
	DstAddr uint32
	DstStr  string // formatted IP
}

func attachTCPConnLat() (*tcpconnlatProbe, error) {
	var objs tcpconnlatObjects
	if err := loadTcpconnlatObjects(&objs, nil); err != nil {
		return nil, fmt.Errorf("load tcpconnlat: %w", err)
	}

	l1, err := link.Kprobe("tcp_v4_connect", objs.HandleTcpV4Connect, nil)
	if err != nil {
		objs.Close()
		return nil, fmt.Errorf("attach tcp_v4_connect: %w", err)
	}

	l2, err := link.Tracepoint("sock", "inet_sock_set_state", objs.HandleSetState, nil)
	if err != nil {
		l1.Close()
		objs.Close()
		return nil, fmt.Errorf("attach inet_sock_set_state: %w", err)
	}

	return &tcpconnlatProbe{objs: objs, links: []link.Link{l1, l2}}, nil
}

func (p *tcpconnlatProbe) read() ([]TCPConnLatResult, error) {
	var results []TCPConnLatResult
	var pid uint32
	var val tcpconnlatConnlatVal

	iter := p.objs.ConnlatAccum.Iterate()
	for iter.Next(&pid, &val) {
		if val.Count == 0 {
			continue
		}
		// Skip loopback destinations
		if isLoopback(val.Daddr) {
			continue
		}
		results = append(results, TCPConnLatResult{
			PID:     pid,
			Comm:    readComm(pid),
			TotalNs: val.TotalNs,
			Count:   val.Count,
			MaxNs:   val.MaxNs,
			DstAddr: val.Daddr,
			DstStr:  formatIPv4(val.Daddr),
		})
	}
	if err := iter.Err(); err != nil {
		return results, fmt.Errorf("iterate connlat_accum map: %w", err)
	}
	return results, nil
}

func (p *tcpconnlatProbe) close() {
	for _, l := range p.links {
		l.Close()
	}
	p.objs.Close()
}

// formatIPv4 formats a uint32 address as "a.b.c.d".
func formatIPv4(addr uint32) string {
	return fmt.Sprintf("%d.%d.%d.%d",
		addr&0xff, (addr>>8)&0xff, (addr>>16)&0xff, (addr>>24)&0xff)
}

// isLoopback returns true if the IPv4 address (in network byte order on LE)
// is in 127.0.0.0/8. On x86, the first octet is addr&0xff.
func isLoopback(addr uint32) bool {
	return addr&0xff == 127
}

// isPrivateAddr returns true for RFC1918, link-local, and loopback addresses.
// On x86 LE: first octet = addr&0xff, second = (addr>>8)&0xff.
func isPrivateAddr(addr uint32) bool {
	first := addr & 0xff
	second := (addr >> 8) & 0xff
	switch {
	case first == 10: // 10.0.0.0/8
		return true
	case first == 172 && second >= 16 && second <= 31: // 172.16.0.0/12
		return true
	case first == 192 && second == 168: // 192.168.0.0/16
		return true
	case first == 169 && second == 254: // 169.254.0.0/16 link-local
		return true
	case first == 127: // 127.0.0.0/8
		return true
	}
	return false
}
