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
