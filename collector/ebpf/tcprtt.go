//go:build 386 || amd64

package ebpf

import (
	"fmt"

	"github.com/cilium/ebpf/link"
)

type tcprttProbe struct {
	objs  tcprttObjects
	links []link.Link
}

// TCPRTTResult holds RTT data for one remote endpoint.
type TCPRTTResult struct {
	DstAddr  uint32
	DstPort  uint16
	DstStr   string // formatted "ip:port"
	SumUs    uint64
	Count    uint32
	MinUs    uint32
	MaxUs    uint32
	LastPID  uint32
	LastComm string
}

func attachTCPRTT() (*tcprttProbe, error) {
	var objs tcprttObjects
	if err := loadTcprttObjects(&objs, nil); err != nil {
		return nil, fmt.Errorf("load tcprtt: %w", err)
	}

	l, err := link.Kprobe("tcp_rcv_established", objs.HandleTcpRcvEstablished, nil)
	if err != nil {
		objs.Close()
		return nil, fmt.Errorf("attach tcp_rcv_established: %w", err)
	}

	return &tcprttProbe{objs: objs, links: []link.Link{l}}, nil
}

func (p *tcprttProbe) read() ([]TCPRTTResult, error) {
	var results []TCPRTTResult
	var key tcprttRttKey
	var val tcprttRttVal

	iter := p.objs.RttAccum.Iterate()
	for iter.Next(&key, &val) {
		if val.Count == 0 {
			continue
		}
		results = append(results, TCPRTTResult{
			DstAddr:  key.Daddr,
			DstPort:  key.Dport,
			DstStr:   formatIPv4Port(key.Daddr, key.Dport),
			SumUs:    val.SumUs,
			Count:    val.Count,
			MinUs:    val.MinUs,
			MaxUs:    val.MaxUs,
			LastPID:  val.LastPid,
			LastComm: readComm(val.LastPid),
		})
	}
	if err := iter.Err(); err != nil {
		return results, fmt.Errorf("iterate rtt_accum map: %w", err)
	}
	return results, nil
}

func (p *tcprttProbe) close() {
	for _, l := range p.links {
		l.Close()
	}
	p.objs.Close()
}
