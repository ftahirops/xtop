//go:build 386 || amd64

package ebpf

import (
	"fmt"

	"github.com/cilium/ebpf/link"
)

type sockioProbe struct {
	objs  sockioObjects
	links []link.Link
}

// SockIOResult holds per-PID per-connection TCP IO data.
type SockIOResult struct {
	PID        uint32
	Comm       string
	DstAddr    uint32
	DstPort    uint16
	DstStr     string
	TxBytes    uint64
	RxBytes    uint64
	RecvWaitNs uint64
	RecvCount  uint32
	MaxRecvNs  uint32
}

func attachSockIO() (*sockioProbe, error) {
	var objs sockioObjects
	if err := loadSockioObjects(&objs, nil); err != nil {
		return nil, fmt.Errorf("load sockio: %w", err)
	}

	l1, err := link.Kprobe("tcp_sendmsg", objs.HandleTcpSendmsg, nil)
	if err != nil {
		objs.Close()
		return nil, fmt.Errorf("attach tcp_sendmsg: %w", err)
	}

	l2, err := link.Kprobe("tcp_cleanup_rbuf", objs.HandleTcpCleanupRbuf, nil)
	if err != nil {
		l1.Close()
		objs.Close()
		return nil, fmt.Errorf("attach tcp_cleanup_rbuf: %w", err)
	}

	l3, err := link.Kprobe("tcp_recvmsg", objs.HandleTcpRecvmsgEnter, nil)
	if err != nil {
		l2.Close()
		l1.Close()
		objs.Close()
		return nil, fmt.Errorf("attach tcp_recvmsg kprobe: %w", err)
	}

	l4, err := link.Kretprobe("tcp_recvmsg", objs.HandleTcpRecvmsgExit, nil)
	if err != nil {
		l3.Close()
		l2.Close()
		l1.Close()
		objs.Close()
		return nil, fmt.Errorf("attach tcp_recvmsg kretprobe: %w", err)
	}

	return &sockioProbe{objs: objs, links: []link.Link{l1, l2, l3, l4}}, nil
}

func (p *sockioProbe) read() ([]SockIOResult, error) {
	var results []SockIOResult
	var key sockioSockioKey
	var val sockioSockioVal

	iter := p.objs.SockioAccum.Iterate()
	for iter.Next(&key, &val) {
		if val.TxBytes == 0 && val.RxBytes == 0 && val.RecvWaitNs == 0 {
			continue
		}
		results = append(results, SockIOResult{
			PID:        key.Pid,
			Comm:       readComm(key.Pid),
			DstAddr:    key.Daddr,
			DstPort:    key.Dport,
			DstStr:     formatIPv4Port(key.Daddr, key.Dport),
			TxBytes:    val.TxBytes,
			RxBytes:    val.RxBytes,
			RecvWaitNs: val.RecvWaitNs,
			RecvCount:  val.RecvCount,
			MaxRecvNs:  val.MaxRecvNs,
		})
	}
	if err := iter.Err(); err != nil {
		return results, fmt.Errorf("iterate sockio_accum map: %w", err)
	}
	return results, nil
}

func (p *sockioProbe) close() {
	for _, l := range p.links {
		l.Close()
	}
	p.objs.Close()
}
