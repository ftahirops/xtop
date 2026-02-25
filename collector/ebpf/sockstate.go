//go:build 386 || amd64

package ebpf

import (
	"fmt"

	"github.com/cilium/ebpf/link"
)

type sockstateProbe struct {
	objs  sockstateObjects
	links []link.Link
}

// SockStateResult holds a TCP state transition and its count.
type SockStateResult struct {
	OldState uint16
	NewState uint16
	Count    uint64
}

func attachSockState() (*sockstateProbe, error) {
	var objs sockstateObjects
	if err := loadSockstateObjects(&objs, nil); err != nil {
		return nil, fmt.Errorf("load sockstate: %w", err)
	}

	l, err := link.Tracepoint("sock", "inet_sock_set_state", objs.HandleSockSetState, nil)
	if err != nil {
		objs.Close()
		return nil, fmt.Errorf("attach inet_sock_set_state: %w", err)
	}

	return &sockstateProbe{objs: objs, links: []link.Link{l}}, nil
}

func (p *sockstateProbe) read() ([]SockStateResult, error) {
	var results []SockStateResult
	var key sockstateStateKey
	var val sockstateStateVal

	iter := p.objs.StateAccum.Iterate()
	for iter.Next(&key, &val) {
		if val.Count == 0 {
			continue
		}
		results = append(results, SockStateResult{
			OldState: key.Oldstate,
			NewState: key.Newstate,
			Count:    val.Count,
		})
	}
	if err := iter.Err(); err != nil {
		return results, fmt.Errorf("iterate state_accum map: %w", err)
	}
	return results, nil
}

func (p *sockstateProbe) close() {
	for _, l := range p.links {
		l.Close()
	}
	p.objs.Close()
}

// tcpStateName maps TCP state numbers to names.
func tcpStateName(state uint16) string {
	switch state {
	case 1:
		return "ESTABLISHED"
	case 2:
		return "SYN_SENT"
	case 3:
		return "SYN_RECV"
	case 4:
		return "FIN_WAIT1"
	case 5:
		return "FIN_WAIT2"
	case 6:
		return "TIME_WAIT"
	case 7:
		return "CLOSE"
	case 8:
		return "CLOSE_WAIT"
	case 9:
		return "LAST_ACK"
	case 10:
		return "LISTEN"
	case 11:
		return "CLOSING"
	default:
		return fmt.Sprintf("STATE_%d", state)
	}
}
