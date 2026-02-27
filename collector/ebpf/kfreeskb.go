//go:build 386 || amd64

package ebpf

import (
	"fmt"

	"github.com/cilium/ebpf/link"
)

type kfreeskbProbe struct {
	objs  kfreeskbObjects
	links []link.Link
}

// KfreeSkbResult holds a packet drop reason and count.
type KfreeSkbResult struct {
	Reason uint32
	Count  uint64
}

func attachKfreeSkb() (*kfreeskbProbe, error) {
	var objs kfreeskbObjects
	if err := loadKfreeskbObjects(&objs, nil); err != nil {
		return nil, fmt.Errorf("load kfreeskb: %w", err)
	}

	l, err := link.Tracepoint("skb", "kfree_skb", objs.HandleKfreeSkb, nil)
	if err != nil {
		objs.Close()
		return nil, fmt.Errorf("attach kfree_skb: %w", err)
	}

	return &kfreeskbProbe{objs: objs, links: []link.Link{l}}, nil
}

func (p *kfreeskbProbe) read() ([]KfreeSkbResult, error) {
	var results []KfreeSkbResult
	var reason uint32
	var val kfreeskbDropVal

	iter := p.objs.DropAccum.Iterate()
	for iter.Next(&reason, &val) {
		if val.Count == 0 {
			continue
		}
		results = append(results, KfreeSkbResult{
			Reason: reason,
			Count:  val.Count,
		})
	}
	if err := iter.Err(); err != nil {
		return results, fmt.Errorf("iterate drop_accum map: %w", err)
	}
	return results, nil
}

func (p *kfreeskbProbe) close() {
	for _, l := range p.links {
		l.Close()
	}
	p.objs.Close()
}

// isBenignDropReason returns true for SKB_DROP_REASON codes that are normal
// TCP/IP lifecycle events, not actual network problems. These are excluded
// from the headline drop rate to avoid false alarms on busy servers.
func isBenignDropReason(reason uint32) bool {
	switch reason {
	case 2:  // NOT_SPECIFIED — generic, no diagnostic value
		return true
	case 3:  // NO_SOCKET — packets for recently closed connections (normal on proxies)
		return true
	case 6:  // SOCKET_FILTER — BPF socket filters (tcpdump, iptables match)
		return true
	case 27: // TCP_FLAGS — normal FIN/RST handling in TCP lifecycle
		return true
	case 28: // TCP_ZEROWINDOW — flow control, expected under load
		return true
	case 29: // TCP_OLD_DATA — retransmit arriving after ACK (normal)
		return true
	case 33: // TCP_OVERWINDOW — flow control
		return true
	case 37: // TCP_OFOMERGE — out-of-order segment merged
		return true
	case 82: // SKB_CONSUMED — packet consumed normally
		return true
	default:
		return false
	}
}

// dropReasonString maps kernel SKB_DROP_REASON enum values to human-readable strings.
func dropReasonString(reason uint32) string {
	switch reason {
	case 2:
		return "NOT_SPECIFIED"
	case 3:
		return "NO_SOCKET"
	case 4:
		return "PKT_TOO_SMALL"
	case 5:
		return "TCP_CSUM"
	case 6:
		return "SOCKET_FILTER"
	case 8:
		return "NETFILTER_DROP"
	case 16:
		return "SOCKET_RCVBUFF"
	case 17:
		return "PROTO_MEM"
	case 26:
		return "SOCKET_BACKLOG"
	case 27:
		return "TCP_FLAGS"
	case 28:
		return "TCP_ZEROWINDOW"
	case 29:
		return "TCP_OLD_DATA"
	case 33:
		return "TCP_OVERWINDOW"
	case 37:
		return "TCP_OFOMERGE"
	case 44:
		return "IP_OUTNOROUTES"
	case 52:
		return "QDISC_DROP"
	case 62:
		return "FULL_RING"
	case 63:
		return "NOMEM"
	case 82:
		return "SKB_CONSUMED"
	default:
		return fmt.Sprintf("REASON_%d", reason)
	}
}
