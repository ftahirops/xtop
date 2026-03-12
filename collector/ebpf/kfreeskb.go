//go:build 386 || amd64

package ebpf

import (
	"fmt"
	"os"
	"strings"
	"sync"

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

// KfreeSkbLocResult holds a drop location (kernel function addr) and count.
type KfreeSkbLocResult struct {
	Addr  uint64
	Count uint64
}

// KfreeSkbProtoResult holds a drop protocol and count.
type KfreeSkbProtoResult struct {
	Proto uint16
	Count uint64
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

// readLocations reads the drop_loc map (kernel function address → count).
func (p *kfreeskbProbe) readLocations() ([]KfreeSkbLocResult, error) {
	var results []KfreeSkbLocResult
	var addr uint64
	var val kfreeskbDropVal

	iter := p.objs.DropLoc.Iterate()
	for iter.Next(&addr, &val) {
		if val.Count == 0 {
			continue
		}
		results = append(results, KfreeSkbLocResult{
			Addr:  addr,
			Count: val.Count,
		})
	}
	if err := iter.Err(); err != nil {
		return results, fmt.Errorf("iterate drop_loc map: %w", err)
	}
	return results, nil
}

// readProtocols reads the drop_proto map (protocol → count).
func (p *kfreeskbProbe) readProtocols() ([]KfreeSkbProtoResult, error) {
	var results []KfreeSkbProtoResult
	var proto uint16
	var val kfreeskbDropVal

	iter := p.objs.DropProto.Iterate()
	for iter.Next(&proto, &val) {
		if val.Count == 0 {
			continue
		}
		results = append(results, KfreeSkbProtoResult{
			Proto: proto,
			Count: val.Count,
		})
	}
	if err := iter.Err(); err != nil {
		return results, fmt.Errorf("iterate drop_proto map: %w", err)
	}
	return results, nil
}

func (p *kfreeskbProbe) close() {
	for _, l := range p.links {
		l.Close()
	}
	p.objs.Close()
}

// ksymCache caches resolved kernel symbols to avoid re-reading /proc/kallsyms.
var ksymCache = struct {
	sync.Mutex
	m map[uint64]string
}{m: make(map[uint64]string)}

// resolveKsym resolves a kernel address to a function name using /proc/kallsyms.
// Results are cached.
func resolveKsym(addr uint64) string {
	ksymCache.Lock()
	if name, ok := ksymCache.m[addr]; ok {
		ksymCache.Unlock()
		return name
	}
	ksymCache.Unlock()

	data, err := os.ReadFile("/proc/kallsyms")
	if err != nil {
		return fmt.Sprintf("0x%x", addr)
	}
	// Find the closest symbol <= addr
	var bestName string
	var bestAddr uint64
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		var symAddr uint64
		if _, err := fmt.Sscanf(fields[0], "%x", &symAddr); err != nil {
			continue
		}
		if symAddr <= addr && symAddr > bestAddr {
			bestAddr = symAddr
			bestName = fields[2]
		}
		if symAddr > addr {
			break
		}
	}
	result := bestName
	if result == "" {
		result = fmt.Sprintf("0x%x", addr)
	}
	ksymCache.Lock()
	ksymCache.m[addr] = result
	ksymCache.Unlock()
	return result
}

// protoString converts an ETH_P_ protocol number to a name.
func protoString(proto uint16) string {
	switch proto {
	case 0x0800:
		return "IPv4"
	case 0x86DD:
		return "IPv6"
	case 0x0806:
		return "ARP"
	case 0x8100:
		return "VLAN"
	default:
		return fmt.Sprintf("0x%04x", proto)
	}
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
