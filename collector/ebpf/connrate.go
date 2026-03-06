//go:build 386 || amd64

package ebpf

import (
	"fmt"

	"github.com/cilium/ebpf/link"
	"github.com/ftahirops/xtop/model"
)

type connrateProbe struct {
	objs  connrateObjects
	links []link.Link
}

func attachConnRate() (*connrateProbe, error) {
	var objs connrateObjects
	if err := loadConnrateObjects(&objs, nil); err != nil {
		return nil, fmt.Errorf("load connrate: %w", err)
	}

	l, err := link.Tracepoint("sock", "inet_sock_set_state", objs.HandleConnrate, nil)
	if err != nil {
		objs.Close()
		return nil, fmt.Errorf("attach inet_sock_set_state: %w", err)
	}

	return &connrateProbe{objs: objs, links: []link.Link{l}}, nil
}

func (p *connrateProbe) read() ([]model.FlowRateEntry, map[uint32]int, error) {
	var results []model.FlowRateEntry
	var key connrateFlowKey
	var val connrateFlowVal

	// Read unique destination counts per PID
	destCounts := make(map[uint32]int)
	var dcPID uint32
	var dcVal uint64
	dcIter := p.objs.DestCount.Iterate()
	for dcIter.Next(&dcPID, &dcVal) {
		destCounts[dcPID] = int(dcVal)
	}
	if err := dcIter.Err(); err != nil {
		return nil, nil, fmt.Errorf("iterate dest_count: %w", err)
	}

	iter := p.objs.FlowAccum.Iterate()
	for iter.Next(&key, &val) {
		if val.ConnectCount == 0 && val.CloseCount == 0 {
			continue
		}
		results = append(results, model.FlowRateEntry{
			PID:             int(key.Pid),
			Comm:            readComm(key.Pid),
			DstIP:           formatIPv4(key.Daddr),
			ConnectCount:    val.ConnectCount,
			CloseCount:      val.CloseCount,
			UniqueDestCount: destCounts[key.Pid],
		})
	}
	if err := iter.Err(); err != nil {
		return results, destCounts, fmt.Errorf("iterate flow_accum map: %w", err)
	}
	return results, destCounts, nil
}

func (p *connrateProbe) close() {
	for _, l := range p.links {
		l.Close()
	}
	p.objs.Close()
}
