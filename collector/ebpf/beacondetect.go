//go:build 386 || amd64

package ebpf

import (
	"fmt"
	"math"
	"sort"

	"github.com/cilium/ebpf/link"
	"github.com/ftahirops/xtop/model"
)

type beacondetectProbe struct {
	objs  beacondetectObjects
	links []link.Link
}

func attachBeaconDetect() (*beacondetectProbe, error) {
	var objs beacondetectObjects
	if err := loadBeacondetectObjects(&objs, nil); err != nil {
		return nil, fmt.Errorf("load beacondetect: %w", err)
	}

	l, err := link.Kprobe("tcp_sendmsg", objs.HandleBeaconSendmsg, nil)
	if err != nil {
		objs.Close()
		return nil, fmt.Errorf("attach tcp_sendmsg: %w", err)
	}

	return &beacondetectProbe{objs: objs, links: []link.Link{l}}, nil
}

func (p *beacondetectProbe) read() ([]model.BeaconIndicator, error) {
	var results []model.BeaconIndicator
	var key beacondetectBeaconKey
	var val beacondetectBeaconVal

	iter := p.objs.BeaconAccum.Iterate()
	for iter.Next(&key, &val) {
		// Filter: skip entries with fewer than 5 intervals
		if val.IntervalCount < 5 {
			continue
		}
		avgNs := float64(val.IntervalSumNs) / float64(val.IntervalCount)
		avgSec := avgNs / 1e9
		// Jitter = (max - min) / avg, normalized
		var jitter float64
		if avgNs > 0 {
			jitter = float64(val.MaxIntervalNs-val.MinIntervalNs) / avgNs
		}
		// Clamp jitter to reasonable range
		jitter = math.Min(jitter, 100.0)

		results = append(results, model.BeaconIndicator{
			PID:            int(key.Pid),
			Comm:           readComm(key.Pid),
			DstIP:          formatIPv4(key.Daddr),
			DstPort:        key.Dport,
			AvgIntervalSec: avgSec,
			Jitter:         jitter,
			SampleCount:    int(val.IntervalCount),
		})
	}
	if err := iter.Err(); err != nil {
		return results, fmt.Errorf("iterate beacon_accum map: %w", err)
	}

	// Sort by jitter ascending (most regular = most suspicious)
	sort.Slice(results, func(i, j int) bool {
		return results[i].Jitter < results[j].Jitter
	})
	// Keep top 10
	if len(results) > 10 {
		results = results[:10]
	}

	return results, nil
}

func (p *beacondetectProbe) close() {
	for _, l := range p.links {
		l.Close()
	}
	p.objs.Close()
}
