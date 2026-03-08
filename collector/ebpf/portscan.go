//go:build 386 || amd64

package ebpf

import (
	"fmt"
	"math/bits"
	"os"
	"strconv"
	"strings"

	"github.com/cilium/ebpf/link"
	"github.com/ftahirops/xtop/model"
)

// ktimeNowNs returns the current monotonic time in nanoseconds (matches bpf_ktime_get_ns).
func ktimeNowNs() uint64 {
	data, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return 0
	}
	parts := strings.Fields(string(data))
	if len(parts) < 1 {
		return 0
	}
	secs, err := strconv.ParseFloat(parts[0], 64)
	if err != nil {
		return 0
	}
	return uint64(secs * 1e9)
}

type portscanProbe struct {
	objs  portscanObjects
	links []link.Link
}

func attachPortScan() (*portscanProbe, error) {
	var objs portscanObjects
	if err := loadPortscanObjects(&objs, nil); err != nil {
		return nil, fmt.Errorf("load portscan: %w", err)
	}

	l, err := link.Kprobe("tcp_v4_send_reset", objs.HandleTcpV4SendReset, nil)
	if err != nil {
		objs.Close()
		return nil, fmt.Errorf("attach tcp_v4_send_reset: %w", err)
	}

	return &portscanProbe{objs: objs, links: []link.Link{l}}, nil
}

func (p *portscanProbe) read() ([]model.PortScanEntry, error) {
	var results []model.PortScanEntry
	var srcIP uint32
	var val portscanScanVal

	// Get current monotonic time to compute scan duration from BPF first_ns
	nowNs := ktimeNowNs()

	iter := p.objs.ScanAccum.Iterate()
	for iter.Next(&srcIP, &val) {
		// Skip loopback (127.0.0.0/8) — local RSTs are not port scans
		if isLoopback(srcIP) {
			continue
		}
		portDiversity := bits.OnesCount64(val.PortBitmap)
		// Filter: require significant RST count AND port diversity
		// Low counts or few ports = normal connection failures, not scans
		if val.RstCount < 50 || portDiversity < 10 {
			continue
		}
		var durSec float64
		if val.FirstNs > 0 && nowNs > val.FirstNs {
			durSec = float64(nowNs-val.FirstNs) / 1e9
		}
		results = append(results, model.PortScanEntry{
			SrcIP:             formatIPv4(srcIP),
			RSTCount:          val.RstCount,
			UniquePortBuckets: portDiversity,
			DurationSec:       durSec,
		})
	}
	if err := iter.Err(); err != nil {
		return results, fmt.Errorf("iterate scan_accum map: %w", err)
	}
	return results, nil
}

func (p *portscanProbe) close() {
	for _, l := range p.links {
		l.Close()
	}
	p.objs.Close()
}
