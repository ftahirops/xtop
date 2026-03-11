//go:build 386 || amd64

package ebpf

import (
	"bufio"
	"encoding/hex"
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

	nowNs := ktimeNowNs()

	// Build set of IPs with established TCP connections — these are clients, not scanners
	establishedIPs := getEstablishedRemoteIPs()

	iter := p.objs.ScanAccum.Iterate()
	for iter.Next(&srcIP, &val) {
		if isLoopback(srcIP) {
			continue
		}
		portDiversity := bits.OnesCount64(val.PortBitmap)
		if val.RstCount < 200 || portDiversity < 16 {
			continue
		}
		var durSec float64
		if val.FirstNs > 0 && nowNs > val.FirstNs {
			durSec = float64(nowNs-val.FirstNs) / 1e9
		}
		if durSec > 60 && float64(val.RstCount)/durSec < 1.0 {
			continue
		}
		// If this IP has active established connections, it's a client, not a scanner.
		// Scanners send RSTs to closed ports and move on — they don't maintain connections.
		ipStr := formatIPv4(srcIP)
		if establishedIPs[ipStr] {
			continue
		}
		results = append(results, model.PortScanEntry{
			SrcIP:             ipStr,
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

// getEstablishedRemoteIPs returns a set of remote IPs that have ESTABLISHED TCP connections.
func getEstablishedRemoteIPs() map[string]bool {
	ips := make(map[string]bool)
	for _, path := range []string{"/proc/net/tcp", "/proc/net/tcp6"} {
		f, err := os.Open(path)
		if err != nil {
			continue
		}
		scanner := bufio.NewScanner(f)
		scanner.Scan() // skip header
		for scanner.Scan() {
			fields := strings.Fields(scanner.Text())
			if len(fields) < 4 {
				continue
			}
			if fields[3] != "01" { // ESTABLISHED
				continue
			}
			// remote_address is fields[2], format: hex_ip:hex_port
			parts := strings.Split(fields[2], ":")
			if len(parts) != 2 || len(parts[0]) != 8 {
				continue
			}
			b, err := hex.DecodeString(parts[0])
			if err != nil || len(b) != 4 {
				continue
			}
			// /proc/net/tcp stores IP in little-endian
			ip := fmt.Sprintf("%d.%d.%d.%d", b[3], b[2], b[1], b[0])
			ips[ip] = true
		}
		f.Close()
	}
	return ips
}

func (p *portscanProbe) close() {
	for _, l := range p.links {
		l.Close()
	}
	p.objs.Close()
}
