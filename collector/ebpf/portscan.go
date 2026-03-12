//go:build 386 || amd64

package ebpf

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"math/bits"
	"os"
	"path/filepath"
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

	// If a proxy/LB is running, suppress port scan detection entirely —
	// proxies generate RSTs to many ports as normal client traffic flows.
	if hasProxyListening() {
		return results, nil
	}

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
		// Slow accumulation over long period = normal client churn, not a scan
		if durSec > 60 && float64(val.RstCount)/durSec < 3.0 {
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

// hasProxyListening checks if a reverse proxy / load balancer is among the
// listening processes. On proxy servers, clients generate RSTs to many ephemeral
// ports as a normal side-effect of proxied connections, causing false-positive
// port scan detections.
func hasProxyListening() bool {
	proxyNames := map[string]bool{
		"haproxy": true, "nginx": true, "envoy": true, "traefik": true,
		"caddy": true, "squid": true, "varnish": true, "apache2": true,
		"httpd": true, "lighttpd": true, "pound": true,
	}
	// Check /proc/net/tcp for LISTEN state (0A) and resolve owning process
	f, err := os.Open("/proc/net/tcp")
	if err != nil {
		return false
	}
	defer f.Close()
	listeningInodes := make(map[string]bool)
	scanner := bufio.NewScanner(f)
	scanner.Scan() // skip header
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 10 {
			continue
		}
		if fields[3] == "0A" { // LISTEN
			listeningInodes[fields[9]] = true
		}
	}
	if len(listeningInodes) == 0 {
		return false
	}
	// Walk /proc/*/fd to find which process owns listening sockets
	procs, _ := filepath.Glob("/proc/[0-9]*/fd")
	for _, fdDir := range procs {
		pid := strings.Split(fdDir, "/")[2]
		comm, err := os.ReadFile("/proc/" + pid + "/comm")
		if err != nil {
			continue
		}
		name := strings.TrimSpace(string(comm))
		if !proxyNames[name] {
			continue
		}
		// This is a proxy process — check if it owns any listening socket
		fds, _ := os.ReadDir(fdDir)
		for _, fd := range fds {
			link, err := os.Readlink(fdDir + "/" + fd.Name())
			if err != nil {
				continue
			}
			if !strings.HasPrefix(link, "socket:[") {
				continue
			}
			inode := link[8 : len(link)-1]
			if listeningInodes[inode] {
				return true
			}
		}
	}
	return false
}

func (p *portscanProbe) close() {
	for _, l := range p.links {
		l.Close()
	}
	p.objs.Close()
}
