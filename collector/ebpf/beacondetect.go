//go:build 386 || amd64

package ebpf

import (
	"fmt"
	"math"
	"sort"

	"github.com/cilium/ebpf/link"
	"github.com/ftahirops/xtop/model"
)

// knownSafeBeaconComm: processes that legitimately send periodic traffic (monitoring, NTP, health checks).
var knownSafeBeaconComm = map[string]bool{
	// Monitoring agents
	"prometheus": true, "grafana-agent": true, "alloy": true, "telegraf": true, "collectd": true,
	"node_exporter": true, "agent": true, "trace-agent": true, "process-agent": true,
	"datadog-agent": true, "newrelic-infra": true, "zabbix_agentd": true, "otel-collector": true,
	"filebeat": true, "fluentd": true, "fluent-bit": true, "logstash": true, "vector": true,
	// NTP / time sync
	"chronyd": true, "ntpd": true, "systemd-timesyn": true,
	// Health checks / service mesh
	"consul": true, "consul-agent": true, "envoy": true, "istio-proxy": true, "linkerd-proxy": true,
	// Databases (keepalives)
	"mysqld": true, "postgres": true, "mongod": true, "redis-server": true,
	// System services
	"sshd": true, "systemd-resolve": true, "networkd-dispat": true,
	// Container orchestration
	"kubelet": true, "kube-proxy": true, "containerd": true, "dockerd": true,
	// Load balancers (health checks to backends)
	"haproxy": true, "nginx": true, "traefik": true, "caddy": true,
	// Package managers (update checks)
	"unattended-upgr": true, "packagekitd": true,
}

// isPrivateIP checks if a uint32 IPv4 address is RFC1918/link-local/CGNAT.
func isPrivateIP(ip uint32) bool {
	// ip is in network byte order: MSB at lowest byte on little-endian
	// Extract octets: ip is stored as host byte order from BPF (little-endian)
	a := byte(ip & 0xff)
	b := byte((ip >> 8) & 0xff)
	// 10.0.0.0/8
	if a == 10 {
		return true
	}
	// 172.16.0.0/12
	if a == 172 && b >= 16 && b <= 31 {
		return true
	}
	// 192.168.0.0/16
	if a == 192 && b == 168 {
		return true
	}
	// 169.254.0.0/16 (link-local)
	if a == 169 && b == 254 {
		return true
	}
	// 100.64.0.0/10 (CGNAT)
	if a == 100 && b >= 64 && b <= 127 {
		return true
	}
	return false
}

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
		// Skip loopback destinations — local health checks are not C2 beacons
		if isLoopback(key.Daddr) {
			continue
		}
		// Skip private/internal destinations — C2 beacons go to public IPs
		if isPrivateIP(key.Daddr) {
			continue
		}
		// Skip known-safe processes (monitoring agents, NTP, health checks, log shippers)
		comm := readComm(key.Pid)
		if knownSafeBeaconComm[comm] {
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
			Comm:           comm,
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
