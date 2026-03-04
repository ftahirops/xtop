//go:build 386 || amd64

package ebpf

import (
	"os"
	"strings"
	"sync"
	"time"

	"github.com/ftahirops/xtop/model"
)

// SecWatchdog manages auto-triggered security deep-inspection probes.
// When sentinel probes detect anomalies (e.g. port scan, DNS anomaly),
// the watchdog activates corresponding deep inspection probes for a
// limited time window, then automatically expires them.
type SecWatchdog struct {
	mu sync.Mutex

	// Active probes (nil when inactive)
	tcpflags     *tcpflagsProbe
	dnsdeep      *dnsdeepProbe
	tlsfinger    *tlsfingerProbe
	beacondetect *beacondetectProbe

	// Expiry timers
	tcpflagsExpiry     time.Time
	dnsdeepExpiry      time.Time
	tlsfingerExpiry    time.Time
	beacondetectExpiry time.Time

	// Primary interface for TC probes
	iface string
}

// NewSecWatchdog creates a new security watchdog manager.
// iface is the primary network interface name (e.g. "eth0") for TC probes.
func NewSecWatchdog(iface string) *SecWatchdog {
	return &SecWatchdog{iface: iface}
}

// TriggerFromEvidence inspects evidence and activates deep inspection probes
// when security signals fire with sufficient strength (>= 0.5).
func (sw *SecWatchdog) TriggerFromEvidence(evidence []model.Evidence) {
	sw.mu.Lock()
	defer sw.mu.Unlock()

	now := time.Now()

	for _, ev := range evidence {
		if ev.Strength < 0.5 {
			continue
		}

		switch ev.ID {
		case "sec.portscan":
			sw.activateTCPFlags(now, 60*time.Second)

		case "sec.dns.anomaly":
			sw.activateDNSDeep(now, 60*time.Second)

		case "sec.outbound.exfil", "sec.beacon":
			sw.activateTLSFinger(now, 60*time.Second)
			sw.activateBeaconDetect(now, 120*time.Second)
		}
	}
}

// activateTCPFlags starts or refreshes the tcpflags probe.
func (sw *SecWatchdog) activateTCPFlags(now time.Time, dur time.Duration) {
	if sw.tcpflags != nil && now.Before(sw.tcpflagsExpiry) {
		return // still active, skip
	}
	// Close old probe if expired
	if sw.tcpflags != nil {
		sw.tcpflags.close()
		sw.tcpflags = nil
	}
	if p, err := attachTCPFlags(sw.iface); err == nil {
		sw.tcpflags = p
		sw.tcpflagsExpiry = now.Add(dur)
	}
}

// activateDNSDeep starts or refreshes the dnsdeep probe.
func (sw *SecWatchdog) activateDNSDeep(now time.Time, dur time.Duration) {
	if sw.dnsdeep != nil && now.Before(sw.dnsdeepExpiry) {
		return
	}
	if sw.dnsdeep != nil {
		sw.dnsdeep.close()
		sw.dnsdeep = nil
	}
	if p, err := attachDNSDeep(sw.iface); err == nil {
		sw.dnsdeep = p
		sw.dnsdeepExpiry = now.Add(dur)
	}
}

// activateTLSFinger starts or refreshes the tlsfinger probe.
func (sw *SecWatchdog) activateTLSFinger(now time.Time, dur time.Duration) {
	if sw.tlsfinger != nil && now.Before(sw.tlsfingerExpiry) {
		return
	}
	if sw.tlsfinger != nil {
		sw.tlsfinger.close()
		sw.tlsfinger = nil
	}
	if p, err := attachTLSFinger(sw.iface); err == nil {
		sw.tlsfinger = p
		sw.tlsfingerExpiry = now.Add(dur)
	}
}

// activateBeaconDetect starts or refreshes the beacondetect probe.
func (sw *SecWatchdog) activateBeaconDetect(now time.Time, dur time.Duration) {
	if sw.beacondetect != nil && now.Before(sw.beacondetectExpiry) {
		return
	}
	if sw.beacondetect != nil {
		sw.beacondetect.close()
		sw.beacondetect = nil
	}
	if p, err := attachBeaconDetect(); err == nil {
		sw.beacondetect = p
		sw.beacondetectExpiry = now.Add(dur)
	}
}

// Collect reads data from all active watchdog probes into SecurityMetrics.
// Expired probes are automatically closed. Updates ActiveWatchdogs and ThreatScore.
func (sw *SecWatchdog) Collect(sec *model.SecurityMetrics) {
	sw.mu.Lock()
	defer sw.mu.Unlock()

	now := time.Now()
	var activeNames []string
	hasResults := false

	// tcpflags
	if sw.tcpflags != nil {
		if now.After(sw.tcpflagsExpiry) {
			sw.tcpflags.close()
			sw.tcpflags = nil
		} else {
			activeNames = append(activeNames, "tcpflags")
			if results, err := sw.tcpflags.read(); err == nil && len(results) > 0 {
				sec.TCPFlagAnomalies = results
				hasResults = true
			}
		}
	}

	// dnsdeep
	if sw.dnsdeep != nil {
		if now.After(sw.dnsdeepExpiry) {
			sw.dnsdeep.close()
			sw.dnsdeep = nil
		} else {
			activeNames = append(activeNames, "dnsdeep")
			if results, err := sw.dnsdeep.read(); err == nil && len(results) > 0 {
				sec.DNSTunnelIndicators = results
				hasResults = true
			}
		}
	}

	// tlsfinger
	if sw.tlsfinger != nil {
		if now.After(sw.tlsfingerExpiry) {
			sw.tlsfinger.close()
			sw.tlsfinger = nil
		} else {
			activeNames = append(activeNames, "tlsfinger")
			if results, err := sw.tlsfinger.read(); err == nil && len(results) > 0 {
				sec.JA3Fingerprints = results
				hasResults = true
			}
		}
	}

	// beacondetect
	if sw.beacondetect != nil {
		if now.After(sw.beacondetectExpiry) {
			sw.beacondetect.close()
			sw.beacondetect = nil
		} else {
			activeNames = append(activeNames, "beacondetect")
			if results, err := sw.beacondetect.read(); err == nil && len(results) > 0 {
				sec.BeaconIndicators = results
				hasResults = true
			}
		}
	}

	sec.ActiveWatchdogs = activeNames

	// Compute threat score
	if len(activeNames) > 0 {
		sec.ThreatScore = "THREAT"
	} else if hasResults {
		sec.ThreatScore = "ANOMALY"
	} else {
		if sec.ThreatScore == "" {
			sec.ThreatScore = "CLEAR"
		}
	}
}

// Close shuts down all active watchdog probes.
func (sw *SecWatchdog) Close() {
	sw.mu.Lock()
	defer sw.mu.Unlock()

	if sw.tcpflags != nil {
		sw.tcpflags.close()
		sw.tcpflags = nil
	}
	if sw.dnsdeep != nil {
		sw.dnsdeep.close()
		sw.dnsdeep = nil
	}
	if sw.tlsfinger != nil {
		sw.tlsfinger.close()
		sw.tlsfinger = nil
	}
	if sw.beacondetect != nil {
		sw.beacondetect.close()
		sw.beacondetect = nil
	}
}

// DetectPrimaryIface returns the name of the primary network interface
// by reading the default route from /proc/net/route.
func DetectPrimaryIface() string {
	data, err := os.ReadFile("/proc/net/route")
	if err != nil {
		return "eth0" // fallback
	}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		// Default route has destination 00000000
		if fields[1] == "00000000" {
			return fields[0]
		}
	}
	return "eth0" // fallback
}
