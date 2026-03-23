package engine

import "github.com/ftahirops/xtop/model"

// Weight categories for evidence IDs.
// Used by weightedDomainScore to assign slot weights.
var evidenceWeightCategory = map[string]string{
	// CPU
	"cpu.psi":              "psi",
	"cpu.busy":             "latency",
	"cpu.runqueue":         "queue",
	"cpu.ctxswitch":        "secondary",
	"cpu.steal":            "secondary",
	"cpu.cgroup.throttle":  "latency",

	// Memory
	"mem.psi":              "psi",
	"mem.available.low":    "latency",
	"mem.reclaim.direct":   "queue",
	"mem.swap.activity":    "latency",
	"mem.major.faults":     "secondary",
	"mem.oom.kills":        "queue", // OOM is a capacity/queue event, not PSI

	// Memory — runtime & kernel
	"mem.psi.acceleration":  "psi",
	"mem.slab.leak":         "queue",
	"mem.alloc.stall":       "queue",
	"mem.swap.in":           "latency",
	"mem.swap.out":          "secondary",

	// IO
	"io.psi":               "psi",
	"io.dstate":            "queue",
	"io.disk.latency":      "latency",
	"io.disk.util":         "latency",
	"io.disk.queuedepth":   "queue",
	"io.disk.flush":        "secondary",
	"io.writeback":         "secondary",
	"io.fsfull":            "secondary",
	"io.inode.pressure":    "secondary",

	// Network
	"net.drops":            "latency",
	"net.drops.rx":         "latency",
	"net.drops.tx":         "secondary",
	"net.tcp.retrans":      "latency", // retransmits are a latency signal, not PSI
	"net.conntrack":        "queue",
	"net.softirq":          "secondary",
	"net.tcp.timewait":     "secondary",
	"net.tcp.synsent":      "latency",
	"net.closewait":              "queue",
	"net.ephemeral":              "queue",
	"net.udp.errors":             "secondary",
	"net.tcp.resets":             "latency",
	"net.tcp.attemptfails":       "latency",
	"net.conntrack.drops":        "latency",
	"net.conntrack.insertfail":   "latency",
	"net.conntrack.growth":       "queue",
	"net.conntrack.invalid":      "secondary",
	"net.conntrack.hashcontention": "secondary",

	// CPU — extended
	"cpu.iowait":           "latency",
	"cpu.irq.imbalance":    "secondary",

	// Language runtimes
	"dotnet.alloc.storm":     "latency",
	"dotnet.threadpool.queue": "queue",
	"dotnet.gc.pause":        "latency",
	"jvm.gc.pause":           "latency",
	"jvm.heap.pressure":      "queue",

	// Proxmox VMs
	"pve.vm.throttle":  "latency",
	"pve.vm.cpupsi":    "secondary",
	"pve.vm.oom":       "psi",
	"pve.vm.swap":      "latency",
	"pve.vm.memlimit":  "queue",
	"pve.vm.mempsi":    "psi",

	// Sentinel evidence
	"net.sentinel.drops":    "latency",
	"net.sentinel.resets":   "latency",
	"mem.sentinel.oom":      "psi",
	"mem.sentinel.reclaim":  "queue",
	"cpu.sentinel.throttle": "latency",

	// Security
	"sec.synflood":       "psi",
	"sec.portscan":       "latency",
	"sec.dns.anomaly":    "queue",
	"sec.dns.tunnel":     "psi",
	"sec.outbound.exfil": "latency",
	"sec.lateral":        "queue",
	"sec.beacon":         "psi",
	"sec.tcp.flags":      "secondary",
}

// emitEvidence creates a v2 Evidence object with smooth normalization.
func emitEvidence(id string, domain model.Domain, value, warn, crit float64,
	measured bool, conf float64, msg, window string,
	owners []model.OwnerAttribution, tags map[string]string) model.Evidence {

	strength := normalize(value, warn, crit)

	sev := model.SeverityInfo
	if strength >= 0.7 {
		sev = model.SeverityCrit
	} else if strength >= 0.01 {
		sev = model.SeverityWarn
	}

	if tags == nil {
		tags = make(map[string]string)
	}
	if cat, ok := evidenceWeightCategory[id]; ok {
		tags["weight"] = cat
	}

	return model.Evidence{
		ID:         id,
		Message:    msg,
		Window:     window,
		Domain:     domain,
		Severity:   sev,
		Strength:   strength,
		Confidence: conf,
		Value:      value,
		Threshold:  crit,
		Measured:   measured,
		Owners:     owners,
		Tags:       tags,
	}
}

// evidenceGroupsFired counts how many unique evidence IDs have strength >= minStrength.
func evidenceGroupsFired(evs []model.Evidence, minStrength float64) int {
	count := 0
	for _, e := range evs {
		if e.Strength >= minStrength {
			count++
		}
	}
	return count
}

// hasMeasuredHighConf returns true if at least one evidence is measured,
// has strength >= minStrength, and confidence >= minConf.
func hasMeasuredHighConf(evs []model.Evidence, minStrength, minConf float64) bool {
	for _, e := range evs {
		if e.Measured && e.Strength >= minStrength && e.Confidence >= minConf {
			return true
		}
	}
	return false
}
