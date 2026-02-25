package ebpf

import (
	"os"
	"path/filepath"
)

// ProbeCapability describes what eBPF probing is available on this system.
type ProbeCapability struct {
	Available     bool
	BTF           bool
	HasRoot       bool
	Reason        string
	Packs         []string
	SentinelPacks []string
	WatchdogPacks []string
}

// Detect checks system capabilities for eBPF probing.
func Detect() ProbeCapability {
	cap := ProbeCapability{}

	if _, err := os.Stat("/sys/kernel/btf/vmlinux"); err == nil {
		cap.BTF = true
	}

	if os.Geteuid() == 0 {
		cap.HasRoot = true
	}

	if !cap.BTF {
		cap.Reason = "kernel BTF not available (/sys/kernel/btf/vmlinux missing)"
		return cap
	}
	if !cap.HasRoot {
		cap.Reason = "root privileges required for eBPF probes"
		return cap
	}

	// Find tracefs
	tracefs := "/sys/kernel/debug/tracing/events"
	if _, err := os.Stat(tracefs); err != nil {
		tracefs = "/sys/kernel/tracing/events"
	}

	checks := map[string][]string{
		"offcpu":        {"sched/sched_switch"},
		"iolatency":     {"block/block_rq_issue", "block/block_rq_complete"},
		"lockwait":      {"syscalls/sys_enter_futex", "syscalls/sys_exit_futex"},
		"tcpretrans":    {"tcp/tcp_retransmit_skb"},
		"netthroughput": {}, // kprobes — always available with BTF
		"tcprtt":        {}, // kprobe — always available with BTF
		"tcpconnlat":    {"sock/inet_sock_set_state"},
	}

	sentinelChecks := map[string][]string{
		"kfreeskb":      {"skb/kfree_skb"},
		"tcpreset":      {},  // kprobe
		"sockstate":     {"sock/inet_sock_set_state"},
		"modload":       {},  // kprobe
		"oomkill":       {"oom/mark_victim"},
		"directreclaim": {"vmscan/mm_vmscan_direct_reclaim_begin", "vmscan/mm_vmscan_direct_reclaim_end"},
		"cgthrottle":    {},  // kprobe
	}

	watchdogChecks := map[string][]string{
		"runqlat":        {"sched/sched_wakeup"},
		"wbstall":        {"writeback/writeback_wait"},
		"pgfault":        {},  // kprobe
		"swapevict":      {}, // kprobe
		"syscalldissect": {"raw_syscalls/sys_enter", "raw_syscalls/sys_exit"},
		"sockio":         {}, // kprobes only, always available with BTF
	}

	checkPacks := func(packChecks map[string][]string) []string {
		var result []string
		for pack, tps := range packChecks {
			ok := true
			for _, tp := range tps {
				if _, err := os.Stat(filepath.Join(tracefs, tp)); err != nil {
					ok = false
					break
				}
			}
			if ok {
				result = append(result, pack)
			}
		}
		return result
	}

	cap.Packs = checkPacks(checks)
	cap.SentinelPacks = checkPacks(sentinelChecks)
	cap.WatchdogPacks = checkPacks(watchdogChecks)

	if len(cap.Packs) > 0 || len(cap.SentinelPacks) > 0 {
		cap.Available = true
	} else {
		cap.Reason = "no tracepoints available"
	}

	return cap
}
