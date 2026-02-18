package ebpf

import (
	"os"
	"path/filepath"
)

// ProbeCapability describes what eBPF probing is available on this system.
type ProbeCapability struct {
	Available bool
	BTF       bool
	HasRoot   bool
	Reason    string
	Packs     []string
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

	for pack, tps := range checks {
		ok := true
		for _, tp := range tps {
			if _, err := os.Stat(filepath.Join(tracefs, tp)); err != nil {
				ok = false
				break
			}
		}
		if ok {
			cap.Packs = append(cap.Packs, pack)
		}
	}

	if len(cap.Packs) > 0 {
		cap.Available = true
	} else {
		cap.Reason = "no tracepoints available"
	}

	return cap
}
