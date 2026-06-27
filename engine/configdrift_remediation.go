package engine

import "fmt"

// suggestedRemediation returns a human-readable suggested fix string for a known
// kernel param key whose value drifted from the given oldVal.
//
// IMPORTANT: this function ONLY returns a text string. It never executes any
// command, writes to /proc/sys, /sys, sysctl, or any other file. The caller
// is responsible for surfacing this text as a suggestion in the UI/narrative.
func suggestedRemediation(key, oldVal string) string {
	switch key {
	case "vm.swappiness":
		return fmt.Sprintf("consider restoring vm.swappiness to %s: sysctl -w vm.swappiness=%s", oldVal, oldVal)
	case "vm.overcommit_memory":
		return fmt.Sprintf("consider restoring vm.overcommit_memory to %s: sysctl -w vm.overcommit_memory=%s", oldVal, oldVal)
	case "vm.dirty_ratio":
		return fmt.Sprintf("consider restoring vm.dirty_ratio to %s: sysctl -w vm.dirty_ratio=%s", oldVal, oldVal)
	case "vm.max_map_count":
		return fmt.Sprintf("consider restoring vm.max_map_count to %s: sysctl -w vm.max_map_count=%s", oldVal, oldVal)
	case "thp.enabled":
		return fmt.Sprintf("consider restoring transparent hugepages to '%s' (check /sys/kernel/mm/transparent_hugepage/enabled)", oldVal)
	case "net.core.somaxconn":
		return fmt.Sprintf("consider restoring net.core.somaxconn to %s: sysctl -w net.core.somaxconn=%s", oldVal, oldVal)
	case "net.ipv4.tcp_tw_reuse":
		return fmt.Sprintf("consider restoring net.ipv4.tcp_tw_reuse to %s: sysctl -w net.ipv4.tcp_tw_reuse=%s", oldVal, oldVal)
	case "net.ipv4.ip_local_port_range":
		return fmt.Sprintf("consider restoring net.ipv4.ip_local_port_range to '%s': sysctl -w net.ipv4.ip_local_port_range='%s'", oldVal, oldVal)
	case "net.netfilter.nf_conntrack_max":
		return fmt.Sprintf("consider restoring net.netfilter.nf_conntrack_max to %s: sysctl -w net.netfilter.nf_conntrack_max=%s", oldVal, oldVal)
	case "kernel.pid_max":
		return fmt.Sprintf("consider restoring kernel.pid_max to %s: sysctl -w kernel.pid_max=%s", oldVal, oldVal)
	case "cpu.governor":
		return fmt.Sprintf("consider restoring CPU frequency governor to '%s' (e.g. echo %s > /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor)", oldVal, oldVal)
	default:
		if oldVal != "" {
			return fmt.Sprintf("consider restoring %s to its previous value '%s' (verify with: sysctl %s)", key, oldVal, key)
		}
		return fmt.Sprintf("consider restoring %s to its previous baseline value (verify with: sysctl %s)", key, key)
	}
}
