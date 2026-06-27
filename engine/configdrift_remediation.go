package engine

import "fmt"

// suggestedRemediation returns a human-readable suggested fix string for a known
// kernel param key whose value drifted from the given oldVal to newVal.
//
// IMPORTANT: this function ONLY returns a text string. It never executes any
// command, writes to /proc/sys, /sys, sysctl, or any other file. The caller
// is responsible for surfacing this text as a suggestion in the UI/narrative.
func suggestedRemediation(key, oldVal, newVal string) string {
	switch key {
	case "vm.swappiness":
		return fmt.Sprintf("consider restoring vm.swappiness from %s to %s: sysctl -w vm.swappiness=%s", newVal, oldVal, oldVal)
	case "vm.overcommit_memory":
		return fmt.Sprintf("consider restoring vm.overcommit_memory from %s to %s: sysctl -w vm.overcommit_memory=%s", newVal, oldVal, oldVal)
	case "vm.dirty_ratio":
		return fmt.Sprintf("consider restoring vm.dirty_ratio from %s to %s: sysctl -w vm.dirty_ratio=%s", newVal, oldVal, oldVal)
	case "vm.max_map_count":
		return fmt.Sprintf("consider restoring vm.max_map_count from %s to %s: sysctl -w vm.max_map_count=%s", newVal, oldVal, oldVal)
	case "thp.enabled":
		return fmt.Sprintf("consider restoring transparent hugepages from '%s' to '%s' (check /sys/kernel/mm/transparent_hugepage/enabled)", newVal, oldVal)
	case "net.core.somaxconn":
		return fmt.Sprintf("consider restoring net.core.somaxconn from %s to %s: sysctl -w net.core.somaxconn=%s", newVal, oldVal, oldVal)
	case "net.ipv4.tcp_tw_reuse":
		return fmt.Sprintf("consider restoring net.ipv4.tcp_tw_reuse from %s to %s: sysctl -w net.ipv4.tcp_tw_reuse=%s", newVal, oldVal, oldVal)
	case "net.ipv4.ip_local_port_range":
		return fmt.Sprintf("consider restoring net.ipv4.ip_local_port_range from '%s' to '%s': sysctl -w net.ipv4.ip_local_port_range='%s'", newVal, oldVal, oldVal)
	case "net.netfilter.nf_conntrack_max":
		return fmt.Sprintf("consider restoring net.netfilter.nf_conntrack_max from %s to %s: sysctl -w net.netfilter.nf_conntrack_max=%s", newVal, oldVal, oldVal)
	case "kernel.pid_max":
		return fmt.Sprintf("consider restoring kernel.pid_max from %s to %s: sysctl -w kernel.pid_max=%s", newVal, oldVal, oldVal)
	case "cpu.governor":
		return fmt.Sprintf("consider restoring CPU frequency governor from '%s' to '%s' (e.g. echo %s > /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor)", newVal, oldVal, oldVal)
	default:
		if oldVal != "" {
			return fmt.Sprintf("consider restoring %s from '%s' to its previous value '%s' (verify with: sysctl %s)", key, newVal, oldVal, key)
		}
		return fmt.Sprintf("consider restoring %s to its previous baseline value (verify with: sysctl %s)", key, key)
	}
}
