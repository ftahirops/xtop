// Package configdrift provides a curated snapshot of RCA-relevant OS/kernel
// configuration keys for config-drift detection (Phase 4).
//
// This file is tagless: ConfigKey, Keys, and pure parse helpers work on all
// platforms so unit tests can run without a Linux build tag.
package configdrift

import "strings"

// ConfigKey describes a single curated configuration entry.
type ConfigKey struct {
	Name   string // logical name, e.g. "vm.swappiness"
	Domain string // RCA domain: "memory"|"cpu"|"network"|"io"|"limits"
	Path   string // file to read, e.g. "/proc/sys/vm/swappiness"
	// Parse normalises the raw file content into a canonical value string.
	// Default is strings.TrimSpace. Pure functions only — no I/O.
	Parse func(raw string) string
}

// trimSpace is the default normaliser.
func trimSpace(s string) string { return strings.TrimSpace(s) }

// ParseTHP parses a Linux transparent-hugepage "enabled" file whose content
// looks like "always [madvise] never". It returns the bracketed token, or the
// trimmed whole string when no brackets are present.
// Exported so it is unit-testable without a Linux build tag.
func ParseTHP(raw string) string {
	s := strings.TrimSpace(raw)
	start := strings.IndexByte(s, '[')
	end := strings.IndexByte(s, ']')
	if start >= 0 && end > start {
		return s[start+1 : end]
	}
	return s
}

// Keys is the curated registry of RCA-relevant config entries.
// Keep this list focused; every key here must be meaningful to the RCA engine.
var Keys = []ConfigKey{
	// ── memory ──────────────────────────────────────────────────────────────
	{
		Name:   "vm.swappiness",
		Domain: "memory",
		Path:   "/proc/sys/vm/swappiness",
		Parse:  trimSpace,
	},
	{
		Name:   "vm.overcommit_memory",
		Domain: "memory",
		Path:   "/proc/sys/vm/overcommit_memory",
		Parse:  trimSpace,
	},
	{
		Name:   "vm.dirty_ratio",
		Domain: "memory",
		Path:   "/proc/sys/vm/dirty_ratio",
		Parse:  trimSpace,
	},
	{
		Name:   "vm.max_map_count",
		Domain: "memory",
		Path:   "/proc/sys/vm/max_map_count",
		Parse:  trimSpace,
	},
	{
		Name:   "thp.enabled",
		Domain: "memory",
		Path:   "/sys/kernel/mm/transparent_hugepage/enabled",
		Parse:  ParseTHP,
	},
	// ── network ─────────────────────────────────────────────────────────────
	{
		Name:   "net.core.somaxconn",
		Domain: "network",
		Path:   "/proc/sys/net/core/somaxconn",
		Parse:  trimSpace,
	},
	{
		Name:   "net.ipv4.tcp_tw_reuse",
		Domain: "network",
		Path:   "/proc/sys/net/ipv4/tcp_tw_reuse",
		Parse:  trimSpace,
	},
	{
		Name:   "net.ipv4.ip_local_port_range",
		Domain: "network",
		Path:   "/proc/sys/net/ipv4/ip_local_port_range",
		Parse:  trimSpace,
	},
	{
		Name:   "net.netfilter.nf_conntrack_max",
		Domain: "network",
		Path:   "/proc/sys/net/netfilter/nf_conntrack_max",
		Parse:  trimSpace,
	},
	// ── cpu ─────────────────────────────────────────────────────────────────
	{
		// May be absent on VMs / kernels without cpufreq — handled gracefully
		// in Snapshot() by skipping missing files.
		Name:   "cpu.governor",
		Domain: "cpu",
		Path:   "/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor",
		Parse:  trimSpace,
	},
}
