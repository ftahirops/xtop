package collector

import (
	"strconv"
	"strings"

	"github.com/ftahirops/xtop/model"
	"github.com/ftahirops/xtop/util"
)

// parseHex64 parses a hex string to uint64, returning 0 on error.
func parseHex64(s string) uint64 {
	v, _ := strconv.ParseUint(strings.TrimSpace(s), 16, 64)
	return v
}

// SysctlCollector reads conntrack stats and FD usage.
type SysctlCollector struct{}

func (s *SysctlCollector) Name() string { return "sysctl" }

func (s *SysctlCollector) Collect(snap *model.Snapshot) error {
	s.collectConntrack(snap)
	s.collectFD(snap)
	return nil
}

func (s *SysctlCollector) collectConntrack(snap *model.Snapshot) {
	ct := &snap.Global.Conntrack
	if v, err := util.ReadFileString("/proc/sys/net/netfilter/nf_conntrack_count"); err == nil {
		ct.Count = util.ParseUint64(strings.TrimSpace(v))
	}
	if v, err := util.ReadFileString("/proc/sys/net/netfilter/nf_conntrack_max"); err == nil {
		ct.Max = util.ParseUint64(strings.TrimSpace(v))
	}
	// /proc/net/stat/nf_conntrack has additional counters
	lines, err := util.ReadFileLines("/proc/net/stat/nf_conntrack")
	if err != nil {
		return
	}
	// Sum across CPUs (skip header), columns: entries searched found new invalid ignore delete ...
	for _, line := range lines[1:] {
		fields := strings.Fields(line)
		if len(fields) < 8 {
			continue
		}
		// #24: nf_conntrack stat file uses hex values
		ct.Found += parseHex64(fields[2])
		ct.Invalid += parseHex64(fields[4])
		ct.Insert += parseHex64(fields[5])
		ct.Delete += parseHex64(fields[7])
	}
}

func (s *SysctlCollector) collectFD(snap *model.Snapshot) {
	// /proc/sys/fs/file-nr: allocated  free(unused)  max
	content, err := util.ReadFileString("/proc/sys/fs/file-nr")
	if err != nil {
		return
	}
	fields := strings.Fields(content)
	if len(fields) >= 3 {
		snap.Global.FD.Allocated = util.ParseUint64(fields[0])
		snap.Global.FD.Max = util.ParseUint64(fields[2])
	}
}
