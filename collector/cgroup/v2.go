package cgroup

import (
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/ftahirops/xtop/model"
	"github.com/ftahirops/xtop/util"
)

// readV2Metrics reads cgroup v2 metrics from the given cgroup directory.
func readV2Metrics(cgDir string) model.CgroupMetrics {
	var cg model.CgroupMetrics

	// cpu.stat
	if kv, err := util.ParseKeyValueFile(filepath.Join(cgDir, "cpu.stat")); err == nil {
		cg.UsageUsec = util.ParseUint64(kv["usage_usec"])
		cg.UserUsec = util.ParseUint64(kv["user_usec"])
		cg.SystemUsec = util.ParseUint64(kv["system_usec"])
		cg.ThrottledUsec = util.ParseUint64(kv["throttled_usec"])
		cg.NrThrottled = util.ParseUint64(kv["nr_throttled"])
		cg.NrPeriods = util.ParseUint64(kv["nr_periods"])
	}

	// memory.current
	if s, err := util.ReadFileString(filepath.Join(cgDir, "memory.current")); err == nil {
		cg.MemCurrent = util.ParseUint64(strings.TrimSpace(s))
	}

	// memory.max (limit)
	if s, err := util.ReadFileString(filepath.Join(cgDir, "memory.max")); err == nil {
		s = strings.TrimSpace(s)
		if s != "max" {
			cg.MemLimit = util.ParseUint64(s)
		}
	}

	// memory.swap.current
	if s, err := util.ReadFileString(filepath.Join(cgDir, "memory.swap.current")); err == nil {
		cg.MemSwap = util.ParseUint64(strings.TrimSpace(s))
	}

	// memory.events (for OOM kills)
	if kv, err := util.ParseKeyValueFile(filepath.Join(cgDir, "memory.events")); err == nil {
		cg.OOMKills = util.ParseUint64(kv["oom_kill"])
		cg.PgFault = util.ParseUint64(kv["pgfault"])     // not always in events
		cg.PgMajFault = util.ParseUint64(kv["pgmajfault"]) // not always in events
	}

	// memory.stat (alternative source for pgfault)
	if cg.PgFault == 0 {
		if kv, err := util.ParseKeyValueFile(filepath.Join(cgDir, "memory.stat")); err == nil {
			cg.PgFault = util.ParseUint64(kv["pgfault"])
			cg.PgMajFault = util.ParseUint64(kv["pgmajfault"])
		}
	}

	// io.stat
	readV2IO(filepath.Join(cgDir, "io.stat"), &cg)

	// pids.current / pids.max
	if s, err := util.ReadFileString(filepath.Join(cgDir, "pids.current")); err == nil {
		cg.PIDCount = util.ParseUint64(strings.TrimSpace(s))
	}
	if s, err := util.ReadFileString(filepath.Join(cgDir, "pids.max")); err == nil {
		s = strings.TrimSpace(s)
		if s != "max" {
			cg.PIDLimit = util.ParseUint64(s)
		}
	}

	return cg
}

// readV2IO parses io.stat. Format per line: "MAJ:MIN rbytes=N wbytes=N rios=N wios=N"
func readV2IO(path string, cg *model.CgroupMetrics) {
	lines, err := util.ReadFileLines(path)
	if err != nil {
		return
	}
	sumV2IOLines(lines, isLayeredMajMin, cg)
}

// sumV2IOLines accumulates io.stat rows into cg, skipping layered
// (device-mapper) rows: on LVM hosts io.stat reports the SAME bytes at both
// the dm row (252:0) and the physical row (8:0), so summing all rows doubled
// every cgroup's IO and the Top-writer attribution built on it.
func sumV2IOLines(lines []string, isLayered func(majmin string) bool, cg *model.CgroupMetrics) {
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		if isLayered(fields[0]) {
			continue
		}
		for _, f := range fields[1:] {
			parts := strings.SplitN(f, "=", 2)
			if len(parts) != 2 {
				continue
			}
			v := util.ParseUint64(parts[1])
			switch parts[0] {
			case "rbytes":
				cg.IORBytes += v
			case "wbytes":
				cg.IOWBytes += v
			case "rios":
				cg.IORIOs += v
			case "wios":
				cg.IOWIOs += v
			}
		}
	}
}

// layeredMajMin caches whether a MAJ:MIN is a device-mapper device
// (has /sys/dev/block/MAJ:MIN/dm). Device numbers are stable for the
// life of the host, so a grow-only cache is safe.
var (
	layeredMu    sync.Mutex
	layeredCache = map[string]bool{}
)

func isLayeredMajMin(majmin string) bool {
	layeredMu.Lock()
	v, ok := layeredCache[majmin]
	layeredMu.Unlock()
	if ok {
		return v
	}
	_, err := os.Stat("/sys/dev/block/" + majmin + "/dm")
	layered := err == nil
	layeredMu.Lock()
	layeredCache[majmin] = layered
	layeredMu.Unlock()
	return layered
}
