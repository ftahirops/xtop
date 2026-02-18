package cgroup

import (
	"path/filepath"
	"strings"

	"github.com/ftahirops/xtop/model"
	"github.com/ftahirops/xtop/util"
)

// readV1CPU reads cgroup v1 CPU metrics.
func readV1CPU(cgDir string, cg *model.CgroupMetrics) {
	// cpuacct.usage (nanoseconds)
	if s, err := util.ReadFileString(filepath.Join(cgDir, "cpuacct.usage")); err == nil {
		cg.UsageUsec = util.ParseUint64(strings.TrimSpace(s)) / 1000 // ns → µs
	}

	// cpuacct.stat (user/system in USER_HZ ticks)
	if kv, err := util.ParseKeyValueFile(filepath.Join(cgDir, "cpuacct.stat")); err == nil {
		// Convert from ticks (USER_HZ=100) to microseconds
		cg.UserUsec = util.ParseUint64(kv["user"]) * 10000   // 1 tick = 10ms = 10000µs
		cg.SystemUsec = util.ParseUint64(kv["system"]) * 10000
	}

	// cpu.stat (for throttling)
	if kv, err := util.ParseKeyValueFile(filepath.Join(cgDir, "cpu.stat")); err == nil {
		cg.NrThrottled = util.ParseUint64(kv["nr_throttled"])
		cg.NrPeriods = util.ParseUint64(kv["nr_periods"])
		cg.ThrottledUsec = util.ParseUint64(kv["throttled_time"]) / 1000 // ns → µs
	}
}

// readV1Memory reads cgroup v1 memory metrics.
func readV1Memory(cgDir string, cg *model.CgroupMetrics) {
	// memory.usage_in_bytes
	if s, err := util.ReadFileString(filepath.Join(cgDir, "memory.usage_in_bytes")); err == nil {
		cg.MemCurrent = util.ParseUint64(strings.TrimSpace(s))
	}

	// memory.limit_in_bytes
	if s, err := util.ReadFileString(filepath.Join(cgDir, "memory.limit_in_bytes")); err == nil {
		v := util.ParseUint64(strings.TrimSpace(s))
		// v1 uses a very large number to mean "no limit"
		if v < 1<<62 {
			cg.MemLimit = v
		}
	}

	// memory.memsw.usage_in_bytes
	if s, err := util.ReadFileString(filepath.Join(cgDir, "memory.memsw.usage_in_bytes")); err == nil {
		cg.MemSwap = util.ParseUint64(strings.TrimSpace(s))
	}

	// memory.oom_control
	if kv, err := util.ParseKeyValueFile(filepath.Join(cgDir, "memory.oom_control")); err == nil {
		cg.OOMKills = util.ParseUint64(kv["oom_kill"])
	}

	// memory.stat
	if kv, err := util.ParseKeyValueFile(filepath.Join(cgDir, "memory.stat")); err == nil {
		cg.PgFault = util.ParseUint64(kv["pgfault"])
		cg.PgMajFault = util.ParseUint64(kv["pgmajfault"])
	}
}
