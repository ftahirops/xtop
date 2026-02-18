package engine

import (
	"fmt"
	"path"

	"github.com/ftahirops/xtop/model"
)

// SuggestActions recommends actions based on the primary bottleneck and evidence.
func SuggestActions(result *model.AnalysisResult) []model.Action {
	if result.PrimaryScore < 20 {
		return nil
	}

	var actions []model.Action

	// Find the primary RCA entry for detailed checks
	var primary *model.RCAEntry
	for i := range result.RCA {
		if result.RCA[i].Bottleneck == result.PrimaryBottleneck {
			primary = &result.RCA[i]
			break
		}
	}

	switch result.PrimaryBottleneck {
	case BottleneckIO:
		actions = append(actions,
			model.Action{Summary: "Identify IO-heavy processes", Command: "iotop -oP -d 2"},
			model.Action{Summary: "Check disk queue depth and latency", Command: "iostat -xz 1 5"},
		)
		// Context-specific actions
		if primary != nil {
			for _, c := range primary.Checks {
				if !c.Passed {
					continue
				}
				switch c.Group {
				case "Dirty pages":
					actions = append(actions,
						model.Action{Summary: "Check for large write bursts or backup jobs", Command: "grep -r . /proc/sys/vm/dirty_*"},
						model.Action{Summary: "Reduce dirty page pressure", Command: "sysctl vm.dirty_ratio=10 vm.dirty_background_ratio=5"},
					)
				}
			}
		}
		if result.PrimaryCulprit != "" {
			actions = append(actions,
				model.Action{Summary: fmt.Sprintf("Inspect IO limits for %s", cleanCgroupName(result.PrimaryCulprit)),
					Command: "cat " + path.Join("/sys/fs/cgroup", result.PrimaryCulprit, "io.max")},
			)
		}
		if result.PrimaryProcess != "" {
			actions = append(actions,
				model.Action{Summary: fmt.Sprintf("Check what %s is writing", result.PrimaryProcess),
					Command: fmt.Sprintf("ls -la /proc/%d/fd/ 2>/dev/null | head -30", result.PrimaryPID)},
			)
		}

	case BottleneckMemory:
		actions = append(actions,
			model.Action{Summary: "Check top memory consumers", Command: "ps aux --sort=-rss | head -20"},
		)
		if primary != nil {
			for _, c := range primary.Checks {
				if !c.Passed {
					continue
				}
				switch c.Group {
				case "Swap active":
					actions = append(actions,
						model.Action{Summary: "Check swap IO pressure", Command: "vmstat 1 5"},
						model.Action{Summary: "Find swapped-out processes", Command: "awk '/VmSwap/{if($2>0)print FILENAME,$2}' /proc/*/status 2>/dev/null | sort -k2 -rn | head -10"},
					)
				case "Direct reclaim":
					actions = append(actions,
						model.Action{Summary: "Check reclaim activity", Command: "grep -E 'pgsteal|pgscan|pgmajfault' /proc/vmstat"},
					)
				case "OOM":
					actions = append(actions,
						model.Action{Summary: "Check OOM kills", Command: "dmesg -T | grep -i 'out of memory' | tail -5"},
					)
				}
			}
		}
		if result.PrimaryCulprit != "" {
			actions = append(actions,
				model.Action{Summary: fmt.Sprintf("Check memory limit for %s", cleanCgroupName(result.PrimaryCulprit)),
					Command: "cat " + path.Join("/sys/fs/cgroup", result.PrimaryCulprit, "memory.max")},
			)
		}

	case BottleneckCPU:
		actions = append(actions,
			model.Action{Summary: "Check top CPU consumers", Command: "ps -eo pid,comm,stat,ni,%cpu --sort=-%cpu | head -20"},
		)
		if primary != nil {
			for _, c := range primary.Checks {
				if !c.Passed {
					continue
				}
				switch c.Group {
				case "Run queue":
					actions = append(actions,
						model.Action{Summary: "Check run queue depth", Command: "sar -q 1 5 2>/dev/null || vmstat 1 5"},
					)
				case "Throttling":
					actions = append(actions,
						model.Action{Summary: "Check cgroup CPU throttling", Command: "find /sys/fs/cgroup -name cpu.stat -exec grep -l throttled {} \\; | head -5"},
					)
				case "Steal":
					actions = append(actions,
						model.Action{Summary: "Check hypervisor CPU steal (VM contention)", Command: "mpstat -P ALL 1 3"},
					)
				}
			}
		}
		if result.PrimaryCulprit != "" {
			actions = append(actions,
				model.Action{Summary: fmt.Sprintf("Check CPU quota for %s", cleanCgroupName(result.PrimaryCulprit)),
					Command: "cat " + path.Join("/sys/fs/cgroup", result.PrimaryCulprit, "cpu.max")},
			)
		}

	case BottleneckNetwork:
		actions = append(actions,
			model.Action{Summary: "Check connection state summary", Command: "ss -s"},
			model.Action{Summary: "Check for drops and retransmits", Command: "nstat -az | grep -iE 'drop|retrans|overflow'"},
		)
		if primary != nil {
			for _, c := range primary.Checks {
				if !c.Passed {
					continue
				}
				switch c.Group {
				case "Drops":
					actions = append(actions,
						model.Action{Summary: "Check interface ring buffer (increase if drops)", Command: "ethtool -g eth0 2>/dev/null"},
					)
				case "Conntrack":
					actions = append(actions,
						model.Action{Summary: "Increase conntrack table size", Command: "sysctl net.nf_conntrack_max"},
					)
				case "TCP states":
					actions = append(actions,
						model.Action{Summary: "Check TIME_WAIT and ephemeral port pressure", Command: "ss -tan state time-wait | wc -l"},
						model.Action{Summary: "Enable TIME_WAIT reuse if needed", Command: "sysctl net.ipv4.tcp_tw_reuse=1"},
					)
				}
			}
		}
	}

	// Exhaustion-specific actions
	for _, ex := range result.Exhaustions {
		switch ex.Resource {
		case "Memory":
			actions = append(actions,
				model.Action{Summary: fmt.Sprintf("Memory exhaustion in ~%.0fm — identify leak or increase RAM", ex.EstMinutes)})
		case "Swap":
			actions = append(actions,
				model.Action{Summary: fmt.Sprintf("Swap exhaustion in ~%.0fm — reduce memory pressure", ex.EstMinutes)})
		case "Ephemeral ports":
			actions = append(actions,
				model.Action{Summary: fmt.Sprintf("Port exhaustion in ~%.0fm — check connection churn", ex.EstMinutes),
					Command: "ss -tan state time-wait | wc -l"})
		case "File descriptors":
			actions = append(actions,
				model.Action{Summary: fmt.Sprintf("FD exhaustion in ~%.0fm — check for FD leaks", ex.EstMinutes),
					Command: "ls /proc/*/fd 2>/dev/null | wc -l"})
		}
	}

	return actions
}
