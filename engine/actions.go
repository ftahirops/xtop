package engine

import (
	"path"

	"github.com/ftahirops/xtop/model"
)

// SuggestActions recommends actions based on the primary bottleneck.
func SuggestActions(result *model.AnalysisResult) []model.Action {
	if result.PrimaryScore < 20 {
		return nil
	}

	var actions []model.Action

	switch result.PrimaryBottleneck {
	case BottleneckIO:
		actions = append(actions,
			model.Action{Summary: "Investigate IO-heavy processes", Command: "iotop -oP"},
			model.Action{Summary: "Check disk queue and latency", Command: "iostat -xz 1 5"},
		)
		if result.PrimaryCulprit != "" {
			actions = append(actions,
				model.Action{Summary: "Inspect cgroup IO limits", Command: "cat " + path.Join("/sys/fs/cgroup", result.PrimaryCulprit, "io.max")},
			)
		}
	case BottleneckMemory:
		actions = append(actions,
			model.Action{Summary: "Check top memory consumers", Command: "ps aux --sort=-rss | head -20"},
			model.Action{Summary: "Check swap and reclaim", Command: "vmstat 1 5"},
		)
		if result.PrimaryCulprit != "" {
			actions = append(actions,
				model.Action{Summary: "Check cgroup memory limit", Command: "cat " + path.Join("/sys/fs/cgroup", result.PrimaryCulprit, "memory.max")},
			)
		}
	case BottleneckCPU:
		actions = append(actions,
			model.Action{Summary: "Check runnable threads", Command: "ps -eo pid,comm,stat,ni,%cpu --sort=-%cpu | head -20"},
		)
		if result.PrimaryCulprit != "" {
			actions = append(actions,
				model.Action{Summary: "Check cgroup CPU quota", Command: "cat " + path.Join("/sys/fs/cgroup", result.PrimaryCulprit, "cpu.max")},
			)
		}
	case BottleneckNetwork:
		actions = append(actions,
			model.Action{Summary: "Check network stats and errors", Command: "ss -s"},
			model.Action{Summary: "Check for drops and retransmits", Command: "nstat -az | grep -i -E 'drop|retrans|overflow'"},
		)
	}

	return actions
}
