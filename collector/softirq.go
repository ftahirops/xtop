package collector

import (
	"strings"

	"github.com/ftahirops/xtop/model"
	"github.com/ftahirops/xtop/util"
)

// SoftIRQCollector reads /proc/softirqs.
type SoftIRQCollector struct{}

func (s *SoftIRQCollector) Name() string { return "softirq" }

func (s *SoftIRQCollector) Collect(snap *model.Snapshot) error {
	lines, err := util.ReadFileLines("/proc/softirqs")
	if err != nil {
		return nil // non-fatal
	}
	si := &snap.Global.SoftIRQ
	for _, line := range lines[1:] { // skip header (CPU columns)
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		label := strings.TrimSuffix(fields[0], ":")
		// Sum across all CPUs
		var total uint64
		for _, f := range fields[1:] {
			total += util.ParseUint64(f)
		}
		switch label {
		case "HI":
			si.HI = total
		case "TIMER":
			si.TIMER = total
		case "NET_TX":
			si.NET_TX = total
		case "NET_RX":
			si.NET_RX = total
		case "BLOCK":
			si.BLOCK = total
		case "IRQ_POLL":
			si.IRQ_POLL = total
		case "TASKLET":
			si.TASKLET = total
		case "SCHED":
			si.SCHED = total
		case "HRTIMER":
			si.HRTIMER = total
		case "RCU":
			si.RCU = total
		}
	}
	return nil
}
