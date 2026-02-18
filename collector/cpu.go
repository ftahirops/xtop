package collector

import (
	"fmt"
	"strings"

	"github.com/ftahirops/xtop/model"
	"github.com/ftahirops/xtop/util"
)

// CPUCollector reads /proc/stat and /proc/loadavg.
type CPUCollector struct{}

func (c *CPUCollector) Name() string { return "cpu" }

func (c *CPUCollector) Collect(snap *model.Snapshot) error {
	if err := c.collectStat(snap); err != nil {
		return err
	}
	return c.collectLoadAvg(snap)
}

func (c *CPUCollector) collectStat(snap *model.Snapshot) error {
	lines, err := util.ReadFileLines("/proc/stat")
	if err != nil {
		return fmt.Errorf("read /proc/stat: %w", err)
	}

	var perCPU []model.CPUTimes
	for _, line := range lines {
		if strings.HasPrefix(line, "cpu ") {
			snap.Global.CPU.Total = parseCPULine(line)
		} else if strings.HasPrefix(line, "cpu") {
			perCPU = append(perCPU, parseCPULine(line))
		}
	}
	snap.Global.CPU.PerCPU = perCPU
	snap.Global.CPU.NumCPUs = len(perCPU)
	return nil
}

func parseCPULine(line string) model.CPUTimes {
	fields := strings.Fields(line)
	// fields[0] = "cpu" or "cpu0", fields[1..] = user nice system idle iowait irq softirq steal guest guest_nice
	var ct model.CPUTimes
	if len(fields) >= 2 {
		ct.User = util.ParseUint64(fields[1])
	}
	if len(fields) >= 3 {
		ct.Nice = util.ParseUint64(fields[2])
	}
	if len(fields) >= 4 {
		ct.System = util.ParseUint64(fields[3])
	}
	if len(fields) >= 5 {
		ct.Idle = util.ParseUint64(fields[4])
	}
	if len(fields) >= 6 {
		ct.IOWait = util.ParseUint64(fields[5])
	}
	if len(fields) >= 7 {
		ct.IRQ = util.ParseUint64(fields[6])
	}
	if len(fields) >= 8 {
		ct.SoftIRQ = util.ParseUint64(fields[7])
	}
	if len(fields) >= 9 {
		ct.Steal = util.ParseUint64(fields[8])
	}
	if len(fields) >= 10 {
		ct.Guest = util.ParseUint64(fields[9])
	}
	if len(fields) >= 11 {
		ct.GuestNice = util.ParseUint64(fields[10])
	}
	return ct
}

func (c *CPUCollector) collectLoadAvg(snap *model.Snapshot) error {
	content, err := util.ReadFileString("/proc/loadavg")
	if err != nil {
		return fmt.Errorf("read /proc/loadavg: %w", err)
	}
	fields := strings.Fields(content)
	if len(fields) < 5 {
		return fmt.Errorf("unexpected /proc/loadavg format")
	}
	snap.Global.CPU.LoadAvg.Load1 = util.ParseFloat64(fields[0])
	snap.Global.CPU.LoadAvg.Load5 = util.ParseFloat64(fields[1])
	snap.Global.CPU.LoadAvg.Load15 = util.ParseFloat64(fields[2])

	// fields[3] = "running/total"
	parts := strings.SplitN(fields[3], "/", 2)
	if len(parts) == 2 {
		snap.Global.CPU.LoadAvg.Running = util.ParseUint64(parts[0])
		snap.Global.CPU.LoadAvg.Total = util.ParseUint64(parts[1])
	}
	return nil
}
