package engine

import (
	"fmt"

	"github.com/ftahirops/xtop/model"
)

// BuildUSEChecklist generates Brendan Gregg's USE method checks from the current
// snapshot and rates: for every resource, check Utilization, Saturation, Errors.
func BuildUSEChecklist(snap *model.Snapshot, rates *model.RateSnapshot) []model.USECheck {
	var checks []model.USECheck

	// --- CPU ---
	cpuUtil := float64(0)
	if rates != nil {
		cpuUtil = rates.CPUBusyPct
	}
	nCPU := snap.Global.CPU.NumCPUs
	if nCPU == 0 {
		nCPU = 1
	}
	rqRatio := float64(snap.Global.CPU.LoadAvg.Running) / float64(nCPU) * 100
	cpuSat := rqRatio
	cpuPSI := snap.Global.PSI.CPU.Some.Avg10

	checks = append(checks, model.USECheck{
		Resource:    "CPU",
		Utilization: cpuUtil,
		Saturation:  cpuSat,
		Errors:      cpuPSI,
		UtilStatus:  useStatus(cpuUtil, 70, 90),
		SatStatus:   useStatus(cpuSat, 100, 200),
		ErrStatus:   useStatus(cpuPSI, 5, 25),
		UtilDetail:  fmt.Sprintf("%.1f%% busy", cpuUtil),
		SatDetail:   fmt.Sprintf("runqueue %d/%d (%.0f%%)", snap.Global.CPU.LoadAvg.Running, nCPU, rqRatio),
		ErrDetail:   fmt.Sprintf("PSI %.1f%%", cpuPSI),
	})

	// --- Memory ---
	memUtil := float64(0)
	if snap.Global.Memory.Total > 0 {
		memUtil = float64(snap.Global.Memory.Total-snap.Global.Memory.Available) / float64(snap.Global.Memory.Total) * 100
	}
	memSat := float64(0)
	if snap.Global.Memory.SwapTotal > 0 {
		memSat = float64(snap.Global.Memory.SwapUsed) / float64(snap.Global.Memory.SwapTotal) * 100
	}
	memPSI := snap.Global.PSI.Memory.Some.Avg10

	checks = append(checks, model.USECheck{
		Resource:    "Memory",
		Utilization: memUtil,
		Saturation:  memSat,
		Errors:      memPSI,
		UtilStatus:  useStatus(memUtil, 80, 95),
		SatStatus:   useStatus(memSat, 30, 70),
		ErrStatus:   useStatus(memPSI, 5, 25),
		UtilDetail:  fmt.Sprintf("%.1f%% used (%s free)", memUtil, useFmtBytes(snap.Global.Memory.Available)),
		SatDetail:   fmt.Sprintf("%.1f%% swap used", memSat),
		ErrDetail:   fmt.Sprintf("PSI %.1f%%", memPSI),
	})

	// --- Disk (worst device by utilization) ---
	ioUtil := float64(0)
	ioSat := float64(0)
	ioPSI := snap.Global.PSI.IO.Some.Avg10
	ioName := ""
	ioAwait := float64(0)
	if rates != nil {
		for _, d := range rates.DiskRates {
			if d.UtilPct > ioUtil {
				ioUtil = d.UtilPct
				ioSat = float64(d.QueueDepth)
				ioName = d.Name
				ioAwait = d.AvgAwaitMs
			}
		}
	}

	diskResource := "Disk"
	if ioName != "" {
		diskResource = "Disk " + ioName
	}
	checks = append(checks, model.USECheck{
		Resource:    diskResource,
		Utilization: ioUtil,
		Saturation:  ioSat,
		Errors:      ioPSI,
		UtilStatus:  useStatus(ioUtil, 70, 90),
		SatStatus:   useStatus(ioSat, 4, 16),
		ErrStatus:   useStatus(ioPSI, 5, 25),
		UtilDetail:  fmt.Sprintf("%.1f%% util, %.1fms await", ioUtil, ioAwait),
		SatDetail:   fmt.Sprintf("queue depth %.0f", ioSat),
		ErrDetail:   fmt.Sprintf("PSI %.1f%%", ioPSI),
	})

	// --- Network ---
	totalDrops := float64(0)
	retrans := float64(0)
	if rates != nil {
		for _, nr := range rates.NetRates {
			totalDrops += nr.RxDropsPS + nr.TxDropsPS
		}
		retrans = rates.RetransRate
	}
	netErrors := totalDrops + retrans
	conntrackPct := float64(0)
	if snap.Global.Conntrack.Max > 0 {
		conntrackPct = float64(snap.Global.Conntrack.Count) / float64(snap.Global.Conntrack.Max) * 100
	}

	checks = append(checks, model.USECheck{
		Resource:    "Network",
		Utilization: 0,
		Saturation:  conntrackPct,
		Errors:      netErrors,
		UtilStatus:  "ok", // can't measure without link speed info
		SatStatus:   useStatus(conntrackPct, 70, 90),
		ErrStatus:   useStatusCount(netErrors, 1, 100),
		UtilDetail:  "N/A (no link speed)",
		SatDetail:   fmt.Sprintf("conntrack %.0f%%", conntrackPct),
		ErrDetail:   fmt.Sprintf("drops %.0f/s, retrans %.0f/s", totalDrops, retrans),
	})

	return checks
}

// useStatus classifies a percentage metric into ok/warn/crit.
func useStatus(val, warn, crit float64) string {
	if val >= crit {
		return "crit"
	}
	if val >= warn {
		return "warn"
	}
	return "ok"
}

// useStatusCount classifies a count/rate metric into ok/warn/crit.
func useStatusCount(val, warn, crit float64) string {
	if val >= crit {
		return "crit"
	}
	if val >= warn {
		return "warn"
	}
	return "ok"
}

// useFmtBytes formats bytes into a short human-readable string.
func useFmtBytes(b uint64) string {
	const gb = 1024 * 1024 * 1024
	const mb = 1024 * 1024
	if b >= gb {
		return fmt.Sprintf("%.1fG", float64(b)/float64(gb))
	}
	if b >= mb {
		return fmt.Sprintf("%.0fM", float64(b)/float64(mb))
	}
	return fmt.Sprintf("%dK", b/1024)
}
