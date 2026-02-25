package ui

import (
	"fmt"
	"sort"
	"strings"

	"github.com/ftahirops/xtop/model"
)

type cgSort int

const (
	cgSortCPU cgSort = iota
	cgSortThrottle
	cgSortMem
	cgSortOOM
	cgSortIO
	cgSortCount
)

var cgSortNames = []string{"CPU%", "Throttle%", "Mem", "OOM", "IO"}

func renderCgroupPage(snap *model.Snapshot, rates *model.RateSnapshot, result *model.AnalysisResult, pm probeQuerier, sortCol cgSort, selected int, width, height int) string {
	var sb strings.Builder
	iw := pageInnerW(width)

	sortName := "CPU%"
	if int(sortCol) < len(cgSortNames) {
		sortName = cgSortNames[sortCol]
	}
	sb.WriteString(titleStyle.Render(fmt.Sprintf("CGROUPS  (sort: %s, %d total)", sortName, len(snap.Cgroups))))
	sb.WriteString("\n")
	sb.WriteString(renderRCAInline(result))
	sb.WriteString(renderProbeStatusLine(pm, snap))
	sb.WriteString("\n")

	// Build merged view: cgroup metrics + rates
	type cgRow struct {
		name     string
		path     string
		cpuPct   float64
		thrPct   float64
		memBytes uint64
		memPct   float64
		oomKills uint64
		ioRMBs   float64
		ioWMBs   float64
		pids     uint64
	}

	rateMap := make(map[string]model.CgroupRate)
	if rates != nil {
		for _, cr := range rates.CgroupRates {
			rateMap[cr.Path] = cr
		}
	}

	var rows []cgRow
	totalMem := snap.Global.Memory.Total
	if totalMem == 0 {
		totalMem = 1
	}
	for _, cg := range snap.Cgroups {
		r := cgRow{
			name:     cg.Name,
			path:     cg.Path,
			memBytes: cg.MemCurrent,
			memPct:   float64(cg.MemCurrent) / float64(totalMem) * 100,
			oomKills: cg.OOMKills,
			pids:     cg.PIDCount,
		}
		if cr, ok := rateMap[cg.Path]; ok {
			r.cpuPct = cr.CPUPct
			r.thrPct = cr.ThrottlePct
			r.ioRMBs = cr.IORateMBs
			r.ioWMBs = cr.IOWRateMBs
		}
		rows = append(rows, r)
	}

	// Sort
	sort.Slice(rows, func(i, j int) bool {
		switch sortCol {
		case cgSortCPU:
			return rows[i].cpuPct > rows[j].cpuPct
		case cgSortThrottle:
			return rows[i].thrPct > rows[j].thrPct
		case cgSortMem:
			return rows[i].memBytes > rows[j].memBytes
		case cgSortOOM:
			return rows[i].oomKills > rows[j].oomKills
		case cgSortIO:
			return (rows[i].ioRMBs + rows[i].ioWMBs) > (rows[j].ioRMBs + rows[j].ioWMBs)
		default:
			return rows[i].cpuPct > rows[j].cpuPct
		}
	})

	// Build table lines
	var tblLines []string
	tblLines = append(tblLines, dimStyle.Render(fmt.Sprintf("%-30s %7s %8s %8s %8s %4s %9s %9s %5s",
		"NAME", "CPU%", "THROT%", "MEM", "MEM%", "OOM", "IO_R MB/s", "IO_W MB/s", "PIDs")))

	maxRows := height - 8
	if maxRows < 5 {
		maxRows = 30
	}
	for i, r := range rows {
		if i >= maxRows {
			break
		}
		name := r.name
		if len(name) > 30 {
			name = name[:27] + "..."
		}
		row := fmt.Sprintf("%-30s %6.1f%% %7.1f%% %8s %7.1f%% %4d %9.2f %9.2f %5d",
			name, r.cpuPct, r.thrPct, fmtBytes(r.memBytes), r.memPct, r.oomKills, r.ioRMBs, r.ioWMBs, r.pids)
		if i == selected {
			tblLines = append(tblLines, selectedStyle.Render(row))
		} else if r.thrPct > 10 || r.oomKills > 0 {
			tblLines = append(tblLines, warnStyle.Render(row))
		} else {
			tblLines = append(tblLines, row)
		}
	}
	sb.WriteString(boxSection("ALL CGROUPS", tblLines, iw))

	sb.WriteString(dimStyle.Render("  [Enter] drilldown processes   [s] cycle sort   [j/k] scroll"))

	return sb.String()
}
