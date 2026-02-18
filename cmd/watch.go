package cmd

import (
	"fmt"
	"os"
	"os/signal"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/ftahirops/xtop/engine"
	"github.com/ftahirops/xtop/model"
)

// ── ANSI color/style codes ──────────────────────────────────────────────────

const (
	R  = "\033[0m"  // reset
	B  = "\033[1m"  // bold
	D  = "\033[2m"  // dim
	UL = "\033[4m"  // underline

	FRed  = "\033[31m"
	FGrn  = "\033[32m"
	FYel  = "\033[33m"
	FBlu  = "\033[34m"
	FCyn  = "\033[36m"

	FBRed = "\033[91m"
	FBGrn = "\033[92m"
	FBYel = "\033[93m"
	FBCyn = "\033[96m"
	FBWht = "\033[97m"

	BRed  = "\033[41m"
	BGrn  = "\033[42m"
	BBlu  = "\033[44m"
)

// ── Thresholds ──────────────────────────────────────────────────────────────

const (
	tPSIWarn        = 1.0
	tPSICrit        = 10.0
	tCPUWarn        = 70.0
	tCPUCrit        = 90.0
	tMemWarn        = 70.0
	tMemCrit        = 85.0
	tSwapWarn       = 20.0
	tDiskUtilWarn   = 60.0
	tDiskUtilCrit   = 85.0
	tDiskAwaitWarn  = 10.0
	tDiskAwaitCrit  = 50.0
	tConntrackWarn  = 75.0
	tTimeWaitWarn   = 1000
	tCloseWaitWarn  = 10
	tRetransWarn    = 5.0
	tRetransCrit    = 50.0
	tDropsWarn      = 1.0
	tMajFaultWarn   = 5.0
	tReclaimWarn    = 0.5
	tCapacityWarn   = 30.0
	tCapacityCrit   = 15.0
)

// ── Styling helpers ─────────────────────────────────────────────────────────

func cval(v float64, warn, crit float64) string {
	// Color a value: green if below warn, yellow if warn, red if crit
	switch {
	case v >= crit:
		return fmt.Sprintf("%s%s%.1f%s", B, FBRed, v, R)
	case v >= warn:
		return fmt.Sprintf("%s%.1f%s", FBYel, v, R)
	default:
		return fmt.Sprintf("%s%.1f%s", FBGrn, v, R)
	}
}

func cpsi(v float64) string {
	switch {
	case v >= tPSICrit:
		return fmt.Sprintf("%s%s%6.1f%%%s", B, FBRed, v, R)
	case v >= tPSIWarn:
		return fmt.Sprintf("%s%6.1f%%%s", FBYel, v, R)
	case v > 0.01:
		return fmt.Sprintf("%s%6.2f%%%s", FYel, v, R)
	default:
		return fmt.Sprintf("%s%6.1f%%%s", D, v, R)
	}
}

func cpct(v float64, warn, crit float64) string {
	switch {
	case v >= crit:
		return fmt.Sprintf("%s%s%6.1f%%%s", B, FBRed, v, R)
	case v >= warn:
		return fmt.Sprintf("%s%6.1f%%%s", FBYel, v, R)
	default:
		return fmt.Sprintf("%s%6.1f%%%s", FBGrn, v, R)
	}
}

func cpctInv(v float64, warn, crit float64) string {
	// Inverse: lower is worse (remaining capacity)
	switch {
	case v <= crit:
		return fmt.Sprintf("%s%s%6.1f%%%s", B, FBRed, v, R)
	case v <= warn:
		return fmt.Sprintf("%s%6.1f%%%s", FBYel, v, R)
	default:
		return fmt.Sprintf("%s%6.1f%%%s", FBGrn, v, R)
	}
}

func cint(v int, warn, crit int) string {
	switch {
	case v >= crit:
		return fmt.Sprintf("%s%s%d%s", B, FBRed, v, R)
	case v >= warn:
		return fmt.Sprintf("%s%d%s", FBYel, v, R)
	default:
		return fmt.Sprintf("%s%d%s", D, v, R)
	}
}

func cfloat(v float64, warn, crit float64) string {
	switch {
	case v >= crit:
		return fmt.Sprintf("%s%s%.1f%s", B, FBRed, v, R)
	case v >= warn:
		return fmt.Sprintf("%s%.1f%s", FBYel, v, R)
	default:
		return fmt.Sprintf("%s%.1f%s", D, v, R)
	}
}

func healthBadge(h model.HealthLevel) string {
	switch h {
	case model.HealthOK:
		return fmt.Sprintf(" %s%s OK %s", BGrn+B+FBWht, " ", R)
	case model.HealthInconclusive:
		return fmt.Sprintf(" %s%s INCONCLUSIVE %s", B+FBYel, " ", R)
	case model.HealthDegraded:
		return fmt.Sprintf(" %s%s DEGRADED %s", BRed+B+FBWht, " ", R)
	case model.HealthCritical:
		return fmt.Sprintf(" %s%s CRITICAL %s", BRed+B+FBWht, " ", R)
	default:
		return h.String()
	}
}

func warnTag() string { return fmt.Sprintf(" %s!%s", FBYel, R) }
func critTag() string { return fmt.Sprintf("%s%s!!%s", B, FBRed, R) }

func bar(pct float64, w int) string {
	if pct < 0 {
		pct = 0
	}
	if pct > 100 {
		pct = 100
	}
	filled := int(pct / 100.0 * float64(w))
	if filled > w {
		filled = w
	}
	empty := w - filled
	var c string
	switch {
	case pct >= 90:
		c = FBRed
	case pct >= 70:
		c = FBYel
	case pct >= 40:
		c = FYel
	default:
		c = FBGrn
	}
	return fmt.Sprintf("%s%s%s%s%s", c, strings.Repeat("#", filled), D, strings.Repeat("-", empty), R)
}

func barInv(pct float64, w int) string {
	// Inverted: 100%=good (green), 0%=bad (red)
	if pct < 0 {
		pct = 0
	}
	if pct > 100 {
		pct = 100
	}
	filled := int(pct / 100.0 * float64(w))
	if filled > w {
		filled = w
	}
	empty := w - filled
	var c string
	switch {
	case pct >= 80:
		c = FBGrn
	case pct >= 50:
		c = FYel
	case pct >= 25:
		c = FBYel
	default:
		c = FBRed
	}
	return fmt.Sprintf("%s%s%s%s%s", c, strings.Repeat("#", filled), D, strings.Repeat("-", empty), R)
}

func fb(b uint64) string {
	switch {
	case b >= 1<<30:
		return fmt.Sprintf("%.1fG", float64(b)/(1<<30))
	case b >= 1<<20:
		return fmt.Sprintf("%.1fM", float64(b)/(1<<20))
	case b >= 1<<10:
		return fmt.Sprintf("%.1fK", float64(b)/(1<<10))
	default:
		return fmt.Sprintf("%dB", b)
	}
}

func trunc(s string, n int) string {
	if len(s) <= n {
		return s
	}
	if n < 3 {
		return s[:n]
	}
	return s[:n-2] + ".."
}

func titleLine(t string) string {
	pad := 78 - len(t) - 2
	if pad < 0 {
		pad = 0
	}
	return fmt.Sprintf("%s%s== %s %s%s", B, FCyn, t, strings.Repeat("=", pad), R)
}

func hr() string {
	return fmt.Sprintf("%s%s%s", D, strings.Repeat("-", 78), R)
}

// ── Sort helpers ────────────────────────────────────────────────────────────

func sortCgCPU(cgs []model.CgroupRate) []model.CgroupRate {
	s := make([]model.CgroupRate, len(cgs))
	copy(s, cgs)
	sort.Slice(s, func(i, j int) bool { return s[i].CPUPct > s[j].CPUPct })
	return s
}

func sortCgThrottle(cgs []model.CgroupRate) []model.CgroupRate {
	s := make([]model.CgroupRate, len(cgs))
	copy(s, cgs)
	sort.Slice(s, func(i, j int) bool { return s[i].ThrottlePct > s[j].ThrottlePct })
	return s
}

func sortProcCPU(p []model.ProcessRate) []model.ProcessRate {
	s := make([]model.ProcessRate, len(p))
	copy(s, p)
	sort.Slice(s, func(i, j int) bool { return s[i].CPUPct > s[j].CPUPct })
	return s
}

func sortProcMem(p []model.ProcessRate) []model.ProcessRate {
	s := make([]model.ProcessRate, len(p))
	copy(s, p)
	sort.Slice(s, func(i, j int) bool { return s[i].RSS > s[j].RSS })
	return s
}

func sortProcIO(p []model.ProcessRate) []model.ProcessRate {
	s := make([]model.ProcessRate, len(p))
	copy(s, p)
	sort.Slice(s, func(i, j int) bool {
		return (s[i].ReadMBs + s[i].WriteMBs) > (s[j].ReadMBs + s[j].WriteMBs)
	})
	return s
}

// ── Main Watch Loop ─────────────────────────────────────────────────────────

func runWatch(eng *engine.Engine, cfg Config) error {
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

	ticker := time.NewTicker(cfg.Interval)
	defer ticker.Stop()

	iteration := 0

	for {
		select {
		case <-sig:
			fmt.Printf("\n%sStopped.%s\n", D, R)
			return nil
		case <-ticker.C:
			iteration++
			snap, rates, result := eng.Tick()
			if snap == nil {
				continue
			}
			if iteration == 1 && rates == nil {
				continue
			}

			fmt.Print("\033[2J\033[H")

			// Title bar
			ts := snap.Timestamp.Format("15:04:05")
			iter := fmt.Sprintf("#%d", iteration)
			if cfg.WatchCount > 0 {
				iter = fmt.Sprintf("#%d/%d", iteration, cfg.WatchCount)
			}
			fmt.Printf(" %s%s xtop v%s %s  %s  %s%s%s  %s%s%s  %s\n",
				B, BBlu+FBWht, Version, R,
				B+ts+R,
				FCyn, cfg.Section, R,
				D, cfg.Interval, R,
				D+iter+R)
			fmt.Println(hr())

			switch cfg.Section {
			case "overview":
				watchOverview(snap, rates, result)
			case "cpu":
				watchCPU(snap, rates)
			case "mem":
				watchMem(snap, rates)
			case "io":
				watchIO(snap, rates)
			case "net":
				watchNet(snap, rates)
			case "cgroup":
				watchCgroup(snap, rates)
			case "rca":
				watchRCA(snap, rates, result)
			}

			fmt.Println()
			fmt.Println(hr())
			fmt.Printf(" %sCtrl+C%s to quit", B, R)
			if cfg.WatchCount > 0 {
				fmt.Printf("  %s|%s  %d/%d", D, R, iteration, cfg.WatchCount)
			}
			fmt.Println()

			if cfg.WatchCount > 0 && iteration >= cfg.WatchCount {
				return nil
			}
		}
	}
}

// ═══════════════════════════════════════════════════════════════════════════
//  OVERVIEW
// ═══════════════════════════════════════════════════════════════════════════

func watchOverview(snap *model.Snapshot, rates *model.RateSnapshot, result *model.AnalysisResult) {
	fmt.Println()

	// Health
	if result != nil {
		fmt.Printf(" %s  Confidence: %s%d%%%s", healthBadge(result.Health), B, result.Confidence, R)
		if result.PrimaryBottleneck != "" && result.PrimaryScore > 0 {
			fmt.Printf("   Primary: %s%s%s %s",
				B+FBWht, result.PrimaryBottleneck, R,
				cpct(float64(result.PrimaryScore), 25, 60))
			if result.AnomalyStartedAgo > 0 {
				fmt.Printf("  %sT-%ds%s", FBYel, result.AnomalyStartedAgo, R)
			}
		} else {
			fmt.Printf("   %sNo bottleneck%s", FBGrn, R)
		}
		fmt.Println()
	}
	fmt.Println()

	// PSI table
	fmt.Println(titleLine("PRESSURE (PSI)"))
	fmt.Printf("       %s%7s  %7s%s\n", D, "some", "full", R)
	psi := snap.Global.PSI
	fmt.Printf(" %s%-4s%s  %s  %s\n", B, "CPU", R, cpsi(psi.CPU.Some.Avg10), cpsi(psi.CPU.Full.Avg10))
	fmt.Printf(" %s%-4s%s  %s  %s\n", B, "MEM", R, cpsi(psi.Memory.Some.Avg10), cpsi(psi.Memory.Full.Avg10))
	fmt.Printf(" %s%-4s%s  %s  %s\n", B, "IO", R, cpsi(psi.IO.Some.Avg10), cpsi(psi.IO.Full.Avg10))
	load := snap.Global.CPU.LoadAvg
	fmt.Printf(" %sLoad%s  %s%.2f  %.2f  %.2f%s  %s%d CPUs  %d/%d run%s\n",
		B, R, FBWht, load.Load1, load.Load5, load.Load15, R,
		D, snap.Global.CPU.NumCPUs, load.Running, load.Total, R)
	if rates != nil && (rates.SwapInRate > 0 || rates.SwapOutRate > 0) {
		fmt.Printf(" %sSwap%s  %sin=%.1f  out=%.1f MB/s%s\n", B, R, FBYel, rates.SwapInRate, rates.SwapOutRate, R)
	}
	fmt.Println()

	// CPU + Mem one-liner
	if rates != nil {
		fmt.Printf(" %sCPU%s  busy %s  user %s%.1f%%%s  sys %s%.1f%%%s  iowait %s  steal %s\n",
			B+FCyn, R,
			cpct(rates.CPUBusyPct, tCPUWarn, tCPUCrit),
			D, rates.CPUUserPct, R,
			D, rates.CPUSystemPct, R,
			cpct(rates.CPUIOWaitPct, 5, 20),
			cpct(rates.CPUStealPct, 5, 20))
	}
	mem := snap.Global.Memory
	memPct := 0.0
	if mem.Total > 0 {
		memPct = float64(mem.Total-mem.Available) / float64(mem.Total) * 100
	}
	fmt.Printf(" %sMEM%s  %s used  %s%s%s avail / %s%s%s total\n",
		B+FCyn, R,
		cpct(memPct, tMemWarn, tMemCrit),
		FBWht, fb(mem.Available), R,
		D, fb(mem.Total), R)
	fmt.Println()

	// Capacity table
	if result != nil && len(result.Capacities) > 0 {
		fmt.Println(titleLine("CAPACITY LEFT"))
		fmt.Printf(" %s%-18s  %-22s  %8s  %-18s%s\n", D, "RESOURCE", "BAR", "LEFT", "CURRENT", R)
		for _, c := range result.Capacities {
			w := ""
			if c.Pct <= tCapacityCrit {
				w = critTag()
			} else if c.Pct <= tCapacityWarn {
				w = warnTag()
			}
			fmt.Printf(" %s%-18s%s  [%-20s] %s  %s%-18s%s%s\n",
				B, c.Label, R,
				barInv(c.Pct, 20),
				cpctInv(c.Pct, tCapacityWarn, tCapacityCrit),
				D, c.Current, R,
				w)
		}
		fmt.Println()
	}

	// Warnings
	if result != nil && len(result.Warnings) > 0 {
		fmt.Println(titleLine("WARNINGS"))
		for i, w := range result.Warnings {
			if i >= 5 {
				fmt.Printf("   %s+%d more%s\n", D, len(result.Warnings)-5, R)
				break
			}
			var icon string
			switch w.Severity {
			case "crit":
				icon = critTag()
			case "warn":
				icon = warnTag()
			default:
				icon = fmt.Sprintf(" %si%s", FCyn, R)
			}
			fmt.Printf(" %s  %s%-12s%s %s%s%s\n", icon, B, w.Signal, R, D, w.Value, R)
		}
		fmt.Println()
	}

	// Mini RCA
	if result != nil {
		active := 0
		for _, r := range result.RCA {
			if r.Score > 0 {
				active++
			}
		}
		if active > 0 {
			fmt.Println(titleLine("ROOT CAUSE ANALYSIS"))
			for _, r := range result.RCA {
				if r.Score == 0 {
					continue
				}
				mark := "  "
				if r.Score >= 60 {
					mark = critTag()
				} else if r.Score >= 25 {
					mark = warnTag()
				}
				top := ""
				if r.TopProcess != "" {
					top = fmt.Sprintf("  %s%s(%d)%s", FBWht, r.TopProcess, r.TopPID, R)
				}
				fmt.Printf(" %s  %-20s %s  %s%d grp%s%s\n",
					mark, r.Bottleneck, cpct(float64(r.Score), 25, 60), D, r.EvidenceGroups, R, top)
			}
			if result.CausalChain != "" {
				fmt.Printf(" %sChain:%s %s%s%s\n", D, R, FBYel, result.CausalChain, R)
			}
		}
	}
}

// ═══════════════════════════════════════════════════════════════════════════
//  CPU
// ═══════════════════════════════════════════════════════════════════════════

func watchCPU(snap *model.Snapshot, rates *model.RateSnapshot) {
	fmt.Println()
	fmt.Println(titleLine("CPU"))

	if rates != nil {
		fmt.Printf("\n %sBusy%s  [%-30s] %s\n", B, R, bar(rates.CPUBusyPct, 30), cpct(rates.CPUBusyPct, tCPUWarn, tCPUCrit))
		fmt.Println()
		fmt.Printf(" user %s  sys %s  iowait %s  steal %s  softirq %s  nice %s\n",
			cpct(rates.CPUUserPct, tCPUWarn, tCPUCrit),
			cpct(rates.CPUSystemPct, 30, 60),
			cpct(rates.CPUIOWaitPct, 5, 20),
			cpct(rates.CPUStealPct, 5, 20),
			cpct(rates.CPUSoftIRQPct, 10, 30),
			cpct(rates.CPUNicePct, 50, 80))
		fmt.Println()
		fmt.Printf(" %sCtx switches%s  %s%.0f/s%s\n", D, R, FBWht, rates.CtxSwitchRate, R)
	}

	load := snap.Global.CPU.LoadAvg
	psi := snap.Global.PSI.CPU
	fmt.Printf(" %sLoad%s  %s%.2f  %.2f  %.2f%s  %s(%d CPUs)%s",
		B, R, FBWht, load.Load1, load.Load5, load.Load15, R, D, snap.Global.CPU.NumCPUs, R)
	fmt.Printf("   %sPSI%s some %s  full %s\n", B, R, cpsi(psi.Some.Avg10), cpsi(psi.Full.Avg10))

	// Top cgroups by CPU
	if rates != nil && len(rates.CgroupRates) > 0 {
		fmt.Println()
		fmt.Println(titleLine("TOP CGROUPS BY CPU"))
		fmt.Printf(" %s%-8s  %-40s%s\n", D, "CPU%", "CGROUP", R)
		fmt.Println(" " + hr())
		sorted := sortCgCPU(rates.CgroupRates)
		for i, cg := range sorted {
			if i >= 8 || cg.CPUPct < 0.1 {
				break
			}
			fmt.Printf(" %s  %s\n",
				cpct(cg.CPUPct, 50, 80),
				B+trunc(cg.Name, 50)+R)
		}
	}

	// Throttled
	if rates != nil && len(rates.CgroupRates) > 0 {
		thr := sortCgThrottle(rates.CgroupRates)
		if len(thr) > 0 && thr[0].ThrottlePct > 0 {
			fmt.Println()
			fmt.Println(titleLine("THROTTLED CGROUPS"))
			for i, cg := range thr {
				if i >= 5 || cg.ThrottlePct <= 0 {
					break
				}
				fmt.Printf(" %s%s%5.1f%%%s throttled  %s\n",
					B, FBRed, cg.ThrottlePct, R, trunc(cg.Name, 50))
			}
		}
	}

	// Top processes
	if rates != nil && len(rates.ProcessRates) > 0 {
		fmt.Println()
		fmt.Println(titleLine("TOP PROCESSES"))
		fmt.Printf(" %s%-7s  %-3s  %7s  %-20s%s\n", D, "PID", "S", "CPU%", "COMMAND", R)
		fmt.Println(" " + hr())
		sorted := sortProcCPU(rates.ProcessRates)
		for i, p := range sorted {
			if i >= 8 || p.CPUPct < 0.1 {
				break
			}
			sc := D
			if p.State == "R" {
				sc = FBGrn
			} else if p.State == "D" {
				sc = B + FBRed
			}
			fmt.Printf(" %-7d  %s%-3s%s  %s  %s%s%s\n",
				p.PID, sc, p.State, R,
				cpct(p.CPUPct, 50, 80),
				FBWht, trunc(p.Comm, 20), R)
		}
	}
}

// ═══════════════════════════════════════════════════════════════════════════
//  MEMORY
// ═══════════════════════════════════════════════════════════════════════════

func watchMem(snap *model.Snapshot, rates *model.RateSnapshot) {
	mem := snap.Global.Memory
	memPct := 0.0
	if mem.Total > 0 {
		memPct = float64(mem.Total-mem.Available) / float64(mem.Total) * 100
	}

	fmt.Println()
	fmt.Println(titleLine("MEMORY"))
	fmt.Printf("\n %sUsed%s  [%-30s] %s   %s%s%s / %s%s%s\n",
		B, R, bar(memPct, 30), cpct(memPct, tMemWarn, tMemCrit),
		FBWht, fb(mem.Total-mem.Available), R, D, fb(mem.Total), R)
	fmt.Printf(" %sAvail%s %s%s%s\n", D, R, FBGrn, fb(mem.Available), R)
	fmt.Println()

	// Breakdown table
	fmt.Printf(" %s%-12s  %8s    %-12s  %8s    %-12s  %8s%s\n",
		D, "METRIC", "VALUE", "METRIC", "VALUE", "METRIC", "VALUE", R)
	fmt.Println(" " + hr())
	fmt.Printf(" %-12s  %s%8s%s    %-12s  %s%8s%s    %-12s  %s%8s%s\n",
		"Buffers", FBWht, fb(mem.Buffers), R,
		"Cached", FBWht, fb(mem.Cached), R,
		"Dirty", FBWht, fb(mem.Dirty), R)
	fmt.Printf(" %-12s  %s%8s%s    %-12s  %s%8s%s    %-12s  %s%8s%s\n",
		"Active", FBWht, fb(mem.Active), R,
		"Inactive", FBWht, fb(mem.Inactive), R,
		"Shmem", FBWht, fb(mem.Shmem), R)
	fmt.Printf(" %-12s  %s%8s%s    %-12s  %s%8s%s    %-12s  %s%8s%s\n",
		"AnonPages", FBWht, fb(mem.AnonPages), R,
		"Mapped", FBWht, fb(mem.Mapped), R,
		"Slab", FBWht, fb(mem.Slab), R)
	fmt.Printf(" %-12s  %s%8s%s    %-12s  %s%8s%s\n",
		"KernelStack", D, fb(mem.KernelStack), R,
		"PageTables", D, fb(mem.PageTables), R)

	// Swap
	fmt.Println()
	fmt.Println(titleLine("SWAP"))
	swapUsed := mem.SwapTotal - mem.SwapFree
	if mem.SwapTotal > 0 {
		swapPct := float64(swapUsed) / float64(mem.SwapTotal) * 100
		fmt.Printf(" [%-20s] %s   %s%s%s / %s%s%s\n",
			bar(swapPct, 20), cpct(swapPct, tSwapWarn, 50),
			FBWht, fb(swapUsed), R, D, fb(mem.SwapTotal), R)
	} else {
		fmt.Printf(" %sNo swap configured%s\n", D, R)
	}
	if rates != nil && (rates.SwapInRate > 0 || rates.SwapOutRate > 0) {
		fmt.Printf(" %sRate%s  in=%s%.1f MB/s%s  out=%s%.1f MB/s%s\n",
			B, R, FBYel, rates.SwapInRate, R, FBYel, rates.SwapOutRate, R)
	} else {
		fmt.Printf(" %sRate: idle%s\n", D, R)
	}
	psi := snap.Global.PSI.Memory
	fmt.Printf(" %sPSI%s  some %s  full %s\n", B, R, cpsi(psi.Some.Avg10), cpsi(psi.Full.Avg10))

	// VMStat
	fmt.Println()
	fmt.Println(titleLine("VMSTAT"))
	vm := snap.Global.VMStat
	oomColor := D
	if vm.OOMKill > 0 {
		oomColor = B + FBRed
	}
	fmt.Printf(" %-14s %s%-10d%s  %-14s %s%-10d%s  %-14s %s%d%s\n",
		"PageFaults", D, vm.PgFault, R,
		"MajFaults", D, vm.PgMajFault, R,
		"OOM Kills", oomColor, vm.OOMKill, R)
	fmt.Printf(" %-14s %s%-10d%s  %-14s %s%-10d%s\n",
		"DirectReclaim", D, vm.PgStealDirect, R,
		"Kswapd", D, vm.PgStealKswapd, R)
	if rates != nil {
		fmt.Printf(" %sRates%s  faults=%s%.0f/s%s  majfaults=%s  reclaim=%s\n",
			D, R, FBWht, rates.PgFaultRate, R,
			cfloat(rates.MajFaultRate, tMajFaultWarn, 50),
			cfloat(rates.DirectReclaimRate, tReclaimWarn, 5))
	}

	// Top processes
	if rates != nil && len(rates.ProcessRates) > 0 {
		fmt.Println()
		fmt.Println(titleLine("TOP PROCESSES BY MEMORY"))
		fmt.Printf(" %s%-7s  %10s  %10s  %-20s%s\n", D, "PID", "RSS", "SWAP", "COMMAND", R)
		fmt.Println(" " + hr())
		sorted := sortProcMem(rates.ProcessRates)
		for i, p := range sorted {
			if i >= 8 || p.RSS == 0 {
				break
			}
			fmt.Printf(" %-7d  %s%10s%s  %s%10s%s  %s%s%s\n",
				p.PID, FBWht, fb(p.RSS), R, D, fb(p.VmSwap), R,
				FBWht, trunc(p.Comm, 20), R)
		}
	}
}

// ═══════════════════════════════════════════════════════════════════════════
//  IO
// ═══════════════════════════════════════════════════════════════════════════

func watchIO(snap *model.Snapshot, rates *model.RateSnapshot) {
	psi := snap.Global.PSI.IO

	fmt.Println()
	fmt.Println(titleLine("IO"))
	fmt.Printf(" %sPSI%s  some %s  full %s\n", B, R, cpsi(psi.Some.Avg10), cpsi(psi.Full.Avg10))

	// Device table
	if rates != nil && len(rates.DiskRates) > 0 {
		fmt.Println()
		fmt.Println(titleLine("DEVICES"))
		fmt.Printf(" %s%-10s  %8s  %8s  %6s  %6s  %8s  %6s  %3s%s\n",
			D, "DEVICE", "READ/s", "WRITE/s", "rIOPS", "wIOPS", "AWAIT", "UTIL%", "QD", R)
		fmt.Println(" " + hr())
		for _, d := range rates.DiskRates {
			awaitStr := cfloat(d.AvgAwaitMs, tDiskAwaitWarn, tDiskAwaitCrit)
			utilStr := cpct(d.UtilPct, tDiskUtilWarn, tDiskUtilCrit)
			w := ""
			if d.UtilPct >= tDiskUtilCrit || d.AvgAwaitMs >= tDiskAwaitCrit {
				w = critTag()
			} else if d.UtilPct >= tDiskUtilWarn || d.AvgAwaitMs >= tDiskAwaitWarn {
				w = warnTag()
			}
			fmt.Printf(" %s%-10s%s  %s%7.1fM%s  %s%7.1fM%s  %6.0f  %6.0f  %sms  %s  %3d %s\n",
				FBWht, d.Name, R,
				FCyn, d.ReadMBs, R,
				FCyn, d.WriteMBs, R,
				d.ReadIOPS, d.WriteIOPS,
				awaitStr, utilStr, d.QueueDepth, w)
		}
	}

	// D-state
	var dTasks []model.ProcessMetrics
	for _, p := range snap.Processes {
		if p.State == "D" {
			dTasks = append(dTasks, p)
		}
	}
	fmt.Println()
	dCount := len(dTasks)
	dLabel := cint(dCount, 1, 5)
	fmt.Print(titleLine(fmt.Sprintf("D-STATE TASKS: %d", dCount)))
	fmt.Println()
	if dCount == 0 {
		_ = dLabel
		fmt.Printf(" %sNone%s\n", FBGrn, R)
	} else {
		for i, p := range dTasks {
			if i >= 8 {
				fmt.Printf(" %s+%d more%s\n", D, dCount-8, R)
				break
			}
			fmt.Printf(" %s%sPID %-7d%s  %s\n", B, FBRed, p.PID, R, p.Comm)
		}
	}

	// Top processes by IO
	if rates != nil && len(rates.ProcessRates) > 0 {
		fmt.Println()
		fmt.Println(titleLine("TOP PROCESSES BY IO"))
		fmt.Printf(" %s%-7s  %9s  %9s  %-20s%s\n", D, "PID", "READ/s", "WRITE/s", "COMMAND", R)
		fmt.Println(" " + hr())
		sorted := sortProcIO(rates.ProcessRates)
		shown := 0
		for _, p := range sorted {
			if shown >= 8 || (p.ReadMBs < 0.001 && p.WriteMBs < 0.001) {
				break
			}
			fmt.Printf(" %-7d  %s%8.2fM%s  %s%8.2fM%s  %s%s%s\n",
				p.PID, FCyn, p.ReadMBs, R, FCyn, p.WriteMBs, R,
				FBWht, trunc(p.Comm, 20), R)
			shown++
		}
		if shown == 0 {
			fmt.Printf(" %sNo IO activity%s\n", D, R)
		}
	}
}

// ═══════════════════════════════════════════════════════════════════════════
//  NETWORK
// ═══════════════════════════════════════════════════════════════════════════

func watchNet(snap *model.Snapshot, rates *model.RateSnapshot) {
	fmt.Println()

	// Health verdict
	netH, issues := netHealth(snap, rates)
	badge := fmt.Sprintf("%s%s OK %s", BGrn+B+FBWht, " ", R)
	if netH == "CRITICAL" {
		badge = fmt.Sprintf("%s%s CRITICAL %s", BRed+B+FBWht, " ", R)
	} else if netH == "DEGRADED" {
		badge = fmt.Sprintf("%s%s DEGRADED %s", BRed+B+FBWht, " ", R)
	}
	fmt.Println(titleLine("NETWORK"))
	fmt.Printf(" %sHealth%s  %s\n", B, R, badge)
	for _, iss := range issues {
		fmt.Printf("         %s%s%s\n", FBYel, iss, R)
	}

	// Throughput
	if rates != nil && len(rates.NetRates) > 0 {
		var rxMB, txMB, rxPPS, txPPS, drops, errs float64
		for _, n := range rates.NetRates {
			rxMB += n.RxMBs
			txMB += n.TxMBs
			rxPPS += n.RxPPS
			txPPS += n.TxPPS
			drops += n.RxDropsPS + n.TxDropsPS
			errs += n.RxErrorsPS + n.TxErrorsPS
		}
		fmt.Println()
		fmt.Println(titleLine("THROUGHPUT"))
		fmt.Printf(" %s%-4s  %10s  %10s  %10s  %10s%s\n",
			D, "", "MB/s", "pps", "drops/s", "errors/s", R)
		fmt.Printf(" %s%-4s%s  %s%10.2f%s  %s%10.0f%s  %s  %s\n",
			B, "RX", R, FCyn, rxMB, R, D, rxPPS, R,
			cfloat(drops, tDropsWarn, 100), cfloat(errs, tDropsWarn, 100))
		fmt.Printf(" %s%-4s%s  %s%10.2f%s  %s%10.0f%s\n",
			B, "TX", R, FCyn, txMB, R, D, txPPS, R)
	}

	// TCP connections
	tcp := snap.Global.TCPStates
	total := tcp.Established + tcp.TimeWait + tcp.CloseWait + tcp.FinWait1 +
		tcp.FinWait2 + tcp.SynSent + tcp.SynRecv + tcp.Listen + tcp.Closing + tcp.LastAck
	if total > 0 {
		fmt.Println()
		fmt.Println(titleLine(fmt.Sprintf("TCP CONNECTIONS (%d total)", total)))
		fmt.Printf(" %s%-12s  %8s  %s%s\n", D, "STATE", "COUNT", "STATUS", R)
		fmt.Println(" " + hr())
		fmt.Printf(" %-12s  %s%8d%s\n", "ESTABLISHED", FBWht, tcp.Established, R)
		fmt.Printf(" %-12s  %s%8d%s\n", "LISTEN", D, tcp.Listen, R)
		fmt.Printf(" %-12s  %s %s\n", "TIME_WAIT",
			cint(tcp.TimeWait, tTimeWaitWarn, 5000),
			twWarn(tcp.TimeWait))
		fmt.Printf(" %-12s  %s %s\n", "CLOSE_WAIT",
			cint(tcp.CloseWait, tCloseWaitWarn, 50),
			cwWarn(tcp.CloseWait))
		fmt.Printf(" %-12s  %s%8d%s\n", "FIN_WAIT", D, tcp.FinWait1+tcp.FinWait2, R)
		fmt.Printf(" %-12s  %s%8d%s\n", "SYN_SENT", D, tcp.SynSent, R)
	}

	// Protocol health
	if rates != nil {
		fmt.Println()
		fmt.Println(titleLine("PROTOCOL HEALTH"))
		fmt.Printf(" %s%-14s  %12s  %s%s\n", D, "METRIC", "RATE", "STATUS", R)
		fmt.Println(" " + hr())
		retransW := ""
		if rates.RetransRate >= tRetransCrit {
			retransW = critTag()
		} else if rates.RetransRate >= tRetransWarn {
			retransW = warnTag()
		}
		fmt.Printf(" %-14s  %s/s %s\n", "TCP retrans", cfloat(rates.RetransRate, tRetransWarn, tRetransCrit), retransW)
		fmt.Printf(" %-14s  %s%10.0f/s%s\n", "TCP resets", D, rates.TCPResetRate, R)
		fmt.Printf(" %-14s  %s%10.0f/s%s\n", "UDP in", D, rates.UDPInRate, R)
		fmt.Printf(" %-14s  %s%10.0f/s%s\n", "UDP out", D, rates.UDPOutRate, R)
		fmt.Printf(" %-14s  %s/s\n", "UDP errors", cfloat(rates.UDPErrRate, 1, 10))
		fmt.Printf(" %-14s  %s%10.0f/s%s\n", "SoftIRQ NET_RX", D, rates.SoftIRQNetRxRate, R)
		fmt.Printf(" %-14s  %s%10.0f/s%s\n", "SoftIRQ NET_TX", D, rates.SoftIRQNetTxRate, R)
	}

	// Conntrack
	ct := snap.Global.Conntrack
	if ct.Max > 0 {
		pct := float64(ct.Count) / float64(ct.Max) * 100
		fmt.Println()
		fmt.Println(titleLine("CONNTRACK"))
		w := ""
		if pct >= 90 {
			w = critTag()
		} else if pct >= tConntrackWarn {
			w = warnTag()
		}
		fmt.Printf(" [%-20s] %s  %s%d%s / %s%d%s %s\n",
			bar(pct, 20), cpct(pct, tConntrackWarn, 90),
			FBWht, ct.Count, R, D, ct.Max, R, w)
	}

	// Per-interface
	if rates != nil && len(rates.NetRates) > 0 {
		fmt.Println()
		fmt.Println(titleLine("PER-INTERFACE"))
		fmt.Printf(" %s%-14s  %8s  %8s  %8s  %8s  %6s  %6s%s\n",
			D, "IFACE", "RX MB/s", "TX MB/s", "RxPPS", "TxPPS", "DROPS", "ERRS", R)
		fmt.Println(" " + hr())
		for _, n := range rates.NetRates {
			dr := n.RxDropsPS + n.TxDropsPS
			er := n.RxErrorsPS + n.TxErrorsPS
			w := ""
			if dr > 0 || er > 0 {
				w = warnTag()
			}
			fmt.Printf(" %s%-14s%s  %s%7.2fM%s  %s%7.2fM%s  %8.0f  %8.0f  %s  %s %s\n",
				FBWht, n.Name, R,
				FCyn, n.RxMBs, R,
				FCyn, n.TxMBs, R,
				n.RxPPS, n.TxPPS,
				cfloat(dr, tDropsWarn, 100),
				cfloat(er, tDropsWarn, 100), w)
		}
	}
}

func twWarn(v int) string {
	if v >= 5000 {
		return critTag() + fmt.Sprintf(" %sPort exhaustion risk%s", FBRed, R)
	}
	if v >= tTimeWaitWarn {
		return warnTag() + fmt.Sprintf(" %sElevated%s", FBYel, R)
	}
	return ""
}

func cwWarn(v int) string {
	if v >= 50 {
		return critTag() + fmt.Sprintf(" %sPossible connection leak%s", FBRed, R)
	}
	if v >= tCloseWaitWarn {
		return warnTag() + fmt.Sprintf(" %sCheck application%s", FBYel, R)
	}
	return ""
}

func netHealth(snap *model.Snapshot, rates *model.RateSnapshot) (string, []string) {
	h := "OK"
	var issues []string
	if rates != nil {
		for _, n := range rates.NetRates {
			if d := n.RxDropsPS + n.TxDropsPS; d > 0 {
				issues = append(issues, fmt.Sprintf("Drops on %s: %.0f/s", n.Name, d))
				h = "DEGRADED"
			}
		}
		if rates.RetransRate >= tRetransCrit {
			issues = append(issues, fmt.Sprintf("High TCP retransmits: %.0f/s", rates.RetransRate))
			h = "CRITICAL"
		} else if rates.RetransRate >= tRetransWarn {
			issues = append(issues, fmt.Sprintf("TCP retransmits: %.0f/s", rates.RetransRate))
			if h == "OK" {
				h = "DEGRADED"
			}
		}
	}
	ct := snap.Global.Conntrack
	if ct.Max > 0 {
		pct := float64(ct.Count) / float64(ct.Max) * 100
		if pct >= 90 {
			issues = append(issues, fmt.Sprintf("Conntrack near full: %.0f%%", pct))
			h = "CRITICAL"
		} else if pct >= tConntrackWarn {
			issues = append(issues, fmt.Sprintf("Conntrack pressure: %.0f%%", pct))
			if h == "OK" {
				h = "DEGRADED"
			}
		}
	}
	tcp := snap.Global.TCPStates
	if tcp.TimeWait >= 5000 {
		issues = append(issues, fmt.Sprintf("Excessive TIME_WAIT: %d", tcp.TimeWait))
		if h == "OK" {
			h = "DEGRADED"
		}
	}
	if tcp.CloseWait >= 50 {
		issues = append(issues, fmt.Sprintf("High CLOSE_WAIT: %d", tcp.CloseWait))
		h = "CRITICAL"
	}
	return h, issues
}

// ═══════════════════════════════════════════════════════════════════════════
//  CGROUP
// ═══════════════════════════════════════════════════════════════════════════

func watchCgroup(snap *model.Snapshot, rates *model.RateSnapshot) {
	fmt.Println()
	fmt.Println(titleLine("CGROUPS"))

	if rates == nil || len(rates.CgroupRates) == 0 {
		fmt.Printf(" %sNo cgroup data%s\n", D, R)
		return
	}

	fmt.Printf(" %s%-32s  %6s  %6s  %8s  %4s  %8s  %8s%s\n",
		D, "CGROUP", "CPU%", "THR%", "MEM", "OOM", "IO_R/s", "IO_W/s", R)
	fmt.Println(" " + hr())

	sorted := sortCgCPU(rates.CgroupRates)
	for i, cg := range sorted {
		if i >= 20 {
			fmt.Printf(" %s+%d more%s\n", D, len(sorted)-20, R)
			break
		}
		var memStr string
		oom := 0
		for _, sc := range snap.Cgroups {
			if sc.Path == cg.Path {
				memStr = fb(sc.MemCurrent)
				oom = int(sc.OOMKills)
				break
			}
		}
		cpuC := D
		if cg.CPUPct > 50 {
			cpuC = B + FBRed
		} else if cg.CPUPct > 10 {
			cpuC = FBYel
		} else if cg.CPUPct > 1 {
			cpuC = FBWht
		}
		thrC := D
		if cg.ThrottlePct > 10 {
			thrC = B + FBRed
		} else if cg.ThrottlePct > 0 {
			thrC = FBYel
		}
		oomC := D
		if oom > 0 {
			oomC = B + FBRed
		}
		w := ""
		if cg.ThrottlePct > 10 || oom > 0 {
			w = warnTag()
		}
		fmt.Printf(" %-32s  %s%5.1f%%%s  %s%5.1f%%%s  %8s  %s%4d%s  %7.2fM  %7.2fM %s\n",
			trunc(cg.Name, 32),
			cpuC, cg.CPUPct, R,
			thrC, cg.ThrottlePct, R,
			memStr,
			oomC, oom, R,
			cg.IORateMBs, cg.IOWRateMBs, w)
	}
}

// ═══════════════════════════════════════════════════════════════════════════
//  RCA
// ═══════════════════════════════════════════════════════════════════════════

func watchRCA(snap *model.Snapshot, rates *model.RateSnapshot, result *model.AnalysisResult) {
	if result == nil {
		fmt.Println()
		fmt.Println(titleLine("ROOT CAUSE ANALYSIS"))
		fmt.Printf(" %sCollecting data...%s\n", D, R)
		return
	}

	// Health
	fmt.Println()
	fmt.Printf(" %s  Confidence: %s%d%%%s\n", healthBadge(result.Health), B, result.Confidence, R)
	if result.PrimaryBottleneck != "" && result.PrimaryScore > 0 {
		fmt.Printf(" %sPrimary:%s %s%s%s %s",
			B, R, B+FBWht, result.PrimaryBottleneck, R,
			cpct(float64(result.PrimaryScore), 25, 60))
		if result.AnomalyStartedAgo > 0 {
			fmt.Printf("  %sT-%ds%s", FBYel, result.AnomalyStartedAgo, R)
		}
		if result.PrimaryCulprit != "" {
			fmt.Printf("  %sCulprit: %s%s", D, result.PrimaryCulprit, R)
		}
		fmt.Println()
	} else {
		fmt.Printf(" %sNo bottleneck detected%s\n", FBGrn, R)
	}

	// Evidence
	if result.PrimaryScore > 0 {
		fmt.Println()
		fmt.Println(titleLine("WHY I THINK THIS"))
		fmt.Printf(" %s%-4s  %-28s  %s%s\n", D, "", "CHECK", "VALUE", R)
		fmt.Println(" " + hr())
		for _, rca := range result.RCA {
			if rca.Bottleneck != result.PrimaryBottleneck {
				continue
			}
			for _, check := range rca.Checks {
				mark := fmt.Sprintf(" %s - %s", D, R)
				vc := D
				if check.Passed {
					mark = fmt.Sprintf(" %s + %s", FBGrn, R)
					vc = FBWht
				}
				fmt.Printf("%s  %-28s  %s%s%s\n", mark, check.Label, vc, check.Value, R)
			}
			fmt.Println()
			gc := FBGrn
			gs := "confident"
			if rca.EvidenceGroups < 2 {
				gc = FBYel
				gs = "insufficient"
			}
			fmt.Printf(" %sEvidence groups: %d/%d (%s)%s\n",
				gc, rca.EvidenceGroups, len(rca.Checks), gs, R)
			break
		}
	}

	// Chain
	if result.CausalChain != "" {
		fmt.Println()
		fmt.Println(titleLine("CAUSAL CHAIN"))
		parts := strings.Split(result.CausalChain, " -> ")
		for i, p := range parts {
			if i > 0 {
				fmt.Printf("   %s->%s  %s%s%s\n", FBYel, R, FBWht, p, R)
			} else {
				fmt.Printf("       %s%s%s\n", FBWht, p, R)
			}
		}
	}

	// Bottleneck scores table
	fmt.Println()
	fmt.Println(titleLine("BOTTLENECK SCORES"))
	fmt.Printf(" %s%-2s  %-20s  %6s  %5s  %-20s%s\n",
		D, "", "BOTTLENECK", "SCORE", "EVID", "TOP PROCESS", R)
	fmt.Println(" " + hr())
	for _, r := range result.RCA {
		mark := "  "
		if r.Score >= 60 {
			mark = critTag()
		} else if r.Score >= 25 {
			mark = warnTag()
		}
		top := D + "-" + R
		if r.TopProcess != "" {
			top = fmt.Sprintf("%s%s%s%s(%d)%s", FBWht, r.TopProcess, R, D, r.TopPID, R)
		}
		fmt.Printf(" %s  %-20s  %s  %s%d grp%s  %s\n",
			mark, r.Bottleneck, cpct(float64(r.Score), 25, 60),
			D, r.EvidenceGroups, R, top)
		for _, e := range r.Evidence {
			fmt.Printf("     %s-> %s%s\n", D, e, R)
		}
	}

	// Capacity
	if len(result.Capacities) > 0 {
		fmt.Println()
		fmt.Println(titleLine("CAPACITY LEFT"))
		fmt.Printf(" %s%-18s  %-22s  %8s  %-18s%s\n", D, "RESOURCE", "BAR", "LEFT", "CURRENT", R)
		fmt.Println(" " + hr())
		for _, c := range result.Capacities {
			w := ""
			if c.Pct <= tCapacityCrit {
				w = critTag()
			} else if c.Pct <= tCapacityWarn {
				w = warnTag()
			}
			fmt.Printf(" %s%-18s%s  [%-20s] %s  %s%-18s%s%s\n",
				B, c.Label, R,
				barInv(c.Pct, 20),
				cpctInv(c.Pct, tCapacityWarn, tCapacityCrit),
				D, c.Current, R, w)
		}
	}

	// Warnings
	if len(result.Warnings) > 0 {
		fmt.Println()
		fmt.Println(titleLine("WARNINGS"))
		for _, w := range result.Warnings {
			var icon string
			switch w.Severity {
			case "crit":
				icon = critTag()
			case "warn":
				icon = warnTag()
			default:
				icon = fmt.Sprintf(" %si%s", FCyn, R)
			}
			fmt.Printf(" %s  %s%-12s%s %s%s%s\n", icon, B, w.Signal, R, D, w.Value, R)
		}
	}

	// Actions
	if len(result.Actions) > 0 {
		fmt.Println()
		fmt.Println(titleLine("SUGGESTED ACTIONS"))
		for _, a := range result.Actions {
			fmt.Printf(" %s%s%s\n", FBWht, a.Summary, R)
			if a.Command != "" {
				fmt.Printf("   %s$ %s%s\n", FCyn, a.Command, R)
			}
		}
	}
}
