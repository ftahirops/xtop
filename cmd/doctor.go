package cmd

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	xtopcfg "github.com/ftahirops/xtop/config"
	"github.com/ftahirops/xtop/engine"
	"github.com/ftahirops/xtop/model"
)

// CheckStatus represents the severity of a doctor check result.
type CheckStatus int

const (
	CheckOK   CheckStatus = 0
	CheckWarn CheckStatus = 1
	CheckCrit CheckStatus = 2
	CheckSkip CheckStatus = 3
)

func (s CheckStatus) String() string {
	switch s {
	case CheckOK:
		return "OK"
	case CheckWarn:
		return "WARN"
	case CheckCrit:
		return "CRIT"
	case CheckSkip:
		return "SKIP"
	}
	return "UNKNOWN"
}

// CheckResult holds the outcome of a single health check.
type CheckResult struct {
	Category string      `json:"category"`
	Name     string      `json:"name"`
	Status   CheckStatus `json:"status"`
	Detail   string      `json:"detail"`
	Advice   string      `json:"advice,omitempty"`
}

// DoctorReport holds the full health check output.
type DoctorReport struct {
	Timestamp   time.Time     `json:"timestamp"`
	Hostname    string        `json:"hostname"`
	Checks      []CheckResult `json:"checks"`
	WorstStatus CheckStatus   `json:"worst_status"`
	RCA         interface{}   `json:"rca,omitempty"`
	Snap        *model.Snapshot     `json:"-"` // for diagnosis rendering
	Rates       *model.RateSnapshot `json:"-"`
}

// runDoctor performs all health checks and outputs the report.
func runDoctor(cfg Config) error {
	eng := engine.NewEngine(cfg.HistorySize, int(cfg.Interval.Seconds()))
	defer eng.Close()
	ticker := engine.Ticker(eng)

	// Collect two snapshots for rate calculation
	showProgress := !cfg.JSONMode && !cfg.MDMode && !cfg.CronMode
	if showProgress {
		fmt.Fprintf(os.Stderr, "\r  Collecting baseline snapshot...")
	}
	ticker.Tick()
	if showProgress {
		fmt.Fprintf(os.Stderr, "\r  Waiting %s for rate calculation...", cfg.Interval)
	}
	time.Sleep(cfg.Interval)
	if showProgress {
		fmt.Fprintf(os.Stderr, "\r  Collecting second snapshot...      ")
	}
	snap, rates, result := ticker.Tick()

	if snap == nil {
		return fmt.Errorf("failed to collect system snapshot")
	}

	hostname, _ := os.Hostname()
	report := DoctorReport{
		Timestamp: time.Now(),
		Hostname:  hostname,
		Snap:      snap,
		Rates:     rates,
	}

	if showProgress {
		fmt.Fprintf(os.Stderr, "\r  Running health checks...           ")
	}

	// RCA-based checks (from existing engine data)
	report.Checks = append(report.Checks, checkCPU(snap, rates, result)...)
	report.Checks = append(report.Checks, checkMemory(snap, rates, result)...)
	report.Checks = append(report.Checks, checkDisk(snap, rates, result)...)
	report.Checks = append(report.Checks, checkNetwork(snap, rates, result)...)
	report.Checks = append(report.Checks, checkFileless(snap)...)

	if showProgress {
		fmt.Fprintf(os.Stderr, "\r  Checking external services...      ")
	}

	// System checks — grouped together to avoid duplicate headers
	report.Checks = append(report.Checks, checkFDSystemWide(snap)...)
	report.Checks = append(report.Checks, checkInodeUsage(snap, rates)...)
	report.Checks = append(report.Checks, checkSystemdFailed()...)
	report.Checks = append(report.Checks, checkSecurityUpdates()...)
	report.Checks = append(report.Checks, checkNTPSync()...)

	// Docker (only shows if installed)
	report.Checks = append(report.Checks, checkDockerDisk()...)
	report.Checks = append(report.Checks, checkSSLCerts()...)

	if showProgress {
		fmt.Fprintf(os.Stderr, "\r  Detecting active services...       ")
	}

	// Active service detection (auto-detects running services)
	report.Checks = append(report.Checks, checkActiveServices()...)

	if showProgress {
		fmt.Fprintf(os.Stderr, "\r                                     \r")
	}

	// Compute worst status
	for _, c := range report.Checks {
		if c.Status < CheckSkip && c.Status > report.WorstStatus {
			report.WorstStatus = c.Status
		}
	}

	// Include RCA if available
	if result != nil && result.PrimaryScore > 0 {
		report.RCA = result
	}

	// Render output
	if cfg.JSONMode {
		return renderDoctorJSON(report)
	}
	if cfg.MDMode {
		fmt.Println(renderDoctorMarkdown(report))
		return nil
	}
	if cfg.CronMode {
		return renderDoctorCron(report)
	}

	// Alert if requested
	if cfg.AlertMode {
		sendDoctorAlert(report, cfg)
	}

	renderDoctorCLI(report, "")

	// #36: Return exit code via error instead of os.Exit to allow deferred cleanup
	if report.WorstStatus == CheckCrit {
		return ExitCodeError{Code: 2}
	}
	if report.WorstStatus == CheckWarn {
		return ExitCodeError{Code: 1}
	}
	return nil
}

// ExitCodeError signals a non-zero exit code without calling os.Exit directly.
type ExitCodeError struct{ Code int }

func (e ExitCodeError) Error() string { return fmt.Sprintf("exit %d", e.Code) }

// runDoctorWatch runs doctor checks in a watch loop with auto-refresh.
func runDoctorWatch(cfg Config) error {
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

	intervalTicker := time.NewTicker(cfg.Interval)
	defer intervalTicker.Stop()

	// #18: Create engine once and reuse across iterations
	eng := engine.NewEngine(cfg.HistorySize, int(cfg.Interval.Seconds()))
	defer eng.Close()
	ticker := engine.Ticker(eng)

	// Prime with first tick for rate baseline
	ticker.Tick()
	time.Sleep(cfg.Interval)

	iteration := 0

	for {
		select {
		case <-sig:
			fmt.Printf("\n%sStopped.%s\n", D, R)
			return nil
		case <-intervalTicker.C:
			iteration++

			snap, rates, result := ticker.Tick()

			if snap == nil {
				continue
			}

			hostname, _ := os.Hostname()
			report := DoctorReport{
				Timestamp: time.Now(),
				Hostname:  hostname,
				Snap:      snap,
				Rates:     rates,
			}

			report.Checks = append(report.Checks, checkCPU(snap, rates, result)...)
			report.Checks = append(report.Checks, checkMemory(snap, rates, result)...)
			report.Checks = append(report.Checks, checkDisk(snap, rates, result)...)
			report.Checks = append(report.Checks, checkNetwork(snap, rates, result)...)
			report.Checks = append(report.Checks, checkFDSystemWide(snap)...)
			report.Checks = append(report.Checks, checkInodeUsage(snap, rates)...)
			report.Checks = append(report.Checks, checkFileless(snap)...)
			report.Checks = append(report.Checks, checkSystemdFailed()...)
			report.Checks = append(report.Checks, checkDockerDisk()...)
			report.Checks = append(report.Checks, checkSecurityUpdates()...)
			report.Checks = append(report.Checks, checkNTPSync()...)
			report.Checks = append(report.Checks, checkSSLCerts()...)

			// Active service detection
			report.Checks = append(report.Checks, checkActiveServices()...)

			// Compute worst status
			for _, c := range report.Checks {
				if c.Status < CheckSkip && c.Status > report.WorstStatus {
					report.WorstStatus = c.Status
				}
			}

			// Include RCA if available
			if result != nil && result.PrimaryScore > 0 {
				report.RCA = result
			}

			// Clear screen and render
			fmt.Print("\033[2J\033[H")

			iter := fmt.Sprintf("%s  #%d", cfg.Interval, iteration)
			if cfg.WatchCount > 0 {
				iter = fmt.Sprintf("%s  #%d/%d", cfg.Interval, iteration, cfg.WatchCount)
			}
			renderDoctorCLI(report, iter)

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

// --- RCA-based check functions ---

func checkCPU(snap *model.Snapshot, rates *model.RateSnapshot, result *model.AnalysisResult) []CheckResult {
	var checks []CheckResult

	nCPU := snap.Global.CPU.NumCPUs
	if nCPU == 0 {
		nCPU = 1
	}
	la := snap.Global.CPU.LoadAvg

	// CPU utilization + load average combined overview
	if rates != nil {
		status := CheckOK
		loadPct := la.Load1 / float64(nCPU) * 100
		detail := fmt.Sprintf("%.1f%% busy — load avg: %.2f/%.2f/%.2f (%d CPUs, %.0f%% capacity)",
			rates.CPUBusyPct, la.Load1, la.Load5, la.Load15, nCPU, loadPct)
		advice := ""
		if rates.CPUBusyPct > 90 {
			status = CheckCrit
			advice = "Identify top CPU consumers: xtop -watch -section cpu"
		} else if rates.CPUBusyPct > 70 {
			status = CheckWarn
			advice = "CPU load is elevated"
		}
		checks = append(checks, CheckResult{
			Category: "CPU", Name: "Utilization", Status: status, Detail: detail, Advice: advice,
		})
	}

	// Load average with human-readable interpretation
	load1 := la.Load1
	load5 := la.Load5
	load15 := la.Load15
	loadPerCPU := load1 / float64(nCPU)
	loadPct := loadPerCPU * 100
	status := CheckOK
	// Human interpretation
	var interpretation string
	switch {
	case loadPct < 25:
		interpretation = "idle"
	case loadPct < 50:
		interpretation = "light load"
	case loadPct < 75:
		interpretation = "moderate load"
	case loadPct < 100:
		interpretation = "heavy load"
	case loadPct < 150:
		interpretation = "overloaded — more tasks than CPUs can handle"
	case loadPct < 200:
		interpretation = "severely overloaded — tasks queueing significantly"
	default:
		interpretation = "critically overloaded — extreme queueing"
	}
	detail := fmt.Sprintf("1m=%.2f  5m=%.2f  15m=%.2f | %d CPUs → %.0f%% capacity (%s)",
		load1, load5, load15, nCPU, loadPct, interpretation)
	advice := ""
	if loadPerCPU > 2 {
		status = CheckCrit
		advice = "System severely overloaded — tasks waiting far exceed CPU capacity"
	} else if loadPerCPU > 1 {
		status = CheckWarn
		advice = "Load exceeds CPU count — tasks are queueing for CPU time"
	}
	// Trend: is load rising or falling?
	if load1 > 0 {
		if load1 > load15*1.5 && load15 > 0 {
			detail += " [RISING]"
		} else if load1 < load15*0.5 && load15 > 0 {
			detail += " [FALLING]"
		} else {
			detail += " [STABLE]"
		}
	}
	// Decompose load into runnable vs IO-blocked when load is meaningful
	if load1 > 1 && rates != nil {
		runnable := int(la.Running)
		dState := 0
		for _, p := range snap.Processes {
			if p.State == "D" {
				dState++
			}
		}
		if dState > 0 && rates.CPUBusyPct < 50 {
			detail += fmt.Sprintf("\n                           %d runnable + %d IO-blocked (D state) → load is IO-driven, NOT CPU", runnable, dState)
			if status == CheckOK {
				status = CheckWarn
			}
			advice = "Load driven by IO-waiting processes, not CPU contention"
		} else if runnable > nCPU {
			detail += fmt.Sprintf("\n                           %d runnable threads vs %d cores → CPU saturated, tasks queueing", runnable, nCPU)
		}
	}
	checks = append(checks, CheckResult{
		Category: "CPU", Name: "Load average", Status: status, Detail: detail, Advice: advice,
	})

	// Run queue — which processes are actually running/runnable (R state)
	type rqEntry struct {
		pid     int
		comm    string
		threads int
	}
	var rProcs []rqEntry
	var dProcs []rqEntry
	for _, p := range snap.Processes {
		if p.State == "R" {
			rProcs = append(rProcs, rqEntry{pid: p.PID, comm: p.Comm, threads: p.NumThreads})
		} else if p.State == "D" {
			dProcs = append(dProcs, rqEntry{pid: p.PID, comm: p.Comm, threads: p.NumThreads})
		}
	}
	if len(rProcs) > 0 || len(dProcs) > 0 {
		status = CheckOK
		advice = ""
		// Classify R-state processes
		rDetail := fmt.Sprintf("%d running (R)", len(rProcs))
		if len(dProcs) > 0 {
			rDetail += fmt.Sprintf(", %d IO-blocked (D)", len(dProcs))
		}
		totalActive := len(rProcs) + len(dProcs)
		if totalActive > nCPU*2 {
			status = CheckCrit
			advice = "Far more active tasks than CPUs — severe contention"
		} else if totalActive > nCPU {
			status = CheckWarn
			advice = "More active tasks than CPUs — some are queueing"
		}
		// Show top R-state processes (sorted by thread count already from proc collector)
		if len(rProcs) > 0 {
			rDetail += "\n                           RUNNING:"
			shown := 0
			// Aggregate by comm name
			commCount := map[string]int{}
			commThreads := map[string]int{}
			commPIDs := map[string][]int{}
			for _, p := range rProcs {
				commCount[p.comm]++
				commThreads[p.comm] += p.threads
				if len(commPIDs[p.comm]) < 3 {
					commPIDs[p.comm] = append(commPIDs[p.comm], p.pid)
				}
			}
			// Sort by count descending
			type commSummary struct {
				comm    string
				count   int
				threads int
				pids    []int
			}
			var sorted []commSummary
			for c, n := range commCount {
				sorted = append(sorted, commSummary{comm: c, count: n, threads: commThreads[c], pids: commPIDs[c]})
			}
			for i := 0; i < len(sorted); i++ {
				for j := i + 1; j < len(sorted); j++ {
					if sorted[j].count > sorted[i].count {
						sorted[i], sorted[j] = sorted[j], sorted[i]
					}
				}
			}
			for _, s := range sorted {
				if shown >= 8 {
					rDetail += fmt.Sprintf("\n                             ... and %d more", len(sorted)-shown)
					break
				}
				pidStr := ""
				for k, pid := range s.pids {
					if k > 0 {
						pidStr += ","
					}
					pidStr += fmt.Sprintf("%d", pid)
				}
				if s.count > len(s.pids) {
					pidStr += ",..."
				}
				if s.count == 1 {
					rDetail += fmt.Sprintf("\n                             %-16s  PID %-8s  %d threads", s.comm, pidStr, s.threads)
				} else {
					rDetail += fmt.Sprintf("\n                             %-16s  x%-3d PIDs %-12s  %d threads total", s.comm, s.count, pidStr, s.threads)
				}
				shown++
			}
		}
		if len(dProcs) > 0 {
			rDetail += "\n                           IO-BLOCKED (D state):"
			shown := 0
			commCount := map[string]int{}
			for _, p := range dProcs {
				commCount[p.comm]++
			}
			type cs struct {
				comm  string
				count int
			}
			var sorted []cs
			for c, n := range commCount {
				sorted = append(sorted, cs{comm: c, count: n})
			}
			for i := 0; i < len(sorted); i++ {
				for j := i + 1; j < len(sorted); j++ {
					if sorted[j].count > sorted[i].count {
						sorted[i], sorted[j] = sorted[j], sorted[i]
					}
				}
			}
			for _, s := range sorted {
				if shown >= 5 {
					rDetail += fmt.Sprintf("\n                             ... and %d more", len(sorted)-shown)
					break
				}
				rDetail += fmt.Sprintf("\n                             %-16s  x%d", s.comm, s.count)
				shown++
			}
		}
		checks = append(checks, CheckResult{
			Category: "CPU", Name: "Run queue", Status: status, Detail: rDetail, Advice: advice,
		})
	}

	// PSI CPU
	psi := snap.Global.PSI.CPU.Some.Avg10
	status = CheckOK
	detail = fmt.Sprintf("some avg10=%.1f%%", psi)
	advice = ""
	if psi > 25 {
		status = CheckCrit
		advice = "Severe CPU pressure"
	} else if psi > 10 {
		status = CheckWarn
		advice = "CPU pressure detected"
	}
	checks = append(checks, CheckResult{
		Category: "CPU", Name: "PSI pressure", Status: status, Detail: detail, Advice: advice,
	})

	return checks
}

func checkMemory(snap *model.Snapshot, rates *model.RateSnapshot, result *model.AnalysisResult) []CheckResult {
	var checks []CheckResult
	mem := snap.Global.Memory

	// Memory usage
	if mem.Total > 0 {
		usedPct := float64(mem.Total-mem.Available) / float64(mem.Total) * 100
		status := CheckOK
		detail := fmt.Sprintf("%.1f%% used (%s available / %s total)",
			usedPct, fmtBytesSimple(mem.Available), fmtBytesSimple(mem.Total))
		advice := ""
		if usedPct > 90 {
			status = CheckCrit
			advice = "Memory critically low; risk of OOM"
		} else if usedPct > 80 {
			status = CheckWarn
			advice = "Memory usage elevated"
		}
		checks = append(checks, CheckResult{
			Category: "Memory", Name: "Usage", Status: status, Detail: detail, Advice: advice,
		})
	}

	// Swap usage
	if mem.SwapTotal > 0 {
		swapUsedPct := float64(mem.SwapUsed) / float64(mem.SwapTotal) * 100
		status := CheckOK
		detail := fmt.Sprintf("%.1f%% used (%s / %s)",
			swapUsedPct, fmtBytesSimple(mem.SwapUsed), fmtBytesSimple(mem.SwapTotal))
		advice := ""
		if swapUsedPct > 80 {
			status = CheckCrit
			advice = "Swap nearly full"
		} else if swapUsedPct > 50 {
			status = CheckWarn
			advice = "Significant swap usage"
		}
		checks = append(checks, CheckResult{
			Category: "Memory", Name: "Swap", Status: status, Detail: detail, Advice: advice,
		})
	} else {
		checks = append(checks, CheckResult{
			Category: "Memory", Name: "Swap", Status: CheckOK, Detail: "No swap configured",
		})
	}

	// PSI Memory
	psi := snap.Global.PSI.Memory.Full.Avg10
	status := CheckOK
	detail := fmt.Sprintf("full avg10=%.1f%%", psi)
	advice := ""
	if psi > 15 {
		status = CheckCrit
		advice = "Severe memory pressure"
	} else if psi > 5 {
		status = CheckWarn
		advice = "Memory pressure detected"
	}
	checks = append(checks, CheckResult{
		Category: "Memory", Name: "PSI pressure", Status: status, Detail: detail, Advice: advice,
	})

	// Available memory absolute check
	if mem.Available < 256*1024*1024 { // < 256 MB
		checks = append(checks, CheckResult{
			Category: "Memory", Name: "Available", Status: CheckCrit,
			Detail: fmt.Sprintf("Only %s available", fmtBytesSimple(mem.Available)),
			Advice: "System may OOM soon",
		})
	}

	return checks
}

func checkDisk(snap *model.Snapshot, rates *model.RateSnapshot, result *model.AnalysisResult) []CheckResult {
	var checks []CheckResult

	// Mount usage
	if rates != nil {
		for _, mr := range rates.MountRates {
			status := CheckOK
			detail := fmt.Sprintf("%.1f%% used (%.1f%% free)", mr.UsedPct, mr.FreePct)
			advice := ""
			if mr.FreePct < 5 {
				status = CheckCrit
				advice = fmt.Sprintf("Filesystem %s critically full", mr.MountPoint)
			} else if mr.FreePct < 15 {
				status = CheckWarn
				advice = fmt.Sprintf("Filesystem %s filling up", mr.MountPoint)
			}
			checks = append(checks, CheckResult{
				Category: "Disk", Name: fmt.Sprintf("FS %s", mr.MountPoint),
				Status: status, Detail: detail, Advice: advice,
			})
		}
	}

	// DiskGuard state
	if result != nil {
		dgState := result.DiskGuardWorst
		if dgState == "" {
			dgState = "OK"
		}
		status := CheckOK
		if dgState == "CRIT" {
			status = CheckCrit
		} else if dgState == "WARN" {
			status = CheckWarn
		}
		checks = append(checks, CheckResult{
			Category: "Disk", Name: "DiskGuard",
			Status: status, Detail: fmt.Sprintf("Worst mount state: %s", dgState),
			Advice: func() string {
				if status != CheckOK {
					return "Check: sudo xtop (DiskGuard page)"
				}
				return ""
			}(),
		})
	}

	// Disk latency
	if rates != nil {
		for _, d := range rates.DiskRates {
			if d.AvgAwaitMs > 0 {
				status := CheckOK
				detail := fmt.Sprintf("await=%.0fms util=%.0f%%", d.AvgAwaitMs, d.UtilPct)
				advice := ""
				if d.AvgAwaitMs > 200 {
					status = CheckCrit
					advice = "Disk latency severe"
				} else if d.AvgAwaitMs > 50 {
					status = CheckWarn
					advice = "Disk latency elevated"
				}
				checks = append(checks, CheckResult{
					Category: "Disk", Name: fmt.Sprintf("Dev %s", d.Name),
					Status: status, Detail: detail, Advice: advice,
				})
			}
		}
	}

	// PSI IO
	psi := snap.Global.PSI.IO.Full.Avg10
	status := CheckOK
	detail := fmt.Sprintf("full avg10=%.1f%%", psi)
	advice := ""
	if psi > 15 {
		status = CheckCrit
		advice = "Severe IO pressure"
	} else if psi > 5 {
		status = CheckWarn
		advice = "IO pressure detected"
	}
	checks = append(checks, CheckResult{
		Category: "Disk", Name: "PSI IO pressure", Status: status, Detail: detail, Advice: advice,
	})

	return checks
}

func checkNetwork(snap *model.Snapshot, rates *model.RateSnapshot, result *model.AnalysisResult) []CheckResult {
	var checks []CheckResult

	// Overall network health
	netLevel := engine.NetHealthLevel(snap, rates)
	status := CheckOK
	if netLevel == "CRITICAL" {
		status = CheckCrit
	} else if netLevel == "DEGRADED" {
		status = CheckWarn
	}
	checks = append(checks, CheckResult{
		Category: "Network", Name: "Overall health",
		Status: status, Detail: netLevel,
	})

	// Retransmissions
	if rates != nil && rates.RetransRate > 0 {
		status := CheckOK
		detail := fmt.Sprintf("%.0f/s", rates.RetransRate)
		advice := ""
		if rates.RetransRate > 50 {
			status = CheckCrit
			advice = "Severe packet loss or congestion"
		} else if rates.RetransRate > 5 {
			status = CheckWarn
			advice = "TCP retransmissions elevated"
		}
		checks = append(checks, CheckResult{
			Category: "Network", Name: "TCP retransmits",
			Status: status, Detail: detail, Advice: advice,
		})
	}

	// Drops
	if rates != nil {
		for _, nr := range rates.NetRates {
			totalDrops := nr.RxDropsPS + nr.TxDropsPS
			if totalDrops > 0 {
				status := CheckOK
				if totalDrops > 100 {
					status = CheckCrit
				} else if totalDrops > 10 {
					status = CheckWarn
				}
				checks = append(checks, CheckResult{
					Category: "Network", Name: fmt.Sprintf("%s drops", nr.Name),
					Status: status, Detail: fmt.Sprintf("%.0f/s", totalDrops),
				})
			}
		}
	}

	// Conntrack
	ct := snap.Global.Conntrack
	if ct.Max > 0 {
		pct := float64(ct.Count) / float64(ct.Max) * 100
		status := CheckOK
		detail := fmt.Sprintf("%.0f%% (%d/%d)", pct, ct.Count, ct.Max)
		advice := ""
		if pct > 90 {
			status = CheckCrit
			advice = "Conntrack table nearly full; sysctl net.netfilter.nf_conntrack_max"
		} else if pct > 75 {
			status = CheckWarn
		}
		checks = append(checks, CheckResult{
			Category: "Network", Name: "Conntrack",
			Status: status, Detail: detail, Advice: advice,
		})
	}

	// TCP states
	states := snap.Global.TCPStates
	if states.CloseWait > 50 {
		status := CheckWarn
		if states.CloseWait > 200 {
			status = CheckCrit
		}
		checks = append(checks, CheckResult{
			Category: "Network", Name: "CLOSE_WAIT",
			Status: status, Detail: fmt.Sprintf("%d connections", states.CloseWait),
			Advice: "Application not closing connections properly",
		})
	}

	return checks
}

func checkFDSystemWide(snap *model.Snapshot) []CheckResult {
	fd := snap.Global.FD
	if fd.Max == 0 {
		return nil
	}
	pct := float64(fd.Allocated) / float64(fd.Max) * 100
	status := CheckOK
	detail := fmt.Sprintf("%.0f%% (%d/%d)", pct, fd.Allocated, fd.Max)
	advice := ""
	if pct > 90 {
		status = CheckCrit
		advice = "FD exhaustion imminent; sysctl fs.file-max"
	} else if pct > 70 {
		status = CheckWarn
		advice = "FD usage high"
	}
	return []CheckResult{{
		Category: "System", Name: "File descriptors",
		Status: status, Detail: detail, Advice: advice,
	}}
}

func checkInodeUsage(snap *model.Snapshot, rates *model.RateSnapshot) []CheckResult {
	if rates == nil {
		return nil
	}
	var checks []CheckResult
	for _, mr := range rates.MountRates {
		if mr.InodeUsedPct > 80 {
			status := CheckWarn
			if mr.InodeUsedPct > 95 {
				status = CheckCrit
			}
			checks = append(checks, CheckResult{
				Category: "Disk", Name: fmt.Sprintf("Inodes %s", mr.MountPoint),
				Status: status, Detail: fmt.Sprintf("%.0f%% used", mr.InodeUsedPct),
				Advice: "Find dirs with many small files: find / -xdev -printf '%h\\n' | sort | uniq -c | sort -rn | head",
			})
		}
	}
	return checks
}

func checkFileless(snap *model.Snapshot) []CheckResult {
	procs := snap.Global.FilelessProcs
	if len(procs) == 0 {
		return []CheckResult{{
			Category: "Security", Name: "Fileless processes",
			Status: CheckOK, Detail: "No fileless processes detected",
		}}
	}

	var checks []CheckResult

	// Emit one check per fileless process with auto-investigation
	for _, fp := range procs {
		status := CheckWarn
		if fp.NetConns > 0 {
			status = CheckCrit
		}

		info := investigateProcess(fp.PID)

		// Build multi-line detail block with labeled fields
		var lines []string
		lines = append(lines, fmt.Sprintf("%sexe%s  %s", B, R, fp.ExePath))
		if info.cmdline != "" {
			lines = append(lines, fmt.Sprintf("%scmd%s  %s", B, R, info.cmdline))
		}
		if info.cwd != "" {
			lines = append(lines, fmt.Sprintf("%scwd%s  %s", B, R, info.cwd))
		}
		rssLine := fmt.Sprintf("%sRSS%s  %-8s  %sFDs%s  %d (%s)",
			B, R, fmtBytesSimple(fp.RSS), B, R, info.fdTotal, info.fdSummary)
		lines = append(lines, rssLine)
		if fp.NetConns > 0 {
			lines = append(lines, fmt.Sprintf("%snet%s  %d outbound -> %s",
				B, R, fp.NetConns, strings.Join(model.MaskIPs(fp.RemoteIPs), ", ")))
		}
		if info.mapsHint != "" {
			lines = append(lines, fmt.Sprintf("%smap%s  %s", B, R, info.mapsHint))
		}

		name := fmt.Sprintf("PID %d (%s)", fp.PID, fp.Comm)
		checks = append(checks, CheckResult{
			Category: "Security", Name: name,
			Status: status, Detail: strings.Join(lines, "\n"),
		})
	}

	return checks
}

// processInfo holds auto-investigation results for a fileless process.
type processInfo struct {
	cmdline   string
	cwd       string
	fdTotal   int
	fdSummary string // e.g. "3 files, 1 socket, 2 pipes"
	mapsHint  string // notable mapped files (not libc/ld-linux/vdso)
}

// investigateProcess gathers forensic details from /proc for a given PID.
func investigateProcess(pid int) processInfo {
	var info processInfo
	pidStr := fmt.Sprintf("%d", pid)
	procDir := filepath.Join("/proc", pidStr)

	// cmdline
	if data, err := os.ReadFile(filepath.Join(procDir, "cmdline")); err == nil {
		// cmdline is NUL-delimited
		cmdline := strings.ReplaceAll(string(data), "\x00", " ")
		cmdline = strings.TrimSpace(cmdline)
		if len(cmdline) > 120 {
			cmdline = cmdline[:120] + "..."
		}
		info.cmdline = cmdline
	}

	// cwd
	if target, err := os.Readlink(filepath.Join(procDir, "cwd")); err == nil {
		info.cwd = target
	}

	// FD inventory
	fdDir := filepath.Join(procDir, "fd")
	if entries, err := os.ReadDir(fdDir); err == nil {
		var nFile, nSocket, nPipe, nAnon, nOther int
		info.fdTotal = len(entries)
		for _, e := range entries {
			target, err := os.Readlink(filepath.Join(fdDir, e.Name()))
			if err != nil {
				continue
			}
			switch {
			case strings.HasPrefix(target, "socket:["):
				nSocket++
			case strings.HasPrefix(target, "pipe:["):
				nPipe++
			case strings.HasPrefix(target, "anon_inode:"):
				nAnon++
			case strings.HasPrefix(target, "/"):
				nFile++
			default:
				nOther++
			}
		}
		var summary []string
		if nFile > 0 {
			summary = append(summary, fmt.Sprintf("%d file", nFile))
		}
		if nSocket > 0 {
			summary = append(summary, fmt.Sprintf("%d socket", nSocket))
		}
		if nPipe > 0 {
			summary = append(summary, fmt.Sprintf("%d pipe", nPipe))
		}
		if nAnon > 0 {
			summary = append(summary, fmt.Sprintf("%d anon", nAnon))
		}
		if nOther > 0 {
			summary = append(summary, fmt.Sprintf("%d other", nOther))
		}
		info.fdSummary = strings.Join(summary, ", ")
		if info.fdSummary == "" {
			info.fdSummary = "none"
		}
	}

	// Memory maps — extract notable mapped files (skip standard libs)
	if data, err := os.ReadFile(filepath.Join(procDir, "maps")); err == nil {
		seen := make(map[string]bool)
		var notable []string
		for _, line := range strings.Split(string(data), "\n") {
			fields := strings.Fields(line)
			if len(fields) < 6 {
				continue
			}
			path := fields[len(fields)-1]
			if path == "" || strings.HasPrefix(path, "[") {
				continue // skip [heap], [stack], [vdso], etc.
			}
			if seen[path] {
				continue
			}
			seen[path] = true
			// Skip standard system libraries
			base := filepath.Base(path)
			if strings.HasPrefix(base, "libc") || strings.HasPrefix(base, "ld-linux") ||
				strings.HasPrefix(base, "libpthread") || strings.HasPrefix(base, "libdl") ||
				strings.HasPrefix(base, "libm.") || strings.HasPrefix(base, "librt") ||
				strings.HasPrefix(base, "libgcc") || strings.HasPrefix(base, "linux-vdso") {
				continue
			}
			notable = append(notable, path)
		}
		if len(notable) > 5 {
			notable = notable[:5]
		}
		if len(notable) > 0 {
			info.mapsHint = strings.Join(notable, ", ")
		}
	}

	return info
}

// --- External tool checks (graceful skip if missing) ---

func checkSystemdFailed() []CheckResult {
	path, err := exec.LookPath("systemctl")
	if err != nil {
		return []CheckResult{{
			Category: "System", Name: "Systemd failed units",
			Status: CheckSkip, Detail: "systemctl not found",
		}}
	}
	out, err := exec.Command(path, "--failed", "--no-legend", "--no-pager").Output()
	if err != nil {
		return []CheckResult{{
			Category: "System", Name: "Systemd failed units",
			Status: CheckSkip, Detail: fmt.Sprintf("systemctl error: %v", err),
		}}
	}
	lines := strings.TrimSpace(string(out))
	if lines == "" {
		return []CheckResult{{
			Category: "System", Name: "Systemd failed units",
			Status: CheckOK, Detail: "No failed units",
		}}
	}
	count := len(strings.Split(lines, "\n"))
	status := CheckWarn
	if count > 3 {
		status = CheckCrit
	}
	// Extract unit names
	var units []string
	for _, line := range strings.Split(lines, "\n") {
		fields := strings.Fields(line)
		if len(fields) > 0 {
			units = append(units, fields[0])
		}
	}
	return []CheckResult{{
		Category: "System", Name: "Systemd failed units",
		Status: status, Detail: fmt.Sprintf("%d failed: %s", count, strings.Join(units, ", ")),
		Advice: "systemctl restart <unit>",
	}}
}

func checkDockerDisk() []CheckResult {
	path, err := exec.LookPath("docker")
	if err != nil {
		return nil // don't show Docker section if not installed
	}
	out, err := exec.Command(path, "system", "df", "--format", "{{.Type}}\t{{.TotalCount}}\t{{.Size}}\t{{.Reclaimable}}").Output()
	if err != nil {
		return []CheckResult{{
			Category: "Docker", Name: "Disk usage",
			Status: CheckSkip, Detail: fmt.Sprintf("docker error: %v", err),
		}}
	}
	return []CheckResult{{
		Category: "Docker", Name: "Disk usage",
		Status: CheckOK, Detail: strings.TrimSpace(string(out)),
	}}
}

func checkSecurityUpdates() []CheckResult {
	path, err := exec.LookPath("apt")
	if err != nil {
		return []CheckResult{{
			Category: "System", Name: "Security updates",
			Status: CheckSkip, Detail: "apt not found (non-Debian system)",
		}}
	}
	out, err := exec.Command(path, "list", "--upgradable").Output()
	if err != nil {
		return []CheckResult{{
			Category: "System", Name: "Security updates",
			Status: CheckSkip, Detail: fmt.Sprintf("apt error: %v", err),
		}}
	}
	lines := strings.Split(string(out), "\n")
	secCount := 0
	for _, line := range lines {
		if strings.Contains(strings.ToLower(line), "security") {
			secCount++
		}
	}
	if secCount == 0 {
		return []CheckResult{{
			Category: "System", Name: "Security updates",
			Status: CheckOK, Detail: "No security updates pending",
		}}
	}
	status := CheckWarn
	if secCount > 10 {
		status = CheckCrit
	}
	return []CheckResult{{
		Category: "System", Name: "Security updates",
		Status: status, Detail: fmt.Sprintf("%d security updates pending", secCount),
		Advice: "apt upgrade",
	}}
}

func checkNTPSync() []CheckResult {
	path, err := exec.LookPath("timedatectl")
	if err != nil {
		return []CheckResult{{
			Category: "System", Name: "NTP sync",
			Status: CheckSkip, Detail: "timedatectl not found",
		}}
	}
	out, err := exec.Command(path, "show", "--property=NTPSynchronized", "--value").Output()
	if err != nil {
		return []CheckResult{{
			Category: "System", Name: "NTP sync",
			Status: CheckSkip, Detail: fmt.Sprintf("timedatectl error: %v", err),
		}}
	}
	val := strings.TrimSpace(string(out))
	if val == "yes" {
		return []CheckResult{{
			Category: "System", Name: "NTP sync",
			Status: CheckOK, Detail: "Clock synchronized",
		}}
	}
	return []CheckResult{{
		Category: "System", Name: "NTP sync",
		Status: CheckWarn, Detail: "Clock NOT synchronized",
		Advice: "systemctl enable --now systemd-timesyncd",
	}}
}

func checkSSLCerts() []CheckResult {
	certDir := "/etc/letsencrypt/live"
	entries, err := os.ReadDir(certDir)
	if err != nil {
		return []CheckResult{{
			Category: "SSL", Name: "Certificates",
			Status: CheckSkip, Detail: "No Let's Encrypt certs found",
		}}
	}
	var checks []CheckResult
	now := time.Now()
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		certPath := filepath.Join(certDir, e.Name(), "cert.pem")
		data, err := os.ReadFile(certPath)
		if err != nil {
			continue
		}
		block, _ := pem.Decode(data)
		if block == nil {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			continue
		}
		daysLeft := int(cert.NotAfter.Sub(now).Hours() / 24)
		status := CheckOK
		detail := fmt.Sprintf("%s expires in %d days (%s)", e.Name(), daysLeft, cert.NotAfter.Format("2006-01-02"))
		advice := ""
		if daysLeft < 7 {
			status = CheckCrit
			advice = "certbot renew --force-renewal"
		} else if daysLeft < 30 {
			status = CheckWarn
			advice = "certbot renew"
		}
		checks = append(checks, CheckResult{
			Category: "SSL", Name: fmt.Sprintf("Cert %s", e.Name()),
			Status: status, Detail: detail, Advice: advice,
		})
	}
	if len(checks) == 0 {
		return []CheckResult{{
			Category: "SSL", Name: "Certificates",
			Status: CheckSkip, Detail: "No certificates found",
		}}
	}
	return checks
}

// --- Output renderers ---

func renderDoctorCLI(report DoctorReport, iterInfo string) {
	// Title bar
	ts := report.Timestamp.Format("2006-01-02 15:04:05")
	fmt.Printf("\n %s%s xtop doctor v%s %s — %s%s%s  %s%s%s",
		B, BBlu+FBWht, Version, R,
		B, report.Hostname, R,
		D, ts, R)
	if iterInfo != "" {
		fmt.Printf("  %s%s%s", D, iterInfo, R)
	}
	fmt.Println()
	fmt.Println()

	const nameW = 22 // fixed-width name column

	lastCategory := ""
	for _, c := range report.Checks {
		if c.Category != lastCategory {
			fmt.Println(titleLine(c.Category))
			lastCategory = c.Category
		}

		var icon string
		switch c.Status {
		case CheckOK:
			icon = fmt.Sprintf("%s✓%s", FBGrn, R)
		case CheckWarn:
			icon = fmt.Sprintf("%s⚠%s", FBYel, R)
		case CheckCrit:
			icon = fmt.Sprintf("%s%s✗%s", B, FBRed, R)
		case CheckSkip:
			icon = fmt.Sprintf("%s○%s", D, R)
		}

		// Pad name to fixed width
		name := c.Name
		if len(name) > nameW {
			name = name[:nameW]
		}
		padded := name + strings.Repeat(" ", nameW-len(name))

		// Handle multi-line Detail (fileless processes etc.)
		lines := strings.Split(c.Detail, "\n")
		fmt.Printf(" %s %s%s%s  %s\n", icon, B, padded, R, lines[0])
		// Subsequent detail lines indented under the detail column
		indent := strings.Repeat(" ", nameW+5) // icon(2) + space + name(nameW) + 2 spaces
		for _, extra := range lines[1:] {
			fmt.Printf("%s%s\n", indent, extra)
		}

		// Advice on separate indented dim line
		if c.Advice != "" {
			fmt.Printf("%s%s→ %s%s\n", indent, D, c.Advice, R)
		}
	}

	// Summary footer
	fmt.Println()
	fmt.Println(hr())
	switch report.WorstStatus {
	case CheckOK:
		fmt.Printf(" %s%s✓ All checks passed%s\n", B, FBGrn, R)
	case CheckWarn:
		fmt.Printf(" %s%s⚠ Some warnings detected%s\n", B, FBYel, R)
	case CheckCrit:
		fmt.Printf(" %s%s✗ Critical issues found%s\n", B, FBRed, R)
	}

	// RCA diagnosis if present
	if result, ok := report.RCA.(*model.AnalysisResult); ok && result != nil {
		fmt.Println()
		fmt.Println(titleLine("Diagnosis"))

		// Root cause from narrative engine
		if result.Narrative != nil && result.Narrative.RootCause != "" {
			fmt.Printf(" %s%sROOT CAUSE:%s %s\n", B, FBRed, R, result.Narrative.RootCause)
			if result.Narrative.Impact != "" {
				fmt.Printf(" %sIMPACT:%s     %s\n", B, R, result.Narrative.Impact)
			}
			if result.Narrative.Pattern != "" {
				fmt.Printf(" %sPATTERN:%s    %s\n", B, R, result.Narrative.Pattern)
			}
			fmt.Println()
		} else if result.PrimaryBottleneck != "" {
			fmt.Printf(" %s%sROOT CAUSE:%s %s (confidence: %d%%)\n",
				B, FBRed, R, result.PrimaryBottleneck, result.Confidence)
			fmt.Println()
		}

		// Load average summary in diagnosis (always show when snap available)
		if report.Snap != nil {
			la := report.Snap.Global.CPU.LoadAvg
			nc := report.Snap.Global.CPU.NumCPUs
			if nc == 0 {
				nc = 1
			}
			lpct := la.Load1 / float64(nc) * 100
			var loadLabel string
			switch {
			case lpct < 50:
				loadLabel = "light"
			case lpct < 100:
				loadLabel = "moderate"
			case lpct < 150:
				loadLabel = "overloaded"
			default:
				loadLabel = "severely overloaded"
			}
			fmt.Printf(" %sLOAD AVG:%s   %.2f / %.2f / %.2f  (%d CPUs → %.0f%% capacity = %s)\n",
				B, R, la.Load1, la.Load5, la.Load15, nc, lpct, loadLabel)
			if report.Rates != nil {
				fmt.Printf(" %sCPU BUSY:%s   %.1f%%", B, R, report.Rates.CPUBusyPct)
				if report.Rates.CPUBusyPct > 0 && la.Load1 > 0 {
					// Show if load is CPU-driven or IO-driven
					dCount := 0
					rCount := 0
					for _, p := range report.Snap.Processes {
						if p.State == "D" {
							dCount++
						} else if p.State == "R" {
							rCount++
						}
					}
					if dCount > 0 && report.Rates.CPUBusyPct < 50 {
						fmt.Printf("  (low CPU but high load → %d IO-blocked processes inflating load)", dCount)
					} else if rCount > nc {
						fmt.Printf("  (%d running threads competing for %d cores)", rCount, nc)
					}
				}
				fmt.Println()
			}
		}

		// Evidence with actual values
		if result.Narrative != nil && len(result.Narrative.Evidence) > 0 {
			fmt.Printf("\n %sEVIDENCE:%s\n", B, R)
			for _, ev := range result.Narrative.Evidence {
				fmt.Printf("   %s•%s %s\n", FBYel, R, ev)
			}
			fmt.Println()
		} else if len(result.PrimaryEvidence) > 0 {
			fmt.Printf("\n %sEVIDENCE:%s\n", B, R)
			for _, ev := range result.PrimaryEvidence {
				fmt.Printf("   %s•%s %s\n", FBYel, R, ev)
			}
			fmt.Println()
		}

		// Culprit process
		culpritName := result.PrimaryAppName
		if culpritName == "" {
			culpritName = result.PrimaryProcess
		}
		if culpritName != "" {
			fmt.Printf(" %sCULPRIT:%s    %s (PID %d)\n", B, R, culpritName, result.PrimaryPID)
		}

		// Top offenders per domain
		if len(result.CPUOwners) > 0 && result.PrimaryBottleneck != "" {
			fmt.Printf(" %sTOP CPU:%s    ", B, R)
			for i, o := range result.CPUOwners {
				if i >= 3 {
					break
				}
				if i > 0 {
					fmt.Print(", ")
				}
				fmt.Printf("%s (%.1f%%)", o.Name, o.Pct)
			}
			fmt.Println()
		}
		if len(result.MemOwners) > 0 {
			fmt.Printf(" %sTOP MEM:%s    ", B, R)
			for i, o := range result.MemOwners {
				if i >= 3 {
					break
				}
				if i > 0 {
					fmt.Print(", ")
				}
				if o.Value != "" {
					fmt.Printf("%s (%s)", o.Name, o.Value)
				} else {
					fmt.Printf("%s (%.1f%%)", o.Name, o.Pct)
				}
			}
			fmt.Println()
		}

		// Temporal chain (what happened first)
		if result.TemporalChain != nil && result.TemporalChain.Summary != "" {
			fmt.Printf("\n %sTIMELINE:%s   %s\n", B, R, result.TemporalChain.Summary)
		}

		// Causal chain
		if result.CausalChain != "" {
			fmt.Printf(" %sCAUSAL:%s     %s\n", B, R, result.CausalChain)
		}

		// Suggested actions
		if len(result.Actions) > 0 {
			fmt.Printf("\n %s%sRECOMMENDED ACTIONS:%s\n", B, FBGrn, R)
			for i, a := range result.Actions {
				if i >= 5 {
					break
				}
				fmt.Printf("   %s%d.%s %s\n", B, i+1, R, a.Summary)
				if a.Command != "" {
					fmt.Printf("      %s$ %s%s\n", D, a.Command, R)
				}
			}
		}

		// Exhaustion predictions
		if len(result.Exhaustions) > 0 {
			for _, ex := range result.Exhaustions {
				if ex.EstMinutes > 0 && ex.EstMinutes < 60 {
					fmt.Printf("\n %s%s⚠ EXHAUSTION WARNING:%s %s at %.0f%% — estimated %.0f minutes to full\n",
						B, FBRed, R, ex.Resource, ex.CurrentPct, ex.EstMinutes)
				}
			}
		}
	}
	fmt.Println()
}

func renderDoctorJSON(report DoctorReport) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(report)
}

func renderDoctorMarkdown(report DoctorReport) string {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("# xtop Doctor Report — %s\n\n", report.Hostname))
	sb.WriteString(fmt.Sprintf("**Timestamp:** %s\n\n", report.Timestamp.Format(time.RFC3339)))

	statusIcon := map[CheckStatus]string{
		CheckOK:   "✅",
		CheckWarn: "⚠️",
		CheckCrit: "❌",
		CheckSkip: "⏭️",
	}

	sb.WriteString("| Status | Category | Check | Detail | Advice |\n")
	sb.WriteString("|--------|----------|-------|--------|--------|\n")
	for _, c := range report.Checks {
		sb.WriteString(fmt.Sprintf("| %s | %s | %s | %s | %s |\n",
			statusIcon[c.Status], c.Category, c.Name, c.Detail, c.Advice))
	}

	sb.WriteString(fmt.Sprintf("\n**Overall:** %s\n", report.WorstStatus))

	sb.WriteString("\n---\n*Generated by [xtop](https://github.com/ftahirops/xtop) doctor*\n")
	return sb.String()
}

func renderDoctorCron(report DoctorReport) error {
	if report.WorstStatus == CheckOK {
		// Silent if OK — cron-friendly
		return nil
	}

	// One-line summary of issues
	var issues []string
	for _, c := range report.Checks {
		if c.Status == CheckWarn || c.Status == CheckCrit {
			issues = append(issues, fmt.Sprintf("[%s] %s/%s: %s", c.Status, c.Category, c.Name, c.Detail))
		}
	}
	fmt.Printf("xtop %s: %s — %s\n", report.Hostname, report.WorstStatus, strings.Join(issues, "; "))

	if report.WorstStatus == CheckCrit {
		return ExitCodeError{Code: 2}
	}
	return ExitCodeError{Code: 1}
}

// --- State change tracking ---

func checkStateChanged(report DoctorReport, dataDir string) bool {
	stateFile := filepath.Join(dataDir, "last_health")
	currentState := fmt.Sprintf("%d", report.WorstStatus)

	prev, err := os.ReadFile(stateFile)
	if err != nil {
		// No previous state — write current and report change
		_ = os.MkdirAll(dataDir, 0700)
		_ = os.WriteFile(stateFile, []byte(currentState), 0600)
		return report.WorstStatus != CheckOK // Only alert if not OK
	}

	prevState := strings.TrimSpace(string(prev))
	changed := prevState != currentState
	_ = os.WriteFile(stateFile, []byte(currentState), 0600)
	return changed
}

// --- Alert dispatch ---

func sendDoctorAlert(report DoctorReport, cfg Config) {
	if !checkStateChanged(report, cfg.DataDir) {
		return // No state change, no alert
	}

	userCfg := xtopcfg.Load()

	notifier := engine.NewNotifier(engine.AlertConfig{
		Webhook:          func() string { if cfg.AlertWebhook != "" { return cfg.AlertWebhook }; return userCfg.Alerts.Webhook }(),
		Command:          func() string { if cfg.AlertCommand != "" { return cfg.AlertCommand }; return userCfg.Alerts.Command }(),
		Email:            userCfg.Alerts.Email,
		SlackWebhook:     userCfg.Alerts.SlackWebhook,
		TelegramBotToken: userCfg.Alerts.TelegramBotToken,
		TelegramChatID:   userCfg.Alerts.TelegramChatID,
	})

	if !notifier.Enabled() {
		return
	}

	// Build alert text
	var issues []string
	for _, c := range report.Checks {
		if c.Status == CheckWarn || c.Status == CheckCrit {
			issues = append(issues, fmt.Sprintf("[%s] %s/%s: %s", c.Status, c.Category, c.Name, c.Detail))
		}
	}

	subject := fmt.Sprintf("xtop %s: %s", report.Hostname, report.WorstStatus)
	body := fmt.Sprintf("Host: %s\nStatus: %s\nTime: %s\n\nIssues:\n%s",
		report.Hostname, report.WorstStatus, report.Timestamp.Format(time.RFC3339),
		strings.Join(issues, "\n"))

	notifier.SendFormatted("doctor_alert", subject, body, map[string]interface{}{
		"hostname": report.Hostname,
		"status":   report.WorstStatus.String(),
		"checks":   report.Checks,
	})
}
