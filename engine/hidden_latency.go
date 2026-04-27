package engine

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/ftahirops/xtop/model"
)

// ─── Hidden Latency Detection v2 ────────────────────────────────────────────
//
// Replaces the rough ctxSwitchRate/cpuPct heuristic with scheduler-level
// metrics from /proc/schedstat. This gives us actual wait-time percentages
// and scheduler latency, not approximations.
//
// /proc/schedstat format (per-CPU line):
//   cpuN <running_time> <waiting_time> <timeslices>
//
// The ratio waiting_time / (running_time + waiting_time) is the true
// "scheduler latency" — time tasks spend waiting in the runqueue.

// readSchedstat parses /proc/schedstat and returns average wait ratio.
func readSchedstat() (waitRatio float64, avgSliceTimeUs float64, err error) {
	data, err := os.ReadFile("/proc/schedstat")
	if err != nil {
		return 0, 0, err
	}

	var totalWait, totalRun uint64
	var totalSlices uint64
	lines := strings.Split(string(data), "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "version") || strings.HasPrefix(line, "timestamp") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 4 || !strings.HasPrefix(fields[0], "cpu") {
			continue
		}
		// fields[1] = running_time (ns), fields[2] = waiting_time (ns), fields[3] = timeslices
		runNs, _ := strconv.ParseUint(fields[1], 10, 64)
		waitNs, _ := strconv.ParseUint(fields[2], 10, 64)
		slices, _ := strconv.ParseUint(fields[3], 10, 64)
		totalRun += runNs
		totalWait += waitNs
		totalSlices += slices
	}

	if totalRun+totalWait == 0 {
		return 0, 0, nil
	}

	waitRatio = float64(totalWait) / float64(totalRun+totalWait) * 100.0

	if totalSlices > 0 {
		avgNs := float64(totalRun) / float64(totalSlices)
		avgSliceTimeUs = avgNs / 1000.0
	}

	return waitRatio, avgSliceTimeUs, nil
}

// readSchedDebug reads /proc/sys/kernel/sched_* tunables for context.
func readSchedDebug() (latencyTargetMs int, minGranularityMs int, wakeupGranularityMs int) {
	// Defaults
	latencyTargetMs = 24
	minGranularityMs = 4
	wakeupGranularityMs = 4

	// Try to read actual values
	if data, err := os.ReadFile("/proc/sys/kernel/sched_latency_ns"); err == nil {
		if ns, err := strconv.ParseInt(strings.TrimSpace(string(data)), 10, 64); err == nil {
			latencyTargetMs = int(ns / 1_000_000)
		}
	}
	if data, err := os.ReadFile("/proc/sys/kernel/sched_min_granularity_ns"); err == nil {
		if ns, err := strconv.ParseInt(strings.TrimSpace(string(data)), 10, 64); err == nil {
			minGranularityMs = int(ns / 1_000_000)
		}
	}
	if data, err := os.ReadFile("/proc/sys/kernel/sched_wakeup_granularity_ns"); err == nil {
		if ns, err := strconv.ParseInt(strings.TrimSpace(string(data)), 10, 64); err == nil {
			wakeupGranularityMs = int(ns / 1_000_000)
		}
	}
	return
}

// DetectHiddenLatencyV2 detects scheduler-level hidden latency using
// /proc/schedstat instead of rough heuristics.
func DetectHiddenLatencyV2(curr *model.Snapshot, rates *model.RateSnapshot, result *model.AnalysisResult) {
	if rates == nil {
		return
	}

	waitRatio, avgSliceUs, err := readSchedstat()
	if err != nil {
		// Fall back to v1 heuristic
		detectHiddenLatency(curr, rates, result)
		return
	}

	latencyTarget, minGran, _ := readSchedDebug()

	// Determine if wait ratio is abnormal
	// Normal: < 5% wait time
	// Elevated: 5-15%
	// Critical: > 15%
	var severity string
	var score int
	switch {
	case waitRatio > 15:
		severity = "crit"
		score = 80
	case waitRatio > 8:
		severity = "warn"
		score = 50
	case waitRatio > 5:
		severity = "info"
		score = 25
	default:
		return
	}

	// Only flag if CPU busy is moderate (not already flagged as CPU bottleneck)
	if rates.CPUBusyPct > 90 && result.PrimaryBottleneck == BottleneckCPU {
		return // Already clearly a CPU bottleneck
	}

	// Build detailed message
	msg := fmt.Sprintf("Scheduler wait time %.1f%% (tasks spending %.0f%% of time in runqueue)",
		waitRatio, waitRatio)

	if avgSliceUs > 10000 {
		msg += fmt.Sprintf(" — very long timeslices (avg %.0f us)", avgSliceUs)
	}

	// Check if scheduler tunables might be contributing
	if latencyTarget > 50 {
		msg += fmt.Sprintf(" — sched_latency=%dms is high", latencyTarget)
	}
	if minGran > 10 {
		msg += fmt.Sprintf(" — sched_min_granularity=%dms is high", minGran)
	}

	result.Warnings = append(result.Warnings, model.Warning{
		Signal:   "hidden_latency_v2",
		Severity: severity,
		Value:    fmt.Sprintf("%.1f%%", waitRatio),
		Detail:   msg,
	})

	// If hidden latency is severe and no primary bottleneck is detected,
	// suggest CPU as the likely root cause (scheduler saturation).
	if score >= 50 && result.PrimaryScore < 30 {
		result.HiddenLatency = true
		result.HiddenLatencyDesc = msg
		result.HiddenLatencyPct = waitRatio
	}
}
