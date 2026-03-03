package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/ftahirops/xtop/collector"
	"github.com/ftahirops/xtop/engine"
	"github.com/ftahirops/xtop/model"
)

// runProc implements the `xtop proc <pid>` subcommand.
// Displays a deep per-PID report.
func runProc(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: xtop proc <pid> [--json]")
	}

	pid, err := strconv.Atoi(args[0])
	if err != nil {
		return fmt.Errorf("invalid PID: %s", args[0])
	}

	jsonOut := false
	intervalSec := 3
	for i := 1; i < len(args); i++ {
		switch args[i] {
		case "--json":
			jsonOut = true
		case "--interval", "-i":
			if i+1 < len(args) {
				i++
				fmt.Sscanf(args[i], "%d", &intervalSec)
			}
		}
	}

	// Collect deep PID info
	info, err := collector.CollectProcDeep(pid)
	if err != nil {
		return fmt.Errorf("cannot read process %d: %w", pid, err)
	}

	// Collect system metrics for impact scoring
	fmt.Fprintf(os.Stderr, "Collecting system metrics (%ds)...\n", intervalSec)
	snap, rates, result := collectOrQuery(intervalSec)

	if jsonOut {
		data := map[string]interface{}{
			"process": info,
		}
		if snap != nil {
			scores := engine.ComputeImpactScores(snap, rates, result)
			for _, s := range scores {
				if s.PID == pid {
					data["impact"] = s
					break
				}
			}
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(data)
	}

	return procANSI(info, snap, rates, result)
}

// procANSI renders the deep PID report with ANSI colors.
func procANSI(info *collector.ProcDeepInfo, snap *model.Snapshot, rates *model.RateSnapshot, result *model.AnalysisResult) error {
	fmt.Println()
	fmt.Printf("  %sxtop proc%s — PID %s%d%s\n", B, R, FBCyn, info.PID, R)
	fmt.Println()

	// Identity block
	fmt.Printf("  %sIDENTITY%s\n", B, R)
	fmt.Printf("    %-14s %s\n", "Command:", info.Comm)
	if info.Cmdline != "" {
		cmd := info.Cmdline
		if len(cmd) > 72 {
			cmd = cmd[:72] + "..."
		}
		fmt.Printf("    %-14s %s\n", "Cmdline:", cmd)
	}
	fmt.Printf("    %-14s %s\n", "State:", info.State)
	fmt.Printf("    %-14s %d\n", "PPID:", info.PPID)
	if info.Service != "" {
		fmt.Printf("    %-14s %s\n", "Service:", info.Service)
	}
	if info.Cgroup != "" {
		cg := info.Cgroup
		if len(cg) > 60 {
			cg = "..." + cg[len(cg)-57:]
		}
		fmt.Printf("    %-14s %s\n", "Cgroup:", cg)
	}
	if !info.StartTime.IsZero() {
		fmt.Printf("    %-14s %s (up %s)\n", "Started:", info.StartTime.Format("Jan 02 15:04:05"), fmtDuration(info.Uptime))
	}
	fmt.Printf("    %-14s %d\n", "Threads:", info.NumThreads)
	fmt.Println()

	// Resource usage
	fmt.Printf("  %sRESOURCE USAGE%s\n", B, R)
	fmt.Printf("    %-14s %s\n", "VmSize:", subcmdFmtBytes(info.VmSize))
	fmt.Printf("    %-14s %s\n", "VmRSS:", subcmdFmtBytes(info.VmRSS))
	if info.VmPeak > 0 {
		fmt.Printf("    %-14s %s\n", "VmPeak:", subcmdFmtBytes(info.VmPeak))
	}
	if info.VmSwap > 0 {
		fmt.Printf("    %-14s %s%s%s\n", "VmSwap:", FBYel, subcmdFmtBytes(info.VmSwap), R)
	}
	fmt.Printf("    %-14s %s read / %s written\n", "IO:",
		subcmdFmtBytes(info.ReadBytes), subcmdFmtBytes(info.WriteBytes))
	fmt.Printf("    %-14s %d read / %d write\n", "Syscalls:", info.SyscR, info.SyscW)
	fmt.Println()

	// File descriptors
	fmt.Printf("  %sFILE DESCRIPTORS%s\n", B, R)
	fdPct := float64(0)
	if info.FDLimit > 0 {
		fdPct = float64(info.FDCount) / float64(info.FDLimit) * 100
	}
	fdColor := FBGrn
	if fdPct > 80 {
		fdColor = FBRed
	} else if fdPct > 50 {
		fdColor = FBYel
	}
	fmt.Printf("    %-14s %s%d%s / %d (%.1f%%)\n", "Open FDs:", fdColor, info.FDCount, R, info.FDLimit, fdPct)

	if len(info.TopFDs) > 0 {
		// Count FD types
		sockets, pipes, files, anon := 0, 0, 0, 0
		for _, fd := range info.TopFDs {
			switch {
			case strings.HasPrefix(fd.Target, "socket:"):
				sockets++
			case strings.HasPrefix(fd.Target, "pipe:"):
				pipes++
			case strings.HasPrefix(fd.Target, "anon_inode:"):
				anon++
			default:
				files++
			}
		}
		fmt.Printf("    %-14s %d socket, %d pipe, %d file, %d anon_inode (sampled %d)\n",
			"FD types:", sockets, pipes, files, anon, len(info.TopFDs))
	}
	fmt.Println()

	// Network connections
	if len(info.TCPConns) > 0 || len(info.UDPConns) > 0 {
		fmt.Printf("  %sNETWORK CONNECTIONS%s\n", B, R)

		if len(info.TCPConns) > 0 {
			// Count by state
			stateCounts := make(map[string]int)
			for _, c := range info.TCPConns {
				stateCounts[c.State]++
			}
			fmt.Printf("    %sTCP:%s", B, R)
			var parts []string
			for state, count := range stateCounts {
				parts = append(parts, fmt.Sprintf("%s=%d", state, count))
			}
			fmt.Printf(" %s\n", strings.Join(parts, ", "))

			// Show first 10
			n := 10
			if len(info.TCPConns) < n {
				n = len(info.TCPConns)
			}
			for i := 0; i < n; i++ {
				c := info.TCPConns[i]
				if c.RemoteAddr == "0.0.0.0" && c.RemotePort == 0 {
					fmt.Printf("      %s:%d  %s%s%s\n",
						c.LocalAddr, c.LocalPort, D, c.State, R)
				} else {
					fmt.Printf("      %s:%d → %s:%d  %s%s%s\n",
						c.LocalAddr, c.LocalPort, c.RemoteAddr, c.RemotePort, D, c.State, R)
				}
			}
			if len(info.TCPConns) > n {
				fmt.Printf("      %s... +%d more%s\n", D, len(info.TCPConns)-n, R)
			}
		}

		if len(info.UDPConns) > 0 {
			fmt.Printf("    %sUDP:%s %d connections\n", B, R, len(info.UDPConns))
		}
		fmt.Println()
	}

	// Impact score
	if snap != nil && rates != nil {
		scores := engine.ComputeImpactScores(snap, rates, result)
		for _, s := range scores {
			if s.PID == info.PID {
				fmt.Printf("  %sIMPACT SCORE%s\n", B, R)
				fmt.Printf("    %-14s %s\n", "Composite:", colorByImpact(s.Composite))
				fmt.Printf("    %-14s CPU=%.0f%% PSI=%.0f%% IO=%.0f%% Mem=%.0f%% Net=%.0f%%\n",
					"Components:",
					s.CPUSaturation*100, s.PSIContrib*100,
					s.IOWait*100, s.MemGrowth*100, s.NetRetrans*100)
				if s.NewnessPenalty > 0 {
					fmt.Printf("    %-14s %s+%.0f%% (started <60s ago)%s\n",
						"Newness:", FBYel, s.NewnessPenalty*100, R)
				}
				fmt.Printf("    %-14s #%d\n", "Rank:", s.Rank)
				fmt.Println()
				break
			}
		}
	}

	return nil
}

// fmtDuration formats a duration to a human-readable string.
func fmtDuration(d time.Duration) string {
	if d < time.Minute {
		return fmt.Sprintf("%.0fs", d.Seconds())
	}
	if d < time.Hour {
		m := int(d.Minutes())
		s := int(d.Seconds()) - m*60
		return fmt.Sprintf("%dm%ds", m, s)
	}
	h := int(d.Hours())
	m := int(d.Minutes()) - h*60
	if h >= 24 {
		days := h / 24
		h = h % 24
		return fmt.Sprintf("%dd%dh%dm", days, h, m)
	}
	return fmt.Sprintf("%dh%dm", h, m)
}
