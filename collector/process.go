package collector

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/ftahirops/xtop/model"
	"github.com/ftahirops/xtop/util"
)

// ProcessCollector reads per-PID stats from /proc.
type ProcessCollector struct {
	MaxProcs int // maximum number of processes to collect (top by CPU+IO)
}

func (p *ProcessCollector) Name() string { return "process" }

func (p *ProcessCollector) Collect(snap *model.Snapshot) error {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return fmt.Errorf("read /proc: %w", err)
	}

	var procs []model.ProcessMetrics
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		pid := util.ParseInt(e.Name())
		if pid <= 0 {
			continue
		}
		pm, err := readProcess(pid)
		if err != nil {
			continue // process may have exited
		}
		procs = append(procs, pm)
	}

	maxProcs := p.MaxProcs
	if maxProcs <= 0 {
		maxProcs = 50
	}

	if len(procs) <= maxProcs {
		snap.Processes = procs
		return nil
	}

	// Keep top N/2 by CPU time AND top N/2 by IO writes, merged and deduped.
	// This ensures IO-heavy processes (disk writers) are always tracked.
	half := maxProcs / 2

	// Top by CPU time
	sort.Slice(procs, func(i, j int) bool {
		return (procs[i].UTime + procs[i].STime) > (procs[j].UTime + procs[j].STime)
	})
	seen := make(map[int]bool)
	var merged []model.ProcessMetrics
	for i := 0; i < len(procs) && len(merged) < half; i++ {
		merged = append(merged, procs[i])
		seen[procs[i].PID] = true
	}

	// Top by IO writes
	sort.Slice(procs, func(i, j int) bool {
		return procs[i].WriteBytes > procs[j].WriteBytes
	})
	for i := 0; i < len(procs) && len(merged) < maxProcs; i++ {
		if !seen[procs[i].PID] {
			merged = append(merged, procs[i])
			seen[procs[i].PID] = true
		}
	}

	// Fill remaining slots with top CPU if space left
	sort.Slice(procs, func(i, j int) bool {
		return (procs[i].UTime + procs[i].STime) > (procs[j].UTime + procs[j].STime)
	})
	for i := 0; i < len(procs) && len(merged) < maxProcs; i++ {
		if !seen[procs[i].PID] {
			merged = append(merged, procs[i])
			seen[procs[i].PID] = true
		}
	}

	snap.Processes = merged
	return nil
}

func readProcess(pid int) (model.ProcessMetrics, error) {
	var pm model.ProcessMetrics
	pm.PID = pid
	pidDir := fmt.Sprintf("/proc/%d", pid)

	// Read /proc/[pid]/stat
	if err := readProcStat(pidDir, &pm); err != nil {
		return pm, err
	}

	// Read /proc/[pid]/status (for memory, ctxt switches)
	readProcStatus(pidDir, &pm)

	// Read /proc/[pid]/io (may fail without permissions)
	readProcIO(pidDir, &pm)

	// Read cgroup
	readProcCgroup(pidDir, &pm)

	// Read FD count and limits
	readProcFD(pidDir, &pm)

	return pm, nil
}

func readProcStat(pidDir string, pm *model.ProcessMetrics) error {
	content, err := util.ReadFileString(filepath.Join(pidDir, "stat"))
	if err != nil {
		return err
	}

	// /proc/[pid]/stat format: pid (comm) state ppid ...
	// comm can contain spaces and parens, so find the last ')' to split
	closeIdx := strings.LastIndex(content, ")")
	if closeIdx < 0 {
		return fmt.Errorf("bad stat format")
	}
	openIdx := strings.Index(content, "(")
	if openIdx < 0 {
		return fmt.Errorf("bad stat format")
	}

	pm.Comm = content[openIdx+1 : closeIdx]
	if closeIdx+2 >= len(content) {
		return fmt.Errorf("stat too short")
	}
	rest := strings.Fields(content[closeIdx+2:]) // skip ") "

	if len(rest) < 37 {
		return fmt.Errorf("stat too short: %d fields", len(rest))
	}

	// Fields after "(comm) ": 0=state 1=ppid 7=minflt 9=majflt 11=utime 12=stime 17=threads 36=processor
	pm.State = rest[0]
	pm.PPID = util.ParseInt(rest[1])
	pm.MinFault = util.ParseUint64(rest[7])
	pm.MajFault = util.ParseUint64(rest[9])
	pm.UTime = util.ParseUint64(rest[11])
	pm.STime = util.ParseUint64(rest[12])
	pm.NumThreads = util.ParseInt(rest[17])
	pm.Processor = util.ParseInt(rest[36])

	return nil
}

func readProcStatus(pidDir string, pm *model.ProcessMetrics) {
	kv, err := util.ParseKeyValueFile(filepath.Join(pidDir, "status"))
	if err != nil {
		return
	}
	pm.RSS = parseStatusKB(kv["VmRSS"])
	pm.VmSize = parseStatusKB(kv["VmSize"])
	pm.VmSwap = parseStatusKB(kv["VmSwap"])
	pm.VoluntaryCtxSwitches = util.ParseUint64(kv["voluntary_ctxt_switches"])
	pm.NonVoluntaryCtxSwitches = util.ParseUint64(kv["nonvoluntary_ctxt_switches"])
}

// parseStatusKB parses a /proc/[pid]/status value like "1234 kB" → bytes.
// Returns 0 if the field is empty (e.g. kernel threads have no VmRSS).
func parseStatusKB(s string) uint64 {
	fields := strings.Fields(s)
	if len(fields) == 0 {
		return 0
	}
	return util.ParseUint64(fields[0]) * 1024
}

func readProcIO(pidDir string, pm *model.ProcessMetrics) {
	kv, err := util.ParseKeyValueFile(filepath.Join(pidDir, "io"))
	if err != nil {
		return
	}
	pm.ReadBytes = util.ParseUint64(kv["read_bytes"])
	pm.WriteBytes = util.ParseUint64(kv["write_bytes"])
	pm.SyscR = util.ParseUint64(kv["syscr"])
	pm.SyscW = util.ParseUint64(kv["syscw"])
}

func readProcCgroup(pidDir string, pm *model.ProcessMetrics) {
	content, err := util.ReadFileString(filepath.Join(pidDir, "cgroup"))
	if err != nil {
		return
	}
	// Take the first line (or the line with hierarchy 0 for v2)
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		// format: hierarchy-ID:controller-list:cgroup-path
		parts := strings.SplitN(line, ":", 3)
		if len(parts) == 3 {
			if parts[0] == "0" {
				// cgroup v2
				pm.CgroupPath = parts[2]
				return
			}
		}
	}
	// Fallback: use first line's path
	for _, line := range strings.Split(content, "\n") {
		parts := strings.SplitN(strings.TrimSpace(line), ":", 3)
		if len(parts) == 3 {
			pm.CgroupPath = parts[2]
			return
		}
	}
}

func readProcFD(pidDir string, pm *model.ProcessMetrics) {
	entries, err := os.ReadDir(filepath.Join(pidDir, "fd"))
	if err != nil {
		return
	}
	pm.FDCount = len(entries)

	// Parse /proc/PID/limits for "Max open files" soft limit
	lines, err := util.ReadFileLines(filepath.Join(pidDir, "limits"))
	if err != nil {
		return
	}
	for _, line := range lines {
		if strings.HasPrefix(line, "Max open files") {
			fields := strings.Fields(line)
			// Format: "Max open files            1048576              1048576              files"
			// The fields after splitting: ["Max", "open", "files", "SOFT", "HARD", "units"]
			if len(fields) >= 4 {
				pm.FDSoftLimit = util.ParseUint64(fields[3])
			}
			break
		}
	}
}
