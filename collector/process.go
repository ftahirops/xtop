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

	// Sort by CPU time (utime+stime) descending, keep top N
	sort.Slice(procs, func(i, j int) bool {
		a := procs[i].UTime + procs[i].STime
		b := procs[j].UTime + procs[j].STime
		return a > b
	})
	maxProcs := p.MaxProcs
	if maxProcs <= 0 {
		maxProcs = 50
	}
	if len(procs) > maxProcs {
		procs = procs[:maxProcs]
	}
	snap.Processes = procs
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
	rest := strings.Fields(content[closeIdx+2:]) // skip ") "

	if len(rest) < 40 {
		return fmt.Errorf("stat too short")
	}

	pm.State = rest[0]
	pm.PPID = util.ParseInt(rest[1])
	pm.UTime = util.ParseUint64(rest[11])
	pm.STime = util.ParseUint64(rest[12])
	pm.NumThreads = util.ParseInt(rest[17])
	pm.Processor = util.ParseInt(rest[36])
	pm.MinFault = util.ParseUint64(rest[7])
	pm.MajFault = util.ParseUint64(rest[9])

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
