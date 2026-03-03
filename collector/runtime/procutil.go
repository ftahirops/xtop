package runtime

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

// readProcRSSMB reads VmRSS from /proc/PID/status and returns MB.
func readProcRSSMB(pid int) float64 {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "VmRSS:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				val, _ := strconv.ParseFloat(fields[1], 64)
				// VmRSS is in kB
				return val / 1024
			}
		}
	}
	return 0
}

// readProcThreads reads thread count from /proc/PID/status.
func readProcThreads(pid int) int {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "Threads:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				val, _ := strconv.Atoi(fields[1])
				return val
			}
		}
	}
	return 0
}

// readProcVolCtxSwitches reads voluntary_ctxt_switches from /proc/PID/status.
func readProcVolCtxSwitches(pid int) int {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "voluntary_ctxt_switches:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				val, _ := strconv.Atoi(fields[1])
				return val
			}
		}
	}
	return 0
}

// readProcCmdline reads /proc/PID/cmdline and returns the null-separated args.
func readProcCmdline(pid int) string {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
	if err != nil {
		return ""
	}
	return string(data)
}

// readProcEnviron reads /proc/PID/environ and returns key=value pairs.
func readProcEnviron(pid int) map[string]string {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/environ", pid))
	if err != nil {
		return nil
	}
	env := make(map[string]string)
	for _, entry := range strings.Split(string(data), "\x00") {
		if idx := strings.IndexByte(entry, '='); idx > 0 {
			env[entry[:idx]] = entry[idx+1:]
		}
	}
	return env
}

// readProcExe reads /proc/PID/exe symlink target.
func readProcExe(pid int) string {
	target, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
	if err != nil {
		return ""
	}
	return target
}

// readProcCPUPct returns approximate CPU% for a process from /proc/PID/stat.
// This is a rough heuristic — returns 0 if unavailable.
func readProcCPUPct(pid int) float64 {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return 0
	}
	// Fields after the comm (which may contain spaces/parens)
	// Find closing paren
	s := string(data)
	idx := strings.LastIndex(s, ")")
	if idx < 0 || idx+2 >= len(s) {
		return 0
	}
	fields := strings.Fields(s[idx+2:])
	if len(fields) < 12 {
		return 0
	}
	// fields[11] = utime, fields[12] = stime (in clock ticks)
	utime, _ := strconv.ParseFloat(fields[11], 64)
	stime, _ := strconv.ParseFloat(fields[12], 64)
	// This is cumulative; for a rough snapshot we just check if it's high
	// Actual CPU% would need delta calculation. Return total ticks as proxy.
	_ = utime + stime
	return 0 // can't compute instantaneous CPU% from a single read
}
