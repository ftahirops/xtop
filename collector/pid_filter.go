package collector

import (
	"os"
	"path/filepath"
	"strings"
)

// containerCgroupMarkers are substrings found in cgroup paths of containerised
// processes.  The PID namespace inside a container starts at 1, so low-PID
// processes there are NOT trusted host kernel threads and must NOT be skipped.
var containerCgroupMarkers = []string{
	"docker",
	"containerd",
	"kubepods",
	"crio",
	"cri-containerd",
	"lxc",
	"machine.slice",
}

// isContainerizedCgroup reports whether a cgroup path string belongs to a
// containerised process.  It checks for well-known container-runtime markers.
// The check is O(len(markers) * len(path)) and is very cheap.
func isContainerizedCgroup(cgroupPath string) bool {
	lower := strings.ToLower(cgroupPath)
	for _, marker := range containerCgroupMarkers {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}

// isContainerizedPID reads /proc/<pid>/cgroup and returns true when the
// process lives inside a container cgroup.  The file is tiny (a few hundred
// bytes at most) so the read is cheap even in a per-process loop.
// Returns false on any I/O error (conservative: treat as host process).
func isContainerizedPID(pid int) bool {
	data, err := os.ReadFile(filepath.Join("/proc", itoa(pid), "cgroup"))
	if err != nil {
		return false
	}
	return isContainerizedCgroup(string(data))
}

// itoa converts an int to its decimal string representation without importing
// strconv (which is already imported in every caller, but keeping this local
// avoids a cross-package import for a tiny helper).
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	pos := len(buf)
	for n > 0 {
		pos--
		buf[pos] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		pos--
		buf[pos] = '-'
	}
	return string(buf[pos:])
}

// shouldSkipLowPID returns true when a process should be excluded from the
// security / fileless scans solely because of its low PID.
//
// Decision matrix:
//
//	PID < 100 AND host process  → skip  (genuine kernel thread / early daemon)
//	PID < 100 AND containerised → scan  (container PID-ns starts at 1; low PID
//	                                     is not privileged from the host's view)
//	PID >= 100                  → scan  (always)
//
// Always skip PID 0 (idle/swapper) and the collector's own PID (selfPID > 0).
func shouldSkipLowPID(pid int, containerized bool, selfPID int) bool {
	if pid == 0 {
		return true
	}
	if selfPID > 0 && pid == selfPID {
		return true
	}
	if pid < 100 && !containerized {
		return true
	}
	return false
}
