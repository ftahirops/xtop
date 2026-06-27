package collector

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// containerCgroupMarkers are substrings found in cgroup paths of containerised
// processes.  The PID namespace inside a container starts at 1, so low-PID
// processes there are NOT trusted host kernel threads and must NOT be skipped.
//
// This is a heuristic marker list; non-standard or future runtimes may not
// match any marker.  Known gaps should be added here conservatively to avoid
// host false-positives (treating a host process as containerised).
var containerCgroupMarkers = []string{
	"docker",
	"containerd",
	"kubepods",
	"crio",
	"cri-containerd",
	"lxc",
	"machine.slice",
	"libpod", // Podman rootless / libpod (cgroupv2: …/libpod-<id>.scope)
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
	data, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "cgroup"))
	if err != nil {
		return false
	}
	return isContainerizedCgroup(string(data))
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
