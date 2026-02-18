package cgroup

import (
	"os"
	"strings"
)

// Version represents the cgroup version.
type Version int

const (
	V1     Version = 1
	V2     Version = 2
	Hybrid Version = 3
)

// DetectVersion determines whether the system uses cgroup v1, v2, or hybrid.
func DetectVersion() Version {
	// Check for v2: /sys/fs/cgroup/cgroup.controllers exists
	if _, err := os.Stat("/sys/fs/cgroup/cgroup.controllers"); err == nil {
		// Check if v1 hierarchies also exist (hybrid)
		if hasV1Hierarchies() {
			return Hybrid
		}
		return V2
	}
	return V1
}

func hasV1Hierarchies() bool {
	entries, err := os.ReadDir("/sys/fs/cgroup")
	if err != nil {
		return false
	}
	for _, e := range entries {
		if e.IsDir() {
			switch e.Name() {
			case "cpu", "cpuacct", "cpu,cpuacct", "memory", "blkio":
				return true
			}
		}
	}
	return false
}

// CgroupRoot returns the cgroup v2 root path.
func CgroupRoot() string {
	// Check /proc/mounts for cgroup2 mount
	data, err := os.ReadFile("/proc/mounts")
	if err != nil {
		return "/sys/fs/cgroup"
	}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 3 && fields[2] == "cgroup2" {
			return fields[1]
		}
	}
	return "/sys/fs/cgroup"
}
