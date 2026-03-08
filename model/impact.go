package model

// ImpactScore represents the composite impact a process has on system health.
type ImpactScore struct {
	PID     int
	Rank    int
	Comm    string
	Service string // resolved from cgroup: k8s pod, systemd unit, or docker container
	Cgroup  string

	// Actual metrics
	CPUPct float64 // actual CPU% from process rates

	// Component scores (0-1 normalized)
	CPUSaturation float64
	PSIContrib    float64
	IOWait        float64
	MemGrowth     float64
	NetRetrans    float64

	// Penalties
	NewnessPenalty float64 // +0.15 for processes started <60s ago
	ChangePenalty  float64 // reserved for future use

	// Final score
	Composite float64 // 0-100 weighted sum

	// Context
	Threads int
	RSS     uint64
	WriteMBs float64
}
