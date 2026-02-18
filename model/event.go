package model

import "time"

// Event represents a detected performance incident.
type Event struct {
	ID             string           `json:"id"`
	StartTime      time.Time        `json:"start_time"`
	EndTime        time.Time        `json:"end_time,omitempty"`
	Duration       int              `json:"duration_sec,omitempty"`
	PeakHealth     HealthLevel      `json:"peak_health"`
	Bottleneck     string           `json:"bottleneck"`
	PeakScore      int              `json:"peak_score"`
	Evidence       []string         `json:"evidence,omitempty"`
	CausalChain    string           `json:"causal_chain,omitempty"`
	CulpritCgroup  string           `json:"culprit_cgroup,omitempty"`
	CulpritProcess string           `json:"culprit_process,omitempty"`
	CulpritPID     int              `json:"culprit_pid,omitempty"`
	PeakCPUBusy    float64          `json:"peak_cpu_busy,omitempty"`
	PeakMemUsedPct float64          `json:"peak_mem_used_pct,omitempty"`
	PeakIOPSI      float64          `json:"peak_io_psi,omitempty"`
	Active         bool             `json:"active"`
	Timeline       []TimelineEntry  `json:"timeline,omitempty"`
}

// TimelineEntry is a timestamped milestone within an incident.
type TimelineEntry struct {
	Time    time.Time `json:"time"`
	Message string    `json:"message"`
}
