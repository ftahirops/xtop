package model

// AppInstance represents a detected application instance.
type AppInstance struct {
	ID          string `json:"id"`           // "mysql-1", "nginx-0"
	AppType     string `json:"app_type"`     // "mysql", "nginx", etc.
	DisplayName string `json:"display_name"` // "MySQL (1)", "Nginx"
	PID         int    `json:"pid"`
	Port        int    `json:"port"`
	Status      string `json:"status"` // "active"
	Version     string `json:"version"`
	UptimeSec   int64  `json:"uptime_sec"`

	// Tier 1: process-level (always available)
	CPUPct      float64 `json:"cpu_pct"`
	RSSMB       float64 `json:"rss_mb"`
	Threads     int     `json:"threads"`
	FDs         int     `json:"fds"`
	Connections int     `json:"connections"`

	// Tier 2: deep metrics (needs credentials)
	HasDeepMetrics bool              `json:"has_deep_metrics"`
	DeepMetrics    map[string]string `json:"deep_metrics,omitempty"`

	// Health
	HealthScore  int      `json:"health_score"`
	HealthIssues []string `json:"health_issues,omitempty"`

	// Config
	ConfigPath string `json:"config_path,omitempty"`
	NeedsCreds bool   `json:"needs_creds"`

	// Docker containers (only for Docker app type)
	Containers []AppDockerContainer `json:"containers,omitempty"`
}

// AppDockerContainer holds per-container stats.
type AppDockerContainer struct {
	ID            string  `json:"id"`
	Name          string  `json:"name"`
	Image         string  `json:"image"`
	State         string  `json:"state"`          // running, exited, paused, etc.
	Status        string  `json:"status"`         // "Up 7 weeks", "Exited (0) 12 months ago"
	Health        string  `json:"health"`         // healthy, unhealthy, none
	CPUPct        float64 `json:"cpu_pct"`
	MemUsedBytes  float64 `json:"mem_used_bytes"`
	MemLimitBytes float64 `json:"mem_limit_bytes"`
	MemPct        float64 `json:"mem_pct"`
	NetRxBytes    float64 `json:"net_rx_bytes"`
	NetTxBytes    float64 `json:"net_tx_bytes"`
	BlockRead     float64 `json:"block_read"`
	BlockWrite    float64 `json:"block_write"`
	PIDs          int     `json:"pids"`
	RestartCount  int     `json:"restart_count"`
	ExitCode      int     `json:"exit_code"`
}

// AppMetrics holds all detected application instances.
type AppMetrics struct {
	Instances []AppInstance `json:"instances,omitempty"`
}
