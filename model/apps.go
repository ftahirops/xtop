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
}

// AppMetrics holds all detected application instances.
type AppMetrics struct {
	Instances []AppInstance `json:"instances,omitempty"`
}
