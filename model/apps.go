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

	// Docker stacks (grouped containers)
	Stacks []DockerStack `json:"stacks,omitempty"`

	// Docker orchestration type: "standalone", "compose", "swarm", "k8s", "mixed"
	OrchestrationType string `json:"orchestration_type,omitempty"`
}

// DockerStack represents a group of containers from the same compose project or standalone.
type DockerStack struct {
	Name        string               `json:"name"`         // compose project name or container name
	Type        string               `json:"type"`         // "compose", "swarm", "k8s", "standalone"
	WorkingDir  string               `json:"working_dir"`  // compose file directory
	ComposeFile string               `json:"compose_file"` // compose file path
	Networks    []DockerStackNetwork `json:"networks,omitempty"`
	Containers  []AppDockerContainer `json:"containers,omitempty"`
	HealthScore int                  `json:"health_score"`
	Issues      []string             `json:"issues,omitempty"`
}

// DockerStackNetwork holds network info for a stack.
type DockerStackNetwork struct {
	Name   string `json:"name"`
	Driver string `json:"driver"`
	Subnet string `json:"subnet"`
}

// DockerPort holds a published port mapping.
type DockerPort struct {
	ContainerPort int    `json:"container_port"`
	HostPort      int    `json:"host_port"`
	HostIP        string `json:"host_ip"`
	Protocol      string `json:"protocol"` // tcp/udp
}

// DockerMount holds a volume/bind mount.
type DockerMount struct {
	Type     string `json:"type"`     // bind, volume, tmpfs
	Source   string `json:"source"`   // host path or volume name
	Target   string `json:"target"`   // container path
	ReadOnly bool   `json:"read_only"`
}

// DockerContainerNet holds per-network info for a container.
type DockerContainerNet struct {
	Name    string `json:"name"`
	IP      string `json:"ip"`
	Gateway string `json:"gateway"`
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

	// From container inspect
	Ports         []DockerPort         `json:"ports,omitempty"`
	Mounts        []DockerMount        `json:"mounts,omitempty"`
	Networks      []DockerContainerNet `json:"networks,omitempty"`
	RestartPolicy string               `json:"restart_policy"` // no/always/unless-stopped/on-failure
	User          string               `json:"user"`
	Privileged    bool                 `json:"privileged"`
	Entrypoint    string               `json:"entrypoint"`
	Command       string               `json:"command"`
	MemLimit      uint64               `json:"mem_limit"`      // bytes, 0 = unlimited
	CPUQuota      float64              `json:"cpu_quota"`       // cores, 0 = unlimited
	CreatedAt     string               `json:"created_at"`
	HasHealthChk  bool                 `json:"has_health_check"`
	RWLayerSize   int64                `json:"rw_layer_size"`
	StackName     string               `json:"stack_name"`     // compose project or "standalone"
	StackType     string               `json:"stack_type"`     // compose/swarm/k8s/standalone
	ImageSize     int64                `json:"image_size"`
}

// AppMetrics holds all detected application instances.
type AppMetrics struct {
	Instances []AppInstance `json:"instances,omitempty"`
}
