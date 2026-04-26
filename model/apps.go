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

	// Resource share — populated by engine.EnrichAppResourceShare() after all
	// apps are collected. See docs/USAGE.md §6 for the SRE framing.
	Share AppResourceShare `json:"share,omitempty"`

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

	// Websites (for hosting panels, nginx, apache, php-fpm)
	Websites []WebsiteMetrics `json:"websites,omitempty"`
}

// WebsiteMetrics holds per-website resource usage.
type WebsiteMetrics struct {
	Domain     string  `json:"domain"`
	Active     bool    `json:"active"`
	CPUPct     float64 `json:"cpu_pct"`
	RSSMB      float64 `json:"rss_mb"`
	Workers    int     `json:"workers"`
	MaxWorkers int     `json:"max_workers"`
	HitsPerMin int     `json:"hits_per_min"`
	DBSizeMB   float64 `json:"db_size_mb"`
	DiskMB     float64 `json:"disk_mb"`
	PHPVersion string  `json:"php_version,omitempty"`
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

// AppResourceShare is the SRE-actionable per-app resource view.
//
// Design principle: never collapse dimensions into a single composite score.
// Each dimension is reported independently in capacity terms (cores, GB,
// MB/s, #active conns) with a rank across apps and, when an incident is
// firing, a contribution-share of the bottleneck dimension.
//
// All fields are derived from per-tick data — no historical state required
// beyond what the rates snapshot already carries. Per-app baselines (7d Δ)
// are a planned follow-up and will land on this struct later.
type AppResourceShare struct {
	// Absolute per-dimension usage
	CPUCoresUsed float64 `json:"cpu_cores_used"`  // e.g. 2.80 (out of NumCPUs)
	MemRSSBytes  uint64  `json:"mem_rss_bytes"`   // RSS in bytes
	ReadMBs      float64 `json:"read_mbs"`        // disk read rate
	WriteMBs     float64 `json:"write_mbs"`       // disk write rate
	NetConns     int     `json:"net_conns"`       // established TCP/UDP connections

	// Share-of-capacity (0..100) per dimension
	CPUPctOfSystem float64 `json:"cpu_pct_of_system"` // (CoresUsed/NumCPUs)*100
	MemPctOfSystem float64 `json:"mem_pct_of_system"` // (RSS/MemTotal)*100
	IOPctOfBusiest float64 `json:"io_pct_of_busiest"` // app IO / worst disk MB/s

	// Headroom — what's still available on THIS host after this app
	CPUCoresHeadroom float64 `json:"cpu_cores_headroom"`
	MemBytesHeadroom uint64  `json:"mem_bytes_headroom"`

	// Rank across all apps (1 = highest consumer on that dimension).
	// Zero = not ranked (fewer than N apps on that dimension).
	RankCPU int `json:"rank_cpu,omitempty"`
	RankMem int `json:"rank_mem,omitempty"`
	RankIO  int `json:"rank_io,omitempty"`
	RankNet int `json:"rank_net,omitempty"`

	// Composite operator-ready impact score from process rates (0..100).
	// Not a sum of dimensions — it's the engine's ImpactScore, already a
	// well-calibrated "how much is this contributing to pain" measure.
	Impact float64 `json:"impact"`

	// BottleneckShare is the % contribution this app makes to the CURRENT
	// primary bottleneck dimension. Populated only when an incident is
	// active. Lets the UI answer "who's causing 72% of the IO pressure?"
	BottleneckDimension string  `json:"bottleneck_dimension,omitempty"` // "cpu" | "memory" | "io" | "network"
	BottleneckSharePct  float64 `json:"bottleneck_share_pct,omitempty"`
}

// AppMetrics holds all detected application instances.
type AppMetrics struct {
	Instances []AppInstance `json:"instances,omitempty"`
}
