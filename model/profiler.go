package model

// Profiler-specific roles (extend ServerRole from identity.go)
const (
	RoleWebHosting ServerRole = "web_hosting"
	RoleHypervisor ServerRole = "hypervisor"
	RoleContainer  ServerRole = "container_platform"
	RoleDatabase   ServerRole = RoleDatabaseServer // alias for consistency
	RoleMixed      ServerRole = "mixed_workload"
	RoleUnknown    ServerRole = "unknown"
)

// RuleStatus indicates whether an audit rule passed.
type RuleStatus int

const (
	RulePass RuleStatus = iota
	RuleWarn
	RuleFail
	RuleSkip // not applicable to this role
)

func (s RuleStatus) String() string {
	switch s {
	case RulePass:
		return "PASS"
	case RuleWarn:
		return "WARN"
	case RuleFail:
		return "FAIL"
	case RuleSkip:
		return "SKIP"
	}
	return "?"
}

// OptDomain groups related optimization audit rules.
// Distinct from Domain (RCA domain in snapshot.go).
type OptDomain string

const (
	OptDomainKernel   OptDomain = "Kernel"
	OptDomainNetwork  OptDomain = "Network"
	OptDomainMemory   OptDomain = "Memory"
	OptDomainIO       OptDomain = "IO"
	OptDomainSecurity OptDomain = "Security"
	OptDomainApps     OptDomain = "Apps"
)

// AuditRule is a single optimization check result.
type AuditRule struct {
	Domain      OptDomain  `json:"domain"`
	Name        string     `json:"name"`
	Description string     `json:"description"`
	Current     string     `json:"current"`
	Recommended string     `json:"recommended"`
	Impact      string     `json:"impact"`
	Status      RuleStatus `json:"status"`
	Weight      int        `json:"weight"` // 1=minor, 5=important, 10=critical
}

// DomainScore is the optimization score for one domain.
type DomainScore struct {
	Domain OptDomain   `json:"domain"`
	Score  int         `json:"score"` // 0-100
	Issues int         `json:"issues"`
	Rules  []AuditRule `json:"rules"`
}

// ServiceCensus describes a detected service and its resource usage.
type ServiceCensus struct {
	Name        string  `json:"name"`
	DisplayName string  `json:"display_name"`
	CPUPct      float64 `json:"cpu_pct"`
	RSSMB       float64 `json:"rss_mb"`
	IOPSRead    float64 `json:"iops_read"`
	IOPSWrite   float64 `json:"iops_write"`
	Connections int     `json:"connections"`
	Processes   int     `json:"processes"`
}

// ServerProfile is the complete system profiler output.
type ServerProfile struct {
	Role         ServerRole      `json:"role"`
	RoleDetail   string          `json:"role_detail"`
	PanelName    string          `json:"panel_name"`
	OverallScore int             `json:"overall_score"`
	Domains      []DomainScore   `json:"domains"`
	Services     []ServiceCensus `json:"services"`
}
