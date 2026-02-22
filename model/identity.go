package model

import "time"

// ServerRole identifies what purpose a server serves.
type ServerRole string

const (
	RoleNATGateway       ServerRole = "nat_gateway"
	RoleRouter           ServerRole = "router"
	RoleFirewall         ServerRole = "firewall"
	RoleWebServer        ServerRole = "web_server"
	RoleDatabaseServer   ServerRole = "database_server"
	RoleDockerHost       ServerRole = "docker_host"
	RoleK8sNode          ServerRole = "k8s_node"
	RoleMailServer       ServerRole = "mail_server"
	RoleDNSServer        ServerRole = "dns_server"
	RoleLoadBalancer     ServerRole = "load_balancer"
	RoleCICDRunner       ServerRole = "cicd_runner"
	RoleMonitoringServer ServerRole = "monitoring_server"
	RoleAppServer        ServerRole = "app_server"
	RoleVPNServer        ServerRole = "vpn_server"
)

// DetectedService represents a service discovered on the system.
type DetectedService struct {
	Name       string            `json:"name"`
	Version    string            `json:"version,omitempty"`
	Ports      []int             `json:"ports,omitempty"`
	Running    bool              `json:"running"`
	Healthy    bool              `json:"healthy"`
	Unit       string            `json:"unit,omitempty"`
	BinaryPath string            `json:"binary_path,omitempty"`
	Extra      map[string]string `json:"extra,omitempty"`
}

// DockerContainer represents a discovered Docker container.
type DockerContainer struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Image    string `json:"image"`
	Status   string `json:"status"`
	Ports    string `json:"ports,omitempty"`
	Purpose  string `json:"purpose,omitempty"`  // inferred from image: "vpn", "web", "database", etc.
}

// K8sNodeInfo holds Kubernetes node information.
type K8sNodeInfo struct {
	NodeRole   string   `json:"node_role"`
	PodCount   int      `json:"pod_count"`
	Namespaces []string `json:"namespaces,omitempty"`
}

// WebsiteInfo holds discovered website/vhost information.
type WebsiteInfo struct {
	Domain     string `json:"domain"`
	Port       int    `json:"port"`
	ConfigFile string `json:"config_file"`
	SSLExpiry  string `json:"ssl_expiry,omitempty"`
}

// DatabaseInfo holds discovered database information.
type DatabaseInfo struct {
	Engine      string  `json:"engine"`
	Name        string  `json:"name"`
	SizeMB      float64 `json:"size_mb,omitempty"`
	Connections int     `json:"connections,omitempty"`
	ReplicaRole string  `json:"replica_role,omitempty"`
}

// HAProxyInfo holds HAProxy analysis results.
type HAProxyInfo struct {
	Running      bool     `json:"running"`
	Version      string   `json:"version,omitempty"`
	ConfigFile   string   `json:"config_file"`
	Mode         string   `json:"mode"`          // "reverse_proxy", "forward_proxy", "both", "tcp_lb"
	Frontends    []string `json:"frontends,omitempty"`
	Backends     []string `json:"backends,omitempty"`
	BindPorts    []int    `json:"bind_ports,omitempty"`
	Evidence     []string `json:"evidence,omitempty"` // reasons for classification
}

// KeepalivedInfo holds keepalived/VRRP analysis results.
type KeepalivedInfo struct {
	Running    bool     `json:"running"`
	VIPs       []string `json:"vips,omitempty"`
	State      string   `json:"state,omitempty"`      // "MASTER", "BACKUP"
	Interface  string   `json:"interface,omitempty"`
	Priority   int      `json:"priority,omitempty"`
}

// VPNInfo holds VPN detection results.
type VPNInfo struct {
	Type       string   `json:"type"`                  // "wireguard", "openvpn", "ipsec"
	Interface  string   `json:"interface,omitempty"`    // "wg0", "tun0", etc.
	Port       int      `json:"port,omitempty"`
	Peers      int      `json:"peers,omitempty"`
	Container  string   `json:"container,omitempty"`    // container name if containerized
	Evidence   []string `json:"evidence,omitempty"`
}

// RoleScore holds evidence-based confidence for a role classification.
type RoleScore struct {
	Role       ServerRole `json:"role"`
	Score      int        `json:"score"`
	MaxScore   int        `json:"max_score"`
	Confidence int        `json:"confidence"` // percentage 0-100
	Evidence   []string   `json:"evidence"`
}

// ServerIdentity is the complete result of server identity discovery.
type ServerIdentity struct {
	DiscoveredAt time.Time         `json:"discovered_at"`
	Roles        []ServerRole      `json:"roles"`
	RoleScores   []RoleScore       `json:"role_scores,omitempty"`
	Services     []DetectedService `json:"services"`
	Containers   []DockerContainer `json:"containers,omitempty"`
	K8s          *K8sNodeInfo      `json:"k8s,omitempty"`
	Websites     []WebsiteInfo     `json:"websites,omitempty"`
	Databases    []DatabaseInfo    `json:"databases,omitempty"`
	HAProxy      *HAProxyInfo      `json:"haproxy,omitempty"`
	Keepalived   *KeepalivedInfo   `json:"keepalived,omitempty"`
	VPN          *VPNInfo          `json:"vpn,omitempty"`
	IPForward    bool              `json:"ip_forward"`
	HasNFTables  bool              `json:"has_nftables"`
	HasIPTables  bool              `json:"has_iptables"`
}

// HasRole returns true if the server has the given role.
func (id *ServerIdentity) HasRole(role ServerRole) bool {
	for _, r := range id.Roles {
		if r == role {
			return true
		}
	}
	return false
}

// ServiceByName returns the first service matching the given name, or nil.
func (id *ServerIdentity) ServiceByName(name string) *DetectedService {
	for i := range id.Services {
		if id.Services[i].Name == name {
			return &id.Services[i]
		}
	}
	return nil
}
