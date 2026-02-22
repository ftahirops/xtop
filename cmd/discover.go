package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	xtopcfg "github.com/ftahirops/xtop/config"
	"github.com/ftahirops/xtop/identity"
	"github.com/ftahirops/xtop/model"
)

// runDiscover performs server identity discovery and saves results.
func runDiscover(cfg Config) error {
	fmt.Fprintf(os.Stderr, "Discovering server identity...\n")

	id := identity.Discover()

	// Save to config
	userCfg := xtopcfg.Load()
	userCfg.ServerIdentity = id
	if err := xtopcfg.Save(userCfg); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: could not save identity to config: %v\n", err)
	}

	// Render output
	if cfg.JSONMode {
		return renderDiscoverJSON(id)
	}
	renderDiscoverCLI(id)
	return nil
}

func renderDiscoverJSON(id *model.ServerIdentity) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(id)
}

func renderDiscoverCLI(id *model.ServerIdentity) {
	const (
		reset   = "\033[0m"
		bold    = "\033[1m"
		red     = "\033[31m"
		green   = "\033[32m"
		yellow  = "\033[33m"
		dim     = "\033[2m"
		cyan    = "\033[36m"
		magenta = "\033[35m"
		blue    = "\033[34m"
	)

	hostname, _ := os.Hostname()
	fmt.Printf("\n%s%sxtop discover — %s%s\n", bold, cyan, hostname, reset)
	fmt.Printf("%s%s%s\n\n", dim, id.DiscoveredAt.Format("2006-01-02 15:04:05"), reset)

	// Roles with confidence
	if len(id.RoleScores) > 0 {
		fmt.Printf("%s%s-- Roles --%s\n", bold, cyan, reset)
		for _, rs := range id.RoleScores {
			badge := roleBadge(string(rs.Role))
			assigned := ""
			color := dim
			if id.HasRole(rs.Role) {
				assigned = " *"
				color = magenta
			}
			fmt.Printf("  %s%s%-14s%s  %s%3d%%%s  %sscore %d/%d%s%s\n",
				color, bold, badge, reset,
				color, rs.Confidence, reset,
				dim, rs.Score, rs.MaxScore, reset,
				assigned)
		}
		fmt.Println()

		// Show evidence for assigned roles
		for _, rs := range id.RoleScores {
			if !id.HasRole(rs.Role) {
				continue
			}
			badge := roleBadge(string(rs.Role))
			fmt.Printf("  %s%s%s evidence:%s\n", bold, cyan, badge, reset)
			for _, ev := range rs.Evidence {
				fmt.Printf("    %s%s%s\n", dim, ev, reset)
			}
		}
		fmt.Println()
	} else {
		fmt.Printf("%s%sRoles%s  %sNone detected%s\n\n", bold, cyan, reset, dim, reset)
	}

	// VPN info
	if id.VPN != nil {
		fmt.Printf("%s%s-- VPN (%s) --%s\n", bold, cyan, id.VPN.Type, reset)
		if id.VPN.Interface != "" {
			fmt.Printf("  Interface:  %s%s%s\n", green, id.VPN.Interface, reset)
		}
		if id.VPN.Port > 0 {
			fmt.Printf("  Port:       %d\n", id.VPN.Port)
		}
		if id.VPN.Peers > 0 {
			fmt.Printf("  Peers:      %s%d connected%s\n", green, id.VPN.Peers, reset)
		}
		if id.VPN.Container != "" {
			fmt.Printf("  Container:  %s\n", id.VPN.Container)
		}
		for _, ev := range id.VPN.Evidence {
			fmt.Printf("  %s%s%s\n", dim, ev, reset)
		}
		fmt.Println()
	}

	// HAProxy info
	if id.HAProxy != nil {
		modeLabel := id.HAProxy.Mode
		switch modeLabel {
		case "reverse_proxy":
			modeLabel = "Reverse Proxy"
		case "forward_proxy":
			modeLabel = "Forward Proxy"
		case "both":
			modeLabel = "Reverse + Forward Proxy"
		case "tcp_lb":
			modeLabel = "TCP Load Balancer"
		}
		fmt.Printf("%s%s-- HAProxy (%s) --%s\n", bold, cyan, modeLabel, reset)
		if id.HAProxy.ConfigFile != "" {
			fmt.Printf("  Config:     %s\n", id.HAProxy.ConfigFile)
		}
		if len(id.HAProxy.Frontends) > 0 {
			fmt.Printf("  Frontends:  %s\n", strings.Join(id.HAProxy.Frontends, ", "))
		}
		if len(id.HAProxy.Backends) > 0 {
			fmt.Printf("  Backends:   %s\n", strings.Join(id.HAProxy.Backends, ", "))
		}
		if len(id.HAProxy.BindPorts) > 0 {
			var ps []string
			for _, p := range id.HAProxy.BindPorts {
				ps = append(ps, fmt.Sprintf("%d", p))
			}
			fmt.Printf("  Bind:       %s\n", strings.Join(ps, ", "))
		}
		for _, ev := range id.HAProxy.Evidence {
			fmt.Printf("  %s%s%s\n", dim, ev, reset)
		}
		fmt.Println()
	}

	// Keepalived info
	if id.Keepalived != nil {
		fmt.Printf("%s%s-- Keepalived --%s\n", bold, cyan, reset)
		if id.Keepalived.State != "" {
			stateColor := green
			if id.Keepalived.State == "BACKUP" {
				stateColor = yellow
			}
			fmt.Printf("  State:      %s%s%s\n", stateColor, id.Keepalived.State, reset)
		}
		if id.Keepalived.Interface != "" {
			fmt.Printf("  Interface:  %s\n", id.Keepalived.Interface)
		}
		if id.Keepalived.Priority > 0 {
			fmt.Printf("  Priority:   %d\n", id.Keepalived.Priority)
		}
		if len(id.Keepalived.VIPs) > 0 {
			fmt.Printf("  %s%sFloating IPs:%s\n", bold, magenta, reset)
			for _, vip := range id.Keepalived.VIPs {
				fmt.Printf("    %s%s%s\n", magenta, vip, reset)
			}
		}
		fmt.Println()
	}

	// Network config
	if id.IPForward || id.HasIPTables || id.HasNFTables {
		fmt.Printf("%s%s-- Network --%s\n", bold, cyan, reset)
		if id.IPForward {
			note := ""
			dockerRunning := false
			for _, svc := range id.Services {
				if svc.Name == "docker" && svc.Running {
					dockerRunning = true
					break
				}
			}
			if dockerRunning && !id.HasRole(model.RoleNATGateway) && !id.HasRole(model.RoleRouter) {
				note = fmt.Sprintf("  %s(set by Docker)%s", dim, reset)
			}
			fmt.Printf("  %s*%s IP Forwarding  %senabled%s%s\n", yellow, reset, yellow, reset, note)
		}
		if id.HasIPTables {
			fmt.Printf("  %s*%s iptables       %suser rules present%s\n", yellow, reset, yellow, reset)
		}
		if id.HasNFTables {
			fmt.Printf("  %s*%s nftables       %suser rules present%s\n", yellow, reset, yellow, reset)
		}
		fmt.Println()
	}

	// Services
	if len(id.Services) > 0 {
		fmt.Printf("%s%s-- Services (%d) --%s\n", bold, cyan, len(id.Services), reset)
		for _, svc := range id.Services {
			icon := green + "+" + reset
			if !svc.Running {
				icon = red + "x" + reset
			}
			version := ""
			if svc.Version != "" {
				version = fmt.Sprintf(" %sv%s%s", dim, svc.Version, reset)
			}
			ports := ""
			if len(svc.Ports) > 0 {
				var ps []string
				for _, p := range svc.Ports {
					ps = append(ps, fmt.Sprintf("%d", p))
				}
				ports = fmt.Sprintf(" %s[%s]%s", dim, strings.Join(ps, ","), reset)
			}
			unit := ""
			if svc.Unit != "" {
				unit = fmt.Sprintf(" %s(%s)%s", dim, svc.Unit, reset)
			}
			health := ""
			if svc.Healthy {
				health = fmt.Sprintf(" %shealthy%s", green, reset)
			}
			fmt.Printf("  %s %-18s%s%s%s%s\n", icon, svc.Name, version, ports, unit, health)
		}
		fmt.Println()
	}

	// Docker containers
	if len(id.Containers) > 0 {
		fmt.Printf("%s%s-- Containers (%d) --%s\n", bold, cyan, len(id.Containers), reset)
		for _, c := range id.Containers {
			icon := green + "+" + reset
			if !strings.HasPrefix(c.Status, "Up") {
				icon = red + "x" + reset
			}
			purpose := ""
			if c.Purpose != "" {
				purpose = fmt.Sprintf(" %s[%s]%s", blue, c.Purpose, reset)
			}
			ports := ""
			if c.Ports != "" {
				ports = fmt.Sprintf(" %s%s%s", dim, c.Ports, reset)
			}
			fmt.Printf("  %s %-20s %s%-30s%s%s %s%s%s%s\n",
				icon, c.Name, dim, c.Image, reset, purpose, dim, c.Status, reset, ports)
		}
		fmt.Println()
	}

	// Kubernetes
	if id.K8s != nil {
		fmt.Printf("%s%s-- Kubernetes --%s\n", bold, cyan, reset)
		fmt.Printf("  Role: %s%s%s\n", magenta, id.K8s.NodeRole, reset)
		fmt.Printf("  Pods: %d\n", id.K8s.PodCount)
		if len(id.K8s.Namespaces) > 0 {
			fmt.Printf("  Namespaces: %s\n", strings.Join(id.K8s.Namespaces, ", "))
		}
		fmt.Println()
	}

	// Websites
	if len(id.Websites) > 0 {
		fmt.Printf("%s%s-- Websites (%d) --%s\n", bold, cyan, len(id.Websites), reset)
		for _, w := range id.Websites {
			ssl := ""
			if w.SSLExpiry != "" {
				ssl = fmt.Sprintf(" %sSSL: %s%s", dim, w.SSLExpiry, reset)
			}
			fmt.Printf("  %s*%s %-30s :%d  %s%s%s%s\n",
				green, reset, w.Domain, w.Port, dim, w.ConfigFile, reset, ssl)
		}
		fmt.Println()
	}

	// Databases
	if len(id.Databases) > 0 {
		fmt.Printf("%s%s-- Databases (%d) --%s\n", bold, cyan, len(id.Databases), reset)
		for _, db := range id.Databases {
			role := ""
			if db.ReplicaRole != "" {
				role = fmt.Sprintf(" %s[%s]%s", yellow, db.ReplicaRole, reset)
			}
			fmt.Printf("  %s*%s %-12s %s%s\n", green, reset, db.Engine, db.Name, role)
		}
		fmt.Println()
	}

	fmt.Printf("%s%sSaved to %s%s\n\n", dim, green, xtopcfg.Path(), reset)
}

// roleBadge returns a human-readable badge for a role.
func roleBadge(role string) string {
	badges := map[string]string{
		"nat_gateway":       "NAT-GW",
		"router":            "ROUTER",
		"firewall":          "FIREWALL",
		"web_server":        "WEB",
		"database_server":   "DATABASE",
		"docker_host":       "DOCKER",
		"k8s_node":          "K8S",
		"mail_server":       "MAIL",
		"dns_server":        "DNS",
		"load_balancer":     "LB",
		"cicd_runner":       "CI/CD",
		"monitoring_server": "MONITORING",
		"app_server":        "APP",
		"vpn_server":        "VPN",
	}
	if b, ok := badges[role]; ok {
		return b
	}
	return strings.ToUpper(role)
}
