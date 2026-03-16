//go:build linux

package profiler

import (
	"os"
	"os/exec"
	"strings"

	"github.com/ftahirops/xtop/model"
	"github.com/ftahirops/xtop/util"
)

// detectRole determines the server's primary role using smart shortcuts.
func detectRole(snap *model.Snapshot) (model.ServerRole, string, string) {
	// Priority 1: Panel detection (instant — known role)
	if role, detail, panel := detectPanel(); role != model.RoleUnknown {
		return role, detail, panel
	}

	// Priority 2: Proxmox hypervisor host
	if snap.Global.Proxmox != nil && snap.Global.Proxmox.IsProxmoxHost {
		detail := "Proxmox VE"
		if snap.Global.Proxmox.PVEVersion != "" {
			detail += " " + snap.Global.Proxmox.PVEVersion
		}
		return model.RoleHypervisor, detail, "Proxmox"
	}

	// Priority 3: Container platform (Docker/K8s dominant)
	if isContainerPlatform(snap) {
		return model.RoleContainer, detectContainerDetail(snap), ""
	}

	// Priority 4: Load balancer (HAProxy/Nginx-LB dominant, low disk usage)
	if isLoadBalancer(snap) {
		return model.RoleLoadBalancer, detectLBDetail(snap), ""
	}

	// Priority 5: Database server (MySQL/Postgres dominant)
	if isDBServer(snap) {
		return model.RoleDatabase, detectDBDetail(snap), ""
	}

	// Priority 6: Mail server
	if isMailServer(snap) {
		return model.RoleMailServer, "Postfix/Dovecot", ""
	}

	// Priority 7: Router / Firewall
	if isRouter() {
		return model.RoleRouter, "IP forwarding enabled", ""
	}

	// Priority 8: Mixed workload (multiple significant services)
	return model.RoleMixed, detectMixedDetail(snap), ""
}

func detectPanel() (model.ServerRole, string, string) {
	// Plesk
	if _, err := os.Stat("/usr/local/psa/version"); err == nil {
		ver, _ := util.ReadFileString("/usr/local/psa/version")
		ver = strings.TrimSpace(ver)
		detail := "Plesk"
		if ver != "" {
			detail += " " + strings.SplitN(ver, " ", 2)[0]
		}
		return model.RoleWebHosting, detail, "Plesk"
	}

	// cPanel
	if _, err := os.Stat("/usr/local/cpanel/version"); err == nil {
		ver, _ := util.ReadFileString("/usr/local/cpanel/version")
		return model.RoleWebHosting, "cPanel " + strings.TrimSpace(ver), "cPanel"
	}

	// CyberPanel
	if _, err := os.Stat("/usr/local/CyberCP"); err == nil {
		return model.RoleWebHosting, "CyberPanel", "CyberPanel"
	}

	// DirectAdmin
	if _, err := os.Stat("/usr/local/directadmin"); err == nil {
		return model.RoleWebHosting, "DirectAdmin", "DirectAdmin"
	}

	// Webmin
	if _, err := os.Stat("/etc/webmin"); err == nil {
		return model.RoleWebHosting, "Webmin", "Webmin"
	}

	return model.RoleUnknown, "", ""
}

func isContainerPlatform(snap *model.Snapshot) bool {
	dockerCount := 0
	kubeletFound := false
	for _, app := range snap.Global.Apps.Instances {
		if app.AppType == "docker" {
			dockerCount++
		}
	}
	for _, p := range snap.Processes {
		if p.Comm == "kubelet" {
			kubeletFound = true
		}
		if p.Comm == "dockerd" || p.Comm == "containerd" {
			dockerCount++
		}
	}
	return kubeletFound || dockerCount > 0
}

func detectContainerDetail(snap *model.Snapshot) string {
	for _, p := range snap.Processes {
		if p.Comm == "kubelet" {
			return "Kubernetes Node"
		}
	}
	// Check docker swarm
	for _, app := range snap.Global.Apps.Instances {
		if app.AppType == "docker" && app.OrchestrationType == "swarm" {
			return "Docker Swarm"
		}
	}
	return "Docker Host"
}

func isLoadBalancer(snap *model.Snapshot) bool {
	for _, app := range snap.Global.Apps.Instances {
		if app.AppType == "haproxy" || app.AppType == "traefik" {
			return true
		}
		// Nginx as reverse proxy (high connections, no vhosts with PHP)
		if app.AppType == "nginx" && app.Connections > 500 {
			// Check if there's no PHP-FPM — pure proxy
			hasPHP := false
			for _, a2 := range snap.Global.Apps.Instances {
				if a2.AppType == "php-fpm" {
					hasPHP = true
					break
				}
			}
			if !hasPHP {
				return true
			}
		}
	}
	return false
}

func detectLBDetail(snap *model.Snapshot) string {
	parts := []string{}
	for _, app := range snap.Global.Apps.Instances {
		switch app.AppType {
		case "haproxy":
			parts = append(parts, "HAProxy")
		case "nginx":
			parts = append(parts, "Nginx")
		case "traefik":
			parts = append(parts, "Traefik")
		}
	}
	// Check for HA (keepalived, corosync, pacemaker)
	for _, p := range snap.Processes {
		switch p.Comm {
		case "keepalived":
			parts = append(parts, "keepalived HA")
		case "corosync":
			parts = append(parts, "Corosync HA")
		case "pacemakerd":
			parts = append(parts, "Pacemaker HA")
		}
	}
	if len(parts) == 0 {
		return "Load Balancer"
	}
	return strings.Join(parts, " + ")
}

func isDBServer(snap *model.Snapshot) bool {
	for _, app := range snap.Global.Apps.Instances {
		switch app.AppType {
		case "mysql", "postgresql", "mongodb":
			// DB is dominant if it uses >30% of RAM
			if snap.SysInfo != nil && app.RSSMB > 0 {
				totalMB := float64(snap.Global.Memory.Total) / (1024 * 1024)
				if totalMB > 0 && app.RSSMB/totalMB > 0.3 {
					return true
				}
			}
		}
	}
	return false
}

func detectDBDetail(snap *model.Snapshot) string {
	for _, app := range snap.Global.Apps.Instances {
		switch app.AppType {
		case "mysql":
			return "MySQL/MariaDB"
		case "postgresql":
			return "PostgreSQL"
		case "mongodb":
			return "MongoDB"
		}
	}
	return "Database"
}

func isMailServer(snap *model.Snapshot) bool {
	for _, p := range snap.Processes {
		if p.Comm == "master" || p.Comm == "postfix" || p.Comm == "dovecot" || p.Comm == "exim4" {
			return true
		}
	}
	return false
}

func isRouter() bool {
	v, err := util.ReadFileString("/proc/sys/net/ipv4/ip_forward")
	if err != nil {
		return false
	}
	if strings.TrimSpace(v) != "1" {
		return false
	}
	// Must also have multiple physical NICs or iptables rules
	out, err := exec.Command("iptables", "-S").Output()
	if err == nil && strings.Count(string(out), "\n") > 5 {
		return true
	}
	return false
}

func detectMixedDetail(snap *model.Snapshot) string {
	var parts []string
	seen := map[string]bool{}
	for _, app := range snap.Global.Apps.Instances {
		if !seen[app.AppType] {
			seen[app.AppType] = true
			parts = append(parts, app.DisplayName)
		}
	}
	if len(parts) > 4 {
		parts = parts[:4]
		parts = append(parts, "...")
	}
	if len(parts) == 0 {
		return "General purpose"
	}
	return strings.Join(parts, ", ")
}
