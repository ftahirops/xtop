//go:build linux

package profiler

import (
	"os"
	"os/exec"
	"sort"
	"strings"

	"github.com/ftahirops/xtop/model"
	"github.com/ftahirops/xtop/util"
)

// roleScore tracks weighted evidence for a server role.
type roleScore struct {
	role   model.ServerRole
	score  float64
	detail string
	panel  string
}

// detectRole determines the server's primary role using weighted scoring.
// Instant shortcuts for known panels/hypervisors, then multi-signal scoring.
func detectRole(snap *model.Snapshot) (model.ServerRole, string, string) {
	// ── Instant shortcuts: panel/hypervisor detection ──
	if role, detail, panel := detectPanel(); role != model.RoleUnknown {
		return role, detail, panel
	}
	if snap.Global.Proxmox != nil && snap.Global.Proxmox.IsProxmoxHost {
		detail := "Proxmox VE"
		if snap.Global.Proxmox.PVEVersion != "" {
			detail += " " + snap.Global.Proxmox.PVEVersion
		}
		return model.RoleHypervisor, detail, "Proxmox"
	}

	// ── Weighted scoring across all signals ──
	scores := map[model.ServerRole]*roleScore{
		model.RoleContainer:    {role: model.RoleContainer},
		model.RoleLoadBalancer: {role: model.RoleLoadBalancer},
		model.RoleDatabase:     {role: model.RoleDatabase},
		model.RoleMailServer:   {role: model.RoleMailServer},
		model.RoleRouter:       {role: model.RoleRouter},
		model.RoleWebServer:    {role: model.RoleWebServer},
		model.RoleAppServer:    {role: model.RoleAppServer},
		model.RoleMixed:        {role: model.RoleMixed},
	}

	totalRAMMB := float64(snap.Global.Memory.Total) / (1024 * 1024)

	// Signal 1: Process presence & resource dominance (heaviest weight)
	scoreByProcessPresence(snap, scores, totalRAMMB)

	// Signal 2: App detection data (CPU%, RAM, connections)
	scoreByAppInstances(snap, scores, totalRAMMB)

	// Signal 3: Log activity analysis
	scoreByLogActivity(snap, scores)

	// Signal 4: Network patterns (listening ports, connections)
	scoreByNetworkPatterns(snap, scores)

	// Signal 5: Container orchestration depth
	scoreByContainerDepth(snap, scores)

	// Signal 6: Filesystem/disk usage patterns
	scoreByDiskPatterns(snap, scores)

	// Signal 7: System configuration clues
	scoreBySystemConfig(scores)

	// ── Pick the winner ──
	var sorted []*roleScore
	for _, rs := range scores {
		if rs.score > 0 {
			sorted = append(sorted, rs)
		}
	}
	if len(sorted) == 0 {
		return model.RoleMixed, "General purpose", ""
	}

	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].score > sorted[j].score
	})

	winner := sorted[0]

	// If top score is very close to second (within 20%), it's truly mixed
	if len(sorted) >= 2 {
		ratio := sorted[1].score / winner.score
		if ratio > 0.80 && winner.role != model.RoleContainer {
			// Build mixed detail from top roles
			detail := buildMixedDetail(sorted)
			return model.RoleMixed, detail, ""
		}
	}

	// If winner score is too low, it's generic
	if winner.score < 5 {
		return model.RoleMixed, detectMixedDetail(snap), ""
	}

	if winner.detail == "" {
		winner.detail = buildDetailForRole(winner.role, snap)
	}
	return winner.role, winner.detail, winner.panel
}

// ── Signal 1: Process-level presence & resource usage ──
func scoreByProcessPresence(snap *model.Snapshot, scores map[model.ServerRole]*roleScore, totalRAMMB float64) {
	// Aggregate per-category resource usage from processes
	type category struct {
		role    model.ServerRole
		cpuPct  float64
		rssMB   float64
		count   int
		threads int
	}
	cats := map[string]*category{}

	processRoleMap := map[string]struct {
		cat  string
		role model.ServerRole
	}{
		// Database
		"mysqld": {"db", model.RoleDatabase}, "mariadbd": {"db", model.RoleDatabase},
		"postgres": {"db", model.RoleDatabase}, "mongod": {"db", model.RoleDatabase},
		"mongos": {"db", model.RoleDatabase}, "redis-server": {"db", model.RoleDatabase},
		"memcached": {"db", model.RoleDatabase},
		// Web servers
		"nginx": {"web", model.RoleWebServer}, "apache2": {"web", model.RoleWebServer},
		"httpd": {"web", model.RoleWebServer}, "litespeed": {"web", model.RoleWebServer},
		"caddy": {"web", model.RoleWebServer}, "php-fpm": {"web", model.RoleWebServer},
		// Load balancers
		"haproxy": {"lb", model.RoleLoadBalancer}, "traefik": {"lb", model.RoleLoadBalancer},
		"envoy": {"lb", model.RoleLoadBalancer}, "keepalived": {"lb", model.RoleLoadBalancer},
		// Container
		"dockerd": {"container", model.RoleContainer}, "containerd": {"container", model.RoleContainer},
		"kubelet": {"container", model.RoleContainer}, "kube-apiserver": {"container", model.RoleContainer},
		"kube-scheduler": {"container", model.RoleContainer}, "etcd": {"container", model.RoleContainer},
		// Mail
		"postfix": {"mail", model.RoleMailServer}, "dovecot": {"mail", model.RoleMailServer},
		"exim4": {"mail", model.RoleMailServer}, "master": {"mail", model.RoleMailServer},
		"amavisd-new": {"mail", model.RoleMailServer}, "opendkim": {"mail", model.RoleMailServer},
		"clamd": {"mail", model.RoleMailServer}, "spamd": {"mail", model.RoleMailServer},
		// App servers
		"java": {"app", model.RoleAppServer}, "node": {"app", model.RoleAppServer},
		"python3": {"app", model.RoleAppServer}, "python": {"app", model.RoleAppServer},
		"dotnet": {"app", model.RoleAppServer}, "gunicorn": {"app", model.RoleAppServer},
		"uvicorn": {"app", model.RoleAppServer}, "pm2": {"app", model.RoleAppServer},
		"puma": {"app", model.RoleAppServer}, "unicorn": {"app", model.RoleAppServer},
	}

	uptimeSec := readSystemUptime()
	for _, proc := range snap.Processes {
		mapping, ok := processRoleMap[proc.Comm]
		if !ok {
			continue
		}
		c, ok := cats[mapping.cat]
		if !ok {
			c = &category{role: mapping.role}
			cats[mapping.cat] = c
		}
		// Compute lifetime CPU%
		if uptimeSec > 0 {
			ticks := proc.UTime + proc.STime
			c.cpuPct += float64(ticks) / 100.0 / float64(uptimeSec) * 100.0
		}
		c.rssMB += float64(proc.RSS) / (1024 * 1024)
		c.count++
		c.threads += proc.NumThreads
	}

	// Score each category based on resource dominance
	for _, c := range cats {
		rs := scores[c.role]
		if rs == nil {
			continue
		}

		// Process count: each process adds a small score
		rs.score += float64(c.count) * 1.0

		// CPU dominance: high CPU = strong signal
		if c.cpuPct > 50 {
			rs.score += 25
		} else if c.cpuPct > 20 {
			rs.score += 15
		} else if c.cpuPct > 5 {
			rs.score += 8
		} else if c.cpuPct > 1 {
			rs.score += 3
		}

		// RAM dominance: percentage of total RAM
		if totalRAMMB > 0 {
			ramPct := c.rssMB / totalRAMMB * 100
			if ramPct > 50 {
				rs.score += 25
			} else if ramPct > 30 {
				rs.score += 15
			} else if ramPct > 10 {
				rs.score += 8
			} else if ramPct > 3 {
				rs.score += 3
			}
		}

		// Thread count: high threads = heavy workload (strong signal for DB/app)
		if c.threads > 200 {
			rs.score += 5
		} else if c.threads > 50 {
			rs.score += 2
		}
	}
}

// ── Signal 2: App detection instances (already-detected apps with accurate metrics) ──
func scoreByAppInstances(snap *model.Snapshot, scores map[model.ServerRole]*roleScore, totalRAMMB float64) {
	appRoleMap := map[string]model.ServerRole{
		"mysql": model.RoleDatabase, "postgresql": model.RoleDatabase,
		"mongodb": model.RoleDatabase, "redis": model.RoleDatabase,
		"memcached": model.RoleDatabase,
		"nginx": model.RoleWebServer, "apache": model.RoleWebServer,
		"litespeed": model.RoleWebServer, "php-fpm": model.RoleWebServer,
		"haproxy": model.RoleLoadBalancer, "traefik": model.RoleLoadBalancer,
		"docker": model.RoleContainer,
		"postfix": model.RoleMailServer, "dovecot": model.RoleMailServer,
		"exim": model.RoleMailServer,
	}

	for _, app := range snap.Global.Apps.Instances {
		role, ok := appRoleMap[app.AppType]
		if !ok {
			continue
		}
		rs := scores[role]
		if rs == nil {
			continue
		}

		// App-detected CPU% is delta-based (accurate)
		if app.CPUPct > 30 {
			rs.score += 15
		} else if app.CPUPct > 10 {
			rs.score += 8
		} else if app.CPUPct > 2 {
			rs.score += 3
		}

		// App RAM dominance
		if totalRAMMB > 0 {
			ramPct := app.RSSMB / totalRAMMB * 100
			if ramPct > 40 {
				rs.score += 15
			} else if ramPct > 20 {
				rs.score += 8
			} else if ramPct > 5 {
				rs.score += 3
			}
		}

		// Connection count: strong signal for web/LB/DB
		if app.Connections > 1000 {
			rs.score += 10
		} else if app.Connections > 200 {
			rs.score += 5
		} else if app.Connections > 20 {
			rs.score += 2
		}
	}
}

// ── Signal 3: Log activity analysis ──
// High error/warn rates indicate heavy service usage.
func scoreByLogActivity(snap *model.Snapshot, scores map[model.ServerRole]*roleScore) {
	if snap.Global.Logs.Services == nil {
		return
	}

	logRoleMap := map[string]model.ServerRole{
		"mysql": model.RoleDatabase, "mariadb": model.RoleDatabase,
		"postgresql": model.RoleDatabase, "mongodb": model.RoleDatabase,
		"redis": model.RoleDatabase,
		"nginx": model.RoleWebServer, "apache": model.RoleWebServer,
		"apache2": model.RoleWebServer, "httpd": model.RoleWebServer,
		"php-fpm": model.RoleWebServer, "litespeed": model.RoleWebServer,
		"haproxy": model.RoleLoadBalancer, "traefik": model.RoleLoadBalancer,
		"postfix": model.RoleMailServer, "dovecot": model.RoleMailServer,
		"exim": model.RoleMailServer, "exim4": model.RoleMailServer,
		"docker": model.RoleContainer, "containerd": model.RoleContainer,
		"kubelet": model.RoleContainer,
	}

	for _, svc := range snap.Global.Logs.Services {
		svcName := strings.ToLower(svc.Name)
		// Try exact match first, then prefix match
		role, ok := logRoleMap[svcName]
		if !ok {
			for prefix, r := range logRoleMap {
				if strings.HasPrefix(svcName, prefix) || strings.Contains(svcName, prefix) {
					role = r
					ok = true
					break
				}
			}
		}
		if !ok {
			continue
		}

		rs := scores[role]
		if rs == nil {
			continue
		}

		// Log activity = service is actively doing work
		totalActivity := svc.ErrorRate + svc.WarnRate
		if totalActivity > 10 {
			rs.score += 8 // very active service
		} else if totalActivity > 1 {
			rs.score += 4
		} else if totalActivity > 0 {
			rs.score += 1
		}

		// High error count = service under heavy load or misconfigured
		if svc.TotalErrors > 1000 {
			rs.score += 5
		} else if svc.TotalErrors > 100 {
			rs.score += 2
		}
	}
}

// ── Signal 4: Network patterns ──
func scoreByNetworkPatterns(snap *model.Snapshot, scores map[model.ServerRole]*roleScore) {
	// Analyze listening ports for service signatures
	webPorts := map[int]bool{80: true, 443: true, 8080: true, 8443: true}
	dbPorts := map[int]bool{3306: true, 5432: true, 27017: true, 6379: true, 11211: true}
	mailPorts := map[int]bool{25: true, 587: true, 993: true, 995: true, 143: true, 110: true, 465: true}
	lbPorts := map[int]bool{80: true, 443: true, 8404: true, 1936: true} // HAProxy stats ports

	webCount := 0
	dbCount := 0
	mailCount := 0

	if snap.Global.Security.NewPorts != nil {
		for _, p := range snap.Global.Security.NewPorts {
			if webPorts[p.Port] {
				webCount++
			}
			if dbPorts[p.Port] {
				dbCount++
			}
			if mailPorts[p.Port] {
				mailCount++
			}
			if lbPorts[p.Port] {
				// Only count LB if haproxy/traefik owns it
				if strings.Contains(strings.ToLower(p.Comm), "haproxy") ||
					strings.Contains(strings.ToLower(p.Comm), "traefik") ||
					strings.Contains(strings.ToLower(p.Comm), "envoy") {
					scores[model.RoleLoadBalancer].score += 5
				}
			}
		}
	}

	if webCount > 0 {
		scores[model.RoleWebServer].score += float64(webCount) * 2
	}
	if dbCount > 0 {
		scores[model.RoleDatabase].score += float64(dbCount) * 3
	}
	if mailCount >= 3 {
		scores[model.RoleMailServer].score += 10 // multiple mail ports = strong signal
	} else if mailCount > 0 {
		scores[model.RoleMailServer].score += float64(mailCount) * 2
	}

	// Total connection count from conntrack
	if snap.Global.Conntrack.Count > 10000 {
		// High connection count favors web/LB
		scores[model.RoleWebServer].score += 3
		scores[model.RoleLoadBalancer].score += 3
	}
}

// ── Signal 5: Container orchestration depth ──
func scoreByContainerDepth(snap *model.Snapshot, scores map[model.ServerRole]*roleScore) {
	rs := scores[model.RoleContainer]

	k8sComponents := 0
	dockerContainers := 0
	for _, p := range snap.Processes {
		switch p.Comm {
		case "kubelet", "kube-apiserver", "kube-scheduler", "kube-controller", "kube-proxy":
			k8sComponents++
		}
	}
	for _, app := range snap.Global.Apps.Instances {
		if app.AppType == "docker" {
			dockerContainers++
		}
	}

	// K8s node: very strong container signal
	if k8sComponents >= 2 {
		rs.score += 30
		rs.detail = "Kubernetes Node"
	} else if k8sComponents == 1 {
		rs.score += 15
		rs.detail = "Kubernetes Node"
	}

	// Docker with many containers: strong signal
	if dockerContainers > 10 {
		rs.score += 15
		if rs.detail == "" {
			rs.detail = "Docker Host"
		}
	} else if dockerContainers > 3 {
		rs.score += 8
		if rs.detail == "" {
			rs.detail = "Docker Host"
		}
	}

	// Docker swarm
	for _, app := range snap.Global.Apps.Instances {
		if app.AppType == "docker" && app.OrchestrationType == "swarm" {
			rs.score += 10
			rs.detail = "Docker Swarm"
			break
		}
	}

	// Penalty: if containerd/dockerd exists but is just infrastructure support
	// (e.g. only 1-2 containers), reduce score
	if dockerContainers <= 1 && k8sComponents == 0 {
		// Docker exists but isn't the primary workload — penalize
		rs.score *= 0.3
	}
}

// ── Signal 6: Disk/filesystem patterns ──
func scoreByDiskPatterns(snap *model.Snapshot, scores map[model.ServerRole]*roleScore) {
	// Large data directories suggest DB or storage role
	for _, mount := range snap.Global.Mounts {
		// DB data directories
		if strings.Contains(mount.MountPoint, "/var/lib/mysql") ||
			strings.Contains(mount.MountPoint, "/var/lib/postgresql") ||
			strings.Contains(mount.MountPoint, "/var/lib/mongodb") {
			scores[model.RoleDatabase].score += 5
		}
		// Mail spool
		if strings.Contains(mount.MountPoint, "/var/mail") ||
			strings.Contains(mount.MountPoint, "/var/spool/mail") ||
			strings.Contains(mount.MountPoint, "/var/vmail") {
			scores[model.RoleMailServer].score += 5
		}
		// Docker/container data
		if strings.Contains(mount.MountPoint, "/var/lib/docker") ||
			strings.Contains(mount.MountPoint, "/var/lib/containerd") ||
			strings.Contains(mount.MountPoint, "/var/lib/kubelet") {
			scores[model.RoleContainer].score += 3
		}
	}

	// Check for common DB data directories existence
	dbDataDirs := []string{
		"/var/lib/mysql", "/var/lib/postgresql",
		"/var/lib/mongodb", "/var/lib/redis",
	}
	for _, dir := range dbDataDirs {
		if info, err := os.Stat(dir); err == nil && info.IsDir() {
			scores[model.RoleDatabase].score += 2
		}
	}

	// Check for mail queue directories
	mailDirs := []string{"/var/spool/postfix", "/var/mail", "/var/vmail"}
	for _, dir := range mailDirs {
		if info, err := os.Stat(dir); err == nil && info.IsDir() {
			scores[model.RoleMailServer].score += 2
		}
	}
}

// ── Signal 7: System configuration clues ──
func scoreBySystemConfig(scores map[model.ServerRole]*roleScore) {
	// IP forwarding → router
	if v, err := util.ReadFileString("/proc/sys/net/ipv4/ip_forward"); err == nil {
		if strings.TrimSpace(v) == "1" {
			scores[model.RoleRouter].score += 10
			// Check iptables for NAT/forwarding rules
			out, err := exec.Command("iptables", "-t", "nat", "-S").Output()
			if err == nil && strings.Contains(string(out), "MASQUERADE") {
				scores[model.RoleRouter].score += 10
				scores[model.RoleRouter].detail = "NAT Gateway"
			}
			out, err = exec.Command("iptables", "-S").Output()
			if err == nil && strings.Count(string(out), "\n") > 10 {
				scores[model.RoleRouter].score += 5
			}
		}
	}

	// MySQL config files suggest dedicated DB
	mysqlConfigs := []string{"/etc/mysql/my.cnf", "/etc/my.cnf"}
	for _, path := range mysqlConfigs {
		if data, err := util.ReadFileString(path); err == nil {
			// Large innodb_buffer_pool = dedicated DB
			if strings.Contains(data, "innodb_buffer_pool_size") {
				scores[model.RoleDatabase].score += 3
			}
		}
	}

	// PostgreSQL config
	if _, err := os.Stat("/etc/postgresql"); err == nil {
		scores[model.RoleDatabase].score += 3
	}

	// Web hosting indicators
	webHostDirs := []string{
		"/var/www", "/home/*/public_html",
		"/etc/nginx/sites-enabled", "/etc/apache2/sites-enabled",
		"/etc/httpd/conf.d",
	}
	for _, dir := range webHostDirs {
		if info, err := os.Stat(dir); err == nil && info.IsDir() {
			scores[model.RoleWebServer].score += 2
		}
	}
}

// ── Panel detection (instant — file existence) ──
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

// ── Detail builders ──

func buildMixedDetail(sorted []*roleScore) string {
	var parts []string
	for i, rs := range sorted {
		if i >= 3 || rs.score < 3 {
			break
		}
		name := roleDisplayName(rs.role)
		if rs.detail != "" {
			name = rs.detail
		}
		parts = append(parts, name)
	}
	if len(parts) == 0 {
		return "General purpose"
	}
	return strings.Join(parts, " + ")
}

func buildDetailForRole(role model.ServerRole, snap *model.Snapshot) string {
	switch role {
	case model.RoleDatabase:
		return detectDBDetail(snap)
	case model.RoleContainer:
		return detectContainerDetail(snap)
	case model.RoleLoadBalancer:
		return detectLBDetail(snap)
	case model.RoleMailServer:
		return detectMailDetail(snap)
	case model.RoleWebServer:
		return detectWebDetail(snap)
	case model.RoleAppServer:
		return detectAppDetail(snap)
	case model.RoleRouter:
		return "IP forwarding enabled"
	default:
		return roleDisplayName(role)
	}
}

func roleDisplayName(role model.ServerRole) string {
	switch role {
	case model.RoleDatabase:
		return "Database"
	case model.RoleContainer:
		return "Container Platform"
	case model.RoleLoadBalancer:
		return "Load Balancer"
	case model.RoleMailServer:
		return "Mail Server"
	case model.RoleWebServer:
		return "Web Server"
	case model.RoleAppServer:
		return "Application Server"
	case model.RoleRouter:
		return "Router/Firewall"
	case model.RoleMixed:
		return "Mixed Workload"
	default:
		return string(role)
	}
}

func detectDBDetail(snap *model.Snapshot) string {
	var dbs []string
	seen := map[string]bool{}
	for _, app := range snap.Global.Apps.Instances {
		switch app.AppType {
		case "mysql":
			if !seen["mysql"] {
				dbs = append(dbs, "MySQL/MariaDB")
				seen["mysql"] = true
			}
		case "postgresql":
			if !seen["pg"] {
				dbs = append(dbs, "PostgreSQL")
				seen["pg"] = true
			}
		case "mongodb":
			if !seen["mongo"] {
				dbs = append(dbs, "MongoDB")
				seen["mongo"] = true
			}
		case "redis":
			if !seen["redis"] {
				dbs = append(dbs, "Redis")
				seen["redis"] = true
			}
		}
	}
	if len(dbs) == 0 {
		return "Database"
	}
	return strings.Join(dbs, " + ")
}

func detectContainerDetail(snap *model.Snapshot) string {
	for _, p := range snap.Processes {
		if p.Comm == "kubelet" {
			return "Kubernetes Node"
		}
	}
	for _, app := range snap.Global.Apps.Instances {
		if app.AppType == "docker" && app.OrchestrationType == "swarm" {
			return "Docker Swarm"
		}
	}
	return "Docker Host"
}

func detectLBDetail(snap *model.Snapshot) string {
	parts := []string{}
	seen := map[string]bool{}
	for _, app := range snap.Global.Apps.Instances {
		switch app.AppType {
		case "haproxy":
			if !seen["haproxy"] {
				parts = append(parts, "HAProxy")
				seen["haproxy"] = true
			}
		case "nginx":
			if !seen["nginx"] {
				parts = append(parts, "Nginx")
				seen["nginx"] = true
			}
		case "traefik":
			if !seen["traefik"] {
				parts = append(parts, "Traefik")
				seen["traefik"] = true
			}
		}
	}
	for _, p := range snap.Processes {
		switch p.Comm {
		case "keepalived":
			if !seen["keepalived"] {
				parts = append(parts, "keepalived HA")
				seen["keepalived"] = true
			}
		case "corosync":
			if !seen["corosync"] {
				parts = append(parts, "Corosync HA")
				seen["corosync"] = true
			}
		case "pacemakerd":
			if !seen["pacemaker"] {
				parts = append(parts, "Pacemaker HA")
				seen["pacemaker"] = true
			}
		}
	}
	if len(parts) == 0 {
		return "Load Balancer"
	}
	return strings.Join(parts, " + ")
}

func detectMailDetail(snap *model.Snapshot) string {
	parts := []string{}
	seen := map[string]bool{}
	for _, p := range snap.Processes {
		switch p.Comm {
		case "master", "postfix":
			if !seen["postfix"] {
				parts = append(parts, "Postfix")
				seen["postfix"] = true
			}
		case "dovecot":
			if !seen["dovecot"] {
				parts = append(parts, "Dovecot")
				seen["dovecot"] = true
			}
		case "exim4":
			if !seen["exim"] {
				parts = append(parts, "Exim")
				seen["exim"] = true
			}
		case "amavisd-new":
			if !seen["amavis"] {
				parts = append(parts, "Amavis")
				seen["amavis"] = true
			}
		case "clamd":
			if !seen["clamav"] {
				parts = append(parts, "ClamAV")
				seen["clamav"] = true
			}
		}
	}
	if len(parts) == 0 {
		return "Mail Server"
	}
	return strings.Join(parts, " + ")
}

func detectWebDetail(snap *model.Snapshot) string {
	parts := []string{}
	seen := map[string]bool{}
	for _, app := range snap.Global.Apps.Instances {
		switch app.AppType {
		case "nginx":
			if !seen["nginx"] {
				parts = append(parts, "Nginx")
				seen["nginx"] = true
			}
		case "apache":
			if !seen["apache"] {
				parts = append(parts, "Apache")
				seen["apache"] = true
			}
		case "litespeed":
			if !seen["litespeed"] {
				parts = append(parts, "LiteSpeed")
				seen["litespeed"] = true
			}
		case "php-fpm":
			if !seen["php"] {
				parts = append(parts, "PHP-FPM")
				seen["php"] = true
			}
		}
	}
	if len(parts) == 0 {
		return "Web Server"
	}
	return strings.Join(parts, " + ")
}

func detectAppDetail(snap *model.Snapshot) string {
	parts := []string{}
	seen := map[string]bool{}
	for _, p := range snap.Processes {
		switch p.Comm {
		case "java":
			if !seen["java"] {
				parts = append(parts, "Java")
				seen["java"] = true
			}
		case "node":
			if !seen["node"] {
				parts = append(parts, "Node.js")
				seen["node"] = true
			}
		case "python3", "python":
			if !seen["python"] {
				parts = append(parts, "Python")
				seen["python"] = true
			}
		case "dotnet":
			if !seen["dotnet"] {
				parts = append(parts, ".NET")
				seen["dotnet"] = true
			}
		case "gunicorn":
			if !seen["gunicorn"] {
				parts = append(parts, "Gunicorn")
				seen["gunicorn"] = true
			}
		}
	}
	if len(parts) == 0 {
		return "Application Server"
	}
	return strings.Join(parts, " + ")
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
