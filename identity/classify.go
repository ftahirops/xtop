package identity

import (
	"fmt"
	"sort"

	"github.com/ftahirops/xtop/model"
)

// roleAccum accumulates weighted evidence for a role.
type roleAccum struct {
	role     model.ServerRole
	score    int
	maxScore int
	evidence []string
}

func (r *roleAccum) add(points, max int, desc string) {
	r.score += points
	r.maxScore += max
	r.evidence = append(r.evidence, fmt.Sprintf("[+%d] %s", points, desc))
}

func (r *roleAccum) skip(max int, desc string) {
	r.maxScore += max
}

// classifyRoles uses weighted evidence scoring to determine server roles.
//
// Each role has multiple signals worth different points. A role is assigned
// only if its score exceeds a threshold (35+ points). Confidence is computed
// as score/maxScore. Container purposes and VPN probes contribute to scoring.
//
// This replaces the old boolean classification that caused false positives
// (e.g., labeling a Docker host as a NAT gateway because Docker set ip_forward).
func classifyRoles(id *model.ServerIdentity) {
	accums := []*roleAccum{
		scoreVPN(id),
		scoreWebServer(id),
		scoreDatabase(id),
		scoreDockerHost(id),
		scoreLoadBalancer(id),
		scoreMonitoring(id),
		scoreNATGateway(id),
		scoreRouter(id),
		scoreFirewall(id),
		scoreK8sNode(id),
		scoreMailServer(id),
		scoreDNSServer(id),
		scoreCICDRunner(id),
		scoreMQ(id),
		scoreCache(id),
		scoreAppServer(id),
	}

	// Sort by score descending
	sort.Slice(accums, func(i, j int) bool {
		return accums[i].score > accums[j].score
	})

	// Assign roles that meet the threshold
	const minScore = 35
	for _, a := range accums {
		if a.score < minScore {
			continue
		}
		id.Roles = append(id.Roles, a.role)
	}

	// Build RoleScores for output
	for _, a := range accums {
		if a.score == 0 {
			continue
		}
		confidence := 0
		if a.maxScore > 0 {
			confidence = a.score * 100 / a.maxScore
		}
		id.RoleScores = append(id.RoleScores, model.RoleScore{
			Role:       a.role,
			Score:      a.score,
			MaxScore:   a.maxScore,
			Confidence: confidence,
			Evidence:   a.evidence,
		})
	}
}

// --- Individual role scorers ---

func scoreVPN(id *model.ServerIdentity) *roleAccum {
	a := &roleAccum{role: model.RoleVPNServer}

	// WireGuard kernel module loaded
	if id.VPN != nil && id.VPN.Type == "wireguard" {
		a.add(30, 30, "WireGuard detected (module/interface/config)")
	} else {
		a.skip(30, "No WireGuard detected")
	}

	// VPN container running
	if hasContainerWithPurpose(id, "vpn") {
		a.add(30, 30, "VPN container running")
	} else {
		a.skip(30, "No VPN container")
	}

	// VPN-specific ports listening (51820, 1194, 500, 4500)
	if hasListeningPort(id, 51820, 1194, 500, 4500) {
		a.add(20, 20, "VPN port listening")
	} else {
		a.skip(20, "No VPN ports")
	}

	// VPN process (openvpn, charon, tailscaled)
	if id.VPN != nil && id.VPN.Type != "" {
		a.add(10, 10, fmt.Sprintf("VPN type: %s", id.VPN.Type))
	} else {
		a.skip(10, "No VPN process")
	}

	// Peers connected
	if id.VPN != nil && id.VPN.Peers > 0 {
		a.add(10, 10, fmt.Sprintf("%d VPN peers connected", id.VPN.Peers))
	} else {
		a.skip(10, "No peers")
	}

	return a
}

func scoreWebServer(id *model.ServerIdentity) *roleAccum {
	a := &roleAccum{role: model.RoleWebServer}

	if hasRunningService(id, "nginx", "apache", "caddy", "traefik") {
		a.add(35, 40, "Web server process running")
	} else if hasContainerWithPurpose(id, "web") || hasContainerWithPurpose(id, "reverse-proxy") {
		a.add(30, 40, "Web server container running")
	} else {
		a.skip(40, "No web server process/container")
	}

	if hasListeningPort(id, 80, 443) {
		a.add(40, 40, "Listening on port 80/443")
	} else if hasListeningPort(id, 8080, 8443) {
		a.add(20, 40, "Listening on port 8080/8443")
	} else {
		a.skip(40, "No web ports")
	}

	if len(id.Websites) > 0 {
		a.add(15, 15, fmt.Sprintf("%d vhosts configured", len(id.Websites)))
	} else {
		a.skip(15, "No vhosts")
	}

	return a
}

func scoreDatabase(id *model.ServerIdentity) *roleAccum {
	a := &roleAccum{role: model.RoleDatabaseServer}

	if hasRunningService(id, "mysql", "postgresql", "redis", "mongodb") {
		a.add(40, 40, "Database process running")
	} else if hasContainerWithPurpose(id, "database") {
		a.add(35, 40, "Database container running")
	} else {
		a.skip(40, "No database process/container")
	}

	if hasListeningPort(id, 5432, 3306, 27017, 6379, 9200, 9042) {
		a.add(30, 30, "Database port listening")
	} else {
		a.skip(30, "No database ports")
	}

	if len(id.Databases) > 0 {
		a.add(20, 20, fmt.Sprintf("%d databases discovered", len(id.Databases)))
	} else {
		a.skip(20, "No databases enumerated")
	}

	return a
}

func scoreCache(id *model.ServerIdentity) *roleAccum {
	a := &roleAccum{role: model.RoleDatabaseServer} // cache counts toward DB
	// Only scored if no DB process — avoids double counting
	if hasRunningService(id, "mysql", "postgresql", "mongodb") {
		return a
	}
	if hasContainerWithPurpose(id, "cache") {
		a.add(50, 60, "Cache container running")
	}
	if hasListeningPort(id, 6379, 11211) && hasRunningService(id, "redis") {
		a.add(50, 60, "Cache service on standard port")
	}
	return a
}

func scoreDockerHost(id *model.ServerIdentity) *roleAccum {
	a := &roleAccum{role: model.RoleDockerHost}

	if hasRunningService(id, "docker", "containerd") {
		a.add(30, 50, "Docker/containerd running")
	} else {
		a.skip(50, "No Docker runtime")
	}

	n := len(id.Containers)
	if n > 0 {
		a.add(20, 20, fmt.Sprintf("%d containers present", n))
	} else {
		a.skip(20, "No containers")
	}

	return a
}

func scoreLoadBalancer(id *model.ServerIdentity) *roleAccum {
	a := &roleAccum{role: model.RoleLoadBalancer}

	if hasRunningService(id, "haproxy") || hasContainerWithPurpose(id, "load-balancer") {
		a.add(40, 40, "HAProxy/LB process running")
	} else {
		a.skip(40, "No LB process")
	}

	if id.HAProxy != nil {
		switch id.HAProxy.Mode {
		case "reverse_proxy":
			a.add(30, 30, "HAProxy classified as reverse proxy")
		case "forward_proxy":
			a.add(20, 30, "HAProxy classified as forward proxy")
		case "both":
			a.add(30, 30, "HAProxy serves as both reverse and forward proxy")
		case "tcp_lb":
			a.add(30, 30, "HAProxy classified as TCP load balancer")
		}
	} else {
		a.skip(30, "No HAProxy config")
	}

	if id.Keepalived != nil && len(id.Keepalived.VIPs) > 0 {
		a.add(20, 20, fmt.Sprintf("Keepalived with %d floating IPs", len(id.Keepalived.VIPs)))
	} else {
		a.skip(20, "No keepalived/VIPs")
	}

	return a
}

func scoreMonitoring(id *model.ServerIdentity) *roleAccum {
	a := &roleAccum{role: model.RoleMonitoringServer}

	if hasRunningService(id, "prometheus", "grafana") {
		a.add(50, 50, "Monitoring service running")
	} else if hasContainerWithPurpose(id, "monitoring") {
		a.add(45, 50, "Monitoring container running")
	} else {
		a.skip(50, "No monitoring service")
	}

	if hasListeningPort(id, 9090, 3000, 5601) {
		a.add(10, 10, "Monitoring port listening")
	} else {
		a.skip(10, "No monitoring ports")
	}

	return a
}

func scoreNATGateway(id *model.ServerIdentity) *roleAccum {
	a := &roleAccum{role: model.RoleNATGateway}

	// ip_forward must be on AND not just Docker
	if id.IPForward && !ipForwardIsDockerOnly(id) {
		a.add(15, 15, "IP forwarding enabled (not Docker-only)")
	} else if id.IPForward {
		a.skip(15, "IP forwarding enabled but set by Docker")
	} else {
		a.skip(15, "IP forwarding disabled")
	}

	// Real NAT rules (excluding Docker MASQUERADE)
	if hasRealNATRules() {
		a.add(25, 25, "Real MASQUERADE/SNAT rules (non-Docker)")
	} else {
		a.skip(25, "No real NAT rules")
	}

	// 2+ physical interfaces
	phys := countPhysicalUpInterfaces()
	if phys >= 2 {
		a.add(20, 20, fmt.Sprintf("%d physical interfaces up", phys))
	} else {
		a.skip(20, fmt.Sprintf("Only %d physical interface", phys))
	}

	// Downstream network
	if hasDownstreamNetwork() {
		a.add(20, 20, "Routes to downstream private network")
	} else {
		a.skip(20, "No downstream network routes")
	}

	// DHCP server
	if hasDHCPServer() {
		a.add(15, 15, "DHCP server running")
	} else {
		a.skip(15, "No DHCP server")
	}

	// Bash history evidence
	if checkBashHistoryForNATWork() {
		a.add(5, 5, "NAT configuration in shell history")
	} else {
		a.skip(5, "No NAT history")
	}

	return a
}

func scoreRouter(id *model.ServerIdentity) *roleAccum {
	a := &roleAccum{role: model.RoleRouter}

	if id.IPForward && !ipForwardIsDockerOnly(id) {
		a.add(15, 15, "IP forwarding enabled (not Docker-only)")
	} else {
		a.skip(15, "IP forwarding not manually set")
	}

	phys := countPhysicalUpInterfaces()
	if phys >= 2 {
		a.add(25, 25, fmt.Sprintf("%d physical interfaces up", phys))
	} else {
		a.skip(25, fmt.Sprintf("Only %d physical interface", phys))
	}

	if hasDownstreamNetwork() {
		a.add(25, 25, "Routes to downstream networks")
	} else {
		a.skip(25, "No downstream routes")
	}

	return a
}

func scoreFirewall(id *model.ServerIdentity) *roleAccum {
	a := &roleAccum{role: model.RoleFirewall}

	if hasRealFirewallRules() {
		a.add(20, 20, "Real firewall rules (non-Docker, non-UFW)")
	} else {
		a.skip(20, "No real firewall rules")
	}

	if id.IPForward && !ipForwardIsDockerOnly(id) {
		a.add(15, 15, "Forwarding between networks")
	} else {
		a.skip(15, "Not forwarding")
	}

	phys := countPhysicalUpInterfaces()
	if phys >= 2 {
		a.add(15, 15, fmt.Sprintf("%d physical interfaces", phys))
	} else {
		a.skip(15, "Single interface")
	}

	return a
}

func scoreK8sNode(id *model.ServerIdentity) *roleAccum {
	a := &roleAccum{role: model.RoleK8sNode}

	if hasRunningService(id, "kubelet") {
		a.add(60, 60, "kubelet running")
	} else {
		a.skip(60, "No kubelet")
	}

	if id.K8s != nil {
		a.add(20, 20, fmt.Sprintf("K8s %s, %d pods", id.K8s.NodeRole, id.K8s.PodCount))
	} else {
		a.skip(20, "No K8s info")
	}

	return a
}

func scoreMailServer(id *model.ServerIdentity) *roleAccum {
	a := &roleAccum{role: model.RoleMailServer}

	if hasRunningService(id, "postfix", "dovecot") || hasContainerWithPurpose(id, "mail") {
		a.add(40, 40, "Mail service running")
	} else {
		a.skip(40, "No mail service")
	}

	if hasListeningPort(id, 25, 587, 993) {
		a.add(30, 30, "Mail ports listening")
	} else {
		a.skip(30, "No mail ports")
	}

	return a
}

func scoreDNSServer(id *model.ServerIdentity) *roleAccum {
	a := &roleAccum{role: model.RoleDNSServer}

	if hasRunningService(id, "bind", "dnsmasq", "unbound") || hasContainerWithPurpose(id, "dns") {
		a.add(40, 40, "DNS service running")
	} else {
		a.skip(40, "No DNS service")
	}

	if hasListeningPort(id, 53) {
		a.add(30, 30, "Port 53 listening")
	} else {
		a.skip(30, "No port 53")
	}

	return a
}

func scoreCICDRunner(id *model.ServerIdentity) *roleAccum {
	a := &roleAccum{role: model.RoleCICDRunner}

	if hasRunningService(id, "gitlab-runner", "jenkins") || hasContainerWithPurpose(id, "cicd") {
		a.add(50, 50, "CI/CD service running")
	} else {
		a.skip(50, "No CI/CD service")
	}

	return a
}

func scoreMQ(id *model.ServerIdentity) *roleAccum {
	// Message queue uses AppServer role since we don't have a dedicated MQ role
	a := &roleAccum{role: model.RoleAppServer}

	if hasContainerWithPurpose(id, "message-queue") {
		a.add(50, 60, "Message queue container running")
	}
	if hasListeningPort(id, 5672, 9092, 4222, 15672) {
		a.add(40, 60, "MQ port listening")
	}

	return a
}

func scoreAppServer(id *model.ServerIdentity) *roleAccum {
	a := &roleAccum{role: model.RoleAppServer}

	if hasRunningService(id, "java", "node", "python", "gunicorn", "uvicorn", "php-fpm") {
		a.add(35, 50, "Application runtime running")
	} else if hasContainerWithPurpose(id, "app") {
		a.add(25, 50, "Application container running")
	} else {
		a.skip(50, "No app runtime")
	}

	return a
}

// hasRunningService checks if any of the named services are running.
func hasRunningService(id *model.ServerIdentity, names ...string) bool {
	for _, name := range names {
		svc := id.ServiceByName(name)
		if svc != nil && svc.Running {
			return true
		}
	}
	return false
}

// hasListeningPort checks if any service is listening on the given ports.
func hasListeningPort(id *model.ServerIdentity, ports ...int) bool {
	for _, svc := range id.Services {
		for _, svcPort := range svc.Ports {
			for _, port := range ports {
				if svcPort == port {
					return true
				}
			}
		}
	}
	return false
}
