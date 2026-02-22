package cmd

import (
	"fmt"
	"os/exec"
	"strings"

	"github.com/ftahirops/xtop/model"
)

// checkIdentityServices verifies all discovered services are still running.
func checkIdentityServices(id *model.ServerIdentity) []CheckResult {
	// Build set of services that are container-backed (no host process to pgrep).
	// These are checked by role-specific health checks (VPN, Docker, etc.) instead.
	containerBacked := make(map[string]bool)
	if id.VPN != nil && id.VPN.Container != "" {
		// VPN service runs inside a container, not as a host process
		containerBacked[id.VPN.Type] = true // e.g., "wireguard"
	}
	for _, c := range id.Containers {
		if c.Purpose != "" && strings.HasPrefix(c.Status, "Up") {
			containerBacked[c.Purpose] = true
		}
	}

	var checks []CheckResult
	for _, svc := range id.Services {
		if !svc.Running {
			continue // wasn't running at discovery time either
		}
		// Skip services that run inside containers — they're checked by
		// role-specific health checks (VPN, Docker, etc.), not by pgrep
		if containerBacked[svc.Name] {
			continue
		}
		// Skip transient port-based services (e.g., "port-68" from DHCP client)
		if strings.HasPrefix(svc.Name, "port-") {
			continue
		}
		// Skip ambiguous runtimes that have no systemd unit and no ports.
		// These are likely transient processes (python3 -m json.tool, node -e "..."),
		// not actual services. Only monitor them if they're systemd-managed or port-bound.
		if isAmbiguousRuntime(svc.Name) && svc.Unit == "" && len(svc.Ports) == 0 {
			continue
		}
		// Check if process is still running by looking for it in /proc
		running := isServiceRunning(svc)
		status := CheckOK
		detail := fmt.Sprintf("%s is running", svc.Name)
		advice := ""
		if !running {
			status = CheckCrit
			detail = fmt.Sprintf("%s is NOT running", svc.Name)
			if svc.Unit != "" {
				advice = fmt.Sprintf("systemctl start %s", svc.Unit)
			} else {
				advice = fmt.Sprintf("Service %s has stopped", svc.Name)
			}
		}
		version := ""
		if svc.Version != "" {
			version = fmt.Sprintf(" v%s", svc.Version)
		}
		checks = append(checks, CheckResult{
			Category: "Identity",
			Name:     fmt.Sprintf("Service %s%s", svc.Name, version),
			Status:   status,
			Detail:   detail,
			Advice:   advice,
		})
	}
	return checks
}

// isAmbiguousRuntime returns true for runtime names that could be transient
// commands rather than long-running services (python, node, java).
func isAmbiguousRuntime(name string) bool {
	switch name {
	case "python", "node", "java":
		return true
	}
	return false
}

// isServiceRunning checks if a service process is still alive.
func isServiceRunning(svc model.DetectedService) bool {
	// Try systemctl is-active first
	if svc.Unit != "" {
		if path, err := exec.LookPath("systemctl"); err == nil {
			out, err := exec.Command(path, "is-active", "--quiet", svc.Unit).CombinedOutput()
			_ = out
			return err == nil
		}
	}
	// Fall back to pgrep
	if path, err := exec.LookPath("pgrep"); err == nil {
		err := exec.Command(path, "-x", svc.Name).Run()
		return err == nil
	}
	return true // assume running if we can't check
}

// checkWebServer validates web server health.
func checkWebServer(id *model.ServerIdentity) []CheckResult {
	if !id.HasRole(model.RoleWebServer) {
		return nil
	}
	var checks []CheckResult

	// Check ports 80/443 are listening
	for _, port := range []int{80, 443} {
		listening := false
		for _, svc := range id.Services {
			for _, p := range svc.Ports {
				if p == port {
					listening = true
				}
			}
		}
		if listening {
			checks = append(checks, CheckResult{
				Category: "WebServer", Name: fmt.Sprintf("Port %d", port),
				Status: CheckOK, Detail: "Listening",
			})
		} else {
			checks = append(checks, CheckResult{
				Category: "WebServer", Name: fmt.Sprintf("Port %d", port),
				Status: CheckWarn, Detail: "Not listening",
				Advice: "Check web server configuration",
			})
		}
	}
	return checks
}

// checkDatabase validates database health for discovered databases.
func checkDatabase(id *model.ServerIdentity) []CheckResult {
	if !id.HasRole(model.RoleDatabaseServer) {
		return nil
	}
	var checks []CheckResult

	// MySQL health
	if svc := id.ServiceByName("mysql"); svc != nil && svc.Running {
		if path, err := exec.LookPath("mysqladmin"); err == nil {
			out, err := exec.Command(path, "ping", "--connect-timeout=2").CombinedOutput()
			status := CheckOK
			detail := "mysqld is alive"
			advice := ""
			if err != nil || !strings.Contains(string(out), "alive") {
				status = CheckCrit
				detail = "MySQL not responding to ping"
				advice = "Check MySQL process and logs"
			}
			checks = append(checks, CheckResult{
				Category: "Database", Name: "MySQL health",
				Status: status, Detail: detail, Advice: advice,
			})
		}
	}

	// PostgreSQL health
	if svc := id.ServiceByName("postgresql"); svc != nil && svc.Running {
		if path, err := exec.LookPath("pg_isready"); err == nil {
			err := exec.Command(path, "-t", "2").Run()
			status := CheckOK
			detail := "PostgreSQL accepting connections"
			advice := ""
			if err != nil {
				status = CheckCrit
				detail = "PostgreSQL not accepting connections"
				advice = "Check PostgreSQL process and pg_hba.conf"
			}
			checks = append(checks, CheckResult{
				Category: "Database", Name: "PostgreSQL health",
				Status: status, Detail: detail, Advice: advice,
			})
		}
	}

	// Redis health
	if svc := id.ServiceByName("redis"); svc != nil && svc.Running {
		if path, err := exec.LookPath("redis-cli"); err == nil {
			out, err := exec.Command(path, "ping").Output()
			status := CheckOK
			detail := "Redis responding to PING"
			advice := ""
			if err != nil || strings.TrimSpace(string(out)) != "PONG" {
				status = CheckCrit
				detail = "Redis not responding"
				advice = "Check Redis process and configuration"
			}
			checks = append(checks, CheckResult{
				Category: "Database", Name: "Redis health",
				Status: status, Detail: detail, Advice: advice,
			})
		}
	}

	return checks
}

// checkDockerHealth validates Docker container health.
func checkDockerHealth(id *model.ServerIdentity) []CheckResult {
	if !id.HasRole(model.RoleDockerHost) {
		return nil
	}
	var checks []CheckResult

	running := 0
	stopped := 0
	unhealthy := 0
	for _, c := range id.Containers {
		if strings.HasPrefix(c.Status, "Up") {
			running++
			if strings.Contains(c.Status, "unhealthy") {
				unhealthy++
			}
		} else {
			stopped++
		}
	}

	// Container count
	checks = append(checks, CheckResult{
		Category: "Docker", Name: "Containers",
		Status: CheckOK,
		Detail: fmt.Sprintf("%d running, %d stopped", running, stopped),
	})

	// Unhealthy containers
	if unhealthy > 0 {
		status := CheckWarn
		if unhealthy > 2 {
			status = CheckCrit
		}
		checks = append(checks, CheckResult{
			Category: "Docker", Name: "Unhealthy containers",
			Status: status,
			Detail: fmt.Sprintf("%d unhealthy", unhealthy),
			Advice: "docker ps --filter health=unhealthy",
		})
	}

	// Restarting containers
	restarting := 0
	for _, c := range id.Containers {
		if strings.Contains(c.Status, "Restarting") {
			restarting++
		}
	}
	if restarting > 0 {
		checks = append(checks, CheckResult{
			Category: "Docker", Name: "Restarting containers",
			Status: CheckCrit,
			Detail: fmt.Sprintf("%d restarting (crash loop?)", restarting),
			Advice: "docker logs <container>",
		})
	}

	return checks
}

// checkK8sHealth validates Kubernetes node health.
func checkK8sHealth(id *model.ServerIdentity) []CheckResult {
	if !id.HasRole(model.RoleK8sNode) {
		return nil
	}
	var checks []CheckResult

	// Check kubelet is running
	kubeletRunning := isServiceRunning(model.DetectedService{Name: "kubelet", Unit: "kubelet.service"})
	status := CheckOK
	detail := "kubelet is running"
	if !kubeletRunning {
		status = CheckCrit
		detail = "kubelet is NOT running"
	}
	checks = append(checks, CheckResult{
		Category: "K8s", Name: "kubelet",
		Status: status, Detail: detail,
		Advice: func() string {
			if !kubeletRunning {
				return "systemctl start kubelet"
			}
			return ""
		}(),
	})

	// Node status via kubectl
	if path, err := exec.LookPath("kubectl"); err == nil {
		out, err := exec.Command(path, "get", "nodes", "--no-headers").Output()
		if err == nil {
			for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
				fields := strings.Fields(line)
				if len(fields) >= 2 {
					nodeStatus := CheckOK
					if fields[1] != "Ready" {
						nodeStatus = CheckCrit
					}
					checks = append(checks, CheckResult{
						Category: "K8s", Name: fmt.Sprintf("Node %s", fields[0]),
						Status: nodeStatus, Detail: fields[1],
					})
				}
			}
		}
	}

	return checks
}

// checkNATHealth validates NAT gateway health.
func checkNATHealth(id *model.ServerIdentity, snap *model.Snapshot) []CheckResult {
	if !id.HasRole(model.RoleNATGateway) {
		return nil
	}
	var checks []CheckResult

	// ip_forward still on
	if !id.IPForward {
		checks = append(checks, CheckResult{
			Category: "NAT", Name: "IP Forwarding",
			Status: CheckCrit, Detail: "ip_forward is disabled",
			Advice: "sysctl -w net.ipv4.ip_forward=1",
		})
	} else {
		checks = append(checks, CheckResult{
			Category: "NAT", Name: "IP Forwarding",
			Status: CheckOK, Detail: "enabled",
		})
	}

	// Conntrack usage (lower thresholds for NAT gateways)
	if snap != nil {
		ct := snap.Global.Conntrack
		if ct.Max > 0 {
			pct := float64(ct.Count) / float64(ct.Max) * 100
			status := CheckOK
			detail := fmt.Sprintf("%.0f%% (%d/%d)", pct, ct.Count, ct.Max)
			advice := ""
			// Lower thresholds for NAT gateways
			if pct > 75 {
				status = CheckCrit
				advice = "NAT gateway conntrack nearly full; sysctl net.netfilter.nf_conntrack_max"
			} else if pct > 50 {
				status = CheckWarn
				advice = "NAT gateway conntrack elevated"
			}
			checks = append(checks, CheckResult{
				Category: "NAT", Name: "Conntrack (NAT)",
				Status: status, Detail: detail, Advice: advice,
			})
		}
	}

	return checks
}

// checkVPNHealth validates VPN service health.
func checkVPNHealth(id *model.ServerIdentity) []CheckResult {
	if !id.HasRole(model.RoleVPNServer) || id.VPN == nil {
		return nil
	}
	var checks []CheckResult

	// Check VPN container if containerized
	if id.VPN.Container != "" {
		containerUp := false
		containerHealthy := false
		for _, c := range id.Containers {
			if c.Name == id.VPN.Container {
				containerUp = strings.HasPrefix(c.Status, "Up")
				containerHealthy = strings.Contains(c.Status, "healthy")
				break
			}
		}
		status := CheckOK
		detail := fmt.Sprintf("Container %s is running", id.VPN.Container)
		advice := ""
		if !containerUp {
			status = CheckCrit
			detail = fmt.Sprintf("Container %s is NOT running", id.VPN.Container)
			advice = fmt.Sprintf("docker start %s", id.VPN.Container)
		} else if !containerHealthy {
			status = CheckWarn
			detail = fmt.Sprintf("Container %s running but not healthy", id.VPN.Container)
			advice = fmt.Sprintf("docker logs %s", id.VPN.Container)
		}
		checks = append(checks, CheckResult{
			Category: "VPN", Name: fmt.Sprintf("%s container", id.VPN.Type),
			Status: status, Detail: detail, Advice: advice,
		})
	}

	// Check VPN port is listening
	if id.VPN.Port > 0 {
		listening := false
		for _, svc := range id.Services {
			for _, p := range svc.Ports {
				if p == id.VPN.Port {
					listening = true
				}
			}
		}
		status := CheckOK
		detail := fmt.Sprintf("Port %d listening", id.VPN.Port)
		if !listening {
			status = CheckCrit
			detail = fmt.Sprintf("Port %d NOT listening", id.VPN.Port)
		}
		checks = append(checks, CheckResult{
			Category: "VPN", Name: fmt.Sprintf("%s port", id.VPN.Type),
			Status: status, Detail: detail,
		})
	}

	return checks
}

// checkDNSHealth validates DNS server health.
func checkDNSHealth(id *model.ServerIdentity) []CheckResult {
	if !id.HasRole(model.RoleDNSServer) {
		return nil
	}
	var checks []CheckResult

	// Check port 53 listening
	listening := false
	for _, svc := range id.Services {
		for _, p := range svc.Ports {
			if p == 53 {
				listening = true
			}
		}
	}

	status := CheckOK
	detail := "Port 53 listening"
	if !listening {
		status = CheckCrit
		detail = "Port 53 NOT listening"
	}
	checks = append(checks, CheckResult{
		Category: "DNS", Name: "Port 53",
		Status: status, Detail: detail,
	})

	// Check DNS process running
	for _, name := range []string{"bind", "dnsmasq", "unbound"} {
		if svc := id.ServiceByName(name); svc != nil && svc.Running {
			running := isServiceRunning(*svc)
			status := CheckOK
			detail := fmt.Sprintf("%s is running", name)
			if !running {
				status = CheckCrit
				detail = fmt.Sprintf("%s is NOT running", name)
			}
			checks = append(checks, CheckResult{
				Category: "DNS", Name: fmt.Sprintf("Process %s", name),
				Status: status, Detail: detail,
			})
		}
	}

	return checks
}
