package cmd

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// serviceProbe defines a service to check by process name.
type serviceProbe struct {
	name string // pgrep name
	unit string // systemd unit (optional)
}

// knownServices lists services to probe directly via pgrep.
var knownServices = []serviceProbe{
	{"sshd", "ssh.service"},
	{"nginx", "nginx.service"},
	{"apache2", "apache2.service"},
	{"httpd", "httpd.service"},
	{"caddy", "caddy.service"},
	{"haproxy", "haproxy.service"},
	{"keepalived", "keepalived.service"},
	{"mysqld", "mysql.service"},
	{"postgres", "postgresql.service"},
	{"redis-server", "redis-server.service"},
	{"mongod", "mongod.service"},
	{"docker", "docker.service"},
	{"containerd", "containerd.service"},
	{"kubelet", "kubelet.service"},
	{"named", "named.service"},
	{"dnsmasq", "dnsmasq.service"},
	{"unbound", "unbound.service"},
	{"openvpn", "openvpn.service"},
	{"grafana", "grafana-server.service"},
	{"prometheus", "prometheus.service"},
	{"elasticsearch", "elasticsearch.service"},
}

// checkActiveServices detects running services and reports their health.
func checkActiveServices() []CheckResult {
	var checks []CheckResult

	pgrepPath, _ := exec.LookPath("pgrep")
	systemctlPath, _ := exec.LookPath("systemctl")

	for _, sp := range knownServices {
		running := false

		// Try systemctl first
		if systemctlPath != "" && sp.unit != "" {
			err := exec.Command(systemctlPath, "is-active", "--quiet", sp.unit).Run()
			if err == nil {
				running = true
			}
		}
		// Fall back to pgrep
		if !running && pgrepPath != "" {
			err := exec.Command(pgrepPath, "-x", sp.name).Run()
			if err == nil {
				running = true
			}
		}

		if !running {
			continue // not installed or not running — skip silently
		}

		checks = append(checks, CheckResult{
			Category: "Services",
			Name:     sp.name,
			Status:   CheckOK,
			Detail:   fmt.Sprintf("%s is running", sp.name),
		})
	}

	// Deep health checks for detected services
	checks = append(checks, checkDatabaseHealth()...)
	checks = append(checks, checkDockerContainers()...)
	checks = append(checks, checkK8sNode()...)
	checks = append(checks, checkWireguard()...)

	if len(checks) == 0 {
		checks = append(checks, CheckResult{
			Category: "Services",
			Name:     "Services",
			Status:   CheckOK,
			Detail:   "No notable services detected",
		})
	}

	return checks
}

// checkDatabaseHealth runs deep health checks for detected databases.
func checkDatabaseHealth() []CheckResult {
	var checks []CheckResult

	// MySQL
	if processRunning("mysqld") {
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
				Category: "Services", Name: "MySQL health",
				Status: status, Detail: detail, Advice: advice,
			})
		}
	}

	// PostgreSQL
	if processRunning("postgres") {
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
				Category: "Services", Name: "PostgreSQL health",
				Status: status, Detail: detail, Advice: advice,
			})
		}
	}

	// Redis
	if processRunning("redis-server") {
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
				Category: "Services", Name: "Redis health",
				Status: status, Detail: detail, Advice: advice,
			})
		}
	}

	return checks
}

// checkDockerContainers checks Docker container health if Docker is running.
func checkDockerContainers() []CheckResult {
	if !processRunning("dockerd") && !processRunning("docker") {
		return nil
	}

	path, err := exec.LookPath("docker")
	if err != nil {
		return nil
	}

	out, err := exec.Command(path, "ps", "-a", "--format", "{{.Names}}\t{{.Status}}").Output()
	if err != nil {
		return nil
	}

	var checks []CheckResult
	running := 0
	stopped := 0
	unhealthy := 0
	restarting := 0

	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	for _, line := range lines {
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, "\t", 2)
		if len(parts) < 2 {
			continue
		}
		status := parts[1]
		if strings.HasPrefix(status, "Up") {
			running++
			if strings.Contains(status, "unhealthy") {
				unhealthy++
			}
		} else if strings.Contains(status, "Restarting") {
			restarting++
		} else {
			stopped++
		}
	}

	checks = append(checks, CheckResult{
		Category: "Services", Name: "Containers",
		Status: CheckOK,
		Detail: fmt.Sprintf("%d running, %d stopped", running, stopped),
	})

	if unhealthy > 0 {
		status := CheckWarn
		if unhealthy > 2 {
			status = CheckCrit
		}
		checks = append(checks, CheckResult{
			Category: "Services", Name: "Unhealthy containers",
			Status: status, Detail: fmt.Sprintf("%d unhealthy", unhealthy),
			Advice: "docker ps --filter health=unhealthy",
		})
	}
	if restarting > 0 {
		checks = append(checks, CheckResult{
			Category: "Services", Name: "Restarting containers",
			Status: CheckCrit, Detail: fmt.Sprintf("%d restarting (crash loop?)", restarting),
			Advice: "docker logs <container>",
		})
	}

	return checks
}

// checkK8sNode checks Kubernetes health if kubelet is running.
func checkK8sNode() []CheckResult {
	if !processRunning("kubelet") {
		return nil
	}
	var checks []CheckResult

	if path, err := exec.LookPath("kubectl"); err == nil {
		out, err := exec.Command(path, "get", "nodes", "--no-headers").Output()
		if err == nil {
			for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
				fields := strings.Fields(line)
				if len(fields) >= 2 {
					status := CheckOK
					if fields[1] != "Ready" {
						status = CheckCrit
					}
					checks = append(checks, CheckResult{
						Category: "Services", Name: fmt.Sprintf("K8s node %s", fields[0]),
						Status: status, Detail: fields[1],
					})
				}
			}
		}
	}

	return checks
}

// checkWireguard checks WireGuard interfaces.
func checkWireguard() []CheckResult {
	// Check for wg interfaces in /sys/class/net
	entries, err := os.ReadDir("/sys/class/net")
	if err != nil {
		return nil
	}

	var checks []CheckResult
	for _, e := range entries {
		if !strings.HasPrefix(e.Name(), "wg") {
			continue
		}
		// WireGuard interface found
		checks = append(checks, CheckResult{
			Category: "Services", Name: fmt.Sprintf("WireGuard %s", e.Name()),
			Status: CheckOK, Detail: "Interface active",
		})
	}

	return checks
}

// processRunning checks if a process is running via pgrep.
func processRunning(name string) bool {
	if path, err := exec.LookPath("pgrep"); err == nil {
		return exec.Command(path, "-x", name).Run() == nil
	}
	return false
}

