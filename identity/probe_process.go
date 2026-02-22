package identity

import (
	"fmt"
	"os"
	"strings"

	"github.com/ftahirops/xtop/model"
	"github.com/ftahirops/xtop/util"
)

// Known service process names and their canonical service name.
var knownProcesses = map[string]string{
	"nginx":          "nginx",
	"apache2":        "apache",
	"httpd":          "apache",
	"mysqld":         "mysql",
	"mariadbd":       "mysql",
	"postgres":       "postgresql",
	"redis-server":   "redis",
	"mongod":         "mongodb",
	"mongos":         "mongodb",
	"dockerd":        "docker",
	"containerd":     "containerd",
	"kubelet":        "kubelet",
	"kube-apiserver": "kube-apiserver",
	"kube-proxy":     "kube-proxy",
	"haproxy":        "haproxy",
	"traefik":        "traefik",
	"caddy":          "caddy",
	"prometheus":     "prometheus",
	"grafana-server": "grafana",
	"grafana":        "grafana",
	"node_exporter":  "node-exporter",
	"alertmanager":   "alertmanager",
	"postfix":        "postfix",
	"dovecot":        "dovecot",
	"named":          "bind",
	"dnsmasq":        "dnsmasq",
	"unbound":        "unbound",
	"gitlab-runner":  "gitlab-runner",
	"jenkins":        "jenkins",
	"sshd":           "sshd",
	"gunicorn":       "gunicorn",
	"uvicorn":        "uvicorn",
	"php-fpm":        "php-fpm",
}

// ambiguousProcesses are runtimes that could be either a service (long-running
// daemon) or a transient one-off command (python3 -c "...", node -e "...").
// These require extra validation: must have a systemd unit, be listening on a
// port, or have been running for > 60 seconds.
var ambiguousProcesses = map[string]string{
	"java":    "java",
	"node":    "node",
	"python3": "python",
	"python":  "python",
}

// probeProcesses scans /proc/*/comm for known service processes.
// Ambiguous runtimes (python, node, java) are only included if they have a
// systemd unit, listen on a port, or have been running for > 60 seconds,
// to avoid false-positive discovery of transient one-off commands.
func probeProcesses(id *model.ServerIdentity) {
	procEntries, err := os.ReadDir("/proc")
	if err != nil {
		return
	}

	// Build set of PIDs already associated with listening ports
	portPIDs := make(map[int]bool)
	for _, svc := range id.Services {
		if len(svc.Ports) > 0 && svc.Extra != nil {
			if pidStr, ok := svc.Extra["pid"]; ok {
				portPIDs[util.ParseInt(pidStr)] = true
			}
		}
	}

	// Read system boot time for uptime calculation
	bootTime := readBootTime()

	seen := make(map[string]bool)
	for _, pe := range procEntries {
		if !pe.IsDir() {
			continue
		}
		pid := util.ParseInt(pe.Name())
		if pid < 1 {
			continue
		}

		comm := readComm(pid)
		if comm == "" {
			continue
		}

		svcName, known := knownProcesses[comm]
		ambigName := ""
		if !known {
			ambigName, known = ambiguousProcesses[comm]
			if known {
				svcName = ambigName
			}
		}
		if !known {
			continue
		}
		if seen[svcName] {
			continue
		}

		// For ambiguous runtimes, validate this is a real service, not a one-off.
		if ambigName != "" {
			if !isDaemonLike(pid, bootTime, portPIDs) {
				continue
			}
		}

		seen[svcName] = true

		svc := findOrCreateService(id, svcName)
		svc.Running = true

		// Read binary path from /proc/PID/exe
		if exe, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid)); err == nil {
			svc.BinaryPath = exe
		}

		// Read cmdline for extra context
		if cmdline, err := util.ReadFileString(fmt.Sprintf("/proc/%d/cmdline", pid)); err == nil {
			// cmdline uses \0 as separator
			args := strings.ReplaceAll(cmdline, "\x00", " ")
			args = strings.TrimSpace(args)
			if args != "" {
				if svc.Extra == nil {
					svc.Extra = make(map[string]string)
				}
				svc.Extra["cmdline"] = args
				svc.Extra["pid"] = fmt.Sprintf("%d", pid)
			}
		}

		// Read cgroup for systemd unit
		if cg, err := util.ReadFileString(fmt.Sprintf("/proc/%d/cgroup", pid)); err == nil {
			for _, line := range strings.Split(cg, "\n") {
				// v2: "0::/system.slice/nginx.service"
				parts := strings.SplitN(line, ":", 3)
				if len(parts) == 3 && strings.HasSuffix(parts[2], ".service") {
					unit := parts[2]
					// Strip leading path to get just the unit name
					if idx := strings.LastIndex(unit, "/"); idx >= 0 {
						unit = unit[idx+1:]
					}
					svc.Unit = unit
					break
				}
			}
		}
	}
}

// isDaemonLike returns true if a process looks like a long-running service
// rather than a transient command. Checks: systemd unit, listening port, or
// running for > 60 seconds.
func isDaemonLike(pid int, bootTime uint64, portPIDs map[int]bool) bool {
	// Already associated with a listening port
	if portPIDs[pid] {
		return true
	}

	// Has a systemd service unit
	if cg, err := util.ReadFileString(fmt.Sprintf("/proc/%d/cgroup", pid)); err == nil {
		for _, line := range strings.Split(cg, "\n") {
			parts := strings.SplitN(line, ":", 3)
			if len(parts) == 3 && strings.HasSuffix(parts[2], ".service") {
				return true
			}
		}
	}

	// Check process uptime > 60 seconds
	if bootTime > 0 {
		if content, err := util.ReadFileString(fmt.Sprintf("/proc/%d/stat", pid)); err == nil {
			closeIdx := strings.LastIndex(content, ")")
			if closeIdx >= 0 && closeIdx+2 < len(content) {
				fields := strings.Fields(content[closeIdx+2:])
				if len(fields) > 19 {
					startTicks := util.ParseUint64(fields[19]) // field 22 = starttime (0-indexed after comm: 19)
					hz := uint64(100)                          // USER_HZ
					uptimeSec := readUptimeSeconds()
					if uptimeSec > 0 {
						procAgeSec := uptimeSec - (startTicks / hz)
						if procAgeSec > 60 {
							return true
						}
					}
				}
			}
		}
	}

	return false
}

// readBootTime reads the system boot time from /proc/stat.
func readBootTime() uint64 {
	lines, err := util.ReadFileLines("/proc/stat")
	if err != nil {
		return 0
	}
	for _, line := range lines {
		if strings.HasPrefix(line, "btime ") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				return util.ParseUint64(parts[1])
			}
		}
	}
	return 0
}

// readUptimeSeconds reads system uptime in seconds from /proc/uptime.
func readUptimeSeconds() uint64 {
	content, err := util.ReadFileString("/proc/uptime")
	if err != nil {
		return 0
	}
	parts := strings.Fields(content)
	if len(parts) < 1 {
		return 0
	}
	// Parse float, return integer seconds
	dotIdx := strings.Index(parts[0], ".")
	if dotIdx > 0 {
		return util.ParseUint64(parts[0][:dotIdx])
	}
	return util.ParseUint64(parts[0])
}
