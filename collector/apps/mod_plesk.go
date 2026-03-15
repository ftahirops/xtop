//go:build linux

package apps

import (
	"bufio"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/ftahirops/xtop/model"
)

type pleskModule struct {
	lastDeep time.Time
	cache    map[string]string
}

func NewPleskModule() AppModule { return &pleskModule{} }

func (m *pleskModule) Type() string        { return "plesk" }
func (m *pleskModule) DisplayName() string { return "Plesk" }

// Detect looks for sw-engine or sw-cp-serverd processes (Plesk control panel).
func (m *pleskModule) Detect(processes []model.ProcessMetrics) []DetectedApp {
	// Must have /usr/local/psa/version
	if _, err := os.Stat("/usr/local/psa/version"); err != nil {
		return nil
	}

	// Find the main sw-cp-serverd or sw-engine process
	for _, p := range processes {
		if p.Comm == "sw-cp-server" || p.Comm == "sw-engine" {
			port := findListeningPort(p.PID)
			if port == 0 {
				port = 8443
			}
			return []DetectedApp{{
				PID:     p.PID,
				Port:    port,
				Comm:    p.Comm,
				Cmdline: readProcCmdline(p.PID),
				Index:   0,
			}}
		}
	}

	// Fallback: cmdline match
	for _, p := range processes {
		cmd := readProcCmdline(p.PID)
		if strings.Contains(cmd, "sw-cp-server") || strings.Contains(cmd, "sw-engine") {
			port := findListeningPort(p.PID)
			if port == 0 {
				port = 8443
			}
			return []DetectedApp{{
				PID:     p.PID,
				Port:    port,
				Comm:    p.Comm,
				Cmdline: cmd,
				Index:   0,
			}}
		}
	}
	return nil
}

func (m *pleskModule) Collect(app *DetectedApp, secrets *AppSecrets) model.AppInstance {
	inst := model.AppInstance{
		AppType:     "plesk",
		DisplayName: "Plesk",
		PID:         app.PID,
		Port:        app.Port,
		Status:      "active",
		UptimeSec:   readProcUptime(app.PID),
		DeepMetrics: make(map[string]string),
		NeedsCreds:  false,
	}

	// Tier 1: sum CPU/RSS across all Plesk-related processes
	pleskComms := map[string]bool{
		"sw-cp-server": true, "sw-engine": true,
		"psa-pc-remot": true, "plesk-ssh-te": true,
	}
	var totalRSS float64
	var totalCPU float64
	var totalThreads int
	var totalFDs int

	pids, _ := procEntries()
	for _, pid := range pids {
		_, comm := readPPIDComm(pid)
		isPlesk := pleskComms[comm] ||
			strings.HasPrefix(comm, "plesk-php") ||
			strings.HasPrefix(comm, "sw-")
		if !isPlesk {
			continue
		}
		totalRSS += readProcRSS(pid)
		totalCPU += readProcCPUPct(pid, readProcUptime(pid))
		totalThreads += readProcThreads(pid)
		totalFDs += readProcFDs(pid)
	}

	inst.RSSMB = totalRSS
	inst.CPUPct = totalCPU
	inst.Threads = totalThreads
	inst.FDs = totalFDs
	if app.Port > 0 {
		inst.Connections = countTCPConnections(app.Port)
	}

	// Version
	if data, err := os.ReadFile("/usr/local/psa/version"); err == nil {
		parts := strings.Fields(strings.TrimSpace(string(data)))
		if len(parts) >= 1 {
			inst.Version = parts[0]
			inst.DeepMetrics["plesk_version"] = parts[0]
		}
		if len(parts) >= 2 {
			inst.DeepMetrics["os_platform"] = parts[1]
		}
	}

	// Deep metrics — throttled to every 30s
	now := time.Now()
	if m.cache != nil && now.Sub(m.lastDeep) < 30*time.Second {
		for k, v := range m.cache {
			inst.DeepMetrics[k] = v
		}
	} else {
		m.collectDeep(&inst)
		m.cache = make(map[string]string)
		for k, v := range inst.DeepMetrics {
			m.cache[k] = v
		}
		m.lastDeep = now
	}

	inst.HasDeepMetrics = len(inst.DeepMetrics) > 0
	inst.HealthScore = m.computeHealth(&inst)

	// Per-website metrics
	inst.Websites = CollectWebsites()

	return inst
}

func (m *pleskModule) collectDeep(inst *model.AppInstance) {
	dm := inst.DeepMetrics

	// Domain count
	if out, err := exec.Command("plesk", "db", "-Ne",
		"SELECT COUNT(*) FROM domains").Output(); err == nil {
		dm["domains"] = strings.TrimSpace(string(out))
	}

	// Subscription count
	if out, err := exec.Command("plesk", "db", "-Ne",
		"SELECT COUNT(*) FROM hosting").Output(); err == nil {
		dm["hosting_subscriptions"] = strings.TrimSpace(string(out))
	}

	// Mail accounts
	if out, err := exec.Command("plesk", "db", "-Ne",
		"SELECT COUNT(*) FROM mail").Output(); err == nil {
		dm["mail_accounts"] = strings.TrimSpace(string(out))
	}

	// Database count
	if out, err := exec.Command("plesk", "db", "-Ne",
		"SELECT COUNT(*) FROM data_bases").Output(); err == nil {
		dm["databases"] = strings.TrimSpace(string(out))
	}

	// Suspended domains
	if out, err := exec.Command("plesk", "db", "-Ne",
		"SELECT COUNT(*) FROM domains WHERE status != 0").Output(); err == nil {
		dm["suspended_domains"] = strings.TrimSpace(string(out))
	}

	// Plesk service status — check key daemons
	pleskServices := []struct {
		name string
		unit string
		key  string
	}{
		{"Panel", "sw-cp-server", "svc_panel"},
		{"Engine", "sw-engine", "svc_engine"},
		{"Nginx", "nginx", "svc_nginx"},
		{"Apache", "apache2", "svc_apache"},
		{"MariaDB", "mariadb", "svc_mariadb"},
		{"Postfix", "postfix", "svc_postfix"},
		{"Dovecot", "dovecot", "svc_dovecot"},
		{"BIND", "named", "svc_named"},
		{"PHP-FPM 8.3", "plesk-php83-fpm", "svc_php83"},
		{"PHP-FPM 8.4", "plesk-php84-fpm", "svc_php84"},
		{"Fail2Ban", "fail2ban", "svc_fail2ban"},
		{"Imunify360", "imunify360", "svc_imunify"},
	}

	running, failed := 0, 0
	var downNames []string
	for _, svc := range pleskServices {
		out, err := exec.Command("systemctl", "is-active", svc.unit).Output()
		status := strings.TrimSpace(string(out))
		if err != nil || status != "active" {
			// Check if unit exists
			existOut, _ := exec.Command("systemctl", "cat", svc.unit).Output()
			if len(existOut) == 0 {
				dm[svc.key] = "n/a"
				continue
			}
			dm[svc.key] = "down"
			failed++
			downNames = append(downNames, svc.name)
		} else {
			dm[svc.key] = "active"
			running++
		}
	}
	dm["services_running"] = strconv.Itoa(running)
	dm["services_failed"] = strconv.Itoa(failed)
	dm["services_down_names"] = strings.Join(downNames, ", ")

	// PHP-FPM pool count per version
	phpVersions := []string{"8.1", "8.2", "8.3", "8.4"}
	totalPools := 0
	for _, ver := range phpVersions {
		poolDir := fmt.Sprintf("/opt/plesk/php/%s/etc/php-fpm.d/", ver)
		files, err := filepath.Glob(poolDir + "*.conf")
		if err != nil || len(files) == 0 {
			continue
		}
		key := fmt.Sprintf("php%s_pools", strings.Replace(ver, ".", "", 1))
		dm[key] = strconv.Itoa(len(files))
		totalPools += len(files)
	}
	dm["php_pools_total"] = strconv.Itoa(totalPools)

	// Certificate status — scan Let's Encrypt certs
	certOk, certExpiring, certExpired := 0, 0, 0
	certDirs, _ := filepath.Glob("/opt/psa/var/modules/letsencrypt/etc/live/*/cert.pem")
	if len(certDirs) == 0 {
		certDirs, _ = filepath.Glob("/etc/letsencrypt/live/*/cert.pem")
	}
	dm["cert_total"] = strconv.Itoa(len(certDirs))
	for _, certPath := range certDirs {
		data, err := os.ReadFile(certPath)
		if err != nil {
			continue
		}
		block, _ := pem.Decode(data)
		if block == nil {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			continue
		}
		remaining := time.Until(cert.NotAfter)
		if remaining <= 0 {
			certExpired++
		} else if remaining < 30*24*time.Hour {
			certExpiring++
		} else {
			certOk++
		}
	}
	dm["certs_ok"] = strconv.Itoa(certOk)
	dm["certs_expiring"] = strconv.Itoa(certExpiring)
	dm["certs_expired"] = strconv.Itoa(certExpired)

	// Disk usage
	for _, dir := range []struct {
		path string
		key  string
	}{
		{"/var/lib/mysql", "disk_mysql_mb"},
		{"/var/mail", "disk_mail_mb"},
		{"/var/www/vhosts", "disk_vhosts_mb"},
	} {
		if out, err := exec.Command("du", "-sm", dir.path).Output(); err == nil {
			fields := strings.Fields(string(out))
			if len(fields) >= 1 {
				dm[dir.key] = fields[0]
			}
		}
	}

	// Mail queue size — parse "-- N Kbytes in M Requests."
	if out, err := exec.Command("postqueue", "-p").Output(); err == nil {
		outStr := strings.TrimSpace(string(out))
		if strings.Contains(outStr, "Mail queue is empty") {
			dm["mail_queue"] = "0"
		} else {
			// Last line format: "-- 5 Kbytes in 2 Requests."
			lines := strings.Split(outStr, "\n")
			last := lines[len(lines)-1]
			if strings.Contains(last, "Requests") {
				// Extract the number before "Requests"
				parts := strings.Fields(last)
				for i, p := range parts {
					if p == "Requests." || p == "Request." {
						if i > 0 {
							dm["mail_queue"] = parts[i-1]
						}
						break
					}
				}
				if dm["mail_queue"] == "" {
					dm["mail_queue"] = "0"
				}
			} else {
				dm["mail_queue"] = "0"
			}
		}
	}

	// Imunify360 stats — use simpler command
	if out, err := exec.Command("imunify360-agent", "malware", "on-demand", "list", "--json").Output(); err == nil {
		dm["imunify_status"] = "active"
		infected := strings.Count(string(out), "\"INFECTED\"")
		dm["imunify_infected"] = strconv.Itoa(infected)
	} else {
		// Try just checking if service is running
		if svcOut, err2 := exec.Command("systemctl", "is-active", "imunify360").Output(); err2 == nil && strings.TrimSpace(string(svcOut)) == "active" {
			dm["imunify_status"] = "active"
			dm["imunify_infected"] = "0"
		} else {
			dm["imunify_status"] = "n/a"
		}
	}

	// Active web connections
	if httpConns := countTCPConnections(80); httpConns > 0 {
		dm["http_connections"] = strconv.Itoa(httpConns)
	}
	if httpsConns := countTCPConnections(443); httpsConns > 0 {
		dm["https_connections"] = strconv.Itoa(httpsConns)
	}

	// Updates available
	if out, err := exec.Command("plesk", "installer", "--select-release-current",
		"--show-components").Output(); err == nil {
		updates := 0
		scanner := bufio.NewScanner(strings.NewReader(string(out)))
		for scanner.Scan() {
			if strings.Contains(scanner.Text(), "[upgrade]") {
				updates++
			}
		}
		dm["updates_available"] = strconv.Itoa(updates)
	}

	// License info
	if out, err := exec.Command("plesk", "bin", "license", "--info").Output(); err == nil {
		for _, line := range strings.Split(string(out), "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "Plesk Key") {
				parts := strings.SplitN(line, ":", 2)
				if len(parts) == 2 {
					dm["license_type"] = strings.TrimSpace(parts[1])
				}
			}
			if strings.Contains(line, "expire") || strings.Contains(line, "Expire") {
				dm["license_expiry"] = strings.TrimSpace(line)
			}
		}
	}
}

func (m *pleskModule) computeHealth(inst *model.AppInstance) int {
	score := 100
	dm := inst.DeepMetrics

	// Only services down affects health — show which ones
	if f, _ := strconv.Atoi(dm["services_failed"]); f > 0 {
		score -= f * 10
		names := dm["services_down_names"]
		if names != "" {
			inst.HealthIssues = append(inst.HealthIssues,
				fmt.Sprintf("Services down: %s", names))
		}
	}

	// Mail queue backed up (only if large)
	if mq, _ := strconv.Atoi(dm["mail_queue"]); mq > 100 {
		score -= 10
		inst.HealthIssues = append(inst.HealthIssues,
			fmt.Sprintf("Mail queue: %d messages backed up", mq))
	}

	// Imunify infected — security concern
	if inf, _ := strconv.Atoi(dm["imunify_infected"]); inf > 0 {
		score -= 15
		inst.HealthIssues = append(inst.HealthIssues,
			fmt.Sprintf("Imunify360: %d infected file(s) detected", inf))
	}

	if score < 0 {
		score = 0
	}
	return score
}
