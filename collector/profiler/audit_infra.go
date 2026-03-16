//go:build linux

package profiler

import (
	"crypto/tls"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/ftahirops/xtop/model"
	"github.com/ftahirops/xtop/util"
)

func auditInfra(role model.ServerRole, snap *model.Snapshot) []model.AuditRule {
	var result []model.AuditRule
	result = append(result, auditTimesync()...)
	result = append(result, auditKernelUpdate()...)
	result = append(result, auditDNS()...)
	result = append(result, auditBackup(role, snap)...)
	result = append(result, auditSystemdHealth()...)
	result = append(result, auditLogRotation()...)
	result = append(result, auditSSLCerts(snap)...)
	return result
}

func auditTimesync() []model.AuditRule {
	timeSyncServices := []struct {
		name string
		proc string
	}{
		{"chrony", "chronyd"},
		{"ntpd", "ntpd"},
		{"systemd-timesyncd", "systemd-timesyn"},
	}

	running := ""
	procs, _ := filepath.Glob("/proc/[0-9]*/comm")
	for _, ts := range timeSyncServices {
		for _, p := range procs {
			if comm, err := util.ReadFileString(p); err == nil {
				if strings.TrimSpace(comm) == ts.proc {
					running = ts.name
					break
				}
			}
		}
		if running != "" {
			break
		}
	}

	status := model.RulePass
	current := running + " running"
	fix := ""
	if running == "" {
		status = model.RuleFail
		current = "no time sync service detected"
		fix = "apt-get install -y chrony && systemctl enable --now chrony"
	}

	return []model.AuditRule{{
		Domain:      model.OptDomainInfra,
		Name:        "time_sync",
		Description: "NTP time synchronization service",
		Current:     current,
		Recommended: "chrony or ntpd running",
		Impact:      "Clock drift causes auth failures, cert errors, log correlation issues",
		Fix:         fix,
		Status:      status,
		Weight:      8,
	}}
}

func auditKernelUpdate() []model.AuditRule {
	_, err := os.Stat("/var/run/reboot-required")
	if err == nil {
		reason, _ := util.ReadFileString("/var/run/reboot-required.pkgs")
		reason = strings.TrimSpace(reason)
		if len(reason) > 100 {
			reason = reason[:100] + "..."
		}
		current := "reboot required"
		if reason != "" {
			current += " (" + strings.Replace(reason, "\n", ", ", -1) + ")"
		}
		return []model.AuditRule{{
			Domain:      model.OptDomainInfra,
			Name:        "kernel_update",
			Description: "Pending kernel/system update requiring reboot",
			Current:     current,
			Recommended: "reboot to apply updates",
			Impact:      "Running outdated kernel with potential security vulnerabilities",
			Fix:         "shutdown -r +1 'Rebooting for kernel update'",
			Status:      model.RuleWarn,
			Weight:      5,
		}}
	}
	return nil
}

func auditDNS() []model.AuditRule {
	data, err := util.ReadFileString("/etc/resolv.conf")
	if err != nil {
		return nil
	}

	var nameservers []string
	for _, line := range strings.Split(data, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "nameserver") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				nameservers = append(nameservers, fields[1])
			}
		}
	}

	status := model.RulePass
	current := fmt.Sprintf("%d nameservers", len(nameservers))
	fix := ""
	if len(nameservers) == 0 {
		status = model.RuleFail
		current = "no nameservers configured"
		fix = "echo 'nameserver 1.1.1.1' >> /etc/resolv.conf && echo 'nameserver 8.8.8.8' >> /etc/resolv.conf"
	} else if len(nameservers) == 1 {
		status = model.RuleWarn
		current = fmt.Sprintf("1 nameserver (%s)", nameservers[0])
	}

	return []model.AuditRule{{
		Domain:      model.OptDomainInfra,
		Name:        "dns_servers",
		Description: "DNS nameserver redundancy",
		Current:     current,
		Recommended: "at least 2 nameservers for redundancy",
		Impact:      "Single DNS failure = all resolution fails",
		Fix:         fix,
		Status:      status,
		Weight:      8,
	}}
}

func auditBackup(role model.ServerRole, snap *model.Snapshot) []model.AuditRule {
	backupTools := []struct {
		comm string
		name string
	}{
		{"restic", "Restic"},
		{"borg", "Borg"},
		{"duplicity", "Duplicity"},
		{"rdiff-backup", "rdiff-backup"},
		{"bacula-fd", "Bacula"},
		{"veeamservice", "Veeam"},
		{"rsnapshot", "rsnapshot"},
	}

	found := ""
	for _, bt := range backupTools {
		for _, p := range snap.Processes {
			if p.Comm == bt.comm {
				found = bt.name
				break
			}
		}
		if found != "" {
			break
		}
	}

	// Also check for common backup paths
	if found == "" {
		backupPaths := []string{
			"/etc/cron.d/backup", "/etc/cron.daily/backup",
			"/usr/local/bin/restic", "/usr/bin/borg",
			"/usr/sbin/bacula-fd",
		}
		for _, p := range backupPaths {
			if _, err := os.Stat(p); err == nil {
				found = "backup tool installed"
				break
			}
		}
	}

	status := model.RulePass
	current := found + " detected"
	fix := ""
	weight := 5

	if found == "" {
		status = model.RuleWarn
		current = "no backup tool detected"
		fix = "apt-get install -y restic && restic init --repo /backup"

		hasDB := false
		for _, app := range snap.Global.Apps.Instances {
			if app.AppType == "mysql" || app.AppType == "postgresql" || app.AppType == "mongodb" {
				hasDB = true
				break
			}
		}
		if hasDB {
			status = model.RuleFail
			weight = 10
			current = "no backup tool detected (DATABASE SERVER)"
		}
	}

	return []model.AuditRule{{
		Domain:      model.OptDomainInfra,
		Name:        "backup",
		Description: "Backup tool/agent detection",
		Current:     current,
		Recommended: "automated backup solution (restic, borg, etc.)",
		Impact:      "No recovery path for data loss or corruption",
		Fix:         fix,
		Status:      status,
		Weight:      weight,
	}}
}

func auditSystemdHealth() []model.AuditRule {
	out, err := exec.Command("systemctl", "--failed", "--no-legend", "--no-pager", "-q").Output()
	if err != nil {
		return nil
	}

	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	failedCount := 0
	var failedNames []string
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		failedCount++
		fields := strings.Fields(line)
		if len(fields) > 0 {
			failedNames = append(failedNames, fields[0])
		}
	}

	if failedCount == 0 {
		return []model.AuditRule{{
			Domain:      model.OptDomainInfra,
			Name:        "systemd_failed",
			Description: "Failed systemd service units",
			Current:     "0 failed units",
			Recommended: "0 failed units",
			Status:      model.RulePass,
			Weight:      5,
		}}
	}

	status := model.RuleWarn
	if failedCount > 3 {
		status = model.RuleFail
	}

	detail := strings.Join(failedNames, ", ")
	if len(detail) > 80 {
		detail = detail[:80] + "..."
	}

	return []model.AuditRule{{
		Domain:      model.OptDomainInfra,
		Name:        "systemd_failed",
		Description: "Failed systemd service units",
		Current:     fmt.Sprintf("%d failed (%s)", failedCount, detail),
		Recommended: "0 failed units",
		Impact:      "Failed services indicate neglected maintenance or configuration errors",
		Fix:         "systemctl reset-failed && systemctl list-units --failed",
		Status:      status,
		Weight:      5,
	}}
}

func auditLogRotation() []model.AuditRule {
	var totalSize int64
	var bigFiles []string

	entries, err := os.ReadDir("/var/log")
	if err != nil {
		return nil
	}

	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		totalSize += info.Size()
		if info.Size() > 500*1024*1024 { // > 500MB
			bigFiles = append(bigFiles, fmt.Sprintf("%s (%.0fMB)", e.Name(), float64(info.Size())/(1024*1024)))
		}
	}

	var result []model.AuditRule

	totalMB := float64(totalSize) / (1024 * 1024)
	status := model.RulePass
	current := fmt.Sprintf("%.0fMB", totalMB)
	fix := ""
	if totalMB > 5000 {
		status = model.RuleFail
		fix = "logrotate -f /etc/logrotate.conf"
	} else if totalMB > 2000 {
		status = model.RuleWarn
		fix = "logrotate -f /etc/logrotate.conf"
	}

	if len(bigFiles) > 0 {
		current += " — large: " + strings.Join(bigFiles, ", ")
		if len(current) > 100 {
			current = current[:100] + "..."
		}
	}

	result = append(result, model.AuditRule{
		Domain:      model.OptDomainInfra,
		Name:        "log_size",
		Description: "/var/log total size",
		Current:     current,
		Recommended: "<2GB",
		Impact:      "Disk space exhaustion from unrotated logs",
		Fix:         fix,
		Status:      status,
		Weight:      5,
	})

	// Check if logrotate exists
	if _, err := os.Stat("/etc/logrotate.conf"); err != nil {
		result = append(result, model.AuditRule{
			Domain:      model.OptDomainInfra,
			Name:        "logrotate",
			Description: "Log rotation configuration",
			Current:     "logrotate not configured",
			Recommended: "logrotate installed and configured",
			Impact:      "Logs grow unbounded, filling disk",
			Fix:         "apt-get install -y logrotate",
			Status:      model.RuleFail,
			Weight:      8,
		})
	}

	return result
}

func auditSSLCerts(snap *model.Snapshot) []model.AuditRule {
	tlsPorts := []int{443, 8443}

	var result []model.AuditRule
	checked := map[int]bool{}

	for _, p := range snap.Global.Security.NewPorts {
		if !checked[p.Port] {
			for _, tp := range tlsPorts {
				if p.Port == tp {
					checked[p.Port] = true
					rule := checkCertExpiry(p.Port)
					if rule != nil {
						result = append(result, *rule)
					}
				}
			}
		}
	}

	return result
}

func checkCertExpiry(port int) *model.AuditRule {
	conn, err := tls.DialWithDialer(
		&net.Dialer{Timeout: 3 * time.Second},
		"tcp",
		fmt.Sprintf("127.0.0.1:%d", port),
		&tls.Config{InsecureSkipVerify: true},
	)
	if err != nil {
		return nil
	}
	defer conn.Close()

	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return nil
	}

	cert := certs[0]
	daysLeft := int(time.Until(cert.NotAfter).Hours() / 24)

	status := model.RulePass
	fix := ""
	if daysLeft < 7 {
		status = model.RuleFail
		fix = "certbot renew --force-renewal"
	} else if daysLeft < 30 {
		status = model.RuleWarn
		fix = "certbot renew"
	}

	cn := cert.Subject.CommonName
	if cn == "" && len(cert.DNSNames) > 0 {
		cn = cert.DNSNames[0]
	}

	return &model.AuditRule{
		Domain:      model.OptDomainInfra,
		Name:        fmt.Sprintf("ssl_cert[:%d]", port),
		Description: fmt.Sprintf("SSL certificate expiry on port %d", port),
		Current:     fmt.Sprintf("%s — expires in %d days (%s)", cn, daysLeft, cert.NotAfter.Format("2006-01-02")),
		Recommended: ">30 days until expiry",
		Impact:      "Expired certificate causes HTTPS errors and service outage",
		Fix:         fix,
		Status:      status,
		Weight:      10,
	}
}
