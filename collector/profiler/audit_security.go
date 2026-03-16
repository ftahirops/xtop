//go:build linux

package profiler

import (
	"fmt"
	"os"
	"strings"

	"github.com/ftahirops/xtop/model"
	"github.com/ftahirops/xtop/util"
)

func auditSecurity(role model.ServerRole, snap *model.Snapshot) []model.AuditRule {
	var result []model.AuditRule

	// Check SSH configuration
	result = append(result, auditSSH(role)...)

	// Check fail2ban
	result = append(result, auditFail2ban()...)

	// Check firewall
	result = append(result, auditFirewall(role, snap)...)

	// Check kernel security
	result = append(result, auditKernelSecurity()...)

	return result
}

func auditSSH(role model.ServerRole) []model.AuditRule {
	var result []model.AuditRule

	sshConf, err := util.ReadFileString("/etc/ssh/sshd_config")
	if err != nil {
		return nil
	}

	// Check PermitRootLogin
	rootLogin := sshConfigValue(sshConf, "PermitRootLogin", "yes")
	status := model.RulePass
	if rootLogin == "yes" {
		status = model.RuleFail
	} else if rootLogin == "prohibit-password" || rootLogin == "without-password" {
		status = model.RulePass
	}
	result = append(result, model.AuditRule{
		Domain:      model.OptDomainSecurity,
		Name:        "ssh_root_login",
		Description: "SSH root login policy",
		Current:     rootLogin,
		Recommended: "prohibit-password or no",
		Impact:      "Root account vulnerable to brute-force SSH attacks",
		Status:      status,
		Weight:      10,
	})

	// Check PasswordAuthentication
	passAuth := sshConfigValue(sshConf, "PasswordAuthentication", "yes")
	status = model.RulePass
	if passAuth == "yes" {
		status = model.RuleWarn
	}
	result = append(result, model.AuditRule{
		Domain:      model.OptDomainSecurity,
		Name:        "ssh_password_auth",
		Description: "SSH password authentication (vs key-only)",
		Current:     passAuth,
		Recommended: "no (use SSH keys only)",
		Impact:      "Password brute-force vulnerability",
		Status:      status,
		Weight:      8,
	})

	// Check MaxAuthTries
	maxAuth := sshConfigValue(sshConf, "MaxAuthTries", "6")
	v := parseUint(maxAuth)
	status = model.RulePass
	if v > 4 {
		status = model.RuleWarn
	}
	result = append(result, model.AuditRule{
		Domain:      model.OptDomainSecurity,
		Name:        "ssh_max_auth_tries",
		Description: "SSH maximum authentication attempts per connection",
		Current:     maxAuth,
		Recommended: "3-4",
		Impact:      "More brute-force attempts before disconnect",
		Status:      status,
		Weight:      3,
	})

	return result
}

func auditFail2ban() []model.AuditRule {
	// Check if fail2ban is running
	_, err := os.Stat("/var/run/fail2ban/fail2ban.sock")
	if err != nil {
		// Not running — check if installed
		_, err2 := os.Stat("/etc/fail2ban/fail2ban.conf")
		current := "not installed"
		if err2 == nil {
			current = "installed but not running"
		}
		return []model.AuditRule{{
			Domain:      model.OptDomainSecurity,
			Name:        "fail2ban",
			Description: "Fail2ban intrusion prevention",
			Current:     current,
			Recommended: "running",
			Impact:      "No automated brute-force protection",
			Status:      model.RuleFail,
			Weight:      8,
		}}
	}
	return []model.AuditRule{{
		Domain:      model.OptDomainSecurity,
		Name:        "fail2ban",
		Description: "Fail2ban intrusion prevention",
		Current:     "running",
		Recommended: "running",
		Impact:      "No automated brute-force protection",
		Status:      model.RulePass,
		Weight:      8,
	}}
}

func auditFirewall(role model.ServerRole, snap *model.Snapshot) []model.AuditRule {
	var result []model.AuditRule

	// Check if any firewall is active
	firewallActive := false

	// Check iptables
	if data, err := util.ReadFileString("/proc/net/ip_tables_names"); err == nil && strings.TrimSpace(data) != "" {
		firewallActive = true
	}

	// Check nftables
	if _, err := os.Stat("/etc/nftables.conf"); err == nil {
		firewallActive = true
	}

	// Check ufw
	if data, _ := util.ReadFileString("/etc/ufw/ufw.conf"); strings.Contains(data, "ENABLED=yes") {
		firewallActive = true
	}

	// Check firewalld
	if _, err := os.Stat("/var/run/firewalld.pid"); err == nil {
		firewallActive = true
	}

	status := model.RulePass
	current := "active"
	if !firewallActive {
		status = model.RuleFail
		current = "no firewall detected"
	}
	result = append(result, model.AuditRule{
		Domain:      model.OptDomainSecurity,
		Name:        "firewall",
		Description: "Host firewall (iptables/nftables/ufw/firewalld)",
		Current:     current,
		Recommended: "active",
		Impact:      "All ports exposed to network without filtering",
		Status:      status,
		Weight:      10,
	})

	// Listening port count
	openPorts := len(snap.Global.Security.NewPorts)
	if openPorts > 20 {
		result = append(result, model.AuditRule{
			Domain:      model.OptDomainSecurity,
			Name:        "open_ports",
			Description: "Number of listening ports",
			Current:     fmt.Sprintf("%d", openPorts),
			Recommended: "<20 (minimize attack surface)",
			Impact:      "Large attack surface from many listening services",
			Status:      model.RuleWarn,
			Weight:      5,
		})
	}

	return result
}

func auditKernelSecurity() []model.AuditRule {
	var result []model.AuditRule

	checks := []struct {
		path, name, desc, impact, rec string
		weight                        int
		check                         func(string) model.RuleStatus
	}{
		{
			"/proc/sys/kernel/randomize_va_space", "kernel.randomize_va_space",
			"Address Space Layout Randomization (ASLR)",
			"Easier exploitation of memory corruption bugs",
			"2 (full randomization)", 10,
			func(v string) model.RuleStatus {
				if strings.TrimSpace(v) == "2" {
					return model.RulePass
				}
				return model.RuleFail
			},
		},
		{
			"/proc/sys/kernel/dmesg_restrict", "kernel.dmesg_restrict",
			"Restrict dmesg to root only",
			"Information leak of kernel addresses and hardware details",
			"1", 3,
			func(v string) model.RuleStatus {
				if strings.TrimSpace(v) == "1" {
					return model.RulePass
				}
				return model.RuleWarn
			},
		},
		{
			"/proc/sys/kernel/kptr_restrict", "kernel.kptr_restrict",
			"Restrict kernel pointer exposure",
			"Kernel address leak aids exploit development",
			"1 or 2", 3,
			func(v string) model.RuleStatus {
				v = strings.TrimSpace(v)
				if v == "1" || v == "2" {
					return model.RulePass
				}
				return model.RuleWarn
			},
		},
		{
			"/proc/sys/net/ipv4/conf/all/rp_filter", "rp_filter",
			"Reverse path filtering (anti-spoofing)",
			"IP spoofing attacks possible",
			"1 (strict) or 2 (loose)", 5,
			func(v string) model.RuleStatus {
				v = strings.TrimSpace(v)
				if v == "1" || v == "2" {
					return model.RulePass
				}
				return model.RuleFail
			},
		},
		{
			"/proc/sys/net/ipv4/conf/all/accept_redirects", "accept_redirects",
			"ICMP redirect acceptance",
			"Man-in-the-middle via route manipulation",
			"0 (disabled)", 5,
			func(v string) model.RuleStatus {
				if strings.TrimSpace(v) == "0" {
					return model.RulePass
				}
				return model.RuleWarn
			},
		},
	}

	for _, c := range checks {
		val, err := util.ReadFileString(c.path)
		if err != nil {
			continue
		}
		result = append(result, model.AuditRule{
			Domain:      model.OptDomainSecurity,
			Name:        c.name,
			Description: c.desc,
			Current:     strings.TrimSpace(val),
			Recommended: c.rec,
			Impact:      c.impact,
			Status:      c.check(val),
			Weight:      c.weight,
		})
	}

	return result
}

// sshConfigValue reads a value from sshd_config, returning defaultVal if not found.
func sshConfigValue(conf, key, defaultVal string) string {
	for _, line := range strings.Split(conf, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "#") || line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) >= 2 && strings.EqualFold(fields[0], key) {
			return fields[1]
		}
	}
	return defaultVal
}
