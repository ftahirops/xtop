package identity

import (
	"os"
	"regexp"
	"strings"

	"github.com/ftahirops/xtop/model"
	"github.com/ftahirops/xtop/util"
)

var (
	kaVIPRe       = regexp.MustCompile(`(?m)^\s+([\d.]+(?:/\d+)?)`)
	kaStateRe     = regexp.MustCompile(`(?m)^\s+state\s+(MASTER|BACKUP)`)
	kaPriorityRe  = regexp.MustCompile(`(?m)^\s+priority\s+(\d+)`)
	kaInterfaceRe = regexp.MustCompile(`(?m)^\s+interface\s+(\S+)`)
)

// probeKeepalived detects keepalived and extracts floating IP configuration.
func probeKeepalived(id *model.ServerIdentity) {
	// Check if keepalived is running
	running := false
	for _, svc := range id.Services {
		if svc.Name == "keepalived" && svc.Running {
			running = true
			break
		}
	}
	if !running && !hasProcess("keepalived") {
		return
	}

	configPaths := []string{
		"/etc/keepalived/keepalived.conf",
	}

	var content string
	for _, p := range configPaths {
		data, err := os.ReadFile(p)
		if err == nil {
			content = string(data)
			break
		}
	}

	ka := &model.KeepalivedInfo{
		Running: true,
	}

	if content == "" {
		id.Keepalived = ka
		return
	}

	// Parse VRRP instances to extract VIPs
	parseKeepalivedConfig(ka, content)
	id.Keepalived = ka
}

// parseKeepalivedConfig extracts VIPs, state, priority, and interface from keepalived.conf.
func parseKeepalivedConfig(ka *model.KeepalivedInfo, content string) {
	// Extract state (MASTER/BACKUP)
	if m := kaStateRe.FindStringSubmatch(content); len(m) > 1 {
		ka.State = m[1]
	}

	// Extract priority
	if m := kaPriorityRe.FindStringSubmatch(content); len(m) > 1 {
		ka.Priority = util.ParseInt(m[1])
	}

	// Extract interface
	if m := kaInterfaceRe.FindStringSubmatch(content); len(m) > 1 {
		ka.Interface = m[1]
	}

	// Extract VIPs from virtual_ipaddress blocks
	inVIPBlock := false
	braceDepth := 0
	for _, line := range strings.Split(content, "\n") {
		trimmed := strings.TrimSpace(line)

		if strings.Contains(trimmed, "virtual_ipaddress") {
			inVIPBlock = true
			if strings.Contains(trimmed, "{") {
				braceDepth++
			}
			continue
		}

		if inVIPBlock {
			if strings.Contains(trimmed, "{") {
				braceDepth++
			}
			if strings.Contains(trimmed, "}") {
				braceDepth--
				if braceDepth <= 0 {
					inVIPBlock = false
				}
				continue
			}
			// Lines inside virtual_ipaddress { } are IP addresses
			if trimmed != "" && !strings.HasPrefix(trimmed, "#") && !strings.HasPrefix(trimmed, "!") {
				// Extract just the IP (may have dev/label suffixes)
				fields := strings.Fields(trimmed)
				if len(fields) > 0 {
					ip := fields[0]
					ka.VIPs = append(ka.VIPs, ip)
				}
			}
		}
	}

	// Also check for actual floating IPs on interfaces via ip addr
	if ka.Interface != "" {
		actualVIPs := findFloatingIPs(ka.Interface, ka.VIPs)
		_ = actualVIPs // VIPs from config are authoritative
	}
}

// findFloatingIPs checks if the declared VIPs are actually present on the interface.
func findFloatingIPs(iface string, declaredVIPs []string) []string {
	content, err := util.ReadFileString("/proc/net/fib_trie")
	if err != nil {
		return nil
	}
	// Simple check: are any of the declared VIPs present in the fib trie?
	var found []string
	for _, vip := range declaredVIPs {
		ip := strings.Split(vip, "/")[0] // strip CIDR
		if strings.Contains(content, ip) {
			found = append(found, vip)
		}
	}
	return found
}

// addKeepalivedProcess adds keepalived to the known process list
// so it can be detected by the process probe.
func init() {
	knownProcesses["keepalived"] = "keepalived"
}
