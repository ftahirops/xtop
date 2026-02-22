package identity

import (
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/ftahirops/xtop/model"
	"github.com/ftahirops/xtop/util"
)

// Docker/container bridge name prefixes — these are NOT real interfaces.
var virtualIfPrefixes = []string{
	"docker", "br-", "veth", "cni", "flannel", "calico",
	"weave", "lxc", "virbr", "podman",
}

// probeKernelParams checks IP forwarding.
func probeKernelParams(id *model.ServerIdentity) {
	content, err := util.ReadFileString("/proc/sys/net/ipv4/ip_forward")
	if err != nil {
		return
	}
	id.IPForward = strings.TrimSpace(content) == "1"
}

// probeIPTables performs deep analysis of iptables/nftables rules.
// It distinguishes Docker/container-generated rules from real user NAT/firewall rules.
func probeIPTables(id *model.ServerIdentity) {
	var iptablesRules string
	if path, err := exec.LookPath("iptables-save"); err == nil {
		out, err := exec.Command(path).Output()
		if err == nil {
			iptablesRules = string(out)
		}
	}

	var nftRules string
	if path, err := exec.LookPath("nft"); err == nil {
		out, err := exec.Command(path, "list", "ruleset").Output()
		if err == nil {
			nftRules = string(out)
		}
	}

	// Only mark HasIPTables/HasNFTables if there are non-trivial rules
	if iptablesRules != "" {
		id.HasIPTables = hasNonDefaultIPTables(iptablesRules)
	}
	if nftRules != "" {
		id.HasNFTables = hasNonDefaultNFT(nftRules)
	}
}

// hasNonDefaultIPTables checks whether iptables has rules beyond Docker/container chains
// and default ACCEPT policies.
func hasNonDefaultIPTables(rules string) bool {
	for _, line := range strings.Split(rules, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "*") ||
			line == "COMMIT" {
			continue
		}
		// Skip chain policy declarations (e.g., ":INPUT ACCEPT [0:0]")
		if strings.HasPrefix(line, ":") {
			continue
		}
		// Skip Docker-generated chains and rules
		if isDockerIPTablesRule(line) {
			continue
		}
		// If we get here, there's a real user rule
		return true
	}
	return false
}

// isDockerIPTablesRule returns true if the iptables rule line is Docker-generated.
func isDockerIPTablesRule(line string) bool {
	dockerChains := []string{
		"-A DOCKER", "-A DOCKER-ISOLATION", "-A DOCKER-USER",
		"DOCKER-ISOLATION-STAGE", "DOCKER-FORWARD",
	}
	for _, dc := range dockerChains {
		if strings.Contains(line, dc) {
			return true
		}
	}
	// MASQUERADE/DNAT rules targeting docker/bridge subnets are Docker-generated
	if (strings.Contains(line, "MASQUERADE") || strings.Contains(line, "DNAT")) &&
		isDockerSubnetRule(line) {
		return true
	}
	// FORWARD rules that reference Docker bridges
	if strings.Contains(line, "FORWARD") && isDockerBridgeRule(line) {
		return true
	}
	return false
}

// isDockerSubnetRule checks if a rule targets Docker bridge subnets (172.17.0.0/16, etc.).
func isDockerSubnetRule(line string) bool {
	dockerSubnets := []string{
		"172.17.", "172.18.", "172.19.", "172.20.",
		"172.21.", "172.22.", "172.23.", "172.24.",
		"172.25.", "172.26.", "172.27.", "172.28.",
		"172.29.", "172.30.", "172.31.",
	}
	for _, subnet := range dockerSubnets {
		if strings.Contains(line, subnet) {
			return true
		}
	}
	// Also check for Docker bridge interface names
	for _, prefix := range virtualIfPrefixes {
		if strings.Contains(line, prefix) {
			return true
		}
	}
	return false
}

// isDockerBridgeRule checks if a FORWARD rule references Docker bridges.
func isDockerBridgeRule(line string) bool {
	for _, prefix := range virtualIfPrefixes {
		if strings.Contains(line, prefix) {
			return true
		}
	}
	return false
}

// hasNonDefaultNFT checks whether nftables has rules beyond Docker/container-generated ones.
func hasNonDefaultNFT(rules string) bool {
	// Docker uses iptables-nft backend — its tables show up as "table ip filter" etc.
	// but with DOCKER chains inside. Check for user-created tables.
	lines := strings.Split(rules, "\n")
	inDockerChain := false
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		// Track if we're inside a Docker-generated chain
		if strings.Contains(trimmed, "chain DOCKER") ||
			strings.Contains(trimmed, "chain DOCKER-ISOLATION") ||
			strings.Contains(trimmed, "chain DOCKER-USER") {
			inDockerChain = true
			continue
		}
		if inDockerChain && trimmed == "}" {
			inDockerChain = false
			continue
		}
		if inDockerChain {
			continue
		}
		// Skip structural lines
		if trimmed == "" || trimmed == "}" || strings.HasPrefix(trimmed, "table ") ||
			strings.HasPrefix(trimmed, "chain ") || strings.HasPrefix(trimmed, "type ") ||
			strings.HasPrefix(trimmed, "policy ") {
			continue
		}
		// Skip rules targeting Docker subnets/interfaces
		if isDockerSubnetRule(trimmed) || isDockerBridgeRule(trimmed) {
			continue
		}
		// Found a real user rule
		if strings.Contains(trimmed, "masquerade") || strings.Contains(trimmed, "snat") ||
			strings.Contains(trimmed, "dnat") || strings.Contains(trimmed, "drop") ||
			strings.Contains(trimmed, "reject") || strings.Contains(trimmed, "accept") {
			return true
		}
	}
	return false
}

// countPhysicalUpInterfaces counts the number of physical (non-virtual) interfaces that are up.
// Virtual interfaces include: docker0, br-*, veth*, cni*, flannel*, etc.
func countPhysicalUpInterfaces() int {
	entries, err := os.ReadDir("/sys/class/net")
	if err != nil {
		return 0
	}
	count := 0
	for _, e := range entries {
		name := e.Name()
		if name == "lo" {
			continue
		}
		if isVirtualInterface(name) {
			continue
		}
		operState, err := util.ReadFileString("/sys/class/net/" + name + "/operstate")
		if err != nil {
			continue
		}
		if strings.TrimSpace(operState) == "up" {
			count++
		}
	}
	return count
}

// isVirtualInterface returns true if the interface name matches known virtual/container prefixes.
func isVirtualInterface(name string) bool {
	for _, prefix := range virtualIfPrefixes {
		if strings.HasPrefix(name, prefix) {
			return true
		}
	}
	return false
}

// hasRealNATRules returns true if there are MASQUERADE/SNAT rules targeting
// non-Docker subnets on non-Docker interfaces — i.e., actual NAT gateway rules.
func hasRealNATRules() bool {
	if path, err := exec.LookPath("iptables-save"); err == nil {
		out, _ := exec.Command(path).Output()
		for _, line := range strings.Split(string(out), "\n") {
			line = strings.TrimSpace(line)
			if !strings.Contains(line, "MASQUERADE") && !strings.Contains(line, "SNAT") {
				continue
			}
			// Skip Docker-generated NAT rules
			if isDockerIPTablesRule(line) || isDockerSubnetRule(line) {
				continue
			}
			return true
		}
	}
	if path, err := exec.LookPath("nft"); err == nil {
		out, _ := exec.Command(path, "list", "ruleset").Output()
		for _, line := range strings.Split(string(out), "\n") {
			line = strings.TrimSpace(line)
			if !strings.Contains(line, "masquerade") && !strings.Contains(line, "snat") {
				continue
			}
			if isDockerSubnetRule(line) || isDockerBridgeRule(line) {
				continue
			}
			return true
		}
	}
	return false
}

// hasRealFirewallRules returns true if there are DROP/REJECT rules
// that are user-configured, not Docker or default UFW boilerplate.
func hasRealFirewallRules() bool {
	if path, err := exec.LookPath("iptables-save"); err == nil {
		out, _ := exec.Command(path).Output()
		for _, line := range strings.Split(string(out), "\n") {
			line = strings.TrimSpace(line)
			if !strings.Contains(line, "DROP") && !strings.Contains(line, "REJECT") {
				continue
			}
			// Skip chain policy declarations
			if strings.HasPrefix(line, ":") {
				continue
			}
			// Skip Docker chains
			if isDockerIPTablesRule(line) {
				continue
			}
			// Skip UFW boilerplate (ufw-*) — that's host firewall, not "firewall server" role
			if strings.Contains(line, "ufw-") {
				continue
			}
			// A real user-written firewall rule that isn't just Docker or UFW
			return true
		}
	}
	return false
}

// ipForwardIsDockerOnly checks if ip_forward was likely enabled by Docker rather
// than configured manually for routing. Evidence:
// - Docker/containerd is running
// - No manual sysctl config for ip_forward
// - No non-Docker interfaces being forwarded to
func ipForwardIsDockerOnly(id *model.ServerIdentity) bool {
	if !hasRunningService(id, "docker", "containerd") {
		return false // Docker isn't running, so something else set ip_forward
	}
	// Check if ip_forward is persistently configured in sysctl
	for _, path := range []string{
		"/etc/sysctl.conf",
		"/etc/sysctl.d/",
	} {
		info, err := os.Stat(path)
		if err != nil {
			continue
		}
		if info.IsDir() {
			entries, err := os.ReadDir(path)
			if err != nil {
				continue
			}
			for _, e := range entries {
				if checkSysctlFileForForward(path + e.Name()) {
					return false // User explicitly configured forwarding
				}
			}
		} else {
			if checkSysctlFileForForward(path) {
				return false // User explicitly configured forwarding
			}
		}
	}
	return true // Docker likely set this
}

// checkSysctlFileForForward checks if a sysctl config file explicitly enables ip_forward.
func checkSysctlFileForForward(path string) bool {
	content, err := util.ReadFileString(path)
	if err != nil {
		return false
	}
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "#") {
			continue
		}
		// net.ipv4.ip_forward = 1 or net.ipv4.conf.all.forwarding = 1
		if (strings.Contains(line, "ip_forward") || strings.Contains(line, "forwarding")) &&
			strings.Contains(line, "= 1") {
			return true
		}
	}
	return false
}

// hasDownstreamNetwork checks if the routing table has routes to private subnets
// through non-Docker, non-loopback interfaces — evidence of serving a downstream LAN.
func hasDownstreamNetwork() bool {
	if path, err := exec.LookPath("ip"); err == nil {
		out, _ := exec.Command(path, "route", "show").Output()
		for _, line := range strings.Split(string(out), "\n") {
			fields := strings.Fields(line)
			if len(fields) < 3 {
				continue
			}
			dest := fields[0]
			// Look for private subnet routes
			isPrivate := strings.HasPrefix(dest, "10.") ||
				strings.HasPrefix(dest, "192.168.") ||
				(strings.HasPrefix(dest, "172.") && !isDockerSubnetRoute(dest))
			if !isPrivate {
				continue
			}
			// Check the interface — must be a physical interface, not Docker bridge
			devIdx := -1
			for i, f := range fields {
				if f == "dev" && i+1 < len(fields) {
					devIdx = i + 1
					break
				}
			}
			if devIdx < 0 {
				continue
			}
			iface := fields[devIdx]
			if !isVirtualInterface(iface) && iface != "lo" {
				return true // Private subnet route through a real interface
			}
		}
	}
	return false
}

// isDockerSubnetRoute checks if a route destination is a Docker bridge subnet.
func isDockerSubnetRoute(dest string) bool {
	// Docker typically uses 172.17.0.0/16 through 172.31.0.0/16
	for i := 17; i <= 31; i++ {
		prefix := fmt.Sprintf("172.%d.", i)
		if strings.HasPrefix(dest, prefix) {
			return true
		}
	}
	return false
}

// hasDHCPServer checks if a DHCP server is running (common for NAT gateways).
func hasDHCPServer() bool {
	if path, err := exec.LookPath("pgrep"); err == nil {
		for _, name := range []string{"dhcpd", "dnsmasq", "kea-dhcp4"} {
			if exec.Command(path, "-x", name).Run() == nil {
				return true
			}
		}
	}
	return false
}

// checkBashHistoryForNATWork looks at root's bash history for evidence of
// manual NAT/routing configuration.
func checkBashHistoryForNATWork() bool {
	// Check multiple possible history locations
	for _, histPath := range []string{
		"/root/.bash_history",
		"/root/.zsh_history",
	} {
		content, err := util.ReadFileString(histPath)
		if err != nil {
			continue
		}
		natKeywords := []string{
			"masquerade", "MASQUERADE", "snat", "SNAT",
			"ip route add", "ip rule add",
			"net.ipv4.ip_forward",
			"iptables -t nat",
		}
		for _, line := range strings.Split(content, "\n") {
			for _, kw := range natKeywords {
				if strings.Contains(line, kw) {
					return true
				}
			}
		}
	}
	return false
}
