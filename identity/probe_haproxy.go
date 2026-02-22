package identity

import (
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"

	"github.com/ftahirops/xtop/model"
)

var (
	haFrontendRe  = regexp.MustCompile(`(?m)^frontend\s+(\S+)`)
	haBackendRe   = regexp.MustCompile(`(?m)^backend\s+(\S+)`)
	haBindRe      = regexp.MustCompile(`(?m)^\s+bind\s+[^:]*:(\d+)`)
	haServerRe    = regexp.MustCompile(`(?m)^\s+server\s+(\S+)\s+(\S+)`)
	haDefaultBkRe = regexp.MustCompile(`(?m)^\s+default_backend\s+(\S+)`)
	haUseBkRe     = regexp.MustCompile(`(?m)^\s+use_backend\s+(\S+)`)
	haModeRe      = regexp.MustCompile(`(?m)^\s+mode\s+(http|tcp)`)
	haConnectRe   = regexp.MustCompile(`(?mi)(?:method\s+CONNECT|CONNECT)`)
	haForwardForRe = regexp.MustCompile(`(?m)^\s+option\s+forwardfor`)
	haProxyConnRe  = regexp.MustCompile(`(?mi)Proxy-Connection`)
)

// probeHAProxy detects HAProxy and classifies it as reverse proxy, forward proxy, or both.
func probeHAProxy(id *model.ServerIdentity) {
	// Check if haproxy is running
	svc := id.ServiceByName("haproxy")
	if svc == nil || !svc.Running {
		return
	}

	// Find config file
	configPaths := []string{
		"/etc/haproxy/haproxy.cfg",
	}
	var configFile string
	var configContent string
	for _, p := range configPaths {
		data, err := os.ReadFile(p)
		if err == nil {
			configFile = p
			configContent = string(data)
			break
		}
	}
	if configContent == "" {
		// Try to get config path from process cmdline
		if svc.Extra != nil {
			if cmdline, ok := svc.Extra["cmdline"]; ok {
				// Look for -f <path>
				parts := strings.Fields(cmdline)
				for i, p := range parts {
					if p == "-f" && i+1 < len(parts) {
						data, err := os.ReadFile(parts[i+1])
						if err == nil {
							configFile = parts[i+1]
							configContent = string(data)
						}
					}
				}
			}
		}
	}

	// Also handle includes (conf.d pattern)
	if configContent != "" {
		configContent = expandHAProxyIncludes(configContent, configFile)
	}

	ha := &model.HAProxyInfo{
		Running:    true,
		ConfigFile: configFile,
	}

	if svc.Version != "" {
		ha.Version = svc.Version
	}

	if configContent == "" {
		ha.Mode = "unknown"
		ha.Evidence = []string{"HAProxy running but config not readable"}
		id.HAProxy = ha
		return
	}

	// Parse config
	analyzeHAProxyConfig(ha, configContent)
	id.HAProxy = ha
}

// analyzeHAProxyConfig parses haproxy.cfg and classifies the proxy mode.
func analyzeHAProxyConfig(ha *model.HAProxyInfo, content string) {
	// Extract frontends
	for _, m := range haFrontendRe.FindAllStringSubmatch(content, -1) {
		ha.Frontends = append(ha.Frontends, m[1])
	}

	// Extract backends
	for _, m := range haBackendRe.FindAllStringSubmatch(content, -1) {
		ha.Backends = append(ha.Backends, m[1])
	}

	// Extract bind ports
	for _, m := range haBindRe.FindAllStringSubmatch(content, -1) {
		port, err := strconv.Atoi(m[1])
		if err == nil {
			ha.BindPorts = append(ha.BindPorts, port)
		}
	}

	// Score reverse proxy vs forward proxy evidence
	reverseScore := 0
	forwardScore := 0
	var evidence []string

	// --- Reverse proxy signals ---

	// default_backend or use_backend directives
	if haDefaultBkRe.MatchString(content) || haUseBkRe.MatchString(content) {
		reverseScore += 2
		evidence = append(evidence, "Has default_backend/use_backend directives (reverse proxy)")
	}

	// Fixed backend server lines
	serverMatches := haServerRe.FindAllStringSubmatch(content, -1)
	if len(serverMatches) > 0 {
		reverseScore += 2
		evidence = append(evidence, fmt.Sprintf("%d backend servers defined (reverse proxy)", len(serverMatches)))
	}

	// Binds on 80/443 (web-facing)
	for _, port := range ha.BindPorts {
		if port == 80 || port == 443 {
			reverseScore++
			evidence = append(evidence, fmt.Sprintf("Binds on port %d (web-facing)", port))
			break
		}
	}

	// option forwardfor
	if haForwardForRe.MatchString(content) {
		reverseScore++
		evidence = append(evidence, "option forwardfor present (reverse proxy)")
	}

	// mode http with backends
	modes := haModeRe.FindAllStringSubmatch(content, -1)
	hasHTTPMode := false
	hasTCPMode := false
	for _, m := range modes {
		if m[1] == "http" {
			hasHTTPMode = true
		}
		if m[1] == "tcp" {
			hasTCPMode = true
		}
	}

	// --- Forward proxy signals ---

	// CONNECT method handling
	if haConnectRe.MatchString(content) {
		forwardScore += 3
		evidence = append(evidence, "CONNECT method handling detected (forward proxy)")
	}

	// Proxy-Connection header manipulation
	if haProxyConnRe.MatchString(content) {
		forwardScore += 2
		evidence = append(evidence, "Proxy-Connection header manipulation (forward proxy)")
	}

	// No backends defined but has frontends (dynamic destination)
	if len(ha.Frontends) > 0 && len(ha.Backends) == 0 {
		forwardScore++
		evidence = append(evidence, "Frontends without backends (may be forward proxy)")
	}

	// --- Classify ---
	if reverseScore > 0 && forwardScore > 0 {
		ha.Mode = "both"
		evidence = append(evidence, fmt.Sprintf("Classification: BOTH (reverse=%d, forward=%d)", reverseScore, forwardScore))
	} else if forwardScore > 0 {
		ha.Mode = "forward_proxy"
		evidence = append(evidence, fmt.Sprintf("Classification: Forward Proxy (score=%d)", forwardScore))
	} else if reverseScore > 0 {
		if hasTCPMode && !hasHTTPMode {
			ha.Mode = "tcp_lb"
			evidence = append(evidence, "Classification: TCP Load Balancer (mode tcp, no mode http)")
		} else {
			ha.Mode = "reverse_proxy"
			evidence = append(evidence, fmt.Sprintf("Classification: Reverse Proxy (score=%d)", reverseScore))
		}
	} else {
		ha.Mode = "unknown"
		evidence = append(evidence, "Classification: Unknown (insufficient config signals)")
	}

	ha.Evidence = evidence
}

// expandHAProxyIncludes reads included config files referenced in the main config.
func expandHAProxyIncludes(content string, mainPath string) string {
	// Look for common include patterns
	lines := strings.Split(content, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		// HAProxy doesn't have native includes, but some setups use
		// .cfg files sourced via systemd EnvironmentFile or wrapper scripts.
		// The most common pattern is conf.d/ directory.
	}

	// Try conf.d directory
	confDirs := []string{
		"/etc/haproxy/conf.d",
		"/etc/haproxy/haproxy.d",
	}
	for _, dir := range confDirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if !strings.HasSuffix(e.Name(), ".cfg") {
				continue
			}
			data, err := os.ReadFile(dir + "/" + e.Name())
			if err == nil {
				content += "\n" + string(data)
			}
		}
	}
	return content
}

