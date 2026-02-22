package identity

import (
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/ftahirops/xtop/model"
	"github.com/ftahirops/xtop/util"
)

// VPN-related container image patterns. The key is matched against the image name
// (case-insensitive contains). The value is the VPN type.
var vpnContainerPatterns = map[string]string{
	"wg-easy":          "wireguard",
	"wireguard":        "wireguard",
	"linuxserver/wireguard": "wireguard",
	"openvpn":          "openvpn",
	"kylemanna/openvpn": "openvpn",
	"ipsec":            "ipsec",
	"vpn":              "vpn",
	"softether":        "softether",
	"tailscale":        "tailscale",
	"headscale":        "headscale",
	"netbird":          "netbird",
	"nebula":           "nebula",
}

// probeVPN detects VPN services through multiple evidence sources:
//   - WireGuard kernel module loaded
//   - WireGuard network interfaces (wg0, wg1, ...)
//   - Container images matching VPN patterns
//   - OpenVPN/StrongSwan/IPSec processes
//   - VPN-related listening ports (51820/udp, 1194, 500/4500)
//   - /etc/wireguard/ config files
func probeVPN(id *model.ServerIdentity) {
	vpn := &model.VPNInfo{}
	var evidence []string

	// 1. WireGuard kernel module
	if _, err := os.Stat("/sys/module/wireguard"); err == nil {
		evidence = append(evidence, "WireGuard kernel module loaded")
		vpn.Type = "wireguard"
	}

	// 2. WireGuard interfaces via ip link
	if ifaces := findWireGuardInterfaces(); len(ifaces) > 0 {
		vpn.Interface = ifaces[0]
		vpn.Type = "wireguard"
		evidence = append(evidence, fmt.Sprintf("WireGuard interface: %s", strings.Join(ifaces, ", ")))
	}

	// 3. WireGuard config directory
	if entries, err := os.ReadDir("/etc/wireguard"); err == nil {
		var confs []string
		for _, e := range entries {
			if strings.HasSuffix(e.Name(), ".conf") {
				confs = append(confs, e.Name())
			}
		}
		if len(confs) > 0 {
			evidence = append(evidence, fmt.Sprintf("WireGuard configs: %s", strings.Join(confs, ", ")))
			vpn.Type = "wireguard"
		}
	}

	// 4. `wg show` for peer count
	if vpn.Type == "wireguard" {
		if path, err := exec.LookPath("wg"); err == nil {
			out, err := exec.Command(path, "show").Output()
			if err == nil {
				output := string(out)
				peers := strings.Count(output, "peer:")
				if peers > 0 {
					vpn.Peers = peers
					evidence = append(evidence, fmt.Sprintf("%d WireGuard peers connected", peers))
				}
			}
		}
	}

	// 5. Container images matching VPN patterns
	for i := range id.Containers {
		c := &id.Containers[i]
		imgLower := strings.ToLower(c.Image)
		for pattern, vpnType := range vpnContainerPatterns {
			if strings.Contains(imgLower, pattern) {
				c.Purpose = "vpn"
				vpn.Container = c.Name
				if vpn.Type == "" {
					vpn.Type = vpnType
				}
				isUp := strings.HasPrefix(c.Status, "Up")
				status := "running"
				if !isUp {
					status = "stopped"
				}
				evidence = append(evidence,
					fmt.Sprintf("Container %q (image: %s) = %s VPN [%s]",
						c.Name, c.Image, vpnType, status))

				// Register as a service
				svc := findOrCreateService(id, vpnType)
				svc.Running = isUp
				if isUp && strings.Contains(c.Status, "healthy") {
					svc.Healthy = true
				}
				break
			}
		}
	}

	// 6. OpenVPN process
	if hasProcess("openvpn") {
		if vpn.Type == "" {
			vpn.Type = "openvpn"
		}
		evidence = append(evidence, "OpenVPN process running")
	}

	// 7. StrongSwan / IPSec
	if hasProcess("charon") || hasProcess("strongswan") || hasProcess("pluto") {
		if vpn.Type == "" {
			vpn.Type = "ipsec"
		}
		evidence = append(evidence, "IPSec/StrongSwan process running")
	}

	// 8. Tailscale
	if hasProcess("tailscaled") {
		if vpn.Type == "" {
			vpn.Type = "tailscale"
		}
		evidence = append(evidence, "Tailscale daemon running")
	}

	// 9. VPN listening ports
	vpnPorts := map[int]string{
		51820: "WireGuard (UDP)",
		1194:  "OpenVPN",
		500:   "IPSec IKE",
		4500:  "IPSec NAT-T",
		41641: "Tailscale",
	}
	for _, svc := range id.Services {
		for _, port := range svc.Ports {
			if desc, ok := vpnPorts[port]; ok {
				if vpn.Port == 0 {
					vpn.Port = port
				}
				evidence = append(evidence, fmt.Sprintf("Port %d listening (%s)", port, desc))
			}
		}
	}

	// Only set VPN info if we found evidence
	if len(evidence) > 0 {
		vpn.Evidence = evidence
		id.VPN = vpn
	}
}

// findWireGuardInterfaces returns WireGuard interface names.
func findWireGuardInterfaces() []string {
	var ifaces []string

	// Method 1: ip link show type wireguard
	if path, err := exec.LookPath("ip"); err == nil {
		out, err := exec.Command(path, "link", "show", "type", "wireguard").Output()
		if err == nil {
			for _, line := range strings.Split(string(out), "\n") {
				// Format: "3: wg0: <POINTOPOINT,..."
				line = strings.TrimSpace(line)
				if strings.Contains(line, ":") {
					fields := strings.Fields(line)
					if len(fields) >= 2 {
						name := strings.TrimSuffix(fields[1], ":")
						if name != "" {
							ifaces = append(ifaces, name)
						}
					}
				}
			}
		}
	}

	// Method 2: check /sys/class/net/wg*
	if len(ifaces) == 0 {
		entries, err := os.ReadDir("/sys/class/net")
		if err == nil {
			for _, e := range entries {
				if strings.HasPrefix(e.Name(), "wg") {
					ifaces = append(ifaces, e.Name())
				}
			}
		}
	}

	return ifaces
}

// hasProcess checks if a process with the given comm name is running.
func hasProcess(name string) bool {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return false
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		pid := util.ParseInt(e.Name())
		if pid < 1 {
			continue
		}
		comm := readComm(pid)
		if comm == name {
			return true
		}
	}
	return false
}
