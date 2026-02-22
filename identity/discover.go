package identity

import (
	"time"

	"github.com/ftahirops/xtop/model"
)

// Discover runs all identity probes and returns a complete ServerIdentity.
func Discover() *model.ServerIdentity {
	id := &model.ServerIdentity{
		DiscoveredAt: time.Now(),
	}

	// 1. Kernel params (ip_forward)
	probeKernelParams(id)

	// 2. Listening ports from /proc/net/tcp
	probeListeningPorts(id)

	// 3. Process matching from /proc/*/comm
	probeProcesses(id)

	// 4. Systemd running services
	probeSystemdServices(id)

	// 5. IPTables / NFTables rules (deep analysis, Docker-aware)
	probeIPTables(id)

	// 6. Docker containers
	probeDockerContainers(id)

	// 7. Classify container purposes from image names
	classifyContainers(id)

	// 8. VPN detection (WireGuard, OpenVPN, containers)
	probeVPN(id)

	// 9. Kubernetes detection
	probeKubernetes(id)

	// 10. HAProxy detection and config analysis
	probeHAProxy(id)

	// 11. Keepalived / floating IP detection
	probeKeepalived(id)

	// 12. Website discovery (nginx/apache vhosts)
	probeWebsites(id)

	// 13. Database health and inventory
	probeDatabases(id)

	// 14. Version extraction for detected services
	probeVersions(id)

	// 15. Classify roles from all evidence (weighted scoring)
	classifyRoles(id)

	return id
}
