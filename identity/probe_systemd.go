package identity

import (
	"os/exec"
	"strings"

	"github.com/ftahirops/xtop/model"
)

// probeSystemdServices queries systemctl for running services and merges
// the results with already-detected services.
func probeSystemdServices(id *model.ServerIdentity) {
	path, err := exec.LookPath("systemctl")
	if err != nil {
		return
	}
	out, err := exec.Command(path, "list-units", "--type=service", "--state=running",
		"--no-legend", "--no-pager").Output()
	if err != nil {
		return
	}

	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 1 {
			continue
		}
		unit := fields[0] // e.g. "nginx.service"

		// Derive canonical name from unit name
		name := strings.TrimSuffix(unit, ".service")
		// Strip common prefixes
		name = strings.TrimPrefix(name, "snap.")

		// Check if any existing service matches this unit
		found := false
		for i := range id.Services {
			if id.Services[i].Unit == unit || id.Services[i].Name == name {
				id.Services[i].Unit = unit
				id.Services[i].Running = true
				found = true
				break
			}
		}

		// Only add well-known services, not every running unit
		if !found {
			if _, known := knownProcesses[name]; known {
				svc := findOrCreateService(id, knownProcesses[name])
				svc.Unit = unit
				svc.Running = true
			}
		}
	}
}
