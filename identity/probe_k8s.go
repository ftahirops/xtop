package identity

import (
	"os"
	"os/exec"
	"strings"

	"github.com/ftahirops/xtop/model"
)

// probeKubernetes detects Kubernetes node role and basic cluster info.
func probeKubernetes(id *model.ServerIdentity) {
	// Check if kubelet is running (already detected by process probe)
	kubeletRunning := false
	for _, svc := range id.Services {
		if svc.Name == "kubelet" && svc.Running {
			kubeletRunning = true
			break
		}
	}
	if !kubeletRunning {
		return
	}

	k8s := &model.K8sNodeInfo{}

	// Determine role: control-plane if admin.conf exists
	if _, err := os.Stat("/etc/kubernetes/admin.conf"); err == nil {
		k8s.NodeRole = "control-plane"
	} else {
		k8s.NodeRole = "worker"
	}

	// Try kubectl for pod count and namespaces
	if kubectlPath, err := exec.LookPath("kubectl"); err == nil {
		// Pod count
		out, err := exec.Command(kubectlPath, "get", "pods",
			"--all-namespaces", "--no-headers").Output()
		if err == nil {
			lines := strings.Split(strings.TrimSpace(string(out)), "\n")
			if lines[0] != "" {
				k8s.PodCount = len(lines)
			}

			// Extract unique namespaces
			nsSet := make(map[string]bool)
			for _, line := range lines {
				fields := strings.Fields(line)
				if len(fields) > 0 {
					nsSet[fields[0]] = true
				}
			}
			for ns := range nsSet {
				k8s.Namespaces = append(k8s.Namespaces, ns)
			}
		}
	}

	id.K8s = k8s
}
