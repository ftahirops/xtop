package runtime

import (
	"fmt"
	"strings"
	"sync"

	"github.com/ftahirops/xtop/model"
)

// GoModule detects Go runtime processes by known binary names or GOMAXPROCS env.
type GoModule struct {
	detected []goProcess
	active   bool
	mu       sync.Mutex
}

type goProcess struct {
	PID  int
	Comm string
}

// knownGoBinaries is a set of well-known Go binaries commonly found on Linux systems.
var knownGoBinaries = map[string]bool{
	"docker":        true,
	"dockerd":       true,
	"containerd":    true,
	"containerd-sh": true,
	"kubelet":       true,
	"kube-proxy":    true,
	"kube-apiserver": true,
	"kube-scheduler": true,
	"kube-controller": true,
	"etcd":          true,
	"prometheus":    true,
	"grafana":       true,
	"grafana-server": true,
	"alertmanager":  true,
	"traefik":       true,
	"caddy":         true,
	"minio":         true,
	"consul":        true,
	"vault":         true,
	"nomad":         true,
	"terraform":     true,
	"coredns":       true,
	"flannel":       true,
	"calico-node":   true,
	"crio":          true,
	"podman":        true,
	"buildah":       true,
	"skopeo":        true,
	"runc":          true,
	"cni":           true,
}

// NewGoModule creates a new Go runtime module.
func NewGoModule() *GoModule {
	return &GoModule{}
}

func (m *GoModule) Name() string        { return "go" }
func (m *GoModule) DisplayName() string  { return "Go" }

func (m *GoModule) Detect(processes []model.ProcessMetrics) bool {
	m.mu.Lock()
	defer m.mu.Unlock()

	var found []goProcess
	seen := make(map[int]bool)

	// First pass: match known Go binaries
	for _, p := range processes {
		if knownGoBinaries[p.Comm] {
			found = append(found, goProcess{PID: p.PID, Comm: p.Comm})
			seen[p.PID] = true
		}
	}

	// Second pass: check for GOMAXPROCS in environ for unrecognized processes
	// Only check processes with high enough PID (skip kernel threads)
	for _, p := range processes {
		if seen[p.PID] || p.PID < 100 {
			continue
		}
		env := readProcEnviron(p.PID)
		if _, ok := env["GOMAXPROCS"]; ok {
			found = append(found, goProcess{PID: p.PID, Comm: p.Comm})
		}
	}

	m.detected = found
	m.active = len(found) > 0
	return m.active
}

func (m *GoModule) Collect() []model.RuntimeProcessMetrics {
	m.mu.Lock()
	procs := make([]goProcess, len(m.detected))
	copy(procs, m.detected)
	m.mu.Unlock()

	var result []model.RuntimeProcessMetrics
	for _, gp := range procs {
		rss := readProcRSSMB(gp.PID)
		threads := readProcThreads(gp.PID)
		volCtx := readProcVolCtxSwitches(gp.PID)

		rpm := model.RuntimeProcessMetrics{
			PID:          gp.PID,
			Comm:         gp.Comm,
			Runtime:      "go",
			WorkingSetMB: rss,
			ThreadCount:  threads,
			Extra:        make(map[string]string),
		}

		rpm.Extra["vol_ctx_switches"] = fmt.Sprintf("%d", volCtx)

		// Read GOMAXPROCS and GOGC from environ
		env := readProcEnviron(gp.PID)
		if v, ok := env["GOMAXPROCS"]; ok {
			rpm.Extra["gomaxprocs"] = v
		}
		if v, ok := env["GOGC"]; ok {
			rpm.Extra["gogc"] = v
		}
		if v, ok := env["GOMEMLIMIT"]; ok {
			rpm.Extra["gomemlimit"] = v
		}

		result = append(result, rpm)
	}
	return result
}

func (m *GoModule) Active() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.active
}

func (m *GoModule) ProcessCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.detected)
}

// isKnownGoBinary checks if a name (possibly truncated to 15 chars by kernel)
// matches a known Go binary.
func isKnownGoBinary(comm string) bool {
	if knownGoBinaries[comm] {
		return true
	}
	// Handle 15-char truncation: check if any known name starts with comm
	if len(comm) == 15 {
		for name := range knownGoBinaries {
			if strings.HasPrefix(name, comm) {
				return true
			}
		}
	}
	return false
}
