package cgroup

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

// KubepodsResolver maps cgroup paths under kubepods.slice (or the v1
// equivalent) to their pod identity (namespace, name, container, QoS class).
// Works without kubelet API access — identity comes from the cgroup name plus
// any labels the kubelet wrote into /var/log/pods metadata, when available.
//
// Resolution order:
//  1. Parse known slice name patterns (fast, works everywhere).
//  2. If the pod directory under /var/log/pods/<ns>_<name>_<uid>/ exists,
//     upgrade the raw pod UID to a human-readable namespace/name/container.
//  3. Results cached for 30 s so repeated lookups during a tick don't stat
//     the filesystem for every process.
type KubepodsResolver struct {
	mu       sync.RWMutex
	cache    map[string]PodIdentity
	cachedAt map[string]time.Time
	ttl      time.Duration
}

// PodIdentity is everything the resolver could determine about one pod.
// Every field is "" when not derivable — callers must treat them as optional.
type PodIdentity struct {
	Namespace   string
	Name        string
	Container   string
	QoS         string
	PodUID      string
}

// NewKubepodsResolver returns a resolver with a 30 s cache TTL.
func NewKubepodsResolver() *KubepodsResolver {
	return &KubepodsResolver{
		cache:    make(map[string]PodIdentity),
		cachedAt: make(map[string]time.Time),
		ttl:      30 * time.Second,
	}
}

// Resolve parses a cgroup path and returns whatever pod identity it can
// recover. Returns zero value on non-kubepods paths — callers should check
// Empty() before acting on the result.
func (r *KubepodsResolver) Resolve(cgroupPath string) PodIdentity {
	if !isKubepodsPath(cgroupPath) {
		return PodIdentity{}
	}
	r.mu.RLock()
	if id, ok := r.cache[cgroupPath]; ok {
		if time.Since(r.cachedAt[cgroupPath]) < r.ttl {
			r.mu.RUnlock()
			return id
		}
	}
	r.mu.RUnlock()

	id := parseKubepodsPath(cgroupPath)
	if id.PodUID != "" {
		// Best-effort: check /var/log/pods for a matching subdirectory so we
		// can upgrade UID-only entries to namespace/name/container.
		upgradeFromVarLogPods(&id)
	}

	r.mu.Lock()
	r.cache[cgroupPath] = id
	r.cachedAt[cgroupPath] = time.Now()
	r.mu.Unlock()
	return id
}

// Empty reports whether the resolver produced no identifying data.
func (p PodIdentity) Empty() bool {
	return p.PodUID == "" && p.Name == "" && p.Namespace == ""
}

// ── Parsing ──────────────────────────────────────────────────────────────────

// isKubepodsPath matches common prefixes kubelet uses for pod cgroups across
// cgroup v1 and v2, including systemd-managed QoS slices.
func isKubepodsPath(p string) bool {
	return strings.Contains(p, "kubepods") ||
		strings.Contains(p, "/pods/") ||
		strings.Contains(p, "/crio-") ||
		strings.Contains(p, "/docker/") && strings.Contains(p, "kube")
}

// Patterns for the common kubepods layouts:
//
//	cgroup v2 (systemd driver):
//	  /kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-pod<uid>.slice/<runtime>-<containerID>.scope
//	cgroup v2 (cgroupfs driver):
//	  /kubepods/burstable/pod<uid>/<containerID>
//	cgroup v1:
//	  /kubepods/besteffort/pod<uid>/<containerID>
var (
	reQoSSystemd = regexp.MustCompile(`kubepods-(\w+)\.slice`)
	rePodSystemd = regexp.MustCompile(`pod([0-9a-f_\-]+)\.(?:slice|scope)`)
	reQoSDir     = regexp.MustCompile(`/kubepods/(\w+)/`)
	rePodDir     = regexp.MustCompile(`/pod([0-9a-f\-]{36})(?:/|$)`)
	reContainer  = regexp.MustCompile(`(?:docker|cri-containerd|crio|containerd)-([0-9a-f]{12,64})`)
)

func parseKubepodsPath(p string) PodIdentity {
	var id PodIdentity

	// Systemd driver uses "_" in pod UIDs inside the slice name; restore dashes.
	if m := reQoSSystemd.FindStringSubmatch(p); m != nil {
		id.QoS = canonicalQoS(m[1])
	} else if m := reQoSDir.FindStringSubmatch(p); m != nil {
		id.QoS = canonicalQoS(m[1])
	} else if strings.Contains(p, "/kubepods/") && !strings.Contains(p, "/besteffort/") &&
		!strings.Contains(p, "/burstable/") {
		id.QoS = "Guaranteed"
	}

	if m := rePodSystemd.FindStringSubmatch(p); m != nil {
		id.PodUID = strings.ReplaceAll(m[1], "_", "-")
	} else if m := rePodDir.FindStringSubmatch(p); m != nil {
		id.PodUID = m[1]
	}

	if m := reContainer.FindStringSubmatch(p); m != nil {
		// Short form keeps the log line readable.
		if len(m[1]) > 12 {
			id.Container = m[1][:12]
		} else {
			id.Container = m[1]
		}
	}
	return id
}

func canonicalQoS(raw string) string {
	switch strings.ToLower(raw) {
	case "besteffort":
		return "BestEffort"
	case "burstable":
		return "Burstable"
	}
	return "Guaranteed"
}

// upgradeFromVarLogPods scans /var/log/pods/<ns>_<name>_<uid>/<container>/
// entries and sets Namespace/Name/Container when a matching UID is present.
// Silent no-op when the directory is absent or unreadable — non-k8s hosts
// don't have this directory, and non-root readers may not either.
func upgradeFromVarLogPods(id *PodIdentity) {
	const root = "/var/log/pods"
	entries, err := os.ReadDir(root)
	if err != nil {
		return
	}
	uid := strings.ReplaceAll(id.PodUID, "_", "-")
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		if !strings.HasSuffix(e.Name(), uid) {
			continue
		}
		// Format is <namespace>_<podname>_<uid>
		parts := strings.SplitN(e.Name(), "_", 3)
		if len(parts) < 3 {
			continue
		}
		id.Namespace = parts[0]
		id.Name = parts[1]
		// If Container is still empty, pick the single subdir inside
		// (common case: one-container pod).
		if id.Container == "" {
			sub, _ := os.ReadDir(filepath.Join(root, e.Name()))
			for _, s := range sub {
				if s.IsDir() {
					id.Container = s.Name()
					break
				}
			}
		}
		return
	}
	_ = fs.ErrNotExist // silence staticcheck if the caller ever gates on err type
}
