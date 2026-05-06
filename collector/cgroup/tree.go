package cgroup

import (
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"

	"github.com/ftahirops/xtop/model"
)

// skipTreeWalk is flipped by the engine when the resource guard says
// the host is loaded enough that walking the entire cgroup tree (which
// can mean thousands of dirent reads on k8s nodes) is unaffordable.
// While set, Collect returns the previously-collected list (cached on
// snap by the previous tick — or nil if we never had one).
var skipTreeWalk atomic.Bool

// SetSkipTreeWalk lets the engine flip the skip flag once per tick.
func SetSkipTreeWalk(v bool) { skipTreeWalk.Store(v) }

// Collector reads cgroup metrics for all discovered cgroups.
type Collector struct {
	version Version
	root    string
	// kube is non-nil; it is cheap enough to always create even on non-k8s
	// hosts (zero allocations until the first Resolve on a kubepods path).
	kube *KubepodsResolver
}

// NewCollector creates a cgroup collector after detecting version and root.
func NewCollector() *Collector {
	return &Collector{
		version: DetectVersion(),
		root:    CgroupRoot(),
		kube:    NewKubepodsResolver(),
	}
}

// Name returns the collector name.
func (c *Collector) Name() string { return "cgroup" }

// Collect walks the cgroup tree and populates snap.Cgroups. Skipped at
// guard level >= 1 — the walk is cheap on 5-cgroup VMs but punishing on
// k8s nodes with thousands of pod cgroups.
func (c *Collector) Collect(snap *model.Snapshot) error {
	if skipTreeWalk.Load() {
		// Leave snap.Cgroups empty — downstream RCA gracefully degrades to
		// process-level attribution.
		return nil
	}
	var cgroups []model.CgroupMetrics

	switch c.version {
	case V2, Hybrid:
		cgroups = c.collectV2(c.root)
	case V1:
		cgroups = c.collectV1()
	}

	snap.Cgroups = cgroups
	return nil
}

// collectV2 walks the cgroup v2 hierarchy.
func (c *Collector) collectV2(root string) []model.CgroupMetrics {
	var results []model.CgroupMetrics
	walkCgroupDirs(root, func(path string) {
		relPath, _ := filepath.Rel(root, path)
		if relPath == "." {
			relPath = "/"
		} else {
			relPath = "/" + relPath
		}
		cg := readV2Metrics(path)
		cg.Path = relPath
		cg.Name = filepath.Base(path)
		if cg.Path == "/" {
			cg.Name = "[root]"
		}
		if c.kube != nil {
			if pod := c.kube.Resolve(relPath); !pod.Empty() {
				cg.PodName = pod.Name
				cg.PodNamespace = pod.Namespace
				cg.ContainerName = pod.Container
				cg.PodQoS = pod.QoS
				if pod.Name != "" {
					// Display name prefers pod/container over the raw slice
					// identifier, matching what kubectl users expect to see.
					if pod.Container != "" {
						cg.Name = pod.Namespace + "/" + pod.Name + ":" + pod.Container
					} else {
						cg.Name = pod.Namespace + "/" + pod.Name
					}
				}
			}
		}
		results = append(results, cg)
	})
	return results
}

// collectV1 reads from v1 controller hierarchies.
func (c *Collector) collectV1() []model.CgroupMetrics {
	var results []model.CgroupMetrics
	// Find the cpu controller path
	cpuRoot := findV1Controller("cpu,cpuacct")
	if cpuRoot == "" {
		cpuRoot = findV1Controller("cpu")
	}
	memRoot := findV1Controller("memory")

	if cpuRoot == "" && memRoot == "" {
		return nil
	}

	// Use whichever controller exists to enumerate cgroups
	enumRoot := cpuRoot
	if enumRoot == "" {
		enumRoot = memRoot
	}

	walkCgroupDirs(enumRoot, func(path string) {
		relPath, _ := filepath.Rel(enumRoot, path)
		if relPath == "." {
			relPath = "/"
		} else {
			relPath = "/" + relPath
		}
		cg := model.CgroupMetrics{
			Path: relPath,
			Name: filepath.Base(path),
		}
		if cg.Path == "/" {
			cg.Name = "[root]"
		}
		if cpuRoot != "" {
			readV1CPU(filepath.Join(cpuRoot, relPath), &cg)
		}
		if memRoot != "" {
			readV1Memory(filepath.Join(memRoot, relPath), &cg)
		}
		if c.kube != nil {
			if pod := c.kube.Resolve(relPath); !pod.Empty() {
				cg.PodName = pod.Name
				cg.PodNamespace = pod.Namespace
				cg.ContainerName = pod.Container
				cg.PodQoS = pod.QoS
				if pod.Name != "" {
					if pod.Container != "" {
						cg.Name = pod.Namespace + "/" + pod.Name + ":" + pod.Container
					} else {
						cg.Name = pod.Namespace + "/" + pod.Name
					}
				}
			}
		}
		results = append(results, cg)
	})
	return results
}

func findV1Controller(name string) string {
	path := filepath.Join("/sys/fs/cgroup", name)
	if _, err := os.Stat(path); err == nil {
		return path
	}
	return ""
}

// walkCgroupDirs calls fn for each directory under root that looks like a cgroup.
func walkCgroupDirs(root string, fn func(path string)) {
	// Always include root
	fn(root)

	entries, err := os.ReadDir(root)
	if err != nil {
		return
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		name := e.Name()
		// Skip system directories
		if strings.HasPrefix(name, "sys-") || name == "init.scope" {
			continue
		}
		subPath := filepath.Join(root, name)
		fn(subPath)
		// Recurse one level deeper for service units
		subEntries, err := os.ReadDir(subPath)
		if err != nil {
			continue
		}
		for _, se := range subEntries {
			if se.IsDir() && !strings.HasPrefix(se.Name(), "sys-") && se.Name() != "init.scope" {
				fn(filepath.Join(subPath, se.Name()))
			}
		}
	}
}
