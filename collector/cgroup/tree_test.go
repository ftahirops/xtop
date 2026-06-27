package cgroup

import (
	"os"
	"path/filepath"
	"sort"
	"testing"
)

// mkdirs creates a directory and all parents, fatally failing the test on error.
func mkdirs(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(path, 0755); err != nil {
		t.Fatalf("mkdirAll %s: %v", path, err)
	}
}

// TestWalkCgroupDirs_K8sDepth verifies that walkCgroupDirs reaches directories
// at Kubernetes cgroup v2 depth (4 levels below root), which the old 2-level
// nested-loop implementation silently missed.
func TestWalkCgroupDirs_K8sDepth(t *testing.T) {
	root := t.TempDir()

	// Build a mimicked k8s cgroup v2 tree:
	//   root/
	//     kubepods.slice/                               depth 1
	//       kubepods-besteffort.slice/                  depth 2
	//         kubepods-besteffort-pod123.slice/          depth 3
	//           cri-containerd-abc.scope/                depth 4  ← OLD CODE MISSES THIS
	//     system.slice/                                  depth 1
	//       foo.service/                                 depth 2
	//     sys-kernel.mount/   ← MUST BE SKIPPED (sys- prefix)
	//     init.scope/         ← MUST BE SKIPPED

	kubeDeep := filepath.Join(root,
		"kubepods.slice",
		"kubepods-besteffort.slice",
		"kubepods-besteffort-pod123.slice",
		"cri-containerd-abc.scope",
	)
	sysService := filepath.Join(root, "system.slice", "foo.service")
	sysShouldSkip := filepath.Join(root, "sys-kernel.mount")
	initShouldSkip := filepath.Join(root, "init.scope")

	mkdirs(t, kubeDeep)
	mkdirs(t, sysService)
	mkdirs(t, sysShouldSkip)
	mkdirs(t, initShouldSkip)

	var visited []string
	walkCgroupDirs(root, func(path string) {
		rel, _ := filepath.Rel(root, path)
		visited = append(visited, rel)
	})
	sort.Strings(visited)

	// Build expected set (relative paths that MUST be visited).
	mustVisit := []string{
		".", // root itself
		"kubepods.slice",
		filepath.Join("kubepods.slice", "kubepods-besteffort.slice"),
		filepath.Join("kubepods.slice", "kubepods-besteffort.slice", "kubepods-besteffort-pod123.slice"),
		// The deep k8s container scope — THIS is the regression proof.
		filepath.Join("kubepods.slice", "kubepods-besteffort.slice", "kubepods-besteffort-pod123.slice", "cri-containerd-abc.scope"),
		"system.slice",
		filepath.Join("system.slice", "foo.service"),
	}

	// Build a lookup set from visited for O(1) checks.
	visitedSet := make(map[string]bool, len(visited))
	for _, p := range visited {
		visitedSet[p] = true
	}

	for _, want := range mustVisit {
		if !visitedSet[want] {
			t.Errorf("walkCgroupDirs did not visit expected path %q (visited: %v)", want, visited)
		}
	}

	// Skipped dirs must NOT appear.
	mustSkip := []string{
		"sys-kernel.mount",
		"init.scope",
	}
	for _, skip := range mustSkip {
		if visitedSet[skip] {
			t.Errorf("walkCgroupDirs visited %q which should have been skipped", skip)
		}
	}
}

// TestWalkCgroupDirs_DepthCap verifies that a tree deeper than maxCgroupDepth
// is truncated at the cap (no infinite or over-deep walk).
func TestWalkCgroupDirs_DepthCap(t *testing.T) {
	root := t.TempDir()

	// Build a chain that is maxCgroupDepth+3 levels deep.
	chain := root
	for i := 0; i < maxCgroupDepth+3; i++ {
		chain = filepath.Join(chain, "level")
		mkdirs(t, chain)
	}

	var visited []string
	walkCgroupDirs(root, func(path string) {
		rel, _ := filepath.Rel(root, path)
		visited = append(visited, rel)
	})

	// Maximum visited depth = maxCgroupDepth levels below root + root itself.
	// rel path is "level/level/.../level" with at most maxCgroupDepth components.
	for _, p := range visited {
		if p == "." {
			continue
		}
		// Count path separators to determine depth.
		depth := len(filepath.SplitList(p)) // SplitList splits on OS separator
		// Use filepath.ToSlash for a cross-platform component count.
		components := 0
		cur := p
		for cur != "." && cur != "" {
			components++
			cur = filepath.Dir(cur)
			if cur == "." || cur == "/" {
				break
			}
		}
		_ = depth
		if components > maxCgroupDepth {
			t.Errorf("walkCgroupDirs visited path %q at depth %d, exceeds maxCgroupDepth %d",
				p, components, maxCgroupDepth)
		}
	}
}

// TestWalkCgroupDirs_SkipFilters verifies skip behaviour in isolation.
func TestWalkCgroupDirs_SkipFilters(t *testing.T) {
	root := t.TempDir()

	mkdirs(t, filepath.Join(root, "normal-slice"))
	mkdirs(t, filepath.Join(root, "sys-devices.mount"))
	mkdirs(t, filepath.Join(root, "init.scope"))
	// sys- skip must apply at non-root depths too
	mkdirs(t, filepath.Join(root, "normal-slice", "sys-subsystem.mount"))
	mkdirs(t, filepath.Join(root, "normal-slice", "allowed.service"))

	var visited []string
	walkCgroupDirs(root, func(path string) {
		rel, _ := filepath.Rel(root, path)
		visited = append(visited, rel)
	})

	visitedSet := make(map[string]bool)
	for _, p := range visited {
		visitedSet[p] = true
	}

	if !visitedSet["normal-slice"] {
		t.Error("normal-slice should be visited")
	}
	if !visitedSet[filepath.Join("normal-slice", "allowed.service")] {
		t.Error("normal-slice/allowed.service should be visited")
	}
	if visitedSet["sys-devices.mount"] {
		t.Error("sys-devices.mount must be skipped (sys- prefix at depth 1)")
	}
	if visitedSet["init.scope"] {
		t.Error("init.scope must be skipped at depth 1")
	}
	if visitedSet[filepath.Join("normal-slice", "sys-subsystem.mount")] {
		t.Error("sys-subsystem.mount must be skipped (sys- prefix at depth 2)")
	}
}
